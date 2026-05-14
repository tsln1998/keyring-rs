//! Session state for the local Bitwarden integration.
//!
//! A session owns the HTTP clients, short-lived bearer token, and in-memory keystore reused
//! across provider refreshes.

use super::auth::{BitwardenAuthError, request_api_key_token};
use super::config::BitwardenProviderConfig;
use super::crypto::{BitwardenKeyIds, initialize_org_keys, initialize_user_crypto};
use super::models::{BitwardenProfile, BitwardenSyncResponse};
use anyhow::{Context, Result, anyhow};
use bitwarden_api_api::apis::configuration::Configuration as ApiConfiguration;
use bitwarden_api_identity::apis::configuration::Configuration as IdentityConfiguration;
use bitwarden_crypto::KeyStore;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

const TOKEN_RENEWAL_WINDOW: Duration = Duration::from_secs(5 * 60);
const BITWARDEN_CLIENT_NAME: &str = "web";
const BITWARDEN_CLIENT_VERSION: &str = "2026.3.1";

/// Lazily authenticated Bitwarden session shared by one provider instance.
pub(crate) struct BitwardenSession {
    /// API configuration used for `/sync`.
    api_config: ApiConfiguration,
    /// Identity configuration used for `/connect/token`.
    identity_config: IdentityConfiguration,
    /// In-memory cryptographic material derived during the first successful login.
    keystore: KeyStore<BitwardenKeyIds>,
    /// Mutable authentication state guarded across concurrent load calls.
    auth: Mutex<BitwardenSessionAuthState>,
}

/// Mutable authentication state that changes as tokens are renewed.
#[derive(Default)]
struct BitwardenSessionAuthState {
    access_token: Option<String>,
    expires_at: Option<Instant>,
    crypto_initialized: bool,
}

impl BitwardenSession {
    /// Builds a local Bitwarden session from static provider configuration.
    pub(crate) fn new(config: &BitwardenProviderConfig) -> Self {
        // `/sync` and `/connect/token` live on different base URLs, but they share the same HTTP
        // client setup so TLS and timeout behavior stays consistent.
        let mut api_config = ApiConfiguration::new();
        api_config.base_path.clone_from(&config.api_url);

        let mut identity_config = IdentityConfiguration::new();
        identity_config.base_path.clone_from(&config.identity_url);
        identity_config.client = api_config.client.clone();

        info!(
            provider = %config.name,
            api_url = %config.api_url,
            identity_url = %config.identity_url,
            "creating bitwarden session"
        );

        Self {
            api_config,
            identity_config,
            keystore: KeyStore::default(),
            auth: Mutex::default(),
        }
    }

    pub(crate) fn keystore(&self) -> &KeyStore<BitwardenKeyIds> {
        &self.keystore
    }

    /// Refreshes organization shared keys from the latest sync profile.
    pub(crate) fn initialize_org_keys(&self, profile: &BitwardenProfile) -> Result<()> {
        debug!(
            organization_count = profile.organizations.as_ref().map_or(0, Vec::len),
            "initializing bitwarden organization keys"
        );
        initialize_org_keys(&self.keystore, profile)
    }

    pub(crate) async fn sync(
        &self,
        config: &BitwardenProviderConfig,
    ) -> Result<BitwardenSyncResponse> {
        // Step 1: ensure the bearer token is present and fresh enough for `/sync`.
        self.ensure_token(config).await?;

        // Step 2: snapshot the access token after authentication. The lock is released before the
        // network call so concurrent loads do not serialize on the entire `/sync` request.
        let access_token = {
            let state = self.auth.lock().await;
            state
                .access_token
                .clone()
                .context("bitwarden session is missing an access token")?
        };

        debug!(provider = %config.name, "requesting bitwarden sync");

        // Step 3: build the authenticated `/sync` request. The Bitwarden web-client headers are
        // required because the endpoint otherwise omits SSH-key ciphers from an otherwise
        // successful response.
        let mut builder = self
            .api_config
            .client
            .get(format!("{}/sync", self.api_config.base_path))
            .query(&[("excludeDomains", "true")])
            // Bitwarden only includes SSH-key ciphers when the sync request identifies as the web
            // client. Without these headers the endpoint still succeeds but silently omits them.
            .header("bitwarden-client-name", BITWARDEN_CLIENT_NAME)
            .header("bitwarden-client-version", BITWARDEN_CLIENT_VERSION)
            .bearer_auth(access_token);

        if let Some(user_agent) = &self.api_config.user_agent {
            builder = builder.header("user-agent", user_agent.clone());
        }

        // Step 4: fetch the raw response body first so both success and failure paths can inspect
        // the same payload.
        let response = builder
            .send()
            .await
            .map_err(|error| anyhow!("bitwarden sync failed: {error}"))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| anyhow!("bitwarden sync failed: {error}"))?;

        debug!(
            provider = %config.name,
            %status,
            body_len = body.len(),
            "received bitwarden sync response"
        );

        if !status.is_success() {
            warn!(
                provider = %config.name,
                %status,
                body_preview = %truncate_for_log(&body),
                "bitwarden sync request failed"
            );
            return Err(anyhow!(
                "bitwarden sync failed with status {status}: {body}"
            ));
        }

        // Step 5: deserialize only after the HTTP layer has succeeded so parse errors remain easy
        // to distinguish from transport or authorization problems.
        serde_json::from_str(&body).map_err(|error| {
            warn!(
                provider = %config.name,
                error = %error,
                body_preview = %truncate_for_log(&body),
                "failed to parse bitwarden sync response"
            );
            anyhow!("bitwarden sync failed: error in serde: {error}")
        })
    }

    async fn ensure_token(
        &self,
        config: &BitwardenProviderConfig,
    ) -> Result<(), BitwardenAuthError> {
        // This quick lock only decides whether a refresh is needed. The actual authentication call
        // happens after the lock is dropped so slow network I/O does not block readers.
        let should_authenticate = {
            let state = self.auth.lock().await;
            match state.expires_at {
                None => true,
                Some(expires_at) => Instant::now() + TOKEN_RENEWAL_WINDOW >= expires_at,
            }
        };

        debug!(provider = %config.name, should_authenticate, "checked bitwarden token freshness");
        if should_authenticate {
            self.authenticate(config).await?;
        }

        Ok(())
    }

    async fn authenticate(
        &self,
        config: &BitwardenProviderConfig,
    ) -> Result<(), BitwardenAuthError> {
        info!(provider = %config.name, "authenticating bitwarden session");

        // First obtain a new bearer token and the crypto bootstrap fields tied to that login.
        let response = request_api_key_token(
            &self.identity_config,
            &config.client_id,
            &config.client_secret,
        )
        .await?;

        // Record the latest token before crypto initialization so later steps operate on the same
        // authenticated session state.
        let should_initialize_crypto = {
            let mut state = self.auth.lock().await;
            state.access_token = Some(response.access_token.clone());
            state.expires_at = Some(Instant::now() + Duration::from_secs(response.expires_in));
            !state.crypto_initialized
        };

        debug!(
            provider = %config.name,
            expires_in = response.expires_in,
            should_initialize_crypto,
            "updated bitwarden auth state"
        );

        if should_initialize_crypto {
            // Crypto bootstrap is only required once per provider lifetime because the keystore is
            // retained across token renewals.
            if let Err(error) = initialize_user_crypto(&self.keystore, &config.password, &response)
            {
                // Roll the token state back when the crypto side fails so the next load does not
                // observe an authenticated-but-unusable session.
                let mut state = self.auth.lock().await;
                state.access_token = None;
                state.expires_at = None;
                warn!(provider = %config.name, error = ?error, "failed to initialize bitwarden crypto");
                return Err(BitwardenAuthError::crypto_bootstrap(error));
            }

            // Mark bootstrap completion only after both the token and keystore are ready.
            let mut state = self.auth.lock().await;
            state.crypto_initialized = true;
            info!(provider = %config.name, "bitwarden crypto initialized");
        }

        Ok(())
    }
}

/// Truncates server response bodies before including them in logs.
fn truncate_for_log(body: &str) -> String {
    const MAX_CHARS: usize = 256;

    if body.chars().count() <= MAX_CHARS {
        return body.to_owned();
    }

    // Keep enough prefix to diagnose API errors without dumping large encrypted payloads into logs.
    let mut preview = body.chars().take(MAX_CHARS).collect::<String>();
    preview.push_str("...");
    preview
}
