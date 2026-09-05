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
use reqwest::{Client, StatusCode};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

const TOKEN_RENEWAL_WINDOW: Duration = Duration::from_secs(5 * 60);
/// Maximum time to establish a connection to either Bitwarden endpoint.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-read timeout that resets after progress; catches endpoints that stop sending data.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Total HTTP budget through response-body reads, even when the server keeps sending data.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const BITWARDEN_CLIENT_NAME: &str = "web";
const BITWARDEN_CLIENT_VERSION: &str = "2026.3.1";

/// Lazily authenticated Bitwarden session shared by one provider instance.
pub(crate) struct BitwardenSession {
    /// API configuration used for `/sync`.
    api: ApiConfiguration,
    /// Identity configuration used for `/connect/token`.
    id: IdentityConfiguration,
    /// In-memory cryptographic material derived during the first successful login.
    store: KeyStore<BitwardenKeyIds>,
    /// Mutable authentication state guarded across concurrent load calls.
    state: Mutex<Auth>,
    /// Serializes token refresh attempts without blocking already authenticated `/sync` calls.
    gate: Mutex<()>,
}

/// Mutable authentication state that changes as tokens are renewed.
#[derive(Default)]
struct Auth {
    /// Published only after crypto bootstrap succeeds; cleared if this token is rejected by sync.
    token: Option<String>,
    /// Monotonic expiry updated or invalidated together with the token.
    exp: Option<Instant>,
    /// Tracks initialized account keys independently of bearer-token renewal or invalidation.
    crypto: bool,
}

impl BitwardenSession {
    /// Builds a local Bitwarden session from static provider configuration.
    ///
    /// No authentication or sync request is sent until the first load.
    ///
    /// # Errors
    ///
    /// Returns HTTP-client initialization failures so a later provider load can retry construction.
    pub(crate) fn new(config: &BitwardenProviderConfig) -> Result<Self> {
        // `/sync` and `/connect/token` live on different base URLs, but they share the same HTTP
        // client setup so TLS and timeout behavior stays consistent.
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .timeout(HTTP_TIMEOUT)
            .build()
            .context("failed to build bitwarden HTTP client")?;
        // Avoid SDK defaults, which create an additional client through infallible `Client::new`.
        let api = ApiConfiguration {
            base_path: config.api_url.clone(),
            user_agent: Some("OpenAPI-Generator/latest/rust".to_owned()),
            client: client.clone(),
            basic_auth: None,
            oauth_access_token: None,
            bearer_access_token: None,
            api_key: None,
        };
        let id = IdentityConfiguration {
            base_path: config.identity_url.clone(),
            user_agent: Some("OpenAPI-Generator/v1/rust".to_owned()),
            client,
            basic_auth: None,
            oauth_access_token: None,
            bearer_access_token: None,
            api_key: None,
        };

        info!(
            provider = %config.name,
            api = %config.api_url,
            id = %config.identity_url,
            "creating bitwarden session"
        );

        Ok(Self {
            api,
            id,
            store: KeyStore::default(),
            state: Mutex::default(),
            gate: Mutex::default(),
        })
    }

    pub(crate) fn store(&self) -> &KeyStore<BitwardenKeyIds> {
        &self.store
    }

    /// Refreshes organization shared keys from the latest sync profile.
    pub(crate) fn init_orgs(&self, profile: &BitwardenProfile) -> Result<()> {
        debug!("initializing bitwarden organization keys");
        initialize_org_keys(&self.store, profile)
    }

    /// Loads a vault snapshot, recovering from HTTP 401 with at most one authentication retry.
    ///
    /// Other HTTP, transport, and decoding failures propagate immediately. Both attempts share the
    /// caller's agent request deadline; each HTTP operation also retains its own client timeouts.
    pub(crate) async fn sync(&self, config: &BitwardenProviderConfig) -> Result<BitwardenSyncResponse> {
        self.token(config).await?;

        // At most two sync attempts, both inside the caller's unchanged request deadline.
        for attempt in 0..2 {
            let token = self
                .state
                .lock()
                .await
                .token
                .clone()
                .context("bitwarden session is missing an access token")?;
            let response = self.request_sync(&token).await?;
            let status = response.status();

            debug!(provider = %config.name, %status, "received bitwarden sync response");

            if status == StatusCode::UNAUTHORIZED {
                // An unauthorized response body is irrelevant and may itself stall. Drop it
                // before waiting for the refresh gate or starting another request.
                drop(response);
                // Serialize invalidation with login. A late 401 must not clear a token that
                // another caller has already replaced while this request was in flight.
                let _gate = self.gate.lock().await;
                let mut state = self.state.lock().await;
                if state.token.as_deref() == Some(&token) {
                    state.token = None;
                    state.exp = None;
                }
                let refresh = state.token.is_none();
                // login reacquires the state lock; retain only the refresh gate across its awaits.
                drop(state);

                if attempt == 1 {
                    // Leave the rejected token invalidated for a later load, without a third sync.
                    return Err(anyhow!(
                        "bitwarden sync failed with status {status} after token refresh"
                    ));
                }
                // Another caller may already have replaced the rejected token. Reuse that
                // replacement rather than invalidating it or performing a second login.
                if refresh {
                    info!(provider = %config.name, "refreshing rejected bitwarden access token");
                    self.login(config).await?;
                }
                continue;
            }

            if !status.is_success() {
                warn!(provider = %config.name, %status, "bitwarden sync request failed");
                return Err(anyhow!("bitwarden sync failed with status {status}"));
            }

            let body = response
                .bytes()
                .await
                .context("failed to read bitwarden sync response")?;
            return serde_json::from_slice(&body).map_err(|error| {
                warn!(provider = %config.name, error = %error, "failed to parse bitwarden sync response");
                anyhow!("bitwarden sync failed: error in serde: {error}")
            });
        }

        unreachable!("the final sync attempt always returns")
    }

    /// Sends one authenticated sync request and returns once response headers are available.
    ///
    /// The caller inspects status before reading the body so a stalled error body cannot delay
    /// authentication recovery. This helper performs no application-level authentication retry.
    async fn request_sync(&self, token: &str) -> Result<reqwest::Response> {
        debug!("requesting bitwarden sync");
        let mut builder = self
            .api
            .client
            .get(format!("{}/sync", self.api.base_path))
            .query(&[("excludeDomains", "true")])
            // Bitwarden only includes SSH-key ciphers when the sync request identifies as the web
            // client. Without these headers the endpoint still succeeds but silently omits them.
            .header("bitwarden-client-name", BITWARDEN_CLIENT_NAME)
            .header("bitwarden-client-version", BITWARDEN_CLIENT_VERSION)
            .bearer_auth(token);

        if let Some(user_agent) = &self.api.user_agent {
            builder = builder.header("user-agent", user_agent.clone());
        }

        builder.send().await.context("bitwarden sync request failed")
    }

    /// Ensures a usable token, serializing login only when expiry requires proactive renewal.
    async fn token(&self, config: &BitwardenProviderConfig) -> Result<(), BitwardenAuthError> {
        // Fast path: authenticated callers should not queue behind a refresh mutex.
        let refresh = self.stale().await;

        debug!(provider = %config.name, refresh, "checked bitwarden token freshness");
        if !refresh {
            return Ok(());
        }

        // Only one task should perform the network login. Re-check freshness after acquiring this
        // lock because another waiter may have refreshed the token while this task was queued.
        let _gate = self.gate.lock().await;
        if self.stale().await {
            self.login(config).await?;
        }

        Ok(())
    }

    /// Treats missing or soon-expiring authentication as requiring a fresh login.
    async fn stale(&self) -> bool {
        let state = self.state.lock().await;
        match state.exp {
            None => true,
            Some(exp) => Instant::now() + TOKEN_RENEWAL_WINDOW >= exp,
        }
    }

    /// Acquires a token and publishes it together with expiry and crypto readiness after success.
    ///
    /// The caller must hold `gate`, but not `state`, throughout login so proactive renewal and
    /// reactive 401 recovery cannot publish competing authentication state.
    async fn login(&self, config: &BitwardenProviderConfig) -> Result<(), BitwardenAuthError> {
        info!(provider = %config.name, "authenticating bitwarden session");

        // First obtain a new bearer token and the crypto bootstrap fields tied to that login.
        let response = request_api_key_token(&self.id, &config.client_id, &config.client_secret).await?;

        // Reject an unrepresentable server-provided TTL before publishing any authentication state.
        let exp = Instant::now()
            .checked_add(Duration::from_secs(response.expires_in))
            .ok_or(BitwardenAuthError::InvalidResponse)?;
        let crypto = !self.state.lock().await.crypto;

        if crypto {
            // Crypto bootstrap is only required once per provider lifetime because the keystore is
            // retained across token renewals.
            if let Err(error) = initialize_user_crypto(&self.store, &config.password, &response) {
                warn!(provider = %config.name, error = ?error, "failed to initialize bitwarden crypto");
                return Err(BitwardenAuthError::crypto_bootstrap(error));
            }

            info!(provider = %config.name, "bitwarden crypto initialized");
        }

        // Publish only usable authentication state. Cancellation or crypto failure before this
        // point must not leave a fresh-looking token paired with an uninitialized keystore.
        let mut state = self.state.lock().await;
        state.token = Some(response.access_token);
        state.exp = Some(exp);
        state.crypto = true;
        debug!(provider = %config.name, ttl = response.expires_in, crypto, "updated bitwarden auth state");

        Ok(())
    }
}
