//! Owns authentication and account crypto for a single explicit vault load.
//!
//! Sessions are not cached by the provider. The only token renewal is a bounded retry of a rejected
//! sync request while this load is already in progress.

use crate::{
    auth::{BitwardenAuthError, request_api_key_token},
    config::BitwardenConfig,
    crypto::{BitwardenKeyIds, initialize_org_keys, initialize_user_crypto},
    models::BitwardenSyncResponse,
};
use anyhow::{Context, Result, bail};
use bitwarden_crypto::KeyStore;
use keyring_core::SecrecyBytes;
use reqwest::{Client, StatusCode};
use secrecy::ExposeSecret;
use std::time::Duration;
use zeroize::Zeroizing;

/// Short-lived account state shared between initial unlock, sync, and item decryption.
///
/// The password is consumed during initialization rather than stored here. API credentials, a bearer
/// token, and unwrapped account keys remain owned by this session until its load finishes.
pub(crate) struct BitwardenSession {
    /// Endpoint settings and API credentials used for this load's sync and optional rejected-token retry.
    config: BitwardenConfig,
    /// Shared HTTP client used for identity and vault requests.
    client: Client,
    /// Account and organization keys needed by the current snapshot's item decryptions.
    pub(crate) store: KeyStore<BitwardenKeyIds>,
    /// Owns the current bearer token in a wrapper that wipes its allocation on drop.
    token: Zeroizing<String>,
}

impl BitwardenSession {
    /// Exchanges API credentials, then uses the supplied password to initialize account keys locally.
    ///
    /// Network timeouts cover requests, not the blocking KDF. Once the blocking closure starts,
    /// cancelling the awaiting future does not interrupt it or immediately release its inputs.
    pub(crate) async fn unlock(config: BitwardenConfig, password: SecrecyBytes) -> Result<Self> {
        let client = Client::builder()
            .user_agent("keyring-rs")
            .connect_timeout(Duration::from_secs(5))
            .read_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()?;
        let mut token =
            request_api_key_token(&client, &config.identity_url, &config.client_id, &config.client_secret).await?;
        let store = KeyStore::default();
        // Password derivation can be CPU- and memory-intensive, so it must not block Tokio workers.
        // Moving its inputs here ties their lifetime to the closure even if the caller goes away.
        let store = tokio::task::spawn_blocking(move || {
            let password_text = std::str::from_utf8(password.expose_secret()).context("password must be UTF-8")?;
            initialize_user_crypto(&store, password_text, &token).map_err(BitwardenAuthError::CryptoBootstrap)?;
            drop(password);
            // Transfer the bearer string without cloning it; the token response drops other fields.
            Ok::<_, anyhow::Error>((store, Zeroizing::new(std::mem::take(&mut token.access_token))))
        })
        .await??;
        Ok(Self {
            config,
            client,
            store: store.0,
            token: store.1,
        })
    }

    /// Obtains a replacement bearer token for this load without repeating master-password derivation.
    ///
    /// Already initialized account keys remain in the session; renewal is only an HTTP credential
    /// recovery step, not an independent refresh of decrypted vault state.
    async fn renew(&mut self) -> Result<()> {
        let mut response = request_api_key_token(
            &self.client,
            &self.config.identity_url,
            &self.config.client_id,
            &self.config.client_secret,
        )
        .await?;
        self.token = Zeroizing::new(std::mem::take(&mut response.access_token));
        Ok(())
    }

    /// Downloads the snapshot and imports organization keys before individual ciphers are decrypted.
    ///
    /// Only a 401 triggers renewal, and only once. Other HTTP errors, invalid payloads, and
    /// organization-key failures terminate the load rather than starting a background retry.
    pub(crate) async fn sync(&mut self) -> Result<BitwardenSyncResponse> {
        for attempt in 0..2 {
            let response = self
                .client
                .get(format!("{}/sync", self.config.api_url.trim_end_matches('/')))
                .query(&[("excludeDomains", "true")])
                // Request the web-client payload shape consumed by the local SSH-key models.
                .header("bitwarden-client-name", "web")
                .header("bitwarden-client-version", "2026.3.1")
                .bearer_auth(self.token.as_str())
                .send()
                .await
                .context("bitwarden sync request failed")?;
            if response.status() == StatusCode::UNAUTHORIZED {
                drop(response);
                use zeroize::Zeroize;
                // Discard the rejected credential before requesting or rejecting its replacement.
                self.token.zeroize();
                if attempt == 1 {
                    bail!("bitwarden sync rejected refreshed token");
                }
                self.renew().await?;
                continue;
            }
            let response = response.error_for_status().context("bitwarden sync failed")?;
            let sync: BitwardenSyncResponse =
                serde_json::from_slice(&response.bytes().await?).context("invalid bitwarden sync response")?;
            let profile = sync
                .profile
                .as_deref()
                .context("bitwarden sync response missing profile")?;
            // Organization-key initialization is a snapshot-wide prerequisite, unlike item decryption.
            initialize_org_keys(&self.store, profile)?;
            return Ok(sync);
        }
        bail!("bitwarden sync failed")
    }
}

impl Drop for BitwardenSession {
    /// Clears the SDK keystore before remaining session fields are dropped.
    ///
    /// This ends the session's key ownership; it does not promise erasure of all library or OS copies.
    fn drop(&mut self) {
        self.store.clear();
    }
}
