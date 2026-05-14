//! Bitwarden provider construction and one-shot identity loading behavior.
//!
//! # Examples
//!
//! Validate configuration before any network access happens:
//!
//! ```
//! use keyring_providers::bitwarden::config::BitwardenProviderConfig;
//! use keyring_providers::bitwarden::provider::BitwardenProvider;
//!
//! let provider = BitwardenProvider::try_from(BitwardenProviderConfig {
//!     name: "vault".to_owned(),
//!     api_url: "https://api.bitwarden.example".to_owned(),
//!     identity_url: "https://identity.bitwarden.example".to_owned(),
//!     client_id: "client-id".to_owned(),
//!     client_secret: "client-secret".to_owned(),
//!     password: "master-password".to_owned(),
//! })
//! .unwrap();
//!
//! assert!(format!("{provider:?}").contains("BitwardenProvider"));
//! let error = BitwardenProvider::try_from(BitwardenProviderConfig {
//!     name: "   ".to_owned(),
//!     api_url: "https://api.bitwarden.example".to_owned(),
//!     identity_url: "https://identity.bitwarden.example".to_owned(),
//!     client_id: "client-id".to_owned(),
//!     client_secret: "client-secret".to_owned(),
//!     password: "master-password".to_owned(),
//! })
//! .unwrap_err();
//! assert_eq!(error.to_string(), "bitwarden provider name must not be empty");
//! ```
//!
//! Load identities from a real Bitwarden deployment when runtime credentials are available:
//!
//! ```no_run
//! use keyring_core::provider::KeyPairProvider;
//! use keyring_providers::bitwarden::config::BitwardenProviderConfig;
//! use keyring_providers::bitwarden::provider::BitwardenProvider;
//!
//! tokio::runtime::Runtime::new().unwrap().block_on(async {
//!     let provider = BitwardenProvider::try_from(BitwardenProviderConfig {
//!         name: "vault".to_owned(),
//!         api_url: std::env::var("BITWARDEN_API_URL").unwrap(),
//!         identity_url: std::env::var("BITWARDEN_IDENTITY_URL").unwrap(),
//!         client_id: std::env::var("BITWARDEN_CLIENT_ID").unwrap(),
//!         client_secret: std::env::var("BITWARDEN_CLIENT_SECRET").unwrap(),
//!         password: std::env::var("BITWARDEN_PASSWORD").unwrap(),
//!     })
//!     .unwrap();
//!     let keys = provider.load().await.unwrap();
//!
//!     assert!(!keys.is_empty());
//! });
//! ```

use super::crypto::{BitwardenKeyIds, decrypt_optional_string, resolve_cipher_key};
use super::models::BitwardenCipher;
use super::session::BitwardenSession;
use crate::bitwarden::config::BitwardenProviderConfig;
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bitwarden_crypto::KeyStore;
use keyring_core::cell::CacheCell;
use keyring_core::provider::{KeyPairProvider, KeyPairSnapshot};
use ssh_agent_lib::ssh_key::PrivateKey;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;
use tracing::{debug, error, info, trace};

/// Configured Bitwarden provider instance assembled by the CLI bootstrap path.
pub struct BitwardenProvider {
    /// Immutable provider configuration loaded from the root TOML document.
    config: BitwardenProviderConfig,
    /// Lazily initialized local Bitwarden session reused across load calls.
    session: OnceCell<BitwardenSession>,
    /// Time-bounded cache of decrypted SSH-key snapshots so agent requests do not trigger a full
    /// vault sync every time the service asks this provider to publish identities.
    keys: CacheCell<KeyPairSnapshot>,
}

#[async_trait]
impl KeyPairProvider for BitwardenProvider {
    async fn load(&self) -> Result<KeyPairSnapshot, anyhow::Error> {
        // Provider loads may happen repeatedly inside one agent lifetime. Keep the expensive vault
        // sync and decryption work behind a one-hour cache, but still surface the last refresh
        // error when the cache is cold or expired.
        debug!(provider = %self.config.name, "loading bitwarden provider keys");
        self.keys
            .get_or_try_init(Duration::from_secs(60 * 60), || async { self.fetch().await })
            .await
    }
}

impl TryFrom<BitwardenProviderConfig> for BitwardenProvider {
    type Error = anyhow::Error;

    /// Validates configuration and prepares a lazy Bitwarden provider instance.
    fn try_from(value: BitwardenProviderConfig) -> Result<Self, Self::Error> {
        if value.name.trim().is_empty() {
            bail!("bitwarden provider name must not be empty");
        }

        Ok(Self {
            config: value,
            session: OnceCell::default(),
            keys: CacheCell::default(),
        })
    }
}

impl Debug for BitwardenProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BitwardenProvider")
            .field("name", &self.config.name)
            .field("api_url", &self.config.api_url)
            .field("identity_url", &self.config.identity_url)
            .finish_non_exhaustive()
    }
}

impl BitwardenProvider {
    /// Executes one full Bitwarden refresh cycle and returns the currently discoverable SSH keys.
    async fn fetch(&self) -> Result<KeyPairSnapshot, anyhow::Error> {
        info!(provider = %self.config.name, "starting bitwarden fetch cycle");

        // Step 1: create or reuse the local Bitwarden session for this provider instance.
        let session = self
            .session
            .get_or_init(|| async { BitwardenSession::new(&self.config) })
            .await;

        // Step 2: fetch the latest vault snapshot.
        let response = session.sync(&self.config).await?;

        // Step 3: refresh organization keys before attempting to decrypt any item payloads.
        let profile = response
            .profile
            .as_deref()
            .context("bitwarden sync response missing profile")?;
        session.initialize_org_keys(profile)?;

        // Step 4: walk the synchronized ciphers and keep only usable SSH private keys.
        let keys = self.discover(response.ciphers.as_deref().unwrap_or(&[]), session.keystore());
        Ok(Arc::<[Arc<PrivateKey>]>::from(
            keys.into_iter().map(Arc::new).collect::<Vec<_>>(),
        ))
    }

    /// Walks the synchronized cipher list and keeps only successfully parsed SSH private keys.
    fn discover(&self, ciphers: &[BitwardenCipher], keystore: &KeyStore<BitwardenKeyIds>) -> Vec<PrivateKey> {
        // Preserve source order for logs and debugging, while letting `parse` decide which entries
        // are usable.
        let mut keys = vec![];
        debug!(provider = %self.config.name, count = ciphers.len(), "discovering bitwarden ssh keys");

        for cipher in ciphers {
            // Discovery failures are logged and skipped so one malformed vault entry does not
            // block unrelated SSH keys from being published.
            match Self::parse(cipher, keystore) {
                Ok(Some(key)) => keys.push(key),
                Ok(None) => {
                    debug!(provider = %self.config.name, cipher = ?cipher.id, "skipping non-usable bitwarden cipher");
                }
                Err(err) => {
                    error!(provider = %self.config.name, cipher = ?cipher.id, error = %err, "failed to parse bitwarden cipher");
                }
            }
        }

        keys
    }

    /// Converts one synchronized Bitwarden cipher into an SSH private key when possible.
    fn parse(cipher: &BitwardenCipher, keystore: &KeyStore<BitwardenKeyIds>) -> Result<Option<PrivateKey>> {
        // Guard clause group 1: only live SSH-key ciphers can produce identities.
        if !cipher.is_ssh_key() {
            trace!(cipher = ?cipher.id, kind = ?cipher.r#type, "skipping non-ssh bitwarden cipher");
            return Ok(None);
        }

        if cipher
            .deleted_date
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            trace!(cipher = ?cipher.id, "skipping deleted bitwarden cipher");
            return Ok(None);
        }

        // Guard clause group 2: the remaining steps require both an item id and an SSH-key payload.
        let Some(cipher_id) = cipher.id else {
            return Ok(None);
        };

        let Some(ssh_key) = cipher.ssh_key.as_ref() else {
            return Ok(None);
        };

        // Step 1: resolve the correct decryption key and decrypt the user-visible metadata plus
        // the OpenSSH private key text.
        let mut ctx = keystore.context_mut();
        let resolved_key = resolve_cipher_key(&mut ctx, cipher)?;
        let decrypted_name = decrypt_optional_string(&mut ctx, resolved_key, cipher.name.as_deref())?;
        let decrypted_private_key = decrypt_optional_string(&mut ctx, resolved_key, ssh_key.private_key.as_deref())?;

        // Missing private-key text means the cipher claims to be an SSH key but cannot currently
        // yield a usable identity.
        let Some(private_key_text) = decrypted_private_key else {
            return Ok(None);
        };

        // Step 2: choose a stable identity comment. A deterministic fallback keeps downstream
        // ordering stable even when the Bitwarden item name is blank.
        let comment = decrypted_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map_or_else(|| format!("bitwarden:{cipher_id}"), ToOwned::to_owned);

        // Step 3: parse the OpenSSH private key into the runtime representation used by the agent.
        let mut private_key = PrivateKey::from_openssh(&private_key_text)
            .with_context(|| format!("failed to parse bitwarden ssh private key for cipher {cipher_id}"))?;
        private_key.set_comment(comment);

        Ok(Some(private_key))
    }
}
