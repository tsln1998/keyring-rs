//! Dummy provider construction and identity loading behavior.
//!
//! # Examples
//!
//! Build a deterministic `ed25519` provider and load its single key:
//!
//! ```
//! use keyring_core::provider::KeyPairProvider;
//! use keyring_providers::dummy::config::DummyProviderConfig;
//! use keyring_providers::dummy::provider::DummyProvider;
//!
//! tokio::runtime::Runtime::new().unwrap().block_on(async {
//!     let provider = DummyProvider::try_from(DummyProviderConfig {
//!         name: "local".to_owned(),
//!     })
//!     .unwrap();
//!     let keys = provider.load().await.unwrap();
//!
//!     assert_eq!(keys.len(), 1);
//!     assert_eq!(keys[0].algorithm().as_str(), "ssh-ed25519");
//! });
//! ```
//!
//! Reject blank provider names:
//!
//! ```
//! use keyring_providers::dummy::config::DummyProviderConfig;
//! use keyring_providers::dummy::provider::DummyProvider;
//!
//! let error = DummyProvider::try_from(DummyProviderConfig {
//!     name: "   ".to_owned(),
//! })
//! .unwrap_err();
//! assert_eq!(error.to_string(), "dummy provider name must not be empty");
//! ```

use crate::dummy::config::DummyProviderConfig;
use anyhow::{Result, bail};
use async_trait::async_trait;
use keyring_core::provider::{KeyPairProvider, KeyPairSnapshot};
use ssh_agent_lib::ssh_key::PrivateKey;
use ssh_agent_lib::ssh_key::private::Ed25519Keypair;
use std::sync::Arc;

/// Configured dummy provider instance used to exercise runtime plumbing end-to-end.
#[derive(Clone, Debug)]
pub struct DummyProvider {
    /// Deterministic test identities published by this provider instance as one shared snapshot.
    identities: KeyPairSnapshot,
}

#[async_trait]
impl KeyPairProvider for DummyProvider {
    async fn load(&self) -> Result<KeyPairSnapshot, anyhow::Error> {
        Ok(Arc::clone(&self.identities))
    }
}

impl TryFrom<DummyProviderConfig> for DummyProvider {
    type Error = anyhow::Error;

    /// Builds a dummy provider with one deterministic `ed25519` identity.
    fn try_from(value: DummyProviderConfig) -> Result<Self, Self::Error> {
        let name = value.name;

        if name.trim().is_empty() {
            bail!("dummy provider name must not be empty");
        }

        Ok(Self {
            // A fixed seed keeps tests and local manual verification stable across restarts.
            identities: Arc::<[Arc<PrivateKey>]>::from([Arc::new(PrivateKey::from(Ed25519Keypair::from_seed(
                &[7_u8; 32],
            )))]),
        })
    }
}
