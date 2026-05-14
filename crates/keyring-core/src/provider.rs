//! Provider-facing key types and traits shared across the workspace.
//!
//! # Examples
//!
//! ```
//! use async_trait::async_trait;
//! use keyring_core::provider::KeyPairProvider;
//! use ssh_key::PrivateKey;
//!
//! struct StaticProvider;
//!
//! #[async_trait]
//! impl KeyPairProvider for StaticProvider {
//!     async fn load(&self) -> Result<Vec<PrivateKey>, anyhow::Error> {
//!         Ok(vec![])
//!     }
//! }
//!
//! tokio::runtime::Runtime::new().unwrap().block_on(async {
//!     let provider = StaticProvider;
//!     let keys = provider.load().await.unwrap();
//!
//!     assert!(keys.is_empty());
//! });
//! ```

use async_trait::async_trait;
use ssh_key::PrivateKey;

/// A configured identity source that can publish SSH private keys on demand.
#[async_trait]
pub trait KeyPairProvider: Send + Sync {
    /// Loads the provider's currently available SSH private keys.
    async fn load(&self) -> Result<Vec<PrivateKey>, anyhow::Error>;
}
