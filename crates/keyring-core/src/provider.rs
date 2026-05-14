//! Provider-facing key types and traits shared across the workspace.
//!
//! # Examples
//!
//! ```
//! use std::sync::Arc;
//!
//! use async_trait::async_trait;
//! use keyring_core::provider::{KeyPair, KeyPairProvider, KeyPairSnapshot};
//! use ssh_key::PrivateKey;
//!
//! struct StaticProvider;
//!
//! #[async_trait]
//! impl KeyPairProvider for StaticProvider {
//!     async fn load(&self) -> Result<KeyPairSnapshot, anyhow::Error> {
//!         Ok(Arc::<[KeyPair]>::from([]))
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
use std::sync::Arc;

/// Shared private key handle published by providers and cached by sessions.
pub type KeyPair = Arc<PrivateKey>;

/// Shared immutable key snapshot returned by providers.
pub type KeyPairSnapshot = Arc<[KeyPair]>;

/// A configured identity source that can publish SSH private keys on demand.
#[async_trait]
pub trait KeyPairProvider: Send + Sync {
    /// Loads the provider's currently available SSH private keys as a shared immutable snapshot.
    ///
    /// Implementations should return keys in stable order because sessions may reuse the snapshot
    /// directly without re-sorting it.
    async fn load(&self) -> Result<KeyPairSnapshot, anyhow::Error>;
}
