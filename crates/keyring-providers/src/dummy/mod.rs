//! In-memory provider used for local development and integration-style tests.
//!
//! The dummy provider never touches disk or network. It simply manufactures a deterministic
//! keypair so the rest of the service stack can be exercised end to end.
//!
//! # Examples
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

pub mod config;
pub mod provider;
