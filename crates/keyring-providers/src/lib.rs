//! Built-in provider implementations shipped with `keyring-rs`.
//!
//! The workspace keeps provider code in a dedicated crate so the service runtime depends only
//! on the minimal trait surface from `keyring-core`.
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

pub mod bitwarden;
pub mod dummy;
