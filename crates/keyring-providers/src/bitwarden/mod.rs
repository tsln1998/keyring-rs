//! Bitwarden-backed provider assembly, sync loading, and SSH key discovery support.
//!
//! This module provides a local Bitwarden integration tailored to this project:
//! authenticate with an API key, fetch `/sync`, decrypt SSH private keys, and expose them
//! through the common provider trait.
//!
//! # Examples
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
//! ```

mod auth;
pub mod config;
mod crypto;
mod models;
pub mod provider;
mod session;
