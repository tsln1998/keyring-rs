//! Configuration model for one Bitwarden-backed provider instance.
//!
//! # Examples
//!
//! ```
//! use keyring_providers::bitwarden::config::BitwardenProviderConfig;
//!
//! let config: BitwardenProviderConfig = serde_json::from_str(
//!     r#"{
//!         "name":"vault",
//!         "api_url":"https://api.bitwarden.example",
//!         "identity_url":"https://identity.bitwarden.example",
//!         "client_id":"client-id",
//!         "client_secret":"client-secret",
//!         "password":"master-password"
//!     }"#,
//! )
//! .unwrap();
//!
//! assert_eq!(config.name, "vault");
//! let debug = format!("{config:?}");
//! assert!(debug.contains("BitwardenProviderConfig"));
//! assert!(debug.contains("client_secret: \"***\""));
//! assert!(debug.contains("password: \"***\""));
//! ```

use serde::Deserialize;
use std::fmt;

/// Configuration for one Bitwarden-backed provider instance.
#[derive(Clone, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitwardenProviderConfig {
    /// Human-readable provider name used in configuration and diagnostics.
    pub name: String,
    /// Base URL for Bitwarden API requests such as `/sync`.
    pub api_url: String,
    /// Base URL for Bitwarden identity and login endpoints.
    pub identity_url: String,
    /// API key client identifier issued by Bitwarden.
    pub client_id: String,
    /// API key secret paired with `client_id`.
    pub client_secret: String,
    /// Master password used by the SDK to unlock vault crypto.
    pub password: String,
}

impl fmt::Debug for BitwardenProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitwardenProviderConfig")
            .field("name", &self.name)
            .field("api_url", &self.api_url)
            .field("identity_url", &self.identity_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"***")
            .field("password", &"***")
            .finish()
    }
}
