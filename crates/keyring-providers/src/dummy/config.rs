//! Configuration model for the in-memory dummy provider.
//!
//! # Examples
//!
//! ```
//! use keyring_providers::dummy::config::DummyProviderConfig;
//!
//! let config: DummyProviderConfig = serde_json::from_str(r#"{"name":"local"}"#).unwrap();
//! assert_eq!(config.name, "local");
//! ```

use serde::Deserialize;

/// Configuration for one dummy provider instance.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DummyProviderConfig {
    /// Human-readable identity group name used for validation and future diagnostics.
    pub name: String,
}
