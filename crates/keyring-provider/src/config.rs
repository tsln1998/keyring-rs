//! Connection and API-key settings for a Bitwarden account.
//!
//! The master password is supplied separately for each load and is never part of configuration.

use anyhow::{Result, bail};
use serde::Deserialize;
use zeroize::Zeroizing;

/// Configures the API and identity services used by an explicit vault load.
///
/// API credentials authorize remote requests; they do not replace the master password used to
/// decrypt the vault. Unknown configuration fields are rejected to surface mistakes early.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitwardenConfig {
    /// Base URL for vault operations, including `/sync`; deployment path prefixes are allowed.
    pub api_url: String,
    /// Base URL for the identity service that exposes `/connect/token`.
    pub identity_url: String,
    /// Bitwarden personal API-key client identifier.
    pub client_id: String,
    /// Bitwarden personal API-key secret; diagnostic formatting redacts this value.
    pub client_secret: Zeroizing<String>,
}

impl BitwardenConfig {
    /// Checks endpoint structure and rejects blank API credentials before making requests.
    ///
    /// HTTP is accepted for local or self-hosted endpoints. Credentials, queries, and fragments
    /// belong outside these base URLs so appending endpoint paths has an unambiguous meaning.
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [("api_url", &self.api_url), ("identity_url", &self.identity_url)] {
            let url = reqwest::Url::parse(value)?;
            if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
                bail!("invalid bitwarden {name}");
            }
            if !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                bail!("bitwarden {name} must not contain credentials, query, or fragment");
            }
        }
        if self.client_id.trim().is_empty() || self.client_secret.trim().is_empty() {
            bail!("bitwarden API credentials must not be empty");
        }
        Ok(())
    }
}
