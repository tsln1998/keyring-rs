//! Connection and API-key settings for a Bitwarden account.
//!
//! The master password is supplied separately for each load and is never part of configuration.

use garde::Validate;
use serde::Deserialize;
use zeroize::Zeroizing;

/// Configures the API and identity services used by an explicit vault load.
///
/// API credentials authorize remote requests; they do not replace the master password used to
/// decrypt the vault. Unknown configuration fields are rejected to surface mistakes early.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct BitwardenConfig {
    /// Base URL for vault operations, including `/sync`; deployment path prefixes are allowed.
    #[garde(custom(http_endpoint))]
    pub api_url: String,
    /// Base URL for the identity service that exposes `/connect/token`.
    #[garde(custom(http_endpoint))]
    pub identity_url: String,
    /// Bitwarden personal API-key client identifier.
    #[garde(custom(not_blank))]
    pub client_id: String,
    /// Bitwarden personal API-key secret; diagnostic formatting redacts this value.
    #[garde(custom(not_blank))]
    pub client_secret: Zeroizing<String>,
}

fn http_endpoint(value: &str, _: &()) -> garde::Result {
    let url = reqwest::Url::parse(value).map_err(|_| garde::Error::new("invalid HTTP endpoint"))?;
    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
        return Err(garde::Error::new("must be an HTTP or HTTPS endpoint with a host"));
    }
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err(garde::Error::new("must not contain credentials, query, or fragment"));
    }
    Ok(())
}

fn not_blank(value: &str, _: &()) -> garde::Result {
    if value.trim().is_empty() {
        Err(garde::Error::new("must not be blank"))
    } else {
        Ok(())
    }
}
