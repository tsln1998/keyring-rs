//! Strict service configuration loading with source text kept out of diagnostics.

use anyhow::{Context, Result};
use keyring_provider::config::BitwardenConfig;
use serde::Deserialize;
use std::{fs, path::Path};
use zeroize::Zeroizing;

/// The single provider configuration accepted by the foreground service.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bitwarden: BitwardenConfig,
}

impl Config {
    /// Reads and validates configuration, reporting field paths without echoing values.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        // The source contains API credentials; wipe this owned text buffer when it is dropped.
        let source = Zeroizing::new(fs::read_to_string(path.as_ref()).context("failed to read configuration")?);
        let deserializer = toml::de::Deserializer::new(&source);
        // Full parser errors can quote source fragments, so retain only the failing field path.
        let config: Self = serde_path_to_error::deserialize(deserializer)
            .map_err(|error| anyhow::anyhow!("invalid configuration at {}", error.path()))?;
        config.bitwarden.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    //! Configuration loading, credential redaction, and safe parser-error reporting.

    use super::*;

    /// Minimal configuration for a single Bitwarden account.
    const VALID: &str = "[bitwarden]\napi_url='https://api.example'\nidentity_url='https://identity.example'\nclient_id='id'\nclient_secret='secret'\n";

    /// Loads the current configuration and keeps API secrets out of debug output.
    #[test]
    fn loads_configuration_with_redacted_credentials() -> Result<()> {
        let config: Config = toml::from_str(VALID)?;
        config.bitwarden.validate()?;
        assert!(!format!("{config:?}").contains("client_secret: \"secret\""));
        Ok(())
    }

    /// Ensures rejected secret-bearing input is absent even from expanded error output.
    #[test]
    fn parse_errors_never_include_source_secrets() -> Result<()> {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new()?;
        let source = VALID.replace("client_secret='secret'", "client_secret=['do-not-log-this']");
        writeln!(file, "{source}")?;
        let error = Config::new(file.path()).expect_err("client_secret must be a string");
        assert!(!format!("{error:#?}").contains("do-not-log-this"));
        Ok(())
    }
}
