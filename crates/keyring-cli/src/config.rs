//! Strict service configuration loading with source text kept out of diagnostics.

use anyhow::{Context, Result};
use garde::Validate;
use keyring_provider::config::BitwardenConfig;
use serde::Deserialize;
use std::{fs, path::Path};
use toml::de::Deserializer;
use zeroize::Zeroizing;

/// The single provider configuration accepted by the foreground service.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[garde(dive)]
    pub bitwarden: BitwardenConfig,
}

impl Config {
    /// Reads and validates configuration, reporting field paths without echoing values.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        // The source contains API credentials; wipe this owned text buffer when it is dropped.
        let source = Zeroizing::new(fs::read_to_string(path.as_ref()).context("failed to read configuration")?);
        let deserializer = Deserializer::parse(&source).map_err(|_| anyhow::anyhow!("invalid configuration"))?;
        let config = Config::deserialize(deserializer).map_err(|_| anyhow::anyhow!("invalid configuration"))?;
        config.validate()?;
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
        let source = VALID.replace(
            "client_secret='secret'",
            "client_secret='fixture-secret-never-in-debug'",
        );
        let config: Config = toml::from_str(&source)?;
        for config in [config.clone(), config] {
            config.validate()?;
            assert_eq!(config.bitwarden.client_secret.as_str(), "fixture-secret-never-in-debug");
            assert!(!format!("{config:?}").contains("fixture-secret-never-in-debug"));
        }
        Ok(())
    }

    /// Ensures rejected secret-bearing input is absent even from expanded error output.
    #[test]
    fn parse_errors_never_include_source_secrets() -> Result<()> {
        use std::io::Write;
        for secret in ["['do-not-log-this']", "'do-not-log-this"] {
            let mut file = tempfile::NamedTempFile::new()?;
            let source = VALID.replace("client_secret='secret'", &format!("client_secret={secret}"));
            writeln!(file, "{source}")?;
            let error = Config::new(file.path()).expect_err("invalid client_secret must be rejected");
            assert!(!format!("{error:#?}").contains("do-not-log-this"));
        }
        Ok(())
    }

    #[test]
    fn validation_errors_include_nested_paths_without_source_values() -> Result<()> {
        use std::io::Write;
        for (original, replacement, path) in [
            (
                "api_url='https://api.example'",
                "api_url='https://do-not-log-this@api.example'",
                "bitwarden.api_url",
            ),
            (
                "identity_url='https://identity.example'",
                "identity_url='https://identity.example/#do-not-log-this'",
                "bitwarden.identity_url",
            ),
            ("client_id='id'", "client_id='   '", "bitwarden.client_id"),
            (
                "client_secret='secret'",
                "client_secret='   '",
                "bitwarden.client_secret",
            ),
        ] {
            let source = VALID
                .replace(original, replacement)
                .replace("client_id='id'", "client_id='do-not-log-this'")
                .replace("client_secret='secret'", "client_secret='do-not-log-this'");
            let mut file = tempfile::NamedTempFile::new()?;
            writeln!(file, "{source}")?;
            let error = Config::new(file.path()).expect_err("invalid configuration must be rejected");
            assert!(error.to_string().contains(path));
            assert!(!format!("{error:#?}").contains("do-not-log-this"));
        }
        Ok(())
    }
}
