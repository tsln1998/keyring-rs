//! Configuration loading, serde parsing, and static validation for the CLI service.
//!
//! # Examples
//!
//! Load a configuration document from disk:
//!
//! ```
//! use keyring_cli::config::Config;
//! use std::io::Write;
//!
//! let mut file = tempfile::NamedTempFile::new().unwrap();
//! write!(file, "[[dummy]]\nname = \"local\"\n").unwrap();
//!
//! let config = Config::new(file.path()).unwrap();
//! assert_eq!(config.dummy.len(), 1);
//! assert!(config.bitwarden.is_empty());
//! ```
//!
//! Build provider instances in declaration order:
//!
//! ```
//! use keyring_cli::config::Config;
//! use keyring_providers::dummy::config::DummyProviderConfig;
//!
//! let config = Config {
//!     dummy: vec![DummyProviderConfig {
//!         name: "local".to_owned(),
//!     }],
//!     bitwarden: vec![],
//! };
//!
//! let providers = config.providers().unwrap();
//! assert_eq!(providers.len(), 1);
//! ```

use anyhow::{Context, Result};
use keyring_core::provider::KeyPairProvider;
use keyring_providers::bitwarden::config::BitwardenProviderConfig;
use keyring_providers::bitwarden::provider::BitwardenProvider;
use keyring_providers::dummy::config::DummyProviderConfig;
use keyring_providers::dummy::provider::DummyProvider;
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Full startup document consumed by the CLI bootstrap path.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Dummy providers instantiated for local development or test-style setups.
    #[serde(default)]
    pub dummy: Vec<DummyProviderConfig>,

    /// Bitwarden-backed providers instantiated from remote vault configuration.
    #[serde(default)]
    pub bitwarden: Vec<BitwardenProviderConfig>,
}

impl Config {
    /// Loads, parses, and validates a configuration document from disk.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or when the TOML payload fails validation.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let source = fs::read_to_string(path).with_context(|| format!("failed to read config {}", path.display()))?;
        let deserializer = toml::de::Deserializer::new(&source);
        serde_path_to_error::deserialize(deserializer)
            .with_context(|| format!("failed to parse config {}", path.display()))
    }

    /// Builds provider objects from the configured provider sections.
    ///
    /// # Errors
    ///
    /// Returns the first provider-construction error encountered while walking the config.
    pub fn providers(self) -> Result<Vec<Box<dyn KeyPairProvider>>> {
        self.dummy
            .into_iter()
            .map(|cfg| DummyProvider::try_from(cfg).map(|provider| Box::new(provider) as Box<dyn KeyPairProvider>))
            .chain(self.bitwarden.into_iter().map(|cfg| {
                BitwardenProvider::try_from(cfg).map(|provider| Box::new(provider) as Box<dyn KeyPairProvider>)
            }))
            .collect()
    }
}
