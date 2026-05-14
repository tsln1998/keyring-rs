//! CLI-side configuration and argument types for the foreground service binary.
//!
//! The binary entrypoint lives in `main.rs`; this crate keeps the reusable startup pieces
//! separate so they can be tested and documented without the Tokio runtime wrapper.
//!
//! # Examples
//!
//! ```
//! use clap::Parser;
//! use keyring_cli::args::Args;
//! use keyring_cli::config::Config;
//! use std::io::Write;
//!
//! let mut file = tempfile::NamedTempFile::new().unwrap();
//! write!(file, "[[dummy]]\nname = \"local\"\n").unwrap();
//!
//! let args = Args::parse_from([
//!     "keyring",
//!     "--config",
//!     file.path().to_str().unwrap(),
//!     "--path",
//!     "/tmp/keyring-rs.sock",
//! ]);
//! let config = Config::new(&args.config).unwrap();
//!
//! assert_eq!(args.path, "/tmp/keyring-rs.sock");
//! assert_eq!(config.dummy.len(), 1);
//! assert!(config.bitwarden.is_empty());
//! ```

pub mod args;
pub mod config;
pub mod init;
pub mod platform;
