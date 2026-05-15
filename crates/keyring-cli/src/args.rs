//! Command-line argument parsing for the single supported foreground service mode.
//!
//! # Examples
//!
//! ```
//! use clap::Parser;
//! use keyring_cli::args::Args;
//!
//! let args = Args::parse_from([
//!     "keyring",
//!     "--config",
//!     "./keyring-rs.toml",
//!     "--path",
//!     "/tmp/keyring-rs.sock",
//! ]);
//!
//! assert_eq!(args.config.to_string_lossy(), "./keyring-rs.toml");
//! assert_eq!(args.path, "/tmp/keyring-rs.sock");
//! ```

use clap::Parser;
use std::path::PathBuf;

/// Process arguments accepted by the `keyring` binary.
#[derive(Debug, Parser, Eq, PartialEq)]
#[command(name = "keyring", arg_required_else_help = true, disable_help_subcommand = true)]
pub struct Args {
    /// Path to the TOML configuration document that declares providers.
    #[arg(short, long, value_name = "CONFIG")]
    pub config: PathBuf,

    /// Unix socket path that the foreground agent process should bind to.
    #[cfg(unix)]
    #[arg(short, long, value_name = "PATH", default_value_t = String::from(r"/tmp/keyring.sock"))]
    pub path: String,

    /// Windows pipe name that the foreground agent process should bind to.
    #[cfg(windows)]
    #[arg(short, long, value_name = "PATH", default_value_t = String::from(r"\\.\pipe\openssh-ssh-agent"))]
    pub path: String,
}
