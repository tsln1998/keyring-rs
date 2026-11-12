//! Argument definitions shared by foreground service startup and control subcommands.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Selects either service startup or a command sent to an existing local agent.
#[derive(Debug, Parser)]
#[command(name = "keyring", arg_required_else_help = true, disable_help_subcommand = true)]
pub struct Args {
    /// Configuration read by the service; control commands do not accept this option.
    #[arg(short, long, value_name = "CONFIG")]
    pub config: Option<PathBuf>,
    /// Socket or named-pipe override, accepted before or after the subcommand.
    #[arg(short, long, global = true, value_name = "SOCKET")]
    pub path: Option<String>,
    /// Omission starts the foreground service; a subcommand targets an existing service.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// User-facing operations; refresh is composed locally from lock and unlock.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Loads the remote vault using a password entered interactively.
    Unlock,
    /// Clears the current snapshot before prompting for a new unlock password.
    Refresh,
    /// Invalidates sessions and asks the service to clear its storage backends.
    Lock,
    /// Reports agent state and backend information without prompting for a password.
    Status {
        #[arg(long)]
        json: bool,
    },
}

impl Args {
    /// Resolves an explicit endpoint, the client's SSH_AUTH_SOCK, or a service default.
    ///
    /// A client must identify an existing agent explicitly or through its environment;
    /// only a new service falls back to the platform's default endpoint.
    pub fn socket(&self) -> anyhow::Result<String> {
        if let Some(path) = &self.path {
            return Ok(path.clone());
        }
        if self.command.is_some() {
            return std::env::var("SSH_AUTH_SOCK").map_err(|_| anyhow::anyhow!("set SSH_AUTH_SOCK or pass --path"));
        }
        #[cfg(unix)]
        {
            Ok("/tmp/keyring.sock".into())
        }
        #[cfg(windows)]
        {
            Ok(r"\\.\pipe\openssh-ssh-agent".into())
        }
    }
}

#[cfg(test)]
mod tests {
    //! Argument placement for control commands.

    use super::*;

    /// Accepts the global socket override on either side of a subcommand.
    #[test]
    fn controls_accept_path_on_either_side_of_subcommand() -> anyhow::Result<()> {
        for argv in [
            vec!["keyring", "--path", "test.sock", "status", "--json"],
            vec!["keyring", "status", "--json", "--path", "test.sock"],
        ] {
            let args = Args::try_parse_from(argv)?;
            assert_eq!(args.socket()?, "test.sock");
            assert!(matches!(args.command, Some(Command::Status { json: true })));
        }
        for argv in [
            vec!["keyring", "--path", "test.sock", "refresh"],
            vec!["keyring", "refresh", "--path", "test.sock"],
        ] {
            let args = Args::try_parse_from(argv)?;
            assert_eq!(args.socket()?, "test.sock");
            assert!(matches!(args.command, Some(Command::Refresh)));
        }
        Ok(())
    }
}
