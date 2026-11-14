//! Argument definitions shared by foreground service startup and control subcommands.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[cfg(unix)]
const SSH_AUTH_SOCK: &str = "/tmp/keyring.sock";

#[cfg(windows)]
const SSH_AUTH_SOCK: &str = r"\\.\pipe\openssh-ssh-agent";

/// Selects either service startup or a command sent to an existing local agent.
#[derive(Debug, Parser)]
#[command(name = "keyring", arg_required_else_help = true, disable_help_subcommand = true)]
pub struct Args {
    /// Socket or named-pipe override, accepted before or after the subcommand.
    #[arg(
        short,
        long,
        global = true,
        env = "SSH_AUTH_SOCK",
        value_name = "SOCKET",
        default_value = SSH_AUTH_SOCK,
    )]
    pub path: String,
    /// Configuration loaded at service startup; control commands use the running service.
    #[arg(short, long, value_name = "CONFIG", default_value = "config.toml")]
    pub config: PathBuf,
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
            assert_eq!(args.path, "test.sock");
            assert!(matches!(args.command, Some(Command::Status { json: true })));
        }
        for argv in [
            vec!["keyring", "--path", "test.sock", "refresh"],
            vec!["keyring", "refresh", "--path", "test.sock"],
        ] {
            let args = Args::try_parse_from(argv)?;
            assert_eq!(args.path, "test.sock");
            assert!(matches!(args.command, Some(Command::Refresh)));
        }
        Ok(())
    }
}
