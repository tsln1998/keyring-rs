//! Foreground `ssh-agent` compatible service entrypoint.
//!
//! The binary owns the Unix listener, handles reload and shutdown signals, and delegates
//! request processing to [`keyring_service::runtime::ServiceAgent`].
//!
//! # Examples
//!
//! ```no_run
//! use std::process::Command;
//!
//! let status = Command::new("keyring")
//!     .args([
//!         "--config",
//!         "./keyring-rs.toml",
//!         "--path",
//!         "/tmp/keyring-rs.sock",
//!     ])
//!     .status()
//!     .unwrap();
//!
//! assert!(status.success());
//! ```

use anyhow::Result;
use clap::Parser;
use core::fmt;
use futures_util::SinkExt;
use futures_util::TryStreamExt as _;
use keyring_cli::args::Args;
use keyring_cli::config::Config;
use keyring_cli::init::init;
use keyring_cli::platform::Listener;
use keyring_cli::platform::Signal;
use keyring_service::runtime::ServiceAgent;
use ssh_agent_lib::agent::Agent;
use ssh_agent_lib::agent::ListeningSocket;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::codec::Codec;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::Request;
use ssh_agent_lib::proto::Response;
use std::path::Path;
use std::time::Duration;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing::{debug, error, info};

type Job = std::result::Result<(), tokio::time::error::Elapsed>;

#[tokio::main]
async fn main() -> Result<()> {
    init();

    let args = Args::parse();
    info!(config = %args.config.display(), path = %args.path, "starting keyring foreground service");

    // The socket path is supplied explicitly rather than derived from the config document.
    let mut socket = Listener::bind(&args.path)?;
    info!(path = %args.path, "listener bound successfully");

    loop {
        // Rebuild the full agent state on each requested reload so provider configuration is
        // always read from disk again before the new loop starts serving traffic.
        let config = load(&args.config)?;

        if serve(&mut socket, config).await? {
            info!("shutdown requested");
            break;
        }
        info!("reload requested");
    }

    Ok(())
}
/// Runs one service generation until a reload or shutdown signal arrives.
async fn serve<S>(socket: &mut S, config: Config) -> Result<bool>
where
    S: ListeningSocket + fmt::Debug + Send,
{
    // `true` means the outer loop should stop after this generation; `false` means rebuild the
    // config and start serving a fresh generation on the same bound listener.
    let shutdown;

    let mut agent = ServiceAgent::new(config.providers().map_err(|error| {
        error!(error = ?error, "failed to construct providers from config");
        error
    })?)?;

    // Keep spawned client tasks in a local join set so this generation can drain them before the
    // next reload or final shutdown returns control to `main`.
    let mut jobs = JoinSet::<Job>::new();
    let signal = Signal::default();

    loop {
        tokio::select! {
            () = signal.user_defined1() => {
                info!("received reload signal");
                shutdown = false;
                break;
            }

            () = signal.interrupt() => {
                info!("received shutdown signal");
                shutdown = true;
                break;
            }

            accepted = socket.accept() => {
                // Accepting happens on the generation task, while request handling is delegated to
                // one spawned task per client connection.
                let socket = accepted.map_err(|error| {
                    error!(error = ?error, "failed to accept client connection");
                    error
                })?;
                debug!("accepted client connection");

                // Each accepted Unix stream receives its own agent session so key caching stays
                // scoped to the lifetime of that client connection. The outer timeout bounds how
                // long this generation waits for the spawned handler future to finish.
                jobs.spawn(timeout(Duration::from_secs(30), {
                    let session = <ServiceAgent as Agent<S>>::new_session(&mut agent, &socket);
                    async move {
                        if let Err(error) = handle::<S>(socket, session).await {
                            error!(error = ?error, "client session failed");
                        } else {
                            debug!("client session closed cleanly");
                        }
                    }
                }));
            }

            joined = jobs.join_next(), if !jobs.is_empty() => {
                if let Some(joined) = joined {
                    // Surface both join failures and timeout wrappers immediately so the current
                    // service generation does not silently drop handler failures.
                    wait(joined)?;
                }
            }
        }
    }

    // Drain the remaining spawned handlers before finishing this generation so reload/shutdown
    // observes a quiescent task set.
    while let Some(joined) = jobs.join_next().await {
        wait(joined)?;
    }

    Ok(shutdown)
}

/// Serves one connected ssh-agent client until disconnect or protocol failure.
async fn handle<S>(socket: S::Stream, mut session: impl Session) -> Result<(), AgentError>
where
    S: ListeningSocket + fmt::Debug + Send,
{
    // `ssh-agent-lib` works with framed request/response objects; the codec owns message
    // boundaries on top of the raw Unix stream.
    let mut wire = Framed::new(socket, Codec::<Request, Response>::default());
    debug!("starting framed ssh-agent session");

    while let Some(req) = wire.try_next().await? {
        debug!(request = ?req, "received ssh-agent request");
        // Protocol-level request failures should still yield an agent response instead of
        // aborting the whole client connection. This matches `ssh-agent-lib`'s built-in
        // listen loop while keeping our local tracing around each request.
        let res = match session.handle(req).await {
            Ok(res) => res,
            Err(AgentError::ExtensionFailure) => {
                error!("agent extension request failed");
                Response::ExtensionFailure
            }
            Err(error) => {
                error!(error = ?error, "agent request handling failed");
                Response::Failure
            }
        };

        debug!(response = ?res, "sending ssh-agent response");
        wire.send(res).await?;
        debug!("sent ssh-agent response");
    }

    debug!("client disconnected");
    Ok(())
}

fn load(path: &Path) -> Result<Config> {
    Config::new(path).map_err(|error| {
        error!(config = %path.display(), error = ?error, "failed to load config");
        error
    })
}

fn wait(joined: std::result::Result<Job, tokio::task::JoinError>) -> Result<()> {
    let result = joined.map_err(|error| {
        error!(error = ?error, "failed to handle client connection");
        error
    })?;

    result.map_err(|error| {
        error!(error = ?error, "timeout when handle client connection");
        error
    })?;

    Ok(())
}
