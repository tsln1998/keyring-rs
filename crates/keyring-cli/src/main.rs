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
use std::time::Duration;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing::{debug, error, info};

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
        let config = match Config::new(&args.config) {
            Ok(config) => config,
            Err(error) => {
                error!(config = %args.config.display(), error = ?error, "failed to load config");
                return Err(error);
            }
        };

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

    let mut agent = ServiceAgent::new(match config.providers() {
        Ok(providers) => providers,
        Err(error) => {
            error!(error = ?error, "failed to construct providers from config");
            return Err(error);
        }
    })?;

    // Keep spawned client tasks in a local join set so this generation can drain them before the
    // next reload or final shutdown returns control to `main`.
    let mut spawner = JoinSet::<Result<_, _>>::new();

    loop {
        let signal = Signal::default();

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
                let socket = match accepted {
                    Ok(socket) => {
                        debug!("accepted client connection");
                        socket
                    }
                    Err(error) => {
                        error!(error = ?error, "failed to accept client connection");
                        return Err(error.into());
                    }
                };

                // Each accepted Unix stream receives its own agent session so key caching stays
                // scoped to the lifetime of that client connection. The outer timeout bounds how
                // long this generation waits for the spawned handler future to finish.
                spawner.spawn(timeout(Duration::from_secs(30), {
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

            joined = spawner.join_next(), if !spawner.is_empty() => {
                if let Some(joined) = joined {
                    // Surface both join failures and timeout wrappers immediately so the current
                    // service generation does not silently drop handler failures.
                    joined
                        .map_err(|error| {
                            error!(error = ?error, "failed to handle client connection");
                            error
                        })?
                        .map_err(|error| {
                            error!(error = ?error, "timeout when handle client connection");
                            error
                        })?;
                }
            }
        }
    }

    // Drain the remaining spawned handlers before finishing this generation so reload/shutdown
    // observes a quiescent task set.
    while let Some(joined) = spawner.join_next().await {
        joined
            .map_err(|error| {
                error!(error = ?error, "failed to handle client connection");
                error
            })?
            .map_err(|error| {
                error!(error = ?error, "timeout when handle client connection");
                error
            })?;
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
    let mut adapter = Framed::new(socket, Codec::<Request, Response>::default());
    debug!("starting framed ssh-agent session");

    loop {
        if let Some(incoming) = adapter.try_next().await? {
            debug!(request = ?incoming, "received ssh-agent request");
            // Protocol-level request failures should still yield an agent response instead of
            // aborting the whole client connection. This matches `ssh-agent-lib`'s built-in
            // listen loop while keeping our local tracing around each request.
            let response = match session.handle(incoming).await {
                Ok(response) => response,
                Err(AgentError::ExtensionFailure) => {
                    error!("agent extension request failed");
                    Response::ExtensionFailure
                }
                Err(error) => {
                    error!(error = ?error, "agent request handling failed");
                    Response::Failure
                }
            };

            debug!(response = ?response, "sending ssh-agent response");
            adapter.send(response).await?;
            debug!("sent ssh-agent response");
        } else {
            debug!("client disconnected");
            return Ok(());
        }
    }
}
