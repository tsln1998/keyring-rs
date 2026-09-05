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
use keyring_cli::platform::SignalEvent;
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
use tokio::sync::watch;
use tokio::task::{JoinError, JoinSet};
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

/// Cooperative budget for processing and writing one decoded request, excluding idle reads.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Bounds the shutdown drain without extending any request's original deadline.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> Result<()> {
    init();

    let args = Args::parse();
    info!(config = %args.config.display(), path = %args.path, "starting keyring foreground service");

    let mut signal = Signal::new()?;
    // Reject invalid local configuration before creating a socket clients could connect to.
    let agent = load(&args.config)?;

    // The socket path is supplied explicitly rather than derived from the config document.
    let mut socket = Listener::bind(&args.path).await?;
    info!(path = %args.path, "listener bound successfully");

    serve(&mut socket, &mut signal, &args.config, agent).await
}

/// Accepts clients continuously while configuration generations are replaced and drained.
///
/// Candidate construction leaves the active agent untouched until validation succeeds. Client
/// failures stay local to their tasks; listener failures still terminate this service loop.
async fn serve<S>(socket: &mut S, signal: &mut Signal, path: &Path, mut agent: ServiceAgent) -> Result<()>
where
    S: ListeningSocket + fmt::Debug + Send,
{
    // Track clients from every generation so shutdown also drains previously replaced agents.
    let mut jobs = JoinSet::new();
    // Allow one blocking config build at a time and coalesce additional signals into one re-read.
    let mut reloads = JoinSet::new();
    let mut reload_pending = false;
    // Each generation owns a separate stop channel; new clients subscribe only to the active one.
    let (mut stop, _) = watch::channel(false);

    loop {
        tokio::select! {
            // Handle ready control events and completed tasks before accepting another client.
            biased;

            event = signal.recv() => {
                match event {
                    SignalEvent::Reload => {
                        info!("received reload signal");
                        if reloads.is_empty() {
                            let path = path.to_owned();
                            // Config parsing reads from disk synchronously; keep it off this loop.
                            reloads.spawn_blocking(move || load(&path));
                        } else {
                            // Re-read once more after this build so changes made while it was
                            // running are not lost when several signals are coalesced.
                            reload_pending = true;
                        }
                    }
                    SignalEvent::Shutdown => {
                        info!("received shutdown signal");
                        break;
                    }
                }
            }

            loaded = reloads.join_next(), if !reloads.is_empty() => {
                match loaded {
                    Some(Ok(Ok(candidate))) => {
                        // No await separates the swap and notification, so the next accepted
                        // client gets both the new agent and its fresh stop channel.
                        agent = candidate;
                        stop.send_replace(true);
                        stop = watch::channel(false).0;
                        info!("configuration reloaded; draining old client sessions");
                    }
                    Some(Ok(Err(error))) => {
                        error!(error = ?error, "configuration reload failed; keeping current agent");
                    }
                    Some(Err(error)) => {
                        error!(error = ?error, "configuration reload task failed; keeping current agent");
                    }
                    None => {}
                }

                if reload_pending {
                    reload_pending = false;
                    let path = path.to_owned();
                    reloads.spawn_blocking(move || load(&path));
                }
            }

            joined = jobs.join_next(), if !jobs.is_empty() => {
                if let Some(joined) = joined {
                    report(joined);
                }
            }

            accepted = socket.accept() => {
                // Accepting happens on the service loop, while request handling is delegated to
                // one spawned task per client connection.
                let socket = accepted.map_err(|error| {
                    error!(error = ?error, "failed to accept client connection");
                    error
                })?;
                debug!("accepted client connection");

                let session = <ServiceAgent as Agent<S>>::new_session(&mut agent, &socket);
                let stop = stop.subscribe();
                jobs.spawn(async move {
                    if let Err(error) = handle::<S>(socket, session, stop).await {
                        error!(error = ?error, "client session failed");
                    } else {
                        debug!("client session closed cleanly");
                    }
                });
            }
        }
    }

    stop.send_replace(true);
    // Discard candidate results on shutdown. An already running blocking read cannot be aborted.
    reloads.abort_all();

    // Old generations were already notified at replacement. Notify the current one and allow
    // every in-flight request to finish within its original deadline before aborting stragglers.
    if timeout(SHUTDOWN_TIMEOUT, async {
        while let Some(joined) = jobs.join_next().await {
            report(joined);
        }
    })
    .await
    .is_err()
    {
        warn!("shutdown drain timed out; cancelling remaining client sessions");
        jobs.abort_all();
        while let Some(joined) = jobs.join_next().await {
            report(joined);
        }
    }

    Ok(())
}

/// Serves one client until disconnect, transport/protocol failure, request timeout, or drain.
///
/// A generation stop interrupts idle reads but lets an accepted request finish its response within
/// the existing deadline. Operational request failures become protocol failure responses.
async fn handle<S>(
    socket: S::Stream,
    mut session: impl Session,
    mut stop: watch::Receiver<bool>,
) -> Result<(), AgentError>
where
    S: ListeningSocket + fmt::Debug + Send,
{
    // `ssh-agent-lib` works with framed request/response objects; the codec owns message
    // boundaries on top of the raw Unix stream.
    let mut wire = Framed::new(socket, Codec::<Request, Response>::default());
    debug!("starting framed ssh-agent session");

    loop {
        // A stop received during the last request must take effect before reading the next one.
        if *stop.borrow() {
            break;
        }
        let req = tokio::select! {
            // Idle reads have no timeout, and a ready stop takes priority over a queued request.
            biased;
            _ = stop.changed() => break,
            req = wire.try_next() => req?,
        };
        let Some(req) = req else { break };
        debug!(request = ?req, "received ssh-agent request");

        // Reload only interrupts idle reads. An accepted request keeps its original deadline
        // through provider loading, authentication retries, signing, and the response write.
        timeout(REQUEST_TIMEOUT, async {
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
            Ok::<(), AgentError>(())
        })
        .await
        .map_err(AgentError::other)??;
    }

    debug!("client disconnected");
    Ok(())
}

/// Builds a startup or reload candidate using only configuration parsing and local validation.
///
/// Provider authentication and key loading remain lazy and are not validated by a successful load.
fn load(path: &Path) -> Result<ServiceAgent> {
    let config = Config::new(path).map_err(|error| {
        error!(config = %path.display(), error = ?error, "failed to load config");
        error
    })?;
    ServiceAgent::new(config.providers()?)
}

/// Logs unwinding client-task panics without propagating them into the service loop.
///
/// Cancellation is expected when the shutdown drain expires; request errors are logged in-task.
fn report(joined: Result<(), JoinError>) {
    if let Err(error) = joined
        && !error.is_cancelled()
    {
        error!(error = ?error, "client session task failed");
    }
}
