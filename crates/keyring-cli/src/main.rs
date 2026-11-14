//! Foreground entrypoint for the agent service and its local control commands.

mod args;
mod config;
mod control;
mod platform;
mod protocol;
mod server;

use anyhow::Result;
use args::{Args, Command};
use clap::Parser;
use config::Config;
use keyring_core::keystore::KeyStore;
use keyring_protocol::agent::Agent;
use keyring_provider::BitwardenProvider;
use std::sync::Arc;
use tokio::task::spawn_blocking;
use tracing_subscriber::EnvFilter;

/// Dispatches control clients early, otherwise starts a locked service on the chosen endpoint.
#[tokio::main]
async fn main() -> Result<()> {
    init();

    match Args::parse() {
        // Prompt locally for the password and ask the running agent to load the vault.
        Args {
            command: Some(Command::Unlock),
            path,
            ..
        } => {
            control::run(&path, control::Action::Unlock).await?;
        }
        // Ask the running agent to invalidate sessions and clear its stored keys.
        Args {
            command: Some(Command::Lock),
            path,
            ..
        } => {
            control::run(&path, control::Action::Lock).await?;
        }
        // Require a successful lock before prompting for a fresh unlock.
        Args {
            command: Some(Command::Refresh),
            path,
            ..
        } => {
            control::run(&path, control::Action::Lock).await?;
            control::run(&path, control::Action::Unlock).await?;
        }
        // Query the running agent and render its status as JSON or tables.
        Args {
            command: Some(Command::Status { json }),
            path,
            ..
        } => {
            control::run(&path, control::Action::Status { json }).await?;
        }
        // Load startup configuration and serve a locked agent until an explicit unlock.
        Args {
            command: None,
            config,
            path,
            ..
        } => {
            let cfg = Config::new(&config)?;
            let provider = Arc::new(BitwardenProvider::new(cfg.bitwarden)?);
            let agent = Agent::new(provider, stores().await?)?;
            server::serve(&path, agent).await?;
        }
    }

    Ok(())
}

/// Performs all process-wide startup initialization required before the service begins serving.
fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(true)
        .try_init();

    #[cfg(unix)]
    unsafe {
        // Disable normal core-file generation before credentials or key material are loaded.
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            tracing::warn!("could not disable core dumps");
        }
    }
    #[cfg(target_os = "linux")]
    unsafe {
        // Restrict Linux dump and ptrace access; this is not a guarantee against privileged access.
        if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
            tracing::warn!("could not disable process dumps");
        }
    }
}

/// Creates the backends available on this platform, including the memory fallback.
///
/// Only real backend instances are returned. The actual platform backend stays in
/// the vector even if its initial availability probe fails; no placeholder is added.
async fn stores() -> Result<Vec<Arc<dyn KeyStore>>> {
    #[cfg(target_os = "linux")]
    use keyring_store_freedesktop::FreeDesktopStore;
    #[cfg(target_os = "macos")]
    use keyring_store_keychain::KeychainStore;

    Ok(vec![
        #[cfg(target_os = "linux")]
        spawn_blocking(|| -> Result<Arc<dyn KeyStore>> { Ok(Arc::new(FreeDesktopStore::new()?)) }).await??,
        #[cfg(target_os = "macos")]
        spawn_blocking(|| -> Result<Arc<dyn KeyStore>> { Ok(Arc::new(KeychainStore::new())) }).await??,
        Arc::new(keyring_store_memory::MemoryStore::default()),
    ])
}
