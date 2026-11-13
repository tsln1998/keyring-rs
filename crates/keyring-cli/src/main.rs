//! Foreground entrypoint for the agent service and its local control commands.

mod args;
mod config;
mod control;
mod init;
mod platform;
mod protocol;
mod server;

use anyhow::Result;
use args::{Args, Command};
use clap::Parser;
use config::Config;
use init::init;
use keyring_core::Store;
use platform::{Listener, Signal};
use std::{process::ExitCode, sync::Arc};

/// Dispatches control clients early, otherwise starts a locked service on the chosen endpoint.
#[tokio::main]
async fn main() -> ExitCode {
    init();
    let args = Args::parse();
    let path = match args.socket() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    if let Some(command) = args.command {
        // Clients use the running service's configuration, never a second local copy.
        if args.config.is_some() {
            eprintln!("--config is only accepted when starting the service");
            return ExitCode::from(2);
        }
        let result = match command {
            Command::Unlock => control::run(&path, control::Action::Unlock).await,
            Command::Refresh => control::refresh(&path).await,
            Command::Lock => control::run(&path, control::Action::Lock).await,
            Command::Status { json } => control::run(&path, control::Action::Status { json }).await,
        };
        return ExitCode::from(result);
    }
    let Some(config) = args.config else {
        eprintln!("--config is required when starting the service");
        return ExitCode::from(2);
    };
    let result = async {
        let configuration = Config::new(&config)?;
        // Backend construction may perform synchronous platform IPC.
        let stores = tokio::task::spawn_blocking(stores).await??;
        let agent = keyring_protocol::ServiceAgent::new(configuration.bitwarden, stores.clone())?;
        let mut signal = Signal::new()?;
        let mut listener = Listener::bind(&path).await?;
        server::serve(&mut listener, &mut signal, &config, agent, stores).await
    }
    .await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Creates the backends available on this platform, including the memory fallback.
///
/// Only real backend instances are returned. The actual platform backend stays in
/// the vector even if its initial availability probe fails; no placeholder is added.
fn stores() -> Result<Vec<Arc<dyn Store>>> {
    let stores: Vec<Arc<dyn Store>> = vec![
        #[cfg(target_os = "macos")]
        Arc::new(keyring_store_keychain::KeychainStore::new()),
        #[cfg(target_os = "linux")]
        Arc::new(keyring_store_freedesktop::FreeDesktopStore::new()?),
        Arc::new(keyring_store_memory::MemoryStore::default()),
    ];
    Ok(stores)
}
