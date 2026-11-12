//! Command-line service wiring, local control clients, and SSH-agent transport support.
//!
//! The protocol crate owns agent state; this crate supplies the process, configuration,
//! platform listeners, and concrete storage backends needed to run it.

pub mod args;
pub mod config;
pub mod control;
pub mod init;
pub mod platform;
pub mod protocol;
pub mod server;

use anyhow::Result;
use keyring_core::Store;
use std::sync::Arc;

/// Creates the backends available on this platform, including the memory fallback.
///
/// Only real backend instances are returned. The actual platform backend stays in
/// the vector even if its initial availability probe fails; no placeholder is added.
pub fn stores() -> Result<Vec<Arc<dyn Store>>> {
    let stores: Vec<Arc<dyn Store>> = vec![
        #[cfg(target_os = "macos")]
        Arc::new(keyring_store_keychain::KeychainStore::new()),
        #[cfg(target_os = "linux")]
        Arc::new(keyring_store_freedesktop::FreeDesktopStore::new()?),
        Arc::new(keyring_store_memory::MemoryStore::default()),
    ];
    Ok(stores)
}
