//! Process-wide startup initialization for the foreground service binary.
//!
//! This module keeps one-time runtime setup separate from `main.rs` so the binary entrypoint
//! stays focused on argument parsing and service lifecycle control.

use tracing_subscriber::EnvFilter;

/// Performs all process-wide startup initialization required before the service begins serving.
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info,keyring_cli=debug,keyring_service=debug,keyring_providers=debug")
    });

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();

    let _ = rustls_rustcrypto::provider().install_default();
}
