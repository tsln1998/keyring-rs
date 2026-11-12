//! Process-wide startup initialization for the foreground service binary.
//!
//! This module keeps one-time runtime setup separate from `main.rs` so the binary entrypoint
//! stays focused on argument parsing and service lifecycle control.

use tracing_subscriber::EnvFilter;

/// Performs all process-wide startup initialization required before the service begins serving.
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
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
