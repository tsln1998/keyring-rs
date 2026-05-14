//! Cross-platform listener wrapper for the foreground agent process.
//!
//! This module keeps platform-specific bind and socket lifecycle details out of `main.rs`.
//! On Unix it owns path unlinking on drop; on Windows it delegates to `ssh-agent-lib`'s
//! named-pipe listener.

use anyhow::Result;
use ssh_agent_lib::agent::ListeningSocket;

use core::future::pending;
#[cfg(windows)]
use ssh_agent_lib::agent::NamedPipeListener;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, info};

/// Foreground agent listener wrapper.
#[derive(Debug)]
pub struct Listener {
    #[cfg(windows)]
    inner: NamedPipeListener,
    #[cfg(unix)]
    inner: UnixListener,
    #[cfg(unix)]
    socket_path: PathBuf,
}

#[derive(Debug, Default)]
pub struct Signal {
    // no-op
}

impl Listener {
    /// Bind the foreground listener to the configured path.
    ///
    /// # Errors
    ///
    /// Returns any bind error reported by the underlying named-pipe listener.
    #[cfg(windows)]
    pub fn bind(path: &str) -> Result<Self> {
        info!(path = %path, "binding windows named-pipe listener");
        Ok(Self {
            inner: NamedPipeListener::bind(path)?,
        })
    }

    /// Bind the foreground listener to the configured path.
    ///
    /// # Errors
    ///
    /// Returns any socket-bind error reported by the operating system.
    #[cfg(unix)]
    pub fn bind(path: &str) -> Result<Self> {
        // A pre-existing socket path is treated as an error so the caller does not silently steal
        // another process's advertised agent endpoint.
        info!(path = %path, "binding unix socket listener");
        Ok(Self {
            inner: UnixListener::bind(path)?,
            socket_path: path.into(),
        })
    }
}

#[ssh_agent_lib::async_trait]
impl ListeningSocket for Listener {
    #[cfg(windows)]
    type Stream = <NamedPipeListener as ListeningSocket>::Stream;
    #[cfg(unix)]
    type Stream = UnixStream;

    #[cfg(unix)]
    async fn accept(&mut self) -> io::Result<Self::Stream> {
        debug!(path = %self.socket_path.display(), "waiting for unix socket client");
        self.inner.accept().await.map(|(stream, _addr)| stream)
    }

    #[cfg(windows)]
    async fn accept(&mut self) -> std::io::Result<Self::Stream> {
        debug!("waiting for named-pipe client");
        self.inner.accept().await
    }
}

#[cfg(unix)]
impl Drop for Listener {
    fn drop(&mut self) {
        debug!(path = %self.socket_path.display(), "removing unix socket path during listener drop");
        let _ = fs::remove_file(&self.socket_path);
    }
}

#[cfg(windows)]
impl Signal {
    pub fn user_defined1(&self) -> impl Future<Output = ()> {
        pending()
    }

    pub fn interrupt(&self) -> impl Future<Output = ()> {
        pending()
    }
}

#[cfg(unix)]
impl Signal {
    pub async fn user_defined1(&self) {
        if let Ok(mut signal) = signal(SignalKind::user_defined1()) {
            signal.recv().await;
        } else {
            pending::<()>().await;
        }
    }

    pub async fn interrupt(&self) {
        if let Ok(mut signal) = signal(SignalKind::interrupt()) {
            signal.recv().await;
        } else {
            pending::<()>().await;
        }
    }
}
