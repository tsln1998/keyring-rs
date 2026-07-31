//! Cross-platform listener wrapper for the foreground agent process.
//!
//! This module keeps platform-specific bind and socket lifecycle details out of `main.rs`.
//! On Unix it owns path unlinking on drop; on Windows it owns named-pipe creation together with
//! the custom security descriptor required by the foreground agent.

use anyhow::Result;
use ssh_agent_lib::agent::ListeningSocket;

#[cfg(windows)]
use core::future::pending;
#[cfg(windows)]
use std::ffi::{OsString, c_void};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io;
#[cfg(windows)]
use std::mem::size_of;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::time::Duration;
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeServer;
#[cfg(windows)]
use tokio::net::windows::named_pipe::ServerOptions;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
#[cfg(unix)]
use tokio::time::timeout;
#[cfg(unix)]
use tracing::warn;
use tracing::{debug, info};
#[cfg(windows)]
use windows::{
    Win32::{
        Foundation::{FALSE, HLOCAL, LocalFree},
        Security::{
            Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorA, SDDL_REVISION_1},
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
    },
    core::PSTR,
};

#[cfg(windows)]
struct NamedPipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

#[cfg(windows)]
impl NamedPipeSecurity {
    /// Builds the security descriptor used for the first named-pipe instance.
    ///
    /// The SDDL grants:
    /// - authenticated users read/write access so ordinary ssh clients can connect
    /// - administrators full access for local debugging and recovery
    /// - local system full access for service-style integrations
    fn new(sddl: &[u8]) -> windows::core::Result<Self> {
        unsafe {
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            let mut descriptor_size = 0u32;

            ConvertStringSecurityDescriptorToSecurityDescriptorA(
                PSTR::from_raw(sddl.as_ptr() as *mut u8),
                SDDL_REVISION_1,
                &mut descriptor,
                Some(&mut descriptor_size),
            )?;

            Ok(Self {
                descriptor,
                attributes: SECURITY_ATTRIBUTES {
                    nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: descriptor.0,
                    bInheritHandle: FALSE,
                },
            })
        }
    }

    /// Returns the raw pointer expected by Tokio's named-pipe constructor.
    fn mut_ptr(&mut self) -> *mut c_void {
        &mut self.attributes as *mut _ as *mut c_void
    }
}

#[cfg(windows)]
impl Drop for NamedPipeSecurity {
    fn drop(&mut self) {
        // Windows allocates the descriptor buffer inside
        // `ConvertStringSecurityDescriptorToSecurityDescriptorA`; release it once the pipe has
        // been created and the raw attributes are no longer needed.
        if !self.descriptor.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
            }
        }
    }
}

/// Foreground agent listener wrapper.
#[derive(Debug)]
pub struct Listener {
    #[cfg(windows)]
    inner: NamedPipeServer,
    #[cfg(windows)]
    path: OsString,
    #[cfg(unix)]
    inner: UnixListener,
    #[cfg(unix)]
    path: PathBuf,
}

/// Control event received by the foreground service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalEvent {
    Reload,
    Shutdown,
}

#[cfg(windows)]
#[derive(Debug, Default)]
pub struct Signal;

#[cfg(unix)]
#[derive(Debug)]
pub struct Signal {
    reload: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

impl Listener {
    /// Bind the foreground listener to the configured path.
    ///
    /// # Errors
    ///
    /// Returns any bind error reported by the underlying named-pipe listener.
    #[cfg(windows)]
    pub async fn bind(path: &str) -> Result<Self> {
        info!(path = %path, "binding windows named-pipe listener");

        let path = OsString::from(path);

        // The first instance is where Windows applies the explicit security descriptor.

        let inner = {
            let mut security = NamedPipeSecurity::new(
                // DACL: Allow Authenticated Users (Read/Write), System & Admins (Full Control)
                b"D:(A;;GRGW;;;AU)(A;;GA;;;BA)(A;;GA;;;SY)\0",
            )?;

            let mut options = ServerOptions::new();

            unsafe {
                options
                    .first_pipe_instance(true)
                    .access_inbound(true)
                    .access_outbound(true)
                    .create_with_security_attributes_raw(&path, security.mut_ptr())
            }
        }?;

        Ok(Self { inner, path })
    }

    /// Bind the foreground listener to the configured path.
    ///
    /// # Errors
    ///
    /// Returns any socket-bind or stale-socket cleanup error reported by the operating system.
    #[cfg(unix)]
    pub async fn bind(path: &str) -> Result<Self> {
        info!(path = %path, "binding unix socket listener");

        let path = PathBuf::from(path);
        let inner = bind_unix(&path).await?;

        Ok(Self { inner, path })
    }
}

#[cfg(unix)]
async fn bind_unix(path: &Path) -> io::Result<UnixListener> {
    match UnixListener::bind(path) {
        Ok(listener) => Ok(listener),
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
            if reclaim_stale_socket(path).await? {
                UnixListener::bind(path)
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
async fn reclaim_stale_socket(path: &Path) -> io::Result<bool> {
    let original = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => metadata,
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(error) => {
            debug!(path = %path.display(), error = ?error, "failed to inspect occupied unix socket path");
            return Ok(false);
        }
    };

    match timeout(Duration::from_secs(1), UnixStream::connect(path)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            return Ok(false);
        }
        Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionRefused => {}
        Ok(Err(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
        Ok(Err(error)) => {
            debug!(path = %path.display(), error = ?error, "unix socket probe was inconclusive");
            return Ok(false);
        }
        Err(error) => {
            debug!(path = %path.display(), error = ?error, "unix socket probe timed out");
            return Ok(false);
        }
    }

    let current = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(error) => {
            debug!(path = %path.display(), error = ?error, "failed to recheck stale unix socket path");
            return Ok(false);
        }
    };

    if !current.file_type().is_socket() || original.dev() != current.dev() || original.ino() != current.ino() {
        debug!(path = %path.display(), "unix socket path changed during stale-socket probe");
        return Ok(false);
    }

    warn!(path = %path.display(), "removing stale unix socket path");
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

#[ssh_agent_lib::async_trait]
impl ListeningSocket for Listener {
    #[cfg(windows)]
    type Stream = NamedPipeServer;
    #[cfg(unix)]
    type Stream = UnixStream;

    #[cfg(unix)]
    async fn accept(&mut self) -> io::Result<Self::Stream> {
        debug!(path = %self.path.display(), "waiting for unix socket client");
        self.inner.accept().await.map(|(stream, _addr)| stream)
    }

    #[cfg(windows)]
    async fn accept(&mut self) -> std::io::Result<Self::Stream> {
        debug!("waiting for named-pipe client");
        self.inner.connect().await?;

        // Hand the connected pipe instance to the caller, and leave a fresh server instance behind
        // so the listener remains ready for the next client.
        Ok(std::mem::replace(
            &mut self.inner,
            ServerOptions::new().create(&self.path)?,
        ))
    }
}

#[cfg(unix)]
impl Drop for Listener {
    fn drop(&mut self) {
        debug!(path = %self.path.display(), "removing unix socket path during listener drop");
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(windows)]
impl Signal {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    pub async fn recv(&mut self) -> SignalEvent {
        pending()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::Listener;
    use anyhow::Result;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
    use tempfile::tempdir;

    #[tokio::test]
    async fn reclaims_stale_socket_path() -> Result<()> {
        let directory = tempdir()?;
        let path = directory.path().join("agent.sock");
        let stale = StdUnixListener::bind(&path)?;
        drop(stale);

        let listener = Listener::bind(path.to_string_lossy().as_ref()).await?;
        assert!(path.exists());
        drop(listener);
        assert!(!path.exists());
        Ok(())
    }

    #[tokio::test]
    async fn preserves_active_socket_path() -> Result<()> {
        let directory = tempdir()?;
        let path = directory.path().join("agent.sock");
        let active = StdUnixListener::bind(&path)?;

        assert!(Listener::bind(path.to_string_lossy().as_ref()).await.is_err());
        let probe = StdUnixStream::connect(&path)?;
        drop(probe);
        drop(active);
        Ok(())
    }

    #[tokio::test]
    async fn preserves_regular_file_path() -> Result<()> {
        let directory = tempdir()?;
        let path = directory.path().join("agent.sock");
        fs::write(&path, "keep me")?;

        assert!(Listener::bind(path.to_string_lossy().as_ref()).await.is_err());
        assert_eq!(fs::read_to_string(&path)?, "keep me");
        Ok(())
    }

    #[tokio::test]
    async fn preserves_symbolic_link_path() -> Result<()> {
        let directory = tempdir()?;
        let target = directory.path().join("target");
        let path = directory.path().join("agent.sock");
        fs::write(&target, "keep me")?;
        symlink(&target, &path)?;

        assert!(Listener::bind(path.to_string_lossy().as_ref()).await.is_err());
        assert!(path.is_symlink());
        assert_eq!(fs::read_to_string(&target)?, "keep me");
        Ok(())
    }

    #[tokio::test]
    async fn removes_owned_socket_path_on_drop() -> Result<()> {
        let directory = tempdir()?;
        let path = directory.path().join("agent.sock");
        let listener = Listener::bind(path.to_string_lossy().as_ref()).await?;
        assert!(path.exists());

        drop(listener);

        assert!(!path.exists());
        Ok(())
    }
}

#[cfg(unix)]
impl Signal {
    pub fn new() -> Result<Self> {
        Ok(Self {
            reload: signal(SignalKind::user_defined1())?,
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    pub async fn recv(&mut self) -> SignalEvent {
        tokio::select! {
            _ = self.reload.recv() => SignalEvent::Reload,
            _ = self.interrupt.recv() => SignalEvent::Shutdown,
            _ = self.terminate.recv() => SignalEvent::Shutdown,
        }
    }
}
