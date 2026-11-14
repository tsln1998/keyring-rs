//! Cross-platform listener wrapper for the foreground agent process.
//!
//! This module keeps platform-specific bind and socket lifecycle details out of `main.rs`.
//! On Unix it owns path unlinking on drop; on Windows it owns named-pipe creation together with
//! the custom security descriptor required by the foreground agent.
//!
//! These endpoints carry ordinary local IPC traffic. Unix mode bits and the Windows DACL
//! control access; neither wrapper adds encryption to the SSH-agent protocol.

use anyhow::Result;

#[cfg(windows)]
use std::ffi::{OsString, c_void};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io;
#[cfg(windows)]
use std::mem::size_of;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::path::PathBuf;
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

/// Owns the Windows-allocated descriptor and the attributes that borrow its buffer.
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

/// Platform notifications that request service shutdown.
#[derive(Debug)]
pub struct Signal {
    #[cfg(windows)]
    interrupt: tokio::signal::windows::CtrlC,
    #[cfg(windows)]
    close: tokio::signal::windows::CtrlClose,
    #[cfg(windows)]
    shutdown: tokio::signal::windows::CtrlShutdown,
    #[cfg(windows)]
    ctrl_break: tokio::signal::windows::CtrlBreak,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
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
        let inner = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(bind_error) if bind_error.kind() == io::ErrorKind::AddrInUse => {
                'reclaim: {
                    // Inspect the directory entry itself, so a symlink is never followed during reclamation.
                    let original = match fs::symlink_metadata(&path) {
                        Ok(metadata) if metadata.file_type().is_socket() => metadata,
                        Ok(_) => return Err(bind_error.into()),
                        Err(error) if error.kind() == io::ErrorKind::NotFound => break 'reclaim,
                        Err(error) => {
                            debug!(path = %path.display(), error = ?error, "failed to inspect occupied unix socket path");
                            return Err(bind_error.into());
                        }
                    };

                    // Only connection refusal establishes staleness; timeout or other errors are inconclusive.
                    match timeout(Duration::from_secs(1), UnixStream::connect(&path)).await {
                        Ok(Ok(stream)) => {
                            drop(stream);
                            return Err(bind_error.into());
                        }
                        Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionRefused => {}
                        Ok(Err(error)) if error.kind() == io::ErrorKind::NotFound => break 'reclaim,
                        Ok(Err(error)) => {
                            debug!(path = %path.display(), error = ?error, "unix socket probe was inconclusive");
                            return Err(bind_error.into());
                        }
                        Err(error) => {
                            debug!(path = %path.display(), error = ?error, "unix socket probe timed out");
                            return Err(bind_error.into());
                        }
                    }

                    let current = match fs::symlink_metadata(&path) {
                        Ok(metadata) => metadata,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => break 'reclaim,
                        Err(error) => {
                            debug!(path = %path.display(), error = ?error, "failed to recheck stale unix socket path");
                            return Err(bind_error.into());
                        }
                    };

                    // Rechecking device and inode narrows the race with another process replacing this path.
                    if !current.file_type().is_socket()
                        || original.dev() != current.dev()
                        || original.ino() != current.ino()
                    {
                        debug!(path = %path.display(), "unix socket path changed during stale-socket probe");
                        return Err(bind_error.into());
                    }

                    warn!(path = %path.display(), "removing stale unix socket path");
                    match fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                UnixListener::bind(&path)?
            }
            Err(error) => return Err(error.into()),
        };
        // Ordinary socket clients must run as the owner; permissions do not encrypt payloads.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        Ok(Self { inner, path })
    }
}

impl Listener {
    /// Accepts a Unix client and leaves peer-address metadata outside the agent session.
    #[cfg(unix)]
    pub async fn accept(&mut self) -> io::Result<UnixStream> {
        debug!(path = %self.path.display(), "waiting for unix socket client");
        self.inner.accept().await.map(|(stream, _addr)| stream)
    }

    /// Transfers the connected pipe while preparing the next instance under the same name.
    #[cfg(windows)]
    pub async fn accept(&mut self) -> std::io::Result<NamedPipeServer> {
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
    /// Attempts to unlink the configured socket path when the listener owner is dropped.
    fn drop(&mut self) {
        debug!(path = %self.path.display(), "removing unix socket path during listener drop");
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(windows)]
impl Signal {
    /// Registers the supported Windows console notifications.
    pub fn new() -> Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::windows::ctrl_c()?,
            close: tokio::signal::windows::ctrl_close()?,
            shutdown: tokio::signal::windows::ctrl_shutdown()?,
            ctrl_break: tokio::signal::windows::ctrl_break()?,
        })
    }

    /// Waits for any subscribed console notification to request shutdown.
    pub async fn recv(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {},
            _ = self.close.recv() => {},
            _ = self.shutdown.recv() => {},
            _ = self.ctrl_break.recv() => {},
        }
    }
}

#[cfg(unix)]
impl Signal {
    /// Subscribes to SIGINT and SIGTERM shutdowns.
    pub fn new() -> Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    /// Waits for a subscribed Unix signal to request shutdown.
    pub async fn recv(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {},
            _ = self.terminate.recv() => {},
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    //! Socket permissions, stale-path recovery, and preservation of unrelated path entries.

    /// Checks the mode of a newly bound socket without exercising remote vault access.
    #[tokio::test]
    async fn socket_permissions_are_owner_only() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempdir()?;
        let path = directory.path().join("permissions.sock");
        let listener = Listener::bind(path.to_str().ok_or_else(|| anyhow::anyhow!("invalid socket path"))?).await?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        drop(listener);
        Ok(())
    }

    use super::Listener;
    use anyhow::Result;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
    use tempfile::tempdir;

    /// Models a previous process exiting without unlinking its socket pathname.
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

    /// Confirms startup cannot replace a listening agent's endpoint.
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

    /// Protects unrelated regular files when the configured path is already occupied.
    #[tokio::test]
    async fn preserves_regular_file_path() -> Result<()> {
        let directory = tempdir()?;
        let path = directory.path().join("agent.sock");
        fs::write(&path, "keep me")?;

        assert!(Listener::bind(path.to_string_lossy().as_ref()).await.is_err());
        assert_eq!(fs::read_to_string(&path)?, "keep me");
        Ok(())
    }

    /// Confirms reclamation neither unlinks symlinks nor alters their targets.
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

    /// Checks normal listener destruction removes the pathname it was configured to use.
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
