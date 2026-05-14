//! Cross-platform listener wrapper for the foreground agent process.
//!
//! This module keeps platform-specific bind and socket lifecycle details out of `main.rs`.
//! On Unix it owns path unlinking on drop; on Windows it owns named-pipe creation together with
//! the custom security descriptor required by the foreground agent.

use anyhow::Result;
use ssh_agent_lib::agent::ListeningSocket;

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
use std::path::PathBuf;
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeServer;
#[cfg(windows)]
use tokio::net::windows::named_pipe::ServerOptions;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, info};
#[cfg(windows)]
use windows::{
    Win32::{
        Foundation::{FALSE, HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorA, SDDL_REVISION_1,
            },
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
    /// Returns any socket-bind error reported by the operating system.
    #[cfg(unix)]
    pub fn bind(path: &str) -> Result<Self> {
        // A pre-existing socket path is treated as an error so the caller does not silently steal
        // another process's advertised agent endpoint.
        info!(path = %path, "binding unix socket listener");
        Ok(Self {
            inner: UnixListener::bind(path)?,
            path: path.into(),
        })
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
