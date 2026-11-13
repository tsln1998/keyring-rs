//! Process-level scenarios use a local fixture and never contact the remote provider.

#![cfg(unix)]

use anyhow::Result;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::{sleep, timeout},
};

/// Reaps the spawned service even when a scenario exits early or an assertion fails.
struct Running(Child);

impl Drop for Running {
    /// Performs best-effort termination and reaping without obscuring the scenario's error.
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Syntactically valid configuration whose provider is never contacted while locked.
const CONFIG: &str = "[bitwarden]\napi_url='http://127.0.0.1:1'\nidentity_url='http://127.0.0.1:1'\nclient_id='fixture'\nclient_secret='fixture-secret'\n";

/// Exercises socket permissions, failed and successful reloads, and graceful path removal.
#[tokio::test]
async fn binary_locked_startup_status_reload_and_shutdown() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config = directory.path().join("keyring.toml");
    let socket = directory.path().join("keyring.sock");
    fs::write(&config, CONFIG)?;
    let binary = env!("CARGO_BIN_EXE_keyring");
    let child = Command::new(binary)
        .arg("--config")
        .arg(&config)
        .arg("--path")
        .arg(&socket)
        // Keep the service independent of the caller's desktop Secret Service session.
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("XDG_RUNTIME_DIR")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut child = Running(child);
    timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(stream) = UnixStream::connect(&socket).await {
                break Ok::<_, anyhow::Error>(stream);
            }
            if child.0.try_wait()?.is_some() {
                anyhow::bail!("service exited before binding");
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    assert_eq!(fs::metadata(&socket)?.permissions().mode() & 0o777, 0o600);
    let status = Command::new(binary)
        .args(["status", "--json", "--path"])
        .arg(&socket)
        .output()?;
    assert!(status.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout)?;
    assert_eq!(status["state"], "locked");
    assert_eq!(status["keys"], serde_json::json!([]));
    assert!(status["snapshot"].is_null());
    let mut stream = UnixStream::connect(&socket).await?;
    stream.write_all(b"\0\0\0\x01\x0b").await?;
    assert_eq!(stream.read_u32().await?, 1);
    assert_eq!(stream.read_u8().await?, 5);
    // A rejected configuration must leave the current generation and connection usable.
    fs::write(&config, "[bitwarden")?;
    assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGUSR1) }, 0);
    sleep(Duration::from_millis(100)).await;
    stream.write_all(b"\0\0\0\x01\x0b").await?;
    assert_eq!(stream.read_u32().await?, 1);
    assert_eq!(stream.read_u8().await?, 5);
    // A valid reload replaces the locked agent and closes connections to its old generation.
    fs::write(&config, CONFIG)?;
    assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGUSR1) }, 0);
    assert!(timeout(Duration::from_secs(5), stream.read_u8()).await?.is_err());
    let status = Command::new(binary).args(["status", "--path"]).arg(&socket).output()?;
    assert!(status.status.success());
    let status = String::from_utf8(status.stdout)?;
    assert!(
        status
            .lines()
            .next()
            .is_some_and(|line| line.split_whitespace().eq(["STATUS", "LOCKED"]))
    );
    // Normal shutdown should exit without the guard needing to kill the process.
    assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGTERM) }, 0);
    timeout(Duration::from_secs(5), async {
        while child.0.try_wait()?.is_none() {
            sleep(Duration::from_millis(10)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    assert!(!socket.exists());
    Ok(())
}

/// Distinguishes endpoint absence, invalid configuration, and missing startup arguments.
#[test]
fn unavailable_socket_and_configuration_errors_have_distinct_exit_codes() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("missing.sock");
    let binary = env!("CARGO_BIN_EXE_keyring");
    let status = Command::new(binary)
        .args(["status", "--json", "--path"])
        .arg(&socket)
        .output()?;
    assert_eq!(status.status.code(), Some(3));
    let status: serde_json::Value = serde_json::from_slice(&status.stdout)?;
    assert_eq!(status["state"], "not-running");
    // Invalid startup configuration must fail before a socket pathname is created.
    let invalid = directory.path().join("invalid.toml");
    fs::write(&invalid, "[bitwarden")?;
    let result = Command::new(binary)
        .arg("--config")
        .arg(&invalid)
        .arg("--path")
        .arg(&socket)
        .output()?;
    assert_eq!(result.status.code(), Some(1));
    assert!(!socket.exists());
    let missing_config = Command::new(binary).arg("--path").arg(&socket).output()?;
    assert_eq!(missing_config.status.code(), Some(2));
    Ok(())
}
