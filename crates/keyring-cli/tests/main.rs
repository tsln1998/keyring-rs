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
    net::{UnixListener, UnixStream},
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

/// Exercises startup-only configuration loading, socket permissions, and graceful shutdown.
#[tokio::test]
async fn binary_locked_startup_ignores_configuration_changes_and_shuts_down() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config = directory.path().join("config.toml");
    let socket = directory.path().join("keyring.sock");
    fs::write(&config, CONFIG)?;
    let binary = env!("CARGO_BIN_EXE_keyring");
    let child = Command::new(binary)
        .current_dir(directory.path())
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
    assert_eq!(status["type"], "status");
    assert_eq!(status["state"], "locked");
    assert_eq!(status["keys"], serde_json::json!([]));
    assert!(status["snapshot"].is_null());
    let mut stream = UnixStream::connect(&socket).await?;
    stream.write_all(b"\0\0\0\x01\x0b").await?;
    assert_eq!(stream.read_u32().await?, 1);
    assert_eq!(stream.read_u8().await?, 5);
    fs::write(&config, "[bitwarden")?;
    stream.write_all(b"\0\0\0\x01\x0b").await?;
    assert_eq!(stream.read_u32().await?, 1);
    assert_eq!(stream.read_u8().await?, 5);
    fs::remove_file(&config)?;
    let status = Command::new(binary)
        .arg("--config")
        .arg(&config)
        .args(["status", "--path"])
        .arg(&socket)
        .output()?;
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
    assert!(child.0.wait()?.success());
    assert!(!socket.exists());
    Ok(())
}

/// Returns one for endpoint absence and invalid or missing startup configuration.
#[test]
fn startup_and_connection_failures_exit_with_one() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("missing.sock");
    let binary = env!("CARGO_BIN_EXE_keyring");
    let status = Command::new(binary)
        .args(["status", "--json", "--path"])
        .arg(&socket)
        .output()?;
    assert_eq!(status.status.code(), Some(1));
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
    let missing_config = Command::new(binary)
        .current_dir(directory.path())
        .arg("--path")
        .arg(&socket)
        .output()?;
    assert_eq!(missing_config.status.code(), Some(1));
    assert!(String::from_utf8(missing_config.stderr)?.contains("failed to read configuration"));
    for command in ["unlock", "refresh", "lock", "status"] {
        let result = Command::new(binary)
            .arg("--config")
            .arg(&invalid)
            .arg(command)
            .arg("--path")
            .arg(&socket)
            .output()?;
        assert_eq!(result.status.code(), Some(1));
        assert!(String::from_utf8(result.stderr)?.contains("cannot connect to agent"));
    }
    Ok(())
}

#[test]
fn argument_parsing_errors_and_help_are_returned_to_main() -> Result<()> {
    let binary = env!("CARGO_BIN_EXE_keyring");
    for args in [
        vec![],
        vec!["--unknown"],
        vec!["invalid-command"],
        vec!["--path"],
        vec!["status", "--unknown"],
    ] {
        let result = Command::new(binary).args(args).env_remove("SSH_AUTH_SOCK").output()?;
        assert_eq!(result.status.code(), Some(1));
        assert!(!result.stderr.is_empty());
    }
    for args in [vec!["--help"], vec!["status", "--help"]] {
        let result = Command::new(binary).args(args).env_remove("SSH_AUTH_SOCK").output()?;
        assert_eq!(result.status.code(), Some(1));
        assert!(String::from_utf8(result.stderr)?.contains("Usage:"));
        assert!(result.stdout.is_empty());
    }
    Ok(())
}

#[test]
fn path_option_overrides_socket_environment() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let environment = directory.path().join("environment.sock");
    let explicit = directory.path().join("explicit.sock");
    for override_path in [None, Some(&explicit)] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_keyring"));
        command.args(["status", "--json"]).env("SSH_AUTH_SOCK", &environment);
        if let Some(path) = override_path {
            command.arg("--path").arg(path);
        }
        let result = command.output()?;
        assert_eq!(result.status.code(), Some(1));
        let status: serde_json::Value = serde_json::from_slice(&result.stdout)?;
        assert_eq!(status["state"], "not-running");
        assert_eq!(
            status["socket"],
            override_path.unwrap_or(&environment).to_string_lossy().as_ref()
        );
    }
    Ok(())
}

#[tokio::test]
async fn refresh_stops_after_failed_lock() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("agent.sock");
    let listener = UnixListener::bind(&socket)?;
    let client = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_keyring"))
            .args(["refresh", "--path"])
            .arg(&socket)
            .output()
    });
    let (mut stream, _) = timeout(Duration::from_secs(5), listener.accept()).await??;
    drop(listener);
    let mut request = [0; 21];
    stream.read_exact(&mut request).await?;
    assert_eq!(&request, b"\0\0\0\x11\x1b\0\0\0\x0clock@keyring");
    let response =
        b"\x1d\0\0\0\x0clock@keyring{\"type\":\"failure\",\"code\":\"busy\",\"message\":\"fixture lock failure\"}";
    stream.write_u32(response.len().try_into()?).await?;
    stream.write_all(response).await?;
    let result = timeout(Duration::from_secs(5), client).await???;
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8(result.stderr)?.contains("fixture lock failure"));
    Ok(())
}
