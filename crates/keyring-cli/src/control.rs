//! Interactive control requests and human-readable status output.
//!
//! Control extensions share the SSH-agent endpoint. Password bytes travel over the local
//! socket or named pipe without transport encryption; access depends on OS endpoint permissions.

use crate::protocol;
use anyhow::Context;
use comfy_table::{Table, presets::NOTHING};
use keyring_core::{SigningMode, StoreKind};
use keyring_protocol::control::{self, Outcome, Phase, Status};
use ssh_agent_lib::proto::{Extension, Request, Response};
use std::time::Duration;
use tokio::time::timeout;
use zeroize::Zeroizing;

/// Operations represented by individual service control extensions.
pub enum Action {
    Unlock,
    Lock,
    Status { json: bool },
}

/// Refreshes by completing lock first, then reconnecting and prompting for a fresh unlock.
///
/// The client reuses neither the connection nor the previous password. The protocol
/// has no separate refresh operation.
pub async fn refresh(path: &str) -> u8 {
    let result = run(path, Action::Lock).await;
    if result != 0 {
        return result;
    }
    run(path, Action::Unlock).await
}

/// Opens the existing local SSH-agent socket; the caller supplies the connection deadline.
#[cfg(unix)]
async fn connect(path: &str) -> std::io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(path).await
}

/// Retries a busy named pipe until connected or cancelled by the caller's deadline.
#[cfg(windows)]
async fn connect(path: &str) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    loop {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(path) {
            Ok(client) => return Ok(client),
            Err(error) if error.raw_os_error() == Some(231) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(error) => return Err(error),
        }
    }
}

/// Executes one control exchange and converts its outcome into a CLI exit code.
///
/// An unavailable endpoint returns 3, busy state returns 4, and authentication failure
/// returns 5. Usage errors return 2; other operational failures return 1.
pub async fn run(path: &str, action: Action) -> u8 {
    let mut stream = match timeout(Duration::from_secs(10), connect(path)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            if let Action::Status { json } = action {
                if json {
                    println!("{}", serde_json::json!({"state": "not-running", "socket": path}));
                } else {
                    let mut summary = Table::new();
                    summary.add_row(["STATUS", "NOT-RUNNING"]);
                    summary.add_row(["SOCKET", &escape(path)]);
                    println!("{}", render_table(summary));
                }
            } else {
                eprintln!("cannot connect to agent at {path}");
            }
            return 3;
        }
    };
    let (name, details) = match action {
        Action::Unlock => {
            // Terminal input can block, so keep it off the async worker threads.
            let password = match tokio::task::spawn_blocking(|| {
                rpassword::prompt_password("Password: ").map(|password| Zeroizing::new(password.into_bytes()))
            })
            .await
            {
                Ok(Ok(password)) => password,
                _ => {
                    eprintln!("failed to read password from terminal");
                    return 1;
                }
            };
            (control::UNLOCK, password)
        }
        Action::Lock => (control::LOCK, Zeroizing::new(Vec::new())),
        Action::Status { .. } => (control::STATUS, Zeroizing::new(Vec::new())),
    };
    // Unlock includes remote authentication, KDF work, decryption, and backend import.
    let budget = if name == control::UNLOCK { 180 } else { 10 };
    let result = timeout(Duration::from_secs(budget), async {
        let mut request = protocol::Incoming(Some(Request::Extension(Extension {
            name: name.into(),
            details: details.to_vec().into(),
        })));
        protocol::write(&mut stream, request.0.as_ref().context("missing control request")?).await?;
        // Release both owned payload copies before waiting for the service's response.
        // Incoming also wipes an unsent unlock payload if this future is dropped early.
        if let Some(Request::Extension(extension)) = request.0.take() {
            use zeroize::Zeroize;
            extension.details.into_bytes().zeroize();
        }
        drop(details);
        let Response::ExtensionResponse(response) = protocol::read_response(&mut stream).await? else {
            anyhow::bail!("agent rejected control extension");
        };
        if response.name != name {
            anyhow::bail!("unexpected agent extension response");
        }
        Ok::<_, anyhow::Error>(response.details.into_bytes())
    })
    .await;
    let bytes = match result {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) => {
            eprintln!("{error}");
            return 1;
        }
        Err(_) => {
            eprintln!("agent request timed out");
            return 1;
        }
    };
    if let Action::Status { json } = action {
        let status: Status = match serde_json::from_slice(&bytes) {
            Ok(status) => status,
            Err(_) => {
                eprintln!("invalid agent status response");
                return 1;
            }
        };
        if json {
            let mut output = serde_json::to_value(&status).expect("status is serializable");
            output["socket"] = path.into();
            println!("{output}");
        } else {
            print!("{}", render(&status));
        }
        return 0;
    }
    let outcome: Outcome = match serde_json::from_slice(&bytes) {
        Ok(outcome) => outcome,
        Err(_) => {
            eprintln!("invalid agent control response");
            return 1;
        }
    };
    if outcome.ok {
        return 0;
    }
    eprintln!("{}", outcome.message.as_deref().unwrap_or("agent operation failed"));
    match outcome.code.as_deref() {
        Some("busy" | "already-unlocked") => 4,
        Some("auth") => 5,
        Some("usage") => 2,
        _ => 1,
    }
}

/// Makes untrusted labels and reasons safe to render as single terminal-table cells.
fn escape(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\n' => "\\n".into(),
            '\r' => "\\r".into(),
            '\t' => "\\t".into(),
            '\\' => "\\\\".into(),
            character if character.is_control() => format!("\\u{:04x}", character as u32),
            character => character.to_string(),
        })
        .collect()
}

/// Uses one borderless style for all sections, with column widths derived from their cells.
fn render_table(mut table: Table) -> String {
    table.load_style(NOTHING);
    for column in table.column_iter_mut() {
        column.set_padding((0, 2));
    }
    table.trim_fmt()
}

/// Renders the service's snapshot and backend sequence without inventing or sorting stores.
pub fn render(status: &Status) -> String {
    let phase = match status.state {
        Phase::Locked => "LOCKED",
        Phase::Loading => "LOADING",
        Phase::Unlocked => "UNLOCKED",
    };
    let mut summary = Table::new();
    summary.add_row(["STATUS", phase]);
    if status.state == Phase::Unlocked
        && let Some(snapshot) = &status.snapshot
    {
        summary.add_row(["SNAPSHOT", &snapshot.loaded_at]);
    }
    let mut sections = vec![render_table(summary)];
    if !status.stores.is_empty() {
        let mut stores = Table::new();
        stores.set_header(["STORE", "STATE"]);
        // The server owns backend ordering and supplies short uppercase failure reasons.
        for store in &status.stores {
            let state = if store.available {
                "OK"
            } else {
                store.reason.as_deref().unwrap_or("UNAVAILABLE")
            };
            stores.add_row([store_name(store.kind), &escape(state)]);
        }
        sections.push(render_table(stores));
    }
    if status.state == Phase::Unlocked && !status.keys.is_empty() {
        let mut keys = Table::new();
        keys.set_header(["FINGERPRINT", "ALGORITHM", "STORE", "SIGNING", "COMMENT"]);
        for key in &status.keys {
            let algorithm = key
                .bits
                .map_or_else(|| key.algorithm.clone(), |bits| format!("rsa-{bits}"));
            let signing = match key.signing {
                SigningMode::Platform => "platform",
                SigningMode::Software => "software",
            };
            keys.add_row([
                key.fingerprint.as_str(),
                &algorithm,
                store_name(key.store),
                signing,
                &escape(&key.comment),
            ]);
        }
        sections.push(render_table(keys));
    }
    format!("{}\n", sections.join("\n\n"))
}

/// Supplies the stable lowercase backend names used in the terminal display.
fn store_name(kind: StoreKind) -> &'static str {
    match kind {
        StoreKind::Keychain => "keychain",
        StoreKind::FreeDesktop => "freedesktop",
        StoreKind::Memory => "memory",
    }
}

#[cfg(test)]
mod tests {
    //! Presentation boundaries for locked state and untrusted terminal text.

    use super::*;

    /// Omits the key table unless a snapshot is unlocked and contains keys.
    #[test]
    fn locked_and_loading_have_no_key_table() {
        for (phase, expected) in [
            (Phase::Locked, "STATUS  LOCKED\n"),
            (Phase::Loading, "STATUS  LOADING\n"),
        ] {
            let status = Status {
                state: phase,
                snapshot: None,
                stores: Vec::new(),
                keys: Vec::new(),
            };
            assert_eq!(render(&status), expected);
        }
    }

    /// Escapes row separators, terminal escapes, and backslashes without interpreting them.
    #[test]
    fn comments_cannot_inject_rows_or_terminal_controls() {
        assert_eq!(escape("a\nb\tc\r\u{1b}\\"), "a\\nb\\tc\\r\\u001b\\\\");
    }
}
