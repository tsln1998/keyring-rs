//! Interactive control requests and human-readable status output.
//!
//! Control extensions share the SSH-agent endpoint. Password bytes travel over the local
//! socket or named pipe without transport encryption; access depends on OS endpoint permissions.

use crate::protocol;
use anyhow::{Context, Result, bail, ensure};
use comfy_table::{Table, presets::NOTHING};
use keyring_core::keystore::SigningMode;
use keyring_protocol::codec::{Request, Response};
use keyring_protocol::control;
use std::time::Duration;
use tokio::time::timeout;

/// Operations represented by individual service control extensions.
pub enum Action {
    Unlock,
    Lock,
    Status { json: bool },
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

/// Executes one control exchange, returning transport and service failures to the caller.
pub async fn run(path: &str, action: Action) -> Result<()> {
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
            }
            bail!("cannot connect to agent at {path}");
        }
    };
    let request = match action {
        Action::Unlock => {
            // Terminal input can block, so keep it off the async worker threads.
            tokio::task::spawn_blocking(|| {
                rpassword::prompt_password("Password: ")
                    .map(|password| control::Request::Unlock(password.into_bytes().into_boxed_slice().into()))
            })
            .await?
            .context("failed to read password from terminal")?
        }
        Action::Lock => control::Request::Lock,
        Action::Status { .. } => control::Request::Status,
    };
    let name = request.name();
    // Unlock includes remote authentication, KDF work, decryption, and backend import.
    let budget = if name == control::UNLOCK { 180 } else { 10 };
    let bytes = timeout(Duration::from_secs(budget), async {
        let request = Request::from(request);
        protocol::write(&mut stream, &request).await?;
        // Release the owned payload before waiting for the service's response.
        drop(request);
        let Response::Extension(Some((response_name, response_details))) = protocol::read_response(&mut stream).await?
        else {
            bail!("agent rejected control extension");
        };
        ensure!(response_name == name, "unexpected agent extension response");
        Ok::<_, anyhow::Error>(response_details)
    })
    .await
    .context("agent request timed out")??;
    let response: control::Response = serde_json::from_slice(&bytes).context("invalid agent control response")?;
    match (action, response) {
        (Action::Status { json }, response @ control::Response::Status { .. }) => {
            if json {
                let mut output = serde_json::to_value(&response)?;
                output["socket"] = path.into();
                println!("{output}");
            } else {
                print!("{}", render(&response)?);
            }
            Ok(())
        }
        (_, control::Response::Failure { message, .. }) => bail!("{message}"),
        (Action::Unlock | Action::Lock, control::Response::Success) => Ok(()),
        _ => bail!("unexpected agent control response"),
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
pub fn render(response: &control::Response) -> Result<String> {
    let control::Response::Status {
        state,
        snapshot,
        stores,
        keys,
    } = response
    else {
        bail!("expected agent status response");
    };
    let label = match state {
        control::State::Locked => "LOCKED",
        control::State::Loading => "LOADING",
        control::State::Unlocked => "UNLOCKED",
    };
    let mut summary = Table::new();
    summary.add_row(["STATUS", label]);
    if *state == control::State::Unlocked
        && let Some(snapshot) = snapshot
    {
        summary.add_row(["SNAPSHOT", &snapshot.loaded_at]);
    }
    let mut sections = vec![render_table(summary)];
    if !stores.is_empty() {
        let mut table = Table::new();
        table.set_header(["STORE", "STATE"]);
        // The server owns backend ordering and supplies short uppercase failure reasons.
        for store in stores {
            let state = if store.available {
                "OK"
            } else {
                store.reason.as_deref().unwrap_or("UNAVAILABLE")
            };
            let kind = serde_json::to_value(store.kind)?;
            table.add_row([
                kind.as_str().context("store kind must serialize as a string")?,
                &escape(state),
            ]);
        }
        sections.push(render_table(table));
    }
    if *state == control::State::Unlocked && !keys.is_empty() {
        let mut table = Table::new();
        table.set_header(["FINGERPRINT", "ALGORITHM", "STORE", "SIGNING", "COMMENT"]);
        for key in keys {
            let algorithm = key
                .bits
                .map_or_else(|| key.algorithm.clone(), |bits| format!("rsa-{bits}"));
            let signing = match key.signing {
                SigningMode::Platform => "platform",
                SigningMode::Software => "software",
            };
            let store = serde_json::to_value(key.store)?;
            table.add_row([
                key.fingerprint.as_str(),
                &algorithm,
                store.as_str().context("store kind must serialize as a string")?,
                signing,
                &escape(&key.comment),
            ]);
        }
        sections.push(render_table(table));
    }
    Ok(format!("{}\n", sections.join("\n\n")))
}

#[cfg(test)]
mod tests {
    //! Presentation boundaries for locked state and untrusted terminal text.

    use super::*;
    use keyring_core::keystore::Kind;

    /// Omits the key table unless a snapshot is unlocked and contains keys.
    #[test]
    fn locked_and_loading_have_no_key_table() -> Result<()> {
        for (state, expected) in [
            (control::State::Locked, "STATUS  LOCKED\n"),
            (control::State::Loading, "STATUS  LOADING\n"),
        ] {
            let response = control::Response::Status {
                state,
                snapshot: None,
                stores: Vec::new(),
                keys: Vec::new(),
            };
            assert_eq!(render(&response)?, expected);
        }
        Ok(())
    }

    #[test]
    fn store_names_use_serde_labels_without_quotes() -> Result<()> {
        for (kind, expected) in [
            (Kind::Keychain, "keychain"),
            (Kind::FreeDesktop, "freedesktop"),
            (Kind::Memory, "memory"),
        ] {
            let response = control::Response::Status {
                state: control::State::Unlocked,
                snapshot: None,
                stores: vec![control::Store {
                    kind,
                    available: true,
                    reason: None,
                }],
                keys: vec![control::Key {
                    fingerprint: "SHA256:fixture".into(),
                    comment: "fixture".into(),
                    algorithm: "ed25519".into(),
                    bits: None,
                    store: kind,
                    signing: SigningMode::Software,
                }],
            };
            let rendered = render(&response)?;
            assert!(
                rendered
                    .lines()
                    .any(|line| line.split_whitespace().eq([expected, "OK"]))
            );
            assert!(rendered.lines().any(|line| {
                line.split_whitespace()
                    .eq(["SHA256:fixture", "ed25519", expected, "software", "fixture"])
            }));
        }
        Ok(())
    }

    /// Escapes row separators, terminal escapes, and backslashes without interpreting them.
    #[test]
    fn comments_cannot_inject_rows_or_terminal_controls() {
        assert_eq!(escape("a\nb\tc\r\u{1b}\\"), "a\\nb\\tc\\r\\u001b\\\\");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn control_failures_return_errors() -> Result<()> {
        for code in ["busy", "already-unlocked", "auth", "usage"] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("agent.sock");
            let listener = tokio::net::UnixListener::bind(&path)?;
            let fixture = async move {
                let (mut stream, _) = listener.accept().await?;
                drop(listener);
                let Request::Extension { name, .. } = protocol::read_request(&mut stream).await? else {
                    bail!("expected a control request");
                };
                assert_eq!(name, control::LOCK);
                protocol::write(
                    &mut stream,
                    &Response::Extension(Some((
                        name,
                        serde_json::to_vec(&control::Response::failure(code, "fixture lock failure"))?.into(),
                    ))),
                )
                .await
            };
            let path = path.to_str().context("invalid fixture socket path")?;
            let (served, result) = timeout(Duration::from_secs(5), async {
                tokio::join!(fixture, run(path, Action::Lock))
            })
            .await?;
            served?;
            assert_eq!(
                result.expect_err("service failure must return an error").to_string(),
                "fixture lock failure"
            );
        }
        Ok(())
    }
}
