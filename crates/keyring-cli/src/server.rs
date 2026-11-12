//! Connection serving, configuration replacement, and orderly agent shutdown.
//!
//! A connection captures one agent generation. State transitions invalidate that generation
//! so old SSH clients cannot continue using a snapshot after lock or configuration reload.

use crate::{
    config::Config,
    platform::{Signal, SignalEvent},
    protocol,
};
use anyhow::Result;
use keyring_core::Store;
use keyring_protocol::{ServiceAgent, control};
use ssh_agent_lib::{
    agent::{ListeningSocket, Session},
    error::AgentError,
    proto::{Request, Response},
};
use std::{fmt, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, watch},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

/// Accepts clients while handling reloads and shutdown for the foreground service.
///
/// A valid reload closes the old generation, clears its stores, and installs a locked
/// agent. Invalid configuration leaves the active agent in place.
pub async fn serve<S>(
    listener: &mut S,
    signal: &mut Signal,
    config: &Path,
    mut agent: ServiceAgent,
    stores: Vec<Arc<dyn Store>>,
) -> Result<()>
where
    S: ListeningSocket + fmt::Debug + Send,
{
    let mut jobs = JoinSet::new();
    let (mut stop, _) = watch::channel(false);
    let mut reloads = JoinSet::new();
    // Coalesce repeated reload signals into at most one extra configuration read.
    let mut pending = false;
    loop {
        tokio::select! {
            biased;
            event = signal.recv() => match event {
                SignalEvent::Shutdown => break,
                SignalEvent::Reload => {
                    if reloads.is_empty() {
                        let path = config.to_owned();
                        reloads.spawn_blocking(move || Config::new(path));
                    } else { pending = true; }
                }
            },
            result = reloads.join_next(), if !reloads.is_empty() => {
                match result {
                    Some(Ok(Ok(candidate))) => {
                        // Stop pending unlocks before waiting for the old agent's cleanup.
                        stop.send_replace(true);
                        agent.invalidate();
                        agent.clear().await?;
                        agent = ServiceAgent::new(candidate.bitwarden, stores.clone())?;
                        // New clients must observe a fresh stop channel, not the old true value.
                        stop = watch::channel(false).0;
                        tracing::info!("configuration reloaded; agent locked");
                    }
                    _ => tracing::error!("configuration reload failed; keeping current agent"),
                }
                if pending {
                    pending = false;
                    let path = config.to_owned();
                    reloads.spawn_blocking(move || Config::new(path));
                }
            },
            _ = jobs.join_next(), if !jobs.is_empty() => {},
            stream = listener.accept() => {
                let stream = stream?;
                let session = agent.session();
                let generation = agent.subscribe();
                let stop = stop.subscribe();
                jobs.spawn(async move {
                    if handle(stream, session, generation, stop).await.is_err() {
                        tracing::debug!("client connection closed after request or transport failure");
                    }
                });
            }
        }
    }
    stop.send_replace(true);
    // Aborting the async task set does not stop a blocking config read already in progress.
    reloads.abort_all();
    // Let connection tasks finish bounded in-flight work before forcing their async cancellation.
    if timeout(Duration::from_secs(30), async {
        while jobs.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        jobs.abort_all();
        while jobs.join_next().await.is_some() {}
    }
    // Backend cleanup is awaited after connections drain; failures propagate to the process.
    timeout(Duration::from_secs(30), agent.clear()).await??;
    Ok(())
}

/// Aborts the connection's read-ahead task when its owning handler is dropped.
struct ReaderTask(JoinHandle<()>);

impl Drop for ReaderTask {
    /// Prevents a detached reader from retaining the socket or queued unlock requests.
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Processes one connection sequentially while independently observing disconnects.
///
/// Deadlines or cancellation drop the in-flight async request. The agent owns rollback;
/// blocking KDF or backend work already started may finish before cleanup completes.
pub async fn handle<Stream>(
    stream: Stream,
    mut session: impl Session,
    mut generation: watch::Receiver<u64>,
    mut stop: watch::Receiver<bool>,
) -> Result<()>
where
    Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let disconnected = CancellationToken::new();
    let reader_cancelled = disconnected.clone();
    // Bound read-ahead, including password-bearing extension payloads awaiting dispatch.
    let (sender, mut receiver) = mpsc::channel(16);
    let _reader = ReaderTask(tokio::spawn(async move {
        // Any reader exit, including task abort, notifies an in-flight request of disconnect.
        let _guard = reader_cancelled.drop_guard();
        while let Ok(request) = protocol::read_request(&mut reader).await {
            if sender.send(request).await.is_err() {
                break;
            }
        }
    }));
    loop {
        if *stop.borrow() {
            break;
        }
        let incoming = tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = generation.changed() => break,
            _ = disconnected.cancelled() => break,
            incoming = receiver.recv() => incoming,
        };
        let Some(mut incoming) = incoming else { break };
        let unlock =
            matches!(incoming.0.as_ref(), Some(Request::Extension(extension)) if extension.name == control::UNLOCK);
        let control_request = matches!(incoming.0.as_ref(), Some(Request::Extension(extension))
            if matches!(extension.name.as_str(), control::UNLOCK | control::LOCK | control::STATUS));
        // Unlock has a larger budget for its explicit remote load and cryptographic work.
        let budget = if unlock { 180 } else { 30 };
        timeout(Duration::from_secs(budget), async {
            let response = tokio::select! {
                biased;
                _ = disconnected.cancelled() => anyhow::bail!("client disconnected"),
                // Lock changes the generation itself, but must still deliver its control outcome.
                _ = generation.changed(), if !control_request => anyhow::bail!("session invalidated"),
                _ = stop.changed(), if unlock => anyhow::bail!("unlock cancelled by service transition"),
                response = async {
                    let Some(request) = incoming.0.take() else { return Response::Failure };
                    match session.handle(request).await {
                        Ok(response) => response,
                        Err(AgentError::ExtensionFailure) => Response::ExtensionFailure,
                        Err(_) => Response::Failure,
                    }
                }
                => response,
            };
            tokio::select! {
                biased;
                // Suppress stale ordinary responses if a transition occurred during the request.
                _ = generation.changed(), if !control_request => anyhow::bail!("session invalidated before response"),
                _ = disconnected.cancelled() => anyhow::bail!("client disconnected"),
                result = protocol::write(&mut writer, &response) => result,
            }
        })
        .await??;
        // A successful control response can be the final message of the old generation.
        if generation.has_changed().unwrap_or(true) {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! In-memory transport checks for control routing and disconnect-triggered unlock rollback.

    mod unlock {
        //! Encrypted provider fixture covering explicit unlock, local SSH use, and lock cleanup.
        //!
        //! The fixture serves only token and sync responses. Later identity and signing requests
        //! must use the imported backend material without any additional remote access.

        use super::*;
        use anyhow::Context;
        use bitwarden_crypto::{EncString, Kdf, KeyEncryptable, MasterKey};
        use keyring_core::Store;
        use serde_json::json;
        use ssh_agent_lib::proto::SignRequest;
        use ssh_key::{LineEnding, PrivateKey, private::Ed25519Keypair};
        use std::num::NonZeroU32;
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        /// Public test input used to encrypt the fixture, never a real account credential.
        const PASSWORD: &str = "fixture-master-password";

        /// Loads an encrypted SSH key, verifies local signing, then locks and closes old sessions.
        #[tokio::test]
        async fn unlock_sign_without_remote_access_and_lock_roundtrip() -> Result<()> {
            // Mirror the provider's password-derived user-key wrapping with inexpensive fixture parameters.
            let master = MasterKey::derive(
                PASSWORD,
                "fixture@example.com",
                &Kdf::PBKDF2 {
                    iterations: NonZeroU32::new(5000).context("invalid KDF iterations")?,
                },
            )?;
            let (user, wrapped) = master.make_user_key()?;
            let key = PrivateKey::from(Ed25519Keypair::from_seed(&[17; 32]));
            let pem = key.to_openssh(LineEnding::LF)?;
            let encrypted_pem: EncString = pem.as_str().encrypt_with_key(&user.0)?;
            let encrypted_name: EncString = "fixture key".encrypt_with_key(&user.0)?;
            // This personal-vault fixture includes an encrypted account field but no organization key.
            let encrypted_private: EncString = "fixture-no-org-key".encrypt_with_key(&user.0)?;
            let token = json!({
                "access_token": "fixture-token", "expires_in": 3600,
                "privateKey": encrypted_private.to_string(),
                "userDecryptionOptions": { "masterPasswordUnlock": {
                    "kdf": { "kdfType": 0, "iterations": 5000 },
                    "salt": "fixture@example.com", "masterKeyEncryptedUserKey": wrapped.to_string()
                }}
            });
            let sync = json!({"profile": {}, "ciphers": [{
                "id": "00000000-0000-0000-0000-000000000001",
                "type": 5, "name": encrypted_name.to_string(),
                "sshKey": { "privateKey": encrypted_pem.to_string() }
            }]});
            let http = TcpListener::bind("127.0.0.1:0").await?;
            let url = format!("http://{}", http.local_addr()?);
            let fixture = tokio::spawn(async move {
                let mut requests = Vec::new();
                // Exactly two responses are available; returning ends the listener's lifetime.
                for body in [token, sync] {
                    let (mut stream, _) = http.accept().await?;
                    // Read headers and the declared body separately so request assertions include both.
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        anyhow::ensure!(header.len() < 65536, "fixture header too large");
                        header.push(stream.read_u8().await?);
                    }
                    let header = String::from_utf8(header)?;
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(str::trim)
                                .map(str::to_owned)
                        })
                        .map(|length| length.parse::<usize>())
                        .transpose()?
                        .unwrap_or(0);
                    let mut request_body = vec![0; length];
                    stream.read_exact(&mut request_body).await?;
                    requests.push(format!("{header}{}", String::from_utf8(request_body)?));
                    let body = serde_json::to_vec(&body)?;
                    stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await?;
                    stream.write_all(&body).await?;
                    stream.shutdown().await?;
                }
                Ok::<_, anyhow::Error>(requests)
            });
            let memory = Arc::new(keyring_store_memory::MemoryStore::default());
            let agent = ServiceAgent::new(
                BitwardenConfig {
                    api_url: url.clone(),
                    identity_url: url,
                    client_id: "fixture-client".into(),
                    client_secret: "fixture-secret".into(),
                },
                vec![memory.clone()],
            )?;
            let (_stop, stop) = watch::channel(false);
            let (mut client, server) = tokio::io::duplex(4096);
            let serving = tokio::spawn(handle(server, agent.session(), agent.subscribe(), stop.clone()));
            protocol::write(
                &mut client,
                &Request::Extension(Extension {
                    name: control::UNLOCK.into(),
                    details: PASSWORD.as_bytes().to_vec().into(),
                }),
            )
            .await?;
            let Response::ExtensionResponse(response) =
                timeout(Duration::from_secs(10), protocol::read_response(&mut client)).await??
            else {
                anyhow::bail!("unlock response missing");
            };
            let outcome: control::Outcome = serde_json::from_slice(response.details.as_ref())?;
            assert!(outcome.ok, "{outcome:?}");
            assert_eq!(agent.status().state, Phase::Unlocked);
            assert_eq!(agent.status().keys[0].store, keyring_core::StoreKind::Memory);
            assert_eq!(memory.list()?.len(), 1);
            // Repeated identity reads must reuse the completed snapshot rather than reload the vault.
            for _ in 0..2 {
                protocol::write(&mut client, &Request::RequestIdentities).await?;
                let Response::IdentitiesAnswer(identities) = protocol::read_response(&mut client).await? else {
                    anyhow::bail!("identities missing");
                };
                assert_eq!(identities.len(), 1);
                assert_eq!(identities[0].pubkey, key.public_key().key_data().clone());
                assert_eq!(identities[0].comment, "fixture key");
            }
            protocol::write(
                &mut client,
                &Request::SignRequest(SignRequest {
                    pubkey: key.public_key().key_data().clone(),
                    data: b"end-to-end signature".to_vec(),
                    flags: 0,
                }),
            )
            .await?;
            let Response::SignResponse(signature) = protocol::read_response(&mut client).await? else {
                anyhow::bail!("signature missing");
            };
            signature::Verifier::verify(key.public_key(), b"end-to-end signature", &signature)?;
            let requests = timeout(Duration::from_secs(5), fixture).await???;
            assert_eq!(requests.len(), 2);
            assert!(requests[0].starts_with("POST /connect/token"));
            assert!(requests[1].starts_with("GET /sync?"));
            assert!(!requests.join("\n").contains(PASSWORD));
            // Lock from a separate connection to exercise invalidation of the existing SSH session.
            let (mut control_client, control_server) = tokio::io::duplex(4096);
            let locking = tokio::spawn(handle(control_server, agent.session(), agent.subscribe(), stop));
            protocol::write(
                &mut control_client,
                &Request::Extension(Extension {
                    name: control::LOCK.into(),
                    details: Vec::new().into(),
                }),
            )
            .await?;
            let Response::ExtensionResponse(response) = protocol::read_response(&mut control_client).await? else {
                anyhow::bail!("lock response missing");
            };
            assert!(serde_json::from_slice::<control::Outcome>(response.details.as_ref())?.ok);
            assert_eq!(agent.status().state, Phase::Locked);
            assert!(memory.list()?.is_empty());
            // Both the old signing connection and the lock connection finish after the generation changes.
            assert!(
                timeout(Duration::from_secs(5), protocol::read_response(&mut client))
                    .await?
                    .is_err()
            );
            timeout(Duration::from_secs(5), serving).await???;
            timeout(Duration::from_secs(5), locking).await???;
            Ok(())
        }
    }

    use super::*;
    use keyring_protocol::control::Phase;
    use keyring_provider::config::BitwardenConfig;
    use ssh_agent_lib::proto::Extension;

    /// Creates a memory-only agent whose provider requests target a controlled local endpoint.
    fn agent(url: &str) -> Result<ServiceAgent> {
        ServiceAgent::new(
            BitwardenConfig {
                api_url: url.into(),
                identity_url: url.into(),
                client_id: "fixture".into(),
                client_secret: "fixture".into(),
            },
            vec![Arc::new(keyring_store_memory::MemoryStore::default())],
        )
    }

    /// Distinguishes SSH failures, unknown extensions, and a valid locked-status response.
    #[tokio::test]
    async fn control_roundtrip_unknown_extension_and_locked_identities() -> Result<()> {
        let agent = agent("http://127.0.0.1:1")?;
        let (mut client, server) = tokio::io::duplex(4096);
        let (_stop, stop) = watch::channel(false);
        let serving = tokio::spawn(handle(server, agent.session(), agent.subscribe(), stop));
        protocol::write(&mut client, &Request::RequestIdentities).await?;
        assert!(matches!(protocol::read_response(&mut client).await?, Response::Failure));
        protocol::write(
            &mut client,
            &Request::Extension(Extension {
                name: "unknown".into(),
                details: Vec::new().into(),
            }),
        )
        .await?;
        assert!(matches!(
            protocol::read_response(&mut client).await?,
            Response::ExtensionFailure
        ));
        protocol::write(
            &mut client,
            &Request::Extension(Extension {
                name: control::STATUS.into(),
                details: Vec::new().into(),
            }),
        )
        .await?;
        let Response::ExtensionResponse(response) = protocol::read_response(&mut client).await? else {
            anyhow::bail!("missing control response");
        };
        let status: control::Status = serde_json::from_slice(response.details.as_ref())?;
        assert_eq!(status.state, Phase::Locked);
        drop(client);
        serving.await??;
        Ok(())
    }

    /// Drops the client after authentication starts and checks the agent returns to locked state.
    #[tokio::test]
    async fn disconnect_during_unlock_rolls_back_to_locked() -> Result<()> {
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let agent = agent(&format!("http://{}", http.local_addr()?))?;
        let (mut client, server) = tokio::io::duplex(4096);
        let (_stop, stop) = watch::channel(false);
        let serving = tokio::spawn(handle(server, agent.session(), agent.subscribe(), stop));
        protocol::write(
            &mut client,
            &Request::Extension(Extension {
                name: control::UNLOCK.into(),
                details: b"never-log-fixture-password".to_vec().into(),
            }),
        )
        .await?;
        // Accept without replying so the disconnect happens during a pending remote request.
        let (_http_connection, _) = timeout(Duration::from_secs(5), http.accept()).await??;
        assert_eq!(agent.status().state, Phase::Loading);
        drop(client);
        assert!(timeout(Duration::from_secs(5), serving).await??.is_err());
        assert_eq!(agent.status().state, Phase::Locked);
        assert!(agent.status().keys.is_empty());
        agent.clear().await?;
        Ok(())
    }
}
