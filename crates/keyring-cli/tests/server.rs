//! Public transport checks with a concrete provider and in-memory connections.

use anyhow::Result;
use keyring_protocol::{
    agent::Agent,
    codec::{Codec, Request, Response},
    control,
};
use keyring_provider::{BitwardenProvider, config::BitwardenConfig};
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

mod unlock {
    //! Encrypted provider fixture covering explicit unlock, local SSH use, and lock cleanup.
    //!
    //! The fixture serves only token and sync responses. Later identity and signing requests
    //! must use the imported backend material without any additional remote access.

    use super::*;
    use anyhow::Context;
    use bitwarden_crypto::{EncString, Kdf, KeyEncryptable, MasterKey};
    use keyring_core::keystore::{KeyStore, Kind};
    use serde_json::json;
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
        let _ = rustls::crypto::ring::default_provider().install_default();

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
        let agent = Agent::new(
            Arc::new(BitwardenProvider::new(BitwardenConfig {
                api_url: url.clone(),
                identity_url: url,
                client_id: "fixture-client".into(),
                client_secret: "fixture-secret".to_owned().into(),
            })?),
            vec![memory.clone()],
        )?;
        let stop = CancellationToken::new();
        let (mut client, server) = tokio::io::duplex(4096);
        let serving = tokio::spawn(Arc::clone(&agent).serve(server, stop.clone()));
        let mut client = Codec::new(&mut client);
        client
            .write(&Request::Extension {
                name: control::UNLOCK.into(),
                details: PASSWORD.as_bytes().to_vec().into(),
            })
            .await?;
        let Response::Extension(Some((name, details))) = timeout(Duration::from_secs(10), client.read()).await?? else {
            anyhow::bail!("unlock response missing");
        };
        assert_eq!(name, control::UNLOCK);
        let response: control::Response = serde_json::from_slice(&details)?;
        assert!(matches!(response, control::Response::Success), "{response:?}");
        let control::Response::Status { state, keys, .. } = status(&agent).await? else {
            anyhow::bail!("status missing");
        };
        assert_eq!(state, control::State::Unlocked);
        assert_eq!(keys[0].store, Kind::Memory);
        assert_eq!(memory.list()?.len(), 1);
        // Repeated identity reads must reuse the completed snapshot rather than reload the vault.
        for _ in 0..2 {
            client.write(&Request::Identities).await?;
            let Response::Identities(identities) = client.read().await? else {
                anyhow::bail!("identities missing");
            };
            assert_eq!(identities.len(), 1);
            assert_eq!(&identities[0].0, key.public_key().key_data());
            assert_eq!(identities[0].1, "fixture key");
        }
        client
            .write(&Request::Signature {
                key: key.public_key().to_bytes()?,
                data: b"end-to-end signature".to_vec(),
                flags: 0,
            })
            .await?;
        let Response::Signature(signature) = client.read().await? else {
            anyhow::bail!("signature missing");
        };
        signature::Verifier::verify(key.public_key(), b"end-to-end signature", &signature)?;
        let requests = timeout(Duration::from_secs(5), fixture).await???;
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("POST /connect/token"));
        assert!(requests[1].starts_with("GET /sync?"));
        assert!(!requests.join("\n").contains(PASSWORD));
        // Lock from a separate connection to exercise invalidation of the existing SSH session.
        let (control_client, control_server) = tokio::io::duplex(4096);
        let locking = tokio::spawn(Arc::clone(&agent).serve(control_server, stop));
        let mut control_client = Codec::new(control_client);
        control_client
            .write(&Request::Extension {
                name: control::LOCK.into(),
                details: Vec::new().into(),
            })
            .await?;
        let Response::Extension(Some((name, details))) = control_client.read().await? else {
            anyhow::bail!("lock response missing");
        };
        assert_eq!(name, control::LOCK);
        assert!(matches!(serde_json::from_slice(&details)?, control::Response::Success));
        assert!(matches!(
            status(&agent).await?,
            control::Response::Status {
                state: control::State::Locked,
                ..
            }
        ));
        assert!(memory.list()?.is_empty());
        // Both the old signing connection and the lock connection finish after revocation.
        assert!(
            timeout(Duration::from_secs(5), client.read::<Response>())
                .await?
                .is_err()
        );
        timeout(Duration::from_secs(5), serving).await???;
        timeout(Duration::from_secs(5), locking).await???;
        Ok(())
    }
}

/// Creates a memory-only agent whose provider requests target a controlled local endpoint.
fn agent(url: &str) -> Result<Arc<Agent>> {
    Agent::new(
        Arc::new(BitwardenProvider::new(BitwardenConfig {
            api_url: url.into(),
            identity_url: url.into(),
            client_id: "fixture".into(),
            client_secret: "fixture".to_owned().into(),
        })?),
        vec![Arc::new(keyring_store_memory::MemoryStore::default())],
    )
}

/// Distinguishes SSH failures, unknown extensions, and a valid locked-status response.
#[tokio::test]
async fn control_roundtrip_unknown_extension_and_locked_identities() -> Result<()> {
    let agent = agent("http://127.0.0.1:1")?;
    let (client, server) = tokio::io::duplex(4096);
    let stop = CancellationToken::new();
    let serving = tokio::spawn(Arc::clone(&agent).serve(server, stop));
    let mut client = Codec::new(client);
    client.write(&Request::Identities).await?;
    assert!(matches!(client.read().await?, Response::Failure));
    client
        .write(&Request::Extension {
            name: "unknown".into(),
            details: Vec::new().into(),
        })
        .await?;
    assert!(matches!(client.read().await?, Response::Extension(None)));
    client
        .write(&Request::Extension {
            name: control::STATUS.into(),
            details: Vec::new().into(),
        })
        .await?;
    let Response::Extension(Some((name, details))) = client.read().await? else {
        anyhow::bail!("missing control response");
    };
    assert_eq!(name, control::STATUS);
    assert!(matches!(
        serde_json::from_slice(&details)?,
        control::Response::Status {
            state: control::State::Locked,
            ..
        }
    ));
    drop(client);
    serving.await??;
    Ok(())
}

/// Drops the client after authentication starts and checks the agent returns to locked state.
#[tokio::test]
async fn disconnect_during_unlock_rolls_back_to_locked() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let agent = agent(&format!("http://{}", http.local_addr()?))?;
    let (client, server) = tokio::io::duplex(4096);
    let stop = CancellationToken::new();
    let serving = tokio::spawn(Arc::clone(&agent).serve(server, stop));
    let mut client = Codec::new(client);
    client
        .write(&Request::Extension {
            name: control::UNLOCK.into(),
            details: b"never-log-fixture-password".to_vec().into(),
        })
        .await?;
    // Accept without replying so the disconnect happens during a pending remote request.
    let (_http_connection, _) = timeout(Duration::from_secs(5), http.accept()).await??;
    assert!(matches!(
        status(&agent).await?,
        control::Response::Status {
            state: control::State::Loading,
            ..
        }
    ));
    drop(client);
    assert!(timeout(Duration::from_secs(5), serving).await??.is_err());
    assert!(matches!(
        status(&agent).await?,
        control::Response::Status { state: control::State::Locked, keys, .. } if keys.is_empty()
    ));
    agent.clear().await?;
    Ok(())
}

async fn status(agent: &Arc<Agent>) -> Result<control::Response> {
    let (client, server) = tokio::io::duplex(4096);
    let stop = CancellationToken::new();
    let serving = tokio::spawn(Arc::clone(agent).serve(server, stop));
    let mut client = Codec::new(client);
    client.write(&Request::from(control::Request::Status)).await?;
    let Response::Extension(Some((_, details))) = client.read().await? else {
        anyhow::bail!("missing status response");
    };
    drop(client);
    serving.await??;
    Ok(serde_json::from_slice(&details)?)
}
