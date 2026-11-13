//! Exercises the real HTTP, password-unlock, and cipher-decryption path against a local fixture.
//!
//! Responses contain synthetic credentials and encrypted SSH material. Captured requests allow
//! assertions about protocol shape, retry limits, and the master password staying out of requests.
//! These tests do not depend on an external Bitwarden account or a storage backend.

use anyhow::{Context, Result};
use bitwarden_crypto::{EncString, Kdf, KeyEncryptable, MasterKey};
use keyring_core::SecrecyBytes;
use keyring_provider::{LoadError, config::BitwardenConfig, load};
use serde_json::{Value, json};
use ssh_key::{LineEnding, PrivateKey, private::Ed25519Keypair};
use std::{
    collections::VecDeque,
    num::NonZeroU32,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

// A distinctive plaintext marker makes accidental transmission observable in captured requests.
const PASSWORD: &str = "fixture-master-password-never-sent";

/// Local identity and API endpoint backed by one ordered queue of scripted JSON responses.
///
/// Both endpoints share a URL so the captured request order describes the whole load lifecycle.
struct Fixture {
    /// Synthetic API credentials and ephemeral loopback addresses passed to the actual loader.
    config: BitwardenConfig,
    /// Complete HTTP requests, including bodies, retained only for test assertions.
    requests: Arc<Mutex<Vec<String>>>,
    /// Listener task stopped when the fixture leaves scope.
    task: JoinHandle<()>,
}

impl Fixture {
    /// Starts an isolated server that consumes one scripted response per complete request.
    async fn new(responses: Vec<(u16, Value)>) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let captured = captured.clone();
                let responses = responses.clone();
                // Separate connection handlers keep the accept loop available for subsequent calls.
                tokio::spawn(async move {
                    let _ = respond(stream, captured, responses).await;
                });
            }
        });
        Ok(Self {
            config: BitwardenConfig {
                api_url: url.clone(),
                identity_url: url,
                client_id: "fixture-client".into(),
                client_secret: "fixture-secret".to_owned().into(),
            },
            requests,
            task,
        })
    }

    /// Copies the capture log so assertions never hold its mutex while performing other work.
    fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Drop for Fixture {
    /// Stops accepting connections; spawned handlers retain ownership of their individual streams.
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Captures one content-length-delimited HTTP request and emits the next scripted JSON response.
///
/// This intentionally small fixture handles the request form used by the provider, not arbitrary
/// HTTP clients: it does not implement chunked bodies or persistent connections.
async fn respond(
    mut stream: TcpStream,
    requests: Arc<Mutex<Vec<String>>>,
    responses: Arc<Mutex<VecDeque<(u16, Value)>>>,
) -> Result<()> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    // Headers may span reads; do not parse Content-Length until the complete header is available.
    let header_end = loop {
        let length = stream.read(&mut buffer).await?;
        if length == 0 {
            anyhow::bail!("disconnected");
        }
        bytes.extend_from_slice(&buffer[..length]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        if bytes.len() > 65536 {
            anyhow::bail!("oversized fixture request");
        }
    };
    let header = std::str::from_utf8(&bytes[..header_end])?;
    let length: usize = header
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::trim)
                .map(str::to_owned)
        })
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(0);
    // Form credentials are in the body, so capturing only headers would miss password leakage.
    while bytes.len() < header_end + length {
        let length = stream.read(&mut buffer).await?;
        if length == 0 {
            anyhow::bail!("disconnected");
        }
        bytes.extend_from_slice(&buffer[..length]);
    }
    requests
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture lock poisoned"))?
        .push(String::from_utf8(bytes)?);
    // An exhausted queue is an unexpected extra request, making accidental retry loops fail.
    let (status, body) = responses
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture lock poisoned"))?
        .pop_front()
        .context("unexpected HTTP request")?;
    let body = serde_json::to_vec(&body)?;
    let reason = if status == 200 { "OK" } else { "Error" };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await?;
    Ok(())
}

/// Builds matching identity and sync responses plus the expected unencrypted SSH key.
///
/// Real SDK encryption keeps the fixture sensitive to KDF, wrapped-user-key, and item-decryption
/// mistakes. The fixed SSH seed and low PBKDF2 cost are test inputs, not production key generation.
fn payload() -> Result<(Value, Value, PrivateKey)> {
    let master = MasterKey::derive(
        PASSWORD,
        "fixture@example.com",
        &Kdf::PBKDF2 {
            iterations: NonZeroU32::new(5000).context("invalid fixture iterations")?,
        },
    )?;
    let (user, wrapped) = master.make_user_key()?;
    // This decrypts to text rather than an account private key. An empty organization profile makes
    // the missing organization capability acceptable while still exercising personal-item loading.
    let encrypted_private: EncString = "fixture-no-org-key".encrypt_with_key(&user.0)?;
    let mut key = PrivateKey::from(Ed25519Keypair::from_seed(&[17; 32]));
    key.set_comment("fixture key");
    let pem = key.to_openssh(LineEnding::LF)?;
    let encrypted_pem: EncString = pem.as_str().encrypt_with_key(&user.0)?;
    let encrypted_name: EncString = "fixture key".encrypt_with_key(&user.0)?;
    let token = json!({
        "access_token": "fixture-token", "expires_in": 3600,
        "privateKey": encrypted_private.to_string(),
        "userDecryptionOptions": { "masterPasswordUnlock": {
            "kdf": { "kdfType": 0, "iterations": 5000 },
            "salt": "fixture@example.com", "masterKeyEncryptedUserKey": wrapped.to_string()
        }}
    });
    let cipher = json!({
        "id": "00000000-0000-0000-0000-000000000001",
        "type": 5, "name": encrypted_name.to_string(),
        "sshKey": { "privateKey": encrypted_pem.to_string() }
    });
    // Identical encrypted data with different lifecycle/type metadata isolates the import filter.
    let mut archived = cipher.clone();
    archived["archivedDate"] = "2026-01-01".into();
    let mut deleted = cipher.clone();
    deleted["deletedDate"] = "2026-01-01".into();
    let mut non_ssh = cipher.clone();
    non_ssh["type"] = 1.into();
    Ok((
        token,
        json!({"profile": {}, "ciphers": [cipher, archived, deleted, non_ssh]}),
        key,
    ))
}

/// Gives each load its own owned password buffer, matching the public provider boundary.
fn password(value: &str) -> SecrecyBytes {
    SecrecyBytes::from(value.as_bytes().to_vec().into_boxed_slice())
}

/// Verifies API-key authentication, local decryption, import filtering, and absence of the master
/// password from captured requests.
#[tokio::test]
async fn real_auth_sync_decryption_never_sends_master_password() -> Result<()> {
    let (token, sync, key) = payload()?;
    let fixture = Fixture::new(vec![(200, token), (200, sync)]).await?;
    let materials = load(fixture.config.clone(), password(PASSWORD)).await?;
    assert_eq!(materials.len(), 1);
    assert_eq!(materials[0].record.identity, key.public_key().key_data().clone());
    assert_eq!(materials[0].record.comment, "fixture key");
    let requests = fixture.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("POST /connect/token"));
    assert!(requests[0].contains("grant_type=client_credentials"));
    assert!(requests[1].starts_with("GET /sync?excludeDomains=true"));
    assert!(requests[1].to_ascii_lowercase().contains("bitwarden-client-name: web"));
    assert!(!requests.join("\n").contains(PASSWORD));
    Ok(())
}

/// A rejected bearer credential permits exactly one new token exchange and one sync retry.
#[tokio::test]
async fn unauthorized_sync_renews_once_and_retries_once() -> Result<()> {
    let (token, sync, _) = payload()?;
    let fixture = Fixture::new(vec![(200, token.clone()), (401, json!({})), (200, token), (200, sync)]).await?;
    assert_eq!(load(fixture.config.clone(), password(PASSWORD)).await?.len(), 1);
    assert_eq!(fixture.requests().len(), 4);
    Ok(())
}

/// A second 401 must end the load rather than starting another renewal cycle.
#[tokio::test]
async fn second_unauthorized_response_does_not_trigger_a_third_sync() -> Result<()> {
    let (token, _, _) = payload()?;
    let fixture = Fixture::new(vec![
        (200, token.clone()),
        (401, json!({})),
        (200, token),
        (401, json!({})),
    ])
    .await?;
    assert!(matches!(
        load(fixture.config.clone(), password(PASSWORD)).await,
        Err(LoadError::Sync(_))
    ));
    assert_eq!(fixture.requests().len(), 4);
    Ok(())
}

/// Local password and unlock-metadata failures belong to authentication and must not download a vault.
#[tokio::test]
async fn invalid_unlock_inputs_fail_before_sync() -> Result<()> {
    let (token, _, _) = payload()?;
    let fixture = Fixture::new(vec![(200, token.clone())]).await?;
    assert!(matches!(
        load(fixture.config.clone(), password("wrong password")).await,
        Err(LoadError::Auth(_))
    ));
    assert_eq!(fixture.requests().len(), 1);
    let mut unknown_kdf = token.clone();
    unknown_kdf["userDecryptionOptions"]["masterPasswordUnlock"]["kdf"]["kdfType"] = json!(999);
    let fixture = Fixture::new(vec![(200, unknown_kdf)]).await?;
    let Err(LoadError::Auth(error)) = load(fixture.config.clone(), password(PASSWORD)).await else {
        anyhow::bail!("expected unsupported KDF authentication error");
    };
    assert!(format!("{error:#}").contains("unsupported bitwarden kdf"));
    assert_eq!(fixture.requests().len(), 1);
    // A successful token exchange is insufficient when the response omits local unlock inputs.
    let mut token = token;
    token
        .as_object_mut()
        .context("invalid fixture token")?
        .remove("userDecryptionOptions");
    let fixture = Fixture::new(vec![(200, token)]).await?;
    let Err(LoadError::Auth(error)) = load(fixture.config.clone(), password(PASSWORD)).await else {
        anyhow::bail!("expected missing metadata authentication error");
    };
    assert!(format!("{error:#}").contains("missing master password unlock data"));
    assert_eq!(fixture.requests().len(), 1);
    Ok(())
}

/// Server errors outside the explicit 401 recovery path must propagate without a retry.
#[tokio::test]
async fn non_auth_http_failure_is_not_retried() -> Result<()> {
    let (token, _, _) = payload()?;
    let fixture = Fixture::new(vec![(200, token), (500, json!({}))]).await?;
    assert!(matches!(
        load(fixture.config.clone(), password(PASSWORD)).await,
        Err(LoadError::Sync(_))
    ));
    assert_eq!(fixture.requests().len(), 2);
    Ok(())
}

/// Independent loads must never reuse an earlier password, bearer session, or unlocked account keys.
#[tokio::test]
async fn each_load_authenticates_and_requires_the_password_again() -> Result<()> {
    let (token, sync, _) = payload()?;
    let fixture = Fixture::new(vec![
        (200, token.clone()),
        (200, sync.clone()),
        (200, token.clone()),
        (200, token),
        (200, sync),
    ])
    .await?;
    assert_eq!(load(fixture.config.clone(), password(PASSWORD)).await?.len(), 1);
    assert!(matches!(
        load(fixture.config.clone(), password("wrong password")).await,
        Err(LoadError::Auth(_))
    ));
    assert_eq!(fixture.requests().len(), 3);
    assert_eq!(load(fixture.config.clone(), password(PASSWORD)).await?.len(), 1);
    let requests = fixture.requests();
    assert_eq!(requests.len(), 5);
    for index in [0, 2, 3] {
        assert!(requests[index].starts_with("POST /connect/token"));
    }
    for index in [1, 4] {
        assert!(requests[index].starts_with("GET /sync?"));
    }
    Ok(())
}
