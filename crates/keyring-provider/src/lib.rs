//! Loads SSH keys from Bitwarden during one explicit unlock operation.
//!
//! API credentials authenticate network requests; the supplied master password unlocks vault keys
//! locally. Each call owns its short-lived account session and returns only the SSH material needed
//! by storage backends. This crate does not retain an unlocked vault or schedule later refreshes.

mod auth;
pub mod config;
mod crypto;
mod models;
mod session;

use anyhow::{Context, Result};
use config::BitwardenConfig;
use crypto::{BitwardenKeyIds, decrypt_optional_string, resolve_cipher_key};
use keyring_core::{SecrecyBytes, StoreMaterial, software};
use models::BitwardenCipher;
use session::BitwardenSession;
use ssh_key::PrivateKey;
use zeroize::Zeroizing;

/// Separates authentication and local account unlock failures from vault loading failures.
///
/// Callers use this distinction to report whether unlocking the account or loading its SSH keys
/// failed. The wrapped error retains diagnostic context without changing the public stage.
#[derive(Debug)]
pub enum LoadError {
    /// The token exchange, password decoding, or account-key initialization failed.
    Auth(anyhow::Error),
    /// Sync, organization-key initialization, or the decryption worker failed.
    Sync(anyhow::Error),
}

impl std::fmt::Display for LoadError {
    /// Reports a stable stage description; the underlying cause remains available through `source`.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Auth(_) => "Bitwarden authentication or master-password unlock failed",
            Self::Sync(_) => "failed to sync and decrypt Bitwarden vault",
        })
    }
}

impl std::error::Error for LoadError {
    /// Preserves the original error chain for callers that need detailed diagnostics.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Auth(error) | Self::Sync(error) => Some(error.as_ref()),
        }
    }
}

/// Authenticates, unlocks, and downloads one vault snapshot, then extracts its usable SSH keys.
///
/// Invalid individual items are skipped; failure to obtain the snapshot or initialize account keys
/// fails the entire load. Account crypto and the access token are released before successful return,
/// while returned private-key material remains owned by the caller for backend import.
///
/// Password derivation and item decryption run on blocking workers. Dropping this future does not
/// stop a worker that has already started; its inputs are released through its normal cleanup path.
pub async fn load(config: BitwardenConfig, password: SecrecyBytes) -> Result<Vec<StoreMaterial>, LoadError> {
    let mut session = BitwardenSession::unlock(config, password)
        .await
        .map_err(LoadError::Auth)?;
    let sync = session.sync().await.map_err(LoadError::Sync)?;
    tokio::task::spawn_blocking(move || {
        let mut keys = Vec::new();
        for cipher in sync.ciphers.as_deref().unwrap_or_default() {
            match decrypt(cipher, &session.store) {
                Ok(Some(key)) => keys.push(key),
                Ok(None) => {}
                // Log only the item ID: error context can originate from encrypted key parsing.
                Err(_) => tracing::warn!(cipher = ?cipher.id, "skipping invalid SSH key cipher"),
            }
        }
        // End account-session ownership here instead of returning it with backend key material.
        // Drop invokes the relevant cleanup; it is not a guarantee that every temporary copy is erased.
        drop(sync);
        drop(session);
        keys
    })
    .await
    .map_err(|error| LoadError::Sync(error.into()))
}

/// Converts one eligible Bitwarden item into backend material without retaining account crypto.
///
/// Items outside the active SSH-key set, or without their required fields, yield `None`. Malformed
/// encrypted fields and invalid SSH private keys return an error for the load loop to skip.
fn decrypt(
    cipher: &BitwardenCipher,
    store: &bitwarden_crypto::KeyStore<BitwardenKeyIds>,
) -> Result<Option<StoreMaterial>> {
    // Filter before touching crypto so unrelated or inactive items cannot fail this load path.
    if !cipher.is_ssh_key() || cipher.is_deleted() || cipher.is_archived() {
        return Ok(None);
    }
    let (Some(id), Some(ssh)) = (cipher.id, cipher.ssh_key.as_ref()) else {
        return Ok(None);
    };
    let mut context = store.context_mut();
    let cipher_key = resolve_cipher_key(&mut context, cipher)?;
    let name = decrypt_optional_string(&mut context, cipher_key, cipher.name.as_deref())?;
    let Some(pem) = decrypt_optional_string(&mut context, cipher_key, ssh.private_key.as_deref())? else {
        return Ok(None);
    };
    // Keep decrypted text in a wiping wrapper during private-key parsing and material extraction.
    let pem = Zeroizing::new(pem);
    let mut key = PrivateKey::from_openssh(pem.as_bytes()).context("invalid Bitwarden SSH private key")?;
    // A vault item name is the displayed comment; a stable ID keeps unnamed items identifiable.
    key.set_comment(
        name.as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map_or_else(|| format!("bitwarden:{id}"), ToOwned::to_owned),
    );
    Ok(Some(software::material(&key)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::{BitwardenCipherSshKey, CIPHER_TYPE_SSH_KEY};

    /// Excluded items must be rejected before their deliberately invalid ciphertext is inspected.
    #[test]
    fn skips_archived_deleted_and_non_ssh_before_decrypting() -> Result<()> {
        for (kind, deleted, archived) in [
            (CIPHER_TYPE_SSH_KEY, None, Some("2026-01-01")),
            (CIPHER_TYPE_SSH_KEY, Some("2026-01-01"), None),
            (1, None, None),
        ] {
            let cipher = BitwardenCipher {
                id: Some(uuid::Uuid::nil()),
                r#type: Some(kind),
                deleted_date: deleted.map(str::to_owned),
                archived_date: archived.map(str::to_owned),
                ssh_key: Some(Box::new(BitwardenCipherSshKey {
                    private_key: Some("invalid".into()),
                })),
                ..Default::default()
            };
            assert!(decrypt(&cipher, &bitwarden_crypto::KeyStore::default())?.is_none());
        }
        Ok(())
    }
}

#[cfg(test)]
mod http_tests {
    //! Exercises the real HTTP, password-unlock, and cipher-decryption path against a local fixture.
    //!
    //! Responses contain synthetic credentials and encrypted SSH material. Captured requests allow
    //! assertions about protocol shape, retry limits, and the master password staying out of requests.
    //! These tests do not depend on an external Bitwarden account or a storage backend.

    use crate::{LoadError, config::BitwardenConfig, load};
    use anyhow::{Context, Result};
    use bitwarden_crypto::{EncString, Kdf, KeyEncryptable, MasterKey};
    use keyring_core::SecrecyBytes;
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
                    client_secret: "fixture-secret".into(),
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
    async fn wrong_password_and_missing_unlock_data_fail_before_sync() -> Result<()> {
        let (token, _, _) = payload()?;
        let fixture = Fixture::new(vec![(200, token.clone())]).await?;
        assert!(matches!(
            load(fixture.config.clone(), password("wrong password")).await,
            Err(LoadError::Auth(_))
        ));
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
}
