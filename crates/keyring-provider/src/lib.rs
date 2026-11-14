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
use garde::Validate;
use keyring_core::{
    keystore::KeyRecord,
    provider::{Error, Provider},
};
use models::BitwardenCipher;
use secrecy::SecretBox;
use session::BitwardenSession;
use ssh_key::PrivateKey;
use std::{future::Future, pin::Pin};
use zeroize::Zeroizing;

pub struct BitwardenProvider {
    config: BitwardenConfig,
}

impl BitwardenProvider {
    pub fn new(config: BitwardenConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }
}

impl Provider for BitwardenProvider {
    fn load(
        &self,
        password: SecretBox<[u8]>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<KeyRecord>, Error>> + Send + '_>> {
        Box::pin(load(self.config.clone(), password))
    }
}

/// Authenticates, unlocks, and downloads one vault snapshot, then extracts its usable SSH keys.
///
/// The application must install a rustls crypto provider before calling this function.
///
/// Invalid individual items are skipped; failure to obtain the snapshot or initialize account keys
/// fails the entire load. Account crypto and the access token are released before successful return,
/// while returned private-key material remains owned by the caller for backend import.
///
/// Password derivation and item decryption run on blocking workers. Dropping this future does not
/// stop a worker that has already started; its inputs are released through its normal cleanup path.
async fn load(config: BitwardenConfig, password: SecretBox<[u8]>) -> Result<Vec<KeyRecord>, Error> {
    let mut session = BitwardenSession::unlock(config, password).await.map_err(|error| {
        let message = if error
            .chain()
            .any(|cause| cause.to_string().contains("missing master password unlock data"))
        {
            "Bitwarden token response is missing userDecryptionOptions.masterPasswordUnlock"
        } else {
            "Bitwarden authentication or master-password unlock failed"
        };
        Error::Auth(error.context(message))
    })?;
    let sync = session
        .sync()
        .await
        .map_err(|error| Error::Sync(error.context("failed to sync and decrypt Bitwarden vault")))?;
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
    .map_err(|error| Error::Sync(anyhow::Error::from(error).context("failed to sync and decrypt Bitwarden vault")))
}

/// Converts one eligible Bitwarden item into backend material without retaining account crypto.
///
/// Items outside the active SSH-key set, or without their required fields, yield `None`. Malformed
/// encrypted fields and invalid SSH private keys return an error for the load loop to skip.
fn decrypt(cipher: &BitwardenCipher, store: &bitwarden_crypto::KeyStore<BitwardenKeyIds>) -> Result<Option<KeyRecord>> {
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
    Ok(Some(KeyRecord::try_from(&key)?))
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
