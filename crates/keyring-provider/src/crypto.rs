//! Local crypto bootstrap and cipher decryption helpers for Bitwarden.
//!
//! Only the key types and flows needed by this repository are implemented here: derive the user
//! key from master-password unlock data, import organization keys, and decrypt SSH-key items.

use super::auth::BitwardenTokenSuccessResponse;
use super::models::{BitwardenCipher, BitwardenProfile};
use anyhow::{Context, Result, anyhow, bail};
use bitwarden_api_api::models::{KdfType, MasterPasswordUnlockResponseModel};
use bitwarden_crypto::{
    Decryptable, EncString, Kdf, KeyStore, KeyStoreContext, MasterKey, SymmetricKeyAlgorithm, UnsignedSharedKey,
    key_slot_ids,
};
use std::num::NonZeroU32;
use uuid::Uuid;

// The provider only needs user, organization, and ephemeral item keys; the local key-id map keeps
// the in-memory keystore as small as possible while still matching Bitwarden's encryption model.
// The asymmetric account key unwraps organization keys. Signing IDs remain local-only because this
// loader extracts SSH material instead of installing an account signing key into the SDK keystore.
key_slot_ids! {
    #[symmetric]
    pub(crate) enum BitwardenSymmetricKeyId {
        User,
        Organization(Uuid),
        #[local]
        Local(LocalId),
    }

    #[private]
    pub(crate) enum BitwardenPrivateKeyId {
        UserPrivateKey,
        #[local]
        Local(LocalId),
    }

    #[signing]
    pub(crate) enum BitwardenSigningKeyId {
        #[local]
        Local(LocalId),
    }

    pub(crate) BitwardenKeyIds => BitwardenSymmetricKeyId, BitwardenPrivateKeyId, BitwardenSigningKeyId;
}

/// Derives account decryption keys from the master password and a successful token response.
///
/// The password-derived master key unwraps the user key, which then unwraps the account private key.
/// Only the user key and a successfully recovered private key are retained in `store`. API-key
/// authentication alone cannot perform this step.
pub(crate) fn initialize_user_crypto(
    store: &KeyStore<BitwardenKeyIds>,
    password: &str,
    token: &BitwardenTokenSuccessResponse,
) -> Result<()> {
    // The token response supplies encrypted account keys, not plaintext vault decryption keys.
    let private_key: EncString = token
        .private_key
        .as_deref()
        .context("bitwarden token response missing private key")?
        .parse()
        .context("failed to parse bitwarden private key")?;
    let unlock = token
        .user_decryption_options
        .as_ref()
        .and_then(|options| options.master_password_unlock.as_deref())
        .context("bitwarden token response missing master password unlock data")?;

    // Required KDF inputs are validated before performing potentially expensive derivation.
    let unlock = parse_master_password_unlock(unlock)?;

    // The master key is a local intermediate: the reusable user key, not the password-derived key,
    // protects personal items and the account's asymmetric private key.
    let master_key = MasterKey::derive(password, &unlock.salt, &unlock.kdf)
        .map_err(|_| anyhow!("invalid bitwarden kdf configuration"))?;
    let user_key = master_key
        .decrypt_user_key(unlock.master_key_wrapped_user_key)
        .context("failed to decrypt bitwarden user key")?;

    let mut ctx = store.context_mut();

    // Inspect the recovered user key before persisting its session-wide identifier. Here,
    // "persist" means retaining it in the SDK's in-memory keystore, not writing it to disk.
    let user_key_id = ctx.add_local_symmetric_key(user_key);
    match ctx.get_symmetric_key_algorithm(user_key_id) {
        Ok(
            SymmetricKeyAlgorithm::Aes256CbcHmac
            | SymmetricKeyAlgorithm::XChaCha20Poly1305
            | SymmetricKeyAlgorithm::XAes256Gcm,
        ) => {}
        Ok(SymmetricKeyAlgorithm::Aes256Gcm) => bail!("unsupported bitwarden user key algorithm"),
        Err(error) => return Err(anyhow!(error)),
    }

    // The private key is needed for organization-key support, but user-level item decryption can
    // still proceed if that unwrap fails.
    if let Ok(private_key_id) = ctx.unwrap_private_key(user_key_id, &private_key) {
        ctx.persist_private_key(private_key_id, BitwardenPrivateKeyId::UserPrivateKey)
            .context("failed to persist bitwarden private key")?;
    } else {
        tracing::warn!("bitwarden private key could not be unwrapped, skipping org key support");
    }

    ctx.persist_symmetric_key(user_key_id, BitwardenSymmetricKeyId::User)
        .context("failed to persist bitwarden user key")?;

    Ok(())
}

/// Imports organization shared keys from the current sync profile.
///
/// Entries without an ID or encrypted key are ignored. A present but unusable shared key fails
/// initialization so organization-owned ciphers are not processed against incomplete account state.
pub(crate) fn initialize_org_keys(store: &KeyStore<BitwardenKeyIds>, profile: &BitwardenProfile) -> Result<()> {
    // No organizations means there is nothing extra to import for this vault snapshot.
    let organizations = profile.organizations.as_deref().unwrap_or(&[]);
    if organizations.is_empty() {
        return Ok(());
    }

    let mut ctx = store.context_mut();

    // Organization keys are encrypted for the user private key recovered during login bootstrap.
    if !ctx.has_private_key(BitwardenPrivateKeyId::UserPrivateKey) {
        bail!("bitwarden user private key is missing");
    }

    for organization in organizations {
        let (Some(id), Some(key)) = (organization.id, organization.key.as_deref()) else {
            continue;
        };

        let shared_key: UnsignedSharedKey = key
            .parse()
            .with_context(|| format!("failed to parse bitwarden organization key for {id}"))?;

        let key = shared_key
            .decapsulate(BitwardenPrivateKeyId::UserPrivateKey, &mut ctx)
            .with_context(|| format!("failed to decrypt bitwarden organization key for {id}"))?;
        ctx.persist_symmetric_key(key, BitwardenSymmetricKeyId::Organization(id))
            .with_context(|| format!("failed to persist bitwarden organization key for {id}"))?;
    }

    Ok(())
}

/// Resolves the symmetric key that should decrypt one cipher's name and SSH-key fields.
///
/// Ownership selects the user or organization key. An optional wrapped item key narrows that scope
/// further; local key identifiers are meaningful only to the SDK context that created them.
pub(crate) fn resolve_cipher_key(
    ctx: &mut KeyStoreContext<'_, BitwardenKeyIds>,
    cipher: &BitwardenCipher,
) -> Result<BitwardenSymmetricKeyId> {
    // Start from the broadest key scope: organization items use the org key, personal items use
    // the user key.
    let base_key = cipher
        .organization_id
        .map_or(BitwardenSymmetricKeyId::User, BitwardenSymmetricKeyId::Organization);

    // Some Bitwarden items are wrapped again with an item-specific symmetric key.
    let key_id = if let Some(key) = cipher.key.as_deref().filter(|value| !value.trim().is_empty()) {
        let wrapped: EncString = key.parse().context("failed to parse bitwarden cipher key")?;
        ctx.unwrap_symmetric_key(base_key, &wrapped)
            .context("failed to unwrap bitwarden cipher key")?
    } else {
        base_key
    };

    // The resolved key must already exist in the keystore; otherwise the caller is operating on an
    // incomplete or inconsistent crypto state.
    if !ctx.has_symmetric_key(key_id) {
        bail!("missing bitwarden cipher key {key_id:?}");
    }

    Ok(key_id)
}

/// Decrypts an optional encrypted string field stored on a Bitwarden item.
///
/// Absence yields `None`; a present but malformed or unauthentic value is an error. The returned
/// plaintext is an ordinary owned string, so callers must choose the appropriate secret wrapper.
pub(crate) fn decrypt_optional_string(
    ctx: &mut KeyStoreContext<'_, BitwardenKeyIds>,
    key: BitwardenSymmetricKeyId,
    value: Option<&str>,
) -> Result<Option<String>> {
    // Missing values are common in Bitwarden payloads and are not an error for the caller.
    let Some(value) = value else {
        return Ok(None);
    };

    let encrypted: EncString = value.parse().context("failed to parse bitwarden enc string")?;

    encrypted.decrypt(ctx, key).map(Some).map_err(|error| anyhow!(error))
}

/// Converts server-provided unlock data into the exact KDF and wrapped-key inputs the SDK expects.
///
/// The account's stored costs and salt are used as supplied rather than replaced with local defaults.
/// Missing Argon2 costs, invalid numeric costs, and absent wrapped keys fail before derivation.
fn parse_master_password_unlock(
    response: &MasterPasswordUnlockResponseModel,
) -> Result<BitwardenMasterPasswordUnlockData> {
    // Translate the remote KDF description into the exact enum expected by `bitwarden-crypto`.
    let kdf = match response.kdf.kdf_type {
        KdfType::PBKDF2_SHA256 => Kdf::PBKDF2 {
            iterations: parse_nonzero_u32(response.kdf.iterations)?,
        },
        KdfType::Argon2id => Kdf::Argon2id {
            iterations: parse_nonzero_u32(response.kdf.iterations)?,
            memory: parse_nonzero_u32(
                response
                    .kdf
                    .memory
                    .context("bitwarden argon2 response missing memory cost")?,
            )?,
            parallelism: parse_nonzero_u32(
                response
                    .kdf
                    .parallelism
                    .context("bitwarden argon2 response missing parallelism")?,
            )?,
        },
        KdfType::__Unknown(_) => bail!("unsupported bitwarden kdf"),
    };

    // Gather the remaining unlock inputs after the KDF shape is known.
    Ok(BitwardenMasterPasswordUnlockData {
        kdf,
        master_key_wrapped_user_key: response
            .master_key_encrypted_user_key
            .as_deref()
            .context("bitwarden unlock response missing wrapped user key")?
            .parse()
            .context("failed to parse wrapped bitwarden user key")?,
        salt: response
            .salt
            .clone()
            .context("bitwarden unlock response missing salt")?,
    })
}

/// Rejects out-of-range or zero KDF costs instead of truncating or substituting a default.
fn parse_nonzero_u32(value: impl TryInto<u32>) -> Result<NonZeroU32> {
    value
        .try_into()
        .ok()
        .and_then(NonZeroU32::new)
        .context("invalid bitwarden kdf parameter")
}

/// Validated unlock inputs consumed by `bitwarden-crypto`; the wrapped user key is still encrypted.
struct BitwardenMasterPasswordUnlockData {
    /// Account-specific algorithm and work factors reported by the identity service.
    kdf: Kdf,
    /// User key protected by the password-derived master key.
    master_key_wrapped_user_key: EncString,
    /// Account salt used for master-key derivation, separate from the API-key client identifier.
    salt: String,
}
