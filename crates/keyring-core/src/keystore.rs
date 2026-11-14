//! Shared key records and synchronous storage contracts.
//!
//! Public records describe identities without carrying private key bytes. Import
//! material owns those bytes only until a backend consumes or drops it.

use anyhow::Context;
use rsa::{PrivateKey as RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, HashAlg, PrivateKey, public::KeyData};
use std::fmt::Debug;

/// Failures shared by all backends so callers can handle them consistently.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The key type or requested signature algorithm is outside the supported set.
    #[error("unsupported key or signing algorithm")]
    Unsupported,
    /// The backend cannot resolve a handle to an owned key.
    #[error("key handle not found")]
    NotFound,
    /// The same public identity already exists in this backend.
    #[error("public key already stored")]
    Duplicate,
    /// Private key decoding, validation, or consistency checks failed.
    #[error("invalid private key: {0}")]
    InvalidKey(String),
    /// The backend cannot currently serve requests, such as while a collection is locked.
    #[error("store unavailable: {0}")]
    Unavailable(String),
    /// A storage or platform operation failed for another reason.
    #[error("store operation failed: {0}")]
    Backend(String),
}

/// Backend identifiers shared by store selection and status output.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// macOS Keychain storage.
    Keychain,
    /// Linux Secret Service storage through the session D-Bus.
    FreeDesktop,
    /// Process-local memory storage used as the always-available fallback.
    Memory,
}

/// Where a backend performs signing, independently of where it stores the key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningMode {
    /// A platform signing API receives the message and operates on a key reference.
    Platform,
    /// The process obtains private key bytes and signs with its software implementation.
    Software,
}

/// A backend's current support and signing path for one requested key specification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    /// Whether this backend currently supports the requested key specification.
    pub supported: bool,
    /// Signing path used when this specification is supported.
    pub signing: SigningMode,
}
/// An opaque identifier meaningful only to the backend that issued it.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KeyId(pub Vec<u8>);

/// The private key representation a backend must accept for an identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum KeySpec {
    /// An RSA private key encoded as PKCS#1 DER, with the actual modulus size.
    Rsa { bits: u32 },
    /// A 32-byte Ed25519 seed, rather than an expanded keypair.
    Ed25519,
}

/// Public metadata kept alongside a private key and safe to list without fetching it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyInfo {
    /// The SSH public key, serialized as an OpenSSH public-key string.
    #[serde(with = "crate::serde::keydata")]
    pub identity: KeyData,
    /// The human-readable SSH comment used as the desktop item label.
    pub comment: String,
    /// The SHA-256 SSH fingerprint checked against the public identity on import.
    pub fingerprint: String,
}

/// A single import's public record and owned private key bytes.
///
/// Backends validate the relationship between the two before accepting the key.
pub struct KeyRecord {
    pub info: KeyInfo,
    /// Owned secret bytes, redacted in diagnostics and zeroized on drop.
    pub secret: SecretBox<[u8]>,
}

/// Storage and signing operations for keys owned by this application.
///
/// Calls are synchronous even when a backend bridges to an asynchronous platform
/// service. Implementations must support shared access from protocol workers.
pub trait KeyStore: Send + Sync {
    /// Identifies the backend in selection decisions and status output.
    fn kind(&self) -> Kind;
    /// Reports the cached availability probe, with a short uppercase error code on failure.
    fn available(&self) -> anyhow::Result<()>;
    /// Describes support for a key specification and the signing implementation used.
    fn capabilities(&self, spec: &KeySpec) -> Capabilities;
    /// Validates and consumes private material, rejecting an already stored identity.
    fn load(&self, record: KeyRecord) -> Result<KeyId, Error>;
    /// Lists backend-local identifiers and public records without returning private key bytes.
    fn list(&self) -> Result<Vec<(KeyId, KeyInfo)>, Error>;
    /// Signs a message and returns algorithm-specific bytes without SSH framing.
    fn sign(&self, id: &KeyId, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>, Error>;
    /// Removes the owned key addressed by this backend's handle.
    fn delete(&self, id: &KeyId) -> Result<(), Error>;
    /// Removes this application's keys, leaving unrelated platform entries alone.
    fn clear(&self) -> Result<(), Error>;
}

impl KeySpec {
    /// Rejects cross-family requests and legacy RSA/SHA-1 before accessing private bytes.
    pub fn supports(&self, algorithm: &Algorithm) -> bool {
        matches!(
            (self, algorithm),
            (KeySpec::Ed25519, Algorithm::Ed25519)
                | (
                    KeySpec::Rsa { .. },
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256 | HashAlg::Sha512)
                    }
                )
        )
    }
}

/// Derives the canonical private-key representation and actual RSA bit size from a public identity.
impl TryFrom<&KeyData> for KeySpec {
    type Error = anyhow::Error;

    fn try_from(key: &KeyData) -> Result<Self, Self::Error> {
        match key {
            KeyData::Ed25519(_) => Ok(KeySpec::Ed25519),
            KeyData::Rsa(public) => {
                let modulus = public.n().as_positive_bytes().context("RSA modulus must be positive")?;
                let first = modulus.first().context("RSA modulus must not be zero")?;
                Ok(KeySpec::Rsa {
                    bits: public.key_size() - first.leading_zeros(),
                })
            }
            _ => anyhow::bail!("unsupported key algorithm: {}", key.algorithm()),
        }
    }
}

/// Converts a decoded SSH private key into the encoding shared by all stores.
///
/// The result owns a secret copy; the caller still owns the input `PrivateKey`.
impl TryFrom<&PrivateKey> for KeyRecord {
    type Error = Error;

    fn try_from(key: &PrivateKey) -> Result<Self, Self::Error> {
        let identity = KeyData::from(key);
        let secret = match key.key_data() {
            ssh_key::private::KeypairData::Ed25519(key) => {
                SecretBox::from(key.private.as_ref().to_vec().into_boxed_slice())
            }
            ssh_key::private::KeypairData::Rsa(key) => {
                let rsa = RsaPrivateKey::try_from(key).map_err(|error| Error::InvalidKey(error.to_string()))?;
                if rsa.n().bit_width() < 2048 {
                    return Err(Error::InvalidKey("RSA keys require at least 2048 bits".into()));
                }
                rsa.validate().map_err(|error| Error::InvalidKey(error.to_string()))?;
                let der = rsa
                    .to_pkcs1_der()
                    .map_err(|error| Error::InvalidKey(error.to_string()))?;
                SecretBox::from(der.as_bytes().to_vec().into_boxed_slice())
            }
            _ => return Err(Error::Unsupported),
        };

        Ok(KeyRecord {
            info: KeyInfo {
                fingerprint: identity.fingerprint(HashAlg::Sha256).to_string(),
                identity,
                comment: key.comment().to_string(),
            },
            secret,
        })
    }
}

impl Debug for KeyRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keep private material out of diagnostics even when the caller logs an import.
        formatter
            .debug_struct("KeyRecord")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}
