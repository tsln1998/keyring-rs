//! Shared key records and the synchronous storage contract used by the protocol layer.
//!
//! Public records describe identities without carrying private key bytes. Import
//! material owns those bytes only until a backend consumes or drops it.

/// Key conversion, validation, and software signing shared by storage backends.
pub mod software;

use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, public::KeyData};

/// Owned secret bytes that are redacted by `secrecy` and zeroized on drop.
///
/// This wrapper does not prevent copies made by cryptographic or platform APIs.
pub type SecrecyBytes = SecretBox<[u8]>;

/// The private key representation a backend must accept for an identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum KeySpec {
    /// An RSA private key encoded as PKCS#1 DER, with the declared modulus size.
    Rsa { bits: u32 },
    /// A 32-byte Ed25519 seed, rather than an expanded keypair.
    Ed25519,
}

/// Backend identifiers shared by store selection and status output.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreKind {
    Keychain,
    FreeDesktop,
    Memory,
}

/// An opaque identifier meaningful only to the backend that issued it.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StoreHandle(pub Vec<u8>);

/// Public metadata kept alongside a private key and safe to list without fetching it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoreRecord {
    /// The SSH public key, serialized as an OpenSSH public-key string.
    #[serde(with = "identity")]
    pub identity: KeyData,
    /// The expected private key encoding and supported signing family.
    pub spec: KeySpec,
    /// The human-readable SSH comment used as the desktop item label.
    pub comment: String,
    /// The SHA-256 SSH fingerprint checked against the public identity on import.
    pub fingerprint: String,
}

/// Keeps serialized records independent of `ssh_key`'s internal key representation.
mod identity {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _, ser::Error as _};
    use ssh_key::{PublicKey, public::KeyData};

    /// Encodes only the public identity in the standard OpenSSH text format.
    pub fn serialize<S: Serializer>(key: &KeyData, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&PublicKey::from(key.clone()).to_openssh().map_err(S::Error::custom)?)
    }

    /// Parses the public key while leaving the record's separate comment untouched.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<KeyData, D::Error> {
        let text = String::deserialize(deserializer)?;
        PublicKey::from_openssh(&text)
            .map(KeyData::from)
            .map_err(D::Error::custom)
    }
}

/// A listed public identity paired with its backend-specific handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredKey {
    pub handle: StoreHandle,
    pub record: StoreRecord,
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
    pub supported: bool,
    pub signing: SigningMode,
}

/// A single import's public record and owned private key bytes.
///
/// Backends validate the relationship between the two before accepting the key.
pub struct StoreMaterial {
    pub record: StoreRecord,
    pub secret: SecrecyBytes,
}

impl std::fmt::Debug for StoreMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keep private material out of diagnostics even when the caller logs an import.
        formatter
            .debug_struct("StoreMaterial")
            .field("record", &self.record)
            .finish_non_exhaustive()
    }
}

/// Failures shared by all backends so callers can handle them consistently.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
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

/// Storage and signing operations for keys owned by this application.
///
/// Calls are synchronous even when a backend bridges to an asynchronous platform
/// service. Implementations must support shared access from protocol workers.
pub trait Store: Send + Sync {
    /// Identifies the backend in selection decisions and status output.
    fn kind(&self) -> StoreKind;
    /// Reports whether the backend's availability probe succeeded.
    fn available(&self) -> bool;
    /// Supplies a short status reason when the backend is unavailable.
    fn unavailable_reason(&self) -> Option<String> {
        (!self.available()).then(|| "UNAVAILABLE".to_owned())
    }
    /// Describes support for a key specification and the signing implementation used.
    fn capabilities(&self, spec: &KeySpec) -> Capabilities;
    /// Validates and consumes private material, rejecting an already stored identity.
    fn load(&self, material: StoreMaterial) -> Result<StoreHandle, StoreError>;
    /// Lists owned public records without returning private key bytes.
    fn list(&self) -> Result<Vec<StoredKey>, StoreError>;
    /// Signs a message and returns algorithm-specific bytes without SSH framing.
    fn sign(&self, handle: &StoreHandle, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>, StoreError>;
    /// Removes the owned key addressed by this backend's handle.
    fn delete(&self, handle: &StoreHandle) -> Result<(), StoreError>;
    /// Removes this application's keys, leaving unrelated platform entries alone.
    fn clear(&self) -> Result<(), StoreError>;
}
