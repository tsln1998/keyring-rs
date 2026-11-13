//! macOS Keychain storage with different signing paths for RSA and Ed25519.
//!
//! Public records are generic-password items. RSA keys are imported as SecKey
//! objects and signed through Security.framework; Ed25519 seeds are separate
//! generic-password items retrieved for software signing. Neither path promises
//! Secure Enclave or other hardware-backed storage.

#![cfg(target_os = "macos")]

use core_foundation::{
    base::{CFType, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFMutableDictionary,
    error::{CFError, CFErrorRef},
    number::CFNumber,
    string::{CFString, CFStringRef},
};
use keyring_core::{
    Capabilities, KeySpec, SigningMode, Store, StoreError, StoreHandle, StoreKind, StoreMaterial, StoreRecord,
    StoredKey, software,
};
use secrecy::ExposeSecret;
use security_framework::{
    item::{ItemClass, ItemSearchOptions, Limit, SearchResult},
    key::{Algorithm as SecAlgorithm, SecKey},
    os::macos::keychain::SecKeychain,
    passwords::{delete_generic_password, get_generic_password, set_generic_password},
};
use security_framework_sys::{
    item::*,
    key::SecKeyCreateWithData,
    keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete},
};
use ssh_key::{Algorithm, HashAlg};
use std::{ffi::c_void, ptr};
use zeroize::Zeroizing;

/// Public records are stored separately so listing does not retrieve private material.
const RECORDS: &str = "keyring-rs.records";
/// Ed25519 seeds need a distinct service from their public records.
const SEEDS: &str = "keyring-rs.ed25519";
/// Scopes RSA key queries and whole-store deletion to this application.
const LABEL: &str = "keyring-rs";
/// Security.framework's missing-item result is benign during bulk cleanup.
const ITEM_NOT_FOUND: i32 = -25300;

// These Security.framework symbols support attributes and a non-interactive
// availability probe not exposed by the higher-level wrappers used below.
unsafe extern "C" {
    static kSecAttrApplicationTag: CFStringRef;
    static kSecAttrIsExtractable: CFStringRef;
    fn SecKeychainGetStatus(keychain: *mut c_void, status: *mut u32) -> i32;
}

/// A Keychain backend retaining the result of its initial availability probe.
pub struct KeychainStore {
    reason: Option<String>,
}

/// Adapts platform and serialization failures to the backend error variant.
fn error(error: impl std::fmt::Display) -> StoreError {
    StoreError::Backend(error.to_string())
}

/// Converts a raw OSStatus, treating only zero as success.
fn check(status: i32) -> Result<(), StoreError> {
    if status == 0 {
        Ok(())
    } else {
        Err(error(security_framework::base::Error::from_code(status)))
    }
}

/// Retains a borrowed framework attribute constant as an owned Core Foundation value.
///
/// The caller must supply a valid CFStringRef exported by Security.framework.
unsafe fn attribute(name: CFStringRef) -> CFType {
    unsafe { CFString::wrap_under_get_rule(name).as_CFType() }
}

impl KeychainStore {
    /// Checks the default keychain's existence and unlocked status without unlocking it.
    pub fn new() -> Self {
        let reason = match SecKeychain::default() {
            Err(_) => Some("NO_KEYCHAIN".into()),
            Ok(keychain) => {
                let mut status = 0;
                let result = unsafe { SecKeychainGetStatus(keychain.as_concrete_TypeRef().cast(), &mut status) };
                if result != 0 {
                    Some("PROBE_FAILED".into())
                } else if status & 1 == 0 {
                    // Bit 0 is kSecUnlockStateStatus; no user prompt is requested here.
                    Some("LOCKED".into())
                } else {
                    None
                }
            }
        };
        Self { reason }
    }

    /// Rejects operations when the cached startup probe found an unavailable keychain.
    fn ready(&self) -> Result<(), StoreError> {
        match &self.reason {
            Some(reason) => Err(StoreError::Unavailable(reason.clone())),
            None => Ok(()),
        }
    }

    /// Uses the fingerprint-based handle as the generic-password account name.
    fn account(handle: &StoreHandle) -> Result<&str, StoreError> {
        std::str::from_utf8(&handle.0).map_err(error)
    }

    /// Loads public metadata separately from an RSA key object or Ed25519 seed.
    fn record(handle: &StoreHandle) -> Result<StoreRecord, StoreError> {
        let bytes = get_generic_password(RECORDS, Self::account(handle)?).map_err(|e| {
            if e.code() == ITEM_NOT_FOUND {
                StoreError::NotFound
            } else {
                error(e)
            }
        })?;
        serde_json::from_slice(&bytes).map_err(error)
    }

    /// Matches an RSA item by both the application label and its per-key tag.
    fn key_query(handle: &StoreHandle) -> CFMutableDictionary<CFType, CFType> {
        let mut query = CFMutableDictionary::new();
        unsafe {
            query.set(attribute(kSecClass), attribute(kSecClassKey));
            query.set(
                attribute(kSecAttrApplicationTag),
                CFData::from_buffer(&handle.0).as_CFType(),
            );
            query.set(attribute(kSecAttrLabel), CFString::new(LABEL).as_CFType());
        }
        query
    }

    /// Obtains a retained platform key reference without exporting its private bytes.
    fn rsa_key(handle: &StoreHandle) -> Result<SecKey, StoreError> {
        let mut query = Self::key_query(handle);
        let mut raw = ptr::null();
        unsafe {
            query.set(attribute(kSecReturnRef), CFBoolean::true_value().as_CFType());
            check(SecItemCopyMatching(query.as_concrete_TypeRef(), &mut raw))?;
        }
        if raw.is_null() {
            return Err(StoreError::NotFound);
        }
        // SAFETY: A successful CopyMatching with kSecReturnRef transfers an owned
        // key reference, released by SecKey's Core Foundation wrapper.
        Ok(unsafe { SecKey::wrap_under_create_rule(raw.cast_mut().cast()) })
    }

    /// Imports PKCS#1 DER as a non-extractable RSA key and persists its reference.
    ///
    /// Non-extractability is an API policy on this imported key, not a claim that
    /// the original software key was generated in protected hardware.
    fn rsa_import(material: &StoreMaterial, handle: &StoreHandle, bits: u32) -> Result<(), StoreError> {
        let mut attributes = CFMutableDictionary::<CFType, CFType>::new();
        unsafe {
            attributes.set(attribute(kSecAttrKeyType), attribute(kSecAttrKeyTypeRSA));
            attributes.set(attribute(kSecAttrKeyClass), attribute(kSecAttrKeyClassPrivate));
            attributes.set(
                attribute(kSecAttrKeySizeInBits),
                CFNumber::from(bits as i64).as_CFType(),
            );
            attributes.set(attribute(kSecAttrIsExtractable), CFBoolean::false_value().as_CFType());
        }
        let data = CFData::from_buffer(material.secret.expose_secret());
        let mut failure: CFErrorRef = ptr::null_mut();
        let raw = unsafe {
            SecKeyCreateWithData(
                data.as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
                &mut failure,
            )
        };
        if raw.is_null() {
            if !failure.is_null() {
                // SAFETY: The failed create call transfers ownership of its CFError.
                return Err(error(unsafe { CFError::wrap_under_create_rule(failure) }));
            }
            return Err(error("SecKeyCreateWithData failed"));
        }
        // SAFETY: SecKeyCreateWithData follows the create rule. The wrapper owns
        // this reference while SecItemAdd persists the key in the keychain.
        let key = unsafe { SecKey::wrap_under_create_rule(raw) };
        let mut query = Self::key_query(handle);
        unsafe {
            query.set(attribute(kSecValueRef), key.as_CFType());
            query.set(attribute(kSecAttrIsExtractable), CFBoolean::false_value().as_CFType());
            check(SecItemAdd(query.as_concrete_TypeRef(), ptr::null_mut()))?;
        }
        Ok(())
    }
}

impl Default for KeychainStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Store for KeychainStore {
    fn kind(&self) -> StoreKind {
        StoreKind::Keychain
    }
    fn available(&self) -> bool {
        self.reason.is_none()
    }
    fn unavailable_reason(&self) -> Option<String> {
        self.reason.clone()
    }
    fn capabilities(&self, spec: &KeySpec) -> Capabilities {
        Capabilities {
            supported: self.available(),
            // Keychain storage alone does not imply platform signing for every key.
            signing: match spec {
                KeySpec::Rsa { .. } => SigningMode::Platform,
                KeySpec::Ed25519 => SigningMode::Software,
            },
        }
    }
    fn load(&self, material: StoreMaterial) -> Result<StoreHandle, StoreError> {
        self.ready()?;
        software::validate(&material)?;
        let handle = StoreHandle(format!("keyring-rs:{}", material.record.fingerprint).into_bytes());
        if self
            .list()?
            .iter()
            .any(|key| key.record.identity == material.record.identity)
        {
            return Err(StoreError::Duplicate);
        }
        let record = serde_json::to_vec(&material.record).map_err(error)?;
        // Import spans two items rather than a transaction. If private material
        // fails to load, attempt to remove the already-written public record too.
        set_generic_password(RECORDS, Self::account(&handle)?, &record).map_err(error)?;
        let result = match material.record.spec {
            KeySpec::Rsa { bits } => Self::rsa_import(&material, &handle, bits),
            KeySpec::Ed25519 => {
                set_generic_password(SEEDS, Self::account(&handle)?, material.secret.expose_secret()).map_err(error)
            }
        };
        if let Err(failure) = result {
            // Cleanup is best effort; retain the original import failure for callers.
            let _ = self.delete(&handle);
            return Err(failure);
        }
        Ok(handle)
    }
    fn list(&self) -> Result<Vec<StoredKey>, StoreError> {
        self.ready()?;
        // Search only the public-record service; seeds and RSA key data stay untouched.
        let result = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(RECORDS)
            .load_data(true)
            .limit(Limit::All)
            .search();
        let result = match result {
            Ok(result) => result,
            Err(error) if error.code() == ITEM_NOT_FOUND => return Ok(Vec::new()),
            Err(failure) => return Err(error(failure)),
        };
        result
            .into_iter()
            .map(|item| {
                let SearchResult::Data(data) = item else {
                    return Err(error("unexpected Keychain record format"));
                };
                let record: StoreRecord = serde_json::from_slice(&data).map_err(error)?;
                Ok(StoredKey {
                    handle: StoreHandle(format!("keyring-rs:{}", record.fingerprint).into_bytes()),
                    record,
                })
            })
            .collect()
    }
    fn sign(&self, handle: &StoreHandle, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.ready()?;
        let record = Self::record(handle)?;
        if !software::supports_algorithm(&record.spec, &algorithm) {
            return Err(StoreError::Unsupported);
        }
        match record.spec {
            KeySpec::Ed25519 => {
                // Wipe the returned seed buffer after this attempt. The Keychain
                // API and signing library may have their own temporary copies.
                let seed = Zeroizing::new(get_generic_password(SEEDS, Self::account(handle)?).map_err(error)?);
                software::sign(&seed, algorithm, data)
            }
            KeySpec::Rsa { .. } => {
                let key = Self::rsa_key(handle)?;
                // The Message variants hash data inside Security.framework, matching
                // the software signer's RSA PKCS#1 v1.5 message-signing behavior.
                let algorithm = match algorithm {
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    } => SecAlgorithm::RSASignatureMessagePKCS1v15SHA256,
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha512),
                    } => SecAlgorithm::RSASignatureMessagePKCS1v15SHA512,
                    _ => return Err(StoreError::Unsupported),
                };
                key.create_signature(algorithm, data).map_err(error)
            }
        }
    }
    fn delete(&self, handle: &StoreHandle) -> Result<(), StoreError> {
        self.ready()?;
        let record = Self::record(handle)?;
        let status = match record.spec {
            KeySpec::Rsa { .. } => unsafe { SecItemDelete(Self::key_query(handle).as_concrete_TypeRef()) },
            KeySpec::Ed25519 => delete_generic_password(SEEDS, Self::account(handle)?)
                .map(|()| 0)
                .unwrap_or_else(|error| error.code()),
        };
        if status != ITEM_NOT_FOUND {
            check(status)?;
        }
        // Remove metadata only after private-item deletion succeeds or finds no item.
        delete_generic_password(RECORDS, Self::account(handle)?).map_err(error)
    }
    fn clear(&self) -> Result<(), StoreError> {
        self.ready()?;
        // Bulk queries do not depend on valid records to locate private items.
        // Continue through every category after an individual failure.
        let mut failed = ItemSearchOptions::new()
            .class(ItemClass::key())
            .label(LABEL)
            .delete()
            .is_err_and(|error| error.code() != ITEM_NOT_FOUND);
        for service in [SEEDS, RECORDS] {
            if let Err(error) = ItemSearchOptions::new()
                .class(ItemClass::generic_password())
                .service(service)
                .delete()
            {
                failed |= error.code() != ITEM_NOT_FOUND;
            }
        }
        if failed {
            return Err(error("failed to clear one or more Keychain items"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{PrivateKey, Signature, private::Ed25519Keypair};

    #[test]
    #[ignore = "requires a real unlocked macOS Keychain; not verified in CI"]
    fn stored_keys_sign_and_rsa_is_not_extractable() -> Result<(), Box<dyn std::error::Error>> {
        let store = KeychainStore::new();
        assert!(store.available());
        store.clear()?;
        let rsa = PrivateKey::from(ssh_key::private::RsaKeypair::random(&mut rand::rng(), 2048)?);
        for key in [PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32])), rsa] {
            let material = software::material(&key)?;
            let record = material.record.clone();
            let handle = store.load(material)?;
            assert!(store.list()?.iter().any(|stored| stored.record == record));
            let algorithm = if key.algorithm().is_rsa() {
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                }
            } else {
                Algorithm::Ed25519
            };
            let signature = Signature::new(algorithm.clone(), store.sign(&handle, algorithm, b"keychain")?)?;
            signature::Verifier::verify(key.public_key(), b"keychain", &signature)?;
            let extractable =
                key.algorithm().is_rsa() && KeychainStore::rsa_key(&handle)?.external_representation().is_some();
            store.delete(&handle)?;
            assert!(store.list()?.is_empty());
            assert!(!extractable, "imported RSA key must not be extractable");
        }
        store.load(software::material(&PrivateKey::from(Ed25519Keypair::from_seed(
            &[42; 32],
        )))?)?;
        store.clear()?;
        assert!(store.list()?.is_empty());
        Ok(())
    }
}
