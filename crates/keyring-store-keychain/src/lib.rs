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
    crypto,
    keystore::{Capabilities, Error, KeyId, KeyInfo, KeyRecord, KeySpec, KeyStore, Kind, SigningMode},
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
use std::{
    ffi::c_void,
    ptr,
    sync::{Mutex, OnceLock},
};
use zeroize::Zeroizing;

/// Public records are stored separately so listing does not retrieve private material.
const RECORDS: &str = "keyring-rs.records";
/// Ed25519 seeds need a distinct service from their public records.
const SEEDS: &str = "keyring-rs.ed25519";
/// Scopes RSA key queries and whole-store deletion to this application.
const LABEL: &str = "keyring-rs";
/// Security.framework's missing-item result is benign during bulk cleanup.
const ITEM_NOT_FOUND: i32 = -25300;
/// Probe passwords never overlap public records or private key material.
const PROBE: &str = "keyring-rs.probe";
/// User-interaction settings are process-wide, so probes must restore them in order.
static PROBE_LOCK: Mutex<()> = Mutex::new(());

// These Security.framework symbols support attributes and a non-interactive
// availability probe not exposed by the higher-level wrappers used below.
unsafe extern "C" {
    static kSecAttrApplicationTag: CFStringRef;
    static kSecAttrIsExtractable: CFStringRef;
    fn SecKeychainGetStatus(keychain: *mut c_void, status: *mut u32) -> i32;
}

/// A Keychain backend retaining the result of its initial availability probe.
pub struct KeychainStore {
    availability: OnceLock<Result<(), String>>,
}

/// Adapts platform and serialization failures to the backend error variant.
fn error(error: impl std::fmt::Display) -> Error {
    Error::Backend(error.to_string())
}

/// Converts a raw OSStatus, treating only zero as success.
fn check(status: i32) -> Result<(), Error> {
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
    /// Verifies the unlocked default keychain with a temporary write/read/delete round trip.
    pub fn new() -> Self {
        let store = Self {
            availability: OnceLock::new(),
        };
        let _ = store.available();
        store
    }

    /// Checks storage permissions without prompting, retaining the result for this instance.
    fn probe() -> Result<(), String> {
        let _lock = PROBE_LOCK.lock().map_err(|_| "PROBE_FAILED".to_owned())?;
        // The framework guard re-enables interaction on drop; only create it if
        // interaction was enabled so an already-disabled setting stays disabled.
        let _interaction = if SecKeychain::user_interaction_allowed().map_err(|_| "PROBE_FAILED".to_owned())? {
            Some(SecKeychain::disable_user_interaction().map_err(|_| "PROBE_FAILED".to_owned())?)
        } else {
            None
        };
        let keychain = SecKeychain::default().map_err(|_| "NO_KEYCHAIN".to_owned())?;
        let mut status = 0;
        let result = unsafe { SecKeychainGetStatus(keychain.as_concrete_TypeRef().cast(), &mut status) };
        if result != 0 {
            return Err("PROBE_FAILED".into());
        }
        // Bit 0 is kSecUnlockStateStatus; probing never attempts to unlock the keychain.
        if status & 1 == 0 {
            return Err("LOCKED".into());
        }
        let nonce = rand::random::<u128>();
        let account = format!("{nonce:032x}");
        let payload = nonce.to_be_bytes();
        let mut query = CFMutableDictionary::<CFType, CFType>::new();
        unsafe {
            query.set(attribute(kSecClass), attribute(kSecClassGenericPassword));
            query.set(attribute(kSecAttrService), CFString::new(PROBE).as_CFType());
            query.set(attribute(kSecAttrAccount), CFString::new(&account).as_CFType());
            query.set(attribute(kSecUseKeychain), keychain.as_CFType());
            query.set(attribute(kSecValueData), CFData::from_buffer(&payload).as_CFType());
            // SecItemAdd fails on collision instead of overwriting an existing password.
            check(SecItemAdd(query.as_concrete_TypeRef(), ptr::null_mut())).map_err(|_| "PROBE_FAILED".to_owned())?;
        }
        let result = get_generic_password(PROBE, &account)
            .map_err(|_| "PROBE_FAILED".to_owned())
            .and_then(|bytes| {
                if bytes == payload {
                    Ok(())
                } else {
                    Err("PROBE_FAILED".to_owned())
                }
            });
        let cleanup = delete_generic_password(PROBE, &account).map_err(|_| "PROBE_FAILED".to_owned());
        result.and(cleanup)
    }

    /// Rejects operations when the cached startup probe found an unavailable keychain.
    fn ready(&self) -> Result<(), Error> {
        self.availability
            .get_or_init(Self::probe)
            .as_ref()
            .map(|_| ())
            .map_err(|reason| Error::Unavailable(reason.clone()))
    }

    /// Uses the fingerprint-based handle as the generic-password account name.
    fn account(handle: &KeyId) -> Result<&str, Error> {
        std::str::from_utf8(&handle.0).map_err(error)
    }

    /// Loads public metadata separately from an RSA key object or Ed25519 seed.
    fn record(handle: &KeyId) -> Result<KeyInfo, Error> {
        let bytes = get_generic_password(RECORDS, Self::account(handle)?).map_err(|e| {
            if e.code() == ITEM_NOT_FOUND {
                Error::NotFound
            } else {
                error(e)
            }
        })?;
        serde_json::from_slice(&bytes).map_err(error)
    }

    /// Matches an RSA item by both the application label and its per-key tag.
    fn key_query(handle: &KeyId) -> CFMutableDictionary<CFType, CFType> {
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
    fn rsa_key(handle: &KeyId) -> Result<SecKey, Error> {
        let mut query = Self::key_query(handle);
        let mut raw = ptr::null();
        unsafe {
            query.set(attribute(kSecReturnRef), CFBoolean::true_value().as_CFType());
            check(SecItemCopyMatching(query.as_concrete_TypeRef(), &mut raw))?;
        }
        if raw.is_null() {
            return Err(Error::NotFound);
        }
        // SAFETY: A successful CopyMatching with kSecReturnRef transfers an owned
        // key reference, released by SecKey's Core Foundation wrapper.
        Ok(unsafe { SecKey::wrap_under_create_rule(raw.cast_mut().cast()) })
    }

    /// Imports PKCS#1 DER as a non-extractable RSA key and persists its reference.
    ///
    /// Non-extractability is an API policy on this imported key, not a claim that
    /// the original software key was generated in protected hardware.
    fn rsa_import(material: &KeyRecord, handle: &KeyId, bits: u32) -> Result<(), Error> {
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

impl KeyStore for KeychainStore {
    fn kind(&self) -> Kind {
        Kind::Keychain
    }
    fn available(&self) -> anyhow::Result<()> {
        self.availability
            .get_or_init(Self::probe)
            .as_ref()
            .map(|_| ())
            .map_err(|reason| anyhow::anyhow!("{reason}"))
    }
    fn capabilities(&self, spec: &KeySpec) -> Capabilities {
        Capabilities {
            supported: self.available().is_ok(),
            // Keychain storage alone does not imply platform signing for every key.
            signing: match spec {
                KeySpec::Rsa { .. } => SigningMode::Platform,
                KeySpec::Ed25519 => SigningMode::Software,
            },
        }
    }
    fn load(&self, record: KeyRecord) -> Result<KeyId, Error> {
        self.ready()?;
        crypto::validate(&record)?;
        let spec: KeySpec = (&record.info.identity).try_into().map_err(|_| Error::Unsupported)?;
        let handle = KeyId(format!("keyring-rs:{}", record.info.fingerprint).into_bytes());
        if self
            .list()?
            .iter()
            .any(|(_, info)| info.identity == record.info.identity)
        {
            return Err(Error::Duplicate);
        }
        let payload = serde_json::to_vec(&record.info).map_err(error)?;
        // Import spans two items rather than a transaction. If private material
        // fails to load, attempt to remove the already-written public record too.
        set_generic_password(RECORDS, Self::account(&handle)?, &payload).map_err(error)?;
        let result = match spec {
            KeySpec::Rsa { bits } => Self::rsa_import(&record, &handle, bits),
            KeySpec::Ed25519 => {
                set_generic_password(SEEDS, Self::account(&handle)?, record.secret.expose_secret()).map_err(error)
            }
        };
        if let Err(failure) = result {
            // Cleanup is best effort; retain the original import failure for callers.
            let _ = self.delete(&handle);
            return Err(failure);
        }
        Ok(handle)
    }
    fn list(&self) -> Result<Vec<(KeyId, KeyInfo)>, Error> {
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
                let record: KeyInfo = serde_json::from_slice(&data).map_err(error)?;
                Ok((KeyId(format!("keyring-rs:{}", record.fingerprint).into_bytes()), record))
            })
            .collect()
    }
    fn sign(&self, handle: &KeyId, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.ready()?;
        let record = Self::record(handle)?;
        let spec: KeySpec = (&record.identity).try_into().map_err(|_| Error::Unsupported)?;
        if !spec.supports(&algorithm) {
            return Err(Error::Unsupported);
        }
        match spec {
            KeySpec::Ed25519 => {
                // Wipe the returned seed buffer after this attempt. The Keychain
                // API and signing library may have their own temporary copies.
                let seed = Zeroizing::new(get_generic_password(SEEDS, Self::account(handle)?).map_err(error)?);
                crypto::sign(&seed, algorithm, data)
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
                    _ => return Err(Error::Unsupported),
                };
                key.create_signature(algorithm, data).map_err(error)
            }
        }
    }
    fn delete(&self, handle: &KeyId) -> Result<(), Error> {
        self.ready()?;
        let record = Self::record(handle)?;
        let spec: KeySpec = (&record.identity).try_into().map_err(|_| Error::Unsupported)?;
        let status = match spec {
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
    fn clear(&self) -> Result<(), Error> {
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
    fn cached_probe_result_controls_availability_and_capabilities() -> anyhow::Result<()> {
        let store = KeychainStore {
            availability: OnceLock::from(Ok(())),
        };
        store.available()?;
        for reason in ["NO_KEYCHAIN", "LOCKED", "PROBE_FAILED"] {
            let store = KeychainStore {
                availability: OnceLock::from(Err(reason.into())),
            };
            std::thread::scope(|scope| {
                for _ in 0..8 {
                    let store = &store;
                    scope.spawn(move || {
                        for _ in 0..3 {
                            assert_eq!(store.available().expect_err("unavailable store").to_string(), reason);
                            assert!(matches!(store.ready(), Err(Error::Unavailable(value)) if value == reason));
                        }
                    });
                }
            });
            for spec in [KeySpec::Ed25519, KeySpec::Rsa { bits: 2048 }] {
                assert!(!store.capabilities(&spec).supported);
            }
        }
        Ok(())
    }

    #[test]
    #[ignore = "requires a real unlocked macOS Keychain; not verified in CI"]
    fn stored_keys_sign_and_rsa_is_not_extractable() -> Result<(), Box<dyn std::error::Error>> {
        let store = KeychainStore::new();
        store.available()?;
        store.clear()?;
        let rsa = PrivateKey::from(ssh_key::private::RsaKeypair::random(&mut rand::rng(), 2048)?);
        for key in [PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32])), rsa] {
            let material = KeyRecord::try_from(&key)?;
            let record = material.info.clone();
            let handle = store.load(material)?;
            assert!(store.list()?.iter().any(|(_, info)| info == &record));
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
        store.load(KeyRecord::try_from(&PrivateKey::from(Ed25519Keypair::from_seed(
            &[42; 32],
        )))?)?;
        store.clear()?;
        assert!(store.list()?.is_empty());
        Ok(())
    }
}
