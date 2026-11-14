//! Process-local storage and software signing for imported SSH keys.
//!
//! Private bytes live in dedicated pages managed by `region`, with best-effort
//! memory locking on each supported platform. Linux also requests exclusion from
//! ordinary core dumps. These measures do not prevent arbitrary process reads.

use keyring_core::{
    crypto,
    keystore::{Capabilities, Error, KeyId, KeyInfo, KeyRecord, KeySpec, KeyStore, Kind, SigningMode},
};
use region::{Allocation, LockGuard, Protection};
use secrecy::ExposeSecret;
use secrecy::zeroize::Zeroize;
use ssh_key::Algorithm;
use std::{collections::HashMap, sync::Mutex};

/// The always-available fallback store, with all key access serialized by a mutex.
#[derive(Default)]
pub struct MemoryStore {
    state: Mutex<State>,
}

/// Owns imported keys and a monotonically increasing handle sequence.
#[derive(Default)]
struct State {
    next: u64,
    keys: HashMap<KeyId, ProtectedMaterial>,
}

/// Owns private pages; `length` excludes page padding, which must also be wiped.
struct ProtectedMaterial {
    info: KeyInfo,
    /// Field order releases the lock before its allocation is freed.
    _lock: Option<LockGuard>,
    secret: Allocation,
    length: usize,
}

// SAFETY: The mapping is exclusively owned and stays at the same address when this
// value moves between threads. MemoryStore serializes access and destruction.
unsafe impl Send for ProtectedMaterial {}

impl ProtectedMaterial {
    /// Copies imported bytes into dedicated pages on every supported platform.
    fn new(material: KeyRecord) -> Result<Self, Error> {
        let length = material.secret.expose_secret().len();
        let mut secret = region::alloc(length, Protection::READ_WRITE)
            .map_err(|error| Error::Backend(format!("cannot allocate private key memory: {error}")))?;
        let lock = region::lock(secret.as_ptr::<u8>(), secret.len()).ok();
        #[cfg(target_os = "linux")]
        unsafe {
            libc::madvise(secret.as_mut_ptr(), secret.len(), libc::MADV_DONTDUMP);
        }
        unsafe {
            // SAFETY: The writable allocation covers length bytes and is distinct
            // from the source, whose owner zeroizes it when this function returns.
            std::ptr::copy_nonoverlapping(material.secret.expose_secret().as_ptr(), secret.as_mut_ptr(), length);
        }
        Ok(Self {
            info: material.info,
            _lock: lock,
            secret,
            length,
        })
    }

    /// Borrows only initialized key bytes while their owning material remains alive.
    fn bytes(&self) -> &[u8] {
        // SAFETY: new initialized this prefix and Drop cannot run during the borrow.
        unsafe { std::slice::from_raw_parts(self.secret.as_ptr(), self.length) }
    }
}

impl Drop for ProtectedMaterial {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: This value exclusively owns the writable allocation. Fields
            // release the lock and allocation only after the entire region is wiped.
            std::slice::from_raw_parts_mut(self.secret.as_mut_ptr::<u8>(), self.secret.len()).zeroize();
        }
    }
}

impl KeyStore for MemoryStore {
    fn kind(&self) -> Kind {
        Kind::Memory
    }
    fn available(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn capabilities(&self, _: &KeySpec) -> Capabilities {
        Capabilities {
            supported: true,
            signing: SigningMode::Software,
        }
    }
    fn load(&self, record: KeyRecord) -> Result<KeyId, Error> {
        crypto::validate(&record)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::Backend("memory lock poisoned".into()))?;
        if state.keys.values().any(|key| key.info.identity == record.info.identity) {
            return Err(Error::Duplicate);
        }
        // Never recycle a deleted handle within this store instance: a stale handle
        // must not start referring to a later import.
        state.next = state
            .next
            .checked_add(1)
            .ok_or_else(|| Error::Backend("handle space exhausted".into()))?;
        let handle = KeyId(state.next.to_be_bytes().to_vec());
        state.keys.insert(handle.clone(), ProtectedMaterial::new(record)?);
        Ok(handle)
    }
    fn list(&self) -> Result<Vec<(KeyId, KeyInfo)>, Error> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::Backend("memory lock poisoned".into()))?;
        Ok(state
            .keys
            .iter()
            .map(|(handle, key)| (handle.clone(), key.info.clone()))
            .collect())
    }
    fn sign(&self, handle: &KeyId, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>, Error> {
        // Keep the mutex guard through signing so delete/clear cannot drop the
        // mapping while the signer borrows its private bytes.
        let state = self
            .state
            .lock()
            .map_err(|_| Error::Backend("memory lock poisoned".into()))?;
        let key = state.keys.get(handle).ok_or(Error::NotFound)?;
        let spec: KeySpec = (&key.info.identity).try_into().map_err(|_| Error::Unsupported)?;
        if !spec.supports(&algorithm) {
            return Err(Error::Unsupported);
        }
        crypto::sign(key.bytes(), algorithm, data)
    }
    fn delete(&self, handle: &KeyId) -> Result<(), Error> {
        // Removing the owning value immediately runs its private-byte cleanup.
        self.state
            .lock()
            .map_err(|_| Error::Backend("memory lock poisoned".into()))?
            .keys
            .remove(handle)
            .ok_or(Error::NotFound)?;
        Ok(())
    }
    fn clear(&self) -> Result<(), Error> {
        // Dropping every value releases the keys without resetting the handle sequence.
        self.state
            .lock()
            .map_err(|_| Error::Backend("memory lock poisoned".into()))?
            .keys
            .clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretBox;
    use ssh_key::{PrivateKey, private::Ed25519Keypair};

    #[test]
    fn private_pages_preserve_unaligned_payload_across_threads() -> Result<(), Box<dyn std::error::Error>> {
        let expected = (0..region::page::size() + 7)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut material = KeyRecord::try_from(&PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32])))?;
        material.secret = SecretBox::from(expected.clone().into_boxed_slice());
        let key = ProtectedMaterial::new(material)?;
        std::thread::spawn(move || assert_eq!(key.bytes(), expected))
            .join()
            .map_err(|_| "private page check panicked")?;
        Ok(())
    }
}
