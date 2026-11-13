//! Process-local storage and software signing for imported SSH keys.
//!
//! Private bytes live in dedicated pages managed by `region`, with best-effort
//! memory locking on each supported platform. Linux also requests exclusion from
//! ordinary core dumps. These measures do not prevent arbitrary process reads.

use keyring_core::{
    Capabilities, KeySpec, SigningMode, Store, StoreError, StoreHandle, StoreKind, StoreMaterial, StoreRecord,
    StoredKey, software,
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
    keys: HashMap<StoreHandle, ProtectedMaterial>,
}

/// Owns private pages; `length` excludes page padding, which must also be wiped.
struct ProtectedMaterial {
    record: StoreRecord,
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
    fn new(material: StoreMaterial) -> Result<Self, StoreError> {
        let length = material.secret.expose_secret().len();
        let mut secret = region::alloc(length, Protection::READ_WRITE)
            .map_err(|error| StoreError::Backend(format!("cannot allocate private key memory: {error}")))?;
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
            record: material.record,
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

impl Store for MemoryStore {
    fn kind(&self) -> StoreKind {
        StoreKind::Memory
    }
    fn available(&self) -> bool {
        true
    }
    fn capabilities(&self, _: &KeySpec) -> Capabilities {
        Capabilities {
            supported: true,
            signing: SigningMode::Software,
        }
    }
    fn load(&self, material: StoreMaterial) -> Result<StoreHandle, StoreError> {
        software::validate(&material)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| StoreError::Backend("memory lock poisoned".into()))?;
        if state
            .keys
            .values()
            .any(|key| key.record.identity == material.record.identity)
        {
            return Err(StoreError::Duplicate);
        }
        // Never recycle a deleted handle within this store instance: a stale handle
        // must not start referring to a later import.
        state.next = state
            .next
            .checked_add(1)
            .ok_or_else(|| StoreError::Backend("handle space exhausted".into()))?;
        let handle = StoreHandle(state.next.to_be_bytes().to_vec());
        state.keys.insert(handle.clone(), ProtectedMaterial::new(material)?);
        Ok(handle)
    }
    fn list(&self) -> Result<Vec<StoredKey>, StoreError> {
        let state = self
            .state
            .lock()
            .map_err(|_| StoreError::Backend("memory lock poisoned".into()))?;
        Ok(state
            .keys
            .iter()
            .map(|(handle, key)| StoredKey {
                handle: handle.clone(),
                record: key.record.clone(),
            })
            .collect())
    }
    fn sign(&self, handle: &StoreHandle, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>, StoreError> {
        // Keep the mutex guard through signing so delete/clear cannot drop the
        // mapping while the signer borrows its private bytes.
        let state = self
            .state
            .lock()
            .map_err(|_| StoreError::Backend("memory lock poisoned".into()))?;
        let key = state.keys.get(handle).ok_or(StoreError::NotFound)?;
        if !software::supports_algorithm(&key.record.spec, &algorithm) {
            return Err(StoreError::Unsupported);
        }
        software::sign(key.bytes(), algorithm, data)
    }
    fn delete(&self, handle: &StoreHandle) -> Result<(), StoreError> {
        // Removing the owning value immediately runs its private-byte cleanup.
        self.state
            .lock()
            .map_err(|_| StoreError::Backend("memory lock poisoned".into()))?
            .keys
            .remove(handle)
            .ok_or(StoreError::NotFound)?;
        Ok(())
    }
    fn clear(&self) -> Result<(), StoreError> {
        // Dropping every value releases the keys without resetting the handle sequence.
        self.state
            .lock()
            .map_err(|_| StoreError::Backend("memory lock poisoned".into()))?
            .keys
            .clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{PrivateKey, private::Ed25519Keypair};

    #[test]
    fn private_pages_preserve_unaligned_payload_across_threads() -> Result<(), Box<dyn std::error::Error>> {
        let expected = (0..region::page::size() + 7)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut material = software::material(&PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32])))?;
        material.secret = keyring_core::SecrecyBytes::from(expected.clone().into_boxed_slice());
        let key = ProtectedMaterial::new(material)?;
        std::thread::spawn(move || assert_eq!(key.bytes(), expected))
            .join()
            .map_err(|_| "private page check panicked")?;
        Ok(())
    }
}
