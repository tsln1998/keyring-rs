//! Process-local storage and software signing for imported SSH keys.
//!
//! Unix builds own anonymous mappings for private bytes and request memory locking.
//! Linux also requests exclusion from ordinary core dumps. These are best-effort
//! measures, not protection against arbitrary reads of the running process.

/// Reusable backend behavior checks and deliberately non-secret test fixtures.
pub mod contract;

use keyring_core::{
    Capabilities, KeySpec, SigningMode, Store, StoreError, StoreHandle, StoreKind, StoreMaterial, StoreRecord,
    StoredKey, software,
};
use secrecy::ExposeSecret;
#[cfg(unix)]
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

/// Owns one key's public record and its platform-specific private byte allocation.
///
/// On Unix, `length` is the key size and `allocation` includes page padding that
/// must also be wiped and unmapped. Other platforms use the secret wrapper directly.
struct ProtectedMaterial {
    record: StoreRecord,
    #[cfg(not(unix))]
    secret: keyring_core::SecrecyBytes,
    #[cfg(unix)]
    secret: std::ptr::NonNull<u8>,
    #[cfg(unix)]
    length: usize,
    #[cfg(unix)]
    allocation: usize,
    /// Records whether `mlock` succeeded so cleanup only unlocks a locked mapping.
    #[cfg(unix)]
    locked: bool,
}

#[cfg(unix)]
// SAFETY: The mapping is exclusively owned and stays at the same address when this
// value moves between threads. MemoryStore serializes access and destruction.
unsafe impl Send for ProtectedMaterial {}

impl ProtectedMaterial {
    /// Moves an import into owned storage, copying to a dedicated mapping on Unix.
    fn new(material: StoreMaterial) -> Result<Self, StoreError> {
        #[cfg(unix)]
        {
            let length = material.secret.expose_secret().len();
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if page_size <= 0 {
                return Err(StoreError::Backend("cannot determine memory page size".into()));
            }
            // A separate, whole-page mapping lets memory protections apply without
            // affecting unrelated allocations managed by the Rust allocator.
            let allocation = length.div_ceil(page_size as usize) * page_size as usize;
            let pointer = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    allocation,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if pointer == libc::MAP_FAILED {
                return Err(StoreError::Backend("cannot allocate private key memory".into()));
            }
            let Some(secret) = std::ptr::NonNull::new(pointer.cast::<u8>()) else {
                unsafe {
                    libc::munmap(pointer, allocation);
                }
                return Err(StoreError::Backend("invalid private key allocation".into()));
            };
            // Resource limits can make mlock fail; the store still accepts the key.
            let locked = unsafe { libc::mlock(pointer, allocation) == 0 };
            #[cfg(target_os = "linux")]
            unsafe {
                // This advice is best effort and does not prevent a live memory dump.
                libc::madvise(pointer, allocation, libc::MADV_DONTDUMP);
            }
            unsafe {
                // SAFETY: The mapping is writable, covers length bytes, and is
                // distinct from the still-live source allocation.
                std::ptr::copy_nonoverlapping(material.secret.expose_secret().as_ptr(), secret.as_ptr(), length);
            }
            Ok(Self {
                record: material.record,
                secret,
                length,
                allocation,
                locked,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                record: material.record,
                secret: material.secret,
            })
        }
    }

    /// Borrows only initialized key bytes while their owning material remains alive.
    fn bytes(&self) -> &[u8] {
        #[cfg(unix)]
        {
            // SAFETY: new initialized this prefix and Drop cannot run during the borrow.
            unsafe { std::slice::from_raw_parts(self.secret.as_ptr(), self.length) }
        }
        #[cfg(not(unix))]
        {
            self.secret.expose_secret()
        }
    }
}

impl Drop for ProtectedMaterial {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            unsafe {
                // SAFETY: This value exclusively owns the live mapping. Wipe the
                // entire allocation before releasing its lock and virtual pages.
                std::slice::from_raw_parts_mut(self.secret.as_ptr(), self.allocation).zeroize();
                if self.locked {
                    libc::munlock(self.secret.as_ptr().cast(), self.allocation);
                }
                libc::munmap(self.secret.as_ptr().cast(), self.allocation);
            }
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
