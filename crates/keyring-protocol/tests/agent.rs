use anyhow::{Result, bail, ensure};
use keyring_core::{
    keystore::{Capabilities, Error as StoreError, KeyId, KeyInfo, KeyRecord, KeySpec, KeyStore, Kind, SigningMode},
    provider::{Error, Provider},
};
use keyring_protocol::{
    agent::Agent,
    codec::{Request, Response},
    control::{self, State},
};
use keyring_store_memory::MemoryStore;
use secrecy::{ExposeSecret, SecretBox};
use ssh_key::{Algorithm, PrivateKey, private::Ed25519Keypair};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

struct FixtureProvider {
    calls: AtomicUsize,
    keys: Vec<PrivateKey>,
}

impl Provider for FixtureProvider {
    fn load(
        &self,
        password: SecretBox<[u8]>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<KeyRecord>, Error>> + Send + '_>> {
        Box::pin(async move {
            assert_eq!(password.expose_secret(), b"fixture-password");
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.keys
                .iter()
                .map(|key| KeyRecord::try_from(key).map_err(|error| Error::Sync(error.into())))
                .collect()
        })
    }
}

fn password() -> SecretBox<[u8]> {
    SecretBox::from(b"fixture-password".to_vec().into_boxed_slice())
}

fn key(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

fn agent(keys: Vec<PrivateKey>, stores: Vec<Arc<dyn KeyStore>>) -> Result<Arc<Agent>> {
    Agent::new(
        Arc::new(FixtureProvider {
            calls: AtomicUsize::new(0),
            keys,
        }),
        stores,
    )
}

/// A memory-backed store that can impersonate platform priorities and failure modes.
struct MockStore {
    kind: Kind,
    supported: bool,
    rsa_only: bool,
    available: bool,
    fail_load: bool,
    fail_after_load: bool,
    fail_list: bool,
    /// Reject loads once this many keys have already been accepted.
    fail_after: Option<usize>,
    fail_clear: bool,
    /// Paired flags let a scenario invalidate the agent during backend signing.
    entered: Option<Arc<AtomicBool>>,
    release: Option<Arc<AtomicBool>>,
    memory: MemoryStore,
}

impl MockStore {
    /// Start with a usable store, then opt into only the faults a scenario needs.
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            supported: true,
            rsa_only: false,
            available: true,
            fail_load: false,
            fail_after_load: false,
            fail_list: false,
            fail_after: None,
            fail_clear: false,
            entered: None,
            release: None,
            memory: MemoryStore::default(),
        }
    }
}

impl KeyStore for MockStore {
    fn kind(&self) -> Kind {
        self.kind
    }

    fn available(&self) -> Result<()> {
        ensure!(self.available, "UNAVAILABLE");
        Ok(())
    }

    fn capabilities(&self, spec: &KeySpec) -> Capabilities {
        Capabilities {
            supported: self.available && self.supported && (!self.rsa_only || matches!(spec, KeySpec::Rsa { .. })),
            signing: SigningMode::Software,
        }
    }

    fn load(&self, record: KeyRecord) -> Result<KeyId, StoreError> {
        let spec = (&record.info.identity)
            .try_into()
            .map_err(|_| StoreError::Unsupported)?;
        if !self.capabilities(&spec).supported {
            return Err(StoreError::Unsupported);
        }
        if self.fail_load
            || self
                .fail_after
                .is_some_and(|limit| self.memory.list().map_or(true, |keys| keys.len() >= limit))
        {
            return Err(StoreError::Backend("injected failure".into()));
        }
        let handle = self.memory.load(record)?;
        if self.fail_after_load {
            return Err(StoreError::Backend("injected failure after writing a key".into()));
        }
        Ok(handle)
    }

    fn list(&self) -> Result<Vec<(KeyId, KeyInfo)>, StoreError> {
        if self.fail_list {
            return Err(StoreError::Backend("unreadable public metadata".into()));
        }
        self.memory.list()
    }

    fn sign(&self, handle: &KeyId, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>, StoreError> {
        if let (Some(entered), Some(release)) = (&self.entered, &self.release) {
            // Let the test revoke the generation while this worker owns the storage lock.
            entered.store(true, Ordering::SeqCst);
            while !release.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
        }
        self.memory.sign(handle, algorithm, data)
    }

    fn delete(&self, handle: &KeyId) -> Result<(), StoreError> {
        self.memory.delete(handle)
    }

    fn clear(&self) -> Result<(), StoreError> {
        if self.fail_clear {
            return Err(StoreError::Backend("injected cleanup failure".into()));
        }
        self.memory.clear()
    }
}

#[tokio::test]
async fn provider_is_loaded_only_on_explicit_unlock() -> Result<()> {
    let provider = Arc::new(FixtureProvider {
        calls: AtomicUsize::new(0),
        keys: vec![key(17)],
    });
    let memory = Arc::new(MemoryStore::default());
    let agent = Agent::new(provider.clone(), vec![memory.clone()])?;
    assert!(matches!(
        agent.status(),
        control::Response::Status {
            state: State::Locked,
            ..
        }
    ));
    assert!(matches!(
        agent.session().handle(Request::Identities).await,
        Response::Failure
    ));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);

    let cloned = Arc::clone(&agent);
    assert!(matches!(cloned.unlock(password()).await, control::Response::Success));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    let control::Response::Status { state, keys, .. } = agent.status() else {
        bail!("status missing");
    };
    assert_eq!(state, State::Unlocked);
    assert_eq!(keys.len(), 1);
    let mut session = agent.session();
    for _ in 0..2 {
        let Response::Identities(identities) = session.handle(Request::Identities).await else {
            anyhow::bail!("identities missing");
        };
        assert_eq!(identities.len(), 1);
        let Response::Signature(signature) = session
            .handle(Request::Signature {
                key: ssh_key::PublicKey::from(identities[0].0.clone()).to_bytes()?,
                data: b"fixture message".to_vec(),
                flags: 0,
            })
            .await
        else {
            anyhow::bail!("signature missing");
        };
        signature::Verifier::verify(
            &ssh_key::PublicKey::from(identities[0].0.clone()),
            b"fixture message",
            &signature,
        )?;
        assert!(matches!(agent.status(), control::Response::Status { keys, .. } if keys.len() == 1));
    }
    assert!(matches!(
        agent.unlock(password()).await,
        control::Response::Failure { code, .. } if code == "already-unlocked"
    ));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);

    assert!(matches!(agent.lock().await, control::Response::Success));
    assert!(matches!(
        cloned.status(),
        control::Response::Status {
            state: State::Locked,
            ..
        }
    ));
    assert!(memory.list()?.is_empty());
    assert!(matches!(session.handle(Request::Identities).await, Response::Failure));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert!(matches!(agent.unlock(password()).await, control::Response::Success));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    agent.clear().await?;
    Ok(())
}

struct FailingProvider {
    sync: bool,
}

impl Provider for FailingProvider {
    fn load(
        &self,
        _password: SecretBox<[u8]>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<KeyRecord>, Error>> + Send + '_>> {
        Box::pin(async move {
            let error = anyhow::anyhow!("fixture-secret-not-for-clients").context("fixture load failed");
            Err(if self.sync {
                Error::Sync(error)
            } else {
                Error::Auth(error)
            })
        })
    }
}

#[tokio::test]
async fn provider_failures_preserve_codes_and_roll_back_without_exposing_sources() -> Result<()> {
    for (sync, code) in [(false, "auth"), (true, "sync")] {
        let memory = Arc::new(MemoryStore::default());
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[17; 32]));
        memory.load(KeyRecord::try_from(&key)?)?;
        let agent = Agent::new(Arc::new(FailingProvider { sync }), vec![memory.clone()])?;
        let control::Response::Failure { code: actual, message } = agent.unlock(password()).await else {
            bail!("failure missing");
        };
        assert_eq!(actual, code);
        assert_eq!(message, "fixture load failed");
        assert!(matches!(
            agent.status(),
            control::Response::Status { state: State::Locked, keys, .. } if keys.is_empty()
        ));
        agent.clear().await?;
        assert!(memory.list()?.is_empty());
    }
    Ok(())
}

/// Construction needs no provider connection and exposes no keys before unlock.
#[tokio::test]
async fn startup_is_locked_and_does_not_authenticate() -> Result<()> {
    let provider = Arc::new(FixtureProvider {
        calls: AtomicUsize::new(0),
        keys: vec![key(1)],
    });
    let agent = Agent::new(provider.clone(), vec![Arc::new(MemoryStore::default())])?;
    let control::Response::Status {
        state, snapshot, keys, ..
    } = agent.status()
    else {
        bail!("status missing");
    };
    assert_eq!(state, State::Locked);
    assert!(snapshot.is_none() && keys.is_empty());
    assert!(matches!(
        agent.session().handle(Request::Identities).await,
        Response::Failure
    ));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn construction_requires_unique_stores_and_a_usable_memory_fallback() {
    let memory = Arc::new(MemoryStore::default());
    assert!(
        agent(
            vec![],
            vec![memory.clone(), Arc::new(MockStore::new(Kind::Keychain)), memory]
        )
        .is_err()
    );
    assert!(agent(vec![], vec![Arc::new(MockStore::new(Kind::Keychain))]).is_err());
    for (available, supported, rsa_only) in [(false, true, false), (true, false, false), (true, true, true)] {
        let mut memory = MockStore::new(Kind::Memory);
        memory.available = available;
        memory.supported = supported;
        memory.rsa_only = rsa_only;
        assert!(agent(vec![], vec![Arc::new(memory)]).is_err());
    }
}

#[tokio::test]
async fn status_reports_availability_and_unavailable_stores_are_skipped() -> Result<()> {
    let mut keychain = MockStore::new(Kind::Keychain);
    keychain.available = false;
    keychain.fail_clear = true;
    keychain.memory.load(KeyRecord::try_from(&key(2))?)?;
    let keychain = Arc::new(keychain);
    let retained = keychain.list()?;
    let memory = Arc::new(MemoryStore::default());
    let agent = agent(vec![key(1)], vec![keychain.clone(), memory.clone()])?;
    let control::Response::Status { stores, .. } = agent.status() else {
        bail!("status missing");
    };
    assert_eq!(stores.len(), 2);
    assert_eq!(stores[0].kind, Kind::Keychain);
    assert!(!stores[0].available);
    assert_eq!(stores[0].reason.as_deref(), Some("UNAVAILABLE"));
    assert_eq!(stores[1].kind, Kind::Memory);
    assert!(stores[1].available);
    assert!(stores[1].reason.is_none());
    assert!(matches!(agent.unlock(password()).await, control::Response::Success));
    assert!(matches!(
        agent.status(),
        control::Response::Status { keys, .. } if keys[0].store == Kind::Memory
    ));
    assert_eq!(keychain.list()?, retained);
    assert_eq!(memory.list()?.len(), 1);
    agent.clear().await?;
    assert_eq!(keychain.list()?, retained);
    assert!(memory.list()?.is_empty());
    Ok(())
}

/// Unsupported and failing platform stores both allow the memory fallback to win.
#[tokio::test]
async fn priority_capabilities_and_failed_import_fall_back_to_memory() -> Result<()> {
    for (available, supported) in [(false, true), (true, false)] {
        let mut keychain = MockStore::new(Kind::Keychain);
        keychain.available = available;
        keychain.supported = supported;
        let mut desktop = MockStore::new(Kind::FreeDesktop);
        desktop.fail_load = true;
        let memory = Arc::new(MemoryStore::default());
        let agent = agent(
            vec![key(1)],
            vec![memory.clone(), Arc::new(desktop), Arc::new(keychain)],
        )?;
        assert!(matches!(agent.unlock(password()).await, control::Response::Success));
        assert!(matches!(
            agent.status(),
            control::Response::Status { keys, .. } if keys[0].store == Kind::Memory
        ));
        assert_eq!(memory.list()?.len(), 1);
    }
    Ok(())
}

/// Priority is independent of input order; duplicate identities keep the last record.
#[tokio::test]
async fn imports_choose_highest_priority_and_deduplicate_last_record() -> Result<()> {
    let keychain = Arc::new(MockStore::new(Kind::Keychain));
    let desktop = Arc::new(MockStore::new(Kind::FreeDesktop));
    let memory = Arc::new(MemoryStore::default());
    let mut first = key(1);
    first.set_comment("first");
    let mut last = key(1);
    last.set_comment("last");
    let agent = agent(
        vec![first, last],
        vec![memory.clone(), desktop.clone(), keychain.clone()],
    )?;
    assert!(matches!(agent.unlock(password()).await, control::Response::Success));
    let control::Response::Status { keys, .. } = agent.status() else {
        bail!("status missing");
    };
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].comment, "last");
    assert_eq!(keychain.list()?.len(), 1);
    assert_eq!(keychain.list()?[0].1.comment, "last");
    assert!(desktop.list()?.is_empty());
    assert!(memory.list()?.is_empty());
    Ok(())
}

/// A full import removes old keys, rotated keys, and keys left in a second backend.
#[tokio::test]
async fn reconciliation_deletes_orphans_rotations_and_duplicate_homes() -> Result<()> {
    let keychain = Arc::new(MockStore::new(Kind::Keychain));
    let memory = Arc::new(MemoryStore::default());
    let mut previous = key(1);
    previous.set_comment("rotated key");
    keychain.load(KeyRecord::try_from(&previous)?)?;
    memory.load(KeyRecord::try_from(&key(2))?)?;
    memory.load(KeyRecord::try_from(&key(3))?)?;
    let mut replacement = key(3);
    replacement.set_comment("rotated key");
    let expected = KeyRecord::try_from(&replacement)?.info;
    let agent = agent(vec![replacement], vec![keychain.clone(), memory.clone()])?;
    assert!(matches!(agent.unlock(password()).await, control::Response::Success));
    let retained = keychain.list()?;
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].1, expected);
    assert!(memory.list()?.is_empty());
    let control::Response::Status { keys, .. } = agent.status() else {
        bail!("status missing");
    };
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].comment, "rotated key");
    assert_eq!(keys[0].fingerprint, expected.fingerprint);
    Ok(())
}

#[tokio::test]
async fn snapshot_cleanup_does_not_require_readable_public_metadata() -> Result<()> {
    let mut keychain = MockStore::new(Kind::Keychain);
    keychain.fail_list = true;
    keychain.memory.load(KeyRecord::try_from(&key(2))?)?;
    let keychain = Arc::new(keychain);
    let agent = agent(vec![key(1)], vec![keychain.clone(), Arc::new(MemoryStore::default())])?;
    assert!(matches!(agent.unlock(password()).await, control::Response::Success));
    let retained = keychain.memory.list()?;
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].1.identity, KeyRecord::try_from(&key(1))?.info.identity);
    assert!(matches!(
        agent.status(),
        control::Response::Status { keys, .. } if keys[0].store == Kind::Keychain
    ));
    agent.clear().await?;
    Ok(())
}

#[tokio::test]
async fn failed_import_requires_cleanup_before_fallback() -> Result<()> {
    for fail_list in [false, true] {
        let mut keychain = MockStore::new(Kind::Keychain);
        keychain.fail_after_load = true;
        keychain.fail_list = fail_list;
        let keychain = Arc::new(keychain);
        let memory = Arc::new(MemoryStore::default());
        let agent = agent(vec![key(1)], vec![keychain.clone(), memory.clone()])?;
        let response = agent.unlock(password()).await;
        if fail_list {
            assert!(matches!(response, control::Response::Failure { code, .. } if code == "store"));
            assert!(matches!(
                agent.status(),
                control::Response::Status { state: State::Locked, keys, .. } if keys.is_empty()
            ));
            assert!(memory.list()?.is_empty());
        } else {
            assert!(matches!(response, control::Response::Success));
            assert!(keychain.list()?.is_empty());
            assert_eq!(memory.list()?.len(), 1);
            assert!(matches!(
                agent.status(),
                control::Response::Status { keys, .. } if keys[0].store == Kind::Memory
            ));
        }
        agent.clear().await?;
        assert!(keychain.memory.list()?.is_empty());
    }
    Ok(())
}

/// Lock removes local data, clears snapshot metadata, and revokes existing sessions.
#[tokio::test]
async fn lock_clears_every_store_and_invalidates_sessions() -> Result<()> {
    let memory = Arc::new(MemoryStore::default());
    let agent = agent(vec![key(1)], vec![memory.clone()])?;
    assert!(matches!(agent.unlock(password()).await, control::Response::Success));
    let mut old = agent.session();
    let generation = agent.subscribe();
    assert!(matches!(agent.lock().await, control::Response::Success));
    assert!(memory.list()?.is_empty());
    assert!(matches!(
        agent.status(),
        control::Response::Status {
            state: State::Locked,
            snapshot: None,
            ..
        }
    ));
    assert!(generation.has_changed()?);
    assert!(matches!(old.handle(Request::Identities).await, Response::Failure));
    Ok(())
}

/// Cleanup errors do not reopen the agent or prevent later stores from clearing.
#[tokio::test]
async fn failed_clear_still_locks_and_clears_other_stores() -> Result<()> {
    let mut broken = MockStore::new(Kind::Keychain);
    broken.fail_clear = true;
    let memory = Arc::new(MemoryStore::default());
    memory.load(KeyRecord::try_from(&key(2))?)?;
    let agent = agent(vec![key(1)], vec![Arc::new(broken), memory.clone()])?;
    assert!(matches!(
        agent.unlock(password()).await,
        control::Response::Failure { code, .. } if code == "store"
    ));
    assert!(agent.clear().await.is_err());
    assert!(matches!(agent.lock().await, control::Response::Failure { code, .. } if code == "store"));
    assert!(memory.list()?.is_empty());
    assert!(matches!(
        agent.status(),
        control::Response::Status {
            state: State::Locked,
            ..
        }
    ));
    Ok(())
}

/// Authentication failure revokes publication and leaves rollback cleanup awaitable.
#[tokio::test]
async fn failed_unlock_rolls_back_without_publishing_keys() -> Result<()> {
    let agent = Agent::new(
        Arc::new(FailingProvider { sync: false }),
        vec![Arc::new(MemoryStore::default())],
    )?;
    let result = agent.unlock(password()).await;
    assert!(matches!(result, control::Response::Failure { code, .. } if code == "auth"));
    assert!(matches!(
        agent.status(),
        control::Response::Status { state: State::Locked, keys, .. } if keys.is_empty()
    ));
    agent.clear().await?;
    Ok(())
}

/// Revocation during backend signing must suppress the result from the old session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_rejects_a_signature_computed_with_an_old_generation() -> Result<()> {
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let mut keychain = MockStore::new(Kind::Keychain);
    keychain.entered = Some(entered.clone());
    keychain.release = Some(release.clone());
    let agent = agent(vec![key(1)], vec![Arc::new(keychain), Arc::new(MemoryStore::default())])?;
    assert!(matches!(agent.unlock(password()).await, control::Response::Success));
    let mut session = agent.session();
    let key = key(1).public_key().to_bytes()?;
    let signing = tokio::spawn(async move {
        session
            .handle(Request::Signature {
                key,
                data: b"request".to_vec(),
                flags: 0,
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    agent.invalidate();
    release.store(true, Ordering::SeqCst);
    assert!(matches!(signing.await?, Response::Failure));
    agent.clear().await?;
    Ok(())
}

/// Each algorithm selects its own capable store and produces a verifiable signature.
#[tokio::test]
async fn mixed_algorithms_choose_their_own_stores_and_verify() -> Result<()> {
    let mut keychain = MockStore::new(Kind::Keychain);
    keychain.rsa_only = true;
    let desktop = MockStore::new(Kind::FreeDesktop);
    let rsa = PrivateKey::from(ssh_key::private::RsaKeypair::random(&mut rand::rng(), 2048)?);
    let agent = agent(
        vec![rsa, key(8)],
        vec![Arc::new(keychain), Arc::new(desktop), Arc::new(MemoryStore::default())],
    )?;
    assert!(matches!(agent.unlock(password()).await, control::Response::Success));
    let control::Response::Status { keys, .. } = agent.status() else {
        bail!("status missing");
    };
    assert_eq!(keys[0].store, Kind::Keychain);
    assert_eq!(keys[0].algorithm, "rsa");
    assert_eq!(keys[1].store, Kind::FreeDesktop);
    assert_eq!(keys[1].algorithm, "ed25519");
    let mut session = agent.session();
    let Response::Identities(identities) = session.handle(Request::Identities).await else {
        bail!("identities missing");
    };
    for (identity, _) in identities {
        let key = ssh_key::PublicKey::from(identity);
        let requested_flags: &[u32] = if key.algorithm().is_rsa() { &[2, 4] } else { &[0] };
        for &flags in requested_flags {
            let Response::Signature(signature) = session
                .handle(Request::Signature {
                    key: key.to_bytes()?,
                    data: b"mixed stores".to_vec(),
                    flags,
                })
                .await
            else {
                bail!("signature missing");
            };
            signature::Verifier::verify(&key, b"mixed stores", &signature)?;
        }
    }
    agent.clear().await?;
    Ok(())
}

/// A failed import must roll back earlier successful writes before another transition.
#[tokio::test]
async fn partial_import_failure_rolls_back_all_stores() -> Result<()> {
    let mut memory = MockStore::new(Kind::Memory);
    memory.fail_load = true;
    let mut keychain = MockStore::new(Kind::Keychain);
    keychain.fail_after = Some(1);
    let keychain = Arc::new(keychain);
    let agent = agent(vec![key(1), key(2)], vec![keychain.clone(), Arc::new(memory)])?;
    let response = agent.unlock(password()).await;
    assert!(matches!(response, control::Response::Failure { code, .. } if code == "store"));
    assert!(matches!(
        agent.status(),
        control::Response::Status { state: State::Locked, keys, .. } if keys.is_empty()
    ));
    agent.clear().await?;
    assert!(keychain.list()?.is_empty());
    Ok(())
}
