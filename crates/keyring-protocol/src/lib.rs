//! SSH-agent request handling and the shared lock/unlock lifecycle.
//!
//! An explicit unlock loads the provider once and imports private material into
//! stores. The published state keeps public records and store handles, without
//! retaining a provider session or scheduling refreshes. Signing uses those handles.
//!
//! State transitions and blocking store access have separate locks. Invalidating
//! a generation immediately revokes sessions, while store cleanup may finish later
//! and can fail. Already running blocking work cannot be stopped by dropping its
//! async caller.

/// Control extension names and the JSON messages shared with clients.
pub mod control;

use anyhow::{Context, Result, bail};
use control::{KeyStatus, Outcome, Phase, Snapshot, Status, StoreStatus};
use keyring_core::{KeySpec, SecrecyBytes, Store, StoreHandle, StoreKind, StoreMaterial, StoreRecord};
use keyring_provider::{LoadError, config::BitwardenConfig};
use secrecy::ExposeSecret;
use ssh_agent_lib::{
    agent::{Agent, ListeningSocket, Session},
    error::AgentError,
    proto::{
        Extension, Identity, RSA_SHA2_256, RSA_SHA2_512, SignRequest,
        extension::{MessageExtension, QueryResponse, SessionBind},
    },
};
use ssh_key::{Algorithm, HashAlg, Signature, public::KeyData};
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::{OwnedMutexGuard, watch};

/// OpenSSH's signed binding between a connection and an SSH session.
const BIND: &str = SessionBind::NAME;

/// A cloneable service handle whose clones share keys, stores, and lifecycle state.
#[derive(Clone)]
pub struct ServiceAgent {
    shared: Arc<Shared>,
}

/// Shared ownership for all connections served by one agent instance.
struct Shared {
    /// Provider configuration only; the account decryption session is not retained.
    config: BitwardenConfig,
    /// Actual backend instances in selection order, including unavailable ones.
    stores: Vec<Arc<dyn Store>>,
    /// Short critical sections protect public state and session authorization.
    state: Mutex<State>,
    /// Serializes transitions across async provider work and subsequent cleanup.
    operations: Arc<tokio::sync::Mutex<()>>,
    /// Serializes blocking import, signing, and cleanup without blocking async tasks.
    storage: Arc<Mutex<()>>,
    /// Notifies the transport when invalidation makes existing sessions obsolete.
    generation: watch::Sender<u64>,
}

/// The visible snapshot; no private key bytes or provider decryption keys live here.
struct State {
    phase: Phase,
    generation: u64,
    keys: BTreeMap<KeyData, Binding>,
    snapshot: Option<Snapshot>,
}

/// Routes a public identity to the backend that accepted its private material.
#[derive(Clone)]
struct Binding {
    kind: StoreKind,
    handle: StoreHandle,
    record: StoreRecord,
}

/// Per-connection authorization generation and accepted OpenSSH session bindings.
///
/// A session remains tied to the generation in which it was created. Locking
/// invalidates it permanently, even if the shared service is unlocked again.
pub struct ServiceSession {
    agent: ServiceAgent,
    generation: u64,
    /// Session IDs and forwarding flags; these do not impose per-key restrictions.
    binds: Vec<(Vec<u8>, bool)>,
}

/// Recover the state guard even after poisoning so invalidation remains possible.
fn state(shared: &Shared) -> MutexGuard<'_, State> {
    shared.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl ServiceAgent {
    /// Build a locked service with unique backend kinds and a usable memory fallback.
    ///
    /// Backends are sorted by `StoreKind` priority: Keychain, FreeDesktop, Memory.
    /// Construction validates configuration and capabilities without loading the vault.
    pub fn new(config: BitwardenConfig, mut stores: Vec<Arc<dyn Store>>) -> Result<Self> {
        config.validate()?;
        stores.sort_by_key(|store| store.kind());
        let mut kinds = HashSet::new();
        if stores.iter().any(|store| !kinds.insert(store.kind())) {
            bail!("duplicate store kind");
        }
        // Require both supported algorithms in the final fallback, regardless of
        // which platform stores are available on this machine.
        if !stores.iter().any(|store| {
            store.kind() == StoreKind::Memory
                && store.available()
                && store.capabilities(&KeySpec::Ed25519).supported
                && store.capabilities(&KeySpec::Rsa { bits: 2048 }).supported
        }) {
            bail!("a memory store supporting RSA and Ed25519 is required");
        }
        Ok(Self {
            shared: Arc::new(Shared {
                config,
                stores,
                state: Mutex::new(State {
                    phase: Phase::Locked,
                    generation: 0,
                    keys: BTreeMap::new(),
                    snapshot: None,
                }),
                operations: Arc::new(tokio::sync::Mutex::new(())),
                storage: Arc::new(Mutex::new(())),
                generation: watch::channel(0).0,
            }),
        })
    }

    /// Capture the current generation for a newly accepted connection.
    pub fn session(&self) -> ServiceSession {
        ServiceSession {
            agent: self.clone(),
            generation: state(&self.shared).generation,
            binds: Vec::new(),
        }
    }

    /// Watch generation changes so the transport can close invalidated connections.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.shared.generation.subscribe()
    }

    /// Return public key metadata and the actual stores in their current order.
    ///
    /// Reading status never contacts the provider or refreshes the snapshot.
    pub fn status(&self) -> Status {
        let current = state(&self.shared);
        let mut keys: Vec<_> = current
            .keys
            .values()
            .map(|binding| {
                let capabilities = self
                    .shared
                    .stores
                    .iter()
                    .find(|store| store.kind() == binding.kind)
                    .map(|store| store.capabilities(&binding.record.spec));
                let (algorithm, bits) = match binding.record.spec {
                    KeySpec::Ed25519 => ("ed25519", None),
                    KeySpec::Rsa { bits } => ("rsa", Some(bits)),
                };
                // Bindings are published only after a store from this fixed Vec
                // accepts the key, so every binding must resolve to a backend.
                let capabilities = capabilities.expect("binding store exists");
                KeyStatus {
                    fingerprint: binding.record.fingerprint.clone(),
                    comment: binding.record.comment.clone(),
                    algorithm: algorithm.into(),
                    bits,
                    store: binding.kind,
                    signing: capabilities.signing,
                }
            })
            .collect();
        keys.sort_by(|left, right| {
            (left.store, &left.comment, &left.fingerprint).cmp(&(right.store, &right.comment, &right.fingerprint))
        });
        // Report the owned backends directly; unavailable stores stay visible,
        // but backends absent from this agent are never synthesized.
        let stores = self
            .shared
            .stores
            .iter()
            .map(|store| StoreStatus {
                kind: store.kind(),
                available: store.available(),
                reason: store.unavailable_reason(),
            })
            .collect();
        Status {
            state: current.phase,
            snapshot: current.snapshot.clone(),
            stores,
            keys,
        }
    }

    /// Load, decrypt, and import one remote snapshot using the supplied password.
    ///
    /// Only a complete import is published. Failure or cancellation invalidates
    /// the generation and schedules rollback; rollback store errors are logged.
    /// Temporary secret buffers are dropped with their owners, but cancellation
    /// cannot immediately stop blocking work or erase copies held by dependencies.
    pub async fn unlock(&self, password: SecrecyBytes) -> Outcome {
        let operation = match Arc::clone(&self.shared.operations).try_lock_owned() {
            Ok(guard) => guard,
            Err(_) => return Outcome::failure("busy", "another state transition is in progress"),
        };
        let generation = {
            let mut current = state(&self.shared);
            if current.phase != Phase::Locked {
                return Outcome::failure("already-unlocked", "agent is already unlocked");
            }
            current.phase = Phase::Loading;
            current.generation
        };
        // Keep rollback armed across every await, including cancellation when
        // the transport drops this future before an outcome can be returned.
        let mut rollback = Rollback {
            shared: Arc::clone(&self.shared),
            operation: Some(operation),
            active: true,
        };
        // The provider returns import material without retaining the account
        // decryption session or access token. Configuration, including API
        // credentials, remains available for future explicit unlocks.
        let materials = match keyring_provider::load(self.shared.config.clone(), password).await {
            Ok(materials) => materials,
            Err(LoadError::Auth(error)) => {
                let message = if error
                    .chain()
                    .any(|cause| cause.to_string().contains("missing master password unlock data"))
                {
                    "Bitwarden token response is missing userDecryptionOptions.masterPasswordUnlock"
                } else {
                    "Bitwarden authentication or master-password unlock failed"
                };
                return Outcome::failure("auth", message);
            }
            Err(LoadError::Sync(_)) => return Outcome::failure("sync", "failed to sync and decrypt Bitwarden vault"),
        };
        let shared = Arc::clone(&self.shared);
        // Backend APIs are synchronous. A detached worker may finish after this
        // future is cancelled; the storage lock orders rollback after that work.
        let imported = tokio::task::spawn_blocking(move || import(&shared, materials, generation)).await;
        let bindings = match imported {
            Ok(Ok(bindings)) => bindings,
            _ => return Outcome::failure("store", "failed to import keys; agent remains locked"),
        };
        {
            let mut current = state(&self.shared);
            // Invalidation can race with blocking import, so recheck before
            // exposing any of its bindings to SSH clients.
            if current.generation != generation {
                return Outcome::failure("cancelled", "unlock was cancelled");
            }
            current.keys = bindings;
            stamp(&mut current);
            current.phase = Phase::Unlocked;
        }
        // Publish all keys together before disarming cleanup.
        rollback.active = false;
        Outcome::success()
    }

    /// Revoke sessions immediately, then await cleanup of every available store.
    ///
    /// A cleanup failure leaves the agent locked but can leave backend data behind.
    /// Competing transitions return `busy` rather than waiting.
    pub async fn lock(&self) -> Outcome {
        let operation = match Arc::clone(&self.shared.operations).try_lock_owned() {
            Ok(guard) => guard,
            Err(_) => return Outcome::failure("busy", "another state transition is in progress"),
        };
        // Revocation precedes potentially slow or failing backend cleanup.
        self.invalidate();
        let shared = Arc::clone(&self.shared);
        match tokio::task::spawn_blocking(move || {
            // Let the blocking worker retain transition ownership if its async
            // caller disappears while cleanup is still running.
            let _operation = operation;
            clear(&shared)
        })
        .await
        {
            Ok(Ok(())) => Outcome::success(),
            _ => Outcome::failure("store", "agent locked, but a platform store could not be cleared"),
        }
    }

    /// Clear published metadata and advance the session generation synchronously.
    ///
    /// This revokes access but does not remove data from any backend. Call `lock`
    /// or `clear` when store cleanup is also required.
    pub fn invalidate(&self) {
        let mut current = state(&self.shared);
        current.phase = Phase::Locked;
        current.keys.clear();
        current.snapshot = None;
        current.generation = current.generation.wrapping_add(1);
        self.shared.generation.send_replace(current.generation);
    }

    /// Revoke sessions and wait for transition ownership before clearing stores.
    ///
    /// Used when cleanup must wait for outstanding work, such as shutdown or
    /// configuration replacement. Unavailable stores are skipped; errors propagate.
    pub async fn clear(&self) -> Result<()> {
        self.invalidate();
        let operation = Arc::clone(&self.shared.operations).lock_owned().await;
        let shared = Arc::clone(&self.shared);
        tokio::task::spawn_blocking(move || {
            let _operation = operation;
            clear(&shared)
        })
        .await?
    }
}

/// Record when a complete import was published; this timestamp is not an expiry.
fn stamp(current: &mut State) {
    let now = OffsetDateTime::now_utc();
    current.snapshot = Some(Snapshot {
        loaded_at: now.format(&Rfc3339).unwrap_or_default(),
    });
}

/// Restores locked state if unlock exits before publishing a complete snapshot.
///
/// The transition guard moves into cleanup so a new unlock cannot overtake it.
struct Rollback {
    shared: Arc<Shared>,
    operation: Option<OwnedMutexGuard<()>>,
    active: bool,
}

impl Drop for Rollback {
    /// Revoke synchronously, then schedule cleanup without blocking the async thread.
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        ServiceAgent {
            shared: Arc::clone(&self.shared),
        }
        .invalidate();
        let shared = Arc::clone(&self.shared);
        let operation = self.operation.take();
        // Cleanup waits behind any import or signature already holding storage.
        // Drop cannot await it or return an error, so failures are logged instead.
        tokio::task::spawn_blocking(move || {
            let _operation = operation;
            if clear(&shared).is_err() {
                tracing::error!("failed to clear stores during rollback");
            }
        });
    }
}

/// Attempt every available store even if an earlier store fails to clear.
///
/// The storage lock prevents cleanup from racing with an import or backend sign.
/// Success says nothing about stores skipped because they are unavailable.
fn clear(shared: &Shared) -> Result<()> {
    let _storage = shared
        .storage
        .lock()
        .map_err(|_| anyhow::anyhow!("storage lock poisoned"))?;
    let mut failed = false;
    for store in shared.stores.iter().filter(|store| store.available()) {
        if store.clear().is_err() {
            failed = true;
            tracing::error!(store = ?store.kind(), "failed to clear store");
        }
    }
    if failed {
        bail!("one or more stores could not be cleared");
    }
    Ok(())
}

/// Replace store contents and choose the first usable home for each public identity.
///
/// The caller publishes the resulting bindings or rolls back all stores on error.
/// Cancellation during blocking work is handled by that rollback after this
/// function releases the storage lock.
fn import(shared: &Shared, materials: Vec<StoreMaterial>, generation: u64) -> Result<BTreeMap<KeyData, Binding>> {
    let _storage = shared
        .storage
        .lock()
        .map_err(|_| anyhow::anyhow!("storage lock poisoned"))?;
    // Check after acquiring storage: cancellation may have happened while this
    // worker was queued behind cleanup or a signature.
    {
        let current = state(shared);
        if current.generation != generation || current.phase != Phase::Loading {
            bail!("key import was cancelled");
        }
    }
    // Public identity, rather than provider record ID, defines a unique SSH key.
    // Later duplicate records replace earlier records and their metadata.
    let mut unique = BTreeMap::new();
    for material in materials {
        unique.insert(material.record.identity.clone(), material);
    }
    // Reconcile from a complete snapshot by removing old keys from every usable
    // backend, including duplicate homes and keys removed from the remote vault.
    for store in shared.stores.iter().filter(|store| store.available()) {
        for key in store.list()? {
            store.delete(&key.handle)?;
        }
    }
    let mut bindings = BTreeMap::new();
    for (_, material) in unique {
        let mut home = None;
        for store in shared.stores.iter().filter(|store| store.available()) {
            if !store.capabilities(&material.record.spec).supported {
                continue;
            }
            // Each backend consumes its input, so preserve the original secret
            // for fallback and give each attempt its own zeroizing secret buffer.
            let copy = StoreMaterial {
                record: material.record.clone(),
                secret: SecrecyBytes::from(material.secret.expose_secret().to_vec().into_boxed_slice()),
            };
            match store.load(copy) {
                Ok(handle) => {
                    home = Some(Binding {
                        kind: store.kind(),
                        handle,
                        record: material.record.clone(),
                    });
                    break;
                }
                Err(_) => {
                    tracing::warn!(store = ?store.kind(), "key import failed; trying next store");
                    // A failing backend may have written the key before returning
                    // an error. Remove that partial home before trying another.
                    for key in store.list()? {
                        if key.record.identity == material.record.identity {
                            store.delete(&key.handle)?;
                        }
                    }
                }
            }
        }
        // A failure after earlier successes is left for the caller's rollback;
        // this function never publishes a partial set of keys.
        let binding = home.context("all stores rejected a key")?;
        bindings.insert(binding.record.identity.clone(), binding);
    }
    Ok(bindings)
}

impl<S: ListeningSocket + fmt::Debug + Send> Agent<S> for ServiceAgent {
    /// Give each accepted stream its own generation and session-binding history.
    fn new_session(&mut self, _: &S::Stream) -> impl Session {
        self.session()
    }
}

#[ssh_agent_lib::async_trait]
impl Session for ServiceSession {
    /// Enumerate the published identities in the map's public-key order.
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let current = state(&self.agent.shared);
        self.check(&current)?;
        Ok(current
            .keys
            .iter()
            .map(|(identity, binding)| Identity {
                pubkey: identity.clone(),
                comment: binding.record.comment.clone(),
            })
            .collect())
    }

    /// Dispatch signing to the selected backend without contacting the provider.
    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let binding = {
            let current = state(&self.agent.shared);
            self.check(&current)?;
            current.keys.get(&request.pubkey).cloned().ok_or(AgentError::Failure)?
        };
        let algorithm = algorithm(&binding.record.spec, request.flags)?;
        let shared = Arc::clone(&self.agent.shared);
        let generation = self.generation;
        // Clone only routing metadata; private material remains owned by stores.
        tokio::task::spawn_blocking(move || {
            let _storage = shared.storage.lock().map_err(other)?;
            // Authorization can change while this worker waits for store access.
            {
                let current = state(&shared);
                if current.phase != Phase::Unlocked || current.generation != generation {
                    return Err(AgentError::Failure);
                }
            }
            let store = shared
                .stores
                .iter()
                .find(|store| store.kind() == binding.kind)
                .ok_or(AgentError::Failure)?;
            let bytes = store
                .sign(&binding.handle, algorithm.clone(), &request.data)
                .map_err(other)?;
            // Invalidation cannot interrupt a backend already signing. Discard
            // its result if the generation changed during that operation.
            let current = state(&shared);
            if current.phase != Phase::Unlocked || current.generation != generation {
                return Err(AgentError::Failure);
            }
            Signature::new(algorithm, bytes).map_err(other)
        })
        .await
        .map_err(other)?
    }

    /// Handle explicit controls and the supported standard SSH-agent extensions.
    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        let name = extension.name;
        let details = extension.details.into_bytes();
        let response = match name.as_str() {
            control::UNLOCK => {
                // Unlock carries raw password bytes, not JSON. Move them into
                // the secret owner before awaiting the provider operation.
                let password = SecrecyBytes::from(details.into_boxed_slice());
                serde_json::to_vec(&self.agent.unlock(password).await).map_err(other)?
            }
            control::LOCK if details.is_empty() => serde_json::to_vec(&self.agent.lock().await).map_err(other)?,
            control::STATUS if details.is_empty() => serde_json::to_vec(&self.agent.status()).map_err(other)?,
            control::LOCK | control::STATUS => {
                serde_json::to_vec(&Outcome::failure("usage", "extension payload must be empty")).map_err(other)?
            }
            "query" => {
                // Advertise standard extensions only; clients already know the
                // private control names. Refresh is client-side lock + unlock.
                return Extension::new_message(QueryResponse {
                    extensions: vec!["query".into(), BIND.into()],
                })
                .map(Some)
                .map_err(other);
            }
            BIND => {
                let extension = Extension {
                    name,
                    details: details.into(),
                };
                let bind = extension
                    .parse_message::<SessionBind>()
                    .map_err(|_| AgentError::ExtensionFailure)?
                    .ok_or(AgentError::ExtensionFailure)?;
                bind.verify_signature().map_err(|_| AgentError::ExtensionFailure)?;
                // Bound the forwarding chain, reject replayed session IDs, and
                // forbid extending a chain after its non-forwarding endpoint.
                if self.binds.len() >= 64
                    || self
                        .binds
                        .iter()
                        .any(|(id, forwarding)| *id == bind.session_id || !forwarding)
                {
                    return Err(AgentError::ExtensionFailure);
                }
                self.binds.push((bind.session_id, bind.is_forwarding));
                return Ok(None);
            }
            _ => return Err(AgentError::ExtensionFailure),
        };
        Ok(Some(Extension {
            name,
            details: response.into(),
        }))
    }
}

impl ServiceSession {
    /// Require both unlocked state and the generation captured at connection time.
    fn check(&self, current: &State) -> Result<(), AgentError> {
        if current.phase != Phase::Unlocked || current.generation != self.generation {
            return Err(AgentError::Failure);
        }
        Ok(())
    }
}

/// Validate SSH signing flags without allowing the legacy RSA/SHA-1 default.
///
/// Ed25519 accepts no flags. If both RSA SHA-2 flags are present, SHA-256 wins.
fn algorithm(spec: &KeySpec, flags: u32) -> Result<Algorithm, AgentError> {
    match spec {
        KeySpec::Ed25519 if flags == 0 => Ok(Algorithm::Ed25519),
        KeySpec::Rsa { .. } if flags & !(RSA_SHA2_256 | RSA_SHA2_512) == 0 => {
            if flags & RSA_SHA2_256 != 0 {
                Ok(Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                })
            } else if flags & RSA_SHA2_512 != 0 {
                Ok(Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                })
            } else {
                Err(AgentError::Failure)
            }
        }
        _ => Err(AgentError::Failure),
    }
}

/// Adapt backend, serialization, and task errors to the SSH-agent error type.
fn other(error: impl fmt::Display) -> AgentError {
    AgentError::other(std::io::Error::other(error.to_string()))
}

#[cfg(test)]
mod tests {
    //! Lifecycle, routing, and SSH extension scenarios using deterministic local keys.
    //!
    //! Most scenarios publish material directly to isolate the protocol from provider
    //! authentication. The failed-unlock scenario uses an unreachable local endpoint.
    //! Mock stores inject backend failures and pause signing at a controlled point.

    use super::*;
    use keyring_core::{Capabilities, SigningMode, StoreError, StoredKey, software};
    use keyring_store_memory::MemoryStore;
    use ssh_agent_lib::proto::Request;
    use ssh_key::{PrivateKey, private::Ed25519Keypair};
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    /// Supply valid configuration with no usable provider, exposing accidental fetches.
    fn config() -> BitwardenConfig {
        BitwardenConfig {
            api_url: "http://127.0.0.1:1".into(),
            identity_url: "http://127.0.0.1:1".into(),
            client_id: "id".into(),
            client_secret: "secret".into(),
        }
    }

    /// Create the real shared service around the scenario's selected store instances.
    fn agent(stores: Vec<Arc<dyn Store>>) -> Result<ServiceAgent> {
        ServiceAgent::new(config(), stores)
    }

    /// Build a repeatable Ed25519 identity.
    fn material(seed: u8) -> Result<StoreMaterial> {
        Ok(software::material(&PrivateKey::from(Ed25519Keypair::from_seed(
            &[seed; 32],
        )))?)
    }

    /// Exercise real import and publication while bypassing remote authentication.
    ///
    /// This helper deliberately omits the async transition guard and rollback; failure
    /// scenarios construct those pieces explicitly when their behavior matters.
    fn publish(agent: &ServiceAgent, materials: Vec<StoreMaterial>) -> Result<()> {
        let generation = {
            let mut current = state(&agent.shared);
            current.phase = Phase::Loading;
            current.generation
        };
        let bindings = import(&agent.shared, materials, generation)?;
        let mut current = state(&agent.shared);
        current.keys = bindings;
        current.phase = Phase::Unlocked;
        stamp(&mut current);
        Ok(())
    }

    /// A memory-backed store that can impersonate platform priorities and failure modes.
    struct MockStore {
        kind: StoreKind,
        supported: bool,
        rsa_only: bool,
        available: bool,
        fail_load: bool,
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
        fn new(kind: StoreKind) -> Self {
            Self {
                kind,
                supported: true,
                rsa_only: false,
                available: true,
                fail_load: false,
                fail_after: None,
                fail_clear: false,
                entered: None,
                release: None,
                memory: MemoryStore::default(),
            }
        }
    }

    impl Store for MockStore {
        /// Advertise the chosen routing priority while keeping storage entirely local.
        fn kind(&self) -> StoreKind {
            self.kind
        }
        /// Model backend discovery separately from support for a particular algorithm.
        fn available(&self) -> bool {
            self.available
        }
        /// Allow whole-backend rejection or an RSA-only platform capability.
        fn capabilities(&self, spec: &KeySpec) -> Capabilities {
            Capabilities {
                supported: self.available && self.supported && (!self.rsa_only || matches!(spec, KeySpec::Rsa { .. })),
                signing: SigningMode::Software,
            }
        }
        /// Inject rejection before delegating accepted keys to the real memory store.
        fn load(&self, material: StoreMaterial) -> Result<StoreHandle, StoreError> {
            if !self.capabilities(&material.record.spec).supported {
                return Err(StoreError::Unsupported);
            }
            if self.fail_load
                || self
                    .fail_after
                    .is_some_and(|limit| self.memory.list().map_or(true, |keys| keys.len() >= limit))
            {
                return Err(StoreError::Backend("injected failure".into()));
            }
            self.memory.load(material)
        }
        /// Expose actual retained keys so reconciliation and cleanup remain observable.
        fn list(&self) -> Result<Vec<StoredKey>, StoreError> {
            self.memory.list()
        }
        /// Optionally pause inside the synchronous backend before computing a signature.
        fn sign(&self, handle: &StoreHandle, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>, StoreError> {
            if let (Some(entered), Some(release)) = (&self.entered, &self.release) {
                // Publish entry before waiting, allowing the async scenario to revoke
                // the generation while the signing worker still owns the storage lock.
                entered.store(true, Ordering::SeqCst);
                while !release.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
            }
            self.memory.sign(handle, algorithm, data)
        }
        /// Keep item deletion realistic instead of mocking reconciliation away.
        fn delete(&self, handle: &StoreHandle) -> Result<(), StoreError> {
            self.memory.delete(handle)
        }
        /// A cleanup failure preserves this store's contents for failure-path coverage.
        fn clear(&self) -> Result<(), StoreError> {
            if self.fail_clear {
                return Err(StoreError::Backend("injected cleanup failure".into()));
            }
            self.memory.clear()
        }
    }

    /// Construction needs no provider connection and exposes no keys before unlock.
    #[tokio::test]
    async fn startup_is_locked_and_does_not_authenticate() -> Result<()> {
        let agent = agent(vec![Arc::new(MemoryStore::default())])?;
        let status = agent.status();
        assert_eq!(status.state, Phase::Locked);
        assert!(status.snapshot.is_none() && status.keys.is_empty());
        assert!(agent.session().request_identities().await.is_err());
        Ok(())
    }

    /// Unsupported and failing platform stores both allow the memory fallback to win.
    #[test]
    fn priority_capabilities_and_failed_import_fall_back_to_memory() -> Result<()> {
        let mut keychain = MockStore::new(StoreKind::Keychain);
        keychain.supported = false;
        let mut desktop = MockStore::new(StoreKind::FreeDesktop);
        desktop.fail_load = true;
        let memory = Arc::new(MemoryStore::default());
        let agent = agent(vec![memory.clone(), Arc::new(desktop), Arc::new(keychain)])?;
        publish(&agent, vec![material(1)?])?;
        assert_eq!(agent.status().keys[0].store, StoreKind::Memory);
        assert_eq!(memory.list()?.len(), 1);
        Ok(())
    }

    /// Priority is independent of input order; duplicate identities keep the last record.
    #[test]
    fn imports_choose_highest_priority_and_deduplicate_last_record() -> Result<()> {
        let keychain = Arc::new(MockStore::new(StoreKind::Keychain));
        let desktop = Arc::new(MockStore::new(StoreKind::FreeDesktop));
        let memory = Arc::new(MemoryStore::default());
        let agent = agent(vec![memory.clone(), desktop.clone(), keychain.clone()])?;
        let mut first = material(1)?;
        first.record.comment = "first".into();
        let mut last = material(1)?;
        last.record.comment = "last".into();
        publish(&agent, vec![first, last])?;
        assert_eq!(agent.status().keys.len(), 1);
        assert_eq!(agent.status().keys[0].comment, "last");
        assert_eq!(keychain.list()?.len(), 1);
        assert_eq!(keychain.list()?[0].record.comment, "last");
        assert!(desktop.list()?.is_empty());
        assert!(memory.list()?.is_empty());
        Ok(())
    }

    /// A full import removes old keys, rotated keys, and keys left in a second backend.
    #[test]
    fn reconciliation_deletes_orphans_rotations_and_duplicate_homes() -> Result<()> {
        let keychain = Arc::new(MockStore::new(StoreKind::Keychain));
        let memory = Arc::new(MemoryStore::default());
        let mut previous = material(1)?;
        previous.record.comment = "rotated key".into();
        keychain.load(previous)?;
        memory.load(material(2)?)?;
        memory.load(material(3)?)?;
        let mut replacement = material(3)?;
        replacement.record.comment = "rotated key".into();
        let expected = replacement.record.clone();
        let agent = agent(vec![keychain.clone(), memory.clone()])?;
        publish(&agent, vec![replacement])?;
        let retained = keychain.list()?;
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].record, expected);
        assert!(memory.list()?.is_empty());
        assert_eq!(agent.status().keys.len(), 1);
        assert_eq!(agent.status().keys[0].comment, "rotated key");
        assert_eq!(agent.status().keys[0].fingerprint, expected.fingerprint);
        Ok(())
    }

    /// Snapshot age never triggers refresh; local identities and signatures stay usable.
    #[tokio::test]
    async fn old_snapshots_serve_sorted_identities_and_signatures_without_remote_access() -> Result<()> {
        let agent = agent(vec![Arc::new(MemoryStore::default())])?;
        publish(&agent, vec![material(2)?, material(1)?])?;
        // The unreachable provider makes an accidental age-based fetch observable.
        state(&agent.shared).snapshot = Some(Snapshot {
            loaded_at: "2000-01-01T00:00:00Z".into(),
        });
        let mut session = agent.session();
        let keys = session.request_identities().await?;
        assert_eq!(keys.len(), 2);
        assert!(keys[0].pubkey < keys[1].pubkey);
        let signature = session
            .sign(SignRequest {
                pubkey: keys[0].pubkey.clone(),
                data: b"hello".to_vec(),
                flags: 0,
            })
            .await?;
        signature::Verifier::verify(&ssh_key::PublicKey::from(keys[0].pubkey.clone()), b"hello", &signature)?;
        // RSA-specific flags must still be rejected for an Ed25519 identity.
        assert!(
            session
                .sign(SignRequest {
                    pubkey: keys[0].pubkey.clone(),
                    data: Vec::new(),
                    flags: RSA_SHA2_256
                })
                .await
                .is_err()
        );
        assert_eq!(
            agent.status().snapshot.context("missing snapshot")?.loaded_at,
            "2000-01-01T00:00:00Z"
        );
        Ok(())
    }

    /// Lock removes local data, clears snapshot metadata, and revokes existing sessions.
    #[tokio::test]
    async fn lock_clears_every_store_and_invalidates_sessions() -> Result<()> {
        let memory = Arc::new(MemoryStore::default());
        let agent = agent(vec![memory.clone()])?;
        publish(&agent, vec![material(1)?])?;
        let mut old = agent.session();
        let generation = agent.subscribe();
        assert!(agent.lock().await.ok);
        assert!(memory.list()?.is_empty());
        assert_eq!(agent.status().state, Phase::Locked);
        assert!(generation.has_changed()?);
        assert!(old.request_identities().await.is_err());
        assert!(agent.status().snapshot.is_none());
        Ok(())
    }

    /// Cleanup errors do not reopen the agent or prevent later stores from clearing.
    #[tokio::test]
    async fn failed_clear_still_locks_and_clears_other_stores() -> Result<()> {
        let mut broken = MockStore::new(StoreKind::Keychain);
        broken.fail_clear = true;
        let memory = Arc::new(MemoryStore::default());
        memory.load(material(2)?)?;
        let agent = agent(vec![Arc::new(broken), memory.clone()])?;
        assert!(!agent.lock().await.ok);
        assert!(memory.list()?.is_empty());
        assert_eq!(agent.status().state, Phase::Locked);
        Ok(())
    }

    /// Conflicts are reported before authentication rather than silently queuing work.
    #[tokio::test]
    async fn repeated_unlock_and_loading_transitions_report_conflicts() -> Result<()> {
        let agent = agent(vec![Arc::new(MemoryStore::default())])?;
        publish(&agent, vec![material(1)?])?;
        let result = agent.unlock(SecrecyBytes::from(Vec::new().into_boxed_slice())).await;
        assert_eq!(result.code.as_deref(), Some("already-unlocked"));
        // Hold transition ownership directly to model an operation already in flight.
        let _guard = agent.shared.operations.lock().await;
        assert_eq!(agent.lock().await.code.as_deref(), Some("busy"));
        assert_eq!(
            agent
                .unlock(SecrecyBytes::from(Vec::new().into_boxed_slice()))
                .await
                .code
                .as_deref(),
            Some("busy")
        );
        Ok(())
    }

    /// Authentication failure revokes publication and leaves rollback cleanup awaitable.
    #[tokio::test]
    async fn failed_unlock_rolls_back_without_publishing_keys() -> Result<()> {
        let agent = agent(vec![Arc::new(MemoryStore::default())])?;
        let result = agent
            .unlock(SecrecyBytes::from(b"never-log-me".to_vec().into_boxed_slice()))
            .await;
        assert!(!result.ok);
        assert_eq!(result.code.as_deref(), Some("auth"));
        assert_eq!(agent.status().state, Phase::Locked);
        assert!(agent.status().keys.is_empty());
        // Waiting for transition ownership also waits behind the rollback worker.
        agent.clear().await?;
        Ok(())
    }

    /// Revocation during backend signing must suppress the result from the old session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lock_rejects_a_signature_computed_with_an_old_generation() -> Result<()> {
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let mut keychain = MockStore::new(StoreKind::Keychain);
        keychain.entered = Some(entered.clone());
        keychain.release = Some(release.clone());
        let agent = agent(vec![Arc::new(keychain), Arc::new(MemoryStore::default())])?;
        publish(&agent, vec![material(1)?])?;
        let mut session = agent.session();
        let identity = session.request_identities().await?.remove(0);
        let signing = tokio::spawn(async move {
            session
                .sign(SignRequest {
                    pubkey: identity.pubkey,
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
        // Do not wait for store cleanup here: signing holds the storage lock until
        // released, while synchronous invalidation must take effect immediately.
        agent.invalidate();
        release.store(true, Ordering::SeqCst);
        assert!(signing.await?.is_err());
        agent.clear().await?;
        Ok(())
    }

    /// Private control responses use JSON; unknown extensions fail and standard query stays narrow.
    #[tokio::test]
    async fn extension_json_unknown_extensions_and_query_are_consistent() -> Result<()> {
        let agent = agent(vec![Arc::new(MemoryStore::default())])?;
        let mut session = agent.session();
        let Some(response) = session
            .extension(Extension {
                name: control::STATUS.into(),
                details: Vec::new().into(),
            })
            .await?
        else {
            bail!("missing status response");
        };
        let status: Status = serde_json::from_slice(response.details.as_ref())?;
        assert_eq!(status.state, Phase::Locked);
        assert!(status.keys.is_empty());
        // Refresh has no server extension: clients compose lock and a fresh unlock.
        for name in ["unknown", "refresh@keyring"] {
            assert!(matches!(
                session
                    .extension(Extension {
                        name: name.into(),
                        details: Vec::new().into()
                    })
                    .await,
                Err(AgentError::ExtensionFailure)
            ));
        }
        let query = session
            .extension(Extension {
                name: "query".into(),
                details: Vec::new().into(),
            })
            .await?
            .context("missing query response")?;
        let bytes = query.details.as_ref();
        assert!(
            !bytes
                .windows(control::UNLOCK.len())
                .any(|window| window == control::UNLOCK.as_bytes())
        );
        // Route through the library dispatcher as well as calling the extension hook.
        let response = session
            .handle(Request::Extension(Extension {
                name: control::LOCK.into(),
                details: Vec::new().into(),
            }))
            .await?;
        assert!(matches!(response, ssh_agent_lib::proto::Response::ExtensionResponse(_)));
        Ok(())
    }

    /// RSA requires explicit SHA-2 flags, with stable precedence if both are requested.
    #[test]
    fn rsa_flag_mapping_rejects_sha1_and_preserves_sha256_precedence() {
        let rsa = KeySpec::Rsa { bits: 2048 };
        assert!(algorithm(&rsa, 0).is_err());
        assert!(algorithm(&rsa, 0x80).is_err());
        assert_eq!(
            algorithm(&rsa, RSA_SHA2_256 | RSA_SHA2_512).ok(),
            Some(Algorithm::Rsa {
                hash: Some(HashAlg::Sha256)
            })
        );
        assert_eq!(
            algorithm(&rsa, RSA_SHA2_512).ok(),
            Some(Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            })
        );
    }

    /// Backend unavailability and algorithm rejection obey the same shared store contract.
    #[test]
    fn shared_contract_checks_unavailable_and_unsupported_stores() -> Result<()> {
        for (available, supported) in [(false, true), (true, false)] {
            let mut store = MockStore::new(StoreKind::Keychain);
            store.available = available;
            store.supported = supported;
            keyring_store_memory::contract::run_store_contract(
                &store,
                &[PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]))],
            )?;
        }
        Ok(())
    }

    /// Each algorithm selects its own capable store and produces a verifiable signature.
    #[tokio::test]
    async fn mixed_algorithms_choose_their_own_stores_and_verify() -> Result<()> {
        let mut keychain = MockStore::new(StoreKind::Keychain);
        keychain.rsa_only = true;
        let desktop = MockStore::new(StoreKind::FreeDesktop);
        let agent = agent(vec![
            Arc::new(keychain),
            Arc::new(desktop),
            Arc::new(MemoryStore::default()),
        ])?;
        let rsa = PrivateKey::from(ssh_key::private::RsaKeypair::random(&mut rand::rngs::OsRng, 2048)?);
        publish(&agent, vec![software::material(&rsa)?, material(8)?])?;
        let status = agent.status();
        assert_eq!(status.keys[0].store, StoreKind::Keychain);
        assert_eq!(status.keys[0].algorithm, "rsa");
        assert_eq!(status.keys[1].store, StoreKind::FreeDesktop);
        assert_eq!(status.keys[1].algorithm, "ed25519");
        let mut session = agent.session();
        // Exercise protocol dispatch using the flags each key algorithm requires.
        for identity in session.request_identities().await? {
            let flags = if identity.pubkey.algorithm().is_rsa() {
                RSA_SHA2_512
            } else {
                0
            };
            let signature = session
                .sign(SignRequest {
                    pubkey: identity.pubkey.clone(),
                    data: b"mixed stores".to_vec(),
                    flags,
                })
                .await?;
            signature::Verifier::verify(&ssh_key::PublicKey::from(identity.pubkey), b"mixed stores", &signature)?;
        }
        Ok(())
    }

    /// Failure after one successful import leaves partial data for rollback to remove.
    #[tokio::test]
    async fn partial_import_failure_rolls_back_all_stores() -> Result<()> {
        let mut memory = MockStore::new(StoreKind::Memory);
        memory.fail_load = true;
        let mut keychain = MockStore::new(StoreKind::Keychain);
        keychain.fail_after = Some(1);
        let keychain = Arc::new(keychain);
        let agent = agent(vec![keychain.clone(), Arc::new(memory)])?;
        let operation = Arc::clone(&agent.shared.operations).lock_owned().await;
        // Construct the same armed guard as unlock without needing provider fixtures.
        let rollback = Rollback {
            shared: Arc::clone(&agent.shared),
            operation: Some(operation),
            active: true,
        };
        state(&agent.shared).phase = Phase::Loading;
        assert!(import(&agent.shared, vec![material(1)?, material(2)?], 0).is_err());
        assert_eq!(keychain.list()?.len(), 1);
        // Dropping revokes immediately; clear waits for the asynchronous cleanup too.
        drop(rollback);
        assert_eq!(agent.status().state, Phase::Locked);
        agent.clear().await?;
        assert!(keychain.list()?.is_empty());
        Ok(())
    }

    /// A queued import cannot repopulate a store after its generation was invalidated.
    #[test]
    fn cancelled_import_cannot_write_keys_after_cleanup() -> Result<()> {
        let memory = Arc::new(MemoryStore::default());
        let agent = agent(vec![memory.clone()])?;
        state(&agent.shared).phase = Phase::Loading;
        let generation = state(&agent.shared).generation;
        agent.invalidate();
        clear(&agent.shared)?;
        assert!(import(&agent.shared, vec![material(1)?], generation).is_err());
        assert!(memory.list()?.is_empty());
        assert_eq!(agent.status().state, Phase::Locked);
        Ok(())
    }
}
