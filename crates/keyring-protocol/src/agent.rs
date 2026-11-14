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

use crate::{
    codec::{Request, Response},
    control,
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use keyring_core::{
    keystore::{KeyId, KeyInfo, KeyRecord, KeySpec, KeyStore, Kind},
    provider::{self, Provider},
};
use secrecy::{ExposeSecret, SecretBox};
use signature::Verifier as _;
use ssh_encoding::{Decode, Encode, Reader};
use ssh_key::{Algorithm, HashAlg, Signature, public::KeyData};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::sync::{OwnedMutexGuard, watch};
use zeroize::Zeroizing;

/// Select RSA signatures using SHA-256 through the SSH-agent signing flags.
const RSA_SHA2_256: u32 = 2;
/// Select RSA signatures using SHA-512 through the SSH-agent signing flags.
const RSA_SHA2_512: u32 = 4;
/// OpenSSH's signed binding between a connection and an SSH session.
const BIND: &str = "session-bind@openssh.com";

/// A service shared by connections and background workers through `Arc`.
pub struct Agent {
    provider: Arc<dyn Provider>,
    /// Actual backend instances in selection order, including unavailable ones.
    stores: Vec<Arc<dyn KeyStore>>,
    /// Short critical sections protect public state and session authorization.
    state: Mutex<State>,
    /// Serializes transitions across async provider work and subsequent cleanup.
    operations: Arc<tokio::sync::Mutex<()>>,
    /// Serializes blocking import, signing, and cleanup without blocking async tasks.
    storage: Mutex<()>,
    /// Notifies the transport when invalidation makes existing sessions obsolete.
    generation: watch::Sender<u64>,
}

/// Per-connection authorization generation and accepted OpenSSH session bindings.
///
/// A session remains tied to the generation in which it was created. Locking
/// invalidates it permanently, even if the shared service is unlocked again.
pub struct Session {
    /// Shared agent used to dispatch storage and control operations.
    agent: Arc<Agent>,
    /// Agent epoch captured at session creation; a mismatch revokes this session.
    generation: u64,
    /// Session IDs and forwarding flags; these do not impose per-key restrictions.
    binds: Vec<(Vec<u8>, bool)>,
}

/// The visible snapshot; no private key bytes or provider decryption keys live here.
struct State {
    /// Current lock state, including whether an explicit unlock is loading keys.
    state: control::State,
    /// Revocation epoch checked by sessions and background work before publishing results.
    generation: u64,
    /// Published identities and their backend routes, ordered by public key.
    keys: BTreeMap<KeyData, Binding>,
    /// Timestamp metadata for the last successfully published unlock snapshot.
    snapshot: Option<control::Snapshot>,
}

/// Routes a public identity to the backend that accepted its private material.
struct Binding {
    /// Backend selected to store and sign for this public identity.
    store: Arc<dyn KeyStore>,
    /// Opaque handle issued by that backend for its stored key.
    handle: KeyId,
    /// Public key, comment, and fingerprint cached without private bytes.
    info: KeyInfo,
}

/// Restores locked state if unlock exits before publishing a complete snapshot.
///
/// The transition guard moves into cleanup so a new unlock cannot overtake it.
struct Rollback {
    /// Agent state and stores that must be revoked and cleared on rollback.
    agent: Arc<Agent>,
    /// Retained until success, or moved into cleanup when this guard is dropped.
    operation: Option<OwnedMutexGuard<()>>,
}

impl Agent {
    /// Return a shared, locked service with unique backend kinds and a usable memory fallback.
    ///
    /// Backends are sorted by `Kind` priority: Keychain, FreeDesktop, Memory.
    /// Construction validates store capabilities without loading the provider.
    pub fn new(provider: Arc<dyn Provider>, mut stores: Vec<Arc<dyn KeyStore>>) -> Result<Arc<Self>> {
        stores.sort_by_key(|store| store.kind());
        if stores.windows(2).any(|pair| pair[0].kind() == pair[1].kind()) {
            bail!("duplicate store kind");
        }
        // Require both supported algorithms in the final fallback, regardless of
        // which platform stores are available on this machine.
        if !stores.iter().any(|store| {
            store.kind() == Kind::Memory
                && store.available().is_ok()
                && store.capabilities(&KeySpec::Ed25519).supported
                && store.capabilities(&KeySpec::Rsa { bits: 2048 }).supported
        }) {
            bail!("a memory store supporting RSA and Ed25519 is required");
        }
        Ok(Arc::new(Self {
            provider,
            stores,
            state: Mutex::new(State {
                state: control::State::Locked,
                generation: 0,
                keys: BTreeMap::new(),
                snapshot: None,
            }),
            operations: Arc::new(tokio::sync::Mutex::new(())),
            storage: Mutex::new(()),
            generation: watch::channel(0).0,
        }))
    }

    /// Recover the state guard even after poisoning so invalidation remains possible.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Capture the current generation for a newly accepted connection.
    pub fn session(self: &Arc<Self>) -> Session {
        Session {
            agent: Arc::clone(self),
            generation: self.state().generation,
            binds: Vec::new(),
        }
    }

    /// Watch generation changes so the transport can close invalidated connections.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    /// Return public key metadata and the actual stores in their current order.
    ///
    /// Reading status never contacts the provider or refreshes the snapshot.
    pub fn status(&self) -> control::Response {
        let current = self.state();
        let mut keys: Vec<_> = current
            .keys
            .values()
            .map(|binding| {
                let spec =
                    KeySpec::try_from(&binding.info.identity).expect("imported key has a supported specification");
                let capabilities = binding.store.capabilities(&spec);
                let (algorithm, bits) = match spec {
                    KeySpec::Ed25519 => ("ed25519", None),
                    KeySpec::Rsa { bits } => ("rsa", Some(bits)),
                };
                control::Key {
                    fingerprint: binding.info.fingerprint.clone(),
                    comment: binding.info.comment.clone(),
                    algorithm: algorithm.into(),
                    bits,
                    store: binding.store.kind(),
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
            .stores
            .iter()
            .map(|store| {
                let available = store.available();
                control::Store {
                    kind: store.kind(),
                    available: available.is_ok(),
                    reason: available.err().map(|error| error.to_string()),
                }
            })
            .collect();
        control::Response::Status {
            state: current.state,
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
    pub async fn unlock(self: &Arc<Self>, password: SecretBox<[u8]>) -> control::Response {
        let operation = match Arc::clone(&self.operations).try_lock_owned() {
            Ok(guard) => guard,
            Err(_) => return control::Response::failure("busy", "another state transition is in progress"),
        };
        let generation = {
            let mut current = self.state();
            if current.state != control::State::Locked {
                return control::Response::failure("already-unlocked", "agent is already unlocked");
            }
            current.state = control::State::Loading;
            current.generation
        };
        // Keep rollback armed across every await, including cancellation when
        // the transport drops this future before an outcome can be returned.
        let mut rollback = Rollback {
            agent: Arc::clone(self),
            operation: Some(operation),
        };
        let records = match self.provider.load(password).await {
            Ok(records) => records,
            Err(error) => {
                let code = match &error {
                    provider::Error::Auth(_) => "auth",
                    provider::Error::Sync(_) => "sync",
                };
                return control::Response::failure(code, error.to_string());
            }
        };
        tracing::debug!(keys = records.len(), "vault load completed; importing SSH keys");
        let agent = Arc::clone(self);
        // Backend APIs are synchronous. A detached worker may finish after this
        // future is cancelled; the storage lock orders rollback after that work.
        let imported = tokio::task::spawn_blocking(move || agent.import(records, generation))
            .await
            .context("SSH key import worker failed")
            .and_then(|result| result);
        let bindings = match imported {
            Ok(bindings) => bindings,
            Err(error) => {
                tracing::error!(error = ?error, "failed to import SSH keys");
                return control::Response::failure("store", "failed to import keys; agent remains locked");
            }
        };
        {
            let mut current = self.state();
            // Invalidation can race with blocking import, so recheck before
            // exposing any of its bindings to SSH clients.
            if current.generation != generation {
                return control::Response::failure("cancelled", "unlock was cancelled");
            }
            current.keys = bindings;
            current.stamp(Utc::now());
            current.state = control::State::Unlocked;
        }
        // Publish all keys together before disarming cleanup.
        drop(rollback.operation.take());
        control::Response::Success
    }

    /// Revoke sessions immediately, then await cleanup of every available store.
    ///
    /// A cleanup failure leaves the agent locked but can leave backend data behind.
    /// Competing transitions return `busy` rather than waiting.
    pub async fn lock(self: &Arc<Self>) -> control::Response {
        let operation = match Arc::clone(&self.operations).try_lock_owned() {
            Ok(guard) => guard,
            Err(_) => return control::Response::failure("busy", "another state transition is in progress"),
        };
        // Revocation precedes potentially slow or failing backend cleanup.
        self.invalidate();
        let agent = Arc::clone(self);
        match tokio::task::spawn_blocking(move || {
            // Let the blocking worker retain transition ownership if its async
            // caller disappears while cleanup is still running.
            let _operation = operation;
            agent.clear_stores()
        })
        .await
        {
            Ok(Ok(())) => control::Response::Success,
            _ => control::Response::failure("store", "agent locked, but a platform store could not be cleared"),
        }
    }

    /// Clear published metadata and advance the session generation synchronously.
    ///
    /// This revokes access but does not remove data from any backend. Call `lock`
    /// or `clear` when store cleanup is also required.
    pub fn invalidate(&self) {
        let mut current = self.state();
        current.state = control::State::Locked;
        current.keys.clear();
        current.snapshot = None;
        current.generation = current.generation.wrapping_add(1);
        self.generation.send_replace(current.generation);
    }

    /// Revoke sessions and wait for transition ownership before clearing stores.
    ///
    /// Used when cleanup must wait for outstanding work, such as shutdown.
    /// Unavailable stores are skipped; errors propagate.
    pub async fn clear(self: &Arc<Self>) -> Result<()> {
        self.invalidate();
        let operation = Arc::clone(&self.operations).lock_owned().await;
        let agent = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _operation = operation;
            agent.clear_stores()
        })
        .await?
    }

    /// Attempt every available store even if an earlier store fails to clear.
    ///
    /// The storage lock prevents cleanup from racing with an import or backend sign.
    /// Success says nothing about stores skipped because they are unavailable.
    fn clear_stores(&self) -> Result<()> {
        let _storage = self
            .storage
            .lock()
            .map_err(|_| anyhow::anyhow!("storage lock poisoned"))?;
        let mut failed = false;
        for store in self.stores.iter().filter(|store| store.available().is_ok()) {
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
    fn import(&self, records: Vec<KeyRecord>, generation: u64) -> Result<BTreeMap<KeyData, Binding>> {
        let _storage = self
            .storage
            .lock()
            .map_err(|_| anyhow::anyhow!("storage lock poisoned"))?;
        // Check after acquiring storage: cancellation may have happened while this
        // worker was queued behind cleanup or a signature.
        {
            let current = self.state();
            if current.generation != generation || current.state != control::State::Loading {
                bail!("key import was cancelled");
            }
        }
        // Public identity, rather than provider record ID, defines a unique SSH key.
        // Later duplicate records replace earlier records and their metadata.
        let mut unique = BTreeMap::new();
        for record in records {
            unique.insert(record.info.identity.clone(), record);
        }
        // Reconcile from a complete snapshot by removing old keys from every usable
        // backend, including duplicate homes and keys removed from the remote vault.
        for store in self.stores.iter().filter(|store| store.available().is_ok()) {
            store
                .clear()
                .with_context(|| format!("{:?}: clear existing keys", store.kind()))?;
        }
        let mut bindings = BTreeMap::new();
        for (identity, record) in unique {
            let spec: KeySpec = (&identity).try_into()?;
            let mut home = None;
            for store in self.stores.iter().filter(|store| store.available().is_ok()) {
                if !store.capabilities(&spec).supported {
                    continue;
                }
                // Each backend consumes its input, so preserve the original secret
                // for fallback and give each attempt its own zeroizing secret buffer.
                let copy = KeyRecord {
                    info: record.info.clone(),
                    secret: SecretBox::from(record.secret.expose_secret().to_vec().into_boxed_slice()),
                };
                match store.load(copy) {
                    Ok(handle) => {
                        home = Some((Arc::clone(store), handle));
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(store = ?store.kind(), %error, "key import failed; trying next store");
                        // A failing backend may have written the key before returning
                        // an error. Remove that partial home before trying another.
                        for (handle, info) in store
                            .list()
                            .with_context(|| format!("{:?}: list after failed import", store.kind()))?
                        {
                            if info.identity == identity {
                                store
                                    .delete(&handle)
                                    .with_context(|| format!("{:?}: delete after failed import", store.kind()))?;
                            }
                        }
                    }
                }
            }
            // A failure after earlier successes is left for the caller's rollback;
            // this function never publishes a partial set of keys.
            let (store, handle) = home.context("all stores rejected a key")?;
            bindings.insert(
                identity,
                Binding {
                    store,
                    handle,
                    info: record.info,
                },
            );
        }
        Ok(bindings)
    }
}

impl Session {
    /// Dispatch supported requests, rejecting all key-management operations.
    pub async fn handle(&mut self, request: Request) -> Response {
        match request {
            Request::Identities => self.identities().map(Response::Identities).unwrap_or(Response::Failure),
            Request::Signature { key, data, flags } => self
                .sign(key, data, flags)
                .await
                .map(Response::Signature)
                .unwrap_or(Response::Failure),
            Request::Extension { name, details } => {
                self.extension(name, details).await.unwrap_or(Response::Extension(None))
            }
            Request::Unsupported => Response::Failure,
        }
    }

    /// Enumerate the published identities in the map's public-key order.
    fn identities(&self) -> Result<Vec<(KeyData, String)>> {
        let current = self.agent.state();
        current.check(self.generation)?;
        Ok(current
            .keys
            .iter()
            .map(|(identity, binding)| (identity.clone(), binding.info.comment.clone()))
            .collect())
    }

    /// Dispatch signing to the selected backend without contacting the provider.
    async fn sign(&self, key: Vec<u8>, data: Vec<u8>, flags: u32) -> Result<Signature> {
        let identity = ssh_key::PublicKey::from_bytes(&key)?;
        let (store, handle) = {
            let current = self.agent.state();
            current.check(self.generation)?;
            let binding = current.keys.get(identity.key_data()).context("unknown SSH key")?;
            (Arc::clone(&binding.store), binding.handle.clone())
        };
        let spec = identity.key_data().try_into()?;
        let algorithm = Self::algorithm(&spec, flags)?;
        let agent = Arc::clone(&self.agent);
        let generation = self.generation;
        // Clone only routing metadata; private material remains owned by stores.
        tokio::task::spawn_blocking(move || {
            let _storage = agent
                .storage
                .lock()
                .map_err(|_| anyhow::anyhow!("store access lock poisoned"))?;
            // Authorization can change while this worker waits for store access.
            agent.state().check(generation)?;
            let bytes = store.sign(&handle, algorithm.clone(), &data)?;
            // Invalidation cannot interrupt a backend already signing. Discard
            // its result if the generation changed during that operation.
            let current = agent.state();
            current.check(generation)?;
            Ok(Signature::new(algorithm, bytes)?)
        })
        .await?
    }

    /// Handle explicit controls and the supported standard SSH-agent extensions.
    async fn extension(&mut self, name: String, details: Zeroizing<Vec<u8>>) -> Result<Response> {
        let response = match name.as_str() {
            control::UNLOCK | control::LOCK | control::STATUS => {
                let response = match control::Request::decode(&name, details) {
                    Ok(control::Request::Unlock(password)) => self.agent.unlock(password).await,
                    Ok(control::Request::Lock) => self.agent.lock().await,
                    Ok(control::Request::Status) => self.agent.status(),
                    Err(error) => control::Response::failure("usage", error.to_string()),
                };
                serde_json::to_vec(&response)?
            }
            "query" => {
                // Advertise standard extensions only; clients already know the
                // private control names. Refresh is client-side lock + unlock.
                ["query", BIND].as_slice().encode_vec()?
            }
            BIND => {
                self.bind(&details)?;
                return Ok(Response::Success);
            }
            _ => bail!("unsupported extension"),
        };
        Ok(Response::Extension(Some((name, response.into()))))
    }

    /// Decode and verify an OpenSSH session binding, rejecting trailing data.
    fn bind(&mut self, details: &[u8]) -> Result<()> {
        let mut reader = details;
        let host_key = reader.read_prefixed(|reader| {
            let key = KeyData::decode(reader)?;
            reader.ensure_finished()?;
            Ok::<_, ssh_key::Error>(key)
        })?;
        let session_id = Vec::<u8>::decode(&mut reader)?;
        let signature = reader.read_prefixed(|reader| {
            let signature = Signature::decode(reader)?;
            reader.ensure_finished()?;
            Ok::<_, ssh_key::Error>(signature)
        })?;
        let forwarding = bool::decode(&mut reader)?;
        reader.ensure_finished()?;
        host_key.verify(&session_id, &signature)?;
        // Bound the forwarding chain, reject replayed session IDs, and
        // forbid extending a chain after its non-forwarding endpoint.
        if self.binds.len() >= 64
            || self
                .binds
                .iter()
                .any(|(id, forwarding)| *id == session_id || !forwarding)
        {
            bail!("invalid session binding chain");
        }
        self.binds.push((session_id, forwarding));
        Ok(())
    }

    /// Validate SSH signing flags without allowing the legacy RSA/SHA-1 default.
    ///
    /// Ed25519 accepts no flags. If both RSA SHA-2 flags are present, SHA-256 wins.
    fn algorithm(spec: &KeySpec, flags: u32) -> Result<Algorithm> {
        match spec {
            KeySpec::Ed25519 if flags == 0 => Ok(Algorithm::Ed25519),
            KeySpec::Rsa { .. } if flags & !(RSA_SHA2_256 | RSA_SHA2_512) == 0 => {
                let hash = if flags & RSA_SHA2_256 != 0 {
                    HashAlg::Sha256
                } else if flags & RSA_SHA2_512 != 0 {
                    HashAlg::Sha512
                } else {
                    bail!("RSA requires a SHA-2 signature flag")
                };
                Ok(Algorithm::Rsa { hash: Some(hash) })
            }
            _ => bail!("unsupported signature flags"),
        }
    }
}

impl State {
    /// Require an unlocked snapshot from the connection's original generation.
    fn check(&self, generation: u64) -> Result<()> {
        if self.state != control::State::Unlocked || self.generation != generation {
            bail!("agent locked or session invalidated");
        }
        Ok(())
    }

    /// Record when a complete import was published; this timestamp is not an expiry.
    fn stamp(&mut self, now: DateTime<Utc>) {
        let timestamp = now.to_rfc3339_opts(SecondsFormat::Nanos, true);
        self.snapshot = Some(control::Snapshot {
            loaded_at: format!(
                "{}Z",
                timestamp
                    .trim_end_matches('Z')
                    .trim_end_matches('0')
                    .trim_end_matches('.')
            ),
        });
    }
}

impl Drop for Rollback {
    /// Revoke synchronously, then schedule cleanup without blocking the async thread.
    fn drop(&mut self) {
        let Some(operation) = self.operation.take() else {
            return;
        };
        self.agent.invalidate();
        let agent = Arc::clone(&self.agent);
        // Cleanup waits behind any import or signature already holding storage.
        // Drop cannot await it or return an error, so failures are logged instead.
        tokio::task::spawn_blocking(move || {
            let _operation = operation;
            if agent.clear_stores().is_err() {
                tracing::error!("failed to clear stores during rollback");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    //! Private generation, timestamp, signing-flag, and session-binding invariants.

    use super::*;
    use keyring_store_memory::MemoryStore;
    use ssh_key::{PrivateKey, private::Ed25519Keypair};
    use std::{future::Future, pin::Pin};

    struct Fixture;

    impl Fixture {
        /// Create the real shared service around the scenario's selected store instances.
        fn agent(stores: Vec<Arc<dyn KeyStore>>) -> Result<Arc<Agent>> {
            Agent::new(Arc::new(Self), stores)
        }

        /// Build a repeatable Ed25519 identity.
        fn record(seed: u8) -> Result<KeyRecord> {
            Ok(KeyRecord::try_from(&PrivateKey::from(Ed25519Keypair::from_seed(
                &[seed; 32],
            )))?)
        }

        /// Exercise real import and publication while bypassing remote authentication.
        ///
        /// Only private snapshot and transition-guard tests bypass the unlock lifecycle.
        fn publish(agent: &Agent, records: Vec<KeyRecord>) -> Result<()> {
            let generation = {
                let mut current = agent.state();
                current.state = control::State::Loading;
                current.generation
            };
            let bindings = agent.import(records, generation)?;
            let mut current = agent.state();
            current.keys = bindings;
            current.state = control::State::Unlocked;
            current.stamp(Utc::now());
            Ok(())
        }

        fn binding(key: &PrivateKey, session_id: &[u8], forwarding: bool) -> Result<Zeroizing<Vec<u8>>> {
            let mut details = Vec::new();
            key.public_key().key_data().encode_prefixed(&mut details)?;
            session_id.encode(&mut details)?;
            let signature: Signature = signature::Signer::try_sign(key, session_id)?;
            signature.encode_prefixed(&mut details)?;
            forwarding.encode(&mut details)?;
            Ok(details.into())
        }
    }

    impl Provider for Fixture {
        fn load(
            &self,
            _password: SecretBox<[u8]>,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<KeyRecord>, provider::Error>> + Send + '_>> {
            Box::pin(async { Err(provider::Error::Auth(anyhow::anyhow!("fixture authentication failure"))) })
        }
    }

    #[test]
    fn snapshot_timestamps_preserve_rfc3339_fractional_precision() -> Result<()> {
        let agent = Fixture::agent(vec![Arc::new(MemoryStore::default())])?;
        for (nanoseconds, expected) in [
            (0, "2023-11-14T22:13:20Z"),
            (100_000_000, "2023-11-14T22:13:20.1Z"),
            (123_400_000, "2023-11-14T22:13:20.1234Z"),
            (1, "2023-11-14T22:13:20.000000001Z"),
            (999_999_999, "2023-11-14T22:13:20.999999999Z"),
        ] {
            let now = DateTime::from_timestamp(1_700_000_000, nanoseconds).context("invalid timestamp")?;
            agent.state().stamp(now);
            let control::Response::Status { snapshot, .. } = agent.status() else {
                bail!("missing status response");
            };
            assert_eq!(snapshot.context("missing snapshot")?.loaded_at, expected);
        }
        Ok(())
    }

    /// Snapshot age never triggers refresh; local identities and signatures stay usable.
    #[tokio::test]
    async fn old_snapshots_serve_sorted_identities_and_signatures_without_remote_access() -> Result<()> {
        let agent = Fixture::agent(vec![Arc::new(MemoryStore::default())])?;
        Fixture::publish(&agent, vec![Fixture::record(2)?, Fixture::record(1)?])?;
        // The failing provider makes an accidental age-based fetch observable.
        agent.state().snapshot = Some(control::Snapshot {
            loaded_at: "2000-01-01T00:00:00Z".into(),
        });
        let session = agent.session();
        let keys = session.identities()?;
        assert_eq!(keys.len(), 2);
        assert!(keys[0].0 < keys[1].0);
        let signature = session.sign(keys[0].0.encode_vec()?, b"hello".to_vec(), 0).await?;
        signature::Verifier::verify(&ssh_key::PublicKey::from(keys[0].0.clone()), b"hello", &signature)?;
        // RSA-specific flags must still be rejected for an Ed25519 identity.
        assert!(
            session
                .sign(keys[0].0.encode_vec()?, Vec::new(), RSA_SHA2_256)
                .await
                .is_err()
        );
        let control::Response::Status { snapshot, .. } = agent.status() else {
            bail!("missing status response");
        };
        assert_eq!(snapshot.context("missing snapshot")?.loaded_at, "2000-01-01T00:00:00Z");
        Ok(())
    }

    /// Conflicts are reported before authentication rather than silently queuing work.
    #[tokio::test]
    async fn repeated_unlock_and_loading_transitions_report_conflicts() -> Result<()> {
        let agent = Fixture::agent(vec![Arc::new(MemoryStore::default())])?;
        Fixture::publish(&agent, vec![Fixture::record(1)?])?;
        let result = agent.unlock(SecretBox::from(Vec::new().into_boxed_slice())).await;
        assert!(matches!(result, control::Response::Failure { code, .. } if code == "already-unlocked"));
        // Hold transition ownership directly to model an operation already in flight.
        let _guard = agent.operations.lock().await;
        assert!(matches!(agent.lock().await, control::Response::Failure { code, .. } if code == "busy"));
        assert!(matches!(
            agent.unlock(SecretBox::from(Vec::new().into_boxed_slice())).await,
            control::Response::Failure { code, .. } if code == "busy"
        ));
        Ok(())
    }

    /// Private control responses use JSON; unknown extensions fail and standard query stays narrow.
    #[tokio::test]
    async fn extension_json_unknown_extensions_and_query_are_consistent() -> Result<()> {
        let agent = Fixture::agent(vec![Arc::new(MemoryStore::default())])?;
        let mut session = agent.session();
        let Response::Extension(Some((name, details))) =
            session.extension(control::STATUS.into(), Vec::new().into()).await?
        else {
            bail!("missing status response");
        };
        assert_eq!(name, control::STATUS);
        let control::Response::Status { state, keys, .. } = serde_json::from_slice(&details)? else {
            bail!("missing status response");
        };
        assert_eq!(state, control::State::Locked);
        assert!(keys.is_empty());
        // Refresh has no server extension: clients compose lock and a fresh unlock.
        for name in ["unknown", "refresh@keyring"] {
            assert!(session.extension(name.into(), Vec::new().into()).await.is_err());
            assert!(matches!(
                session
                    .handle(Request::Extension {
                        name: name.into(),
                        details: Vec::new().into(),
                    })
                    .await,
                Response::Extension(None)
            ));
        }
        let Response::Extension(Some((_, query))) = session.extension("query".into(), Vec::new().into()).await? else {
            bail!("missing query response");
        };
        let bytes = query.as_slice();
        assert_eq!(bytes, b"\0\0\0\x25\0\0\0\x05query\0\0\0\x18session-bind@openssh.com");
        assert!(
            !bytes
                .windows(control::UNLOCK.len())
                .any(|window| window == control::UNLOCK.as_bytes())
        );
        for name in [control::LOCK, control::STATUS] {
            let Response::Extension(Some((response_name, details))) = session
                .handle(Request::Extension {
                    name: name.into(),
                    details: b"invalid".to_vec().into(),
                })
                .await
            else {
                bail!("missing control failure response");
            };
            assert_eq!(response_name, name);
            assert!(matches!(
                serde_json::from_slice(&details)?,
                control::Response::Failure { code, .. } if code == "usage"
            ));
        }
        let response = session
            .handle(Request::Extension {
                name: control::LOCK.into(),
                details: Vec::new().into(),
            })
            .await;
        assert!(matches!(response, Response::Extension(Some(_))));
        assert!(matches!(session.handle(Request::Unsupported).await, Response::Failure));
        Ok(())
    }

    #[tokio::test]
    async fn session_bind_verifies_host_keys_and_rejects_replay_and_chain_extensions() -> Result<()> {
        use ssh_key::EcdsaCurve;

        let agent = Fixture::agent(vec![Arc::new(MemoryStore::default())])?;
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
            Algorithm::Rsa { hash: None },
        ] {
            let key = PrivateKey::random(&mut rand::rng(), algorithm)?;
            let mut session = agent.session();
            let mut corrupted = Fixture::binding(&key, b"corrupted", true)?;
            let last_signature_byte = corrupted.len() - 2;
            corrupted[last_signature_byte] ^= 1;
            assert!(matches!(
                session
                    .handle(Request::Extension {
                        name: BIND.into(),
                        details: corrupted,
                    })
                    .await,
                Response::Extension(None)
            ));
            let mut trailing = Fixture::binding(&key, b"trailing", true)?;
            trailing.push(0);
            assert!(session.extension(BIND.into(), trailing).await.is_err());
            assert!(session.binds.is_empty());
            assert!(matches!(
                session
                    .handle(Request::Extension {
                        name: BIND.into(),
                        details: Fixture::binding(&key, b"forwarded", true)?,
                    })
                    .await,
                Response::Success
            ));
            assert!(
                session
                    .extension(BIND.into(), Fixture::binding(&key, b"forwarded", true)?)
                    .await
                    .is_err()
            );
            assert!(matches!(
                session
                    .extension(BIND.into(), Fixture::binding(&key, b"endpoint", false)?)
                    .await?,
                Response::Success
            ));
            assert!(
                session
                    .extension(BIND.into(), Fixture::binding(&key, b"next", true)?)
                    .await
                    .is_err()
            );
            assert_eq!(session.binds.len(), 2);
        }
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[11; 32]));
        let mut session = agent.session();
        for identifier in 0..64u8 {
            assert!(matches!(
                session
                    .extension(BIND.into(), Fixture::binding(&key, &[identifier; 32], true)?)
                    .await?,
                Response::Success
            ));
        }
        assert!(
            session
                .extension(BIND.into(), Fixture::binding(&key, b"too long", true)?)
                .await
                .is_err()
        );
        assert_eq!(session.binds.len(), 64);
        Ok(())
    }

    /// RSA requires explicit SHA-2 flags, with stable precedence if both are requested.
    #[test]
    fn rsa_flag_mapping_rejects_sha1_and_preserves_sha256_precedence() {
        let rsa = KeySpec::Rsa { bits: 2048 };
        assert!(Session::algorithm(&rsa, 0).is_err());
        assert!(Session::algorithm(&rsa, 0x80).is_err());
        assert_eq!(
            Session::algorithm(&rsa, RSA_SHA2_256 | RSA_SHA2_512).ok(),
            Some(Algorithm::Rsa {
                hash: Some(HashAlg::Sha256)
            })
        );
        assert_eq!(
            Session::algorithm(&rsa, RSA_SHA2_512).ok(),
            Some(Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            })
        );
    }

    /// A queued import cannot repopulate a store after its generation was invalidated.
    #[test]
    fn cancelled_import_cannot_write_keys_after_cleanup() -> Result<()> {
        let memory = Arc::new(MemoryStore::default());
        let agent = Fixture::agent(vec![memory.clone()])?;
        agent.state().state = control::State::Loading;
        let generation = agent.state().generation;
        agent.invalidate();
        agent.clear_stores()?;
        assert!(agent.import(vec![Fixture::record(1)?], generation).is_err());
        assert!(memory.list()?.is_empty());
        assert!(matches!(
            agent.status(),
            control::Response::Status {
                state: control::State::Locked,
                ..
            }
        ));
        Ok(())
    }
}
