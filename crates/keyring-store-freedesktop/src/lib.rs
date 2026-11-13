//! Linux Secret Service storage using the session bus's active provider.
//!
//! KWallet-compatible attributes describe generic binary entries. Public key
//! metadata lives in `payload`; private key bytes are stored in the item's Secret.
//! Signing retrieves those bytes and runs locally, rather than asking the desktop
//! provider to sign.

#![cfg(target_os = "linux")]

use keyring_core::{
    Capabilities, KeySpec, SigningMode, Store, StoreError, StoreHandle, StoreKind, StoreMaterial, StoreRecord,
    StoredKey, software,
};
use secrecy::ExposeSecret;
use ssh_key::Algorithm;
use std::{collections::HashMap, future::Future, time::Duration};
use tokio::runtime::Runtime;
use zbus::{Connection, OwnedObjectPath, OwnedVariant, Proxy, Variant};
use zeroize::Zeroizing;

const SERVICE: &str = "org.freedesktop.secrets";
const ROOT: &str = "/org/freedesktop/secrets";
/// The `server` namespace scopes this application's items without enforcing access control.
const APPLICATION: &str = "keyring-rs";

/// A synchronous store backed by a dedicated runtime and one probed collection.
///
/// A failed availability probe is retained as a status reason; it does not remove
/// this backend from the protocol layer's store list.
pub struct FreeDesktopStore {
    runtime: Option<Runtime>,
    backend: Result<Backend, String>,
}

/// Keeps the bus connection alive for object paths in the default collection.
struct Backend {
    connection: Connection,
    collection: OwnedObjectPath,
}

/// Converts transport, serialization, and object-path failures to the shared error type.
fn error(error: impl std::fmt::Display) -> StoreError {
    StoreError::Backend(error.to_string())
}

impl FreeDesktopStore {
    /// Probes an already-running provider and unlocked default collection without prompts.
    ///
    /// Runtime creation can fail outright. Desktop availability failures instead
    /// produce a store whose cached reason can be shown in status output.
    pub fn new() -> Result<Self, StoreError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(error)?;
        let backend = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), async {
                let connection = zbus::connection::Builder::session()
                    .method_timeout(Duration::from_secs(5))
                    .build()
                    .await
                    .map_err(|_| "NO_SESSION_BUS".to_owned())?;
                let bus = Proxy::new(
                    &connection,
                    "org.freedesktop.DBus",
                    "/org/freedesktop/DBus",
                    "org.freedesktop.DBus",
                )
                .await
                .map_err(|_| "PROBE_FAILED".to_owned())?;
                let owned: bool = bus
                    .call("NameHasOwner", &(SERVICE,))
                    .await
                    .map_err(|_| "PROBE_FAILED".to_owned())?;
                if !owned {
                    // Do not implicitly activate a provider while merely probing status.
                    return Err("NO_SERVICE".to_owned());
                }
                let service = Proxy::new(&connection, SERVICE, ROOT, "org.freedesktop.Secret.Service")
                    .await
                    .map_err(|_| "PROBE_FAILED".to_owned())?;
                let collection: OwnedObjectPath = service
                    .call("ReadAlias", &("default",))
                    .await
                    .map_err(|_| "PROBE_FAILED".to_owned())?;
                // Secret Service uses the root path as the "no collection" sentinel.
                if collection.as_str() == "/" {
                    return Err("NO_COLLECTION".into());
                }
                let collection_proxy = Proxy::new(
                    &connection,
                    SERVICE,
                    collection.clone(),
                    "org.freedesktop.Secret.Collection",
                )
                .await
                .map_err(|_| "PROBE_FAILED".to_owned())?;
                let locked: bool = collection_proxy
                    .get_property("Locked")
                    .await
                    .map_err(|_| "PROBE_FAILED".to_owned())?;
                if locked {
                    return Err("LOCKED".into());
                }
                drop(collection_proxy);
                drop(service);
                drop(bus);
                Ok(Backend { connection, collection })
            })
            .await
            .map_err(|_| "TIMEOUT".to_owned())?
        });
        Ok(Self {
            runtime: Some(runtime),
            backend,
        })
    }

    /// Resolves the cached probe result into a connection or an availability error.
    fn backend(&self) -> Result<&Backend, StoreError> {
        self.backend
            .as_ref()
            .map_err(|reason| StoreError::Unavailable(reason.clone()))
    }

    /// Runs one operation with a deadline on the store's private asynchronous runtime.
    ///
    /// Timing out drops the future; it does not roll back work already accepted by
    /// the remote service or guarantee that a session-close request was sent.
    fn run<T>(&self, future: impl Future<Output = Result<T, StoreError>>) -> Result<T, StoreError> {
        self.runtime
            .as_ref()
            .ok_or_else(|| StoreError::Unavailable("runtime stopped".into()))?
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(8), future)
                    .await
                    .map_err(|_| StoreError::Backend("Secret Service operation timed out".into()))?
            })
    }

    /// Builds an interface proxy whose connection is borrowed from the live backend.
    async fn proxy<'a>(
        backend: &'a Backend,
        path: OwnedObjectPath,
        interface: &'a str,
    ) -> Result<Proxy<'a>, StoreError> {
        Proxy::new(&backend.connection, SERVICE, path, interface)
            .await
            .map_err(error)
    }

    /// Targets the service root rather than a collection or item object.
    async fn service(backend: &Backend) -> Result<Proxy<'_>, StoreError> {
        Proxy::new(&backend.connection, SERVICE, ROOT, "org.freedesktop.Secret.Service")
            .await
            .map_err(error)
    }

    /// Finds application-owned items and refuses a partial result containing locked items.
    async fn items(backend: &Backend) -> Result<Vec<OwnedObjectPath>, StoreError> {
        let service = Self::service(backend).await?;
        let attributes = HashMap::from([("server", APPLICATION)]);
        let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
            service.call("SearchItems", &(attributes,)).await.map_err(error)?;
        if !locked.is_empty() {
            // A locked owned item must not disappear from listing or cleanup silently.
            return Err(StoreError::Unavailable("stored items are locked".into()));
        }
        Ok(unlocked)
    }

    /// Checks item ownership using the namespace, independently of its public payload.
    async fn attributes(backend: &Backend, path: OwnedObjectPath) -> Result<HashMap<String, String>, StoreError> {
        let item = Self::proxy(backend, path, "org.freedesktop.Secret.Item").await?;
        let attributes: HashMap<String, String> = item.get_property("Attributes").await.map_err(error)?;
        if attributes.get("server").map(String::as_str) != Some(APPLICATION) {
            return Err(StoreError::NotFound);
        }
        Ok(attributes)
    }

    /// Reads the public record required for listing and signature policy checks.
    async fn record(backend: &Backend, path: OwnedObjectPath) -> Result<StoreRecord, StoreError> {
        let attributes = Self::attributes(backend, path).await?;
        serde_json::from_str(attributes.get("payload").ok_or(StoreError::NotFound)?).map_err(error)
    }

    /// Deletes an owned item even when an external editor removed or damaged its payload.
    async fn delete_item(backend: &Backend, path: OwnedObjectPath) -> Result<(), StoreError> {
        Self::attributes(backend, path.clone()).await?;
        let item = Self::proxy(backend, path, "org.freedesktop.Secret.Item").await?;
        let prompt: OwnedObjectPath = item.call("Delete", &()).await.map_err(error)?;
        if prompt.as_str() != "/" {
            // The store does not drive desktop prompts; report the unmet interaction.
            return Err(StoreError::Unavailable("item deletion requires a prompt".into()));
        }
        Ok(())
    }

    /// Validates an opaque handle as a D-Bus object path before using it remotely.
    fn path(handle: &StoreHandle) -> Result<OwnedObjectPath, StoreError> {
        let path = std::str::from_utf8(&handle.0).map_err(error)?;
        OwnedObjectPath::try_from(path.to_owned()).map_err(error)
    }
}

impl Drop for FreeDesktopStore {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            // Drop can occur inside another Tokio runtime, where blocking runtime
            // destruction is invalid. Application item cleanup is an explicit clear().
            runtime.shutdown_background();
        }
    }
}

impl Store for FreeDesktopStore {
    fn kind(&self) -> StoreKind {
        StoreKind::FreeDesktop
    }
    fn available(&self) -> bool {
        self.backend.is_ok()
    }
    fn unavailable_reason(&self) -> Option<String> {
        self.backend.as_ref().err().cloned()
    }
    fn capabilities(&self, _: &KeySpec) -> Capabilities {
        Capabilities {
            supported: self.available(),
            signing: SigningMode::Software,
        }
    }
    fn load(&self, material: StoreMaterial) -> Result<StoreHandle, StoreError> {
        software::validate(&material)?;
        let backend = self.backend()?;
        if self
            .list()?
            .iter()
            .any(|key| key.record.identity == material.record.identity)
        {
            return Err(StoreError::Duplicate);
        }
        self.run(async {
            let service = Self::service(backend).await?;
            // "plain" adds no session encryption to the local D-Bus transfer.
            // Encryption of persisted entries is the provider's responsibility.
            let (_, session): (OwnedVariant, OwnedObjectPath) = service
                .call("OpenSession", &("plain", Variant::from("")))
                .await
                .map_err(error)?;
            let result = async {
                // KWallet maps server/user to folder/entry names and type to its
                // binary entry kind. Fingerprints keep duplicate comments distinct.
                // All attributes, including payload, contain public metadata only.
                let attributes = HashMap::from([
                    ("application".to_owned(), APPLICATION.to_owned()),
                    ("server".to_owned(), APPLICATION.to_owned()),
                    ("user".to_owned(), material.record.fingerprint.clone()),
                    ("type".to_owned(), "binary".to_owned()),
                    (
                        "payload".to_owned(),
                        serde_json::to_string(&material.record).map_err(error)?,
                    ),
                ]);
                let properties = HashMap::from([
                    (
                        "org.freedesktop.Secret.Item.Label",
                        Variant::from(material.record.comment.as_str()),
                    ),
                    ("org.freedesktop.Secret.Item.Attributes", Variant::from(attributes)),
                ]);
                let secret = (
                    &session,
                    Vec::<u8>::new(),
                    material.secret.expose_secret(),
                    "application/octet-stream",
                );
                // The Secret carries the canonical raw seed or DER, not JSON or Base64.
                let collection =
                    Self::proxy(backend, backend.collection.clone(), "org.freedesktop.Secret.Collection").await?;
                let (item, prompt): (OwnedObjectPath, OwnedObjectPath) = collection
                    .call("CreateItem", &(properties, secret, false))
                    .await
                    .map_err(error)?;
                if prompt.as_str() != "/" {
                    return Err(StoreError::Unavailable("key import requires a prompt".into()));
                }
                Ok(StoreHandle(item.as_str().as_bytes().to_vec()))
            }
            .await;
            // Attempt to close the session after success or an ordinary inner error;
            // a close failure must not replace the import's actual result.
            if let Ok(proxy) = Self::proxy(backend, session, "org.freedesktop.Secret.Session").await {
                let _: Result<(), _> = proxy.call("Close", &()).await;
            }
            result
        })
    }
    fn list(&self) -> Result<Vec<StoredKey>, StoreError> {
        let backend = self.backend()?;
        self.run(async {
            let mut keys = Vec::new();
            for path in Self::items(backend).await? {
                // Listing reads attributes only and never opens a secret session.
                keys.push(StoredKey {
                    handle: StoreHandle(path.as_str().as_bytes().to_vec()),
                    record: Self::record(backend, path).await?,
                });
            }
            Ok(keys)
        })
    }
    fn sign(&self, handle: &StoreHandle, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>, StoreError> {
        let backend = self.backend()?;
        self.run(async {
            let path = Self::path(handle)?;
            let record = Self::record(backend, path.clone()).await?;
            if !software::supports_algorithm(&record.spec, &algorithm) {
                return Err(StoreError::Unsupported);
            }
            let service = Self::service(backend).await?;
            let (_, session): (OwnedVariant, OwnedObjectPath) = service
                .call("OpenSession", &("plain", Variant::from("")))
                .await
                .map_err(error)?;
            let result = async {
                let item = Self::proxy(backend, path, "org.freedesktop.Secret.Item").await?;
                let (_, _, secret, _): (OwnedObjectPath, Vec<u8>, Vec<u8>, String) =
                    item.call("GetSecret", &(&session,)).await.map_err(error)?;
                // Bound this retrieved buffer's lifetime to the signing attempt.
                // This cannot wipe copies held by the transport or crypto libraries.
                let secret = Zeroizing::new(secret);
                software::sign(&secret, algorithm, data)
            }
            .await;
            // Preserve signing failures while still attempting remote session cleanup.
            if let Ok(proxy) = Self::proxy(backend, session, "org.freedesktop.Secret.Session").await {
                let _: Result<(), _> = proxy.call("Close", &()).await;
            }
            result
        })
    }
    fn delete(&self, handle: &StoreHandle) -> Result<(), StoreError> {
        self.run(Self::delete_item(self.backend()?, Self::path(handle)?))
    }
    fn clear(&self) -> Result<(), StoreError> {
        let backend = self.backend()?;
        self.run(async {
            let mut failed = false;
            for path in Self::items(backend).await? {
                // One item failure must not prevent deletion attempts for the rest.
                if Self::delete_item(backend, path).await.is_err() {
                    failed = true;
                }
            }
            if failed {
                return Err(StoreError::Backend("failed to delete one or more items".into()));
            }
            Ok(())
        })
    }
}
