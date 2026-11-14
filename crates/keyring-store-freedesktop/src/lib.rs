//! Linux Secret Service storage using the session bus's active provider.
//!
//! KWallet-compatible attributes describe generic binary entries. Public key
//! metadata lives in `payload`; private key bytes are stored in the item's Secret.
//! Signing retrieves those bytes and runs locally, rather than asking the desktop
//! provider to sign.

#![cfg(target_os = "linux")]

use keyring_core::{
    crypto,
    keystore::{Capabilities, Error, KeyId, KeyInfo, KeyRecord, KeySpec, KeyStore, Kind, SigningMode},
};
use secrecy::ExposeSecret;
use ssh_key::Algorithm;
use std::{collections::HashMap, future::Future, sync::OnceLock, time::Duration};
use tokio::runtime::Runtime;
use zbus::{Connection, OwnedObjectPath, OwnedVariant, Proxy, Variant};
use zeroize::Zeroizing;

const SERVICE: &str = "org.freedesktop.secrets";
const ROOT: &str = "/org/freedesktop/secrets";
/// The `server` namespace scopes this application's items without enforcing access control.
const APPLICATION: &str = "keyring-rs";
/// Probe entries stay outside normal key listing and cleanup.
const PROBE: &str = "keyring-rs.probe";
/// Discovery must not stall startup when the desktop service is absent.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Bounds each remote call, including cleanup after a probe times out.
const METHOD_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounds a complete storage operation or the probe's write/read stage.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(8);

/// A synchronous store backed by a dedicated runtime and one probed collection.
///
/// A failed availability probe is retained as a status reason; it does not remove
/// this backend from the protocol layer's store list.
pub struct FreeDesktopStore {
    runtime: Option<Runtime>,
    backend: OnceLock<Result<Backend, String>>,
}

/// Keeps the bus connection alive for object paths in the default collection.
struct Backend {
    connection: Connection,
    collection: OwnedObjectPath,
}

/// Converts transport, serialization, and object-path failures to the shared error type.
fn error(error: impl std::fmt::Display) -> Error {
    Error::Backend(error.to_string())
}

impl FreeDesktopStore {
    /// Verifies an already-running provider with a temporary write/read/delete round trip.
    ///
    /// Runtime creation can fail outright. Desktop availability failures instead
    /// produce a store whose cached reason can be shown in status output.
    pub fn new() -> Result<Self, Error> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(error)?;
        let store = Self {
            runtime: Some(runtime),
            backend: OnceLock::new(),
        };
        let _ = store.probe();
        Ok(store)
    }

    /// Serializes initialization and retains both successful and failed probes.
    fn probe(&self) -> &Result<Backend, String> {
        self.backend.get_or_init(|| {
            let runtime = self.runtime.as_ref().ok_or_else(|| "PROBE_FAILED".to_owned())?;
            runtime.block_on(async {
                let backend = tokio::time::timeout(DISCOVERY_TIMEOUT, Self::connect())
                    .await
                    .map_err(|_| "TIMEOUT".to_owned())??;
                Self::verify(&backend).await?;
                Ok(backend)
            })
        })
    }

    /// Discovers an existing, unlocked default collection without activating a provider.
    async fn connect() -> Result<Backend, String> {
        let connection = zbus::connection::Builder::session()
            .method_timeout(METHOD_TIMEOUT)
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
    }

    /// Keeps transport deadlines distinguishable from access or protocol failures.
    fn probe_error(failure: zbus::Error) -> String {
        match failure {
            zbus::Error::InputOutput(error) if error.kind() == std::io::ErrorKind::TimedOut => "TIMEOUT",
            zbus::Error::FDO(error)
                if matches!(*error, zbus::fdo::Error::Timeout(_) | zbus::fdo::Error::NoReply(_)) =>
            {
                "TIMEOUT"
            }
            _ => "PROBE_FAILED",
        }
        .to_owned()
    }

    /// Tests actual storage permissions, keeping cleanup outside the write/read deadline.
    async fn verify(backend: &Backend) -> Result<(), String> {
        let nonce = rand::random::<u128>();
        let payload = nonce.to_be_bytes();
        let mut session = None;
        let mut item = None;
        let result = tokio::time::timeout(OPERATION_TIMEOUT, async {
            let service = Self::service(backend).await.map_err(|_| "PROBE_FAILED".to_owned())?;
            let (_, session_path): (OwnedVariant, OwnedObjectPath) = service
                .call("OpenSession", &("plain", Variant::from("")))
                .await
                .map_err(Self::probe_error)?;
            session = Some(session_path.clone());
            let attributes = HashMap::from([
                ("application", APPLICATION.to_owned()),
                ("server", PROBE.to_owned()),
                ("user", format!("{nonce:032x}")),
                ("type", "binary".to_owned()),
            ]);
            let properties = HashMap::from([
                ("org.freedesktop.Secret.Item.Label", Variant::from(PROBE)),
                ("org.freedesktop.Secret.Item.Attributes", Variant::from(attributes)),
            ]);
            let collection = Self::proxy(backend, backend.collection.clone(), "org.freedesktop.Secret.Collection")
                .await
                .map_err(|_| "PROBE_FAILED".to_owned())?;
            let secret = (
                &session_path,
                Vec::<u8>::new(),
                payload.as_slice(),
                "application/octet-stream",
            );
            let (path, prompt): (OwnedObjectPath, OwnedObjectPath) = collection
                .call("CreateItem", &(properties, secret, false))
                .await
                .map_err(Self::probe_error)?;
            if path.as_str() != "/" {
                item = Some(path.clone());
            }
            if prompt.as_str() != "/" || item.is_none() {
                return Err("PROBE_FAILED".to_owned());
            }
            let proxy = Self::proxy(backend, path, "org.freedesktop.Secret.Item")
                .await
                .map_err(|_| "PROBE_FAILED".to_owned())?;
            let (_, _, bytes, _): (OwnedObjectPath, Vec<u8>, Vec<u8>, String) = proxy
                .call("GetSecret", &(&session_path,))
                .await
                .map_err(Self::probe_error)?;
            if bytes != payload {
                return Err("PROBE_FAILED".to_owned());
            }
            Ok(())
        })
        .await
        .map_err(|_| "TIMEOUT".to_owned())
        .and_then(|result| result);

        // A known item must be removed even after a read failure or timeout.
        let cleanup = if let Some(path) = item {
            tokio::time::timeout(METHOD_TIMEOUT, async {
                let proxy = Self::proxy(backend, path, "org.freedesktop.Secret.Item")
                    .await
                    .map_err(|_| "PROBE_FAILED".to_owned())?;
                let prompt: OwnedObjectPath = proxy.call("Delete", &()).await.map_err(Self::probe_error)?;
                if prompt.as_str() != "/" {
                    return Err("PROBE_FAILED".to_owned());
                }
                Ok(())
            })
            .await
            .map_err(|_| "TIMEOUT".to_owned())
            .and_then(|result| result)
        } else {
            Ok(())
        };
        if let Some(path) = session {
            // Session-close failures must not replace the storage probe's result.
            let _ = tokio::time::timeout(METHOD_TIMEOUT, async {
                let proxy = Self::proxy(backend, path, "org.freedesktop.Secret.Session").await?;
                proxy.call::<_, _, ()>("Close", &()).await.map_err(error)
            })
            .await;
        }
        result.and(cleanup)
    }

    /// Resolves the cached probe result into a connection or an availability error.
    fn backend(&self) -> Result<&Backend, Error> {
        self.probe()
            .as_ref()
            .map_err(|reason| Error::Unavailable(reason.clone()))
    }

    /// Runs one operation with a deadline on the store's private asynchronous runtime.
    ///
    /// Timing out drops the future; it does not roll back work already accepted by
    /// the remote service or guarantee that a session-close request was sent.
    fn run<T>(&self, future: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
        self.runtime
            .as_ref()
            .ok_or_else(|| Error::Unavailable("runtime stopped".into()))?
            .block_on(async {
                tokio::time::timeout(OPERATION_TIMEOUT, future)
                    .await
                    .map_err(|_| Error::Backend("Secret Service operation timed out".into()))?
            })
    }

    /// Builds an interface proxy whose connection is borrowed from the live backend.
    async fn proxy<'a>(backend: &'a Backend, path: OwnedObjectPath, interface: &'a str) -> Result<Proxy<'a>, Error> {
        Proxy::new(&backend.connection, SERVICE, path, interface)
            .await
            .map_err(error)
    }

    /// Targets the service root rather than a collection or item object.
    async fn service(backend: &Backend) -> Result<Proxy<'_>, Error> {
        Proxy::new(&backend.connection, SERVICE, ROOT, "org.freedesktop.Secret.Service")
            .await
            .map_err(error)
    }

    /// Finds application-owned items and refuses a partial result containing locked items.
    async fn items(backend: &Backend) -> Result<Vec<OwnedObjectPath>, Error> {
        let service = Self::service(backend).await?;
        let attributes = HashMap::from([("server", APPLICATION)]);
        let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
            service.call("SearchItems", &(attributes,)).await.map_err(error)?;
        if !locked.is_empty() {
            // A locked owned item must not disappear from listing or cleanup silently.
            return Err(Error::Unavailable("stored items are locked".into()));
        }
        Ok(unlocked)
    }

    /// Checks item ownership using the namespace, independently of its public payload.
    async fn attributes(backend: &Backend, path: OwnedObjectPath) -> Result<HashMap<String, String>, Error> {
        let item = Self::proxy(backend, path, "org.freedesktop.Secret.Item").await?;
        let attributes: HashMap<String, String> = item.get_property("Attributes").await.map_err(error)?;
        if attributes.get("server").map(String::as_str) != Some(APPLICATION) {
            return Err(Error::NotFound);
        }
        Ok(attributes)
    }

    /// Reads the public record required for listing and signature policy checks.
    async fn record(backend: &Backend, path: OwnedObjectPath) -> Result<KeyInfo, Error> {
        let attributes = Self::attributes(backend, path).await?;
        serde_json::from_str(attributes.get("payload").ok_or(Error::NotFound)?).map_err(error)
    }

    /// Deletes an owned item even when an external editor removed or damaged its payload.
    async fn delete_item(backend: &Backend, path: OwnedObjectPath) -> Result<(), Error> {
        Self::attributes(backend, path.clone()).await?;
        let item = Self::proxy(backend, path, "org.freedesktop.Secret.Item").await?;
        let prompt: OwnedObjectPath = item.call("Delete", &()).await.map_err(error)?;
        if prompt.as_str() != "/" {
            // The store does not drive desktop prompts; report the unmet interaction.
            return Err(Error::Unavailable("item deletion requires a prompt".into()));
        }
        Ok(())
    }

    /// Validates an opaque handle as a D-Bus object path before using it remotely.
    fn path(handle: &KeyId) -> Result<OwnedObjectPath, Error> {
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

impl KeyStore for FreeDesktopStore {
    fn kind(&self) -> Kind {
        Kind::FreeDesktop
    }
    fn available(&self) -> anyhow::Result<()> {
        self.probe()
            .as_ref()
            .map(|_| ())
            .map_err(|reason| anyhow::anyhow!("{reason}"))
    }
    fn capabilities(&self, _: &KeySpec) -> Capabilities {
        Capabilities {
            supported: self.available().is_ok(),
            signing: SigningMode::Software,
        }
    }
    fn load(&self, record: KeyRecord) -> Result<KeyId, Error> {
        crypto::validate(&record)?;
        let backend = self.backend()?;
        if self
            .list()?
            .iter()
            .any(|(_, info)| info.identity == record.info.identity)
        {
            return Err(Error::Duplicate);
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
                    ("user".to_owned(), record.info.fingerprint.clone()),
                    ("type".to_owned(), "binary".to_owned()),
                    (
                        "payload".to_owned(),
                        serde_json::to_string(&record.info).map_err(error)?,
                    ),
                ]);
                let properties = HashMap::from([
                    (
                        "org.freedesktop.Secret.Item.Label",
                        Variant::from(record.info.comment.as_str()),
                    ),
                    ("org.freedesktop.Secret.Item.Attributes", Variant::from(attributes)),
                ]);
                let secret = (
                    &session,
                    Vec::<u8>::new(),
                    record.secret.expose_secret(),
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
                    return Err(Error::Unavailable("key import requires a prompt".into()));
                }
                Ok(KeyId(item.as_str().as_bytes().to_vec()))
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
    fn list(&self) -> Result<Vec<(KeyId, KeyInfo)>, Error> {
        let backend = self.backend()?;
        self.run(async {
            let mut keys = Vec::new();
            for path in Self::items(backend).await? {
                // Listing reads attributes only and never opens a secret session.
                keys.push((
                    KeyId(path.as_str().as_bytes().to_vec()),
                    Self::record(backend, path).await?,
                ));
            }
            Ok(keys)
        })
    }
    fn sign(&self, handle: &KeyId, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>, Error> {
        let backend = self.backend()?;
        self.run(async {
            let path = Self::path(handle)?;
            let record = Self::record(backend, path.clone()).await?;
            let spec: KeySpec = (&record.identity).try_into().map_err(|_| Error::Unsupported)?;
            if !spec.supports(&algorithm) {
                return Err(Error::Unsupported);
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
                crypto::sign(&secret, algorithm, data)
            }
            .await;
            // Preserve signing failures while still attempting remote session cleanup.
            if let Ok(proxy) = Self::proxy(backend, session, "org.freedesktop.Secret.Session").await {
                let _: Result<(), _> = proxy.call("Close", &()).await;
            }
            result
        })
    }
    fn delete(&self, handle: &KeyId) -> Result<(), Error> {
        self.run(Self::delete_item(self.backend()?, Self::path(handle)?))
    }
    fn clear(&self) -> Result<(), Error> {
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
                return Err(Error::Backend("failed to delete one or more items".into()));
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct Mock {
        failure: &'static str,
        calls: Mutex<Vec<&'static str>>,
        secret: Mutex<Vec<u8>>,
    }

    struct Service(Arc<Mock>);
    struct Collection(Arc<Mock>);
    struct Item(Arc<Mock>);
    struct Session(Arc<Mock>);

    type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

    impl Mock {
        async fn connect(self: &Arc<Self>) -> anyhow::Result<(Connection, Backend)> {
            let (server, client) = std::os::unix::net::UnixStream::pair()?;
            let server = zbus::connection::Builder::unix_stream(server)
                .server(zbus::Guid::generate())
                .p2p()
                .serve_at(ROOT, Service(self.clone()))
                .serve_at("/collection", Collection(self.clone()))
                .serve_at("/item", Item(self.clone()))
                .serve_at("/session", Session(self.clone()));
            let client = zbus::connection::Builder::unix_stream(client).p2p();
            let (server, connection) = tokio::try_join!(server.build(), client.build())?;
            Ok((
                server,
                Backend {
                    connection,
                    collection: "/collection".try_into()?,
                },
            ))
        }

        fn call(&self, method: &'static str) -> zbus::fdo::Result<()> {
            self.calls.lock().expect("calls lock").push(method);
            if method == "GetSecret" && matches!(self.failure, "method timeout" | "method timeout and delete failure") {
                return Err(zbus::fdo::Error::Timeout(method.into()));
            }
            if self.failure == method || (self.failure == "method timeout and delete failure" && method == "Delete") {
                return Err(zbus::fdo::Error::AccessDenied(method.into()));
            }
            Ok(())
        }

        fn check(failure: &'static str, expected: &[&str]) -> anyhow::Result<()> {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()?;
            let mock = Arc::new(Self {
                failure,
                calls: Mutex::new(Vec::new()),
                secret: Mutex::new(Vec::new()),
            });
            let (_server, backend) = runtime.block_on(mock.connect())?;
            let result = runtime.block_on(FreeDesktopStore::verify(&backend));
            let reason = match failure {
                "" | "Close" => None,
                "read timeout" | "delete timeout" | "method timeout" | "method timeout and delete failure" => {
                    Some("TIMEOUT")
                }
                _ => Some("PROBE_FAILED"),
            };
            assert_eq!(result.as_ref().err().map(String::as_str), reason, "{failure}");
            assert_eq!(
                mock.secret.lock().expect("secret lock").is_empty(),
                !matches!(
                    failure,
                    "Delete" | "delete prompt" | "delete timeout" | "method timeout and delete failure"
                ),
                "{failure}"
            );
            let store = FreeDesktopStore {
                runtime: Some(runtime),
                backend: OnceLock::from(result.map(|_| backend)),
            };
            std::thread::scope(|scope| {
                for _ in 0..8 {
                    let store = &store;
                    scope.spawn(move || {
                        for _ in 0..3 {
                            assert_eq!(
                                store.available().err().as_ref().map(ToString::to_string).as_deref(),
                                reason
                            );
                            assert_eq!(store.capabilities(&KeySpec::Ed25519).supported, reason.is_none());
                        }
                    });
                }
            });
            assert_eq!(*mock.calls.lock().expect("calls lock"), expected, "{failure}");
            Ok(())
        }
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Service")]
    impl Service {
        fn open_session(
            &self,
            algorithm: &str,
            _input: Variant<'_>,
        ) -> zbus::fdo::Result<(OwnedVariant, OwnedObjectPath)> {
            self.0.call("OpenSession")?;
            assert_eq!(algorithm, "plain");
            Ok((Variant::from("").try_to_owned()?, "/session".try_into()?))
        }
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Collection")]
    impl Collection {
        fn create_item(
            &self,
            properties: HashMap<String, OwnedVariant>,
            secret: (OwnedObjectPath, Vec<u8>, Vec<u8>, String),
            replace: bool,
        ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
            self.0.call("CreateItem")?;
            assert!(!replace);
            let attributes = HashMap::<String, String>::try_from(
                properties
                    .get("org.freedesktop.Secret.Item.Attributes")
                    .expect("attributes")
                    .try_clone()?,
            )?;
            assert_eq!(attributes.get("server").map(String::as_str), Some(PROBE));
            assert_eq!(attributes.get("type").map(String::as_str), Some("binary"));
            assert_ne!(PROBE, APPLICATION);
            assert!(!attributes.contains_key("payload"));
            assert_eq!(secret.0.as_str(), "/session");
            assert!(secret.1.is_empty());
            assert_eq!(secret.2.len(), 16);
            assert_eq!(secret.3, "application/octet-stream");
            if self.0.failure == "create prompt" {
                return Ok(("/".try_into()?, "/prompt".try_into()?));
            }
            *self.0.secret.lock().expect("secret lock") = secret.2;
            Ok(("/item".try_into()?, "/".try_into()?))
        }
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Item")]
    impl Item {
        #[zbus(out_args("secret"))]
        async fn get_secret(&self, session: OwnedObjectPath) -> zbus::fdo::Result<Secret> {
            self.0.call("GetSecret")?;
            assert_eq!(session.as_str(), "/session");
            if self.0.failure == "read timeout" {
                std::future::pending::<()>().await;
            }
            let mut bytes = self.0.secret.lock().expect("secret lock").clone();
            if self.0.failure == "mismatch" {
                bytes.push(0);
            }
            Ok((session, Vec::new(), bytes, "application/octet-stream".into()))
        }

        async fn delete(&self) -> zbus::fdo::Result<OwnedObjectPath> {
            self.0.call("Delete")?;
            if self.0.failure == "delete timeout" {
                std::future::pending::<()>().await;
            }
            if self.0.failure == "delete prompt" {
                return Ok("/prompt".try_into()?);
            }
            self.0.secret.lock().expect("secret lock").clear();
            Ok("/".try_into()?)
        }
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Session")]
    impl Session {
        fn close(&self) -> zbus::fdo::Result<()> {
            self.0.call("Close")
        }
    }

    #[test]
    fn storage_probe_cleans_up_and_caches_results() -> anyhow::Result<()> {
        for failure in [
            "",
            "mismatch",
            "GetSecret",
            "Delete",
            "delete prompt",
            "Close",
            "method timeout",
            "method timeout and delete failure",
        ] {
            Mock::check(failure, &["OpenSession", "CreateItem", "GetSecret", "Delete", "Close"])?;
        }
        Mock::check("OpenSession", &["OpenSession"])?;
        for failure in ["CreateItem", "create prompt"] {
            Mock::check(failure, &["OpenSession", "CreateItem", "Close"])?;
        }
        Ok(())
    }

    #[test]
    fn timed_out_probe_still_deletes_the_item_and_closes_the_session() -> anyhow::Result<()> {
        for failure in ["read timeout", "delete timeout"] {
            Mock::check(failure, &["OpenSession", "CreateItem", "GetSecret", "Delete", "Close"])?;
        }
        Ok(())
    }

    #[test]
    fn cached_probe_failures_report_uppercase_codes_and_disable_capabilities() {
        for reason in [
            "NO_SESSION_BUS",
            "PROBE_FAILED",
            "NO_SERVICE",
            "NO_COLLECTION",
            "LOCKED",
            "TIMEOUT",
        ] {
            let store = FreeDesktopStore {
                runtime: None,
                backend: OnceLock::from(Err(reason.into())),
            };
            for _ in 0..2 {
                assert_eq!(store.available().expect_err("unavailable store").to_string(), reason);
            }
            for spec in [KeySpec::Ed25519, KeySpec::Rsa { bits: 2048 }] {
                assert!(!store.capabilities(&spec).supported);
            }
        }
    }
}
