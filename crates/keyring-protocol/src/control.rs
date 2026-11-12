//! Private SSH-agent extensions and their JSON response types.
//!
//! Unlock requests carry raw password bytes; lock and status requests have empty
//! payloads. Control outcomes and status use JSON inside extension responses.
//! Refresh is a client operation that sends lock and then unlock on a new connection.

use keyring_core::{SigningMode, StoreKind};
use serde::{Deserialize, Serialize};

/// Load a fresh provider snapshot with the password supplied as the request bytes.
pub const UNLOCK: &str = "unlock@keyring";
/// Revoke access and clear available stores; the request payload must be empty.
pub const LOCK: &str = "lock@keyring";
/// Read public state without remote access; the request payload must be empty.
pub const STATUS: &str = "status@keyring";

/// Lifecycle state exposed to clients using lowercase, kebab-case JSON names.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// No identities are published, even if a failed cleanup left backend data.
    Locked,
    /// A password-driven load is in progress; keys are not yet available to SSH.
    Loading,
    /// A complete imported snapshot is available for identity and signing requests.
    Unlocked,
}

/// Provenance timestamp for the currently published snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    /// RFC 3339 publication time; it does not trigger expiration or automatic refresh.
    pub loaded_at: String,
}

/// Availability of an actual store owned by the service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoreStatus {
    /// Backend kind, also used to match keys to their selected store.
    pub kind: StoreKind,
    /// Whether this backend currently reports that it can be used.
    pub available: bool,
    /// Short backend-provided reason when unavailable, normally an uppercase code.
    pub reason: Option<String>,
}

/// Public details about an imported identity, without provider IDs or secret bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyStatus {
    /// Public-key fingerprint used to identify the key in status output.
    pub fingerprint: String,
    /// User-facing comment associated with the SSH identity.
    pub comment: String,
    /// Lowercase key algorithm name, such as `ed25519` or `rsa`.
    pub algorithm: String,
    /// RSA modulus size; absent for algorithms without a reported bit count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u32>,
    /// Backend that accepted this key during the last successful import.
    pub store: StoreKind,
    /// Whether signing is performed by the platform or by software.
    pub signing: SigningMode,
}

/// A public view of the service state and its backend routing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    /// Current phase, independent of whether all backend cleanup succeeded.
    pub state: Phase,
    /// Present only while a successfully imported snapshot remains published.
    pub snapshot: Option<Snapshot>,
    /// Actual backends in the service's order; clients should preserve this order.
    pub stores: Vec<StoreStatus>,
    /// Published keys sorted by store, comment, and fingerprint.
    pub keys: Vec<KeyStatus>,
}

/// Structured result of an explicit lock or unlock request.
///
/// A failed lock can still revoke access; `ok` also reflects backend cleanup.
#[derive(Debug, Serialize, Deserialize)]
pub struct Outcome {
    /// Whether the requested operation completed successfully.
    pub ok: bool,
    /// Machine-readable failure code, omitted on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Human-readable failure description, omitted on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Outcome {
    /// Construct a success response without error fields.
    pub fn success() -> Self {
        Self {
            ok: true,
            code: None,
            message: None,
        }
    }
    /// Construct a failure response with a stable code and an explanatory message.
    pub fn failure(code: &str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            code: Some(code.into()),
            message: Some(message.into()),
        }
    }
}
