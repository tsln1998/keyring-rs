//! Typed control messages carried by private SSH-agent extensions.
//!
//! Unlock requests carry raw password bytes; lock and status requests have empty
//! payloads. Control responses use JSON with a `type` tag inside same-name extensions.
//! Refresh is a client operation that sends lock and then unlock on a new connection.

use crate::codec;
use keyring_core::keystore::{Kind, SigningMode};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Load a fresh provider snapshot with the password supplied as the request bytes.
pub const UNLOCK: &str = "unlock@keyring";
/// Revoke access and clear available stores; the request payload must be empty.
pub const LOCK: &str = "lock@keyring";
/// Read public state without remote access; the request payload must be empty.
pub const STATUS: &str = "status@keyring";

/// Explicit operations accepted through the control extensions.
pub enum Request {
    /// Load a fresh provider snapshot using owned, zeroizing password bytes.
    Unlock(SecretBox<[u8]>),
    /// Revoke sessions and clear the available stores.
    Lock,
    /// Read public state without contacting the provider.
    Status,
}

/// A control acknowledgement, failure, or public status view.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Response {
    /// The operation completed successfully, including any required backend cleanup.
    Success,
    /// The operation failed; a failed lock can still have revoked access.
    Failure {
        /// Stable, machine-readable failure code.
        code: String,
        /// Human-readable failure description.
        message: String,
    },
    /// The service state and its actual backend routing.
    Status {
        /// Current state, independent of whether all backend cleanup succeeded.
        state: State,
        /// Present only while a successfully imported snapshot remains published.
        snapshot: Option<Snapshot>,
        /// Actual backends in the service's order; clients should preserve this order.
        stores: Vec<Store>,
        /// Published keys sorted by store, comment, and fingerprint.
        keys: Vec<Key>,
    },
}

/// Lifecycle state exposed to clients using lowercase, kebab-case JSON names.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
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
pub struct Store {
    /// Backend kind, also used to match keys to their selected store.
    pub kind: Kind,
    /// Whether this backend currently reports that it can be used.
    pub available: bool,
    /// Short backend-provided reason when unavailable, normally an uppercase code.
    pub reason: Option<String>,
}

/// Public details about an imported identity, without provider IDs or secret bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Key {
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
    pub store: Kind,
    /// Whether signing is performed by the platform or by software.
    pub signing: SigningMode,
}

impl Request {
    /// Return the SSH-agent extension name used for this operation.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unlock(_) => UNLOCK,
            Self::Lock => LOCK,
            Self::Status => STATUS,
        }
    }

    /// Decode an extension payload, retaining password bytes in a secret owner.
    pub fn decode(name: &str, mut details: Zeroizing<Vec<u8>>) -> anyhow::Result<Self> {
        match name {
            UNLOCK => Ok(Self::Unlock(SecretBox::from(
                std::mem::take(&mut *details).into_boxed_slice(),
            ))),
            LOCK if details.is_empty() => Ok(Self::Lock),
            STATUS if details.is_empty() => Ok(Self::Status),
            LOCK | STATUS => anyhow::bail!("extension payload must be empty"),
            _ => anyhow::bail!("unsupported control extension"),
        }
    }
}

/// Wrap a control request in the ordinary SSH-agent extension envelope.
impl From<Request> for codec::Request {
    fn from(request: Request) -> Self {
        let name = request.name().into();
        let details = match request {
            Request::Unlock(password) => password.expose_secret().to_vec().into(),
            Request::Lock | Request::Status => Vec::new().into(),
        };
        Self::Extension { name, details }
    }
}

impl Response {
    /// Construct a failure response with a stable code and an explanatory message.
    pub fn failure(code: &str, message: impl Into<String>) -> Self {
        Self::Failure {
            code: code.into(),
            message: message.into(),
        }
    }
}
