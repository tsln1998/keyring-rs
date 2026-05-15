//! Provider-backed SSH agent behavior without a process-wide identity registry.
//!
//! Providers are queried lazily per client session. Each session caches the loaded key list so
//! repeated identity and sign requests on the same connection reuse the same snapshot.
//!
//! # Examples
//!
//! ```
//! use keyring_service::runtime::ServiceAgent;
//!
//! let error = ServiceAgent::new(vec![]).unwrap_err();
//! assert_eq!(error.to_string(), "at least one provider must be configured");
//! ```

use anyhow::{Context, Result, bail};
use core::fmt;
use itertools::Itertools;
use keyring_core::provider::{KeyPair, KeyPairProvider};
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use sha2::{Sha256, Sha512};
use signature::{SignatureEncoding, Signer};
use ssh_agent_lib::agent::{Agent, ListeningSocket, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::Extension;
use ssh_agent_lib::proto::extension::{QueryResponse, SessionBind};
use ssh_agent_lib::proto::{Identity as AgentIdentity, RSA_SHA2_256, RSA_SHA2_512, SignRequest};
use ssh_agent_lib::ssh_key::public::KeyData;
use ssh_agent_lib::ssh_key::{Algorithm, PrivateKey};
use ssh_agent_lib::ssh_key::{HashAlg, Signature};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::OnceCell;
use tracing::{debug, error, info};

const QUERY: &str = "query";
const BIND: &str = "session-bind@openssh.com";

/// SSH agent implementation that carries providers into each session.
pub struct ServiceAgent {
    /// Shared provider list copied into every newly accepted agent session.
    providers: Arc<Vec<Box<dyn KeyPairProvider>>>,
}

struct ServiceSession {
    /// Shared provider list inherited from the parent service agent.
    providers: Arc<Vec<Box<dyn KeyPairProvider>>>,
    /// Per-session cache populated on the first request that needs identities.
    ///
    /// The public key blob is used as the lookup key so sign requests can resolve to the cached
    /// private key in O(1) time.
    keys: OnceCell<HashMap<KeyData, KeyPair>>,
    /// Accepted session-bind records for this agent connection.
    binds: Vec<Bind>,
}

struct Bind {
    id: Vec<u8>,
    fwd: bool,
}

impl ServiceAgent {
    /// Stores the configured providers so sessions can load identities.
    ///
    /// # Errors
    ///
    /// Returns an error when no providers were configured.
    pub fn new(providers: Vec<Box<dyn KeyPairProvider>>) -> Result<Self> {
        if providers.is_empty() {
            bail!("at least one provider must be configured");
        }

        info!(count = providers.len(), "creating service agent");

        Ok(Self {
            providers: Arc::new(providers),
        })
    }
}

impl<S> Agent<S> for ServiceAgent
where
    S: ListeningSocket + fmt::Debug + Send,
{
    /// Creates a fresh per-connection session so each client observes its own cached key snapshot.
    fn new_session(&mut self, _: &<S as ListeningSocket>::Stream) -> impl Session {
        ServiceSession {
            providers: Arc::clone(&self.providers),
            keys: OnceCell::new(),
            binds: Vec::new(),
        }
    }
}

#[ssh_agent_lib::async_trait]
impl Session for ServiceSession {
    async fn request_identities(&mut self) -> Result<Vec<AgentIdentity>, AgentError> {
        let keys = self.load_once().await.map_err(other)?;

        // The agent protocol publishes only public key blobs plus comments; the private key data
        // remains cached inside the session for future signing requests. We sort by `KeyData`
        // before returning because `HashMap` iteration order is intentionally unstable.
        let identities: Vec<_> = keys
            .iter()
            .map(|(pubkey, key)| AgentIdentity {
                pubkey: pubkey.clone(),
                comment: key.comment().to_owned(),
            })
            .sorted_by(|left, right| left.pubkey.cmp(&right.pubkey))
            .collect();

        info!(count = identities.len(), "publishing identities for session");
        Ok(identities)
    }

    async fn sign(&mut self, req: SignRequest) -> Result<Signature, AgentError> {
        debug!(flags = req.flags, len = req.data.len(), "sign request received");

        let keys = self.load_once().await.map_err(other)?;

        // Clients refer to identities by their public key blob, so we resolve the request back
        // to the cached private key before signing.
        let key = keys.get(&req.pubkey).ok_or_else(|| {
            error!("sign request referenced unpublished public key");
            AgentError::other(std::io::Error::other(
                "no published identity matched the requested public key blob",
            ))
        })?;

        let sig = Self::sig(key.as_ref(), &req.data, req.flags).map_err(other)?;

        debug!(alg = %sig.algorithm().as_str(), "sign request completed");
        Ok(sig)
    }

    async fn extension(&mut self, ext: Extension) -> Result<Option<Extension>, AgentError> {
        debug!(name = %ext.name, "agent extension request received");

        match ext.name.as_str() {
            QUERY => {
                // OpenSSH clients may probe extension support before using non-core messages.
                let res = Extension::new_message(QueryResponse {
                    extensions: vec![QUERY.into(), BIND.into()],
                })
                .map_err(AgentError::other)?;
                debug!("reporting supported agent extensions");
                Ok(Some(res))
            }
            BIND => {
                // Windows OpenSSH sends `session-bind@openssh.com` before the first sign request.
                // Accepting it keeps parity with the built-in agent path and avoids failing the
                // whole connection on an otherwise valid authentication flow.
                let bind = ext
                    .parse_message::<SessionBind>()
                    .map_err(|err| {
                        error!(error = ?err, "failed to parse session-bind extension");
                        AgentError::ExtensionFailure
                    })
                    .and_then(|bind| {
                        bind.ok_or_else(|| {
                            error!("session-bind extension payload did not match its declared type");
                            AgentError::ExtensionFailure
                        })
                    })
                    .and_then(|bind| {
                        bind.verify_signature().map_err(|err| {
                            error!(error = ?err, "session-bind signature verification failed");
                            AgentError::ExtensionFailure
                        })?;
                        Ok(bind)
                    })?;

                let dup = self.binds.iter().any(|item| item.id == bind.session_id);
                if dup {
                    error!("duplicate session-bind received for the same connection");
                    return Err(AgentError::ExtensionFailure);
                }

                let locked = self.binds.iter().any(|item| !item.fwd);
                if locked {
                    error!("refusing session-bind after the connection was already bound for authentication");
                    return Err(AgentError::ExtensionFailure);
                }

                self.binds.push(Bind {
                    id: bind.session_id,
                    fwd: bind.is_forwarding,
                });

                Ok(None)
            }
            _ => {
                debug!(name = %ext.name, "unsupported agent extension");
                Err(AgentError::Failure)
            }
        }
    }
}

impl std::fmt::Debug for ServiceAgent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceAgent")
            .field("providers", &self.providers.len())
            .finish()
    }
}

impl std::fmt::Debug for ServiceSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceSession")
            .field("loaded", &self.keys.initialized())
            .field("providers", &self.providers.len())
            .field("bindings", &self.binds.len())
            .finish()
    }
}

impl ServiceSession {
    /// Loads and memoizes the provider snapshot for the lifetime of one client connection.
    async fn load_once(&self) -> Result<&HashMap<KeyData, KeyPair>> {
        // A single session should observe one consistent key snapshot even if it makes multiple
        // `request_identities` and `sign` calls back to back.
        self.keys
            .get_or_try_init(|| async {
                info!("initializing provider snapshot for session");
                self.load().await
            })
            .await
    }

    /// Pulls already-normalized key snapshots from every configured provider and indexes them by
    /// public key so later sign requests can avoid re-scanning the full snapshot.
    async fn load(&self) -> Result<HashMap<KeyData, KeyPair>> {
        let mut out = HashMap::new();

        for (i, src) in self.providers.iter().enumerate() {
            let keys = src
                .load()
                .await
                .with_context(|| format!("provider load failed at index {i}"))?;

            info!(provider = i, count = keys.len(), "provider returned keys");

            out.extend(keys.iter().map(|key| (KeyData::from(key.as_ref()), Arc::clone(key))));
        }

        info!(count = out.len(), "assembled provider key index");
        Ok(out)
    }

    /// Produces a protocol-compatible signature for the requested key and algorithm flags.
    fn sig(key: &PrivateKey, data: &[u8], flags: u32) -> Result<Signature> {
        match key.algorithm() {
            Algorithm::Ed25519 => key.try_sign(data).context("identity failed to sign"),
            Algorithm::Rsa { .. } => {
                let hash = if flags & RSA_SHA2_256 != 0 {
                    HashAlg::Sha256
                } else if flags & RSA_SHA2_512 != 0 {
                    HashAlg::Sha512
                } else {
                    bail!("identity only supports rsa-sha2-256 and rsa-sha2-512");
                };
                let key: rsa::RsaPrivateKey = key
                    .key_data()
                    .rsa()
                    .context("identity is not an rsa key")?
                    .try_into()
                    .context("identity failed to prepare rsa signing")?;

                let signature = match hash {
                    HashAlg::Sha256 => RsaSigningKey::<Sha256>::new(key)
                        .try_sign(data)
                        .map(|signature| signature.to_vec())
                        .context("identity failed to sign"),
                    HashAlg::Sha512 => RsaSigningKey::<Sha512>::new(key)
                        .try_sign(data)
                        .map(|signature| signature.to_vec())
                        .context("identity failed to sign"),
                    _ => unreachable!(),
                }?;

                Signature::new(Algorithm::Rsa { hash: Some(hash) }, signature)
                    .context("identity produced an invalid rsa signature")
            }
            _ => bail!("identity uses an unsupported key algorithm"),
        }
    }
}

fn other(err: impl fmt::Display) -> AgentError {
    AgentError::other(std::io::Error::other(format!("{err:#}")))
}
