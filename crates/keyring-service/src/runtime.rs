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
use keyring_core::provider::KeyPairProvider;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use sha2::{Sha256, Sha512};
use signature::{SignatureEncoding, Signer};
use ssh_agent_lib::agent::{Agent, ListeningSocket, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::Extension;
use ssh_agent_lib::proto::extension::{QueryResponse, SessionBind};
use ssh_agent_lib::proto::{Identity as AgentIdentity, RSA_SHA2_256, RSA_SHA2_512, SignRequest};
use ssh_agent_lib::ssh_key::{Algorithm, PrivateKey};
use ssh_agent_lib::ssh_key::{HashAlg, Signature};
use std::sync::Arc;
use tokio::sync::OnceCell;
use tracing::{debug, error, info};

/// SSH agent implementation that carries providers into each session.
pub struct ServiceAgent {
    /// Shared provider list copied into every newly accepted agent session.
    providers: Arc<Vec<Box<dyn KeyPairProvider>>>,
}

struct ServiceSession {
    /// Shared provider list inherited from the parent service agent.
    providers: Arc<Vec<Box<dyn KeyPairProvider>>>,
    /// Per-session cache populated on the first request that needs identities.
    keys: OnceCell<Arc<[PrivateKey]>>,
    /// Accepted session-bind records for this agent connection.
    session_bindings: Vec<SessionBinding>,
}

const QUERY_EXTENSION_NAME: &str = "query";
const SESSION_BIND_EXTENSION_NAME: &str = "session-bind@openssh.com";

struct SessionBinding {
    session_id: Vec<u8>,
    is_forwarding: bool,
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

        info!(provider_count = providers.len(), "creating service agent");

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
            session_bindings: Vec::new(),
        }
    }
}

#[ssh_agent_lib::async_trait]
impl Session for ServiceSession {
    async fn request_identities(&mut self) -> Result<Vec<AgentIdentity>, AgentError> {
        debug!("request_identities received");
        let keys = self
            .load_once()
            .await
            .map_err(|error| AgentError::other(std::io::Error::other(format!("{error:#}"))))?;

        // The agent protocol publishes only public key blobs plus comments; the private key data
        // remains cached inside the session for future signing requests.
        let identities: Vec<_> = keys
            .iter()
            .map(|key| AgentIdentity {
                pubkey: key.public_key().key_data().clone(),
                comment: key.comment().to_owned(),
            })
            .collect();
        info!(
            identity_count = identities.len(),
            "publishing identities for session"
        );
        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        debug!(
            flags = request.flags,
            payload_len = request.data.len(),
            "sign request received"
        );
        let keys = self
            .load_once()
            .await
            .map_err(|error| AgentError::other(std::io::Error::other(format!("{error:#}"))))?;

        // Clients refer to identities by their public key blob, so we resolve the request back
        // to the cached private key before signing.
        let key = keys
            .iter()
            .find(|key| key.public_key().key_data() == &request.pubkey)
            .ok_or_else(|| {
                error!("sign request referenced unpublished public key");
                AgentError::other(std::io::Error::other(
                    "no published identity matched the requested public key blob",
                ))
            })?;

        let signature = Self::sign(key, &request.data, request.flags)
            .map_err(|error| AgentError::other(std::io::Error::other(format!("{error:#}"))))?;
        debug!(algorithm = %signature.algorithm().as_str(), "sign request completed");
        Ok(signature)
    }

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        debug!(name = %extension.name, "agent extension request received");

        match extension.name.as_str() {
            QUERY_EXTENSION_NAME => {
                // OpenSSH clients may probe extension support before using non-core messages.
                let response = Extension::new_message(QueryResponse {
                    extensions: vec![
                        QUERY_EXTENSION_NAME.into(),
                        SESSION_BIND_EXTENSION_NAME.into(),
                    ],
                })
                .map_err(AgentError::other)?;
                debug!("reporting supported agent extensions");
                Ok(Some(response))
            }
            SESSION_BIND_EXTENSION_NAME => {
                // Windows OpenSSH sends `session-bind@openssh.com` before the first sign request.
                // Accepting it keeps parity with the built-in agent path and avoids failing the
                // whole connection on an otherwise valid authentication flow.
                let bind = extension
                    .parse_message::<SessionBind>()
                    .map_err(|error| {
                        error!(error = ?error, "failed to parse session-bind extension");
                        AgentError::ExtensionFailure
                    })?
                    .ok_or_else(|| {
                        error!("session-bind extension payload did not match its declared type");
                        AgentError::ExtensionFailure
                    })?;

                bind.verify_signature().map_err(|error| {
                    error!(error = ?error, "session-bind signature verification failed");
                    AgentError::ExtensionFailure
                })?;

                if self
                    .session_bindings
                    .iter()
                    .any(|binding| binding.session_id == bind.session_id)
                {
                    error!(
                        session_id_len = bind.session_id.len(),
                        "duplicate session-bind received for the same connection"
                    );
                    return Err(AgentError::ExtensionFailure);
                }

                if self
                    .session_bindings
                    .iter()
                    .any(|binding| !binding.is_forwarding)
                {
                    error!(
                        "refusing session-bind after the connection was already bound for authentication"
                    );
                    return Err(AgentError::ExtensionFailure);
                }

                let session_id_len = bind.session_id.len();
                let is_forwarding = bind.is_forwarding;
                self.session_bindings.push(SessionBinding {
                    session_id: bind.session_id,
                    is_forwarding,
                });
                info!(
                    binding_count = self.session_bindings.len(),
                    session_id_len, is_forwarding, "accepted session-bind for agent connection"
                );
                Ok(None)
            }
            _ => {
                debug!(name = %extension.name, "unsupported agent extension");
                Err(AgentError::Failure)
            }
        }
    }
}

impl std::fmt::Debug for ServiceAgent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceAgent")
            .field("provider_count", &self.providers.len())
            .finish()
    }
}

impl std::fmt::Debug for ServiceSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceSession")
            .field("provider_count", &self.providers.len())
            .field("keys_loaded", &self.keys.initialized())
            .field("session_binding_count", &self.session_bindings.len())
            .finish()
    }
}

impl ServiceSession {
    /// Loads and memoizes the provider snapshot for the lifetime of one client connection.
    async fn load_once(&self) -> Result<Arc<[PrivateKey]>> {
        // A single session should observe one consistent key snapshot even if it makes multiple
        // `request_identities` and `sign` calls back to back.
        let cache_hit = self.keys.initialized();
        debug!(cache_hit, "loading provider snapshot for session");
        self.keys
            .get_or_try_init(|| async {
                info!("initializing provider snapshot for session");
                self.load().await.map(Arc::<[PrivateKey]>::from)
            })
            .await
            .map(Arc::clone)
    }

    /// Pulls keys from every configured provider and normalizes the final ordering.
    async fn load(&self) -> Result<Vec<PrivateKey>> {
        let mut keys = Vec::new();

        for (index, provider) in self.providers.iter().enumerate() {
            debug!(provider_index = index, "loading provider keys");
            let mut loaded = provider
                .load()
                .await
                .with_context(|| format!("provider load failed at index {index}"))?;
            info!(
                provider_index = index,
                loaded_key_count = loaded.len(),
                "provider returned keys"
            );

            // Deterministic per-provider ordering keeps `ssh-add -L` output stable across
            // reloads and makes tests independent from provider iteration order.
            loaded.sort_by(|left, right| {
                left.comment()
                    .cmp(right.comment())
                    .then_with(|| left.algorithm().as_str().cmp(right.algorithm().as_str()))
                    .then_with(|| {
                        left.public_key()
                            .to_bytes()
                            .expect("validated public key should encode")
                            .cmp(
                                &right
                                    .public_key()
                                    .to_bytes()
                                    .expect("validated public key should encode"),
                            )
                    })
            });

            keys.extend(loaded);
        }

        info!(
            total_key_count = keys.len(),
            "assembled provider key snapshot"
        );
        Ok(keys)
    }

    /// Produces a protocol-compatible signature for the requested key and algorithm flags.
    fn sign(key: &PrivateKey, payload: &[u8], flags: u32) -> Result<Signature> {
        match key.algorithm() {
            Algorithm::Ed25519 => key.try_sign(payload).context("identity failed to sign"),
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
                        .try_sign(payload)
                        .map(|signature| signature.to_vec())
                        .context("identity failed to sign"),
                    HashAlg::Sha512 => RsaSigningKey::<Sha512>::new(key)
                        .try_sign(payload)
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
