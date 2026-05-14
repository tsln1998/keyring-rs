//! SSH-agent protocol runtime backed by configured key providers.
//!
//! This crate translates provider-loaded private keys into the subset of the OpenSSH agent
//! protocol implemented by `ssh-agent-lib`.
//!
//! # Examples
//!
//! List identities from a provider-backed session and observe that the published order is stable:
//!
//! ```
//! use keyring_core::provider::KeyPairProvider;
//! use keyring_service::runtime::ServiceAgent;
//! use ssh_agent_lib::agent::{Agent, Session};
//! use ssh_agent_lib::ssh_key::private::Ed25519Keypair;
//! use ssh_agent_lib::ssh_key::{PrivateKey, PublicKey};
//! use std::sync::Arc;
//! use std::sync::atomic::{AtomicUsize, Ordering};
//! use tokio::net::{UnixListener, UnixStream};
//!
//! #[derive(Clone)]
//! struct CountingIdentity {
//!     private_key: PrivateKey,
//! }
//!
//! impl CountingIdentity {
//!     fn ed25519(name: &str, seed: u8) -> Self {
//!         let mut private_key = PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]));
//!         private_key.set_comment(name);
//!         Self { private_key }
//!     }
//! }
//!
//! struct CountingProvider {
//!     load_calls: Arc<AtomicUsize>,
//!     identities: Vec<CountingIdentity>,
//! }
//!
//! #[ssh_agent_lib::async_trait]
//! impl KeyPairProvider for CountingProvider {
//!     async fn load(&self) -> Result<Arc<[Arc<PrivateKey>]>, anyhow::Error> {
//!         self.load_calls.fetch_add(1, Ordering::SeqCst);
//!         Ok(Arc::<[Arc<PrivateKey>]>::from(
//!             self.identities
//!                 .iter()
//!                 .cloned()
//!                 .map(|identity| Arc::new(identity.private_key))
//!                 .collect::<Vec<_>>(),
//!         ))
//!     }
//! }
//!
//! tokio::runtime::Runtime::new().unwrap().block_on(async {
//!     let provider = CountingProvider {
//!         load_calls: Arc::new(AtomicUsize::new(0)),
//!         identities: vec![
//!             CountingIdentity::ed25519("zeta", 8),
//!             CountingIdentity::ed25519("alpha", 7),
//!         ],
//!     };
//!     let mut agent = ServiceAgent::new(vec![Box::new(provider)]).unwrap();
//!     let (socket, _) = UnixStream::pair().unwrap();
//!     let mut session = <ServiceAgent as Agent<UnixListener>>::new_session(&mut agent, &socket);
//!     let identities = session.request_identities().await.unwrap();
//!
//!     assert_eq!(identities.len(), 2);
//!     assert_eq!(
//!         identities
//!             .iter()
//!             .map(|identity| identity.comment.as_str())
//!             .collect::<Vec<_>>(),
//!         vec!["zeta", "alpha"]
//!     );
//!     assert!(identities.iter().all(|identity| {
//!         !PublicKey::from(identity.pubkey.clone())
//!             .to_bytes()
//!             .unwrap()
//!             .is_empty()
//!     }));
//! });
//! ```
//!
//! Sign with a known key, reject an unknown key, and reuse the provider snapshot within one
//! session:
//!
//! ```
//! use keyring_core::provider::KeyPairProvider;
//! use keyring_service::runtime::ServiceAgent;
//! use ssh_agent_lib::agent::{Agent, Session};
//! use ssh_agent_lib::proto::SignRequest;
//! use ssh_agent_lib::ssh_key::private::Ed25519Keypair;
//! use ssh_agent_lib::ssh_key::{Algorithm, PrivateKey, PrivateKey as SshPrivateKey};
//! use std::sync::Arc;
//! use std::sync::atomic::{AtomicUsize, Ordering};
//! use tokio::net::{UnixListener, UnixStream};
//!
//! #[derive(Clone)]
//! struct CountingIdentity {
//!     private_key: PrivateKey,
//! }
//!
//! impl CountingIdentity {
//!     fn ed25519(name: &str, seed: u8) -> Self {
//!         let mut private_key = PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]));
//!         private_key.set_comment(name);
//!         Self { private_key }
//!     }
//! }
//!
//! struct CountingProvider {
//!     load_calls: Arc<AtomicUsize>,
//!     identities: Vec<CountingIdentity>,
//! }
//!
//! #[ssh_agent_lib::async_trait]
//! impl KeyPairProvider for CountingProvider {
//!     async fn load(&self) -> Result<Arc<[Arc<PrivateKey>]>, anyhow::Error> {
//!         self.load_calls.fetch_add(1, Ordering::SeqCst);
//!         Ok(Arc::<[Arc<PrivateKey>]>::from(
//!             self.identities
//!                 .iter()
//!                 .cloned()
//!                 .map(|identity| Arc::new(identity.private_key))
//!                 .collect::<Vec<_>>(),
//!         ))
//!     }
//! }
//!
//! tokio::runtime::Runtime::new().unwrap().block_on(async {
//!     let load_calls = Arc::new(AtomicUsize::new(0));
//!     let provider = CountingProvider {
//!         load_calls: load_calls.clone(),
//!         identities: vec![CountingIdentity::ed25519("signer", 7)],
//!     };
//!     let mut agent = ServiceAgent::new(vec![Box::new(provider)]).unwrap();
//!     let (socket, _) = UnixStream::pair().unwrap();
//!     let mut session = <ServiceAgent as Agent<UnixListener>>::new_session(&mut agent, &socket);
//!     let identities = session.request_identities().await.unwrap();
//!     let identity = identities.first().unwrap();
//!
//!     assert!(matches!(identity.pubkey.algorithm(), Algorithm::Ed25519));
//!
//!     let signature = session
//!         .sign(SignRequest {
//!             pubkey: identity.pubkey.clone(),
//!             data: b"payload".to_vec(),
//!             flags: 0,
//!         })
//!         .await
//!         .unwrap();
//!     assert_eq!(signature.algorithm().as_str(), "ssh-ed25519");
//!     assert!(!signature.as_bytes().is_empty());
//!
//!     session
//!         .sign(SignRequest {
//!             pubkey: identity.pubkey.clone(),
//!             data: b"payload-2".to_vec(),
//!             flags: 0,
//!         })
//!         .await
//!         .unwrap();
//!     assert_eq!(load_calls.load(Ordering::SeqCst), 1);
//!
//!     let unknown_key = SshPrivateKey::from(Ed25519Keypair::from_seed(&[9_u8; 32]))
//!         .public_key()
//!         .key_data()
//!         .clone();
//!     let error = session
//!         .sign(SignRequest {
//!             pubkey: unknown_key,
//!             data: b"payload".to_vec(),
//!             flags: 0,
//!         })
//!         .await
//!         .unwrap_err();
//!     assert!(error
//!         .to_string()
//!         .contains("no published identity matched the requested public key blob"));
//! });
//! ```

pub mod runtime;
