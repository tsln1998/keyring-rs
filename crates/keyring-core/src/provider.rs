use crate::keystore::KeyRecord;
use secrecy::SecretBox;
use std::{future::Future, pin::Pin};

/// Provider failures with a safe display message and diagnostic source context.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Authentication or password-based unlocking failed.
    #[error("{0}")]
    Auth(#[source] anyhow::Error),
    /// Fetching or decrypting the provider's key snapshot failed.
    #[error("{0}")]
    Sync(#[source] anyhow::Error),
}

/// Loads owned key material for one explicit unlock without retaining account sessions.
pub trait Provider: Send + Sync {
    /// Load fresh key records for an explicit unlock, consuming the supplied password.
    fn load(
        &self,
        password: SecretBox<[u8]>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<KeyRecord>, Error>> + Send + '_>>;
}
