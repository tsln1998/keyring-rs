//! Shared behavioral checks used by memory and opt-in platform backend tests.
//!
//! These helpers are destructive: they clear the supplied store's application
//! entries. The deterministic fixture is public test material and must not be used
//! as a real identity.

use keyring_core::{Store, StoreError, software};
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature, private::Ed25519Keypair};

/// Checks import, listing, duplicate rejection, signing, deletion, and clearing.
///
/// Unsupported key types must fail to load. Supported types must produce signatures
/// that verify against the original public key and honor the RSA hash policy.
pub fn run_store_contract(store: &dyn Store, keys: &[PrivateKey]) -> Result<(), StoreError> {
    store.clear()?;
    for key in keys {
        // Each load consumes its material, so build a fresh owner for repeated imports.
        let make_material = || software::material(key);
        let material = make_material()?;
        let expected = material.record.clone();
        let capabilities = store.capabilities(&expected.spec);
        if !store.available() {
            assert!(!capabilities.supported);
        }
        if !capabilities.supported {
            assert!(store.load(material).is_err());
            continue;
        }
        let handle = store.load(material)?;
        assert!(
            store
                .list()?
                .iter()
                .any(|key| key.handle == handle && key.record == expected)
        );
        assert!(matches!(store.load(make_material()?), Err(StoreError::Duplicate)));
        let algorithms = match expected.spec {
            keyring_core::KeySpec::Ed25519 => vec![Algorithm::Ed25519],
            keyring_core::KeySpec::Rsa { .. } => vec![
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
            ],
        };
        for algorithm in algorithms {
            let bytes = store.sign(&handle, algorithm.clone(), b"store contract")?;
            let signature = Signature::new(algorithm.clone(), bytes.clone())
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            signature::Verifier::verify(key.public_key(), b"store contract", &signature)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            if capabilities.signing == keyring_core::SigningMode::Software {
                // Ed25519 and the supported RSA PKCS#1 v1.5 signatures are
                // deterministic, allowing an exact check of the software path.
                let material = make_material()?;
                use secrecy::ExposeSecret;
                assert_eq!(
                    bytes,
                    software::sign(material.secret.expose_secret(), algorithm, b"store contract")?
                );
            }
        }
        assert!(store.sign(&handle, Algorithm::Rsa { hash: None }, b"legacy").is_err());
        store.delete(&handle)?;
        assert!(!store.list()?.iter().any(|key| key.handle == handle));
        assert!(store.sign(&handle, key.algorithm(), b"deleted").is_err());
        // Reimport before clear so deletion and whole-store cleanup are both exercised.
        store.load(make_material()?)?;
        store.clear()?;
        assert!(store.list()?.is_empty());
    }
    Ok(())
}

/// Returns a stable, intentionally public Ed25519 identity for backend checks.
pub fn ed25519_fixture() -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryStore;

    /// Covers both supported key families without requiring a desktop secret service.
    #[test]
    fn memory_contract() -> Result<(), Box<dyn std::error::Error>> {
        let rsa = PrivateKey::from(ssh_key::private::RsaKeypair::random(&mut rand::rngs::OsRng, 2048)?);
        run_store_contract(&MemoryStore::default(), &[ed25519_fixture(), rsa])?;
        Ok(())
    }

    /// A plausible private key must not allow tampered public metadata through import.
    #[test]
    fn rejects_mismatched_public_record() -> Result<(), StoreError> {
        let mut material = software::material(&ed25519_fixture())?;
        material.record.fingerprint.push('x');
        assert!(MemoryStore::default().load(material).is_err());
        Ok(())
    }
}
