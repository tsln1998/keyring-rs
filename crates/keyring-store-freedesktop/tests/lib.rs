#![cfg(target_os = "linux")]

use keyring_core::{Store, software};
use keyring_store_freedesktop::FreeDesktopStore;
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature, private::Ed25519Keypair};

#[test]
#[ignore = "requires a real unlocked Secret Service collection; not verified in CI"]
fn stored_keys_round_trip_and_sign() -> Result<(), Box<dyn std::error::Error>> {
    let store = FreeDesktopStore::new()?;
    assert!(store.available(), "{:?}", store.unavailable_reason());
    store.clear()?;
    let rsa = PrivateKey::from(ssh_key::private::RsaKeypair::random(&mut rand::rng(), 2048)?);
    for key in [PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32])), rsa] {
        let material = software::material(&key)?;
        let record = material.record.clone();
        let handle = store.load(material)?;
        assert!(store.list()?.iter().any(|stored| stored.record == record));
        let algorithm = if key.algorithm().is_rsa() {
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            }
        } else {
            Algorithm::Ed25519
        };
        let signature = Signature::new(algorithm.clone(), store.sign(&handle, algorithm, b"desktop")?)?;
        signature::Verifier::verify(key.public_key(), b"desktop", &signature)?;
        store.delete(&handle)?;
        assert!(store.list()?.is_empty());
    }
    store.load(software::material(&PrivateKey::from(Ed25519Keypair::from_seed(
        &[42; 32],
    )))?)?;
    store.clear()?;
    assert!(store.list()?.is_empty());
    Ok(())
}
