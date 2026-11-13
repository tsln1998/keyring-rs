use keyring_core::{Store, StoreError, StoredKey, software};
use keyring_store_memory::MemoryStore;
use ssh_key::{Algorithm, PrivateKey, Signature, private::Ed25519Keypair};

#[test]
fn stores_signs_and_releases_keys() -> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::default();
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32]));
    let material = software::material(&key)?;
    let record = material.record.clone();
    let handle = store.load(material)?;
    assert_eq!(
        store.list()?,
        vec![StoredKey {
            handle: handle.clone(),
            record,
        }]
    );
    assert!(matches!(
        store.load(software::material(&key)?),
        Err(StoreError::Duplicate)
    ));
    let signature = Signature::new(Algorithm::Ed25519, store.sign(&handle, Algorithm::Ed25519, b"memory")?)?;
    signature::Verifier::verify(key.public_key(), b"memory", &signature)?;
    store.delete(&handle)?;
    assert!(matches!(
        store.sign(&handle, Algorithm::Ed25519, b"deleted"),
        Err(StoreError::NotFound)
    ));
    let replacement = store.load(software::material(&key)?)?;
    assert_ne!(handle, replacement);
    store.clear()?;
    assert!(store.list()?.is_empty());
    assert!(matches!(
        store.sign(&replacement, Algorithm::Ed25519, b"cleared"),
        Err(StoreError::NotFound)
    ));
    Ok(())
}

#[test]
fn rejects_mismatched_public_record() -> Result<(), StoreError> {
    let mut material = software::material(&PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32])))?;
    material.record.fingerprint.push('x');
    assert!(MemoryStore::default().load(material).is_err());
    Ok(())
}
