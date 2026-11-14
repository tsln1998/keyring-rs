use keyring_core::keystore::{Error, KeyRecord, KeyStore};
use keyring_store_memory::MemoryStore;
use ssh_key::{Algorithm, PrivateKey, Signature, private::Ed25519Keypair};

#[test]
fn stores_signs_and_releases_keys() -> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::default();
    store.available()?;
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32]));
    let material = KeyRecord::try_from(&key)?;
    let info = material.info.clone();
    let handle = store.load(material)?;
    assert_eq!(store.list()?, vec![(handle.clone(), info)]);
    assert!(matches!(store.load(KeyRecord::try_from(&key)?), Err(Error::Duplicate)));
    let signature = Signature::new(Algorithm::Ed25519, store.sign(&handle, Algorithm::Ed25519, b"memory")?)?;
    signature::Verifier::verify(key.public_key(), b"memory", &signature)?;
    store.delete(&handle)?;
    assert!(matches!(
        store.sign(&handle, Algorithm::Ed25519, b"deleted"),
        Err(Error::NotFound)
    ));
    let replacement = store.load(KeyRecord::try_from(&key)?)?;
    assert_ne!(handle, replacement);
    store.clear()?;
    assert!(store.list()?.is_empty());
    assert!(matches!(
        store.sign(&replacement, Algorithm::Ed25519, b"cleared"),
        Err(Error::NotFound)
    ));
    Ok(())
}

#[test]
fn rejects_mismatched_public_record() -> Result<(), Error> {
    let mut material = KeyRecord::try_from(&PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32])))?;
    material.info.fingerprint.push('x');
    assert!(MemoryStore::default().load(material).is_err());
    Ok(())
}
