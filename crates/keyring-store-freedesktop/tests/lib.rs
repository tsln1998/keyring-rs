#![cfg(target_os = "linux")]

use keyring_core::keystore::{KeyRecord, KeyStore};
use keyring_store_freedesktop::FreeDesktopStore;
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature, private::Ed25519Keypair};

#[test]
#[ignore = "requires a real unlocked Secret Service collection; not verified in CI"]
fn availability_probe_preserves_keys_and_removes_temporary_items() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let connection = runtime.block_on(zbus::Connection::session())?;
    let service = runtime.block_on(zbus::Proxy::new(
        &connection,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    ))?;
    let probes = || -> zbus::Result<_> {
        let (mut unlocked, mut locked): (Vec<zbus::OwnedObjectPath>, Vec<zbus::OwnedObjectPath>) =
            runtime.block_on(service.call(
                "SearchItems",
                &(std::collections::HashMap::from([("server", "keyring-rs.probe")]),),
            ))?;
        unlocked.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        locked.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        Ok((unlocked, locked))
    };
    let before = probes()?;
    let store = FreeDesktopStore::new()?;
    store.available()?;
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&rand::random()));
    let handle = store.load(KeyRecord::try_from(&key)?)?;
    let result = (|| -> anyhow::Result<()> {
        let expected = store.list()?;
        let other = FreeDesktopStore::new()?;
        other.available()?;
        let actual = other.list()?;
        assert_eq!(actual.len(), expected.len());
        assert!(expected.iter().all(|key| actual.contains(key)));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let other = &other;
                scope.spawn(move || other.available().expect("cached availability"));
            }
        });
        assert_eq!(probes()?, before);
        Ok(())
    })();
    let cleanup = store.delete(&handle);
    result?;
    cleanup?;
    Ok(())
}

#[test]
#[ignore = "requires a real unlocked Secret Service collection; not verified in CI"]
fn stored_keys_round_trip_and_sign() -> Result<(), Box<dyn std::error::Error>> {
    let store = FreeDesktopStore::new()?;
    store.available()?;
    store.clear()?;
    let rsa = PrivateKey::from(ssh_key::private::RsaKeypair::random(&mut rand::rng(), 2048)?);
    for key in [PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32])), rsa] {
        let material = KeyRecord::try_from(&key)?;
        let record = material.info.clone();
        let handle = store.load(material)?;
        assert!(store.list()?.iter().any(|(_, info)| info == &record));
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
    store.load(KeyRecord::try_from(&PrivateKey::from(Ed25519Keypair::from_seed(
        &[42; 32],
    )))?)?;
    store.clear()?;
    assert!(store.list()?.is_empty());
    Ok(())
}
