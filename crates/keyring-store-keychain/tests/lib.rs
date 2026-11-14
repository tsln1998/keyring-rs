#![cfg(target_os = "macos")]

use keyring_core::keystore::{KeyRecord, KeyStore};
use keyring_store_keychain::KeychainStore;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
use security_framework_sys::base::errSecItemNotFound;
use ssh_key::{PrivateKey, private::Ed25519Keypair};

#[test]
#[ignore = "requires a real unlocked macOS Keychain; not verified in CI"]
fn availability_probe_preserves_keys_and_removes_temporary_items() -> anyhow::Result<()> {
    let probes = || -> anyhow::Result<usize> {
        match ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service("keyring-rs.probe")
            .load_data(true)
            .limit(Limit::All)
            .search()
        {
            Ok(items) => Ok(items.len()),
            Err(error) if error.code() == errSecItemNotFound => Ok(0),
            Err(error) => Err(error.into()),
        }
    };
    let before = probes()?;
    let store = KeychainStore::new();
    store.available()?;
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&rand::random()));
    let handle = store.load(KeyRecord::try_from(&key)?)?;
    let result = (|| -> anyhow::Result<()> {
        let expected = store.list()?;
        let other = KeychainStore::new();
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
