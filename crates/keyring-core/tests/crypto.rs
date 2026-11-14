use keyring_core::{
    crypto::{sign, validate},
    keystore::{Error, KeyInfo, KeyRecord},
};
use rsa::{PrivateKey as RsaPrivateKey, pkcs1::EncodeRsaPrivateKey};
use secrecy::SecretBox;
use ssh_key::{Algorithm, HashAlg, PrivateKey, private::Ed25519Keypair};

/// Exercises the two separate RSA restrictions with an intentionally weak fixture.
#[test]
fn rsa_rejects_small_keys_and_sha1() -> Result<(), Box<dyn std::error::Error>> {
    let rsa = RsaPrivateKey::new(&mut rand::rng(), 1024)?;
    let der = rsa.to_pkcs1_der()?;
    assert!(matches!(
        sign(der.as_bytes(), Algorithm::Rsa { hash: None }, b"test"),
        Err(Error::Unsupported)
    ));
    // An allowed hash must still reject the undersized key after decoding it.
    assert!(
        sign(
            der.as_bytes(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256)
            },
            b"test"
        )
        .is_err()
    );
    let identity = ssh_key::public::KeyData::Rsa(ssh_key::public::RsaPublicKey::try_from(rsa.to_public_key())?);
    let record = KeyRecord {
        info: KeyInfo {
            fingerprint: identity.fingerprint(HashAlg::Sha256).to_string(),
            identity,
            comment: String::new(),
        },
        secret: SecretBox::from(der.as_bytes().to_vec().into_boxed_slice()),
    };
    assert!(matches!(
        validate(&record),
        Err(Error::InvalidKey(reason)) if reason == "RSA keys require at least 2048 bits"
    ));
    Ok(())
}

#[test]
fn validation_rejects_private_bytes_for_another_public_identity() -> anyhow::Result<()> {
    let mut record = KeyRecord::try_from(&PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32])))?;
    let other = KeyRecord::try_from(&PrivateKey::from(Ed25519Keypair::from_seed(&[17; 32])))?;
    record.info = other.info;
    assert!(matches!(validate(&record), Err(Error::InvalidKey(_))));
    Ok(())
}
