use keyring_core::{
    StoreError,
    software::{material, sign},
};
use rsa::{PrivateKey as RsaPrivateKey, pkcs1::EncodeRsaPrivateKey};
use ssh_key::{Algorithm, HashAlg, PrivateKey};

/// Exercises the two separate RSA restrictions with an intentionally weak fixture.
#[test]
fn rsa_rejects_small_keys_and_sha1() -> Result<(), Box<dyn std::error::Error>> {
    let rsa = RsaPrivateKey::new(&mut rand::rng(), 1024)?;
    let der = rsa.to_pkcs1_der()?;
    assert!(matches!(
        sign(der.as_bytes(), Algorithm::Rsa { hash: None }, b"test"),
        Err(StoreError::Unsupported)
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
    // Import applies the same size policy as signing.
    let key = PrivateKey::from(ssh_key::private::RsaKeypair::try_from(&rsa)?);
    assert!(material(&key).is_err());
    Ok(())
}
