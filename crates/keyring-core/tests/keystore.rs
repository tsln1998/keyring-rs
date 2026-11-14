use anyhow::Result;
use keyring_core::{
    crypto::validate,
    keystore::{Error, KeyRecord, KeySpec},
};
use rsa::PrivateKey as RsaPrivateKey;
use ssh_key::{
    Algorithm, HashAlg, Mpint, PrivateKey,
    public::{Ed25519PublicKey, KeyData, OpaquePublicKey, RsaPublicKey},
};

#[test]
fn ed25519_spec_is_derived_from_a_borrowed_identity() -> Result<()> {
    let identity = KeyData::Ed25519(Ed25519PublicKey([42; 32]));
    assert_eq!(KeySpec::try_from(&identity)?, KeySpec::Ed25519);
    Ok(())
}

#[test]
fn rsa_spec_uses_the_modulus_significant_bits() -> Result<()> {
    for bits in [2047_u32, 2048, 2049, 4096] {
        let mut modulus = vec![0; (bits as usize).div_ceil(8)];
        modulus[0] = 1 << ((bits - 1) % 8);
        *modulus.last_mut().expect("nonempty modulus") = 1;
        let identity = KeyData::Rsa(RsaPublicKey::new(
            Mpint::from_positive_bytes(&[1, 0, 1]),
            Mpint::from_positive_bytes(&modulus),
        )?);
        assert_eq!(KeySpec::try_from(&identity)?, KeySpec::Rsa { bits });
    }
    Ok(())
}

#[test]
fn unsupported_key_spec_errors_identify_the_algorithm() -> Result<()> {
    let identity = KeyData::Other(OpaquePublicKey::new(
        vec![1, 2, 3],
        Algorithm::new("unsupported@example.test")?,
    ));
    assert_eq!(
        KeySpec::try_from(&identity)
            .expect_err("unsupported algorithm")
            .to_string(),
        "unsupported key algorithm: unsupported@example.test"
    );
    Ok(())
}

#[test]
fn signing_algorithms_match_the_key_family() -> Result<()> {
    for (algorithm, ed25519, rsa) in [
        (Algorithm::Ed25519, true, false),
        (Algorithm::Rsa { hash: None }, false, false),
        (
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            false,
            true,
        ),
        (
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            false,
            true,
        ),
        (Algorithm::new("unsupported@example.test")?, false, false),
    ] {
        assert_eq!(KeySpec::Ed25519.supports(&algorithm), ed25519);
        assert_eq!(KeySpec::Rsa { bits: 2048 }.supports(&algorithm), rsa);
    }
    Ok(())
}

#[test]
fn rsa_import_rejects_small_keys() -> Result<()> {
    let rsa = RsaPrivateKey::new(&mut rand::rng(), 1024)?;
    // Import applies the same size policy as signing.
    let key = PrivateKey::from(ssh_key::private::RsaKeypair::try_from(&rsa)?);
    assert!(matches!(KeyRecord::try_from(&key), Err(Error::InvalidKey(_))));
    Ok(())
}

#[test]
fn rsa_import_preserves_a_non_byte_aligned_modulus() -> Result<()> {
    let rsa = RsaPrivateKey::new(&mut rand::rng(), 2049)?;
    let key = PrivateKey::from(ssh_key::private::RsaKeypair::try_from(&rsa)?);
    let record = KeyRecord::try_from(&key)?;
    assert_eq!(KeySpec::try_from(&record.info.identity)?, KeySpec::Rsa { bits: 2049 });
    validate(&record)?;
    Ok(())
}
