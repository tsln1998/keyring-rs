//! Canonical private key encodings and the software signing policy.
//!
//! Ed25519 uses its 32-byte seed; RSA uses PKCS#1 DER and requires at least
//! 2048 bits. RSA signatures use PKCS#1 v1.5 with SHA-256 or SHA-512.

use crate::{KeySpec, SecrecyBytes, StoreError, StoreMaterial, StoreRecord};
use ed25519_dalek::SigningKey;
use rsa::{
    PrivateKey as RsaPrivateKey,
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    pkcs1v15,
    signature::{SignatureEncoding, Signer},
    traits::PublicKeyParts,
};
use secrecy::ExposeSecret;
use sha2::{Sha256, Sha512};
use ssh_key::{Algorithm, HashAlg, PrivateKey, public::KeyData};
use zeroize::Zeroizing;

/// Preserves a conversion or cryptographic validation failure as an invalid key.
fn invalid(error: impl std::fmt::Display) -> StoreError {
    StoreError::InvalidKey(error.to_string())
}

/// Converts a decoded SSH private key into the encoding shared by all stores.
///
/// The result owns a secret copy; the caller still owns the input `PrivateKey`.
pub fn material(key: &PrivateKey) -> Result<StoreMaterial, StoreError> {
    let (spec, secret) = match key.key_data() {
        ssh_key::private::KeypairData::Ed25519(key) => (
            KeySpec::Ed25519,
            SecrecyBytes::from(key.private.as_ref().to_vec().into_boxed_slice()),
        ),
        ssh_key::private::KeypairData::Rsa(key) => {
            // Reconstruct the RSA key from its mathematical components so storage
            // does not depend on OpenSSH's private key container format.
            let precision = u32::try_from(key.public.n.as_bytes().len() * 8).map_err(invalid)?;
            let component = |value: &ssh_key::Mpint| {
                let bytes = value
                    .as_positive_bytes()
                    .ok_or_else(|| invalid("RSA components must be positive"))?;
                rsa::BoxedUint::from_be_slice(bytes, precision).map_err(invalid)
            };
            let rsa = RsaPrivateKey::from_components(
                component(&key.public.n)?,
                component(&key.public.e)?,
                component(&key.private.d)?,
                vec![component(&key.private.p)?, component(&key.private.q)?],
            )
            .map_err(invalid)?;
            validate_rsa(&rsa)?;
            let der = rsa.to_pkcs1_der().map_err(invalid)?;
            (
                KeySpec::Rsa {
                    bits: rsa.n().bit_width(),
                },
                SecrecyBytes::from(der.as_bytes().to_vec().into_boxed_slice()),
            )
        }
        _ => return Err(StoreError::Unsupported),
    };
    let identity = KeyData::from(key);
    Ok(StoreMaterial {
        record: StoreRecord {
            fingerprint: identity.fingerprint(HashAlg::Sha256).to_string(),
            identity,
            spec,
            comment: key.comment().to_owned(),
        },
        secret,
    })
}

/// Applies the modulus-size policy and checks the RSA components for consistency.
fn validate_rsa(key: &RsaPrivateKey) -> Result<(), StoreError> {
    if key.n().bit_width() < 2048 {
        return Err(invalid("RSA keys require at least 2048 bits"));
    }
    key.validate().map_err(invalid)
}

/// Verifies that private bytes, key specification, public identity, and fingerprint agree.
///
/// A well-formed public record alone is insufficient: derive the public key from
/// the private material before allowing a backend to store it.
pub fn validate(material: &StoreMaterial) -> Result<(), StoreError> {
    let identity = match material.record.spec {
        KeySpec::Ed25519 => {
            // Wipe this temporary seed copy on scope exit; the caller's material
            // remains owned by the caller until the import consumes it.
            let seed = Zeroizing::new(<[u8; 32]>::try_from(material.secret.expose_secret()).map_err(invalid)?);
            KeyData::from(ssh_key::public::Ed25519PublicKey(
                SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
            ))
        }
        KeySpec::Rsa { bits } => {
            let key = RsaPrivateKey::from_pkcs1_der(material.secret.expose_secret()).map_err(invalid)?;
            validate_rsa(&key)?;
            if key.n().bit_width() != bits {
                return Err(invalid("RSA bit size does not match record"));
            }
            KeyData::from(ssh_key::public::RsaPublicKey {
                e: ssh_key::Mpint::from_positive_bytes(&key.e_bytes()).map_err(invalid)?,
                n: ssh_key::Mpint::from_positive_bytes(&key.n_bytes()).map_err(invalid)?,
            })
        }
    };
    if identity != material.record.identity
        || identity.fingerprint(HashAlg::Sha256).to_string() != material.record.fingerprint
    {
        return Err(invalid("private key does not match public record"));
    }
    Ok(())
}

/// Signs the message using canonical private bytes and returns the raw signature.
///
/// The requested algorithm selects the private key decoder. Callers with a
/// public record should first check `supports_algorithm` to enforce its key family.
pub fn sign(secret: &[u8], algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>, StoreError> {
    match algorithm {
        Algorithm::Ed25519 => {
            let seed = Zeroizing::new(<[u8; 32]>::try_from(secret).map_err(invalid)?);
            Ok(SigningKey::from_bytes(&seed).sign(data).to_bytes().to_vec())
        }
        Algorithm::Rsa {
            hash: Some(hash @ (HashAlg::Sha256 | HashAlg::Sha512)),
        } => {
            // Message-signing APIs perform the selected hash themselves. A legacy
            // RSA request with no hash never reaches this branch.
            let key = RsaPrivateKey::from_pkcs1_der(secret).map_err(invalid)?;
            validate_rsa(&key)?;
            match hash {
                HashAlg::Sha256 => pkcs1v15::SigningKey::<Sha256>::new(key)
                    .try_sign(data)
                    .map(|signature| signature.to_vec())
                    .map_err(invalid),
                HashAlg::Sha512 => pkcs1v15::SigningKey::<Sha512>::new(key)
                    .try_sign(data)
                    .map(|signature| signature.to_vec())
                    .map_err(invalid),
                _ => Err(StoreError::Unsupported),
            }
        }
        _ => Err(StoreError::Unsupported),
    }
}

/// Rejects cross-family requests and legacy RSA/SHA-1 before accessing private bytes.
pub fn supports_algorithm(spec: &KeySpec, algorithm: &Algorithm) -> bool {
    matches!(
        (spec, algorithm),
        (KeySpec::Ed25519, Algorithm::Ed25519)
            | (
                KeySpec::Rsa { .. },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256 | HashAlg::Sha512)
                }
            )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let rsa = rsa::pkcs1::RsaPrivateKeyRef::try_from(der.as_bytes())?;
        let key = PrivateKey::from(ssh_key::private::RsaKeypair {
            public: ssh_key::public::RsaPublicKey {
                e: ssh_key::Mpint::from_positive_bytes(rsa.public_exponent.as_bytes())?,
                n: ssh_key::Mpint::from_positive_bytes(rsa.modulus.as_bytes())?,
            },
            private: ssh_key::private::RsaPrivateKey {
                d: ssh_key::Mpint::from_positive_bytes(rsa.private_exponent.as_bytes())?,
                iqmp: ssh_key::Mpint::from_positive_bytes(rsa.coefficient.as_bytes())?,
                p: ssh_key::Mpint::from_positive_bytes(rsa.prime1.as_bytes())?,
                q: ssh_key::Mpint::from_positive_bytes(rsa.prime2.as_bytes())?,
            },
        });
        assert!(material(&key).is_err());
        Ok(())
    }
}
