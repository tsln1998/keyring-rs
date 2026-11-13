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
            let rsa = RsaPrivateKey::try_from(key).map_err(invalid)?;
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
            comment: key.comment().to_string(),
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
            KeyData::from(ssh_key::public::RsaPublicKey::try_from(key.to_public_key()).map_err(invalid)?)
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
