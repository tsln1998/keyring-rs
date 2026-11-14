//! Canonical private key encodings and the software signing policy.
//!
//! Ed25519 uses its 32-byte seed; RSA uses PKCS#1 DER and requires at least
//! 2048 bits. RSA signatures use PKCS#1 v1.5 with SHA-256 or SHA-512.

use crate::keystore::{Error, KeyRecord, KeySpec};
use ed25519_dalek::SigningKey;
use rsa::{
    PrivateKey as RsaPrivateKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs1v15,
    signature::{SignatureEncoding, Signer},
    traits::PublicKeyParts,
};
use secrecy::ExposeSecret;
use sha2::{Sha256, Sha512};
use ssh_key::{Algorithm, HashAlg, public::KeyData};
use zeroize::Zeroizing;

/// Verifies that private bytes, key specification, public identity, and fingerprint agree.
///
/// A well-formed public record alone is insufficient: derive the public key from
/// the private material before allowing a backend to store it.
pub fn validate(record: &KeyRecord) -> Result<(), Error> {
    let spec: KeySpec = (&record.info.identity)
        .try_into()
        .map_err(|error: anyhow::Error| Error::InvalidKey(error.to_string()))?;
    let identity = match spec {
        KeySpec::Ed25519 => {
            // Wipe this temporary seed copy on scope exit; the caller's material
            // remains owned by the caller until the import consumes it.
            let seed = Zeroizing::new(
                <[u8; 32]>::try_from(record.secret.expose_secret())
                    .map_err(|error| Error::InvalidKey(error.to_string()))?,
            );
            KeyData::from(ssh_key::public::Ed25519PublicKey(
                SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
            ))
        }
        KeySpec::Rsa { .. } => {
            let key = RsaPrivateKey::from_pkcs1_der(record.secret.expose_secret())
                .map_err(|error| Error::InvalidKey(error.to_string()))?;
            if key.n().bit_width() < 2048 {
                return Err(Error::InvalidKey("RSA keys require at least 2048 bits".into()));
            }
            key.validate().map_err(|error| Error::InvalidKey(error.to_string()))?;
            KeyData::from(
                ssh_key::public::RsaPublicKey::try_from(key.to_public_key())
                    .map_err(|error| Error::InvalidKey(error.to_string()))?,
            )
        }
    };
    if identity != record.info.identity || identity.fingerprint(HashAlg::Sha256).to_string() != record.info.fingerprint
    {
        return Err(Error::InvalidKey("private key does not match public record".into()));
    }
    Ok(())
}

/// Signs the message using canonical private bytes and returns the raw signature.
///
/// The requested algorithm selects the private key decoder. Callers with a
/// public record should first check [`KeySpec::supports`] to enforce its key family.
pub fn sign(secret: &[u8], algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>, Error> {
    match algorithm {
        Algorithm::Ed25519 => {
            let seed =
                Zeroizing::new(<[u8; 32]>::try_from(secret).map_err(|error| Error::InvalidKey(error.to_string()))?);
            Ok(SigningKey::from_bytes(&seed).sign(data).to_bytes().to_vec())
        }
        Algorithm::Rsa {
            hash: Some(hash @ (HashAlg::Sha256 | HashAlg::Sha512)),
        } => {
            // Message-signing APIs perform the selected hash themselves. A legacy
            // RSA request with no hash never reaches this branch.
            let key = RsaPrivateKey::from_pkcs1_der(secret).map_err(|error| Error::InvalidKey(error.to_string()))?;
            if key.n().bit_width() < 2048 {
                return Err(Error::InvalidKey("RSA keys require at least 2048 bits".into()));
            }
            key.validate().map_err(|error| Error::InvalidKey(error.to_string()))?;
            match hash {
                HashAlg::Sha256 => pkcs1v15::SigningKey::<Sha256>::new(key)
                    .try_sign(data)
                    .map(|signature| signature.to_vec())
                    .map_err(|error| Error::InvalidKey(error.to_string())),
                HashAlg::Sha512 => pkcs1v15::SigningKey::<Sha512>::new(key)
                    .try_sign(data)
                    .map(|signature| signature.to_vec())
                    .map_err(|error| Error::InvalidKey(error.to_string())),
                _ => Err(Error::Unsupported),
            }
        }
        _ => Err(Error::Unsupported),
    }
}
