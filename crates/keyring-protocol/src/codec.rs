//! The supported SSH-agent messages, without transport or private-key operations.
//!
//! Extension payloads clear themselves when dispatched, cancelled, or discarded.

use ssh_encoding::{CheckedSum, Decode, Encode, Error, Reader, Writer};
use ssh_key::{Signature, public::KeyData};
use zeroize::Zeroizing;

/// Request the public keys currently available from the agent.
const REQUEST_IDENTITIES: u8 = 11;
/// Request a signature for a key blob, message, and signing flags.
const REQUEST_SIGNATURE: u8 = 13;
/// Invoke a named extension with the remaining packet bytes as its payload.
const REQUEST_EXTENSION: u8 = 27;

/// An ordinary request failed or used an unsupported operation.
const RESPONSE_FAILURE: u8 = 5;
/// A request succeeded without returning an operation-specific payload.
const RESPONSE_SUCCESS: u8 = 6;
/// Return public keys together with their human-readable comments.
const RESPONSE_IDENTITIES: u8 = 12;
/// Return the requested SSH signature inside a length-prefixed blob.
const RESPONSE_SIGNATURE: u8 = 14;
/// Report an unsupported or failed extension without a response payload.
const RESPONSE_EXTENSION_FAILURE: u8 = 28;
/// Return an extension name followed by its raw response payload.
const RESPONSE_EXTENSION_SUCCESS: u8 = 29;

/// Supported SSH-agent request bodies, decoded after transport framing.
pub enum Request {
    /// Request the public identities currently available for signing.
    Identities,
    /// Request a signature using the key identified by its SSH public-key blob.
    Signature {
        // SSH public-key blob identifying the key to use for signing.
        key: Vec<u8>,
        // Message bytes to sign, before any algorithm-specific hashing.
        data: Vec<u8>,
        // Client-supplied signature flags, including the RSA SHA-2 selection bits.
        flags: u32,
    },
    /// Invoke a named SSH-agent extension with its raw payload.
    Extension {
        // Extension name identifying the requested operation.
        name: String,
        // Raw extension payload, zeroized on drop because unlock carries a password.
        details: Zeroizing<Vec<u8>>,
    },
    /// An unrecognized request whose remaining payload has been discarded.
    Unsupported,
}

/// SSH-agent response bodies, encoded before transport framing.
pub enum Response {
    /// Report a failed or unsupported ordinary request.
    Failure,
    /// Acknowledge a request without a response payload, such as session binding.
    Success,
    /// Return the public keys and their associated comments.
    Identities(
        // Public identities listed as (public key, comment) pairs.
        Vec<(
            // SSH public key for this identity.
            KeyData,
            // Human-readable comment associated with the key.
            String,
        )>,
    ),
    /// Return an algorithm-tagged SSH signature for the requested message.
    Signature(Signature),
    /// Return a named extension response or report extension-specific failure.
    Extension(
        // None encodes extension failure (28); Some carries a response (29).
        Option<(
            // Name identifying the extension that produced the response.
            String,
            // Raw extension response bytes, zeroized on drop.
            Zeroizing<Vec<u8>>,
        )>,
    ),
}

/// Decode request bodies and discard the remaining bytes of unsupported messages.
impl Decode for Request {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self, Error> {
        match u8::decode(reader)? {
            REQUEST_IDENTITIES => Ok(Self::Identities),
            REQUEST_SIGNATURE => Ok(Self::Signature {
                key: Vec::decode(reader)?,
                data: Vec::decode(reader)?,
                flags: u32::decode(reader)?,
            }),
            REQUEST_EXTENSION => {
                let name = String::decode(reader)?;
                let mut details = Zeroizing::new(vec![0; reader.remaining_len()]);
                reader.read(&mut details)?;
                Ok(Self::Extension { name, details })
            }
            _ => {
                reader.drain(reader.remaining_len())?;
                Ok(Self::Unsupported)
            }
        }
    }
}

/// Encode supported requests, preserving extension payloads as raw packet tails.
impl Encode for Request {
    fn encoded_len(&self) -> Result<usize, Error> {
        match self {
            Self::Identities => Ok(1),
            Self::Signature { key, data, .. } => [1, key.encoded_len()?, data.encoded_len()?, 4].checked_sum(),
            Self::Extension { name, details } => [1, name.encoded_len()?, details.len()].checked_sum(),
            Self::Unsupported => Err(Error::Length),
        }
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        match self {
            Self::Identities => REQUEST_IDENTITIES.encode(writer),
            Self::Signature { key, data, flags } => {
                REQUEST_SIGNATURE.encode(writer)?;
                key.encode(writer)?;
                data.encode(writer)?;
                flags.encode(writer)
            }
            Self::Extension { name, details } => {
                REQUEST_EXTENSION.encode(writer)?;
                name.encode(writer)?;
                writer.write(details)
            }
            Self::Unsupported => Err(Error::Length),
        }
    }
}

/// Decode responses, checking identity counts and nested key and signature boundaries.
impl Decode for Response {
    type Error = ssh_key::Error;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        match u8::decode(reader)? {
            RESPONSE_FAILURE => Ok(Self::Failure),
            RESPONSE_SUCCESS => Ok(Self::Success),
            RESPONSE_IDENTITIES => {
                let count = u32::decode(reader)? as usize;
                if count > reader.remaining_len() / 8 {
                    return Err(Error::Length.into());
                }
                let mut identities = Vec::new();
                for _ in 0..count {
                    identities.push((
                        reader.read_prefixed(|reader| {
                            let key = KeyData::decode(reader)?;
                            reader.ensure_finished()?;
                            Ok::<_, ssh_key::Error>(key)
                        })?,
                        String::decode(reader)?,
                    ));
                }
                Ok(Self::Identities(identities))
            }
            RESPONSE_SIGNATURE => reader
                .read_prefixed(|reader| {
                    let signature = Signature::decode(reader)?;
                    reader.ensure_finished()?;
                    Ok::<_, ssh_key::Error>(signature)
                })
                .map(Self::Signature),
            RESPONSE_EXTENSION_FAILURE => Ok(Self::Extension(None)),
            RESPONSE_EXTENSION_SUCCESS => {
                let name = String::decode(reader)?;
                let mut details = Zeroizing::new(vec![0; reader.remaining_len()]);
                reader.read(&mut details)?;
                Ok(Self::Extension(Some((name, details))))
            }
            _ => Err(Error::Length.into()),
        }
    }
}

/// Encode responses with SSH string framing for public keys and signatures.
impl Encode for Response {
    fn encoded_len(&self) -> Result<usize, Error> {
        match self {
            Self::Identities(identities) => identities.iter().try_fold(5usize, |length, (key, comment)| {
                [length, key.encoded_len_prefixed()?, comment.encoded_len()?].checked_sum()
            }),
            Self::Signature(signature) => [1, signature.encoded_len_prefixed()?].checked_sum(),
            Self::Extension(Some((name, details))) => [1, name.encoded_len()?, details.len()].checked_sum(),
            Self::Failure | Self::Success | Self::Extension(None) => Ok(1),
        }
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        match self {
            Self::Failure => RESPONSE_FAILURE.encode(writer),
            Self::Success => RESPONSE_SUCCESS.encode(writer),
            Self::Identities(identities) => {
                RESPONSE_IDENTITIES.encode(writer)?;
                u32::try_from(identities.len())
                    .map_err(|_| Error::Length)?
                    .encode(writer)?;
                for (key, comment) in identities {
                    key.encode_prefixed(writer)?;
                    comment.encode(writer)?;
                }
                Ok(())
            }
            Self::Signature(signature) => {
                RESPONSE_SIGNATURE.encode(writer)?;
                signature.encode_prefixed(writer)
            }
            Self::Extension(None) => RESPONSE_EXTENSION_FAILURE.encode(writer),
            Self::Extension(Some((name, details))) => {
                RESPONSE_EXTENSION_SUCCESS.encode(writer)?;
                name.encode(writer)?;
                writer.write(details)
            }
        }
    }
}
