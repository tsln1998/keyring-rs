//! The supported SSH-agent messages, without transport or private-key operations.
//!
//! Extension payloads clear themselves when dispatched, cancelled, or discarded.

use signature::Verifier;
use ssh_encoding::{CheckedSum, Decode, Encode, Error, Reader, Writer};
use ssh_key::{Signature, public::KeyData};
use zeroize::Zeroizing;

pub const RSA_SHA2_256: u32 = 2;
pub const RSA_SHA2_512: u32 = 4;
pub const SESSION_BIND: &str = "session-bind@openssh.com";

pub struct Identity {
    pub key: KeyData,
    pub comment: String,
}

pub struct SignRequest {
    pub key: Vec<u8>,
    pub data: Vec<u8>,
    pub flags: u32,
}

pub struct Extension {
    pub name: String,
    pub details: Zeroizing<Vec<u8>>,
}

pub enum Request {
    RequestIdentities,
    SignRequest(SignRequest),
    Extension(Extension),
    Unsupported,
}

pub enum Response {
    Failure,
    Success,
    IdentitiesAnswer(Vec<Identity>),
    SignResponse(Signature),
    ExtensionFailure,
    ExtensionResponse(Extension),
}

impl Decode for Extension {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self, Error> {
        let name = String::decode(reader)?;
        let mut details = Zeroizing::new(vec![0; reader.remaining_len()]);
        reader.read(&mut details)?;
        Ok(Self { name, details })
    }
}

impl Encode for Extension {
    fn encoded_len(&self) -> Result<usize, Error> {
        [self.name.encoded_len()?, self.details.len()].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        self.name.encode(writer)?;
        writer.write(&self.details)
    }
}

impl Decode for Request {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self, Error> {
        match u8::decode(reader)? {
            11 => Ok(Self::RequestIdentities),
            13 => Ok(Self::SignRequest(SignRequest {
                key: Vec::decode(reader)?,
                data: Vec::decode(reader)?,
                flags: u32::decode(reader)?,
            })),
            27 => Extension::decode(reader).map(Self::Extension),
            _ => {
                reader.drain(reader.remaining_len())?;
                Ok(Self::Unsupported)
            }
        }
    }
}

impl Encode for Request {
    fn encoded_len(&self) -> Result<usize, Error> {
        match self {
            Self::RequestIdentities => Ok(1),
            Self::SignRequest(request) => [1, request.key.encoded_len()?, request.data.encoded_len()?, 4].checked_sum(),
            Self::Extension(extension) => [1, extension.encoded_len()?].checked_sum(),
            Self::Unsupported => Err(Error::Length),
        }
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        match self {
            Self::RequestIdentities => 11u8.encode(writer),
            Self::SignRequest(request) => {
                13u8.encode(writer)?;
                request.key.encode(writer)?;
                request.data.encode(writer)?;
                request.flags.encode(writer)
            }
            Self::Extension(extension) => {
                27u8.encode(writer)?;
                extension.encode(writer)
            }
            Self::Unsupported => Err(Error::Length),
        }
    }
}

impl Decode for Response {
    type Error = ssh_key::Error;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        match u8::decode(reader)? {
            5 => Ok(Self::Failure),
            6 => Ok(Self::Success),
            12 => {
                let count = u32::decode(reader)? as usize;
                if count > reader.remaining_len() / 8 {
                    return Err(Error::Length.into());
                }
                let mut identities = Vec::new();
                for _ in 0..count {
                    identities.push(Identity {
                        key: reader.read_prefixed(|reader| {
                            let key = KeyData::decode(reader)?;
                            reader.ensure_finished()?;
                            Ok::<_, ssh_key::Error>(key)
                        })?,
                        comment: String::decode(reader)?,
                    });
                }
                Ok(Self::IdentitiesAnswer(identities))
            }
            14 => reader
                .read_prefixed(|reader| {
                    let signature = Signature::decode(reader)?;
                    reader.ensure_finished()?;
                    Ok::<_, ssh_key::Error>(signature)
                })
                .map(Self::SignResponse),
            28 => Ok(Self::ExtensionFailure),
            29 => Ok(Self::ExtensionResponse(Extension::decode(reader)?)),
            _ => Err(Error::Length.into()),
        }
    }
}

impl Encode for Response {
    fn encoded_len(&self) -> Result<usize, Error> {
        match self {
            Self::IdentitiesAnswer(identities) => identities.iter().try_fold(5usize, |length, identity| {
                [
                    length,
                    identity.key.encoded_len_prefixed()?,
                    identity.comment.encoded_len()?,
                ]
                .checked_sum()
            }),
            Self::SignResponse(signature) => [1, signature.encoded_len_prefixed()?].checked_sum(),
            Self::ExtensionResponse(extension) => [1, extension.encoded_len()?].checked_sum(),
            Self::Failure | Self::Success | Self::ExtensionFailure => Ok(1),
        }
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Error> {
        match self {
            Self::Failure => 5u8.encode(writer),
            Self::Success => 6u8.encode(writer),
            Self::IdentitiesAnswer(identities) => {
                12u8.encode(writer)?;
                u32::try_from(identities.len())
                    .map_err(|_| Error::Length)?
                    .encode(writer)?;
                for identity in identities {
                    identity.key.encode_prefixed(writer)?;
                    identity.comment.encode(writer)?;
                }
                Ok(())
            }
            Self::SignResponse(signature) => {
                14u8.encode(writer)?;
                signature.encode_prefixed(writer)
            }
            Self::ExtensionFailure => 28u8.encode(writer),
            Self::ExtensionResponse(extension) => {
                29u8.encode(writer)?;
                extension.encode(writer)
            }
        }
    }
}

pub(crate) fn session_bind(details: &[u8]) -> anyhow::Result<(Vec<u8>, bool)> {
    let mut reader = details;
    let host_key = reader.read_prefixed(|reader| {
        let key = KeyData::decode(reader)?;
        reader.ensure_finished()?;
        Ok::<_, ssh_key::Error>(key)
    })?;
    let session_id = Vec::<u8>::decode(&mut reader)?;
    let signature = reader.read_prefixed(|reader| {
        let signature = Signature::decode(reader)?;
        reader.ensure_finished()?;
        Ok::<_, ssh_key::Error>(signature)
    })?;
    let forwarding = bool::decode(&mut reader)?;
    reader.ensure_finished()?;
    host_key.verify(&session_id, &signature)?;
    Ok((session_id, forwarding))
}
