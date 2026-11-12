//! Bounded SSH-agent framing for requests, responses, and local control extensions.
//!
//! Frames use a four-byte network-order payload length. Temporary frame buffers are
//! zeroized on drop because unlock extensions contain the user's master password.

use anyhow::{Context, Result, bail};
use ssh_agent_lib::proto::{Request, Response};
use ssh_encoding::{Decode, Encode, Reader};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

/// Maximum accepted payload size, excluding the four-byte frame header.
const MAX_PACKET: usize = 1024 * 1024;

/// Owns a decoded request until it is dispatched or discarded.
///
/// An unlock payload still held here is wiped on drop, including queued requests
/// abandoned when a connection ends. Ownership moves to the session on dispatch.
pub struct Incoming(pub Option<Request>);

impl Decode for Incoming {
    type Error = <Request as Decode>::Error;

    /// Wraps the ordinary protocol decoder with request-lifetime cleanup.
    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        Request::decode(reader).map(|request| Self(Some(request)))
    }
}

impl Drop for Incoming {
    /// Wipes an undispatched unlock payload without changing other extension handling.
    fn drop(&mut self) {
        if let Some(Request::Extension(extension)) = self.0.take()
            && extension.name == keyring_protocol::control::UNLOCK
        {
            extension.details.into_bytes().zeroize();
        }
    }
}

/// Reads one complete bounded frame, rejecting empty packets and unused trailing bytes.
async fn read<Packet: Decode>(reader: &mut (impl AsyncRead + Unpin)) -> Result<Packet> {
    let length = reader.read_u32().await.context("agent disconnected")? as usize;
    if length == 0 || length > MAX_PACKET {
        bail!("invalid SSH agent packet length");
    }
    // read_exact accepts transport fragmentation without exposing a partially decoded request.
    let mut bytes = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut bytes).await?;
    let mut input = bytes.as_slice();
    let packet = Packet::decode(&mut input).map_err(|_| anyhow::anyhow!("invalid SSH agent packet"))?;
    if !input.is_empty() {
        bail!("trailing bytes in SSH agent packet");
    }
    Ok(packet)
}

/// Decodes a request with cleanup for unlock bytes that have not been dispatched.
pub async fn read_request(reader: &mut (impl AsyncRead + Unpin)) -> Result<Incoming> {
    read(reader).await
}

/// Decodes a single response using the same length and trailing-data checks as requests.
pub async fn read_response(reader: &mut (impl AsyncRead + Unpin)) -> Result<Response> {
    read(reader).await
}

/// Encodes and flushes one bounded frame through a temporary zeroizing buffer.
///
/// This framing layer does not encrypt traffic or control copies held by the OS.
pub async fn write<Packet: Encode>(writer: &mut (impl AsyncWrite + Unpin), packet: &Packet) -> Result<()> {
    let length = packet
        .encoded_len()
        .map_err(|_| anyhow::anyhow!("cannot encode agent packet"))?;
    if length > MAX_PACKET {
        bail!("SSH agent packet too large");
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(length + 4));
    (length as u32)
        .encode(&mut *bytes)
        .map_err(|_| anyhow::anyhow!("cannot encode packet length"))?;
    packet
        .encode(&mut *bytes)
        .map_err(|_| anyhow::anyhow!("cannot encode agent packet"))?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Framing checks against fragmented input and lengths rejected before allocation.

    use super::*;
    use tokio::io::duplex;

    /// Exercises a byte-at-a-time request and an oversized frame header with no body.
    #[tokio::test]
    async fn accepts_fragmented_frames_and_rejects_oversized_frames() -> Result<()> {
        let (mut reader, mut writer) = duplex(64);
        let sender = tokio::spawn(async move {
            // One payload byte is SSH_AGENTC_REQUEST_IDENTITIES; preceding bytes are its length.
            for byte in [0, 0, 0, 1, 11] {
                writer.write_all(&[byte]).await?;
                tokio::task::yield_now().await;
            }
            Ok::<_, std::io::Error>(())
        });
        assert!(matches!(
            read_request(&mut reader).await?.0,
            Some(Request::RequestIdentities)
        ));
        sender.await??;
        let (mut reader, mut writer) = duplex(64);
        writer.write_u32((MAX_PACKET + 1) as u32).await?;
        assert!(read_request(&mut reader).await.is_err());
        Ok(())
    }
}
