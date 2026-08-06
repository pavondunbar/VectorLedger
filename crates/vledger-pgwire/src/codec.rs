//! Low-level frame codec: read/write length-prefixed postgres messages.
//!
//! The PostgreSQL wire protocol v3 uses two message formats:
//! - **Startup** (first packet): `int32 len | payload`  (no type byte)
//! - **Regular**: `byte type | int32 len | payload`
//!
//! `len` in both cases counts itself (so payload_len = len - 4).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum allowed size for a startup packet payload (64 KiB).
/// Prevents OOM from a client claiming an arbitrarily large startup packet.
const MAX_STARTUP_PAYLOAD: usize = 65_536;

/// Maximum allowed size for a regular message payload (16 MiB).
/// Matches PostgreSQL's own server-side limit for protocol messages.
const MAX_MESSAGE_PAYLOAD: usize = 16 * 1024 * 1024;

/// Read the startup packet (no type byte, length-prefixed).
///
/// Returns payload bytes (NOT including the 4-byte length field).
/// Rejects any packet whose declared payload exceeds `MAX_STARTUP_PAYLOAD`.
pub async fn read_startup<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let total_len = u32::from_be_bytes(len_buf) as usize;
    if total_len < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "startup packet length < 4",
        ));
    }
    let payload_len = total_len - 4;
    // Fix #8: reject oversized startup packets before allocating.
    if payload_len > MAX_STARTUP_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "startup packet payload {payload_len} bytes exceeds limit {MAX_STARTUP_PAYLOAD}"
            ),
        ));
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Ok(payload)
}

/// Read a regular frontend message `(type_byte, payload)`.
///
/// Rejects any message whose declared payload exceeds `MAX_MESSAGE_PAYLOAD`.
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    reader.read_exact(&mut hdr).await?;
    let msg_type = hdr[0];
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    if len < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message length {len} < 4"),
        ));
    }
    let payload_len = len - 4;
    // Fix #8: reject oversized messages before allocating.
    if payload_len > MAX_MESSAGE_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "message payload {payload_len} bytes exceeds limit {MAX_MESSAGE_PAYLOAD}"
            ),
        ));
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Ok((msg_type, payload))
}

/// Write raw bytes to the stream and flush.
pub async fn write_all<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> std::io::Result<()> {
    writer.write_all(data).await?;
    writer.flush().await
}

/// Write a sequence of messages and flush once.
pub async fn write_messages<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msgs: &[Vec<u8>],
) -> std::io::Result<()> {
    for msg in msgs {
        writer.write_all(msg).await?;
    }
    writer.flush().await
}
