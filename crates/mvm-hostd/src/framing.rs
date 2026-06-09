//! mvm_hostd::framing — length-prefixed message framing.
//!
//! Was `mvm_core::framing` (plan 121 B4); relocated here (plan 126 B5)
//! because its only callers are mvm-hostd's same-uid UDS channels, and
//! the move drops `tokio` from `mvm-core`'s default dependency closure.
//!
//! Wire format: a 4-byte big-endian length prefix followed by the body.
//! The cap is enforced on read **before** allocating the body buffer —
//! the Plan 104 §"Capability gating" gate-1 invariant: a corrupt or
//! hostile peer setting `length_prefix = u32::MAX` must be rejected
//! without a multi-gigabyte allocation.
//!
//! Generic over the async stream (`S: AsyncRead + AsyncWrite`) so the
//! same framing serves any `UnixStream` / vsock / pipe. Today every
//! caller frames JSON, so the entry points are `read_json_frame` /
//! `write_json_frame`.
//!
//! ## Auth + encryption (ADR-066 §5) — designed-for, not shipped
//!
//! This is the no-auth length-prefixed transport: correct for the
//! same-uid UDS channels (the supervisor proxies + their broker /
//! host-signer / audit-signer servers). It is **not** the host↔guest
//! trust-boundary frame — that stays in `mvm_guest::vsock`'s
//! Ed25519-signed `AuthenticatedFrame` (session-id + sequence replay
//! protection, separately fuzzed) until a pluggable [`AuthStage`] +
//! optional encryption stage retrofit lands behind a real cargo-fuzz +
//! live-boot validation pass (plan 121 B4 Option B). The seam below is
//! the shape that retrofit slots into; `NoAuth` is the only impl today.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Width of the big-endian length prefix.
pub const FRAME_LEN_BYTES: usize = 4;

/// Default max frame size for the same-uid UDS control channels (Plan
/// 104). Builder and host↔guest channels carry their own (larger) caps.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 65_536;

/// Errors from the framing layer. Callers map this onto their own error
/// type (e.g. the proxies' `ProxyError`, the servers' `anyhow`).
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Underlying stream read/write failed.
    #[error("frame I/O failed")]
    Io(#[from] std::io::Error),
    /// Body failed to serialize.
    #[error("frame body encode failed")]
    Encode(#[source] serde_json::Error),
    /// Body failed to deserialize.
    #[error("frame body decode failed")]
    Decode(#[source] serde_json::Error),
    /// The length prefix exceeded the caller's cap — rejected before
    /// allocating the body buffer.
    #[error("frame body {size} bytes exceeds cap {cap}")]
    TooLarge {
        /// The length the peer claimed.
        size: usize,
        /// The cap the caller enforces.
        cap: usize,
    },
    /// Body length did not fit the u32 length prefix.
    #[error("frame body too large for the u32 length prefix")]
    LengthOverflow,
}

/// Write a length-prefixed JSON frame: 4-byte BE length + JSON body.
pub async fn write_json_frame<S, T>(stream: &mut S, value: &T) -> Result<(), FrameError>
where
    S: AsyncWrite + Unpin + ?Sized,
    T: serde::Serialize,
{
    let body = serde_json::to_vec(value).map_err(FrameError::Encode)?;
    let len: u32 = body
        .len()
        .try_into()
        .map_err(|_| FrameError::LengthOverflow)?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&body).await?;
    Ok(())
}

/// Read a length-prefixed JSON frame, enforcing `max_frame_bytes` on the
/// length prefix **before** allocating the body buffer.
pub async fn read_json_frame<S, T>(stream: &mut S, max_frame_bytes: usize) -> Result<T, FrameError>
where
    S: AsyncRead + Unpin + ?Sized,
    T: serde::de::DeserializeOwned,
{
    let mut len_buf = [0u8; FRAME_LEN_BYTES];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_frame_bytes {
        return Err(FrameError::TooLarge {
            size: len,
            cap: max_frame_bytes,
        });
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(FrameError::Decode)
}

/// Synchronous sibling of [`write_json_frame`] for the same-uid UDS control
/// channels that run *without* a tokio runtime. The libkrun supervisor's
/// prelaunch accept path (Plan 118 WS-1 1a) runs before `start_enter`, so it
/// can't park a runtime. Same wire format — 4-byte BE length + JSON body.
pub fn write_json_frame_sync<W, T>(stream: &mut W, value: &T) -> Result<(), FrameError>
where
    W: std::io::Write + ?Sized,
    T: serde::Serialize,
{
    let body = serde_json::to_vec(value).map_err(FrameError::Encode)?;
    let len: u32 = body
        .len()
        .try_into()
        .map_err(|_| FrameError::LengthOverflow)?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&body)?;
    Ok(())
}

/// Synchronous sibling of [`read_json_frame`]. Enforces `max_frame_bytes` on
/// the length prefix **before** allocating the body — same gate-1 invariant as
/// the async path (a hostile `length_prefix = u32::MAX` must not OOM the reader).
pub fn read_json_frame_sync<R, T>(stream: &mut R, max_frame_bytes: usize) -> Result<T, FrameError>
where
    R: std::io::Read + ?Sized,
    T: serde::de::DeserializeOwned,
{
    let mut len_buf = [0u8; FRAME_LEN_BYTES];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_frame_bytes {
        return Err(FrameError::TooLarge {
            size: len,
            cap: max_frame_bytes,
        });
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(FrameError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Msg {
        kind: String,
        n: u32,
    }

    #[tokio::test]
    async fn round_trips_a_json_frame() {
        let msg = Msg {
            kind: "ping".into(),
            n: 7,
        };
        let mut buf = Vec::new();
        write_json_frame(&mut buf, &msg).await.unwrap();
        // 4-byte BE length prefix + body.
        let body_len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(body_len, buf.len() - FRAME_LEN_BYTES);

        let mut cursor = std::io::Cursor::new(buf);
        let got: Msg = read_json_frame(&mut cursor, DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap();
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn rejects_oversize_length_prefix_before_alloc() {
        // A hostile length prefix of u32::MAX with no body must be
        // rejected on the cap check, not OOM the reader.
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut cursor = std::io::Cursor::new(framed);
        let err = read_json_frame::<_, Msg>(&mut cursor, DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FrameError::TooLarge {
                size,
                cap: DEFAULT_MAX_FRAME_BYTES
            } if size == u32::MAX as usize
        ));
    }

    #[tokio::test]
    async fn truncated_body_is_an_io_error_not_a_panic() {
        // Length prefix says 16 bytes, but only 4 follow.
        let mut framed = Vec::new();
        framed.extend_from_slice(&16u32.to_be_bytes());
        framed.extend_from_slice(b"abcd");
        let mut cursor = std::io::Cursor::new(framed);
        let err = read_json_frame::<_, Msg>(&mut cursor, DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::Io(_)));
    }

    #[tokio::test]
    async fn malformed_body_is_a_decode_error() {
        let mut framed = Vec::new();
        let junk = b"not json";
        framed.extend_from_slice(&(junk.len() as u32).to_be_bytes());
        framed.extend_from_slice(junk);
        let mut cursor = std::io::Cursor::new(framed);
        let err = read_json_frame::<_, Msg>(&mut cursor, DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::Decode(_)));
    }

    #[test]
    fn sync_round_trips_a_json_frame() {
        let msg = Msg {
            kind: "ping".into(),
            n: 7,
        };
        let mut buf = Vec::new();
        write_json_frame_sync(&mut buf, &msg).unwrap();
        let body_len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(body_len, buf.len() - FRAME_LEN_BYTES);
        let mut cursor = std::io::Cursor::new(buf);
        let got: Msg = read_json_frame_sync(&mut cursor, DEFAULT_MAX_FRAME_BYTES).unwrap();
        assert_eq!(got, msg);
    }

    #[test]
    fn sync_rejects_oversize_length_prefix_before_alloc() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut cursor = std::io::Cursor::new(framed);
        let err =
            read_json_frame_sync::<_, Msg>(&mut cursor, DEFAULT_MAX_FRAME_BYTES).unwrap_err();
        assert!(matches!(
            err,
            FrameError::TooLarge {
                size,
                cap: DEFAULT_MAX_FRAME_BYTES
            } if size == u32::MAX as usize
        ));
    }

    #[test]
    fn sync_truncated_body_is_an_io_error() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&16u32.to_be_bytes());
        framed.extend_from_slice(b"abcd");
        let mut cursor = std::io::Cursor::new(framed);
        let err =
            read_json_frame_sync::<_, Msg>(&mut cursor, DEFAULT_MAX_FRAME_BYTES).unwrap_err();
        assert!(matches!(err, FrameError::Io(_)));
    }
}
