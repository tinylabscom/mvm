//! Bounded length-prefixed JSON framing for host control channels.
//!
//! Available only with `hostd-transport`, keeping the default core dependency
//! closure free of an async runtime.
//!
//! Wire format: a 4-byte big-endian length prefix followed by the body.
//! The cap is enforced on read **before** allocating the body buffer:
//! a corrupt or hostile peer setting `length_prefix = u32::MAX` must be
//! rejected without a multi-gigabyte allocation.
//!
//! Generic over the async stream (`S: AsyncRead + AsyncWrite`) so the
//! same framing serves any `UnixStream` / vsock / pipe. Today every
//! caller frames JSON, so the entry points are `read_json_frame` /
//! `write_json_frame`.
//!
//! These helpers provide no authentication. Peer checks, timeouts and cap
//! selection belong to callers. Authenticated host-to-guest session framing
//! is separate and is not implemented by this transport.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Width of the big-endian length prefix.
pub const FRAME_LEN_BYTES: usize = 4;

/// Default max frame size for the same-uid UDS control channels.
/// Builder and host↔guest channels carry their own (larger) caps.
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

// Synchronous libkrun control framing stays in `libkrun_sys::framing` beside
// its wire types, without coupling synchronous callers to an async runtime.

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    const WIRE: &[u8] = b"\0\0\0\x15{\"kind\":\"ping\",\"n\":7}";

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Msg {
        kind: String,
        n: u32,
    }

    fn message() -> Msg {
        Msg {
            kind: "ping".into(),
            n: 7,
        }
    }

    #[derive(Default)]
    struct ShortWriter {
        bytes: Vec<u8>,
        fail_after: Option<usize>,
        flushes: usize,
        errors: usize,
    }

    impl AsyncWrite for ShortWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let remaining = self
                .fail_after
                .map_or(usize::MAX, |limit| limit.saturating_sub(self.bytes.len()));
            if remaining == 0 && !bytes.is_empty() {
                self.errors += 1;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "fixture write failure",
                )));
            }
            let len = bytes.len().min(2).min(remaining);
            self.bytes.extend_from_slice(&bytes[..len]);
            Poll::Ready(Ok(len))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct ShortReader<'a>(&'a [u8]);

    impl AsyncRead for ShortReader<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let len = self.0.len().min(buf.remaining()).min(1);
            let (bytes, rest) = self.0.split_at(len);
            buf.put_slice(bytes);
            self.0 = rest;
            Poll::Ready(Ok(()))
        }
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

    #[tokio::test]
    async fn short_writes_preserve_wire_bytes_without_flushing() {
        let mut writer = ShortWriter::default();
        write_json_frame(&mut writer, &message()).await.unwrap();
        assert_eq!(writer.bytes, WIRE);
        assert_eq!(writer.flushes, 0);
    }

    #[tokio::test]
    async fn short_reads_complete_the_prefix_and_body() {
        let mut reader = ShortReader(WIRE);
        let got: Msg = read_json_frame(&mut reader, DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap();
        assert_eq!(got, message());
        assert!(reader.0.is_empty());
    }

    #[tokio::test]
    async fn caller_cap_accepts_equality_and_rejects_before_reading_body() {
        let body_len = WIRE.len() - FRAME_LEN_BYTES;
        let mut reader = std::io::Cursor::new(WIRE);
        let got: Msg = read_json_frame(&mut reader, body_len).await.unwrap();
        assert_eq!(got, message());

        let mut reader = std::io::Cursor::new(WIRE);
        let err = read_json_frame::<_, Msg>(&mut reader, body_len - 1)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FrameError::TooLarge { size, cap } if size == body_len && cap == body_len - 1
        ));
        assert_eq!(reader.position(), FRAME_LEN_BYTES as u64);
    }

    #[tokio::test]
    async fn truncated_prefix_is_an_unexpected_eof() {
        for len in 0..FRAME_LEN_BYTES {
            let mut reader = std::io::Cursor::new(&WIRE[..len]);
            let err = read_json_frame::<_, Msg>(&mut reader, DEFAULT_MAX_FRAME_BYTES)
                .await
                .unwrap_err();
            assert!(
                matches!(err, FrameError::Io(ref source) if source.kind() == io::ErrorKind::UnexpectedEof),
                "prefix length {len}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn zero_length_body_reaches_json_decoding() {
        let mut reader = std::io::Cursor::new([0; FRAME_LEN_BYTES]);
        let err = read_json_frame::<_, Msg>(&mut reader, 0).await.unwrap_err();
        assert!(matches!(err, FrameError::Decode(_)));
    }

    #[tokio::test]
    async fn serialization_failure_writes_nothing() {
        struct Unencodable;

        impl Serialize for Unencodable {
            fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("fixture encode failure"))
            }
        }

        let mut writer = ShortWriter::default();
        let err = write_json_frame(&mut writer, &Unencodable)
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::Encode(_)));
        assert!(writer.bytes.is_empty());
        assert_eq!(writer.flushes, 0);
    }

    #[tokio::test]
    async fn write_failure_preserves_partial_progress_without_retry_or_flush() {
        let mut writer = ShortWriter {
            fail_after: Some(6),
            ..ShortWriter::default()
        };
        let err = write_json_frame(&mut writer, &message()).await.unwrap_err();
        assert!(matches!(
            err,
            FrameError::Io(ref source) if source.kind() == io::ErrorKind::BrokenPipe
        ));
        assert_eq!(writer.bytes, WIRE[..6]);
        assert_eq!(writer.flushes, 0);
        assert_eq!(
            writer.errors, 1,
            "terminal write errors must not be retried"
        );
    }

    #[tokio::test]
    async fn writer_does_not_apply_the_default_receive_cap() {
        let value = "x".repeat(DEFAULT_MAX_FRAME_BYTES);
        let mut bytes = Vec::new();
        write_json_frame(&mut bytes, &value).await.unwrap();
        let body_len = u32::from_be_bytes(bytes[..FRAME_LEN_BYTES].try_into().unwrap()) as usize;
        assert_eq!(body_len, DEFAULT_MAX_FRAME_BYTES + 2);
        assert_eq!(bytes.len(), FRAME_LEN_BYTES + body_len);
    }
}
