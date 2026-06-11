//! Sync length-prefixed JSON framing for the same-uid supervisor control channels.
//!
//! Wire format: a 4-byte big-endian length prefix followed by the JSON body. The cap is
//! enforced on read **before** allocating the body buffer (a hostile `length_prefix =
//! u32::MAX` must not OOM the reader).
//!
//! Lives here — next to the `SupervisorBaseConfig`/`SupervisorAttachConfig` wire types it
//! frames — because both ends need it without a dependency cycle: the **writer** is
//! `mvm-backend`'s libkrun `claim_standby` and the **reader** is the
//! `mvm-libkrun-supervisor` bin's prelaunch attach path. `mvm-backend`
//! cannot depend on `mvm-hostd` (that crate depends on `mvm-backend`), so this can't live
//! in `mvm_hostd::framing` (which keeps the *async* tokio variants for its own channels).
//!
//! This is the no-auth transport — correct for the same-uid control UDS. The trust
//! boundary is the supervisor's independent plan re-verify on the attach, not this
//! frame.

use std::io::{Read, Write};

/// Width of the big-endian length prefix.
pub const FRAME_LEN_BYTES: usize = 4;

/// Errors from the sync framing layer. Hand-rolled (no `thiserror`) to keep this leaf
/// crate's dependency surface minimal.
#[derive(Debug)]
pub enum FrameError {
    /// Underlying stream read/write failed.
    Io(std::io::Error),
    /// Body failed to (de)serialize.
    Json(serde_json::Error),
    /// The length prefix exceeded the caller's cap — rejected before allocating.
    TooLarge { size: usize, cap: usize },
    /// Body length did not fit the u32 length prefix.
    LengthOverflow,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "frame I/O failed: {e}"),
            FrameError::Json(e) => write!(f, "frame body JSON failed: {e}"),
            FrameError::TooLarge { size, cap } => {
                write!(f, "frame body {size} bytes exceeds cap {cap}")
            }
            FrameError::LengthOverflow => {
                write!(f, "frame body too large for the u32 length prefix")
            }
        }
    }
}

impl std::error::Error for FrameError {}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        FrameError::Io(e)
    }
}

/// Write a length-prefixed JSON frame: 4-byte BE length + JSON body.
pub fn write_json_frame_sync<W, T>(stream: &mut W, value: &T) -> Result<(), FrameError>
where
    W: Write + ?Sized,
    T: serde::Serialize,
{
    let body = serde_json::to_vec(value).map_err(FrameError::Json)?;
    let len: u32 = body
        .len()
        .try_into()
        .map_err(|_| FrameError::LengthOverflow)?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&body)?;
    Ok(())
}

/// Read a length-prefixed JSON frame, enforcing `max_frame_bytes` on the length prefix
/// **before** allocating the body buffer.
pub fn read_json_frame_sync<R, T>(stream: &mut R, max_frame_bytes: usize) -> Result<T, FrameError>
where
    R: Read + ?Sized,
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
    serde_json::from_slice(&body).map_err(FrameError::Json)
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

    #[test]
    fn round_trips_a_json_frame() {
        let msg = Msg {
            kind: "ping".into(),
            n: 7,
        };
        let mut buf = Vec::new();
        write_json_frame_sync(&mut buf, &msg).unwrap();
        let body_len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(body_len, buf.len() - FRAME_LEN_BYTES);
        let mut cursor = std::io::Cursor::new(buf);
        let got: Msg = read_json_frame_sync(&mut cursor, 65_536).unwrap();
        assert_eq!(got, msg);
    }

    #[test]
    fn rejects_oversize_length_prefix_before_alloc() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut cursor = std::io::Cursor::new(framed);
        let err = read_json_frame_sync::<_, Msg>(&mut cursor, 65_536).unwrap_err();
        assert!(
            matches!(err, FrameError::TooLarge { size, cap: 65_536 } if size == u32::MAX as usize)
        );
    }

    #[test]
    fn truncated_body_is_an_io_error() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&16u32.to_be_bytes());
        framed.extend_from_slice(b"abcd");
        let mut cursor = std::io::Cursor::new(framed);
        let err = read_json_frame_sync::<_, Msg>(&mut cursor, 65_536).unwrap_err();
        assert!(matches!(err, FrameError::Io(_)));
    }
}
