//! Length-prefixed JSON framing for the four supervisor proxies.
//!
//! Thin adapter over [`mvm_core::framing`] (plan 121 B4): the on-wire
//! format (4-byte big-endian length + JSON body, cap-before-alloc) and
//! its tests live in `mvm-core`; this module only maps the shared
//! [`FrameError`] onto the path-carrying [`ProxyError`] the proxy call
//! sites surface, and keeps the UDS [`connect`] helper.

use mvm_core::framing::{self, FrameError};
use serde::ser::Error as _;
use tokio::net::UnixStream;

use super::ProxyError;

pub const FRAME_LEN_BYTES: usize = framing::FRAME_LEN_BYTES;
pub const DEFAULT_MAX_FRAME_BYTES: usize = framing::DEFAULT_MAX_FRAME_BYTES;

/// Map a framing error onto the path-carrying `ProxyError`.
fn with_path(err: FrameError, path: &std::path::Path) -> ProxyError {
    match err {
        FrameError::Io(source) => ProxyError::Io {
            path: path.to_path_buf(),
            source,
        },
        FrameError::Decode(source) => ProxyError::Decode {
            path: path.to_path_buf(),
            source,
        },
        FrameError::TooLarge { size, cap } => ProxyError::ResponseTooLarge {
            path: path.to_path_buf(),
            size,
            cap,
        },
        FrameError::Encode(source) => ProxyError::Encode { source },
        FrameError::LengthOverflow => ProxyError::Encode {
            source: serde_json::Error::custom("request body too large for u32 length prefix"),
        },
    }
}

/// Write a length-prefixed JSON frame to the UDS stream.
pub async fn write_frame<T: serde::Serialize>(
    stream: &mut UnixStream,
    path: &std::path::Path,
    value: &T,
) -> Result<(), ProxyError> {
    framing::write_json_frame(stream, value)
        .await
        .map_err(|e| with_path(e, path))
}

/// Read a length-prefixed JSON frame from the UDS stream. Enforces the
/// max-frame-bytes cap before allocating the body buffer.
pub async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    path: &std::path::Path,
    max_frame_bytes: usize,
) -> Result<T, ProxyError> {
    framing::read_json_frame(stream, max_frame_bytes)
        .await
        .map_err(|e| with_path(e, path))
}

/// Connect to the UDS path. Returns a typed `Connect` error if the
/// subprocess hasn't started yet or has died.
pub async fn connect(path: &std::path::Path) -> Result<UnixStream, ProxyError> {
    UnixStream::connect(path)
        .await
        .map_err(|source| ProxyError::Connect {
            path: path.to_path_buf(),
            source,
        })
}
