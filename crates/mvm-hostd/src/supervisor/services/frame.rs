//! Shared length-prefixed JSON framing for the four supervisor proxies.
//!
//! All four broker subprocesses speak the same on-wire framing: 4-byte
//! big-endian length prefix + JSON body. The cap is enforced on read
//! *before* allocating the body buffer (matching the subprocess
//! servers' Plan 104 §"Capability gating" gate 1).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::ProxyError;

pub const FRAME_LEN_BYTES: usize = 4;
pub const DEFAULT_MAX_FRAME_BYTES: usize = 65_536;

/// Write a length-prefixed JSON frame to the UDS stream.
pub async fn write_frame<T: serde::Serialize>(
    stream: &mut UnixStream,
    path: &std::path::Path,
    value: &T,
) -> Result<(), ProxyError> {
    let body = serde_json::to_vec(value).map_err(|source| ProxyError::Encode { source })?;
    let len: u32 = body.len().try_into().map_err(|_| ProxyError::Encode {
        source: serde::ser::Error::custom("request body too large for u32 length prefix"),
    })?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|source| ProxyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    stream
        .write_all(&body)
        .await
        .map_err(|source| ProxyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

/// Read a length-prefixed JSON frame from the UDS stream. Enforces the
/// max-frame-bytes cap before allocating the body buffer.
pub async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    path: &std::path::Path,
    max_frame_bytes: usize,
) -> Result<T, ProxyError> {
    let mut len_buf = [0u8; FRAME_LEN_BYTES];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|source| ProxyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_frame_bytes {
        return Err(ProxyError::ResponseTooLarge {
            path: path.to_path_buf(),
            size: len,
            cap: max_frame_bytes,
        });
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|source| ProxyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    serde_json::from_slice(&body).map_err(|source| ProxyError::Decode {
        path: path.to_path_buf(),
        source,
    })
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
