//! UDS client to `mvm-audit-signer` for the `host.audit.v1` handler
//! (Plan 104 §host.audit.v1, ADR-062).
//!
//! Each `append` opens a fresh UDS connection. Pooling lives at the
//! supervisor's `AuditSignerProxy` (Plan 104 §C5); the broker is a
//! direct client because the audit-signer's UDS path is part of the
//! broker's `SubprocessConfig`, and going through the supervisor would
//! add a hop per workload-emitted entry.
//!
//! Wire format mirrors `mvm-audit-signer::server`: 4-byte big-endian
//! length prefix + JSON `AppendEntryRequest`; response is the same
//! shape. Frame cap matches the audit-signer's
//! `DEFAULT_MAX_FRAME_BYTES` (64 KiB).

use std::path::{Path, PathBuf};

use mvm_core::protocol::audit_signer::{AppendEntryRequest, AppendEntryResponse};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const FRAME_LEN_BYTES: usize = 4;
const DEFAULT_MAX_FRAME_BYTES: usize = 65_536;

/// Errors the client can surface beyond a typed [`AppendEntryResponse::Err`].
#[derive(Debug, Error)]
pub enum AuditClientError {
    #[error("connect to {path} failed: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("UDS I/O on {path} failed: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("response from {path} too large: {size} > {cap}")]
    ResponseTooLarge {
        path: PathBuf,
        size: usize,
        cap: usize,
    },
    #[error("response envelope parse failed from {path}: {source}")]
    Decode {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("request envelope encode failed: {source}")]
    Encode {
        #[source]
        source: serde_json::Error,
    },
}

/// One-call-per-connection UDS client.
///
/// Cheap to construct: holds only the path. Each [`append`] re-opens
/// the socket and shuts it down after the response — there's no
/// connection state to retain.
#[derive(Debug, Clone)]
pub struct AuditClient {
    uds_path: PathBuf,
    max_frame_bytes: usize,
}

impl AuditClient {
    /// New client targeting the audit-signer UDS at `uds_path`.
    pub fn new(uds_path: impl Into<PathBuf>) -> Self {
        Self {
            uds_path: uds_path.into(),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    /// Set the max bytes the client will read on a response. Defaults
    /// to 64 KiB.
    pub fn with_max_frame_bytes(mut self, max: usize) -> Self {
        self.max_frame_bytes = max;
        self
    }

    /// Send one [`AppendEntryRequest`] and return the typed response.
    /// Errors are split between transport ([`AuditClientError`]) and
    /// protocol-level (`AppendEntryResponse::Err`); callers handle both.
    pub async fn append(
        &self,
        req: &AppendEntryRequest,
    ) -> Result<AppendEntryResponse, AuditClientError> {
        let mut stream = connect(&self.uds_path).await?;
        write_frame(&mut stream, &self.uds_path, req).await?;
        let resp =
            read_frame::<AppendEntryResponse>(&mut stream, &self.uds_path, self.max_frame_bytes)
                .await?;
        let _ = stream.shutdown().await;
        Ok(resp)
    }
}

async fn connect(path: &Path) -> Result<UnixStream, AuditClientError> {
    UnixStream::connect(path)
        .await
        .map_err(|source| AuditClientError::Connect {
            path: path.to_path_buf(),
            source,
        })
}

async fn write_frame<T: serde::Serialize>(
    stream: &mut UnixStream,
    path: &Path,
    value: &T,
) -> Result<(), AuditClientError> {
    let body = serde_json::to_vec(value).map_err(|source| AuditClientError::Encode { source })?;
    let len: u32 = body.len().try_into().map_err(|_| AuditClientError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other("frame body too large for u32 prefix"),
    })?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|source| AuditClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    stream
        .write_all(&body)
        .await
        .map_err(|source| AuditClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    path: &Path,
    max_frame_bytes: usize,
) -> Result<T, AuditClientError> {
    let mut len_buf = [0u8; FRAME_LEN_BYTES];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|source| AuditClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_frame_bytes {
        return Err(AuditClientError::ResponseTooLarge {
            path: path.to_path_buf(),
            size: len,
            cap: max_frame_bytes,
        });
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|source| AuditClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    serde_json::from_slice(&body).map_err(|source| AuditClientError::Decode {
        path: path.to_path_buf(),
        source,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mvm_core::protocol::audit_signer::AuditSignerErrorCode;
    use mvm_core::security::SIG_ALG_ED25519;
    use tempfile::tempdir;
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    use super::*;

    /// Spin up a one-shot mock UDS server that records the request it
    /// sees + replies with a canned response.
    async fn spawn_mock(
        path: PathBuf,
        response: AppendEntryResponse,
        captured: Arc<Mutex<Option<AppendEntryRequest>>>,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.unwrap();
            let req: AppendEntryRequest = serde_json::from_slice(&body).unwrap();
            *captured.lock().await = Some(req);

            let resp_bytes = serde_json::to_vec(&response).unwrap();
            let resp_len: u32 = resp_bytes.len().try_into().unwrap();
            stream.write_all(&resp_len.to_be_bytes()).await.unwrap();
            stream.write_all(&resp_bytes).await.unwrap();
            let _ = stream.shutdown().await;
        })
    }

    fn sample_req() -> AppendEntryRequest {
        AppendEntryRequest::AppendEntry {
            request_id: "req-1".into(),
            category: "workload_audit".into(),
            ts: "2026-05-28T00:00:00Z".into(),
            workload_id: "wl-001".into(),
            tenant_id: "t-001".into(),
            session_id: "sess-001".into(),
            correlation_id: "01HCORR0000000000000000".into(),
            fields: serde_json::json!({"foo": "bar"}),
        }
    }

    #[tokio::test]
    async fn append_round_trips_an_ok_response() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-signer.sock");
        let response = AppendEntryResponse::Ok {
            request_id: "req-1".into(),
            chain_head: "head1".into(),
            entry_hash: "head1".into(),
            sig_alg: SIG_ALG_ED25519,
        };
        let captured = Arc::new(Mutex::new(None));
        let mock = spawn_mock(path.clone(), response.clone(), captured.clone()).await;
        tokio::task::yield_now().await;

        let client = AuditClient::new(&path);
        let resp = client.append(&sample_req()).await.unwrap();
        assert_eq!(resp, response);

        let captured_req = captured.lock().await.clone().unwrap();
        assert_eq!(captured_req.request_id(), "req-1");
        mock.abort();
    }

    #[tokio::test]
    async fn surfaces_typed_subprocess_err_response() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-signer.sock");
        let err_resp = AppendEntryResponse::Err {
            request_id: "req-1".into(),
            code: AuditSignerErrorCode::InvalidRequest,
            message: "category not in allow-list".into(),
        };
        let captured = Arc::new(Mutex::new(None));
        let mock = spawn_mock(path.clone(), err_resp.clone(), captured).await;
        tokio::task::yield_now().await;

        let client = AuditClient::new(&path);
        let resp = client.append(&sample_req()).await.unwrap();
        assert_eq!(resp, err_resp);
        mock.abort();
    }

    #[tokio::test]
    async fn returns_connect_error_when_socket_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does-not-exist.sock");
        let client = AuditClient::new(&path);
        let err = client.append(&sample_req()).await.unwrap_err();
        assert!(matches!(err, AuditClientError::Connect { .. }));
    }
}
