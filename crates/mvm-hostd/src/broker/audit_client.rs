//! UDS client to `mvm-audit-signer` for the `host.audit.v1` handler.
//!
//! Each `append` opens a fresh UDS connection. Pooling lives at the
//! supervisor's `AuditSignerProxy`; the broker is a
//! direct client because the audit-signer's UDS path is part of the
//! broker's `SubprocessConfig`, and going through the supervisor would
//! add a hop per workload-emitted entry.
//!
//! Wire format mirrors `mvm-audit-signer::server`: 4-byte big-endian
//! length prefix + JSON `AppendEntryRequest`; response is the same
//! shape. Frame cap matches the audit-signer's
//! `DEFAULT_MAX_FRAME_BYTES` (64 KiB).

use std::path::{Path, PathBuf};

use mvm_core::protocol::audit_signer::{
    AppendEntryRequest, AppendEntryResponse, SignerHelperAppendEntry, SignerHelperRequest,
    SignerHelperResponse,
};
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
    #[error("protocol violation from {path}: {message}")]
    Protocol { path: PathBuf, message: String },
}

/// One-call-per-connection UDS client.
///
/// Cheap to construct: holds only the path. Each `append` re-opens
/// the socket and shuts it down after the response — there's no
/// connection state to retain.
#[derive(Debug, Clone)]
pub struct AuditClient {
    target: AuditClientTarget,
    max_frame_bytes: usize,
}

#[derive(Debug, Clone)]
enum AuditClientTarget {
    PerVmSigner { uds_path: PathBuf },
    SignerHelper { uds_path: PathBuf, vm_id: String },
}

impl AuditClient {
    /// New client targeting the audit-signer UDS at `uds_path`.
    pub fn new(uds_path: impl Into<PathBuf>) -> Self {
        Self {
            target: AuditClientTarget::PerVmSigner {
                uds_path: uds_path.into(),
            },
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    /// New client targeting the resident signer helper for one server-derived
    /// `vm_id`.
    pub fn new_signer_helper(uds_path: impl Into<PathBuf>, vm_id: impl Into<String>) -> Self {
        Self {
            target: AuditClientTarget::SignerHelper {
                uds_path: uds_path.into(),
                vm_id: vm_id.into(),
            },
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
        match &self.target {
            AuditClientTarget::PerVmSigner { uds_path } => {
                let mut stream = connect(uds_path).await?;
                write_frame(&mut stream, uds_path, req).await?;
                let resp =
                    read_frame::<AppendEntryResponse>(&mut stream, uds_path, self.max_frame_bytes)
                        .await?;
                let _ = stream.shutdown().await;
                Ok(resp)
            }
            AuditClientTarget::SignerHelper { uds_path, vm_id } => {
                let helper_req = helper_request_from_append(req, vm_id);
                let mut stream = connect(uds_path).await?;
                write_frame(&mut stream, uds_path, &helper_req).await?;
                let resp =
                    read_frame::<SignerHelperResponse>(&mut stream, uds_path, self.max_frame_bytes)
                        .await?;
                let _ = stream.shutdown().await;
                helper_response_to_append_response(resp, uds_path)
            }
        }
    }
}

fn helper_request_from_append(req: &AppendEntryRequest, vm_id: &str) -> SignerHelperRequest {
    match req {
        AppendEntryRequest::AppendEntry {
            request_id,
            category,
            ts,
            workload_id,
            tenant_id,
            session_id,
            correlation_id,
            fields,
        } => SignerHelperRequest::AppendEntry(SignerHelperAppendEntry {
            request_id: request_id.clone(),
            vm_id: vm_id.to_string(),
            category: category.clone(),
            ts: ts.clone(),
            workload_id: workload_id.clone(),
            tenant_id: tenant_id.clone(),
            session_id: session_id.clone(),
            correlation_id: correlation_id.clone(),
            fields: fields.clone(),
        }),
        AppendEntryRequest::Probe { request_id } => SignerHelperRequest::Probe {
            request_id: request_id.clone(),
        },
    }
}

fn helper_response_to_append_response(
    resp: SignerHelperResponse,
    path: &Path,
) -> Result<AppendEntryResponse, AuditClientError> {
    match resp {
        SignerHelperResponse::Ok {
            request_id,
            chain_head,
            entry_hash,
            sig_alg,
        } => Ok(AppendEntryResponse::Ok {
            request_id,
            chain_head,
            entry_hash,
            sig_alg,
        }),
        SignerHelperResponse::Pong { request_id } => Ok(AppendEntryResponse::Pong { request_id }),
        SignerHelperResponse::Err {
            request_id,
            code,
            message,
        } => Ok(AppendEntryResponse::Err {
            request_id,
            code,
            message,
        }),
        SignerHelperResponse::Registered { .. } | SignerHelperResponse::Deregistered { .. } => {
            Err(AuditClientError::Protocol {
                path: path.to_path_buf(),
                message: "signer helper returned a control response to append".into(),
            })
        }
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
