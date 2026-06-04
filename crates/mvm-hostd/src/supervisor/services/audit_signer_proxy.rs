//! Client for `mvm-audit-signer` (the audit chain-signer subprocess;
//! Plan 104 §H-L1.2).
//!
//! Two verb-specific methods: `probe` (health check used by the
//! admission ceremony to confirm the subprocess is ready before
//! admitting a workload — Plan 104 §H-L5.7), and `append_entry`
//! (one typed audit entry per call). Both return a typed result.

use std::path::PathBuf;

use mvm_core::protocol::audit_signer::{
    AppendEntryRequest, AppendEntryResponse, AuditSignerErrorCode,
};

use super::{
    ProxyError,
    frame::{DEFAULT_MAX_FRAME_BYTES, connect, read_frame, write_frame},
};

#[derive(Debug, Clone)]
pub struct AuditSignerProxy {
    pub uds_path: PathBuf,
    pub max_frame_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendOk {
    pub request_id: String,
    pub chain_head: String,
    pub entry_hash: String,
    pub sig_alg: u8,
}

#[derive(Debug, Clone)]
pub struct AppendErr {
    pub request_id: String,
    pub code: AuditSignerErrorCode,
    pub message: String,
}

/// Typed audit entry the supervisor wants chain-signed and appended.
///
/// Maps 1:1 to the `AppendEntry` variant of
/// [`AppendEntryRequest`](mvm_core::protocol::audit_signer::AppendEntryRequest)
/// but keeps the supervisor-side caller free of the wire enum's
/// `verb`-tagged discriminator.
#[derive(Debug, Clone)]
pub struct AuditEntryFields {
    pub category: String,
    pub ts: String,
    pub workload_id: String,
    pub tenant_id: String,
    pub session_id: String,
    pub correlation_id: String,
    pub fields: serde_json::Value,
}

impl AuditSignerProxy {
    pub fn new(uds_path: impl Into<PathBuf>) -> Self {
        Self {
            uds_path: uds_path.into(),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    /// Health probe. Used by the admission ceremony to confirm the
    /// subprocess is up before admitting the workload.
    pub async fn probe(&self, request_id: impl Into<String>) -> Result<String, ProxyError> {
        let request_id = request_id.into();
        let req = AppendEntryRequest::Probe {
            request_id: request_id.clone(),
        };
        let mut stream = connect(&self.uds_path).await?;
        write_frame(&mut stream, &self.uds_path, &req).await?;
        let resp: AppendEntryResponse =
            read_frame(&mut stream, &self.uds_path, self.max_frame_bytes).await?;
        match resp {
            AppendEntryResponse::Pong {
                request_id: echoed_id,
            } => Ok(echoed_id),
            other => Err(ProxyError::Decode {
                path: self.uds_path.clone(),
                source: serde::de::Error::custom(format!("expected Pong, got {:?}", other)),
            }),
        }
    }

    /// Append one typed audit entry. Returns the new chain head on
    /// success.
    pub async fn append_entry(
        &self,
        request_id: impl Into<String>,
        entry: AuditEntryFields,
    ) -> Result<Result<AppendOk, AppendErr>, ProxyError> {
        let req = AppendEntryRequest::AppendEntry {
            request_id: request_id.into(),
            category: entry.category,
            ts: entry.ts,
            workload_id: entry.workload_id,
            tenant_id: entry.tenant_id,
            session_id: entry.session_id,
            correlation_id: entry.correlation_id,
            fields: entry.fields,
        };
        let mut stream = connect(&self.uds_path).await?;
        write_frame(&mut stream, &self.uds_path, &req).await?;
        let resp: AppendEntryResponse =
            read_frame(&mut stream, &self.uds_path, self.max_frame_bytes).await?;
        Ok(match resp {
            AppendEntryResponse::Ok {
                request_id,
                chain_head,
                entry_hash,
                sig_alg,
            } => Ok(AppendOk {
                request_id,
                chain_head,
                entry_hash,
                sig_alg,
            }),
            AppendEntryResponse::Err {
                request_id,
                code,
                message,
            } => Err(AppendErr {
                request_id,
                code,
                message,
            }),
            AppendEntryResponse::Pong { .. } => {
                return Err(ProxyError::Decode {
                    path: self.uds_path.clone(),
                    source: serde::de::Error::custom("expected Ok/Err for append_entry, got Pong"),
                });
            }
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mvm_core::security::SIG_ALG_ED25519;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    use super::*;

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

    fn sample_fields() -> AuditEntryFields {
        AuditEntryFields {
            category: "service_call".into(),
            ts: "2026-05-27T22:30:00Z".into(),
            workload_id: "wl-001".into(),
            tenant_id: "t-001".into(),
            session_id: "sess-001".into(),
            correlation_id: "01HCORR".into(),
            fields: serde_json::json!({"verb": "now"}),
        }
    }

    #[tokio::test]
    async fn probe_echoes_request_id() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-signer.sock");

        let response = AppendEntryResponse::Pong {
            request_id: "probe-1".into(),
        };
        let captured = Arc::new(Mutex::new(None));
        let mock = spawn_mock(path.clone(), response, captured.clone()).await;
        tokio::task::yield_now().await;

        let proxy = AuditSignerProxy::new(&path);
        let echo = proxy.probe("probe-1").await.expect("probe must succeed");
        assert_eq!(echo, "probe-1");

        let captured_req = captured.lock().await.clone().expect("mock must capture");
        assert!(matches!(captured_req, AppendEntryRequest::Probe { .. }));
        mock.abort();
    }

    #[tokio::test]
    async fn append_entry_unwraps_ok_response() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-signer.sock");

        let response = AppendEntryResponse::Ok {
            request_id: "req-append".into(),
            chain_head: "abc123".into(),
            entry_hash: "abc123".into(),
            sig_alg: SIG_ALG_ED25519,
        };
        let captured = Arc::new(Mutex::new(None));
        let mock = spawn_mock(path.clone(), response, captured.clone()).await;
        tokio::task::yield_now().await;

        let proxy = AuditSignerProxy::new(&path);
        let ok = proxy
            .append_entry("req-append", sample_fields())
            .await
            .expect("transport must succeed")
            .expect("subprocess must respond Ok");
        assert_eq!(ok.chain_head, "abc123");
        assert_eq!(ok.entry_hash, "abc123");
        assert_eq!(ok.sig_alg, SIG_ALG_ED25519);

        let captured_req = captured.lock().await.clone().expect("mock must capture");
        match captured_req {
            AppendEntryRequest::AppendEntry { category, .. } => {
                assert_eq!(category, "service_call");
            }
            _ => panic!("expected AppendEntry"),
        }
        mock.abort();
    }

    #[tokio::test]
    async fn append_entry_surfaces_chain_drift_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-signer.sock");

        let response = AppendEntryResponse::Err {
            request_id: "req-drift".into(),
            code: AuditSignerErrorCode::ChainDriftDetected,
            message: "head mismatch".into(),
        };
        let captured = Arc::new(Mutex::new(None));
        let mock = spawn_mock(path.clone(), response, captured).await;
        tokio::task::yield_now().await;

        let proxy = AuditSignerProxy::new(&path);
        let outcome = proxy
            .append_entry("req-drift", sample_fields())
            .await
            .expect("transport must succeed");
        match outcome {
            Err(append_err) => {
                assert_eq!(append_err.code, AuditSignerErrorCode::ChainDriftDetected);
            }
            other => panic!("expected Err, got {:?}", other),
        }
        mock.abort();
    }

    #[tokio::test]
    async fn probe_rejects_unexpected_response_variant() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit-signer.sock");

        // Misbehaving subprocess: returns Ok instead of Pong.
        let response = AppendEntryResponse::Ok {
            request_id: "probe-1".into(),
            chain_head: "x".into(),
            entry_hash: "x".into(),
            sig_alg: SIG_ALG_ED25519,
        };
        let captured = Arc::new(Mutex::new(None));
        let mock = spawn_mock(path.clone(), response, captured).await;
        tokio::task::yield_now().await;

        let proxy = AuditSignerProxy::new(&path);
        let err = proxy
            .probe("probe-1")
            .await
            .expect_err("probe must reject unexpected variant");
        assert!(matches!(err, ProxyError::Decode { .. }), "got {:?}", err);
        mock.abort();
    }
}
