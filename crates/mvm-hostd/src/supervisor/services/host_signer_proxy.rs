//! Client for `mvm-host-signer` (the host signer subprocess; Plan 104
//! §H-L1.1).
//!
//! Two verb-specific methods (`sign_plan`, `sign_credential`) on top of
//! the typed `SignRequest`/`SignResponse` envelope. Each method
//! generates a per-call `request_id` (caller can override via
//! `_with_request_id` variants when correlation across logs matters).

use std::path::PathBuf;

use mvm_core::protocol::host_signer::{HostSignerErrorCode, SignRequest, SignResponse};

use super::{
    ProxyError,
    frame::{DEFAULT_MAX_FRAME_BYTES, connect, read_frame, write_frame},
};

#[derive(Debug, Clone)]
pub struct HostSignerProxy {
    pub uds_path: PathBuf,
    pub max_frame_bytes: usize,
}

/// Successful sign — typed for use-at-call-site convenience. Maps
/// 1:1 with the `Ok` variant of `SignResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignOk {
    pub request_id: String,
    pub sig_alg: u8,
    pub signature: Vec<u8>,
    pub signer_pubkey: Vec<u8>,
}

/// Subprocess-typed error from the sign path. Distinct from
/// [`ProxyError`] (transport) so callers can branch on whether the
/// subprocess is just not-ready vs the UDS itself failed.
#[derive(Debug, Clone)]
pub struct SignErr {
    pub request_id: String,
    pub code: HostSignerErrorCode,
    pub message: String,
}

impl HostSignerProxy {
    pub fn new(uds_path: impl Into<PathBuf>) -> Self {
        Self {
            uds_path: uds_path.into(),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    /// Sign an ExecutionPlan bytes. Caller is responsible for the
    /// plan's canonical form.
    pub async fn sign_plan(
        &self,
        bytes: Vec<u8>,
        request_id: impl Into<String>,
    ) -> Result<Result<SignOk, SignErr>, ProxyError> {
        let req = SignRequest::SignPlan {
            bytes,
            request_id: request_id.into(),
        };
        self.send(&req).await
    }

    async fn send(&self, req: &SignRequest) -> Result<Result<SignOk, SignErr>, ProxyError> {
        let mut stream = connect(&self.uds_path).await?;
        write_frame(&mut stream, &self.uds_path, req).await?;
        let resp: SignResponse =
            read_frame(&mut stream, &self.uds_path, self.max_frame_bytes).await?;
        Ok(match resp {
            SignResponse::Ok {
                request_id,
                sig_alg,
                signature,
                signer_pubkey,
            } => Ok(SignOk {
                request_id,
                sig_alg,
                signature,
                signer_pubkey,
            }),
            SignResponse::Err {
                request_id,
                code,
                message,
            } => Err(SignErr {
                request_id,
                code,
                message,
            }),
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
        response: SignResponse,
        captured: Arc<Mutex<Option<SignRequest>>>,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.unwrap();
            let req: SignRequest = serde_json::from_slice(&body).unwrap();
            *captured.lock().await = Some(req);

            let resp_bytes = serde_json::to_vec(&response).unwrap();
            let resp_len: u32 = resp_bytes.len().try_into().unwrap();
            stream.write_all(&resp_len.to_be_bytes()).await.unwrap();
            stream.write_all(&resp_bytes).await.unwrap();
            let _ = stream.shutdown().await;
        })
    }

    #[tokio::test]
    async fn sign_plan_unwraps_ok_response() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("host-signer.sock");

        let response = SignResponse::Ok {
            request_id: "req-001".into(),
            sig_alg: SIG_ALG_ED25519,
            signature: vec![0u8; 64],
            signer_pubkey: vec![1u8; 32],
        };
        let captured = Arc::new(Mutex::new(None));
        let mock = spawn_mock(path.clone(), response, captured.clone()).await;
        tokio::task::yield_now().await;

        let proxy = HostSignerProxy::new(&path);
        let ok = proxy
            .sign_plan(b"plan-bytes".to_vec(), "req-001")
            .await
            .expect("transport must succeed")
            .expect("subprocess must respond Ok");

        assert_eq!(ok.request_id, "req-001");
        assert_eq!(ok.sig_alg, SIG_ALG_ED25519);
        assert_eq!(ok.signature.len(), 64);
        assert_eq!(ok.signer_pubkey.len(), 32);

        let captured_req = captured.lock().await.clone().expect("mock must capture");
        assert!(matches!(captured_req, SignRequest::SignPlan { .. }));
        assert_eq!(captured_req.request_id(), "req-001");
        mock.abort();
    }

    #[tokio::test]
    async fn sign_plan_surfaces_typed_subprocess_err() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("host-signer.sock");

        let response = SignResponse::Err {
            request_id: "req-notready".into(),
            code: HostSignerErrorCode::NotReady,
            message: "TPM still initialising".into(),
        };
        let captured = Arc::new(Mutex::new(None));
        let mock = spawn_mock(path.clone(), response, captured).await;
        tokio::task::yield_now().await;

        let proxy = HostSignerProxy::new(&path);
        let outcome = proxy
            .sign_plan(b"plan".to_vec(), "req-notready")
            .await
            .expect("transport must succeed");

        match outcome {
            Err(sign_err) => {
                assert_eq!(sign_err.code, HostSignerErrorCode::NotReady);
                assert_eq!(sign_err.request_id, "req-notready");
            }
            other => panic!("expected Err, got {:?}", other),
        }
        mock.abort();
    }

    #[tokio::test]
    async fn connect_failure_surfaces_as_proxy_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.sock");
        let proxy = HostSignerProxy::new(&path);
        let err = proxy
            .sign_plan(b"plan".to_vec(), "req")
            .await
            .expect_err("connect to missing UDS must fail");
        assert!(matches!(err, ProxyError::Connect { .. }));
    }
}
