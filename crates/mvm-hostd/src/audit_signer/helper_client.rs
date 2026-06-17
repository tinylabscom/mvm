//! Client for the resident per-tenant signer helper.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_core::protocol::audit_signer::{
    SignerHelperRequest, SignerHelperResponse, SignerHelperSignHost,
};
use mvm_core::protocol::host_signer::{SignRequest, SignResponse};

/// Default cap for helper control frames.
pub const DEFAULT_HELPER_MAX_FRAME_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct SignerHelperClient {
    uds_path: PathBuf,
    max_frame_bytes: usize,
}

impl SignerHelperClient {
    pub fn new(uds_path: impl Into<PathBuf>) -> Self {
        Self {
            uds_path: uds_path.into(),
            max_frame_bytes: DEFAULT_HELPER_MAX_FRAME_BYTES,
        }
    }

    pub fn with_max_frame_bytes(mut self, max_frame_bytes: usize) -> Self {
        self.max_frame_bytes = max_frame_bytes;
        self
    }

    pub fn send(&self, req: &SignerHelperRequest) -> Result<SignerHelperResponse> {
        send_helper_request(&self.uds_path, req, self.max_frame_bytes)
    }

    pub fn sign_host(&self, req: SignRequest) -> Result<SignResponse> {
        let request_id = req.request_id().to_string();
        let outcome: Result<SignResponse> =
            match self.send(&SignerHelperRequest::SignHost(SignerHelperSignHost {
                request_id: request_id.clone(),
                request: req,
            }))? {
                SignerHelperResponse::HostSigned { response, .. } => Ok(response),
                SignerHelperResponse::Err { message, .. } => {
                    bail!("signer-helper host-sign refused: {message}")
                }
                other => bail!("signer-helper returned unexpected host-sign response: {other:?}"),
            };
        outcome.with_context(|| format!("host-sign request {request_id} via signer helper"))
    }
}

fn send_helper_request(
    path: &Path,
    req: &SignerHelperRequest,
    max_frame_bytes: usize,
) -> Result<SignerHelperResponse> {
    let mut stream =
        UnixStream::connect(path).with_context(|| format!("connect {}", path.display()))?;
    let body = serde_json::to_vec(req).context("encode signer-helper request")?;
    let len: u32 = body
        .len()
        .try_into()
        .context("signer-helper request too large")?;
    stream
        .write_all(&len.to_be_bytes())
        .with_context(|| format!("write signer-helper request len to {}", path.display()))?;
    stream
        .write_all(&body)
        .with_context(|| format!("write signer-helper request body to {}", path.display()))?;
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .with_context(|| format!("read signer-helper response len from {}", path.display()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_frame_bytes {
        bail!("signer-helper response {len} bytes exceeds cap {max_frame_bytes}");
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .with_context(|| format!("read signer-helper response body from {}", path.display()))?;
    serde_json::from_slice(&body).context("decode signer-helper response")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mvm_core::protocol::audit_signer::AuditSignerErrorCode;
    use mvm_core::protocol::host_signer::HostSignerErrorCode;
    use tempfile::tempdir;
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    use super::*;

    async fn spawn_mock(
        path: PathBuf,
        response: SignerHelperResponse,
        captured: Arc<Mutex<Option<SignerHelperRequest>>>,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let req: SignerHelperRequest =
                crate::framing::read_json_frame(&mut stream, DEFAULT_HELPER_MAX_FRAME_BYTES)
                    .await
                    .unwrap();
            *captured.lock().await = Some(req);
            crate::framing::write_json_frame(&mut stream, &response)
                .await
                .unwrap();
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sign_host_unwraps_nested_response() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("helper.sock");
        let captured = Arc::new(Mutex::new(None));
        let mock = spawn_mock(
            path.clone(),
            SignerHelperResponse::HostSigned {
                request_id: "sign-1".into(),
                response: SignResponse::Ok {
                    request_id: "sign-1".into(),
                    sig_alg: mvm_core::security::SIG_ALG_ED25519,
                    signature: vec![0u8; 64],
                    signer_pubkey: vec![1u8; 32],
                },
            },
            captured.clone(),
        )
        .await;
        tokio::task::yield_now().await;

        let client = SignerHelperClient::new(&path);
        let resp = tokio::task::spawn_blocking(move || {
            client.sign_host(SignRequest::SignPlan {
                bytes: b"plan".to_vec(),
                request_id: "sign-1".into(),
            })
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(resp.request_id(), "sign-1");

        let captured_req = captured.lock().await.clone().expect("mock captured");
        assert!(matches!(captured_req, SignerHelperRequest::SignHost(_)));
        mock.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unexpected_response_kind_is_an_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("helper.sock");
        let mock = spawn_mock(
            path.clone(),
            SignerHelperResponse::Err {
                request_id: "sign-1".into(),
                code: AuditSignerErrorCode::InvalidRequest,
                message: "bad request".into(),
            },
            Arc::new(Mutex::new(None)),
        )
        .await;
        tokio::task::yield_now().await;

        let client = SignerHelperClient::new(&path);
        let err = tokio::task::spawn_blocking(move || {
            client.sign_host(SignRequest::SignPlan {
                bytes: b"plan".to_vec(),
                request_id: "sign-1".into(),
            })
        })
        .await
        .unwrap()
        .unwrap_err();
        assert!(err.to_string().contains("host-sign refused"));
        mock.abort();
    }

    #[test]
    fn missing_helper_socket_errors() {
        let dir = tempdir().unwrap();
        let client = SignerHelperClient::new(dir.path().join("missing.sock"));
        let err = client
            .sign_host(SignRequest::SignPlan {
                bytes: b"plan".to_vec(),
                request_id: "sign-1".into(),
            })
            .unwrap_err();
        assert!(err.to_string().contains("connect"));
    }

    #[test]
    fn sign_response_err_is_returned_to_caller() {
        let resp = SignerHelperResponse::HostSigned {
            request_id: "sign-1".into(),
            response: SignResponse::Err {
                request_id: "sign-1".into(),
                code: HostSignerErrorCode::NotReady,
                message: "loading".into(),
            },
        };
        assert_eq!(resp.request_id(), "sign-1");
    }
}
