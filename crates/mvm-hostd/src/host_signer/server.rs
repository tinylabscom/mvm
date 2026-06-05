//! UDS server loop — accepts `SignRequest` envelopes from the supervisor,
//! dispatches via [`Keystore`], writes back the [`SignResponse`].
//!
//! Frame format: 4-byte big-endian length prefix + JSON `SignRequest`.
//! Response: 4-byte big-endian length prefix + JSON `SignResponse`.
//! Max-frame-bytes cap enforced *before* parse (same pattern as the
//! broker's gate 1).

use anyhow::{Context, Result};
use mvm_core::protocol::host_signer::{HostSignerErrorCode, SignRequest, SignResponse};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};

use crate::host_signer::keystore::SharedKeystore;

const DEFAULT_MAX_FRAME_BYTES: usize = 65_536;

/// Accept loop.
pub async fn serve(
    listener: UnixListener,
    keystore: SharedKeystore,
    workload_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    info!(
        workload_id = %workload_id,
        max_frame_bytes,
        "mvm-host-signer accept loop started"
    );
    loop {
        let (stream, _addr) = listener
            .accept()
            .await
            .context("mvm-host-signer UDS accept failed")?;
        let keystore = keystore.clone();
        let workload_id = workload_id.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, keystore, workload_id, max_frame_bytes).await
            {
                warn!(error = %e, "mvm-host-signer connection terminated with error");
            }
        });
    }
}

/// Variant of [`serve`] for tests + cases where the caller already has
/// a `UnixListener` (the supervisor-side spawn path in W1b.2 will call
/// this with a pre-bound listener).
pub async fn serve_on_listener(
    listener: UnixListener,
    keystore: SharedKeystore,
    workload_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    serve(listener, keystore, workload_id, max_frame_bytes).await
}

async fn handle_connection(
    mut stream: UnixStream,
    keystore: SharedKeystore,
    workload_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    let req = read_frame::<SignRequest>(&mut stream, max_frame_bytes).await?;
    debug!(
        workload_id = %workload_id,
        request_id = %req.request_id(),
        "mvm-host-signer received request"
    );

    let response = dispatch(&req, &keystore);
    write_frame(&mut stream, &response).await?;
    stream
        .shutdown()
        .await
        .context("mvm-host-signer UDS shutdown failed")?;
    Ok(())
}

fn dispatch(req: &SignRequest, keystore: &SharedKeystore) -> SignResponse {
    let request_id = req.request_id().to_string();
    let bytes_to_sign: &[u8] = match req {
        SignRequest::SignPlan { bytes, .. } => bytes,
    };
    let result = keystore.sign(bytes_to_sign);
    SignResponse::Ok {
        request_id,
        sig_alg: result.sig_alg,
        signature: result.signature,
        signer_pubkey: result.pub_key_bytes,
    }
}

/// Read a length-prefixed JSON frame.
// Length-prefixed JSON framing lives in `crate::framing` (plan 126 B5;
// was `mvm_core::framing`); these wrappers keep the host-signer error
// context on the shared transport. The cap-before-alloc gate is enforced
// there.
async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    max_frame_bytes: usize,
) -> Result<T> {
    crate::framing::read_json_frame(stream, max_frame_bytes)
        .await
        .context("mvm-host-signer frame read failed")
}

/// Write a length-prefixed JSON frame.
async fn write_frame<T: serde::Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    crate::framing::write_json_frame(stream, value)
        .await
        .context("mvm-host-signer frame write failed")
}

/// Build an `Err` response with the supplied typed code. Kept around
/// so future paths (W1b.2 unsigned-config, W8 enclave-error) have a
/// uniform constructor. Currently unused in the happy-path dispatch.
#[allow(dead_code)]
pub fn err_response(
    request_id: impl Into<String>,
    code: HostSignerErrorCode,
    message: impl Into<String>,
) -> SignResponse {
    SignResponse::Err {
        request_id: request_id.into(),
        code,
        message: message.into(),
    }
}

/// Default max-frame-bytes for the server.
pub fn default_max_frame_bytes() -> usize {
    DEFAULT_MAX_FRAME_BYTES
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use ed25519_dalek::{Verifier, VerifyingKey};
    use mvm_core::protocol::host_signer::SignRequest;
    use mvm_core::security::SIG_ALG_ED25519;
    use tempfile::tempdir;
    use tokio::net::UnixStream as ClientStream;

    use super::*;
    use crate::host_signer::keystore::Keystore;
    use tokio::io::AsyncReadExt;

    async fn write_req(stream: &mut ClientStream, req: &SignRequest) -> Result<()> {
        let body = serde_json::to_vec(req).unwrap();
        let len: u32 = body.len().try_into().unwrap();
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&body).await?;
        Ok(())
    }

    async fn read_resp(stream: &mut ClientStream) -> Result<SignResponse> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    fn uds_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("host-signer.sock")
    }

    #[tokio::test]
    async fn sign_plan_round_trips_and_signature_verifies() {
        let dir = tempdir().unwrap();
        let path = uds_path(&dir);
        let listener = UnixListener::bind(&path).unwrap();
        let keystore = Arc::new(Keystore::generate());
        let pub_key = keystore.pub_key();

        let server_task = tokio::spawn({
            let keystore = keystore.clone();
            async move {
                let _ = serve_on_listener(listener, keystore, "wl-test".into(), 65_536).await;
            }
        });
        tokio::task::yield_now().await;

        let mut client = ClientStream::connect(&path).await.unwrap();
        let plan_bytes = b"canonical-execution-plan".to_vec();
        let req = SignRequest::SignPlan {
            bytes: plan_bytes.clone(),
            request_id: "req-1".into(),
        };
        write_req(&mut client, &req).await.unwrap();
        let resp = read_resp(&mut client).await.unwrap();

        match resp {
            SignResponse::Ok {
                request_id,
                sig_alg,
                signature,
                signer_pubkey,
            } => {
                assert_eq!(request_id, "req-1");
                assert_eq!(sig_alg, SIG_ALG_ED25519);
                assert_eq!(signature.len(), 64);
                assert_eq!(signer_pubkey, pub_key);

                let pk_arr: [u8; 32] = signer_pubkey.try_into().unwrap();
                let vk = VerifyingKey::from_bytes(&pk_arr).unwrap();
                let sig_arr: [u8; 64] = signature.try_into().unwrap();
                let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
                vk.verify(&plan_bytes, &sig).expect("signature must verify");
            }
            other => panic!("expected Ok response, got {:?}", other),
        }

        server_task.abort();
    }

    #[tokio::test]
    async fn rejects_frames_above_the_cap() {
        let dir = tempdir().unwrap();
        let path = uds_path(&dir);
        let listener = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("failed to bind host signer test listener: {err}"),
        };
        let keystore = Arc::new(Keystore::generate());

        let server_task = tokio::spawn({
            let keystore = keystore.clone();
            async move {
                let _ = serve_on_listener(listener, keystore, "wl-test".into(), 16).await;
            }
        });
        tokio::task::yield_now().await;

        let mut client = ClientStream::connect(&path).await.unwrap();
        let req = SignRequest::SignPlan {
            bytes: vec![0u8; 256],
            request_id: "too-big".into(),
        };
        write_req(&mut client, &req).await.unwrap();
        let mut buf = [0u8; 4];
        match client.read(&mut buf).await {
            Ok(0) => {}
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {}
            Ok(n) => panic!("expected EOF/reset after oversized frame rejection, got {n} bytes"),
            Err(err) => {
                panic!("expected EOF/reset after oversized frame rejection, got {err}")
            }
        }

        server_task.abort();
    }

    #[test]
    fn err_response_constructor_carries_typed_code() {
        let resp = err_response(
            "req-x",
            HostSignerErrorCode::KeyUnavailable,
            "key file missing",
        );
        match resp {
            SignResponse::Err { code, .. } => {
                assert_eq!(code, HostSignerErrorCode::KeyUnavailable);
            }
            _ => panic!("expected Err"),
        }
    }
}
