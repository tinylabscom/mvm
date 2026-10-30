//! UDS server loop — accepts `SignRequest` envelopes from the supervisor,
//! dispatches via `Keystore`, writes back the [`SignResponse`].
//!
//! Frame format: 4-byte big-endian length prefix + JSON `SignRequest`.
//! Response: 4-byte big-endian length prefix + JSON `SignResponse`.
//! Max-frame-bytes cap enforced *before* parse (same pattern as the
//! broker's gate 1).

use std::borrow::Cow;

use anyhow::{Context, Result};
use mvm_core::protocol::host_signer::{HostSignerErrorCode, SignRequest, SignResponse};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};

use crate::audit_signer::helper_client::SignerHelperClient;
use crate::host_signer::keystore::{Keystore, SharedKeystore};

const DEFAULT_MAX_FRAME_BYTES: usize = 65_536;

#[path = "plan_payload.rs"]
mod plan_payload;

#[derive(Clone)]
enum SignBackend {
    Local(SharedKeystore),
    Helper(SignerHelperClient),
}

/// Accept loop.
pub async fn serve(
    listener: UnixListener,
    keystore: SharedKeystore,
    workload_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    serve_with_backend(
        listener,
        SignBackend::Local(keystore),
        workload_id,
        max_frame_bytes,
    )
    .await
}

async fn serve_with_backend(
    listener: UnixListener,
    backend: SignBackend,
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
        let backend = backend.clone();
        let workload_id = workload_id.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, backend, workload_id, max_frame_bytes).await {
                warn!(error = %e, "mvm-host-signer connection terminated with error");
            }
        });
    }
}

/// Variant of [`serve`] for tests + cases where the caller already has
/// a `UnixListener` (the supervisor-side spawn path calls this with a
/// pre-bound listener).
pub async fn serve_on_listener(
    listener: UnixListener,
    keystore: SharedKeystore,
    workload_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    serve(listener, keystore, workload_id, max_frame_bytes).await
}

/// Variant that runs `mvm-host-signer` as a keyless compatibility proxy
/// backed by the resident signer helper.
pub async fn serve_via_helper_on_listener(
    listener: UnixListener,
    helper: SignerHelperClient,
    workload_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    serve_with_backend(
        listener,
        SignBackend::Helper(helper),
        workload_id,
        max_frame_bytes,
    )
    .await
}

async fn handle_connection(
    mut stream: UnixStream,
    backend: SignBackend,
    workload_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    let req = read_frame::<SignRequest>(&mut stream, max_frame_bytes).await?;
    debug!(
        workload_id = %workload_id,
        request_id = %req.request_id(),
        "mvm-host-signer received request"
    );

    let response = dispatch(&req, &backend).await;
    write_frame(&mut stream, &response).await?;
    stream
        .shutdown()
        .await
        .context("mvm-host-signer UDS shutdown failed")?;
    Ok(())
}

async fn dispatch(req: &SignRequest, backend: &SignBackend) -> SignResponse {
    match backend {
        SignBackend::Local(keystore) => dispatch_local(req, keystore),
        SignBackend::Helper(client) => {
            let request_id = req.request_id().to_string();
            let client = client.clone();
            let req = req.clone();
            match tokio::task::spawn_blocking(move || client.sign_host(req)).await {
                Ok(Ok(resp)) => resp,
                Ok(Err(e)) => err_response(
                    request_id,
                    HostSignerErrorCode::InternalError,
                    format!("signer helper request failed: {e}"),
                ),
                Err(e) => err_response(
                    request_id,
                    HostSignerErrorCode::InternalError,
                    format!("signer helper task failed: {e}"),
                ),
            }
        }
    }
}

pub(crate) fn dispatch_local(req: &SignRequest, keystore: &Keystore) -> SignResponse {
    let request_id = req.request_id().to_string();
    let bytes_to_sign: Cow<'_, [u8]> = match req {
        SignRequest::SignPlan { bytes, .. } => {
            if !plan_payload::is_supported_canonical_plan(bytes) {
                return err_response(
                    request_id,
                    HostSignerErrorCode::InvalidRequest,
                    "invalid execution plan payload",
                );
            }
            Cow::Borrowed(bytes)
        }
        SignRequest::SignTelemetryHandshake { handshake, .. } => {
            match mvm_core::net::telemetry::handshake_signing_bytes(
                &handshake.hello,
                &handshake.ack,
                &keystore.verifying_key(),
            ) {
                Ok(bytes) => Cow::Owned(bytes),
                Err(_) => {
                    return err_response(
                        request_id,
                        HostSignerErrorCode::InvalidRequest,
                        "invalid telemetry handshake",
                    );
                }
            }
        }
    };
    let result = keystore.sign(&bytes_to_sign);
    SignResponse::Ok {
        request_id,
        sig_alg: result.sig_alg,
        signature: result.signature,
        signer_pubkey: result.pub_key_bytes,
    }
}

/// Read a length-prefixed JSON frame.
// Length-prefixed JSON framing lives in `crate::framing`; these wrappers
// keep the host-signer error context on the shared transport. The
// cap-before-alloc gate is enforced there.
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

/// Build an `Err` response with the supplied typed code.
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
    use mvm_core::protocol::audit_signer::{SignerHelperRequest, SignerHelperResponse};
    use mvm_core::protocol::host_signer::SignRequest;
    use mvm_core::security::SIG_ALG_ED25519;
    use tempfile::tempdir;
    use tokio::net::UnixStream as ClientStream;

    use super::*;
    use crate::audit_signer::helper_client::SignerHelperClient;
    use crate::host_signer::keystore::Keystore;
    use tokio::io::AsyncReadExt;
    use tokio::sync::Mutex;

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

    fn core_plan_payload() -> Vec<u8> {
        use mvm_core::plan::types::{AssetIdentity, AssetKind, EnvironmentRef, PolicyRef};
        let mut plan = mvm_core::plan::test_support::PlanFixture::new()
            .caller_commitment(mvm_core::plan::CallerCommitment::from_bytes([11; 32]))
            .sdk_uses_sidecar(false)
            .grants(Some(mvm_contract::grants::Grants::default()))
            .build();
        plan.environment = Some(EnvironmentRef {
            kernel_sha256: "1".repeat(64),
        });
        plan.bundle = Some(mvm_core::plan::PlanArtifact {
            bundle_sha256: "3".repeat(64),
            manifest_sig_base64: mvm_core::plan::signature_to_base64(&[7; 64]),
            key_id: mvm_core::plan::KeyId("bundle-fixture".into()),
        });
        // Budget policy is external to ExecutionPlan. Preserve its pins, not an
        // invented inline budget or a claim that this codec test admits a pack.
        plan.network_policy = PolicyRef(format!("sha256:{}", "2".repeat(64)));
        plan.asset_identities.push(AssetIdentity {
            kind: AssetKind::Policy,
            name: "request-budget-policy-fixture".into(),
            digest: "2".repeat(64),
        });
        plan.action_budget = Some(
            mvm_contract::policy::action_budget::ActionBudget::default().with_max_egress_flows(1),
        );
        encode_core_plan(&plan)
    }

    fn encode_core_plan(plan: &mvm_core::plan::ExecutionPlan) -> Vec<u8> {
        mvm_core::plan::sign_plan(
            plan,
            &ed25519_dalek::SigningKey::from_bytes(&[23; 32]),
            "plan-fixture",
        )
        .0
        .payload
    }

    fn assert_invalid_plan(bytes: Vec<u8>) {
        let keystore = Keystore::generate();
        let before = Keystore::test_signing_calls();
        let response = dispatch_local(
            &SignRequest::SignPlan {
                bytes,
                request_id: "invalid-plan-fixture".into(),
            },
            &keystore,
        );
        assert_eq!(
            Keystore::test_signing_calls(),
            before,
            "invalid input must not reach the signing primitive"
        );
        match response {
            SignResponse::Err {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, "invalid-plan-fixture");
                assert_eq!(code, HostSignerErrorCode::InvalidRequest);
                assert_eq!(message, "invalid execution plan payload");
            }
            other => panic!("expected static invalid-plan refusal, got {other:?}"),
        }
    }

    fn assert_valid_plan(bytes: Vec<u8>) {
        let plan: mvm_core::plan::ExecutionPlan = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&plan).unwrap(), bytes);
        mvm_core::plan::content_id::verify_plan_id(&plan).unwrap();
        let keystore = Keystore::generate();
        let before = Keystore::test_signing_calls();
        let response = dispatch_local(
            &SignRequest::SignPlan {
                bytes: bytes.clone(),
                request_id: "canonical-plan-fixture".into(),
            },
            &keystore,
        );
        assert_eq!(Keystore::test_signing_calls(), before + 1);
        match response {
            SignResponse::Ok {
                request_id,
                signature,
                signer_pubkey,
                ..
            } => {
                assert_eq!(request_id, "canonical-plan-fixture");
                assert_eq!(signer_pubkey, keystore.pub_key());
                let key = VerifyingKey::from_bytes(&signer_pubkey.try_into().unwrap()).unwrap();
                key.verify(
                    &bytes,
                    &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
                )
                .unwrap();
                let signed = mvm_core::plan::SignedExecutionPlan(
                    mvm_core::protocol::signing::SignedPayload {
                        payload: bytes,
                        signature,
                        signer_id: "canonical-plan-fixture".into(),
                    },
                );
                assert_eq!(
                    mvm_core::plan::verify_plan(&signed, &[("canonical-plan-fixture", &key)])
                        .unwrap(),
                    plan
                );
            }
            other => panic!("expected exact-payload signature, got {other:?}"),
        }
    }

    #[test]
    fn sign_plan_payload_accepts_exact_current_core_payload() {
        assert_valid_plan(core_plan_payload());
    }

    #[test]
    fn sign_plan_payload_keeps_the_existing_supported_schema_rule() {
        let mut plan: mvm_core::plan::ExecutionPlan =
            serde_json::from_slice(&core_plan_payload()).unwrap();
        plan.schema_version = 0;
        assert_valid_plan(encode_core_plan(&plan));
    }

    #[test]
    fn sign_plan_payload_caps_direct_dispatch_without_a_new_smaller_limit() {
        let mut plan: mvm_core::plan::ExecutionPlan =
            serde_json::from_slice(&core_plan_payload()).unwrap();
        plan.audit_labels.insert("padding".into(), String::new());
        let overhead = encode_core_plan(&plan).len();
        let padding = DEFAULT_MAX_FRAME_BYTES.checked_sub(overhead).unwrap();
        plan.audit_labels
            .insert("padding".into(), "x".repeat(padding));
        let at_limit = encode_core_plan(&plan);
        assert_eq!(at_limit.len(), DEFAULT_MAX_FRAME_BYTES);
        assert_valid_plan(at_limit);
        plan.audit_labels.get_mut("padding").unwrap().push('x');
        let oversized = encode_core_plan(&plan);
        assert_eq!(oversized.len(), DEFAULT_MAX_FRAME_BYTES + 1);
        assert_invalid_plan(oversized);
    }

    #[test]
    fn sign_plan_payload_handles_many_drive_roots_without_reordering() {
        use mvm_contract::grants::{DriveGrant, DriveProgramId, Grants, WorkspaceRoot};
        use std::num::{NonZeroU32, NonZeroU64};
        let mut plan: mvm_core::plan::ExecutionPlan =
            serde_json::from_slice(&core_plan_payload()).unwrap();
        plan.grants = Some(Grants {
            drive: Some(DriveGrant {
                workspace_roots: (0..4096)
                    .rev()
                    .map(|index| WorkspaceRoot::parse(format!("/r{index:04}")).unwrap())
                    .collect(),
                program_id: DriveProgramId::parse("agent").unwrap(),
                max_bytes_in: NonZeroU64::new(64).unwrap(),
                max_bytes_out: NonZeroU64::new(64).unwrap(),
                ttl: NonZeroU32::new(1).unwrap(),
            }),
            ..Grants::default()
        });
        let bytes = encode_core_plan(&plan);
        assert!(bytes.len() < DEFAULT_MAX_FRAME_BYTES);
        assert_valid_plan(bytes);
    }

    #[test]
    fn sign_plan_payload_rejects_nonplan_and_cross_purpose_bytes() {
        for bytes in [
            Vec::new(),
            b"arbitrary bytes".to_vec(),
            b"mvm.prebirth.grant.v1\0{}".to_vec(),
            br#"{"verb":"sign_telemetry_handshake","request_id":"fixture"}"#.to_vec(),
            b"[]".to_vec(),
        ] {
            assert_invalid_plan(bytes);
        }
    }

    #[test]
    fn sign_plan_payload_rejects_wrong_identity_and_future_schema() {
        let mut plan: mvm_core::plan::ExecutionPlan =
            serde_json::from_slice(&core_plan_payload()).unwrap();
        plan.plan_id = mvm_core::plan::PlanId(format!("sha256:{}", "0".repeat(64)));
        assert_invalid_plan(serde_json::to_vec(&plan).unwrap());
        plan.schema_version = mvm_core::plan::SCHEMA_VERSION.checked_add(1).unwrap();
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        assert_invalid_plan(serde_json::to_vec(&plan).unwrap());
    }

    #[test]
    fn sign_plan_payload_rejects_noncanonical_duplicate_and_unknown_json() {
        let bytes = core_plan_payload();
        let plan: mvm_core::plan::ExecutionPlan = serde_json::from_slice(&bytes).unwrap();
        let mut trailing = bytes.clone();
        trailing.push(b' ');
        assert_invalid_plan(trailing);
        assert_invalid_plan(serde_json::to_vec_pretty(&plan).unwrap());

        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let reordered = serde_json::to_vec(&value).unwrap();
        assert_ne!(bytes, reordered);
        assert_invalid_plan(reordered);
        value["unexpected"] = serde_json::json!("must-not-appear-in-diagnostics");
        assert_invalid_plan(serde_json::to_vec(&value).unwrap());

        let text = String::from_utf8(bytes).unwrap();
        let field = format!("\"schema_version\":{}", mvm_core::plan::SCHEMA_VERSION);
        assert_eq!(text.matches(&field).count(), 1);
        assert_invalid_plan(
            text.replacen(&field, &format!("{field},{field}"), 1)
                .into_bytes(),
        );
    }

    #[test]
    fn sign_plan_payload_rejects_deep_and_overflow_inputs_without_signing() {
        assert_invalid_plan(format!("{}0{}", "[".repeat(256), "]".repeat(256)).into_bytes());
        let bytes = core_plan_payload();
        let plan: mvm_core::plan::ExecutionPlan = serde_json::from_slice(&bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let field = format!("\"plan_version\":{}", plan.plan_version);
        assert_eq!(text.matches(&field).count(), 1);
        assert_invalid_plan(
            text.replacen(&field, "\"plan_version\":18446744073709551616", 1)
                .into_bytes(),
        );
    }

    #[test]
    fn sign_plan_payload_rejects_nested_duplicate_labels_without_signing() {
        let mut plan: mvm_core::plan::ExecutionPlan =
            serde_json::from_slice(&core_plan_payload()).unwrap();
        plan.audit_labels.clear();
        plan.audit_labels.insert("label".into(), "value".into());
        let text = String::from_utf8(encode_core_plan(&plan)).unwrap();
        let field = "\"audit_labels\":{\"label\":\"value\"}";
        assert_eq!(text.matches(field).count(), 1);
        assert_invalid_plan(
            text.replacen(
                field,
                "\"audit_labels\":{\"label\":\"value\",\"label\":\"value\"}",
                1,
            )
            .into_bytes(),
        );
    }

    #[cfg(unix)]
    #[test]
    fn telemetry_handshake_keeps_its_purpose_and_actual_signature() {
        use mvm_core::net::telemetry::{
            TelemetryReceiver, TelemetrySender, handshake_signing_bytes,
        };
        use mvm_core::protocol::host_signer::TelemetryHandshake;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        let keystore = Keystore::generate();
        let host_key = keystore.verifying_key();
        let guest_key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
        let guest_public = guest_key.verifying_key();
        let (mut host_io, mut guest_io) = UnixStream::pair().unwrap();
        for stream in [&host_io, &guest_io] {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
        }
        let guest = std::thread::spawn(move || {
            let _sender = TelemetrySender::connect(&mut guest_io, guest_key, &host_key).unwrap();
        });
        let before = Keystore::test_signing_calls();
        let mut transcript = None;
        let _receiver = TelemetryReceiver::connect_authenticated(
            &mut host_io,
            &host_key,
            &guest_public,
            |hello, ack| {
                let bytes = handshake_signing_bytes(hello, ack, &host_key).unwrap();
                let response = dispatch_local(
                    &SignRequest::SignTelemetryHandshake {
                        handshake: Box::new(TelemetryHandshake {
                            hello: hello.clone(),
                            ack: ack.clone(),
                        }),
                        request_id: "telemetry-fixture".into(),
                    },
                    &keystore,
                );
                let SignResponse::Ok { signature, .. } = response else {
                    panic!("valid telemetry handshake must retain its signing route");
                };
                let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
                host_key.verify(&bytes, &signature).unwrap();
                transcript = Some(bytes);
                Ok(signature)
            },
        )
        .unwrap();
        guest.join().unwrap();
        assert_eq!(Keystore::test_signing_calls(), before + 1);
        assert_invalid_plan(transcript.unwrap());
    }

    async fn spawn_helper_mock(
        path: PathBuf,
        response: SignerHelperResponse,
        captured: Arc<Mutex<Option<SignerHelperRequest>>>,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let req: SignerHelperRequest = crate::framing::read_json_frame(&mut stream, 65_536)
                .await
                .unwrap();
            *captured.lock().await = Some(req);
            crate::framing::write_json_frame(&mut stream, &response)
                .await
                .unwrap();
        })
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
        let plan_bytes = core_plan_payload();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn helper_proxy_forwards_sign_plan_to_signer_helper() {
        let dir = tempdir().unwrap();
        let signer_path = uds_path(&dir);
        let helper_path = dir.path().join("signer-helper.sock");
        let listener = UnixListener::bind(&signer_path).unwrap();
        let captured = Arc::new(Mutex::new(None));

        let helper = spawn_helper_mock(
            helper_path.clone(),
            SignerHelperResponse::HostSigned {
                request_id: "req-helper".into(),
                response: SignResponse::Ok {
                    request_id: "req-helper".into(),
                    sig_alg: SIG_ALG_ED25519,
                    signature: vec![2u8; 64],
                    signer_pubkey: vec![3u8; 32],
                },
            },
            captured.clone(),
        )
        .await;
        tokio::task::yield_now().await;

        let server_task = tokio::spawn(async move {
            let _ = serve_via_helper_on_listener(
                listener,
                SignerHelperClient::new(helper_path),
                "wl-test".into(),
                65_536,
            )
            .await;
        });
        tokio::task::yield_now().await;

        let mut client = ClientStream::connect(&signer_path).await.unwrap();
        let req = SignRequest::SignPlan {
            bytes: core_plan_payload(),
            request_id: "req-helper".into(),
        };
        write_req(&mut client, &req).await.unwrap();
        let resp = read_resp(&mut client).await.unwrap();

        match resp {
            SignResponse::Ok {
                request_id,
                signature,
                signer_pubkey,
                ..
            } => {
                assert_eq!(request_id, "req-helper");
                assert_eq!(signature, vec![2u8; 64]);
                assert_eq!(signer_pubkey, vec![3u8; 32]);
            }
            other => panic!("expected Ok response, got {other:?}"),
        }
        let captured_req = captured.lock().await.clone().expect("helper request");
        assert!(matches!(captured_req, SignerHelperRequest::SignHost(_)));

        server_task.abort();
        helper.abort();
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
