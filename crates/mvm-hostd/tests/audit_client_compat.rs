//! Public-path compatibility over bounded Unix fixtures and in-process signers.
#![cfg(unix)]

use std::path::Path;
use std::time::Duration;

use mvm_core::protocol::audit_signer::{
    AppendEntryRequest, AppendEntryResponse, AuditSignerErrorCode, SignerHelperRequest,
    SignerHelperResponse,
};
use mvm_core::security::SIG_ALG_ED25519;
use mvm_hostd::audit::audit_client as audit;
use mvm_hostd::broker::audit_client as broker;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
enum Route {
    Direct,
    Helper,
}

impl Route {
    fn client(self, path: &Path) -> audit::AuditClient {
        let client: broker::AuditClient = match self {
            Self::Direct => audit::AuditClient::new(path),
            Self::Helper => broker::AuditClient::new_signer_helper(path, "vm-compat"),
        };
        client
    }
}

fn request() -> AppendEntryRequest {
    AppendEntryRequest::AppendEntry {
        request_id: "compat".into(),
        category: "workload_audit".into(),
        ts: "2026-05-28T00:00:00Z".into(),
        workload_id: "workload".into(),
        tenant_id: "local".into(),
        session_id: "session".into(),
        correlation_id: "correlation".into(),
        fields: serde_json::json!({"event": "compat"}),
    }
}

async fn exchange(
    route: Route,
    response: &[u8],
    cap: usize,
) -> Result<AppendEntryResponse, audit::AuditClientError> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let client = route.client(&path).with_max_frame_bytes(cap);
    let request = request();
    let peer = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let len = stream.read_u32().await.unwrap();
        assert!(len <= 65_536, "fixture request must be bounded");
        let mut body = vec![0; len as usize];
        stream.read_exact(&mut body).await.unwrap();
        match route {
            Route::Direct => {
                let received: AppendEntryRequest = serde_json::from_slice(&body).unwrap();
                assert_eq!(received, request);
            }
            Route::Helper => {
                let received: SignerHelperRequest = serde_json::from_slice(&body).unwrap();
                let SignerHelperRequest::AppendEntry(received) = received else {
                    panic!("expected helper append");
                };
                assert_eq!(received.vm_id, "vm-compat");
                let mut received = serde_json::to_value(received).unwrap();
                received.as_object_mut().unwrap().remove("vm_id");
                let mut expected = serde_json::to_value(&request).unwrap();
                expected.as_object_mut().unwrap().remove("verb");
                assert_eq!(received, expected);
            }
        }
        stream
            .write_u32(u32::try_from(response.len()).unwrap())
            .await
            .unwrap();
        // Oversized frames need only a prefix; the client must refuse before reading a body.
        if response.len() <= cap {
            stream.write_all(response).await.unwrap();
        }
    };
    // Both futures are owned here: timeout or panic drops every socket, without detached tasks.
    let (result, ()) = tokio::time::timeout(DEADLINE, async {
        tokio::join!(client.append(&request), peer)
    })
    .await
    .expect("client and fixture must finish within the deadline");
    let result: Result<AppendEntryResponse, broker::AuditClientError> = result;
    result
}

#[tokio::test]
async fn both_routes_preserve_type_identity_and_successful_append() {
    let expected = AppendEntryResponse::Ok {
        request_id: "compat".into(),
        chain_head: "head".into(),
        entry_hash: "hash".into(),
        sig_alg: SIG_ALG_ED25519,
    };
    let helper = SignerHelperResponse::Ok {
        request_id: "compat".into(),
        chain_head: "head".into(),
        entry_hash: "hash".into(),
        sig_alg: SIG_ALG_ED25519,
    };
    for (route, bytes) in [
        (Route::Direct, serde_json::to_vec(&expected).unwrap()),
        (Route::Helper, serde_json::to_vec(&helper).unwrap()),
    ] {
        assert_eq!(exchange(route, &bytes, 65_536).await.unwrap(), expected);
    }
}

#[tokio::test]
async fn both_routes_preserve_typed_signer_refusals_and_response_caps() {
    let expected = AppendEntryResponse::Err {
        request_id: "compat".into(),
        code: AuditSignerErrorCode::InvalidRequest,
        message: "category refused".into(),
    };
    let helper = SignerHelperResponse::Err {
        request_id: "compat".into(),
        code: AuditSignerErrorCode::InvalidRequest,
        message: "category refused".into(),
    };
    for (route, bytes) in [
        (Route::Direct, serde_json::to_vec(&expected).unwrap()),
        (Route::Helper, serde_json::to_vec(&helper).unwrap()),
    ] {
        assert_eq!(
            exchange(route, &bytes, bytes.len()).await.unwrap(),
            expected
        );
        let error: broker::AuditClientError = exchange(route, &bytes, 0).await.unwrap_err();
        let error: audit::AuditClientError = error;
        assert!(matches!(
            error,
            audit::AuditClientError::ResponseTooLarge { size, cap: 0, path }
                if size == bytes.len() && path.ends_with("audit.sock")
        ));
    }
}

#[tokio::test]
async fn both_routes_preserve_decode_and_connect_errors() {
    for route in [Route::Direct, Route::Helper] {
        assert!(matches!(
            exchange(route, b"not-json", 65_536).await.unwrap_err(),
            broker::AuditClientError::Decode { .. }
        ));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.sock");
        let error = tokio::time::timeout(DEADLINE, route.client(&path).append(&request()))
            .await
            .expect("missing socket must refuse promptly")
            .unwrap_err();
        assert!(
            matches!(error, audit::AuditClientError::Connect { path: actual, .. } if actual == path)
        );
    }
}

#[tokio::test]
async fn helper_preserves_unexpected_response_protocol_error() {
    let bytes = serde_json::to_vec(&SignerHelperResponse::Deregistered {
        request_id: "compat".into(),
        vm_id: "vm-compat".into(),
    })
    .unwrap();
    assert!(matches!(
        exchange(Route::Helper, &bytes, 65_536).await.unwrap_err(),
        broker::AuditClientError::Protocol { message, .. }
            if message == "signer helper returned a non-append response to append"
    ));
}

#[tokio::test]
async fn both_routes_append_through_real_in_process_signers() {
    use std::sync::Arc;

    use mvm_core::protocol::audit_signer::SignerHelperRegisterVm;
    use mvm_hostd::audit_signer::{chain::Chain, helper, server};
    use tokio::sync::Mutex;

    let dir = tempfile::tempdir().unwrap();
    let direct_path = dir.path().join("direct.sock");
    let helper_path = dir.path().join("helper.sock");
    let direct_log = dir.path().join("direct.jsonl");
    let helper_log = dir.path().join("helper.jsonl");
    let chain = Chain::open(&direct_log, &dir.path().join("direct.head"), None).unwrap();
    let mut signer = helper::SignerHelper::new("local", None);
    assert!(matches!(
        signer.dispatch(SignerHelperRequest::RegisterVm(SignerHelperRegisterVm {
            request_id: "register".into(),
            vm_id: "vm-compat".into(),
            tenant_id: "local".into(),
            workload_id: "workload".into(),
            workload_chain_path: helper_log.to_str().unwrap().into(),
            chain_head_secondary_path: dir.path().join("helper.head").to_str().unwrap().into(),
        })),
        SignerHelperResponse::Registered { .. }
    ));
    let direct_listener = UnixListener::bind(&direct_path).unwrap();
    let helper_listener = UnixListener::bind(&helper_path).unwrap();
    let clients = async {
        for (route, path) in [(Route::Direct, &direct_path), (Route::Helper, &helper_path)] {
            let client = route.client(path);
            let response = client.append(&request()).await.unwrap();
            let AppendEntryResponse::Ok {
                request_id,
                chain_head,
                entry_hash,
                sig_alg,
            } = response
            else {
                panic!("real signer must append");
            };
            assert_eq!(request_id, "compat");
            assert_eq!(chain_head, entry_hash);
            assert_eq!(chain_head.len(), 64);
            assert_eq!(sig_alg, SIG_ALG_ED25519);

            let mut refused = request();
            if let AppendEntryRequest::AppendEntry { category, .. } = &mut refused {
                *category = "unknown-category".into();
            }
            assert!(matches!(
                client.append(&refused).await.unwrap(),
                AppendEntryResponse::Err {
                    code: AuditSignerErrorCode::InvalidRequest,
                    ..
                }
            ));
        }
    };
    // The accept loops are owned by this select; its completion drops both listeners.
    // Their connection tasks live only within this test's runtime.
    tokio::time::timeout(DEADLINE, async {
        tokio::select! {
            () = clients => {},
            result = server::serve_on_listener(
                direct_listener, Arc::new(Mutex::new(chain)), "workload".into(), 65_536,
            ) => panic!("direct server stopped: {result:?}"),
            result = helper::serve_on_listener(
                helper_listener, Arc::new(Mutex::new(signer)), 65_536,
            ) => panic!("helper server stopped: {result:?}"),
        }
    })
    .await
    .expect("real signer exchanges must finish within the deadline");
    for log in [direct_log, helper_log] {
        assert_eq!(std::fs::read_to_string(log).unwrap().lines().count(), 1);
    }
}
