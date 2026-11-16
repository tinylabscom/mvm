#![cfg(unix)]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

use mvm_core::protocol::audit_signer::{SignerHelperRequest, SignerHelperResponse};
use mvm_core::protocol::host_signer::{SignRequest, SignResponse};
use mvm_core::signer_helper as core;
use mvm_hostd::audit_signer::helper_client as hostd;

#[tokio::test]
async fn facade_preserves_type_identity_exchange_and_caller_cap() {
    for cap in [hostd::DEFAULT_HELPER_MAX_FRAME_BYTES, 0] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let client: core::SignerHelperClient =
            hostd::SignerHelperClient::new(path).with_max_frame_bytes(cap);
        let client: hostd::SignerHelperClient = client;
        let (sender, receiver) = std::sync::mpsc::channel();
        let client_thread = std::thread::spawn(move || {
            let result = client.sign_host(SignRequest::SignPlan {
                bytes: b"plan".to_vec(),
                request_id: "compat".into(),
            });
            let _ = sender.send(result);
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut prefix = [0; 4];
            peer.read_exact(&mut prefix).await.unwrap();
            let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
            peer.read_exact(&mut body).await.unwrap();
            let request: SignerHelperRequest = serde_json::from_slice(&body).unwrap();
            let SignerHelperRequest::SignHost(request) = request else {
                panic!("expected host-sign request");
            };
            assert_eq!(request.request_id, "compat");
            assert_eq!(request.request.request_id(), "compat");
            let response = SignerHelperResponse::HostSigned {
                request_id: "compat".into(),
                response: SignResponse::Ok {
                    request_id: "compat".into(),
                    sig_alg: mvm_core::security::SIG_ALG_ED25519,
                    signature: vec![0; 64],
                    signer_pubkey: vec![1; 32],
                },
            };
            let body = serde_json::to_vec(&response).unwrap();
            peer.write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
                .await
                .unwrap();
            // The zero-cap client may close immediately after the prefix.
            if cap != 0 {
                peer.write_all(&body).await.unwrap();
            }
        })
        .await
        .expect("helper fixture exchange must finish before its deadline");
        let result = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("synchronous client must finish before its fixture deadline");
        if cap == 0 {
            assert!(result.unwrap_err().to_string().contains("exceeds cap 0"));
        } else {
            assert_eq!(result.unwrap().request_id(), "compat");
        }
        client_thread.join().unwrap();
    }
}
