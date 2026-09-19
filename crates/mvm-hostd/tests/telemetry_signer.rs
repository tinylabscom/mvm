//! The telemetry collector delegates its handshake, not its key custody.
#![cfg(unix)]

use std::{os::unix::net::UnixStream, sync::Arc, time::Duration};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use mvm_core::{
    net::{
        session::{Session, SessionError, read_json_frame, write_json_frame},
        telemetry::{TelemetryError, TelemetryReceiver, TelemetrySender},
    },
    protocol::{
        audit_signer::{SignerHelperRequest, SignerHelperResponse, SignerHelperSignHost},
        host_signer::{HostSignerErrorCode, SignRequest, SignResponse, TelemetryHandshake},
        telemetry::{CoverageState, ProducerEpoch, RecordBody, SourceKind, TelemetryRecord},
    },
    security::{PROTOCOL_VERSION_AUTHENTICATED, SIG_ALG_ED25519, SessionHello},
};
use mvm_hostd::audit_signer::{
    helper::{SignerHelper, serve_on_listener},
    helper_client::{DEFAULT_HELPER_MAX_FRAME_BYTES, SignerHelperClient},
};
use tokio::{net::UnixListener, sync::Mutex};

fn sockets() -> (UnixStream, UnixStream) {
    let (host, guest) = UnixStream::pair().unwrap();
    for stream in [&host, &guest] {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
    }
    (host, guest)
}

fn capture_handshake() -> (TelemetryHandshake, VerifyingKey) {
    capture_handshake_for_id("mvm.telemetry.v1.00112233-4455-4677-8899-aabbccddeeff")
}

fn capture_handshake_for_id(id: &str) -> (TelemetryHandshake, VerifyingKey) {
    let (mut host, mut guest) = sockets();
    let host_key = SigningKey::from_bytes(&[7; 32]);
    let anchor = host_key.verifying_key();
    let guest_key = SigningKey::from_bytes(&[9; 32]);
    let producer = std::thread::spawn(move || Session::guest(&mut guest, guest_key, &anchor));
    let hello = SessionHello {
        version: PROTOCOL_VERSION_AUTHENTICATED,
        session_id: id.into(),
        challenge: vec![1; 32],
        host_pubkey: anchor.to_bytes().to_vec(),
        host_ephemeral_pubkey: vec![3; 32],
    };
    write_json_frame(&mut host, &hello, DEFAULT_HELPER_MAX_FRAME_BYTES).unwrap();
    let ack = read_json_frame(&mut host, DEFAULT_HELPER_MAX_FRAME_BYTES).unwrap();
    drop(host);
    assert!(
        producer.join().unwrap().is_err(),
        "fixture intentionally omits confirmation"
    );
    (TelemetryHandshake { hello, ack }, anchor)
}

fn request(handshake: TelemetryHandshake) -> SignRequest {
    SignRequest::SignTelemetryHandshake {
        handshake: Box::new(handshake),
        request_id: "telemetry-signer-test".into(),
    }
}

fn dispatch(helper: &mut SignerHelper, handshake: TelemetryHandshake) -> SignResponse {
    match helper.dispatch(SignerHelperRequest::SignHost(SignerHelperSignHost {
        request_id: "telemetry-signer-test".into(),
        request: request(handshake),
    })) {
        SignerHelperResponse::HostSigned { response, .. } => response,
        other => panic!("unexpected helper response {other:?}"),
    }
}

#[test]
fn telemetry_handshake_request_roundtrips_and_rejects_unknown_nested_fields() {
    let (handshake, _) = capture_handshake();
    let request = request(handshake);
    let bytes = serde_json::to_vec(&request).unwrap();
    assert_eq!(
        serde_json::from_slice::<SignRequest>(&bytes).unwrap(),
        request
    );
    assert_eq!(request.request_id(), "telemetry-signer-test");
    for pointer in ["/handshake", "/handshake/hello", "/handshake/ack"] {
        let mut value = serde_json::to_value(&request).unwrap();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<SignRequest>(value).is_err());
    }
}

#[test]
fn signer_helper_signs_only_a_valid_telemetry_handshake_for_its_own_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-key");
    std::fs::write(&path, [7; 32]).unwrap();
    let mut helper = SignerHelper::new("local", Some(path));
    let (handshake, anchor) = capture_handshake();
    let bytes = serde_json::to_vec(&(&handshake.hello, &handshake.ack)).unwrap();
    match dispatch(&mut helper, handshake.clone()) {
        SignResponse::Ok {
            signature,
            signer_pubkey,
            ..
        } => {
            assert_eq!(signer_pubkey, anchor.as_bytes());
            anchor
                .verify(
                    &bytes,
                    &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
                )
                .unwrap();
        }
        other => panic!("valid handshake refused: {other:?}"),
    }
    for mutation in 0..8 {
        let mut invalid = handshake.clone();
        match mutation {
            0 => {
                invalid.hello.session_id = "machine-control-secret-sentinel".into();
                invalid.ack.session_id.clone_from(&invalid.hello.session_id);
            }
            1 => {
                invalid.hello.session_id = "mvm.telemetry.v1.secret-sentinel".into();
                invalid.ack.session_id.clone_from(&invalid.hello.session_id);
            }
            2 => {
                invalid.hello.host_pubkey = SigningKey::from_bytes(&[8; 32])
                    .verifying_key()
                    .to_bytes()
                    .to_vec()
            }
            3 => invalid.hello.version = 0,
            4 => invalid.ack.guest_challenge.clear(),
            5 => invalid.ack.challenge_response.clear(),
            6 => invalid.ack.session_id = "secret-sentinel".into(),
            7 => invalid.ack.guest_ephemeral_pubkey.clear(),
            _ => unreachable!(),
        }
        let response = dispatch(&mut helper, invalid);
        assert!(
            matches!(
                response,
                SignResponse::Err {
                    code: HostSignerErrorCode::InvalidRequest,
                    ..
                }
            ),
            "mutation {mutation}: {response:?}"
        );
        assert!(!format!("{response:?}").contains("secret-sentinel"));
    }
}

#[test]
fn valid_guest_proofs_do_not_authorize_other_services_or_noncanonical_session_ids() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-key");
    std::fs::write(&path, [7; 32]).unwrap();
    let mut helper = SignerHelper::new("local", Some(path));
    for id in [
        "machine-control",
        "mvm.telemetry.v1.00112233-4455-1677-8899-aabbccddeeff",
        "mvm.telemetry.v1.00112233-4455-4677-8899-AABBCCDDEEFF",
        "mvm.telemetry.v1.not-a-uuid",
    ] {
        let (handshake, _) = capture_handshake_for_id(id);
        assert!(matches!(
            dispatch(&mut helper, handshake),
            SignResponse::Err {
                code: HostSignerErrorCode::InvalidRequest,
                ..
            }
        ));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_record_reaches_a_collector_using_the_resident_signer_socket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-key");
    std::fs::write(&path, [7; 32]).unwrap();
    let socket = dir.path().join("signer.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let service = tokio::spawn(serve_on_listener(
        listener,
        Arc::new(Mutex::new(SignerHelper::new("local", Some(path)))),
        DEFAULT_HELPER_MAX_FRAME_BYTES,
    ));
    let client = SignerHelperClient::new(socket);
    let handle = tokio::runtime::Handle::current();
    let (mut host, mut guest) = sockets();
    let anchor = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let guest_key = SigningKey::from_bytes(&[9; 32]);
    let expected_guest = guest_key.verifying_key();
    let record = TelemetryRecord::builder()
        .epoch(ProducerEpoch::new([1; 16]).unwrap())
        .producer(1)
        .sequence(1)
        .source(SourceKind::GuestAgent)
        .body(RecordBody::Coverage {
            state: CoverageState::Started,
            code: "signer-witness".try_into().unwrap(),
        })
        .build()
        .unwrap();
    let expected = record.clone();
    let producer = tokio::task::spawn_blocking(move || {
        let mut sender = TelemetrySender::connect(&mut guest, guest_key, &anchor).unwrap();
        sender.send(&mut guest, &record).unwrap();
    });
    let collector = tokio::task::spawn_blocking(move || {
        let mut receiver = TelemetryReceiver::connect_with_signer(
            &mut host,
            &anchor,
            &expected_guest,
            |hello, ack| {
                handle
                    .block_on(client.sign_telemetry_handshake(
                        hello,
                        ack,
                        &anchor,
                        Duration::from_secs(2),
                    ))
                    .map_err(|_| SessionError::InvalidHandshake("signer refused".into()))
            },
        )
        .unwrap();
        receiver.receive(&mut host).unwrap()
    });
    assert_eq!(collector.await.unwrap(), expected);
    producer.await.unwrap();
    service.abort();
    assert!(service.await.unwrap_err().is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn a_stalled_signer_request_has_one_deadline_and_closes_its_socket() {
    use tokio::io::AsyncReadExt;
    let (handshake, anchor) = tokio::task::spawn_blocking(capture_handshake)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stall.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let call = tokio::spawn(async move {
        SignerHelperClient::new(path)
            .sign_telemetry_handshake(
                &handshake.hello,
                &handshake.ack,
                &anchor,
                Duration::from_secs(2),
            )
            .await
    });
    let (mut peer, _) = listener.accept().await.unwrap();
    let _: SignerHelperRequest =
        mvm_hostd::framing::read_json_frame(&mut peer, DEFAULT_HELPER_MAX_FRAME_BYTES)
            .await
            .unwrap();
    tokio::time::advance(Duration::from_secs(3)).await;
    assert_eq!(call.await.unwrap(), Err(TelemetryError::Authentication));
    let mut byte = [0];
    assert_eq!(
        peer.read(&mut byte).await.unwrap(),
        0,
        "timed-out RPC releases the owned socket"
    );
}

#[tokio::test]
async fn signer_client_refuses_invalid_deadlines_before_connecting() {
    let (handshake, anchor) = tokio::task::spawn_blocking(capture_handshake)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let client = SignerHelperClient::new(dir.path().join("absent.sock"));
    for timeout in [Duration::ZERO, Duration::MAX] {
        assert_eq!(
            client
                .sign_telemetry_handshake(&handshake.hello, &handshake.ack, &anchor, timeout)
                .await,
            Err(TelemetryError::Authentication)
        );
    }
}

#[tokio::test]
async fn signer_client_rejects_confused_correlations_keys_algorithms_and_signatures() {
    let (handshake, anchor) = tokio::task::spawn_blocking(capture_handshake)
        .await
        .unwrap();
    let transcript = serde_json::to_vec(&(&handshake.hello, &handshake.ack)).unwrap();
    let signature = SigningKey::from_bytes(&[7; 32])
        .sign(&transcript)
        .to_bytes()
        .to_vec();
    for mutation in 0..7 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reply.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let mut response = SignResponse::Ok {
            request_id: handshake.hello.session_id.clone(),
            sig_alg: SIG_ALG_ED25519,
            signature: signature.clone(),
            signer_pubkey: anchor.to_bytes().to_vec(),
        };
        if let SignResponse::Ok {
            request_id,
            sig_alg,
            signature,
            signer_pubkey,
        } = &mut response
        {
            match mutation {
                0 => *request_id = "wrong-inner".into(),
                1 => *sig_alg = 0,
                2 => signer_pubkey.fill(0),
                3 => signature.clear(),
                4 => signature[0] ^= 1,
                5 | 6 => {}
                _ => unreachable!(),
            }
        }
        if mutation == 6 {
            response = SignResponse::Err {
                request_id: handshake.hello.session_id.clone(),
                code: HostSignerErrorCode::KeyUnavailable,
                message: "secret-sentinel".into(),
            };
        }
        let outer = if mutation == 5 {
            "wrong-outer".into()
        } else {
            handshake.hello.session_id.clone()
        };
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let _: SignerHelperRequest =
                mvm_hostd::framing::read_json_frame(&mut peer, DEFAULT_HELPER_MAX_FRAME_BYTES)
                    .await
                    .unwrap();
            mvm_hostd::framing::write_json_frame(
                &mut peer,
                &SignerHelperResponse::HostSigned {
                    request_id: outer,
                    response,
                },
            )
            .await
            .unwrap();
        });
        let result = SignerHelperClient::new(path)
            .sign_telemetry_handshake(
                &handshake.hello,
                &handshake.ack,
                &anchor,
                Duration::from_secs(2),
            )
            .await;
        assert_eq!(
            result,
            Err(TelemetryError::Authentication),
            "mutation {mutation}"
        );
        assert!(!format!("{result:?}").contains("secret-sentinel"));
        server.await.unwrap();
    }
}
