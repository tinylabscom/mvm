//! The full guest-telemetry chain, composed the way a host collector must
//! compose it: register the boot, resolve the expected peer, assert it is
//! current, and only then authenticate the receiver against the guest's
//! actual serving half. The registration-gate test pins the sequence in
//! isolation; this witness runs the sequence against
//! `serve_telemetry_connection` — the code a real guest runs — over a live
//! stream, so the two halves cannot drift apart unnoticed.

use std::os::unix::net::UnixStream;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use mvm_agentd::telemetry_service::{AGENT_COVERAGE_CODE, SessionEnd, serve_telemetry_connection};
use mvm_core::net::telemetry::{TelemetryReceiver, handshake_signing_bytes};
use mvm_core::protocol::telemetry::{CoverageState, RecordBody, TelemetryRecord};
use mvm_vmm::host::telemetry_registration::{
    assert_peer_is_current, register_telemetry_boot, resolve_expected_telemetry_peer,
};

fn registered_guest_key(state: &std::path::Path, vm: &str, seed: u8) -> SigningKey {
    let guest_key = SigningKey::from_bytes(&[seed; 32]);
    let key_b64 =
        base64::engine::general_purpose::STANDARD.encode(guest_key.verifying_key().as_bytes());
    register_telemetry_boot(state, vm, &key_b64).unwrap();
    guest_key
}

/// Dial the guest half under `expected`, returning the first record if the
/// session authenticates. The guest side is the real serving function, not a
/// test double.
fn dial_serving_guest(
    guest_key: SigningKey,
    anchor_key: &SigningKey,
    expected: VerifyingKey,
) -> (Option<TelemetryRecord>, SessionEnd) {
    let anchor = anchor_key.verifying_key();
    let (mut host, mut guest) = UnixStream::pair().unwrap();
    let guest_half =
        std::thread::spawn(move || serve_telemetry_connection(&mut guest, guest_key, &anchor));
    let signer = anchor_key.clone();
    let received = TelemetryReceiver::connect_with_signer(&mut host, &anchor, &expected, {
        move |hello, ack| {
            let bytes =
                handshake_signing_bytes(hello, ack, &signer.verifying_key()).map_err(|_| {
                    mvm_core::net::session::SessionError::InvalidHandshake("bad handshake".into())
                })?;
            Ok(signer.sign(&bytes))
        }
    })
    .ok()
    .and_then(|mut receiver| receiver.receive(&mut host).ok());
    drop(host);
    (received, guest_half.join().unwrap())
}

#[test]
fn the_resolved_registration_dials_the_serving_guest_and_receives_coverage() {
    let state = tempfile::tempdir().unwrap();
    let anchor_key = SigningKey::from_bytes(&[31; 32]);
    let guest_key = registered_guest_key(state.path(), "vm-chain", 32);

    let peer = resolve_expected_telemetry_peer(state.path(), "vm-chain").unwrap();
    assert_peer_is_current(state.path(), &peer).unwrap();

    let (record, end) = dial_serving_guest(guest_key, &anchor_key, peer.key);
    assert_eq!(end, SessionEnd::PeerClosed);
    let record = record.expect("the registered peer's session yields the coverage record");
    match *record.body() {
        RecordBody::Coverage { state, ref code } => {
            assert_eq!(state, CoverageState::Started);
            assert_eq!(code.as_str(), AGENT_COVERAGE_CODE);
        }
        ref other => panic!("expected coverage, got {other:?}"),
    }
}

#[test]
fn a_reregistered_boot_refuses_at_the_gate_before_any_dial() {
    let state = tempfile::tempdir().unwrap();
    let guest_key = registered_guest_key(state.path(), "vm-warm", 33);
    let peer = resolve_expected_telemetry_peer(state.path(), "vm-warm").unwrap();

    // A warm-claim-shaped re-registration under the same key supersedes the
    // resolved expectation; the required sequence refuses before connecting.
    let key_b64 =
        base64::engine::general_purpose::STANDARD.encode(guest_key.verifying_key().as_bytes());
    register_telemetry_boot(state.path(), "vm-warm", &key_b64).unwrap();
    assert_peer_is_current(state.path(), &peer)
        .expect_err("a superseded expectation must refuse before any dial");
}

#[test]
fn a_guest_serving_a_key_other_than_the_registered_one_fails_the_session() {
    let state = tempfile::tempdir().unwrap();
    let anchor_key = SigningKey::from_bytes(&[34; 32]);
    let _registered = registered_guest_key(state.path(), "vm-imposter", 35);
    let peer = resolve_expected_telemetry_peer(state.path(), "vm-imposter").unwrap();
    assert_peer_is_current(state.path(), &peer).unwrap();

    // The gate passes — the registration is current — but the guest on the
    // wire holds a different key, so the authenticated session itself must
    // refuse, and no record crosses.
    let imposter = SigningKey::from_bytes(&[36; 32]);
    let (record, end) = dial_serving_guest(imposter, &anchor_key, peer.key);
    assert!(
        record.is_none(),
        "no record may cross an unauthenticated session"
    );
    assert_eq!(end, SessionEnd::Failed);
}
