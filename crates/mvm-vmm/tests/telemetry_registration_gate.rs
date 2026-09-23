//! The registration gate is the only thing that distinguishes boots sharing
//! a key: a warm child inherits its parent's signing key, so the encrypted
//! session authenticates both boots equally. A dialer must therefore resolve
//! the current registration, assert its expectation is current, and only then
//! authenticate — this test pins that required sequence and the refusal.

use std::os::unix::net::UnixStream;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use mvm_core::net::telemetry::{TelemetryReceiver, TelemetrySender};
use mvm_vmm::host::telemetry_registration::{
    assert_peer_is_current, register_telemetry_boot, resolve_expected_telemetry_peer,
};

#[test]
fn a_stale_boot_expectation_is_refused_even_though_the_session_still_authenticates() {
    let state = tempfile::tempdir().unwrap();
    let anchor_key = SigningKey::from_bytes(&[7; 32]);
    let anchor = anchor_key.verifying_key();
    let guest_key = SigningKey::from_bytes(&[9; 32]);
    let key_b64 =
        base64::engine::general_purpose::STANDARD.encode(guest_key.verifying_key().as_bytes());

    // Boot one: register, resolve, and authenticate under the resolved peer.
    register_telemetry_boot(state.path(), "vm-a", &key_b64).unwrap();
    let peer = resolve_expected_telemetry_peer(state.path(), "vm-a").unwrap();
    assert_peer_is_current(state.path(), &peer).unwrap();

    let handshake = |expected: ed25519_dalek::VerifyingKey| {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        let guest_key = guest_key.clone();
        let producer = std::thread::spawn(move || {
            TelemetrySender::connect(&mut guest, guest_key, &anchor).map(|_| ())
        });
        let signer = anchor_key.clone();
        let outcome =
            TelemetryReceiver::connect_with_signer(&mut host, &anchor, &expected, |hello, ack| {
                use ed25519_dalek::Signer as _;
                let bytes = mvm_core::net::telemetry::handshake_signing_bytes(hello, ack, &anchor)
                    .map_err(|_| {
                        mvm_core::net::session::SessionError::InvalidHandshake(
                            "bad handshake".into(),
                        )
                    })?;
                Ok(signer.sign(&bytes))
            })
            .map(|_| ());
        let _ = producer.join();
        outcome
    };
    handshake(peer.key).expect("the current boot authenticates under its registration");

    // Boot two: a warm-claim-shaped re-registration under the SAME key.
    register_telemetry_boot(state.path(), "vm-a", &key_b64).unwrap();

    // The cryptographic session cannot tell the boots apart — the same key
    // still authenticates. Only the registration gate refuses the stale boot.
    handshake(peer.key).expect("the session alone cannot distinguish boots sharing a key");
    let refusal = assert_peer_is_current(state.path(), &peer)
        .expect_err("a superseded boot expectation must be refused");
    assert!(refusal.to_string().contains("stale"), "{refusal}");

    // The required sequence, repeated for the new boot, succeeds.
    let fresh = resolve_expected_telemetry_peer(state.path(), "vm-a").unwrap();
    assert_peer_is_current(state.path(), &fresh).unwrap();
    assert_eq!(fresh.key, peer.key);
    assert!(fresh.generation > peer.generation);
}
