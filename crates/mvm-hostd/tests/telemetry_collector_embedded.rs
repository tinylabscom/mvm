//! The embedded collector as the endpoint runs it: started in-process from
//! the endpoint-config telemetry section, the required dialer sequence
//! against a transport-level guest double, the delegated resident signer,
//! and the observable status/records outputs its readers consume.
#![cfg(unix)]

use std::os::unix::net::UnixListener as StdUnixListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use mvm_hostd::audit_signer::helper::{SignerHelper, serve_on_listener};
use mvm_hostd::audit_signer::helper_client::DEFAULT_HELPER_MAX_FRAME_BYTES;
use mvm_hostd::telemetry_collector::{TelemetryEmbedConfig, start_embedded};
use mvm_vmm::host::telemetry_provisioning::{
    TELEMETRY_COLLECTOR_STATUS_FILE, TELEMETRY_RECORDS_FILE,
};
use tokio::sync::Mutex;

fn wait_for(what: &str, timeout: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_embedded_collector_dials_authenticates_and_persists_what_it_receives() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();

    // The host signer: one key, used by the resident-signer helper to sign
    // handshakes and published as the anchor the guest pins.
    let host_key = SigningKey::from_bytes(&[7; 32]);
    let key_path = dir.path().join("synthetic-key");
    std::fs::write(&key_path, [7; 32]).unwrap();
    let anchor_path = dir.path().join("host-signer.pub");
    std::fs::write(&anchor_path, host_key.verifying_key().to_bytes()).unwrap();

    let signer_sock = state_dir.join("audit-signer.sock");
    let signer_listener = tokio::net::UnixListener::bind(&signer_sock).unwrap();
    let signer = tokio::spawn(serve_on_listener(
        signer_listener,
        Arc::new(Mutex::new(SignerHelper::new("local", Some(key_path)))),
        DEFAULT_HELPER_MAX_FRAME_BYTES,
    ));

    let guest_key = SigningKey::from_bytes(&[9; 32]);
    let key_b64 =
        base64::engine::general_purpose::STANDARD.encode(guest_key.verifying_key().as_bytes());
    mvm_vmm::host::telemetry_registration::register_telemetry_boot(&state_dir, "vm-e2e", &key_b64)
        .unwrap();

    let telemetry_sock = state_dir.join("telemetry.sock");
    let guest_listener = StdUnixListener::bind(&telemetry_sock).unwrap();
    let anchor = host_key.verifying_key();
    // Guest double: the shared transport's sender playing the guest role,
    // announcing coverage the way the real serving half does. The serving
    // half itself carries its own full-chain witness.
    // The guest holds its session open until released: the collector's stop
    // is a test seam that joins the receive loop, and that loop only returns
    // at a session boundary — in production the process's death is the
    // teardown, so the test must end the session before stopping.
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let guest = std::thread::spawn(move || {
        use mvm_core::net::telemetry::TelemetrySender;
        use mvm_core::protocol::telemetry::{
            CoverageState, ProducerEpoch, RecordBody, SourceKind, TelemetryRecord,
        };
        let (mut stream, _) = guest_listener.accept().unwrap();
        let mut sender = TelemetrySender::connect(&mut stream, guest_key, &anchor).unwrap();
        let record = TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([5; 16]).unwrap())
            .producer(1)
            .sequence(1)
            .source(SourceKind::GuestAgent)
            .body(RecordBody::Coverage {
                state: CoverageState::Started,
                code: "guest-agent".try_into().unwrap(),
            })
            .build()
            .unwrap();
        sender.send(&mut stream, &record).unwrap();
        let _ = release_rx.recv();
    });

    let config = TelemetryEmbedConfig {
        state_dir: state_dir.clone(),
        telemetry_sock,
        signer_sock,
        host_anchor_path: anchor_path,
        records_byte_cap: 64 * 1024,
    };
    // Started the way the endpoint starts it, off the async runtime's thread.
    let embedded = tokio::task::spawn_blocking(move || start_embedded("vm-e2e", &config))
        .await
        .unwrap()
        .expect("embedded collector starts");

    // The first status snapshot precedes any dialing; then the session's
    // effects: the coverage record persisted and status reaching collecting.
    let status_path = state_dir.join(TELEMETRY_COLLECTOR_STATUS_FILE);
    assert!(status_path.exists(), "first snapshot precedes dialing");
    let records_path = state_dir.join(TELEMETRY_RECORDS_FILE);
    wait_for("the coverage record", Duration::from_secs(10), || {
        std::fs::read_to_string(&records_path)
            .map(|s| s.contains("guest-agent"))
            .unwrap_or(false)
    });
    wait_for("a collecting status", Duration::from_secs(10), || {
        std::fs::read_to_string(&status_path)
            .map(|s| s.contains("collecting"))
            .unwrap_or(false)
    });

    // End the guest session first so the collector's receive loop reaches a
    // boundary, then stop drains promptly.
    drop(release_tx);
    let _ = guest.join();
    tokio::task::spawn_blocking(move || embedded.stop())
        .await
        .unwrap();
    signer.abort();
}

#[test]
fn a_telemetry_section_with_unknown_fields_is_refused() {
    let refused: Result<TelemetryEmbedConfig, _> = serde_json::from_str(
        r#"{"state_dir":"/s","telemetry_sock":"/t","signer_sock":"/g",
            "host_anchor_path":"/a","records_byte_cap":1,"surprise":true}"#,
    );
    assert!(refused.is_err(), "unknown fields must fail closed");
}
