//! The collector as a real subprocess: config on stdin, the required dialer
//! sequence against a transport-level guest double, the delegated resident
//! signer, and the observable outputs the spawner and doctor read.
#![cfg(unix)]

use std::io::Write as _;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use mvm_hostd::audit_signer::helper::{SignerHelper, serve_on_listener};
use mvm_hostd::audit_signer::helper_client::DEFAULT_HELPER_MAX_FRAME_BYTES;
use mvm_vmm::host::telemetry_collector_spawn::{
    TELEMETRY_COLLECTOR_STATUS_FILE, TELEMETRY_RECORDS_FILE, TelemetryCollectorProcessConfig,
};
use tokio::sync::Mutex;

fn collector_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mvm-telemetry-collector")
}

fn spawn_collector_process(config: &TelemetryCollectorProcessConfig) -> Child {
    let mut child = Command::new(collector_bin())
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn collector bin");
    let stdin = child.stdin.as_mut().expect("stdin piped");
    stdin
        .write_all(serde_json::to_string(config).unwrap().as_bytes())
        .unwrap();
    drop(child.stdin.take());
    child
}

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
async fn the_collector_process_dials_the_serving_guest_and_persists_what_it_receives() {
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

    // The registered guest, served by the REAL guest half over the bridged
    // socket the backend would provide.
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
        // Hold the session open until the collector is killed.
        let mut sink = [0u8; 16];
        use std::io::Read as _;
        while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
    });

    let config = TelemetryCollectorProcessConfig {
        vm_name: "vm-e2e".into(),
        state_dir: state_dir.clone(),
        telemetry_sock,
        signer_sock,
        host_anchor_path: anchor_path,
        records_byte_cap: 64 * 1024,
    };
    let mut child = spawn_collector_process(&config);

    // Readiness first (the spawner's contract), then the session's effects.
    let status_path = state_dir.join(TELEMETRY_COLLECTOR_STATUS_FILE);
    wait_for("the status file", Duration::from_secs(10), || {
        status_path.exists()
    });
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

    child.kill().unwrap();
    child.wait().unwrap();
    let _ = guest.join();
    signer.abort();
}

#[test]
fn a_config_with_unknown_fields_is_refused_before_anything_runs() {
    let mut child = Command::new(collector_bin())
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn collector bin");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"vm_name":"x","surprise":true}"#)
        .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid config"), "{stderr}");
}
