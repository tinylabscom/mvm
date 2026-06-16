//! End-to-end host-spine test of the `host.audit.v1` round-trip over the real
//! `mvm-broker` + `mvm-audit-signer` subprocesses — the path a guest's
//! `mvm.audit.emit` drives once it reaches `BROKER_PORT`, exercised here on the
//! host with no VM and no language veneer.
//!
//! Spawns both bins (their UDS-bind is the readiness signal — neither emits a
//! stdout handshake), connects a client to the broker UDS, sends a
//! `host.audit.v1::emit` `ServiceCall`, and then **verifies the resulting
//! per-VM workload chain** with `verify_workload_chain` against the host-signer
//! public key. Proves spawn → broker dispatch → audit-signer chain-sign →
//! `workload_audit`-categorised, host-key-signed, verifiable entry — the whole
//! E5.3b host spine end to end.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceId, ServiceResponse};
use mvm_core::protocol::host_audit::{EmitRequest, EmitResponse};
use mvm_hostd::audit::host_keypair;
use mvm_hostd::audit_signer::verify::verify_workload_chain;

const BROKER_BIN: &str = env!("CARGO_BIN_EXE_mvm-broker");
const AUDIT_SIGNER_BIN: &str = env!("CARGO_BIN_EXE_mvm-audit-signer");

fn write_frame<W: Write>(w: &mut W, value: &impl serde::Serialize) {
    let body = serde_json::to_vec(value).unwrap();
    w.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    w.write_all(&body).unwrap();
    w.flush().unwrap();
}

fn read_frame<R: Read, T: serde::de::DeserializeOwned>(r: &mut R) -> T {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).unwrap();
    let n = u32::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).unwrap();
    serde_json::from_slice(&buf).unwrap()
}

/// Spawn `bin` with `cfg` JSON on stdin (closed after, so the bin proceeds to
/// bind), stdout/stderr discarded (the bins log JSON to stderr).
fn spawn_with_config(bin: &str, cfg: &serde_json::Value) -> Child {
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {bin}: {e}"));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(cfg).unwrap())
        .unwrap();
    child
}

/// Poll for `path` to appear (the bins emit no handshake — UDS-bind is ready).
fn wait_for_path(path: &std::path::Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if Instant::now() >= deadline {
            panic!("{} never appeared within {timeout:?}", path.display());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Kills the child on drop so a panicking assertion never leaks a process.
struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn host_audit_v1_round_trip_signs_a_verifiable_workload_chain() {
    let dir = tempfile::tempdir().unwrap();
    let keys_dir = dir.path().join("keys");

    // The audit-signer chain key + the broker's verify pubkey are the one
    // host-signer keypair (the same identity the claim-8 lifecycle chain uses).
    let signer = host_keypair::load_or_init_at(&keys_dir).expect("host signer");
    let secret_key = keys_dir.join(host_keypair::SECRET_FILENAME);
    let public_key = keys_dir.join(host_keypair::PUBLIC_FILENAME);

    let audit_sock = dir.path().join("audit-signer.sock");
    let broker_sock = dir.path().join("broker.sock");
    // The per-VM workload chain the audit-signer appends to + the verifier reads.
    let workload_chain = dir.path().join("local.vm-it.workload.jsonl");

    // ── audit-signer: binds `audit_sock`, signs into `workload_chain` ──
    let audit_cfg = serde_json::json!({
        "workload_id": "wl-it",
        "tenant_id": "local",
        "uds_path": audit_sock,
        "audit_jsonl_path": workload_chain,
        "chain_head_secondary_path": dir.path().join("audit-signer.head"),
        "software_chain_key_path": secret_key,
    });
    let _audit_guard = Kill(spawn_with_config(AUDIT_SIGNER_BIN, &audit_cfg));
    wait_for_path(&audit_sock, Duration::from_secs(10));

    // ── broker: binds `broker_sock`, forwards host.audit.v1 to `audit_sock` ──
    let broker_cfg = serde_json::json!({
        "workload_id": "wl-it",
        "tenant_id": "local",
        "uds_path": broker_sock,
        "host_signer_public_key_path": public_key,
        "audit_signer_uds_path": audit_sock,
    });
    let _broker_guard = Kill(spawn_with_config(BROKER_BIN, &broker_cfg));
    wait_for_path(&broker_sock, Duration::from_secs(10));

    // ── the workload's emit, as it arrives at the broker UDS ──
    let mut conn = UnixStream::connect(&broker_sock).expect("connect to broker UDS");
    let call = ServiceCall {
        service: ServiceId::parse("host.audit.v1").unwrap(),
        verb: "emit".into(),
        correlation_id: CorrelationId::new("guest-supplied-ignored"),
        payload: serde_json::to_value(EmitRequest {
            ts: "2026-06-16T00:00:00Z".into(),
            fields: serde_json::json!({"event": "it.round_trip", "n": 1}),
        })
        .unwrap(),
    };
    write_frame(&mut conn, &call);
    let resp: ServiceResponse = read_frame(&mut conn);
    let chain_head = match resp {
        ServiceResponse::Ok { payload, .. } => {
            serde_json::from_value::<EmitResponse>(payload)
                .expect("Ok payload is an EmitResponse")
                .chain_head
        }
        ServiceResponse::Err { code, message, .. } => {
            panic!("emit was refused: {code:?} {message}")
        }
    };
    assert!(!chain_head.is_empty(), "emit must return a chain head");

    // ── the entry is on the per-VM chain, verifiable under the host pubkey ──
    let entries =
        verify_workload_chain(&workload_chain, &signer.verifying).expect("chain must verify");
    assert_eq!(entries, 1, "exactly one workload_audit entry was appended");
}
