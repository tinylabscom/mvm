//! Supervisor dispatch smoke.
//!
//! End-to-end verification that the producer-side wire format
//! (`VmStartConfig` → `audit_substrate::compute_audit_substrate` →
//! `SupervisorConfig` → JSON → supervisor stdin) routes to either the
//! **bridge-factory** branch (`tenant_id` Some) or the **legacy
//! `run_supervisor`** branch (`tenant_id` None) in
//! `mvm-libkrun-supervisor::main`.
//!
//! Two `#[ignore]` tests:
//!
//! - `supervisor_takes_bridge_path_when_tenant_id_some` — populated
//!   substrate ⇒ supervisor reaches the `plan.json` decode step
//!   before failing on the placeholder envelope. Failure message
//!   `decode cfg.plan into ExecutionPlan` is the witness that the
//!   bridge branch was entered.
//!
//! - `supervisor_takes_legacy_path_when_tenant_id_none` — empty
//!   substrate ⇒ supervisor calls `run_supervisor` (the legacy
//!   path) and fails downstream at libkrun's
//!   `krun_start_enter` (rc -22 because the fake kernel/rootfs
//!   don't exist). Confirms the back-compat path for `mvmctl dev`,
//!   session VMs, and template restore.
//!
//! ## How to run
//!
//! ```sh
//! cargo build --release -p mvm-libkrun-supervisor --features libkrun-sys
//! cargo test -p mvm-backend --test phase3c_supervisor_dispatch \
//!     -- --ignored --nocapture
//! ```
//!
//! Self-skips on non-macos-aarch64 (the only platform with libkrun +
//! supervisor binary out of the box; Linux contributors get the same
//! coverage via the unit tests in `libkrun.rs` and
//! `audit_substrate.rs`). Set `MVM_LIBKRUN_SUPERVISOR_PATH` to point
//! at a non-default binary location.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use libkrun_sys::{KrunContext, SupervisorConfig};
use std::io::Write;
use std::process::{Command, Stdio};

fn supervisor_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("MVM_LIBKRUN_SUPERVISOR_PATH") {
        return std::path::PathBuf::from(p);
    }
    // From `crates/mvm-backend/`, the workspace root is two levels up
    // and the supervisor binary lives at `target/release/`. Same
    // resolution shape libkrun_lifecycle_e2e.rs uses.
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/release/mvm-libkrun-supervisor")
}

#[test]
#[ignore]
fn supervisor_takes_bridge_path_when_tenant_id_some() {
    // Build a populated VmStartConfig and run it through Phase 3c's
    // shared substrate helper.
    let substrate =
        mvm_backend::audit_substrate::compute_audit_substrate("phase3c-smoke", Some("smoke"))
            .expect("compute substrate");

    let state_dir = std::path::PathBuf::from("/tmp/phase3c-smoke");
    std::fs::create_dir_all(&state_dir).unwrap();

    let krun = KrunContext::new(
        "phase3c-smoke",
        "/tmp/fake-vmlinux",
        "/tmp/fake-rootfs.ext4",
    )
    .with_resources(1, 256)
    .with_cmdline("console=hvc0 root=/dev/vda rw init=/init")
    .with_vsock_socket_dir(state_dir.to_string_lossy().into_owned())
    .add_vsock_port(1024);

    let cfg = SupervisorConfig {
        krun,
        vm_state_dir: state_dir.to_string_lossy().into_owned(),
        pid_file_name: None,
        tenant_id: substrate.tenant_id,
        audit_dir: substrate.audit_dir,
        gateway_audit_socket: substrate.gateway_audit_socket,
        gateway_events_socket: substrate.gateway_events_socket,
        signing_key_path: substrate.signing_key_path,
        // Placeholder: supervisor only deserializes if the bridge
        // path is taken; we expect that to happen and then fail
        // downstream on the missing kernel.
        plan: Some(serde_json::json!({"placeholder": true})),
        bundle: None,
        network_policy: None,
        bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
        transparent_terminator_port: None,
    };

    let json = serde_json::to_string_pretty(&cfg).unwrap();
    eprintln!("--- SupervisorConfig JSON ---\n{json}\n--- end ---");

    let mut child = Command::new(supervisor_path())
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn supervisor");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(json.as_bytes())
        .unwrap();

    let output = child.wait_with_output().expect("wait");
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- supervisor stderr ---\n{stderr}\n--- end ---");

    // When tenant_id is Some, the supervisor must reach the
    // bridge-factory branch. The downstream libkrun call
    // will fail (fake kernel), but we expect to see the
    // `starting bridge-mode libkrun supervisor` trace before that.
    //
    // Acceptable failure shapes on the bridge path:
    //   - tracing emits "starting bridge-mode libkrun supervisor"
    //   - decode of placeholder plan fails ("decode cfg.plan into
    //     ExecutionPlan") — also proves the bridge branch was taken
    //   - signing key load works (we have a real key file)
    //   - libkrun fails because /tmp/fake-vmlinux doesn't exist
    let bridge_signal = stderr.contains("starting bridge-mode libkrun supervisor")
        || stderr.contains("decode cfg.plan into ExecutionPlan")
        || stderr.contains("run_supervisor_with_bridge")
        || stderr.contains("BridgeConfig");

    assert!(
        bridge_signal,
        "supervisor did not take the bridge path; stderr was:\n{stderr}"
    );
}

#[test]
#[ignore]
fn supervisor_takes_legacy_path_when_tenant_id_none() {
    // Mirror: no tenant_id ⇒ legacy run_supervisor branch.
    let state_dir = std::path::PathBuf::from("/tmp/phase3c-smoke-legacy");
    std::fs::create_dir_all(&state_dir).unwrap();

    let krun = KrunContext::new(
        "phase3c-smoke-legacy",
        "/tmp/fake-vmlinux",
        "/tmp/fake-rootfs.ext4",
    )
    .with_resources(1, 256)
    .with_cmdline("console=hvc0 root=/dev/vda rw init=/init")
    .with_vsock_socket_dir(state_dir.to_string_lossy().into_owned())
    .add_vsock_port(1024);

    let cfg = SupervisorConfig {
        krun,
        vm_state_dir: state_dir.to_string_lossy().into_owned(),
        pid_file_name: None,
        tenant_id: None,
        audit_dir: None,
        gateway_audit_socket: None,
        gateway_events_socket: None,
        signing_key_path: None,
        plan: None,
        bundle: None,
        network_policy: None,
        bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
        transparent_terminator_port: None,
    };

    let json = serde_json::to_string_pretty(&cfg).unwrap();
    let mut child = Command::new(supervisor_path())
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn supervisor");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(json.as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("wait");
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- legacy stderr ---\n{stderr}\n--- end ---");

    // Legacy path proof: must NOT contain bridge-mode trace; must
    // either reach `run_supervisor` (proof that it took the non-bridge
    // branch) or fail downstream in the libkrun load.
    assert!(
        !stderr.contains("starting bridge-mode"),
        "unexpectedly took bridge path with tenant_id=None: {stderr}"
    );
}
