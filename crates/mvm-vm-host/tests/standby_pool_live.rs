//! Live integration for the libkrun standby pool, driving the **real**
//! `LibkrunBackend::spawn_standby`/`claim_standby` through the `VmBackend` trait + the real
//! `mvm-libkrun-supervisor` binary.
//!
//! Gated behind `libkrun-live` (needs libkrun to link + a supervisor bin on PATH/alongside).
//! Two scenarios:
//!
//! 1. `spawn_standby_binds_control_socket` — runnable wherever libkrun links: a spawned
//!    standby is a live process that binds its control UDS and blocks before any boot. No
//!    guest kernel is touched until claim, so this proves the backend→bin spawn wiring with
//!    no bootable image.
//! 2. `valid_attach_boots_and_agent_reachable` — `#[ignore]`: the full spawn→claim→boot
//!    happy path needs a real default-microvm kernel/rootfs + in-guest agent. Run manually
//!    on a libkrun-capable host (model on `examples/agent_ping` + the prelaunch harness);
//!    the refusal logic + spawn wiring are covered by the unit ladder + scenario 1.
#![cfg(feature = "libkrun-live")]

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use mvm_core::vm_backend::{StandbySpec, VmBackend};

/// Build a StandbySpec that pre-loads a (bogus) kernel — the prelaunch supervisor blocks on
/// the control UDS *before* loading the kernel, so the kernel path is never read until a
/// claim, and this scenario never claims.
fn spec(dir: &Path, nonce: &str) -> StandbySpec {
    StandbySpec {
        id: format!("standby-{nonce}"),
        kernel_path: "/nonexistent/vmlinux".into(),
        kernel_sha256: "a".repeat(64),
        vcpus: 1,
        mem_mib: 256,
        signing_key_path: dir.join("host-signer.ed25519"),
        signer_id: "host:test".into(),
        binding_nonce: nonce.into(),
        control_socket: dir.join(format!("control-{nonce}.sock")),
        vm_state_dir: dir.join("state").to_string_lossy().into_owned(),
    }
}

fn wait_for_socket(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if UnixStream::connect(path).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

fn pid_alive(pid: u32) -> bool {
    // SAFETY: kill(pid, 0) is a liveness probe with no signal delivered.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[test]
fn spawn_standby_binds_control_socket() {
    let dir = tempfile::tempdir().unwrap();
    let backend = mvm_backend::libkrun::LibkrunBackend;
    assert!(backend.supports_standby_pool());

    let handle = backend
        .spawn_standby(&spec(dir.path(), "deadbeef01"))
        .expect("spawn_standby");

    // The spawned supervisor is a live process that binds its control UDS and blocks there
    // (before any boot). Both must hold for the warm-pool primitive to be claimable.
    assert!(
        wait_for_socket(&handle.control_socket, Duration::from_secs(10)),
        "standby must bind its control UDS"
    );
    assert!(
        pid_alive(handle.pid),
        "standby supervisor must be alive and blocked"
    );

    // Cleanup: the standby would otherwise block until its attach timeout. Reap it.
    // SAFETY: SIGTERM to a pid we just spawned.
    unsafe { libc::kill(handle.pid as libc::pid_t, libc::SIGTERM) };
}

#[test]
#[ignore = "needs a real kernel+rootfs+agent; run manually on a libkrun-capable host (model on examples/agent_ping)"]
fn valid_attach_boots_and_agent_reachable() {
    // Build a StandbySpec with the default-microvm kernel + the agent vsock port, spawn it,
    // then `claim_standby` with a StandbyClaim whose plan_json is a freshly-signed admitted
    // envelope (signed with the SAME on-disk host key the spec points at) + a real rootfs.
    // Assert the guest boots and the agent answers a vsock ping. Left as a manual harness —
    // scenario 1 + the unit ladder cover the spawn wiring and the claim/verify logic.
    unimplemented!("manual live-boot harness — see module docs");
}
