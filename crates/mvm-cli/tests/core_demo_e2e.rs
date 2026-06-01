//! The core demo, end to end: `dev up` (builder VM) → `compile` the
//! hello-app → `up` (build in-VM, boot, wait for the guest agent over
//! vsock) → teardown. This is the regression guard for the whole spine.
//!
//! Gated on `MVM_E2E_SMOKE=1` because it needs libkrun + the builder VM
//! and runs for minutes; the default (ungated) run skips and passes.
//!
//! On macOS the workload microVM runs via libkrun (vsock-capable; the
//! path the guest agent answers on). `--hypervisor libkrun` is passed
//! explicitly so the test doesn't depend on `up`'s per-host auto-select
//! preferring libkrun over apple-container on macOS 26+ (which is a
//! deliberate apple-container priority for general use; the demo wants
//! the vsock path).
//!
//! `up` waits for the guest agent (`wait_for_guest_agent` → vsock Ping)
//! and only prints `Guest agent not reachable.` on failure — so `up`
//! exiting 0 *without* that line is the boot→ping proof.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

fn mvmctl(args: &[&str]) -> std::process::Output {
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("mvmctl").expect("locate mvmctl");
    cmd.args(args);
    // The E2E pins the builder backend to libkrun on macOS so the
    // test doesn't depend on the Swift mvm-vz-supervisor having been
    // built. Plan 98's auto-select would otherwise pick Vz on macOS
    // 26+ Apple Silicon and bail with "mvm-vz-supervisor binary not
    // found." The pin is per-child so it doesn't leak into other
    // tests running in the same cargo invocation.
    if cfg!(target_os = "macos") {
        cmd.env("MVM_BUILDER_BACKEND", "libkrun");
    }
    cmd.output().expect("spawn mvmctl")
}

/// On macOS the workload microVM must run via libkrun (vsock-capable).
/// On Linux the host's native Firecracker is correct. The E2E threads
/// `--hypervisor` through so it doesn't rely on `up`'s host-specific
/// auto-select choosing the same backend the test assumes.
fn workload_hypervisor() -> &'static str {
    if cfg!(target_os = "macos") {
        "libkrun"
    } else {
        "firecracker"
    }
}

#[test]
fn core_demo_dev_compile_up_ping() {
    if std::env::var("MVM_E2E_SMOKE").ok().as_deref() != Some("1") {
        eprintln!("skipping core-demo E2E; set MVM_E2E_SMOKE=1 to run");
        return;
    }
    let out = tempfile::tempdir().expect("tmp out");
    let app = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/python/hello-app/app.py"
    );

    // 1) builder VM up (idempotent).
    assert!(mvmctl(&["dev", "up"]).status.success(), "dev up failed");

    // 2) lower the decorator app to flake.nix + launch.json.
    let c = mvmctl(&["compile", app, "--out", out.path().to_str().unwrap()]);
    assert!(
        c.status.success(),
        "compile failed: {}",
        String::from_utf8_lossy(&c.stderr)
    );

    // 3) build + boot the workload microVM; `up` waits for the agent.
    //    Exit 0 with no "not reachable" line == the agent answered.
    let up = mvmctl(&[
        "up",
        "--hypervisor",
        workload_hypervisor(),
        "--flake",
        out.path().to_str().unwrap(),
    ]);
    let log = String::from_utf8_lossy(&up.stderr);
    assert!(up.status.success(), "up failed: {log}");
    assert!(
        !log.contains("Guest agent not reachable"),
        "agent never answered: {log}"
    );

    // 4) tear down the builder (best-effort).
    let _ = mvmctl(&["dev", "down"]);
}
