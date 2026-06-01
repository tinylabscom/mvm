//! The core demo, end to end: `dev up` (builder VM) → `compile` the
//! hello-app → `up` (build in-VM, boot, wait for the guest agent over
//! vsock) → teardown. This is the regression guard for the whole spine.
//!
//! Gated on `MVM_E2E_SMOKE=1` because it needs libkrun + the builder VM
//! and runs for minutes; the default (ungated) run skips and passes.
//! On macOS the workload backend must be libkrun, so the demo runs with
//! `MVM_BUILDER_BACKEND=libkrun` set in the environment.
//!
//! `up` waits for the guest agent (`wait_for_guest_agent` → vsock Ping)
//! and only prints `Guest agent not reachable.` on failure — so `up`
//! exiting 0 *without* that line is the boot→ping proof.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

fn mvmctl(args: &[&str]) -> std::process::Output {
    #[allow(deprecated)]
    Command::cargo_bin("mvmctl")
        .expect("locate mvmctl")
        .args(args)
        .output()
        .expect("spawn mvmctl")
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
    let up = mvmctl(&["up", "--flake", out.path().to_str().unwrap()]);
    let log = String::from_utf8_lossy(&up.stderr);
    assert!(up.status.success(), "up failed: {log}");
    assert!(
        !log.contains("Guest agent not reachable"),
        "agent never answered: {log}"
    );

    // 4) tear down the builder (best-effort).
    let _ = mvmctl(&["dev", "down"]);
}
