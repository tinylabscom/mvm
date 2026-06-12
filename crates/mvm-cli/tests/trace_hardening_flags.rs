//! CLI surface tests for the trace-hardening flags.
//!
//! Asserts that `--ack-divergence` appears on `mvmctl run --help` and
//! `--recording-sha256` appears on `mvmctl build compile --help`.

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

/// `mvmctl run --help` must advertise `--ack-divergence`.
#[test]
fn run_help_contains_ack_divergence() {
    let out = mvmctl(&["run", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "expected success, got: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("--ack-divergence"),
        "`mvmctl run --help` missing '--ack-divergence'; stdout:\n{stdout}"
    );
}

/// `mvmctl build compile --help` must advertise `--recording-sha256`.
#[test]
fn compile_help_contains_recording_sha256() {
    let out = mvmctl(&["build", "compile", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "expected success, got: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("--recording-sha256"),
        "`mvmctl build compile --help` missing '--recording-sha256'; stdout:\n{stdout}"
    );
}
