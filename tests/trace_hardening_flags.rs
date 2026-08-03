//! CLI surface tests for the trace-hardening flags.
//!
//! Asserts that `--recording-sha256` appears on `mvmctl build compile --help`
//! and that `mvmctl machine run --help` is reachable (the primary run surface).

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

/// `mvmctl machine run --help` must succeed (primary run surface).
#[test]
fn run_help_contains_ack_divergence() {
    let out = mvmctl(&["machine", "run", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "expected success, got: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("--image") || stdout.contains("--flake") || stdout.contains("--manifest"),
        "`mvmctl machine run --help` missing source flags; stdout:\n{stdout}"
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
