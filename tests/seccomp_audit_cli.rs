//! Integration tests for `mvmctl seccomp-audit`.
//!
//! The ptrace-based audit runner only works on Linux; this file is gated
//! entirely so non-Linux hosts simply skip it.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

fn mvmctl_bin() -> PathBuf {
    // `cargo test` sets `CARGO_BIN_EXE_mvmctl` for integration tests in the
    // binary package. Fall back to the current exe's target directory so the
    // test can also be invoked by other runners.
    std::env::var("CARGO_BIN_EXE_mvmctl")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let mut path = std::env::current_exe().expect("current exe path");
            path.pop(); // deps
            path.pop(); // debug or release
            path.push("mvmctl");
            path
        })
}

#[test]
fn audit_true_finds_no_missing_syscalls() {
    let output = Command::new(mvmctl_bin())
        .args(["seccomp-audit", "--json", "minimal", "--", "/bin/true"])
        .output()
        .expect("mvmctl seccomp-audit should spawn");

    assert!(
        output.status.success(),
        "mvmctl seccomp-audit exited with {status:?}\nstderr: {stderr}",
        status = output.status,
        stderr = String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("seccomp-audit --json should emit valid JSON");

    assert_eq!(report["tier"], "minimal");
    assert_eq!(report["child_exit_code"], 0);
    assert_eq!(report["missing"], 0);
    assert!(
        report["missing_syscalls"].as_array().unwrap().is_empty(),
        "expected no missing syscalls for /bin/true"
    );
}

#[test]
fn audit_true_against_essential_finds_missing_syscalls() {
    let output = Command::new(mvmctl_bin())
        .args([
            "seccomp-audit",
            "--json",
            "--fail-on-missing",
            "essential",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("mvmctl seccomp-audit should spawn");

    assert!(
        !output.status.success(),
        "expected --fail-on-missing to exit non-zero when syscalls are missing"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("seccomp-audit --json should emit valid JSON");

    assert_eq!(report["tier"], "essential");
    assert!(report["missing"].as_i64().unwrap_or(0) > 0);
}
