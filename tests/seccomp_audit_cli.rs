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

/// `--fail-on-missing` must exit non-zero exactly when the report says
/// syscalls are missing, and zero when it does not.
///
/// This used to assert the stronger "`/bin/true` under `essential` always has
/// missing syscalls", which is an x86_64 fact rather than a contract. On
/// aarch64 `/bin/true` observes 15 syscalls and every one of them is in the
/// 36-syscall `essential` tier, so the audit correctly reports `missing: 0`
/// and correctly exits zero — and the old assertion failed on correct
/// behaviour. Verified on an aarch64 Linux host:
///
/// ```text
/// { "tier": "essential", "allowed": 36, "observed": 15, "missing": 0, ... }
/// ```
///
/// Asserting the biconditional keeps the test meaningful on both: whichever
/// arch runs it exercises one side, and neither a flag that never fails nor
/// one that always fails can pass.
#[test]
fn fail_on_missing_exits_nonzero_exactly_when_syscalls_are_missing() {
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

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("seccomp-audit --json should emit valid JSON");

    assert_eq!(report["tier"], "essential");
    let missing = report["missing"]
        .as_i64()
        .expect("the report carries a missing count");
    assert!(missing >= 0, "missing count must not be negative");

    assert_eq!(
        output.status.success(),
        missing == 0,
        "--fail-on-missing must exit non-zero exactly when the report lists \
         missing syscalls; report said missing={missing} but the exit status \
         was {status:?}",
        status = output.status
    );

    // The child still runs to completion either way — the flag changes
    // mvmctl's exit status, not the audited program's.
    assert_eq!(report["child_exit_code"], 0);
}
