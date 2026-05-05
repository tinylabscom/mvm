//! Functional integration test for `mvm-seccomp-apply` (ADR-002 §W2.4).
//!
//! The unit tests in `mvm-security::seccomp` cover tier *structure*
//! (cumulative-subset, no duplicates, manifest roundtrip). They don't
//! exercise the BPF program at runtime. This test does:
//!
//! 1. Spawn `mvm-seccomp-apply <tier> -- syscall-probe`.
//! 2. The probe attempts `socket(AF_INET, SOCK_STREAM, 0)`.
//! 3. Assert the probe's exit code matches the tier's promise:
//!    - `unrestricted` / `network` → 0 (call allowed)
//!    - `standard` → `EPERM` (call denied with seccomp errno-action)
//!
//! Linux-only because seccomp is a Linux kernel feature. The crate
//! still builds on macOS (the gated stub binaries pass `cargo check`),
//! but the test is skipped at compile time.

#![cfg(target_os = "linux")]

use std::process::{Command, Output};

fn shim() -> &'static str {
    env!("CARGO_BIN_EXE_mvm-seccomp-apply")
}

fn probe() -> &'static str {
    env!("CARGO_BIN_EXE_syscall-probe")
}

fn run_under(tier: &str) -> Output {
    Command::new(shim())
        .arg(tier)
        .arg("--")
        .arg(probe())
        .output()
        .expect("spawn mvm-seccomp-apply")
}

#[test]
fn unrestricted_allows_socket() {
    let out = run_under("unrestricted");
    assert!(
        out.status.success(),
        "expected socket() to succeed under unrestricted; status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn network_tier_allows_socket() {
    let out = run_under("network");
    assert!(
        out.status.success(),
        "expected socket() to succeed under network tier; status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn standard_tier_denies_socket_with_eperm() {
    let out = run_under("standard");
    assert_eq!(
        out.status.code(),
        Some(libc::EPERM),
        "expected EPERM ({}) under standard tier; status={:?} stderr={}",
        libc::EPERM,
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}
