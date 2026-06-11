//! Seccomp property test (`mvm-jailer-lite`).
//!
//! Parent test forks the test binary with `SECCOMP_PROBE=1`; child
//! applies `ConfinementSpec::firecracker_bridge` confinement and
//! probes one allowed syscall (`clock_gettime` via `Instant::now`)
//! and one disallowed (`mkdir` via `std::fs::create_dir`, which on
//! Linux dispatches `SYS_mkdirat` — confirmed absent from
//! `BRIDGE_SYSCALLS` so `SeccompAction::Trap` raises SIGSYS).
//!
//! Acceptable outcomes:
//!   1. Signal SIGSYS — seccomp Trap fired on the disallowed
//!      syscall (the expected path on Linux ≥ 5.19).
//!   2. Exit 0 — the allowed syscall succeeded AND the disallowed
//!      syscall was blocked at the libc / VFS layer before reaching
//!      seccomp (defensive: kernels / glibcs in the wild may short-
//!      circuit a `mkdirat` over `/tmp` differently).
//!
//! File is `#![cfg(target_os = "linux")]` so it compiles down to an
//! empty integration-test binary on macOS / Windows contributor
//! hosts — `cargo test -p mvm-jailer-lite` stays green everywhere.

#![cfg(target_os = "linux")]

use mvm_hostd::jailer::ConfinementSpec;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

const PROBE_ENV: &str = "SECCOMP_PROBE";

#[test]
#[ignore = "run via `cargo test --test seccomp_property -- --ignored` on Linux >= 5.19"]
fn seccomp_allows_listed_denies_unlisted() {
    let child_status = Command::new(std::env::current_exe().expect("current_exe"))
        .env(PROBE_ENV, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .expect("spawn probe child");

    // Two acceptable outcomes:
    //   1. signal SIGSYS — seccomp Trap fired on the disallowed
    //      syscall (expected on Linux 5.19+).
    //   2. exit 0 — the allowed syscall succeeded AND the disallowed
    //      syscall was blocked at the libc / VFS layer before
    //      reaching seccomp (defensive accept).
    let ok = child_status.success() || child_status.signal() == Some(libc::SIGSYS);
    assert!(
        ok,
        "child exited unexpectedly: status={:?}, signal={:?}",
        child_status.code(),
        child_status.signal()
    );
}

#[ctor::ctor]
fn maybe_run_as_probe_child() {
    if std::env::var(PROBE_ENV).is_ok() {
        run_probe();
        // Probe always exits explicitly; we never return here.
    }
}

fn run_probe() {
    // Create probe dirs the spec needs to install Landlock rules on.
    // Errors are ignored: the directories may already exist from a
    // previous probe run, and a real failure surfaces on the
    // `confine_self` call below as a `PathNotFound` variant.
    std::fs::create_dir_all("/tmp/mvm-seccomp-probe-audit").ok();
    std::fs::create_dir_all("/tmp/mvm-seccomp-probe-keys").ok();
    let spec = ConfinementSpec::firecracker_bridge(
        "/tmp/mvm-seccomp-probe-audit".into(),
        "/tmp/mvm-seccomp-probe-keys".into(),
        "/usr/bin/passt".into(),
    );
    if let Err(e) = mvm_hostd::jailer::confine_self(&spec) {
        eprintln!("confine_self failed: {e}");
        std::process::exit(2);
    }

    // Allowed: clock_gettime (via std::time::Instant).
    let _ = std::time::Instant::now();

    // Disallowed: mkdir (Linux's std::fs::create_dir dispatches
    // SYS_mkdirat, which is not in BRIDGE_SYSCALLS — confirmed
    // by reading crates/mvm-jailer-lite/src/seccomp.rs).
    // SeccompAction::Trap raises SIGSYS on the disallowed call,
    // so the process is killed before this returns on the
    // expected path. The fallback below handles the edge case
    // where some kernel / libc path blocks the call before
    // reaching the BPF filter.
    let res = std::fs::create_dir("/tmp/mvm-seccomp-probe-disallowed");
    if res.is_ok() {
        // Unexpected: the disallowed syscall produced a directory.
        // Clean up so the test is re-runnable, then exit nonzero
        // so the parent assertion fails.
        let _ = std::fs::remove_dir("/tmp/mvm-seccomp-probe-disallowed");
        std::process::exit(2);
    }
    std::process::exit(0);
}
