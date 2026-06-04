//! ADR-064 — Landlock property test (`mvm-jailer-lite`).
//!
//! Same-process test: applies `ConfinementSpec::firecracker_bridge`
//! confinement, writes inside the spec's `audit_dir` (must succeed
//! — the rw_bridge_access grant covers `WriteFile` + `MakeReg`)
//! and writes to `/tmp` outside the ruleset (must fail with
//! EACCES). Seccomp does NOT block `openat` / `write` for the
//! denied path because both syscalls are on the allowlist — the
//! refusal comes from the Landlock LSM layer.
//!
//! File is `#![cfg(target_os = "linux")]` so it compiles down to
//! an empty integration-test binary on macOS / Windows contributor
//! hosts.

#![cfg(target_os = "linux")]

use mvm_hostd::jailer::ConfinementSpec;

#[test]
#[ignore = "run via `cargo test --test landlock_property -- --ignored` on Linux >= 5.19"]
fn landlock_denies_paths_outside_ruleset() {
    let audit_dir = "/tmp/mvm-landlock-probe-audit";
    let keys_dir = "/tmp/mvm-landlock-probe-keys";
    // Directories must exist before `confine_self` because
    // `landlock::PathFd::new` opens them to install the ruleset.
    std::fs::create_dir_all(audit_dir).ok();
    std::fs::create_dir_all(keys_dir).ok();

    let spec = ConfinementSpec::firecracker_bridge(
        audit_dir.into(),
        keys_dir.into(),
        "/usr/bin/passt".into(),
    );
    mvm_hostd::jailer::confine_self(&spec).expect("confine_self");

    // Allowed: write inside audit_dir (the rw_bridge_access grant
    // covers ReadFile / WriteFile / MakeReg / Refer / RemoveFile).
    let ok = std::fs::write(format!("{audit_dir}/probe.log"), "ok");
    assert!(ok.is_ok(), "audit_dir write must succeed: {ok:?}");

    // Denied: write to /tmp (parent of audit_dir, not in ruleset).
    let denied = std::fs::write("/tmp/mvm-landlock-probe-outside", "nope");
    assert!(denied.is_err(), "writing outside ruleset must be denied");
    let err = denied.expect_err("denied write returns error");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EACCES),
        "expected EACCES, got {err:?}"
    );
}
