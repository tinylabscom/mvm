//! Landlock property test (`mvm-jailer-lite`).
//!
//! The parent test re-runs this binary with `LANDLOCK_PROBE=1`; the child,
//! from a constructor that runs before the test harness starts any thread,
//! applies `ConfinementSpec::network_endpoint` confinement, writes inside the
//! spec's `audit_dir` (must succeed — the rw_bridge_access grant covers
//! `WriteFile` + `MakeReg`) and writes to `/tmp` outside the ruleset (must
//! fail with EACCES). Seccomp does NOT block `openat` / `write` for the denied
//! path because both syscalls are on the allowlist — the refusal comes from
//! the Landlock LSM layer.
//!
//! A child, because confinement refuses a multi-threaded process: Landlock
//! binds only the thread that applies it, so the harness's other threads would
//! stay unconfined. This test used to confine its own test thread in place,
//! which is exactly the half-confined shape the refusal now rules out.
//!
//! File is `#![cfg(target_os = "linux")]` so it compiles down to
//! an empty integration-test binary on macOS / Windows contributor
//! hosts.

#![cfg(target_os = "linux")]

use std::process::Command;

use mvm_hostd::jailer::ConfinementSpec;

const PROBE_ENV: &str = "LANDLOCK_PROBE";

#[test]
#[ignore = "run via `cargo test --test landlock_property -- --ignored` on Linux >= 5.19"]
fn landlock_denies_paths_outside_ruleset() {
    let output = Command::new(std::env::current_exe().expect("current_exe"))
        .env(PROBE_ENV, "1")
        .output()
        .expect("spawn probe child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "probe child failed: status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert!(stdout.contains("inside=ok"), "{stdout}");
    assert!(
        stdout.contains(&format!("outside=errno {}", libc::EACCES)),
        "{stdout}"
    );
}

#[ctor::ctor]
fn maybe_run_as_probe_child() {
    if std::env::var(PROBE_ENV).is_ok() {
        run_probe();
    }
}

fn run_probe() -> ! {
    let audit_dir = "/tmp/mvm-landlock-probe-audit";
    let keys_dir = "/tmp/mvm-landlock-probe-keys";
    // Directories must exist before `confine_self` because
    // `landlock::PathFd::new` opens them to install the ruleset.
    std::fs::create_dir_all(audit_dir).ok();
    std::fs::create_dir_all(keys_dir).ok();

    // The substitution endpoint is the live confined role — the per-VM process
    // that holds a workload's decrypted secrets.
    let secret_dir = "/tmp/mvm-landlock-probe-secrets";
    let binding_dir = "/tmp/mvm-landlock-probe-bindings";
    std::fs::create_dir_all(secret_dir).ok();
    std::fs::create_dir_all(binding_dir).ok();
    let spec = ConfinementSpec::network_endpoint(
        secret_dir.into(),
        binding_dir.into(),
        audit_dir.into(),
        keys_dir.into(),
        // Local resolver backend: this probe is about path grants, and a
        // resolver socket would add a write path it does not exercise.
        None,
    );
    if let Err(error) = mvm_hostd::jailer::confine_self(&spec) {
        eprintln!("confine_self failed: {error}");
        std::process::exit(2);
    }

    // Allowed: write inside audit_dir (the rw_bridge_access grant
    // covers ReadFile / WriteFile / MakeReg / Refer / RemoveFile).
    match std::fs::write(format!("{audit_dir}/probe.log"), "ok") {
        Ok(()) => println!("inside=ok"),
        Err(error) => println!("inside={error}"),
    }

    // Denied: write to /tmp (parent of audit_dir, not in ruleset).
    match std::fs::write("/tmp/mvm-landlock-probe-outside", "nope") {
        Ok(()) => println!("outside=written"),
        Err(error) => println!("outside=errno {}", error.raw_os_error().unwrap_or(-1)),
    }
    std::process::exit(0);
}
