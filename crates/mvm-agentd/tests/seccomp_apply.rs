//! Functional integration test for `mvm-seccomp-apply`.
//!
//! The unit tests in `mvm-core::crypto::seccomp` cover tier *structure*
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

// ── The agent's own workload spawn paths ────────────────────────────────
//
// The tests above prove the shim. These prove the agent: a tier admitted the
// way activation admits it — off the kernel cmdline — lands in a process the
// agent starts for the workload. Each launch path is checked separately,
// because each builds its own `Command`, and one that forgets to confine its
// child is the failure this guards. Admitting is process state, so these all
// admit the same tier; the shim tests above never pass through it.

use mvm_agentd::vsock::{ExecEvent, ProcResult, ProcWaitEvent};

fn admit_standard() {
    let admitted =
        mvm_agentd::workload_seccomp::admit_from_cmdline("console=ttyS0 mvm.seccomp=standard")
            .expect("admit the standard tier");
    assert_eq!(
        admitted,
        Some(mvm_core::crypto::seccomp::SeccompTier::Standard)
    );
}

fn exec_and_collect(argv: &[&str]) -> (ExecEvent, String) {
    let argv: Vec<String> = argv.iter().map(|arg| (*arg).to_string()).collect();
    let mut stdout = Vec::new();
    let terminal = mvm_agentd::exec_stream::stream_exec_argv(&argv, None, Some(30), |event| {
        if let ExecEvent::Stdout { chunk } = event {
            stdout.extend_from_slice(&chunk);
        }
    });
    (terminal, String::from_utf8_lossy(&stdout).into_owned())
}

/// `Exec` / `ExecBatch` / `RunCode`: the denied call fails with the tier's
/// errno, so the filter is installed and is the standard one.
#[test]
fn an_exec_under_the_admitted_standard_tier_cannot_open_a_socket() {
    admit_standard();
    let (terminal, _) = exec_and_collect(&[probe()]);
    assert!(
        matches!(terminal, ExecEvent::Exit { code } if code == libc::EPERM),
        "socket() must fail with EPERM under the admitted standard tier, got {terminal:?}"
    );
}

/// The child carries the filter and `no_new_privs`, and an ordinary program
/// still runs under the tier: a shell and `cat` are what a workload exec
/// usually is.
#[test]
fn an_exec_child_reports_a_seccomp_filter_and_no_new_privs() {
    admit_standard();
    let (terminal, stdout) = exec_and_collect(&["/bin/sh", "-c", "cat /proc/self/status"]);
    assert!(
        matches!(terminal, ExecEvent::Exit { code: 0 }),
        "a shell must run under the standard tier: {terminal:?}"
    );
    let field = |name: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
            .unwrap_or_else(|| panic!("{name} missing from /proc/self/status:\n{stdout}"))
            .to_string()
    };
    assert_eq!(field("Seccomp:"), "2", "2 is SECCOMP_MODE_FILTER");
    assert_eq!(field("NoNewPrivs:"), "1");
}

/// `ProcStart`: the process-control path builds its own `Command`.
#[test]
fn a_started_process_under_the_admitted_standard_tier_cannot_open_a_socket() {
    admit_standard();
    let registry = mvm_agentd::process_rpc::Registry::new();
    let caps = mvm_agentd::process_rpc::Caps::production();
    let started = mvm_agentd::process_rpc::handle_proc_start(
        &registry,
        &caps,
        &[probe().to_string()],
        &Default::default(),
        None,
        &[],
    );
    let ProcResult::Started { pid_token } = started else {
        panic!("process did not start: {started:?}");
    };
    let terminal =
        mvm_agentd::process_rpc::handle_proc_wait(&registry, &caps, &pid_token, Some(30), |_| {});
    assert!(
        matches!(terminal, ProcWaitEvent::Exit { code } if code == libc::EPERM),
        "socket() must fail with EPERM under the admitted standard tier, got {terminal:?}"
    );
}
