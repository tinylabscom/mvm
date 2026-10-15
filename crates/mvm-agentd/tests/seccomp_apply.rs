//! Functional integration test for `mvm-seccomp-apply`, and for the tier the
//! guest agent installs in the workload processes it starts — admitted at
//! activation off the kernel cmdline, or on the post-restore handshake of a
//! warm-claimed child.
//!
//! The unit tests in `mvm-core::crypto::seccomp` cover tier *structure*
//! (cumulative-subset, no duplicates, manifest roundtrip). They don't
//! exercise the BPF program at runtime. This test does:
//!
//! 1. Spawn `mvm-seccomp-apply <tier> -- syscall-probe`. For the `groups`
//!    probe the test spawns the probe directly with a tier it installs on
//!    itself (`syscall-probe groups <tier>`): the shim's apply-then-exec
//!    goes through std's `Command::exec`, which resets SIGPIPE after the
//!    filter is installed, and `essential` grants no `rt_sigaction` for the
//!    reset — so the shim's handoff dies there, while a process confined
//!    after startup, the agent's own ordering, does not.
//! 2. The probe attempts `socket(AF_INET, SOCK_STREAM, 0)`, or the
//!    `AF_VSOCK` equivalent when asked, or `getgroups(0, NULL)`.
//! 3. Assert the probe's exit code matches the tier's promise:
//!    - `unrestricted` / `network` → 0 (call allowed)
//!    - `standard` → `EPERM` (call denied with seccomp errno-action)
//!    - `vsock` → `AF_VSOCK` passes the filter, `AF_INET` is `EPERM`
//!    - every enforcing tier → `getgroups` succeeds without changing groups
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
    run_family_under(tier, "inet")
}

fn run_family_under(tier: &str, family: &str) -> Output {
    Command::new(shim())
        .arg(tier)
        .arg("--")
        .arg(probe())
        .arg(family)
        .output()
        .expect("spawn mvm-seccomp-apply")
}

/// The groups probe installs the tier on itself rather than going through
/// the shim — the file header has why the shim's exec handoff cannot reach
/// `essential`.
fn run_groups_self_confined(tier: &str) -> Output {
    Command::new(probe())
        .arg("groups")
        .arg(tier)
        .output()
        .expect("spawn syscall-probe")
}

/// The filter let `socket` through. The probe exits 0 when the socket opened
/// and with the errno otherwise; a kernel without the vsock transport loaded
/// answers `AF_VSOCK` with `EAFNOSUPPORT`, which is the kernel speaking after
/// the filter allowed the call. Only `EPERM` is the filter's answer.
fn assert_passed_the_filter(out: &Output, what: &str) {
    assert!(
        out.status.code().is_some() && out.status.code() != Some(libc::EPERM),
        "expected {what} to pass the filter; status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn assert_denied_by_the_filter(out: &Output, what: &str) {
    assert_eq!(
        out.status.code(),
        Some(libc::EPERM),
        "expected {what} to fail with EPERM; status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn every_enforcing_tier_allows_reading_supplementary_groups() {
    for tier in ["essential", "minimal", "standard", "vsock", "network"] {
        let out = run_groups_self_confined(tier);
        assert!(
            out.status.success(),
            "getgroups must succeed under {tier}; status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
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

/// A GPU-granted launch's tier: the vsock socket its shims dial the host GPU
/// endpoint over is allowed, and no other address family is.
#[test]
fn vsock_tier_allows_an_af_vsock_socket_and_denies_af_inet() {
    assert_passed_the_filter(
        &run_family_under("vsock", "vsock"),
        "socket(AF_VSOCK) under vsock",
    );
    assert_denied_by_the_filter(
        &run_family_under("vsock", "inet"),
        "socket(AF_INET) under vsock",
    );
}

/// Without a GPU grant the tier stays `standard`, which refuses a vsock
/// socket as it refuses every other one.
#[test]
fn standard_tier_denies_an_af_vsock_socket_with_eperm() {
    assert_denied_by_the_filter(
        &run_family_under("standard", "vsock"),
        "socket(AF_VSOCK) under standard",
    );
}

/// A GPU launch that also needs `network` keeps its vsock socket.
#[test]
fn network_tier_allows_an_af_vsock_socket() {
    assert_passed_the_filter(
        &run_family_under("network", "vsock"),
        "socket(AF_VSOCK) under network",
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

// ── A warm-claimed child ────────────────────────────────────────────────
//
// A child restored out of a standby parent never reads a tier off its kernel
// cmdline: the parent booted with no plan, and the child inherits that
// cmdline. Its tier arrives on the post-restore handshake, which admits it
// through `admit_restored`. These run the workload spawn path after admitting
// that way, so they prove the claim's tier — not a boot-time one — is what
// lands in the workload. Every test in this binary admits `standard`, so the
// process state they share agrees whichever runs first.

fn admit_as_a_warm_claimed_child() {
    let admitted = mvm_agentd::workload_seccomp::admit_restored(
        mvm_core::crypto::seccomp::SeccompTier::Standard,
        false,
    )
    .expect("a restored child admits its claim's tier");
    assert_eq!(admitted, mvm_core::crypto::seccomp::SeccompTier::Standard);
}

#[test]
fn a_warm_claimed_child_under_standard_cannot_open_a_socket() {
    admit_as_a_warm_claimed_child();
    let (terminal, _) = exec_and_collect(&[probe()]);
    assert!(
        matches!(terminal, ExecEvent::Exit { code } if code == libc::EPERM),
        "socket() must fail with EPERM in a warm-claimed child under standard, got {terminal:?}"
    );
}

#[test]
fn a_warm_claimed_childs_workload_reports_a_seccomp_filter() {
    admit_as_a_warm_claimed_child();
    let (terminal, stdout) = exec_and_collect(&["/bin/sh", "-c", "cat /proc/self/status"]);
    assert!(
        matches!(terminal, ExecEvent::Exit { code: 0 }),
        "a shell must run under the standard tier: {terminal:?}"
    );
    let seccomp = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp:"))
        .map(str::trim);
    assert_eq!(seccomp, Some("2"), "2 is SECCOMP_MODE_FILTER:\n{stdout}");
}

/// Admit-once holds across the handshake: a second claim's handshake cannot
/// swap the tier the first one admitted.
#[test]
fn a_warm_claimed_child_refuses_a_second_different_tier() {
    admit_as_a_warm_claimed_child();
    let refusal = mvm_agentd::workload_seccomp::admit_restored(
        mvm_core::crypto::seccomp::SeccompTier::Network,
        false,
    )
    .expect_err("a different tier is refused once one is admitted");
    assert!(refusal.contains("already standard"), "{refusal}");
    assert_eq!(
        mvm_agentd::workload_seccomp::admitted_tier(),
        Some(mvm_core::crypto::seccomp::SeccompTier::Standard)
    );
}
