//! The confinement self-test under a real seccomp filter.
//!
//! Each test re-runs this binary as a child with `CHILD_ENV` naming a
//! scenario. The child sets up the way `mvm-network-endpoint` does — async
//! runtime first, then the filter — runs the endpoint's self-test, and reports
//! on stdout. A refusal kills the child, so the parent reads its exit status
//! and its stderr, which is where the refusal reporter writes.
//!
//! Only the seccomp half of confinement is applied. What is under test is
//! whether the syscall allowlist covers the probes, and whether a gap is named;
//! Landlock answers a path it does not grant with an error rather than a kill,
//! and it is not active on every Linux runner.

#![cfg(target_os = "linux")]

use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use mvm_hostd::jailer::ConfinementSpec;
use mvm_hostd::jailer::self_test::ConfinementSelfTest;

const CHILD_ENV: &str = "MVM_CONFINEMENT_SELF_TEST_CHILD";
const DIR_ENV: &str = "MVM_CONFINEMENT_SELF_TEST_DIR";

#[ctor::ctor]
fn run_as_child_when_asked() {
    let Ok(scenario) = std::env::var(CHILD_ENV) else {
        return;
    };
    let dir = PathBuf::from(std::env::var(DIR_ENV).expect("scenario dir"));
    match scenario.as_str() {
        "real-filter" => self_test_under_filter(&dir, None),
        "without-flock" => self_test_under_filter(&dir, Some("flock")),
        "refusal-outside-a-probe" => refusal_outside_a_probe(&dir),
        other => panic!("unknown scenario {other}"),
    }
}

fn endpoint_spec(dir: &Path) -> ConfinementSpec {
    let [secrets, bindings, audit, keys] =
        ["secrets", "bindings", "audit", "keys"].map(|name| dir.join(name));
    for path in [&secrets, &bindings, &audit, &keys] {
        std::fs::create_dir_all(path).expect("create spec dir");
    }
    ConfinementSpec::network_endpoint(secrets, bindings, audit, keys, None)
}

fn self_test_under_filter(dir: &Path, without: Option<&str>) -> ! {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let mut spec = endpoint_spec(dir);
    if let Some(name) = without {
        spec.allowed_syscalls.retain(|allowed| *allowed != name);
    }
    mvm_hostd::jailer::seccomp::apply(&spec).expect("install the filter");

    let audit = dir.join("audit");
    let report = ConfinementSelfTest::network_endpoint(&audit, runtime.handle()).run();
    println!("ran={}", report.ran.join(","));
    for (probe, error) in &report.errored {
        println!("errored={probe}: {error}");
    }
    std::process::exit(0);
}

fn refusal_outside_a_probe(dir: &Path) -> ! {
    mvm_hostd::jailer::seccomp::apply(&endpoint_spec(dir)).expect("install the filter");
    // `getppid` is not on the allowlist.
    let _ = std::os::unix::process::parent_id();
    std::process::exit(0);
}

fn run_scenario(scenario: &str) -> (Output, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let output = Command::new(std::env::current_exe().expect("current_exe"))
        .env(CHILD_ENV, scenario)
        .env(DIR_ENV, dir.path())
        .output()
        .expect("run the scenario child");
    (output, dir)
}

fn describe(output: &Output) -> String {
    format!(
        "status={:?} signal={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        output.status.signal(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The endpoint's whole self-test runs to completion under the filter the
/// endpoint ships, and every probe's calls succeed.
#[test]
fn the_endpoint_self_test_passes_under_the_real_filter() {
    let (output, dir) = run_scenario("real-filter");
    let report = describe(&output);
    assert!(output.status.success(), "{report}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(
            "ran=thread-spawn,blocking-pool,clock-and-entropy,name-resolution,\
             tls-trust-store,file-append,socket-accept"
        ),
        "{report}"
    );
    assert!(!stdout.contains("errored="), "{report}");
    // The audit-path probe cleans up after itself.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path().join("audit"))
        .expect("audit dir")
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// A filter that lacks a call a probe needs kills the process at startup, and
/// the last thing it writes names the probe and the call.
#[test]
fn a_filter_missing_a_required_syscall_is_named_with_the_probe() {
    let (output, _dir) = run_scenario("without-flock");
    let report = describe(&output);
    assert_eq!(output.status.signal(), Some(libc::SIGSYS), "{report}");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let refused = format!(
        "seccomp refused {} syscall {}",
        std::env::consts::ARCH,
        libc::SYS_flock
    );
    assert!(stderr.contains(&refused), "{report}");
    assert!(
        stderr.contains("during self-test probe \"file-append\""),
        "{report}"
    );
    assert!(stderr.contains("CONFINED_ROLE_SYSCALLS"), "{report}");
    // Killed inside the probe: it never reported finishing.
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("ran="),
        "{report}"
    );
}

/// A refusal after the self-test — the case the self-test exists to make
/// rare — is still named, just without a probe.
#[test]
fn a_refusal_outside_the_self_test_is_still_named() {
    let (output, _dir) = run_scenario("refusal-outside-a-probe");
    let report = describe(&output);
    assert_eq!(output.status.signal(), Some(libc::SIGSYS), "{report}");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let refused = format!(
        "seccomp refused {} syscall {}",
        std::env::consts::ARCH,
        libc::SYS_getppid
    );
    assert!(stderr.contains(&refused), "{report}");
    assert!(!stderr.contains("self-test probe"), "{report}");
}
