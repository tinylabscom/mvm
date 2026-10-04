//! The confinement self-test, and confinement's reach across threads, under
//! the real filter and ruleset.
//!
//! Each test re-runs this binary as a child with `CHILD_ENV` naming a
//! scenario. The scenario runs from a constructor, before the test harness
//! starts its threads, so the child begins single-threaded exactly as
//! `mvm-network-endpoint` does. It sets up the way the endpoint does —
//! confinement first, then the async runtime — and reports on stdout. A
//! refusal kills the child, so the parent reads its exit status and its
//! stderr, which is where the refusal reporter writes.
//!
//! The scenarios that apply full confinement need Landlock, as the endpoint
//! itself does; the endpoint refuses to serve on a kernel without it.

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
        "thread-before-seccomp" => thread_started_before_the_filter(&dir),
        "thread-before-confinement" => thread_started_before_confinement(&dir),
        "threads-after-confinement" => threads_started_after_confinement(&dir),
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

/// The endpoint's runtime, built the way the endpoint builds it.
fn endpoint_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("mvm-subst-endpoint")
        .build()
        .expect("runtime")
}

fn self_test_under_filter(dir: &Path, without: Option<&str>) -> ! {
    let mut spec = endpoint_spec(dir);
    if let Some(name) = without {
        spec.allowed_syscalls.retain(|allowed| *allowed != name);
    }
    mvm_hostd::jailer::confine_self(&spec).expect("confine");
    let runtime = endpoint_runtime();

    let audit = dir.join("audit");
    let report = ConfinementSelfTest::network_endpoint(&audit, runtime.handle())
        .run()
        .expect("every required probe passes");
    println!("ran={}", report.ran.join(","));
    for (probe, error) in &report.errored {
        println!("errored={probe}: {error}");
    }
    std::process::exit(0);
}

/// A thread that exists before the filter is installed is still filtered: it
/// makes a call off the allowlist after the install and is killed for it.
fn thread_started_before_the_filter(dir: &Path) -> ! {
    let (go, wait) = std::sync::mpsc::channel::<()>();
    let early = std::thread::Builder::new()
        .name("started-before-the-filter".into())
        .spawn(move || {
            wait.recv().expect("released");
            eprintln!("early thread calling getppid");
            // `getppid` is not on the allowlist.
            std::os::unix::process::parent_id()
        })
        .expect("spawn");
    mvm_hostd::jailer::seccomp::apply(&endpoint_spec(dir)).expect("install the filter");
    go.send(()).expect("release");
    let parent = early.join().expect("join");
    println!("early thread was not filtered: getppid returned {parent}");
    std::process::exit(0);
}

/// Full confinement refuses a process that already has a second thread, and
/// applies nothing when it does.
fn thread_started_before_confinement(dir: &Path) -> ! {
    let (_hold, wait) = std::sync::mpsc::channel::<()>();
    let _early = std::thread::spawn(move || {
        let _ = wait.recv();
    });
    match mvm_hostd::jailer::confine_self(&endpoint_spec(dir)) {
        Ok(()) => println!("confined with a second thread running"),
        Err(error) => println!("refused: {error}"),
    }
    // SAFETY: PR_GET_SECCOMP takes no pointer arguments.
    let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    println!("seccomp-mode={mode}");
    println!("root-readable={}", std::fs::File::open("/").is_ok());
    std::process::exit(0);
}

/// Every kind of thread the endpoint starts after confining — a plain thread,
/// a runtime worker, and a blocking-pool thread started by that worker — is
/// refused a path outside the ruleset and runs under the filter.
fn threads_started_after_confinement(dir: &Path) -> ! {
    use mvm_hostd::jailer::self_test::require_calling_thread_confined;

    let outside = dir.join("outside-the-ruleset");
    std::fs::write(&outside, "not granted").expect("write the outside file");
    mvm_hostd::jailer::confine_self(&endpoint_spec(dir)).expect("confine");

    let report = |kind: &str, path: &Path| {
        let read = match std::fs::read(path) {
            Ok(_) => "read".to_string(),
            Err(error) => format!("errno {}", error.raw_os_error().unwrap_or(-1)),
        };
        let confined = match require_calling_thread_confined() {
            Ok(()) => "confined".to_string(),
            Err(error) => error.to_string(),
        };
        format!("{kind}: outside={read} check={confined}")
    };

    let plain = {
        let outside = outside.clone();
        std::thread::spawn(move || report("thread", &outside))
            .join()
            .expect("join")
    };
    println!("{plain}");

    let runtime = endpoint_runtime();
    let (worker, blocking) = runtime
        .block_on(runtime.spawn(async move {
            let worker = report("worker", &outside);
            let blocking = tokio::task::spawn_blocking(move || report("blocking", &outside))
                .await
                .expect("blocking task");
            (worker, blocking)
        }))
        .expect("worker task");
    println!("{worker}");
    println!("{blocking}");
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
            "ran=thread-spawn,blocking-pool,runtime-threads,clock-and-entropy,\
             name-resolution,tls-trust-store,file-append,socket-accept"
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

/// A thread started before the seccomp filter is installed is filtered too.
/// Without `SECCOMP_FILTER_FLAG_TSYNC` the filter binds only the installing
/// thread, and this call would succeed.
#[test]
fn a_thread_started_before_the_filter_is_filtered() {
    let (output, _dir) = run_scenario("thread-before-seccomp");
    let report = describe(&output);
    assert_eq!(output.status.signal(), Some(libc::SIGSYS), "{report}");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("early thread calling getppid"), "{report}");
    let refused = format!(
        "seccomp refused {} syscall {}",
        std::env::consts::ARCH,
        libc::SYS_getppid
    );
    assert!(stderr.contains(&refused), "{report}");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("not filtered"),
        "{report}"
    );
}

/// Landlock cannot reach a thread that already exists, so confinement refuses
/// a process with a second thread — and refuses before applying either layer,
/// rather than leaving the process half-confined.
#[test]
fn confinement_refuses_a_process_that_already_has_a_second_thread() {
    let (output, _dir) = run_scenario("thread-before-confinement");
    let report = describe(&output);
    assert!(output.status.success(), "{report}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("refused: refusing to confine a process with 2 threads"),
        "{report}"
    );
    assert!(stdout.contains("seccomp-mode=0"), "{report}");
    assert!(stdout.contains("root-readable=true"), "{report}");
}

/// The threads that do the endpoint's work all start after confinement and
/// inherit both layers: each is refused a file outside the ruleset (EACCES,
/// Landlock's answer) and reports seccomp filter mode.
#[test]
fn threads_started_after_confinement_inherit_both_layers() {
    let (output, _dir) = run_scenario("threads-after-confinement");
    let report = describe(&output);
    assert!(output.status.success(), "{report}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    for kind in ["thread", "worker", "blocking"] {
        let expected = format!("{kind}: outside=errno {} check=confined", libc::EACCES);
        assert!(stdout.contains(&expected), "{kind}: {report}");
    }
}
