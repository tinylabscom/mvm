//! Explicit owned-process witnesses. No hypervisor, keychain or guest is used.

use super::*;
use mvm_core::util::test_env::TestEnv;
use mvm_vmm::host::hvf_stop::{ConnectedInstance, OwnedInstance};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const HELPER_TEST: &str = "supervisor::hvf_stop::native_tests::owned_process_helper";

/// Run only as an explicitly spawned, test-owned subprocess.
#[test]
#[ignore = "subprocess entry point, not a standalone test"]
fn owned_process_helper() {
    let vm = std::env::var("MVM_OWNED_STOP_VM").unwrap();
    let mode = std::env::var("MVM_OWNED_STOP_MODE").unwrap();
    let stop = Box::leak(Box::new(AtomicBool::new(false)));
    let owner = StopControl::start(&vm, stop).unwrap();
    let (notice, stopped) = mpsc::sync_channel(1);
    owner.authority.0.state.lock().unwrap().stop_notice = Some(notice);
    println!("OWNED_READY");
    std::io::stdout().flush().unwrap();
    if mode != "natural" {
        stopped.recv_timeout(Duration::from_secs(20)).unwrap();
    }
    if mode == "natural" || mode == "ack-hold" {
        // Test-owned pipe is the fixture's explicit release event, not a stop
        // protocol shortcut. Production stop still has to observe real death.
        let mut release = [0];
        wait_readable(
            std::io::stdin().as_raw_fd(),
            Instant::now() + Duration::from_secs(30),
        );
        std::io::stdin().read_exact(&mut release).unwrap();
    }
    if mode != "no-terminal" {
        owner
            .publish_terminal_status(
                mvm_vmm::host::hvf_supervisor::ProtectedSupervisorStatus::Stopped,
            )
            .unwrap();
        assert!(matches!(
            owner.publish_finalized().unwrap(),
            FinalizationPublication::Durable
        ));
    }
    drop(owner);
}

fn spawn(vm: &str, mode: &str) -> Child {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            HELPER_TEST,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("MVM_OWNED_STOP_VM", vm)
        .env("MVM_OWNED_STOP_MODE", mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let output = child.stdout.as_mut().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = Vec::new();
    loop {
        wait_readable(output.as_raw_fd(), deadline);
        let mut byte = [0];
        output.read_exact(&mut byte).unwrap();
        line.push(byte[0]);
        assert!(line.len() <= 4096, "bounded helper readiness");
        if byte == [b'\n'] {
            if line.ends_with(b"OWNED_READY\n") {
                break;
            }
            line.clear();
        }
    }
    child
}

fn wait_readable(fd: libc::c_int, deadline: Instant) {
    let mut event = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "owned helper I/O deadline");
        let millis = i32::try_from(remaining.as_millis())
            .unwrap_or(i32::MAX)
            .max(1);
        // SAFETY: this test owns the pipe descriptor for the entire call.
        let ready = unsafe { libc::poll(&mut event, 1, millis) };
        if ready > 0 {
            return;
        }
        if ready < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        panic!("owned helper I/O did not become ready");
    }
}

#[test]
#[ignore = "requires scoped control review before owned native execution"]
fn native_owned_peer_stop_ignores_an_unrelated_live_pid_file() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let mut unrelated = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut child = Some(spawn("owned-peer", "stop"));
    std::fs::write(
        wire::state_dir("owned-peer").unwrap().join("hvf.pid"),
        unrelated.id().to_string(),
    )
    .unwrap();
    let owner = OwnedInstance::adopt(&mut child, "owned-peer").unwrap();
    let outcome = owner.stop();
    let unrelated_still_live = unrelated.try_wait().unwrap().is_none();
    drop(unrelated.stdin.take());
    unrelated.wait().unwrap();
    assert!(outcome.is_ok());
    assert!(
        unrelated_still_live,
        "PID evidence must never become signal authority"
    );
}

#[test]
#[ignore = "requires scoped control review before owned native execution"]
fn native_owned_natural_exit_remains_provable_after_endpoint_closes() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let mut child = spawn("natural-peer", "natural");
    let mut release = child.stdin.take().unwrap();
    let mut child = Some(child);
    let owner = OwnedInstance::adopt(&mut child, "natural-peer").unwrap();
    release.write_all(&[1]).unwrap();
    assert!(owner.wait(Instant::now() + Duration::from_secs(5)).is_ok());
    assert!(owner.try_exited().unwrap());
    assert!(owner.stop().is_ok());
}

#[test]
#[ignore = "requires scoped control review before owned native execution"]
fn native_ack_without_exit_times_out_and_retains_evidence() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let mut child = spawn("ack-peer", "ack-hold");
    let result = ConnectedInstance::connect("ack-peer").unwrap().stop();
    let alive = child.try_wait().unwrap().is_none();
    let retained = wire::read_instance("ack-peer").is_ok();
    child.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
    child.wait().unwrap();
    assert!(result.is_err());
    assert!(alive);
    assert!(retained);
}

#[test]
#[ignore = "requires scoped control review before owned native execution"]
fn native_exit_without_terminal_attestation_retains_evidence() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let mut child = spawn("no-terminal-peer", "no-terminal");
    let result = ConnectedInstance::connect("no-terminal-peer")
        .unwrap()
        .stop();
    child.wait().unwrap();
    assert!(result.is_err());
    assert!(wire::read_instance("no-terminal-peer").is_ok());
    assert!(
        !wire::state_dir("no-terminal-peer")
            .unwrap()
            .join(wire::FINALIZED_FILE)
            .exists()
    );
}

#[test]
#[ignore = "requires scoped control review before owned native execution"]
fn native_peer_pid_mismatch_refuses_without_consuming_owned_child() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let mut helper = spawn("mismatch-peer", "stop");
    let unrelated = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut unrelated = Some(unrelated);
    let refused = OwnedInstance::adopt(&mut unrelated, "mismatch-peer").is_err();
    let mut unrelated = unrelated.expect("refused adoption must retain ownership");
    let unrelated_still_live = unrelated.try_wait().unwrap().is_none();
    drop(unrelated.stdin.take());
    unrelated.wait().unwrap();
    let stopped = ConnectedInstance::connect("mismatch-peer").unwrap().stop();
    helper.wait().unwrap();
    assert!(refused);
    assert!(unrelated_still_live);
    assert!(stopped.is_ok());
}
