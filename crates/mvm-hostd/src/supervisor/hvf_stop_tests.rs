use super::*;
use mvm_core::protocol::hvf_control::{verify_challenge, verify_finalized};
use mvm_core::util::test_env::TestEnv;

struct Home {
    _env: TestEnv,
    _dir: tempfile::TempDir,
}

fn home() -> Home {
    let mut env = TestEnv::new();
    let dir = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(dir.path());
    Home {
        _env: env,
        _dir: dir,
    }
}

fn control(vm: &str) -> (StopControl, &'static AtomicBool) {
    let stop = Box::leak(Box::new(AtomicBool::new(false)));
    (StopControl::start(vm, stop).unwrap(), stop)
}

fn challenge(vm: &str) -> (UnixStream, SignedControl) {
    let deadline = Instant::now() + wire::CONNECTION_BUDGET;
    let mut stream = wire::connect(vm, deadline).unwrap();
    wire::write_all(&mut stream, &[9; 32], deadline).unwrap();
    let response = wire::read_frame(&mut stream, deadline).unwrap();
    (stream, response)
}

fn request(response: &SignedControl, instance: &HvfInstance) -> SignedControl {
    let (key, root) = wire::existing_operator().unwrap();
    let connection_nonce = verify_challenge(response, &root, instance, &[9; 32]).unwrap();
    broker_control::sign(
        ControlRequest::HvfInstanceV1(HvfInstanceControl::StopHvfInstance {
            instance: instance.clone(),
            connection_nonce,
            issued_at_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }),
        &key.to_bytes(),
    )
    .unwrap()
}

fn send(stream: &mut UnixStream, request: &SignedControl) -> bool {
    let deadline = Instant::now() + wire::CONNECTION_BUDGET;
    wire::write_frame(stream, request, deadline).unwrap();
    let mut acknowledgment = [0];
    wire::read_exact(stream, &mut acknowledgment, deadline).is_ok() && acknowledgment == [1]
}

#[test]
fn valid_stop_dispatches_but_does_not_publish_terminal_or_remove_evidence() {
    let _home = home();
    let (owner, stop) = control("dispatch");
    let instance = wire::read_instance("dispatch").unwrap();
    let (mut stream, response) = challenge("dispatch");
    assert!(send(&mut stream, &request(&response, &instance)));
    assert!(stop.load(Ordering::Acquire));
    assert!(
        !wire::state_dir("dispatch")
            .unwrap()
            .join(wire::FINALIZED_FILE)
            .exists()
    );
    drop(owner);
    assert_eq!(wire::read_instance("dispatch").unwrap(), instance);
    assert!(
        wire::state_dir("dispatch")
            .unwrap()
            .join(wire::SOCKET_FILE)
            .exists()
    );
}

#[test]
fn old_stop_authenticated_before_transfer_cannot_commit_after_rotation() {
    let _home = home();
    let (owner, stop) = control("parent");
    let parent = wire::read_instance("parent").unwrap();
    let (mut stream, response) = challenge("parent");
    let old_request = request(&response, &parent);
    owner.authority().transfer("child", || Ok(())).unwrap();
    let child = wire::read_instance("child").unwrap();
    assert_ne!(parent.boot_nonce, child.boot_nonce);
    assert!(!send(&mut stream, &old_request));
    assert!(!stop.load(Ordering::Acquire));
    let (mut stream, response) = challenge("child");
    assert!(send(&mut stream, &request(&response, &child)));
    assert!(stop.load(Ordering::Acquire));
}

#[test]
fn stop_first_refuses_transfer_before_running_capture_callback() {
    let _home = home();
    let (owner, stop) = control("stop-first");
    let instance = wire::read_instance("stop-first").unwrap();
    let (mut stream, response) = challenge("stop-first");
    assert!(send(&mut stream, &request(&response, &instance)));
    let ran = AtomicBool::new(false);
    assert!(
        owner
            .authority()
            .transfer("never-child", || {
                ran.store(true, Ordering::Release);
                Ok(())
            })
            .is_err()
    );
    assert!(!ran.load(Ordering::Acquire));
    assert!(stop.load(Ordering::Acquire));
    assert!(wire::read_instance("never-child").is_err());
}

#[test]
fn replay_on_fresh_connection_and_invalid_signature_are_refused() {
    let _home = home();
    let (_owner, stop) = control("replay");
    let instance = wire::read_instance("replay").unwrap();
    let (mut first, response) = challenge("replay");
    let valid = request(&response, &instance);
    let mut invalid = valid.clone();
    invalid.sig = "invalid".into();
    assert!(!send(&mut first, &invalid));
    assert!(!stop.load(Ordering::Acquire));
    let (mut second, _) = challenge("replay");
    assert!(!send(&mut second, &valid));
    assert!(!stop.load(Ordering::Acquire));
    let (mut third, response) = challenge("replay");
    assert!(send(&mut third, &request(&response, &instance)));
}

#[test]
fn failed_transfer_preserves_both_generations_and_stops_without_finalization() {
    let _home = home();
    let (owner, stop) = control("failed-parent");
    let parent = wire::read_instance("failed-parent").unwrap();
    assert!(
        owner
            .authority()
            .transfer("failed-child", || -> Result<()> {
                anyhow::bail!("capture finalization failed")
            })
            .is_err()
    );
    assert!(stop.load(Ordering::Acquire));
    assert_eq!(wire::read_instance("failed-parent").unwrap(), parent);
    assert!(wire::read_instance("failed-child").is_ok());
    assert!(owner.publish_finalized().is_err());
    for vm in ["failed-parent", "failed-child"] {
        assert!(
            !wire::state_dir(vm)
                .unwrap()
                .join(wire::FINALIZED_FILE)
                .exists()
        );
    }
}

#[test]
fn finalized_record_requires_explicit_owner_call_and_names_current_generation() {
    let _home = home();
    let (owner, _) = control("terminal-parent");
    owner
        .authority()
        .transfer("terminal-child", || Ok(()))
        .unwrap();
    owner.publish_finalized().unwrap();
    let terminal: SignedControl = wire::read_record(
        &wire::state_dir("terminal-child")
            .unwrap()
            .join(wire::FINALIZED_FILE),
    )
    .unwrap();
    let (_, root) = wire::existing_operator().unwrap();
    verify_finalized(
        &terminal,
        &root,
        &wire::read_instance("terminal-child").unwrap(),
    )
    .unwrap();
    assert!(
        verify_finalized(
            &terminal,
            &root,
            &wire::read_instance("terminal-parent").unwrap()
        )
        .is_err()
    );
    assert!(owner.publish_finalized().is_err());
}

#[test]
fn same_name_start_refuses_without_replacing_original_identity() {
    let _home = home();
    let (_owner, _) = control("exclusive");
    let instance = wire::read_instance("exclusive").unwrap();
    let other_stop = Box::leak(Box::new(AtomicBool::new(false)));
    assert!(StopControl::start("exclusive", other_stop).is_err());
    assert_eq!(wire::read_instance("exclusive").unwrap(), instance);
    assert!(!other_stop.load(Ordering::Acquire));
}
