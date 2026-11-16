use super::*;

fn binding() -> AuditBinding {
    AuditBinding {
        tenant_id: "tenant".into(),
        instance_id: "workload".into(),
        workload_id: "workload".into(),
        plan_id: "plan".into(),
        epoch: 7,
        generation: [9; 32],
    }
}

fn target() -> ShutdownTarget {
    ShutdownTarget::Hvf(HvfInstance {
        vm_id: "workload".into(),
        boot_nonce: [3; 32],
    })
}

#[test]
fn registration_matches_every_admitted_identity_component() {
    let expected = binding();
    for wrong in [
        AuditBinding {
            tenant_id: "other".into(),
            ..expected.clone()
        },
        AuditBinding {
            instance_id: "other".into(),
            ..expected.clone()
        },
        AuditBinding {
            workload_id: "other".into(),
            ..expected.clone()
        },
        AuditBinding {
            plan_id: "other".into(),
            ..expected.clone()
        },
        AuditBinding {
            epoch: 8,
            ..expected.clone()
        },
        AuditBinding {
            generation: [4; 32],
            ..expected.clone()
        },
    ] {
        let mut registration = Registration::new(expected.clone());
        assert!(registration.register(wrong, target()).is_err());
        assert!(registration.take_target().is_err());
    }
}

#[test]
fn no_target_duplicate_registration_and_repeated_notification_are_refused() {
    let mut registration = Registration::new(binding());
    assert!(registration.take_target().is_err());
    registration.register(binding(), target()).unwrap();
    assert!(registration.register(binding(), target()).is_err());
    assert_eq!(registration.take_target().unwrap(), target());
    assert!(registration.take_target().is_err());
    assert!(registration.register(binding(), target()).is_err());
}

#[test]
fn the_target_must_name_the_admitted_workload() {
    let mut registration = Registration::new(binding());
    let wrong = ShutdownTarget::Hvf(HvfInstance {
        vm_id: "other".into(),
        boot_nonce: [3; 32],
    });
    assert!(registration.register(binding(), wrong).is_err());
}

#[test]
fn registration_roundtrip_is_bounded_and_rejects_unknown_fields() {
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    let message = RegistrationMessage {
        binding: binding(),
        target: target(),
    };
    write_message(&mut writer, &message).unwrap();
    let decoded: RegistrationMessage = read_message(&mut reader).unwrap();
    assert_eq!(decoded.binding, binding());
    assert_eq!(decoded.target, target());
    writer
        .write_all(&(MAX_MESSAGE_BYTES + 1).to_be_bytes())
        .unwrap();
    assert!(read_message::<RegistrationMessage>(&mut reader).is_err());
    let mut extra = serde_json::to_value(binding()).unwrap();
    extra["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<AuditBinding>(extra).is_err());
}

#[test]
fn endpoint_receives_readiness_then_notifies_once_without_target_authority() {
    let (mut keeper, stream) = UnixStream::pair().unwrap();
    let mut endpoint = EndpointControl { stream };
    write_message(&mut keeper, &binding()).unwrap();
    endpoint.wait_ready(&binding()).unwrap();
    endpoint.notify_failure().unwrap();
    let mut notification = [0];
    keeper.read_exact(&mut notification).unwrap();
    assert_eq!(notification, [FAILURE]);
}

#[test]
fn a_stale_endpoint_cannot_accept_another_launch_readiness() {
    let (mut keeper, stream) = UnixStream::pair().unwrap();
    let mut endpoint = EndpointControl { stream };
    let mut wrong = binding();
    wrong.generation = [1; 32];
    write_message(&mut keeper, &wrong).unwrap();
    assert!(endpoint.wait_ready(&binding()).is_err());
}

#[test]
fn keeper_retains_the_target_after_launcher_completion_and_stops_a_real_child() {
    let launch = LaunchControl::new(binding()).unwrap();
    let binding = launch.binding().clone();
    let (notifications, endpoint) = UnixStream::pair().unwrap();
    let mut client = EndpointControl {
        stream: endpoint.try_clone().unwrap(),
    };
    let keeper = KeeperControl {
        binding: binding.clone(),
        registration: launch.keeper.try_clone().unwrap(),
        notifications,
        endpoint,
    };
    let child = Command::new("sleep").arg("30").spawn().unwrap();
    let worker = std::thread::spawn(move || {
        keeper.serve(
            |received| {
                assert_eq!(received, target());
                Ok(child)
            },
            |mut child| {
                assert!(child.try_wait()?.is_none());
                child.kill()?;
                assert!(!child.wait()?.success());
                Ok(())
            },
        )
    });
    launch.register(target()).unwrap();
    // No launcher capability remains; the detached keeper still holds the target.
    client.wait_ready(&binding).unwrap();
    client.notify_failure().unwrap();
    worker.join().unwrap().unwrap();
}

#[test]
fn each_launch_mints_a_new_generation_and_builder_has_no_target_variant() {
    let first = LaunchControl::new(binding()).unwrap();
    let second = LaunchControl::new(binding()).unwrap();
    assert_ne!(first.binding().generation, second.binding().generation);
    assert_ne!(first.binding().generation, [0; 32]);
    assert!(serde_json::from_str::<ShutdownTarget>(r#"{"Builder":{"name":"builder"}}"#).is_err());
    assert!(
        LaunchControl::new(AuditBinding {
            epoch: 0,
            ..binding()
        })
        .is_err()
    );
}

#[test]
fn losing_the_endpoint_after_registration_stops_the_target_once() {
    let launch = LaunchControl::new(binding()).unwrap();
    let binding = launch.binding().clone();
    let (notifications, endpoint) = UnixStream::pair().unwrap();
    let mut client = EndpointControl {
        stream: endpoint.try_clone().unwrap(),
    };
    let keeper = KeeperControl {
        binding: binding.clone(),
        registration: launch.keeper.try_clone().unwrap(),
        notifications,
        endpoint,
    };
    let worker = std::thread::spawn(move || {
        keeper.serve(Ok, |received| {
            assert_eq!(received, target());
            Ok(())
        })
    });
    launch.register(target()).unwrap();
    client.wait_ready(&binding).unwrap();
    drop(client);
    worker.join().unwrap().unwrap();
}

#[test]
fn absent_registration_never_publishes_endpoint_readiness() {
    let launch = LaunchControl::new(binding()).unwrap();
    let (notifications, endpoint) = UnixStream::pair().unwrap();
    let mut client = EndpointControl {
        stream: endpoint.try_clone().unwrap(),
    };
    let keeper = KeeperControl {
        binding: launch.binding().clone(),
        registration: launch.keeper.try_clone().unwrap(),
        notifications,
        endpoint,
    };
    let expected = launch.binding().clone();
    drop(launch);
    assert!(
        keeper
            .serve(
                |_| -> anyhow::Result<()> { panic!("no registration must not prepare a target") },
                |()| panic!("no registration must not stop a target"),
            )
            .is_err()
    );
    assert!(client.wait_ready(&expected).is_err());
}

#[test]
fn adopted_endpoint_drop_signals_eof_even_while_original_fd_is_open() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let (mut keeper, original) = UnixStream::pair().unwrap();
    env.set(NOTIFY_FD, original.as_raw_fd().to_string());
    let control = EndpointControl::from_env().unwrap().unwrap();
    for fd in [original.as_raw_fd(), control.stream.as_raw_fd()] {
        // SAFETY: both descriptors are owned live streams during inspection.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
    drop(control);
    keeper
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    assert_eq!(keeper.read(&mut [0]).unwrap(), 0);
}

fn fixture_command(role: &str, directory: &std::path::Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "host::audit_control::tests::lifecycle_process_fixture",
            "--ignored",
        ])
        .env_remove(REGISTER_FD)
        .env_remove(NOTIFY_FD)
        .env_remove(BINDING)
        .env("MVM_AUDIT_TEST_ROLE", role)
        .env("MVM_AUDIT_TEST_DIR", directory);
    command
}

#[test]
fn inherited_control_keeps_serving_after_the_real_launcher_process_exits() {
    use super::super::process_exit::{ProcessExitObserver, ProcessExitWait};
    use std::process::Stdio;
    use std::time::Instant;

    let directory = tempfile::tempdir().unwrap();
    let mut launcher = fixture_command("launcher", directory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut notification_trigger = launcher.stdin.take().unwrap();
    assert!(launcher.wait().unwrap().success());
    let keeper_pid = std::fs::read_to_string(directory.path().join("keeper.pid"))
        .unwrap()
        .parse()
        .unwrap();
    let observer = ProcessExitObserver::arm(keeper_pid).unwrap();
    assert_eq!(
        observer.wait_event(Instant::now()).unwrap(),
        ProcessExitWait::TimedOut
    );
    notification_trigger.write_all(&[1]).unwrap();
    drop(notification_trigger);
    assert_eq!(
        observer
            .wait_event(Instant::now() + Duration::from_secs(10))
            .unwrap(),
        ProcessExitWait::Exited,
    );
    let stopped: ShutdownTarget =
        serde_json::from_slice(&std::fs::read(directory.path().join("stopped.json")).unwrap())
            .unwrap();
    assert_eq!(stopped, target());
}

#[test]
#[ignore = "subprocess fixture for inherited audit control"]
fn lifecycle_process_fixture() {
    let Some(role) = std::env::var_os("MVM_AUDIT_TEST_ROLE") else {
        return;
    };
    let directory = PathBuf::from(std::env::var_os("MVM_AUDIT_TEST_DIR").unwrap());
    match role.to_str().unwrap() {
        "launcher" => {
            let launch = LaunchControl::new(binding()).unwrap();
            let mut command = fixture_command("keeper", &directory);
            launch.configure(&mut command).unwrap();
            let keeper = command.spawn().unwrap();
            std::fs::write(directory.join("keeper.pid"), keeper.id().to_string()).unwrap();
            launch.register(target()).unwrap();
            // The witness deliberately removes the launcher, not merely its
            // registration handle. The test controller observes the orphan's exit.
            std::process::exit(0);
        }
        "keeper" => {
            let keeper = KeeperControl::from_env().unwrap().unwrap();
            let mut command = fixture_command("endpoint", &directory);
            keeper.configure_endpoint(&mut command);
            command.env(
                "MVM_AUDIT_TEST_BINDING",
                serde_json::to_string(&keeper.binding).unwrap(),
            );
            let mut endpoint = command.spawn().unwrap();
            keeper
                .serve(Ok, |target| {
                    std::fs::write(directory.join("stopped.json"), serde_json::to_vec(&target)?)?;
                    Ok(())
                })
                .unwrap();
            assert!(endpoint.wait().unwrap().success());
        }
        "endpoint" => {
            assert!(std::env::var_os(REGISTER_FD).is_none());
            assert!(std::env::var_os(BINDING).is_none());
            let expected =
                serde_json::from_str(&std::env::var("MVM_AUDIT_TEST_BINDING").unwrap()).unwrap();
            let mut endpoint = EndpointControl::from_env().unwrap().unwrap();
            endpoint.wait_ready(&expected).unwrap();
            let _ = std::io::stdin().read_exact(&mut [0]);
            endpoint.notify_failure().unwrap();
        }
        _ => panic!("unknown audit fixture role"),
    }
}
