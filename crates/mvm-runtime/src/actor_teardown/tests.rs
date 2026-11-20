use super::*;
use std::process::Command;

fn helper(role: &str, resources: &[PathBuf]) -> Helper {
    let mut child = Some(
        Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("stand-in child"),
    );
    capture_helper(role, &mut child, resources).expect("original child capture")
}

#[test]
fn ownerless_successful_rollback_does_not_mint_no_dispatch_proof() {
    let directory = tempfile::tempdir().unwrap();
    let error = start_failure::finish(
        start_failure::PendingStart {
            vm: None,
            helpers: Arc::new(Mutex::new(Vec::new())),
            state: ResourceIdentity::capture(directory.path()).unwrap(),
            socket_directory: None,
            name: "uncertain-dispatch".into(),
            no_dispatch: None,
        },
        Err(anyhow::anyhow!("dispatch outcome unknown")),
    )
    .unwrap_err();
    let failure = error.downcast_ref::<ActorStartFailure>().unwrap();
    assert!(failure.take_owner().unwrap().is_none());
    failure.retry_stop().unwrap();
    assert!(failure.no_dispatch_proof().is_none());
}

#[test]
fn all_original_helpers_are_reaped_before_resources_are_removed() {
    let dir = tempfile::tempdir().unwrap();
    let resource = dir.path().join("holder.sock");
    std::fs::write(&resource, b"stand-in").unwrap();
    let mut helpers = vec![
        helper("mailbox", &[]),
        helper("actor-holder", std::slice::from_ref(&resource)),
    ];
    let ids = helpers
        .iter()
        .map(|helper| helper.identity.pid)
        .collect::<Vec<_>>();
    reap_helpers(&mut helpers).unwrap();
    assert!(
        helpers
            .iter()
            .all(|helper| helper.owner.exit_status().is_some())
    );
    assert_eq!(
        ids,
        helpers
            .iter()
            .map(|helper| helper.identity.pid)
            .collect::<Vec<_>>()
    );
    remove_helper_resources(&helpers).unwrap();
    assert!(!resource.exists());
}

#[test]
fn changing_or_deleting_a_pid_file_does_not_change_original_child_custody() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("mailbox.pid");
    let mut helpers = vec![helper("mailbox", &[])];
    std::fs::write(&pid_file, std::process::id().to_string()).unwrap();
    std::fs::remove_file(&pid_file).unwrap();
    reap_helpers(&mut helpers).unwrap();
    assert!(helpers[0].owner.exit_status().is_some());
}

#[test]
fn replacement_resource_keeps_cleanup_unknown_even_after_all_children_exit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("endpoint.sock");
    std::fs::write(&path, b"original").unwrap();
    let mut helpers = vec![helper("endpoint", std::slice::from_ref(&path))];
    std::fs::rename(&path, dir.path().join("retained-original")).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    reap_helpers(&mut helpers).unwrap();
    assert!(remove_helper_resources(&helpers).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    assert!(
        remove_helper_resources(&helpers).is_err(),
        "retry cannot authorize replacement"
    );
}

#[test]
fn failed_capture_retains_the_exact_child_and_never_adopts_a_bare_pid() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Some(Command::new("sleep").arg("30").spawn().unwrap());
    let pid = child.as_ref().unwrap().id();
    assert!(capture_helper("mailbox", &mut child, &[dir.path().join("missing")]).is_err());
    let mut child = child.expect("failed capture retains child");
    assert_eq!(child.id(), pid);
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn original_resource_removal_is_idempotent_but_is_not_a_terminal_proof() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resource");
    std::fs::write(&path, b"resource").unwrap();
    let resource = ResourceIdentity::capture(&path).unwrap();
    resource.remove().unwrap();
    resource.remove().unwrap();
    assert!(!path.exists());
}

#[cfg(feature = "test-support")]
mod mock_lifecycle {
    use super::*;
    use mvm_contract::protocol::actor_budget::ActorResources;
    use mvm_core::util::test_env::TestEnv;
    use mvm_core::vm_backend::VmBackend;

    fn config() -> VmStartConfig {
        VmStartConfig {
            name: "actor-owned-test".into(),
            ..Default::default()
        }
    }

    #[test]
    fn explicit_entrypoint_dispatch_keeps_original_owner_available_for_stop() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .expect("home lock");
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let backend = AnyBackend::Mock(crate::mock::MockBackend::new());
        let mut owner = backend.start_owned_actor(&config(), None).unwrap();
        assert_eq!(
            owner.entrypoint,
            entrypoint::DispatchState::Ready,
            "boot did not dispatch the app"
        );
        let original = owner.journal().instance;
        let running = owner
            .dispatch_entrypoint(std::time::Instant::now() + std::time::Duration::from_secs(5))
            .unwrap();
        assert!(
            owner
                .dispatch_entrypoint(std::time::Instant::now() + std::time::Duration::from_secs(5))
                .is_err()
        );
        let reader = std::thread::spawn(move || running.wait(|_| {}));
        assert_eq!(
            reader.join().unwrap().unwrap(),
            mvm_agentd::vsock::EntrypointEvent::Exit { code: 0 }
        );
        assert!(owner.is_running().unwrap(), "app terminal is not VM exit");
        let proof = owner.stop_and_reap().unwrap();
        assert_eq!(proof.journal().instance, original);
    }

    #[test]
    fn entrypoint_handshake_failure_keeps_original_stop_custody_and_forbids_retry() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .expect("home lock");
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let backend = AnyBackend::Mock(crate::mock::MockBackend::new());
        let mut owner = backend.start_owned_actor(&config(), None).unwrap();
        let original = owner.journal().instance;
        std::fs::remove_file(mvm_core::config::mvm_keys_dir().join("host-signer.ed25519")).unwrap();
        assert!(
            owner
                .dispatch_entrypoint(std::time::Instant::now() + std::time::Duration::from_secs(5))
                .is_err()
        );
        assert_eq!(owner.entrypoint, entrypoint::DispatchState::Uncertain);
        assert!(owner.failed_entrypoint_stream.is_some());
        assert!(owner.is_running().unwrap());
        assert!(
            owner
                .dispatch_entrypoint(std::time::Instant::now() + std::time::Duration::from_secs(5))
                .is_err()
        );
        let proof = owner.stop_and_reap().unwrap();
        assert_eq!(proof.journal().instance, original);
    }

    #[test]
    fn observed_resource_envelope_accepts_exact_boundary_and_refuses_undercharge() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .expect("home lock");
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let backend = AnyBackend::Mock(crate::mock::MockBackend::new());
        let mut owner = backend.start_owned_actor(&config(), None).unwrap();
        let socket = home.path().join("holder.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let regular = home.path().join("config");
        std::fs::write(&regular, b"not a socket").unwrap();
        let mut child = Some(Command::new("sleep").arg("30").spawn().unwrap());
        owner
            .attach_helper("holder", &mut child, &[socket.clone(), socket, regular])
            .unwrap();
        let descriptors = owner.helpers[0].owner.retained_process_descriptor_count();
        assert_eq!(descriptors, 1, "one actual kernel observer was retained");
        let exact = ActorResources {
            live_vms: 1,
            resident_vmms: 1,
            file_descriptors: descriptors,
            host_sockets: 1,
            ..Default::default()
        };
        owner.verify_resource_envelope(&exact).unwrap();
        for undercharged in [
            ActorResources {
                live_vms: 0,
                ..exact
            },
            ActorResources {
                resident_vmms: 0,
                ..exact
            },
            ActorResources {
                file_descriptors: 0,
                ..exact
            },
            ActorResources {
                host_sockets: 0,
                ..exact
            },
        ] {
            assert!(owner.verify_resource_envelope(&undercharged).is_err());
        }
        let proof = owner.stop_and_reap().unwrap();
        assert_eq!(proof.journal().instance, owner.journal().instance);
        assert!(
            owner.verify_resource_envelope(&exact).is_err(),
            "stopped is never Running"
        );
    }

    #[test]
    fn observed_resource_envelope_refuses_foreign_replacement_socket() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .expect("home lock");
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let backend = AnyBackend::Mock(crate::mock::MockBackend::new());
        let mut owner = backend.start_owned_actor(&config(), None).unwrap();
        let socket = home.path().join("holder.sock");
        let old = home.path().join("original.sock");
        let _original = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let mut child = Some(Command::new("sleep").arg("30").spawn().unwrap());
        owner
            .attach_helper("holder", &mut child, std::slice::from_ref(&socket))
            .unwrap();
        let charge = ActorResources {
            live_vms: 1,
            resident_vmms: 1,
            file_descriptors: 100,
            host_sockets: 100,
            ..Default::default()
        };
        owner.verify_resource_envelope(&charge).unwrap();
        std::fs::rename(&socket, &old).unwrap();
        let replacement = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert!(owner.verify_resource_envelope(&charge).is_err());
        drop(replacement);
        std::fs::remove_file(&socket).unwrap();
        std::fs::rename(&old, &socket).unwrap();
        owner.verify_resource_envelope(&charge).unwrap();
        let proof = owner.stop_and_reap().unwrap();
        assert_eq!(proof.journal().instance, owner.journal().instance);
    }

    #[test]
    fn retained_terminal_owner_can_retry_proof_after_interrupted_durable_release() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .expect("home lock");
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let backend = AnyBackend::Mock(crate::mock::MockBackend::new());
        let mut owner = backend.start_owned_actor(&config(), None).unwrap();
        assert!(owner.is_running().unwrap());
        let first = owner.stop_and_reap().unwrap();
        // No reservation or journal is changed by runtime proof creation.
        let retry = owner.stop_and_reap().unwrap();
        assert_eq!(first.journal().instance, retry.journal().instance);
        assert!(!crate::mock::MockBackend::vm_dir(&config().name).exists());
    }

    #[test]
    fn typed_start_failure_transfers_original_generation_into_unknown_owner_slot() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .expect("home lock");
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let model = crate::mock::MockBackend::new();
        let id = model.start(&config()).unwrap();
        let generation = model.actor_generation(&id).unwrap();
        let pending = start_failure::PendingStart {
            vm: Some(OriginalVm::Mock {
                backend: model.clone(),
                id,
                generation,
            }),
            helpers: Arc::new(Mutex::new(vec![helper("mailbox", &[])])),
            state: ResourceIdentity::capture(&crate::mock::MockBackend::vm_dir(&config().name))
                .unwrap(),
            socket_directory: None,
            name: config().name,
            no_dispatch: None,
        };
        let error = start_failure::finish(pending, Err(anyhow::anyhow!("activation reply lost")))
            .unwrap_err();
        let retained = error
            .downcast_ref::<ActorStartFailure>()
            .expect("typed retained error");
        assert!(retained.no_dispatch_proof().is_none());
        let mut owner = retained
            .take_owner()
            .unwrap()
            .expect("original owner transferred");
        assert_eq!(
            owner.journal().instance,
            ActorInstance::Mock {
                vm_id: VmId(config().name),
                generation,
            }
        );
        assert!(
            retained.take_owner().unwrap().is_none(),
            "ownership transfers once"
        );
        let proof = owner.stop_and_reap().unwrap();
        assert_eq!(proof.journal().instance, owner.journal().instance);
        assert_eq!(model.count(), 0);
    }

    #[test]
    fn preboot_helper_capture_failure_is_reaped_or_retained_not_detached() {
        let dir = tempfile::tempdir().unwrap();
        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let error = match capture_spawned_helper("holder", child, &[dir.path().join("missing")]) {
            Ok(_) => panic!("missing resource cannot be captured"),
            Err(error) => error,
        };
        let retained = error
            .downcast_ref::<mvm_vmm::host::retained_spawn::RetainedSpawnFailure>()
            .expect("failed capture retains an original rollback witness");
        retained.retry_stop().unwrap();
        retained.retry_stop().unwrap();
    }

    #[test]
    fn attachment_failure_retains_and_reaps_child_but_never_returns_terminal_proof() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .expect("home lock");
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let backend = AnyBackend::Mock(crate::mock::MockBackend::new());
        let mut owner = backend.start_owned_actor(&config(), None).unwrap();
        let mut child = Some(Command::new("sleep").arg("30").spawn().unwrap());
        let pid = child.as_ref().unwrap().id();
        assert!(
            owner
                .attach_helper("mailbox", &mut child, &[home.path().join("missing")])
                .is_err()
        );
        assert!(
            child.is_none(),
            "capture failure transfers custody, never drops it"
        );
        assert_eq!(owner.journal().unverified_helpers[0].pid, Some(pid));
        let generous = ActorResources {
            live_vms: 1,
            resident_vmms: 1,
            file_descriptors: 100,
            host_sockets: 100,
            ..Default::default()
        };
        assert!(owner.verify_resource_envelope(&generous).is_err());
        assert!(owner.stop_and_reap().is_err());
        assert!(
            owner.quarantined[0]
                .owner
                .as_ref()
                .unwrap()
                .exit_status()
                .is_some()
        );
        assert!(owner.stop_and_reap().is_err());
    }

    #[test]
    fn reused_mock_name_is_never_stopped_by_an_older_owner() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .expect("home lock");
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let model = crate::mock::MockBackend::new();
        let backend = AnyBackend::Mock(model.clone());
        let mut owner = backend.start_owned_actor(&config(), None).unwrap();
        model.stop(owner.vm_id()).unwrap();
        let replacement = model.start(&config()).unwrap();
        assert!(
            owner
                .verify_resource_envelope(&ActorResources {
                    live_vms: 1,
                    resident_vmms: 1,
                    file_descriptors: 100,
                    host_sockets: 100,
                    ..Default::default()
                })
                .is_err(),
            "a replacement generation cannot satisfy original Running"
        );
        assert!(owner.stop_and_reap().is_err());
        assert_eq!(
            model.status(&replacement).unwrap(),
            mvm_core::vm_backend::VmStatus::Running
        );
        model.stop(&replacement).unwrap();
    }

    #[test]
    fn a_mock_stop_failure_retains_the_live_original_and_cannot_mint_proof() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .expect("home lock");
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let model = crate::mock::MockBackend::new();
        let backend = AnyBackend::Mock(model.clone().with_failing_stop());
        let mut owner = backend.start_owned_actor(&config(), None).unwrap();
        assert!(owner.stop_and_reap().is_err());
        assert!(owner.is_running().unwrap());
        model.stop(owner.vm_id()).unwrap();
    }
}
