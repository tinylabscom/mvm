//! Tests for standby creation: the factory parent's boot shape, capture and refusals.
#![cfg(test)]

use super::{test_support::*, *};
use crate::driver::MockDriver;
use mvm_core::util::test_env::TestEnv;

#[test]
fn trusted_snapshot_requires_the_exact_opt_in_value() {
    assert!(trusted_snapshot_opted_in(Some("1")));
    assert!(!trusted_snapshot_opted_in(Some("0")));
    assert!(!trusted_snapshot_opted_in(Some("")));
    assert!(!trusted_snapshot_opted_in(None));
}

fn without_per_boot_tokens(cmdline: &str) -> String {
    cmdline
        .split_whitespace()
        .filter(|token| !token.starts_with("mvm.hostname=") && !token.starts_with("mvm.hostepoch="))
        .collect::<Vec<_>>()
        .join(" ")
}

fn mapping_standby<D: VmmDriver, S: NetworkEndpointSpawner, B: BrokerRegistrar>(
    runner: &WorkloadRunner<D, S, B>,
    ctx: &SpawnContext<'_>,
    spec: &StandbySpec,
) -> std::result::Result<StandbyHandle, StandbyError> {
    let config = factory_parent_config(ctx.launch.expect("mapping fixture has a launch"), spec)?;
    runner.spawn_bound_standby_captured(ctx, spec, &config)
}

/// A spawned parent is claimable only once captured: the handle must carry
/// the checkpoint a later claim verifies content and lineage against, and
/// that checkpoint must carry saved memory — a rootfs-only capture would
/// make every claim a cold boot.
#[test]
fn spawn_standby_captured_stamps_a_memory_carrying_checkpoint() {
    use mvm_core::checkpoint::CheckpointClass;

    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let tmp = tempfile::tempdir().unwrap();
    let store = CheckpointStore::at(tmp.path().join("checkpoints"));
    let rootfs = tmp.path().join("parent-rootfs.ext4");
    std::fs::write(&rootfs, b"parent rootfs bytes").unwrap();

    let runner = WorkloadRunner::new(
        MockDriver::default().with_vm_full_rootfs(&rootfs),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let launch = checked_source_config("workload-a", rootfs.display().to_string());
    let spec = standby_spec_for("parent-a", tmp.path(), &launch);
    let guest = spawn_activation_guest(runner.driver.clone(), &spec.id);
    let handle = runner
        .spawn_standby_captured(
            &SpawnContext {
                checkpoints: &store,
                launch: Some(&launch),
            },
            &spec,
        )
        .unwrap();
    guest.join().unwrap();

    let id = handle
        .parent_checkpoint
        .expect("a captured parent must carry its checkpoint id");
    let meta = store.read_meta(&CheckpointId::new(id)).unwrap();
    assert_eq!(meta.class, CheckpointClass::VmFull);
    assert!(
        meta.content.iter().any(|b| b.name == "memory.bin"),
        "the capture must carry saved memory, got: {:?}",
        meta.content.iter().map(|b| &b.name).collect::<Vec<_>>()
    );
    // The parent is released once captured — a pool slot costs disk, not a
    // resident VM — and the handle says so.
    assert_eq!(handle.pid, 0, "a captured parent backs no live process");
    assert!(
        runner.driver.killed_vms().contains(&spec.id),
        "the captured parent must be stopped, got: {:?}",
        runner.driver.killed_vms()
    );
}

/// A backend that keeps the paused source resident after capture hands the
/// claim a handle that still names the live process, and does not stop it.
#[test]
fn spawn_standby_captured_keeps_a_retained_parent_resident() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let tmp = tempfile::tempdir().unwrap();
    let store = CheckpointStore::at(tmp.path().join("checkpoints"));
    let rootfs = tmp.path().join("parent-rootfs.ext4");
    std::fs::write(&rootfs, b"parent rootfs bytes").unwrap();

    let runner = WorkloadRunner::new(
        MockDriver::default()
            .with_vm_full_rootfs(&rootfs)
            .with_retained_paused_source(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let launch = checked_source_config("workload-a", rootfs.display().to_string());
    let spec = standby_spec_for("parent-retained", tmp.path(), &launch);
    let guest = spawn_activation_guest(runner.driver.clone(), &spec.id);
    let handle = runner
        .spawn_standby_captured(
            &SpawnContext {
                checkpoints: &store,
                launch: Some(&launch),
            },
            &spec,
        )
        .unwrap();
    guest.join().unwrap();
    assert_eq!(handle.pid, std::process::id());
    assert!(!runner.driver.killed_vms().contains(&spec.id));
}

/// The trusted-snapshot backend is opened only on a macOS build that has the
/// feature; setting its switch elsewhere must not change how a parent is
/// captured.
#[test]
fn the_trusted_snapshot_switch_does_not_reroute_a_capture_on_a_build_without_the_backend() {
    if cfg!(all(feature = "trusted-apfs", target_os = "macos")) {
        return;
    }
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    env.set("MVM_HVF_ENABLE_TRUSTED_SNAPSHOT", "1");

    let tmp = tempfile::tempdir().unwrap();
    let store = CheckpointStore::at(tmp.path().join("checkpoints"));
    let rootfs = tmp.path().join("parent-rootfs.ext4");
    std::fs::write(&rootfs, b"parent rootfs bytes").unwrap();
    let runner = WorkloadRunner::new(
        MockDriver::default().with_vm_full_rootfs(&rootfs),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let launch = checked_source_config("workload-a", rootfs.display().to_string());
    let spec = standby_spec_for("parent-switch", tmp.path(), &launch);
    let guest = spawn_activation_guest(runner.driver.clone(), &spec.id);
    runner
        .spawn_standby_captured(
            &SpawnContext {
                checkpoints: &store,
                launch: Some(&launch),
            },
            &spec,
        )
        .expect("the switch is inert without the backend");
    guest.join().unwrap();
}

#[test]
fn a_runner_reports_the_standby_capabilities_of_its_driver() {
    let plain = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    assert!(!plain.supports_preloaded_standby());
    assert_eq!(plain.late_volume_slots(), 0);
    let slotted = WorkloadRunner::new(
        MockDriver::default()
            .with_preloaded_standby()
            .with_late_volume_slots(4),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    assert!(slotted.supports_preloaded_standby());
    assert_eq!(slotted.late_volume_slots(), 4);
}

/// An unsigned source-built runtime is booted on the cmdline the runner
/// derives from the bound launch, never on the one the caller supplied.
#[test]
fn a_checked_source_launch_boots_the_derived_cmdline_not_the_supplied_one() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let (_image, rootfs) = overlay_aware_rootfs("checked-cmdline");
    let config = checked_source_config("checked-cmdline", rootfs.clone());
    let driver = MockDriver::default().with_vm_full_rootfs(Path::new(&rootfs));
    let guest = spawn_activation_guest(driver.clone(), "checked-cmdline");
    let runner = WorkloadRunner::new(
        driver,
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let redaction = RedactionPolicy::default();
    runner
        .start_workload(&WorkloadLaunchInputs {
            config: &config,
            tenant: "local",
            secrets: &[],
            redaction: &redaction,
            network_policy: &config.network_policy,
            cmdline: "mvm.supplied_sentinel=1".into(),
        })
        .unwrap();
    guest.join().unwrap();
    let specs = runner.driver.booted_specs();
    assert!(
        !specs[0].cmdline.contains("mvm.supplied_sentinel"),
        "{}",
        specs[0].cmdline
    );
}

/// The launch a warm parent is spawned for: a plain sealed boot whose rootfs
/// is the one the parent will attach.
fn standby_launch_config(rootfs: &Path) -> VmStartConfig {
    VmStartConfig {
        name: "workload-a".into(),
        rootfs_path: rootfs.display().to_string(),
        kernel_path: Some("/img/kernel".into()),
        cpus: 2,
        memory_mib: 512,
        // Every launch carries the overlay triple — it is the only source
        // of the guest agent, so a parent warmed without one cannot reach
        // an agent to be captured.
        runtime_overlay_path: Some("/img/runtime.ext4".into()),
        runtime_overlay_verity_path: Some("/img/runtime.verity".into()),
        runtime_overlay_roothash: Some("b".repeat(64)),
        ..Default::default()
    }
}

/// A spawn-and-capture records a clean, pre-workload parent: the pool
/// round-trip the CLI runs afterwards sees an idle standby, and — the
/// invariant this test actually exercises — no substitution endpoint and no
/// broker are ever stood up for it, unlike every real workload boot on this
/// runner. Those two are the host-side authority a parent must never hold.
#[test]
fn spawn_standby_captured_records_a_parent_with_no_endpoint_and_no_broker() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let tmp = tempfile::tempdir().unwrap();
    let store = CheckpointStore::at(tmp.path().join("checkpoints"));
    let rootfs = tmp.path().join("parent-rootfs.ext4");
    std::fs::write(&rootfs, b"parent rootfs bytes").unwrap();

    let runner = WorkloadRunner::new(
        MockDriver::default().with_vm_full_rootfs(&rootfs),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let launch = checked_source_config("workload-a", rootfs.display().to_string());
    let spec = standby_spec_for("standby-test", &tmp.path().join("vm"), &launch);
    let guest = spawn_activation_guest(runner.driver.clone(), &spec.id);
    let handle = runner
        .spawn_standby_captured(
            &SpawnContext {
                checkpoints: &store,
                launch: Some(&launch),
            },
            &spec,
        )
        .expect("spawn_standby_captured succeeds through the mock driver");
    guest.join().unwrap();

    let pool = crate::standby_pool::SupervisorStandbyPool::at(tmp.path().join("pool"));
    pool.record(&handle).unwrap();
    let recorded = pool.list().unwrap();
    assert_eq!(recorded.len(), 1);
    assert!(matches!(
        recorded[0].state,
        mvm_core::vm_backend::StandbyState::Idle
    ));

    // The parent boots with no vsock channel at all: no egress relay, no
    // broker port, no exit report — so a stray guest dial to any of them
    // stays ECONNREFUSED. Only a claimed child gets those three; parents and
    // workloads live in disjoint namespaces and this is where that holds.
    let booted = runner.driver.booted_specs();
    assert_eq!(booted.len(), 1);
    let identity = booted[0].blocks.last().unwrap();
    assert_eq!(
        identity.source,
        Path::new(&spec.vm_state_dir).join(mvm_vmm::host::flowmux_identity::IDENTITY_DRIVE_FILE)
    );
    assert!(identity.read_only);
    assert!(
        booted[0].vsock.is_empty(),
        "parent boot must carry no vsock channel (no egress, broker or exit channel), got: {:?}",
        booted[0]
            .vsock
            .iter()
            .map(|p| p.service.port())
            .collect::<Vec<_>>()
    );

    // No substitution endpoint and no broker were stood up for the parent:
    // neither double was ever invoked, unlike every real `start_workload`.
    assert!(
        runner.spawner.seen.lock().unwrap().is_none(),
        "a standby parent must never get a substitution endpoint"
    );
    assert!(
        runner.broker.seen.lock().unwrap().is_none(),
        "a standby parent must never get a host-services broker"
    );
}

#[test]
fn standby_parent_refuses_missing_identity_before_boot() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let rootfs = home.path().join("rootfs.ext4");
    std::fs::write(&rootfs, b"parent rootfs").unwrap();
    let launch = standby_launch_config(&rootfs);
    let spec = standby_spec_for("no-identity", &home.path().join("parent"), &launch);
    let store = CheckpointStore::at(home.path().join("checkpoints"));
    let runner = WorkloadRunner::new(
        MockDriver::default().with_vm_full_rootfs(&rootfs),
        RealNetworkEndpointSpawner,
        RecordingBrokerRegistrar::new(),
    );
    let error = mapping_standby(
        &runner,
        &SpawnContext {
            checkpoints: &store,
            launch: Some(&launch),
        },
        &spec,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("provision standby guest identity"),
        "{error}"
    );
    assert!(runner.driver.booted_specs().is_empty());
    assert!(runner.broker.seen.lock().unwrap().is_none());
}

/// A parent's cmdline gets the same truncation refusal a workload's does,
/// and needs it more: a child inherits the parent's cmdline out of restored
/// memory rather than deriving its own, so a parent booted with its trailing
/// tokens silently dropped by the kernel hands that loss to every child.
#[test]
fn spawn_standby_captured_refuses_a_parent_cmdline_the_kernel_would_truncate() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let tmp = tempfile::tempdir().unwrap();
    let store = CheckpointStore::at(tmp.path().join("checkpoints"));
    let rootfs = tmp.path().join("parent-rootfs.ext4");
    std::fs::write(&rootfs, b"parent rootfs bytes").unwrap();

    let runner = WorkloadRunner::new(
        MockDriver::default().with_vm_full_rootfs(&rootfs),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let mut launch = standby_launch_config(&rootfs);
    // A sealed boot; the universal initramfs moves the roothash off the
    // cmdline, so force an overflow with an oversized verb grant instead.
    launch.verity_path = Some(tmp.path().join("rootfs.verity").display().to_string());
    launch.roothash = Some("a".repeat(4096));
    launch.initrd_path = Some(mvm_vmm::host::cmdline::seed_universal_initramfs(
        home.path(),
    ));
    let state_dir = mvm_core::config::vm_state_dir("parent-oversized");
    std::fs::create_dir_all(&state_dir).unwrap();
    let nonce = mvm_core::plan::Nonce::from_bytes([3u8; 16]);
    let not_after = mvm_core::time::parse_iso8601("2099-01-01T00:00:00Z").unwrap();
    let envelope = mvm_core::protocol::vm_backend::VerbGrantEnvelope {
        pubkey_hex: "cc".repeat(32),
        plan_nonce_hex: nonce.as_hex().to_string(),
        predecessor_session_id: None,
        predecessor_plan_nonce_hex: None,
        grant: mvm_core::plan::VerbGrant {
            session_id: "parent-oversized".into(),
            plan_nonce: nonce,
            not_after,
            verbs: vec![mvm_core::plan::VerbId::new(&"a".repeat(4000)).unwrap()],
            drive: None,
            application_terminal: None,
            sig: vec![0u8; 64],
        },
    };
    std::fs::write(
        state_dir.join("verb-grant.json"),
        serde_json::to_vec(&envelope).unwrap(),
    )
    .unwrap();
    // Derive the spec from this launch: the compat key now carries the
    // launch's egress enablement, so a spec built from the rootfs alone
    // could refuse for a mismatched key rather than the oversized cmdline
    // this test is about.
    let spec = standby_spec_for("parent-oversized", tmp.path(), &launch);

    let err = mapping_standby(
        &runner,
        &SpawnContext {
            checkpoints: &store,
            launch: Some(&launch),
        },
        &spec,
    )
    .expect_err("an oversized parent cmdline must be refused before the boot");

    assert!(
        matches!(err, StandbyError::SpawnFailed(ref m) if m.contains("command line")),
        "expected a SpawnFailed naming the kernel command line, got: {err:?}"
    );
    assert!(
        runner.driver.booted_specs().is_empty(),
        "nothing may boot before the refusal"
    );
}

/// A spawn with no launch to mirror is refused outright. The alternative —
/// inventing a default boot shape — is what produced a parent that booted a
/// bare rootfs while every workload booted a verity-sealed stack plus the
/// runtime overlay carrying the guest agent.
#[test]
fn spawn_standby_captured_refuses_without_the_launch_it_must_mirror() {
    let tmp = tempfile::tempdir().unwrap();
    let store = CheckpointStore::at(tmp.path().join("checkpoints"));
    let rootfs = tmp.path().join("parent-rootfs.ext4");
    std::fs::write(&rootfs, b"parent rootfs bytes").unwrap();

    let runner = WorkloadRunner::new(
        MockDriver::default().with_vm_full_rootfs(&rootfs),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let spec = sample_standby_spec("parent-a", tmp.path(), &rootfs);

    let err = runner
        .spawn_standby_captured(
            &SpawnContext {
                checkpoints: &store,
                launch: None,
            },
            &spec,
        )
        .expect_err("a parent cannot be assembled without the launch it serves");

    assert!(
        matches!(err, StandbyError::SpawnFailed(ref m) if m.contains("launch config")),
        "expected a SpawnFailed naming the missing launch, got: {err:?}"
    );
    assert!(
        runner.driver.booted_specs().is_empty(),
        "nothing may boot before the refusal"
    );
}

/// The same guard as `standby_boot`'s, but through the runner's real
/// wiring: the shipped defect was not that the mappers disagreed, it was
/// that the spawn path never called them. Boot a sealed, overlay-carrying
/// launch as a workload and then warm a parent for it, and the two specs
/// the driver was handed must describe the same guest.
#[test]
fn the_parent_and_the_workload_boot_the_same_shape_through_the_runner() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let (dir, rootfs) = overlay_aware_rootfs("shape-parity");
    std::fs::write(dir.path().join("rootfs.verity"), b"verity").unwrap();
    let source = checked_source_config("shape-parity", rootfs.clone());
    let lease = crate::runtime_evidence::RuntimeLifecycleLease::acquire("shape-parity").unwrap();
    let bound = lease.bind(&source).unwrap();
    let launch = VmStartConfig {
        verity_path: Some(dir.path().join("rootfs.verity").display().to_string()),
        roothash: Some("a".repeat(64)),
        cpus: 2,
        memory_mib: 512,
        ..bound
    };

    let store = CheckpointStore::at(home.path().join("checkpoints"));
    let driver = MockDriver::default().with_vm_full_rootfs(Path::new(&rootfs));
    let guest = spawn_activation_guest(driver.clone(), "shape-parity");
    let parent_guest = spawn_activation_guest(driver.clone(), "standby-parity");
    let runner = WorkloadRunner::new(
        driver,
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    mapping_start(&runner, &launch).expect("workload boots");
    guest.join().expect("guest thread");
    let spec = standby_spec_for(
        "standby-parity",
        &home.path().join("standby-parity"),
        &launch,
    );
    mapping_standby(
        &runner,
        &SpawnContext {
            checkpoints: &store,
            launch: Some(&launch),
        },
        &spec,
    )
    .expect("warm parent spawns for that launch");
    parent_guest.join().expect("parent guest thread");

    let booted = runner.driver.booted_specs();
    assert_eq!(booted.len(), 2, "one workload boot, then one parent boot");
    let (workload, parent) = (&booted[0], &booted[1]);
    // Non-vacuity: the fixture must actually exercise the full sealed stack,
    // or "the two match" would say nothing.
    assert_eq!(
        workload.blocks.len(),
        5,
        "fixture must boot rootfs + verity + overlay + overlay verity + identity"
    );
    assert_boot_disks_and_private_identity(parent, workload, Path::new(&spec.vm_state_dir));
    assert_eq!(
        without_per_boot_tokens(&parent.cmdline),
        without_per_boot_tokens(&workload.cmdline)
    );
    assert!(!parent.cmdline.contains("mvm.hostname="));
    assert_eq!(parent.kernel, workload.kernel);
    assert_eq!(parent.initramfs, workload.initramfs);
}

/// The same parity, for the launch shape the pool used to refuse: one whose
/// policy allows egress.
///
/// A restored child inherits its cmdline from the parent's saved memory, so
/// the only way a warm child ends up with the guest egress client a cold boot
/// would have started is for the parent to have started it. This drives both
/// paths through the real runner wiring and requires the two specs to be
/// equal — and it names the token, so a failure says which side lost it. The
/// parent still gets no substitution endpoint and no broker: what it boots is
/// the enablement, not the authority.
#[test]
fn a_parent_warmed_for_an_egress_allowing_launch_boots_that_launchs_shape() {
    use mvm_core::network_policy::HostPort;

    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    // `_dir` holds the rootfs's temp dir alive for the whole test.
    let (_dir, rootfs) = overlay_aware_rootfs("egress-parity");
    let source = checked_source_config("egress-parity", rootfs.clone());
    let lease = crate::runtime_evidence::RuntimeLifecycleLease::acquire("egress-parity").unwrap();
    let bound = lease.bind(&source).unwrap();
    let launch = VmStartConfig {
        network_policy: NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]),
        cpus: 2,
        memory_mib: 512,
        ..bound
    };

    let store = CheckpointStore::at(home.path().join("checkpoints"));
    let driver = MockDriver::default().with_vm_full_rootfs(Path::new(&rootfs));
    let guest = spawn_activation_guest(driver.clone(), "egress-parity");
    let parent_guest = spawn_activation_guest(driver.clone(), "standby-egress-parity");
    let runner = WorkloadRunner::new(
        driver,
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    mapping_start(&runner, &launch).expect("workload boots");
    guest.join().unwrap();
    let spec = standby_spec_for(
        "standby-egress-parity",
        &home.path().join("standby-egress-parity"),
        &launch,
    );
    assert!(
        spec.vsock_egress,
        "the compat key for this launch must ask for an egress-enabled parent"
    );
    mapping_standby(
        &runner,
        &SpawnContext {
            checkpoints: &store,
            launch: Some(&launch),
        },
        &spec,
    )
    .expect("warm parent spawns for an egress-allowing launch");
    parent_guest.join().unwrap();

    let booted = runner.driver.booted_specs();
    assert_eq!(booted.len(), 2, "one workload boot, then one parent boot");
    let (workload, parent) = (&booted[0], &booted[1]);
    assert!(
        workload.cmdline.contains("mvm.vsock_egress=1"),
        "fixture must boot the guest egress client: {}",
        workload.cmdline
    );
    assert!(
        parent.cmdline.contains("mvm.vsock_egress=1"),
        "the parent must boot it too, or every child restored from it has no network: {}",
        parent.cmdline
    );
    assert_eq!(
        without_per_boot_tokens(&parent.cmdline),
        without_per_boot_tokens(&workload.cmdline)
    );
    assert!(!parent.cmdline.contains("mvm.hostname="));
    assert_boot_disks_and_private_identity(parent, workload, Path::new(&spec.vm_state_dir));
    assert!(
        !parent.cmdline.contains("api.example.com"),
        "the parent's cmdline must name no destination: {}",
        parent.cmdline
    );
    assert!(
        parent.vsock.is_empty(),
        "an egress-enabled parent still wires no egress channel to dial"
    );
    assert!(!parent.trusted_builder);
}

fn assert_boot_disks_and_private_identity(
    parent: &mvm_vmm::driver::spec::VmmSpec,
    workload: &mvm_vmm::driver::spec::VmmSpec,
    parent_state: &Path,
) {
    let (parent_identity, parent_disks) = parent.blocks.split_last().unwrap();
    let (workload_identity, workload_disks) = workload.blocks.split_last().unwrap();
    assert_eq!(
        parent_disks, workload_disks,
        "parent retains the workload's disk stack"
    );
    for (identity, state) in [
        (parent_identity, parent_state.to_path_buf()),
        (workload_identity, vm_state_dir(&workload.name)),
    ] {
        assert_eq!(
            identity.source,
            state.join(mvm_vmm::host::flowmux_identity::IDENTITY_DRIVE_FILE)
        );
        assert!(identity.read_only);
        assert!(!identity.ephemeral);
    }
    assert_ne!(parent_identity.source, workload_identity.source);
    assert_eq!(
        parent_identity.device_node(),
        workload_identity.device_node()
    );
}

// ── Warm claim: the guarded fork of a clean parent into a fresh child ──────
