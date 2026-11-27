use super::*;

fn budget() -> HostBudget {
    HostBudget {
        max_total_memory_mib: Some(512),
        max_total_cpu_millicores: None,
    }
}

fn charge() -> MachineCharge {
    MachineCharge {
        memory_mib: 512,
        cpu_millicores: 0,
    }
}

#[test]
fn concurrent_final_slot_is_reserved_once() {
    let home = tempfile::tempdir().unwrap();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let attempts: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|name| {
                let barrier = &barrier;
                let home = home.path();
                scope.spawn(move || {
                    barrier.wait();
                    HostBudgetPermit::reserve_at(home, &budget(), name, charge())
                })
            })
            .collect();
        let results: Vec<_> = attempts.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    });
}

#[test]
fn a_pre_effect_failure_releases_but_coordinator_crash_retains() {
    let home = tempfile::tempdir().unwrap();
    drop(HostBudgetPermit::reserve_at(home.path(), &budget(), "first", charge()).unwrap());
    let permit = HostBudgetPermit::reserve_at(home.path(), &budget(), "second", charge()).unwrap();
    permit.bind_coordinator(&"a".repeat(64)).unwrap();
    drop(permit);
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "third", charge()).is_err());
}

#[test]
fn dispatch_without_charge_survives_owner_drop() {
    let home = tempfile::tempdir().unwrap();
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    plan.image.name = "first".into();
    plan.resources.mem_mib = 512;
    plan.grants = None;
    let permit = HostBudgetPermit::reserve_at(home.path(), &budget(), "first", charge()).unwrap();
    permit.bind_plan(&plan).unwrap();
    permit.mark_dispatching(&plan).unwrap();
    assert!(permit.mark_dispatching(&plan).is_err());
    drop(permit);
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "second", charge()).is_err());
}

#[test]
fn invalid_ledger_refuses_instead_of_resetting_capacity() {
    let home = tempfile::tempdir().unwrap();
    let permit = HostBudgetPermit::reserve_at(home.path(), &budget(), "first", charge()).unwrap();
    permit.bind_coordinator(&"a".repeat(64)).unwrap();
    let path = home.path().join("admission-budget/reservations.json");
    std::fs::write(path, b"bad").unwrap();
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "second", charge()).is_err());
}

#[test]
fn wrong_plan_or_coordinator_cannot_rebind_a_hold() {
    let home = tempfile::tempdir().unwrap();
    let permit = HostBudgetPermit::reserve_at(home.path(), &budget(), "first", charge()).unwrap();
    permit.bind_coordinator(&"a".repeat(64)).unwrap();
    assert!(permit.bind_coordinator(&"b".repeat(64)).is_err());
    let plan = mvm_core::plan::test_support::PlanFixture::new().build();
    assert!(permit.bind_plan(&plan).is_err());
}

fn plan(name: &str) -> ExecutionPlan {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    plan.workload.0 = name.into();
    plan.resources.mem_mib = 512;
    plan.grants = None;
    plan
}

#[test]
fn legacy_live_charge_and_pending_hold_share_one_total() {
    let home = tempfile::tempdir().unwrap();
    super::super::record_charge_at(home.path(), "legacy", charge()).unwrap();
    let directory = mvm_core::config::vm_state_dir_at(home.path(), "legacy");
    atomic_io::write_private(
        &directory.join("hvf.pid"),
        platform::current_owner().unwrap().as_bytes(),
    )
    .unwrap();
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "new", charge()).is_err());
}

#[test]
fn malformed_legacy_accounting_is_never_proof_of_free_capacity() {
    for corrupt_charge in [false, true] {
        let home = tempfile::tempdir().unwrap();
        super::super::record_charge_at(home.path(), "legacy", charge()).unwrap();
        let directory = mvm_core::config::vm_state_dir_at(home.path(), "legacy");
        if corrupt_charge {
            std::fs::write(directory.join(super::super::CHARGE_FILE), b"bad").unwrap();
        } else {
            atomic_io::write_private(&directory.join("hvf.pid"), b"2147483647 corrupt").unwrap();
        }
        assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "new", charge()).is_err());
    }
}

#[test]
fn committed_charge_is_counted_once_and_exact_death_releases_ordinary_capacity() {
    let home = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let identity =
        mvm_vmm::host::network_endpoint_spawn::EndpointPid::of_child(child.id()).render();
    let permit = HostBudgetPermit::reserve_at(home.path(), &budget(), "first", charge()).unwrap();
    let plan = plan("first");
    permit.bind_plan(&plan).unwrap();
    permit.mark_dispatching(&plan).unwrap();
    let directory = mvm_core::config::vm_state_dir_at(home.path(), "first");
    mvm_core::config::create_private_dir(&directory).unwrap();
    atomic_io::write_private(&directory.join("hvf.pid"), identity.as_bytes()).unwrap();
    permit.record_started("first").unwrap();
    let wider = HostBudget {
        max_total_memory_mib: Some(1024),
        ..budget()
    };
    let second = HostBudgetPermit::reserve_at(home.path(), &wider, "second", charge());
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        second.is_ok(),
        "legacy charge must not count the live hold twice"
    );
    drop(second);
    drop(permit);
    std::fs::remove_file(directory.join("hvf.pid")).unwrap();
    assert!(
        HostBudgetPermit::reserve_at(home.path(), &budget(), "third", charge()).is_ok(),
        "stored original process identity proves death even after marker removal"
    );
}

#[test]
fn a_dead_launcher_reclaims_only_an_ordinary_prepared_hold() {
    let home = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let owner = mvm_vmm::host::network_endpoint_spawn::EndpointPid::of_child(child.id()).render();
    let mut permit =
        HostBudgetPermit::reserve_at(home.path(), &budget(), "first", charge()).unwrap();
    permit
        .mutate(|record| {
            record.owner = owner;
            Ok(())
        })
        .unwrap();
    permit.drop_policy = DropPolicy::Retain;
    child.kill().unwrap();
    child.wait().unwrap();
    drop(permit);
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "second", charge()).is_ok());
}

#[test]
fn failed_or_stale_reopen_cannot_release_someone_elses_hold() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let permit = HostBudgetPermit::reserve_at(home.path(), &budget(), "first", charge()).unwrap();
    assert!(HostBudgetPermit::reopen(permit.id(), &"a".repeat(64)).is_err());
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "second", charge()).is_err());
    permit.bind_coordinator(&"a".repeat(64)).unwrap();
    assert!(HostBudgetPermit::reopen(permit.id(), &"b".repeat(64)).is_err());
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "second", charge()).is_err());
}

#[test]
fn symlinked_ledger_or_lock_never_resets_a_hold() {
    use std::os::unix::fs::symlink;
    for name in ["reservations.json", "reservations.lock"] {
        let home = tempfile::tempdir().unwrap();
        let permit =
            HostBudgetPermit::reserve_at(home.path(), &budget(), "first", charge()).unwrap();
        permit.bind_coordinator(&"a".repeat(64)).unwrap();
        let path = home.path().join("admission-budget").join(name);
        let held = path.with_extension("saved");
        std::fs::rename(&path, &held).unwrap();
        symlink(&held, &path).unwrap();
        assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "second", charge()).is_err());
        assert!(held.is_file());
    }
}

#[test]
fn coordinator_terminal_reconciliation_is_digest_bound_and_durable() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let permit = HostBudgetPermit::reserve_at(home.path(), &budget(), "first", charge()).unwrap();
    permit.bind_coordinator(&"a".repeat(64)).unwrap();
    let plan = plan("first");
    permit.bind_plan(&plan).unwrap();
    permit.mark_dispatching(&plan).unwrap();
    let id = permit.id().to_owned();
    drop(permit);
    let reopened = HostBudgetPermit::reopen(&id, &"a".repeat(64)).unwrap();
    assert!(reopened.mark_dispatching(&plan).is_err());
    reopened.reconcile_terminal(&"b".repeat(64)).unwrap();
    reopened.reconcile_terminal(&"b".repeat(64)).unwrap();
    assert!(reopened.reconcile_terminal(&"c".repeat(64)).is_err());
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "second", charge()).is_ok());
}

#[test]
fn ordinary_without_pid_evidence_refunds_only_after_owned_cleanup_succeeds() {
    let home = tempfile::tempdir().unwrap();
    let permit = HostBudgetPermit::reserve_at(home.path(), &budget(), "first", charge()).unwrap();
    let plan = plan("first");
    permit.bind_plan(&plan).unwrap();
    permit.mark_dispatching(&plan).unwrap();
    permit.record_started("first").unwrap();
    assert!(
        permit
            .reconcile_ordinary_stopped(|| anyhow::bail!("original stop unconfirmed"))
            .is_err()
    );
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "second", charge()).is_err());
    permit
        .reconcile_ordinary_stopped(|| {
            assert!(
                HostBudgetPermit::reserve_at(home.path(), &budget(), "second", charge()).is_err(),
                "capacity cannot be refunded before the owned cleanup callback finishes"
            );
            Ok(())
        })
        .unwrap();
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "second", charge()).is_ok());
}

#[test]
fn coordinator_cannot_use_the_ordinary_owned_refund() {
    let home = tempfile::tempdir().unwrap();
    let permit = HostBudgetPermit::reserve_at(home.path(), &budget(), "first", charge()).unwrap();
    permit.bind_coordinator(&"a".repeat(64)).unwrap();
    permit.bind_plan(&plan("first")).unwrap();
    let called = std::cell::Cell::new(false);
    assert_eq!(
        permit
            .reconcile_ordinary_stopped(|| {
                called.set(true);
                Ok(())
            })
            .unwrap(),
        HostBudgetRelease::CoordinatorRetained
    );
    assert!(
        called.get(),
        "accounting must not prevent original-owner cleanup"
    );
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "second", charge()).is_err());
}

#[test]
fn dispatch_rereads_the_same_hosts_budget_and_refuses_corrupt_config() {
    let home = tempfile::tempdir().unwrap();
    let permit = HostBudgetPermit::reserve_at(home.path(), &budget(), "first", charge()).unwrap();
    let plan = plan("first");
    permit.bind_plan(&plan).unwrap();
    let directory = home.path().join("config");
    std::fs::create_dir(&directory).unwrap();
    atomic_io::write_private(
        &directory.join("config.toml"),
        b"host_budget_memory_mib = 1",
    )
    .unwrap();
    assert!(permit.mark_dispatching(&plan).is_err());
    atomic_io::write_private(&directory.join("config.toml"), b"not valid toml").unwrap();
    assert!(permit.mark_dispatching(&plan).is_err());
    atomic_io::write_private(
        &directory.join("config.toml"),
        b"host_budget_memory_mib = 512",
    )
    .unwrap();
    permit.mark_dispatching(&plan).unwrap();
}

#[test]
fn legacy_bare_pid_keeps_started_capacity_unknown_instead_of_failing_start() {
    let home = tempfile::tempdir().unwrap();
    let permit = HostBudgetPermit::reserve_at(home.path(), &budget(), "first", charge()).unwrap();
    let plan = plan("first");
    permit.bind_plan(&plan).unwrap();
    permit.mark_dispatching(&plan).unwrap();
    let directory = mvm_core::config::vm_state_dir_at(home.path(), "first");
    mvm_core::config::create_private_dir(&directory).unwrap();
    atomic_io::write_private(
        &directory.join("fc.pid"),
        std::process::id().to_string().as_bytes(),
    )
    .unwrap();
    permit
        .record_started("first")
        .expect("legacy marker is unknown, not a post-start refusal");
    drop(permit);
    std::fs::remove_file(directory.join("fc.pid")).unwrap();
    assert!(
        HostBudgetPermit::reserve_at(home.path(), &budget(), "second", charge()).is_err(),
        "missing or bare PID evidence must not refund a possibly executed hold"
    );
}

#[test]
fn unconfigured_ordinary_admission_has_no_pending_journal_but_actor_hold_is_tracked() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let ordinary = HostBudgetPermit::reserve_ordinary("ordinary", charge()).unwrap();
    let plan = plan("ordinary");
    ordinary.bind_plan(&plan).unwrap();
    ordinary.mark_dispatching(&plan).unwrap();
    assert!(ordinary.bind_coordinator(&"a".repeat(64)).is_err());
    drop(ordinary);
    assert!(!home.path().join("admission-budget").exists());
    let actor = HostBudgetPermit::reserve("actor", charge()).unwrap();
    actor.bind_coordinator(&"a".repeat(64)).unwrap();
    assert!(
        home.path()
            .join("admission-budget/reservations.json")
            .is_file()
    );
}

#[test]
fn firecracker_identity_sidecar_must_match_the_bare_pid_marker() {
    let directory = tempfile::tempdir().unwrap();
    let original = mvm_vmm::host::network_endpoint_spawn::EndpointPid::of_child(std::process::id());
    atomic_io::write_private(
        &directory.path().join("fc.pid"),
        original.pid.to_string().as_bytes(),
    )
    .unwrap();
    atomic_io::write_private(
        &directory.path().join("fc.identity"),
        original.render().as_bytes(),
    )
    .unwrap();
    assert_eq!(
        platform::machine_identity(directory.path()).unwrap(),
        Some(original.render())
    );
    atomic_io::write_private(&directory.path().join("fc.pid"), b"2147483647").unwrap();
    assert!(platform::machine_identity(directory.path()).is_err());
}

#[test]
fn never_dispatched_reconciliation_is_durable_without_a_plan_and_replay_bound() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let permit =
        HostBudgetPermit::reserve_at(home.path(), &budget(), "cancelled", charge()).unwrap();
    permit.bind_coordinator(&"a".repeat(64)).unwrap();
    let id = permit.id().to_owned();
    permit.reconcile_never_dispatched(&"b".repeat(64)).unwrap();
    drop(permit);
    let reopened = HostBudgetPermit::reopen(&id, &"a".repeat(64)).unwrap();
    reopened
        .reconcile_never_dispatched(&"b".repeat(64))
        .unwrap();
    let path = home.path().join("admission-budget/reservations.json");
    let before = std::fs::read(&path).unwrap();
    assert!(
        reopened
            .reconcile_never_dispatched(&"c".repeat(64))
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(reopened.bind_plan(&plan("cancelled")).is_err());
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "next", charge()).is_ok());
}

#[test]
fn never_dispatched_reconciliation_refuses_ordinary_dispatched_and_running_holds() {
    for phase in [
        Phase::Prepared,
        Phase::Dispatching,
        Phase::Running {
            process: platform::current_owner().unwrap(),
        },
    ] {
        let home = tempfile::tempdir().unwrap();
        let permit =
            HostBudgetPermit::reserve_at(home.path(), &budget(), "first", charge()).unwrap();
        if phase != Phase::Prepared {
            permit.bind_coordinator(&"a".repeat(64)).unwrap();
        }
        permit.bind_plan(&plan("first")).unwrap();
        permit
            .mutate(|record| {
                record.phase = phase;
                Ok(())
            })
            .unwrap();
        let path = home.path().join("admission-budget/reservations.json");
        let before = std::fs::read(&path).unwrap();
        assert!(permit.reconcile_never_dispatched(&"b".repeat(64)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "next", charge()).is_err());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn runtime_preboot_proof_keeps_coordinator_charged_until_durable_cancellation() {
    let _guard = mvm_runtime::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .expect("home lock");
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let mut plan = plan("refused");
    plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
    let signed = mvm_core::plan::sign_plan(
        &plan,
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        "host:test",
    );
    let config = mvm_core::vm_backend::VmStartConfig {
        name: "refused".into(),
        rootfs_path: home
            .path()
            .join("missing-rootfs.ext4")
            .display()
            .to_string(),
        plan_json: Some(serde_json::to_string(&signed).unwrap()),
        ..Default::default()
    };
    let error = mvm_runtime::AnyBackend::from_hypervisor("hvf")
        .start_owned_actor(&config, None)
        .unwrap_err();
    let failure = error
        .downcast_ref::<mvm_runtime::actor_teardown::ActorStartFailure>()
        .expect("original runtime failure");
    let proof = failure.no_dispatch_proof().expect("no process dispatched");
    let permit = HostBudgetPermit::reserve_at(home.path(), &budget(), "refused", charge()).unwrap();
    permit.bind_coordinator(&"a".repeat(64)).unwrap();
    permit.bind_plan(&plan).unwrap();
    permit.mark_dispatching_for(&plan, "refused").unwrap();
    let emitter = crate::audit::emitter::AuditEmitter::with_dir(
        ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        &home.path().join("audit"),
    )
    .unwrap();
    assert!(
        permit
            .record_runtime_no_dispatch(proof, "another", &plan, &emitter)
            .is_err()
    );
    assert!(permit.reconcile_never_dispatched(&"b".repeat(64)).is_err());
    let audit_file =
        crate::audit::emitter::audit_path_for_tenant(&home.path().join("audit"), &plan.tenant.0);
    std::fs::create_dir(&audit_file).unwrap();
    assert!(
        permit
            .record_runtime_no_dispatch(proof, "refused", &plan, &emitter)
            .is_err()
    );
    assert!(permit.reconcile_never_dispatched(&"b".repeat(64)).is_err());
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "next", charge()).is_err());
    std::fs::remove_dir(&audit_file).unwrap();
    permit
        .record_runtime_no_dispatch(proof, "refused", &plan, &emitter)
        .unwrap();
    assert!(permit.mark_dispatching(&plan).is_err());
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "next", charge()).is_err());
    permit.reconcile_never_dispatched(&"b".repeat(64)).unwrap();
    assert!(HostBudgetPermit::reserve_at(home.path(), &budget(), "next", charge()).is_ok());
}

#[cfg(unix)]
#[test]
fn a_config_saved_under_a_group_writable_umask_is_private_and_admitted() {
    use std::os::unix::fs::PermissionsExt as _;

    const CHILD: &str = "MVM_HOSTD_CONFIG_UMASK_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // The umask is process-wide, so the save runs in a fresh single-test
        // process rather than in the shared test runner.
        let status = std::process::Command::new("sh")
            .args(["-c", "umask 002; exec \"$@\"", "config-umask"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "admission_budget::permit::tests::a_config_saved_under_a_group_writable_umask_is_private_and_admitted",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }

    let home = tempfile::tempdir().unwrap();
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
    std::fs::create_dir(home.path().join("probe")).unwrap();
    assert_eq!(mode(&home.path().join("probe")), 0o775, "child umask");

    let config_dir = home.path().join("config");
    let config = mvm_core::user_config::MvmConfig {
        host_budget_memory_mib: Some(4096),
        ..Default::default()
    };
    mvm_core::user_config::save(&config, Some(&config_dir)).unwrap();
    assert_eq!(mode(&config_dir), 0o700);
    assert_eq!(mode(&config_dir.join("config.toml")), 0o600);
    assert_eq!(
        budget_at(home.path()).unwrap().max_total_memory_mib,
        Some(4096)
    );
}

#[cfg(unix)]
#[test]
fn a_group_writable_config_is_refused_with_its_path_and_the_fix() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = tempfile::tempdir().unwrap();
    let config_dir = home.path().join("config");
    mvm_core::user_config::save(&Default::default(), Some(&config_dir)).unwrap();
    let path = config_dir.join("config.toml");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();

    let message = budget_at(home.path()).unwrap_err().to_string();
    assert!(message.contains(&path.display().to_string()), "{message}");
    assert!(message.contains("0664"), "{message}");
    assert!(
        message.contains(&format!("chmod 600 {}", path.display())),
        "{message}"
    );

    // Saving again replaces the file at its private mode.
    mvm_core::user_config::save(&Default::default(), Some(&config_dir)).unwrap();
    assert!(budget_at(home.path()).is_ok());
}

fn record_path(home: &Path, vm: &str) -> PathBuf {
    super::super::charge_path_at(home, vm)
}

/// With no host budget configured, the charge record is written on its own
/// thread beside the boot, with the same durable write as before (data synced
/// before the rename, then the directory), and the start only joins it.
#[test]
fn an_unbounded_charge_is_written_beside_the_boot_and_joined_at_start() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let permit = HostBudgetPermit::reserve_ordinary("early-charge", charge()).unwrap();

    permit.record_charge_beside_boot("early-charge");
    let plan = plan("early-charge");
    permit.bind_plan(&plan).unwrap();
    permit.mark_dispatching(&plan).unwrap();
    permit.record_started("early-charge").unwrap();

    let record = record_path(home.path(), "early-charge");
    let written = std::fs::read(&record).expect("the started machine has its record");
    assert_eq!(
        serde_json::from_slice::<MachineCharge>(&written).unwrap(),
        charge()
    );
    drop(permit);
    assert!(record.is_file(), "a started machine keeps its record");
}

/// The early write is not part of the admission's audit durability: when it
/// fails (here because its state directory cannot be created, as when another
/// command reaped it), the launch is not refused and the charge is written at
/// start as before.
#[test]
fn a_failed_early_charge_write_is_recorded_at_start_instead() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let state = mvm_core::config::vm_state_dir_at(home.path(), "reaped");
    std::fs::create_dir_all(state.parent().unwrap()).unwrap();
    std::fs::write(&state, b"not a directory").unwrap();
    let permit = HostBudgetPermit::reserve_ordinary("reaped", charge()).unwrap();

    permit.record_charge_beside_boot("reaped");
    permit.join_early_charge_for_test();
    std::fs::remove_file(&state).unwrap();
    permit.record_started("reaped").unwrap();

    assert!(record_path(home.path(), "reaped").is_file());
}

/// An early record whose launch never started (refused or failed before boot,
/// including a budget configured after admission) is removed when the permit
/// is dropped, so a later budgeted admission cannot count it as phantom load.
#[test]
fn an_early_record_with_no_started_machine_is_never_counted_against_a_budget() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let permit = HostBudgetPermit::reserve_ordinary("never-booted", charge()).unwrap();
    permit.record_charge_beside_boot("never-booted");
    permit.join_early_charge_for_test();
    assert!(record_path(home.path(), "never-booted").is_file());

    // A budget configured after the record was written refuses the dispatch.
    let config = mvm_core::user_config::MvmConfig {
        host_budget_memory_mib: Some(512),
        ..Default::default()
    };
    mvm_core::user_config::save(&config, None).unwrap();
    assert!(permit.mark_dispatching(&plan("never-booted")).is_err());
    drop(permit);

    assert!(!record_path(home.path(), "never-booted").exists());
    let budgeted = HostBudgetPermit::reserve_ordinary("next", charge())
        .expect("no phantom charge is left to count against the budget");
    drop(budgeted);
}

/// A machine that starts under another name than the one admitted (a warm
/// claim's child) is recorded at start under its own name, and the admitted
/// name's early record is removed with the permit.
#[test]
fn a_machine_started_under_another_name_is_recorded_under_its_own() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let permit = HostBudgetPermit::reserve_ordinary("requested", charge()).unwrap();
    permit.record_charge_beside_boot("requested");

    permit.record_started("claimed-child").unwrap();
    drop(permit);

    assert!(record_path(home.path(), "claimed-child").is_file());
    assert!(!record_path(home.path(), "requested").exists());
}

/// A configured host budget keeps today's order: nothing is written beside
/// the boot, and the ledger and record are written once the machine started.
#[test]
fn a_tracked_charge_is_not_written_beside_the_boot() {
    let home = tempfile::tempdir().unwrap();
    let permit = HostBudgetPermit::reserve_at(home.path(), &budget(), "tracked", charge()).unwrap();
    let record = record_path(home.path(), "tracked");

    permit.record_charge_beside_boot("tracked");
    assert!(!record.exists(), "a tracked hold is charged by its ledger");

    let plan = plan("tracked");
    permit.bind_plan(&plan).unwrap();
    permit.mark_dispatching(&plan).unwrap();
    permit.record_started("tracked").unwrap();
    assert!(record.is_file(), "the tracked path still records at start");
}
