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

/// What a neighbour machine leaves in its state dir for these tests.
struct Neighbour<'a> {
    record: Option<&'a [u8]>,
    marker: Option<&'a [u8]>,
    plan: bool,
}

fn neighbour(home: &Path, name: &str, evidence: Neighbour<'_>) {
    let directory = mvm_core::config::vm_state_dir_at(home, name);
    mvm_core::config::create_private_dir(&directory).unwrap();
    if let Some(record) = evidence.record {
        atomic_io::write_private(&directory.join(super::super::CHARGE_FILE), record).unwrap();
    }
    if let Some(marker) = evidence.marker {
        atomic_io::write_private(&directory.join("hvf.pid"), marker).unwrap();
    }
    if evidence.plan {
        let plan = serde_json::to_vec(&plan(name)).unwrap();
        atomic_io::write_private(&directory.join(super::super::PLAN_FILE), &plan).unwrap();
    }
}

fn live_marker() -> Vec<u8> {
    platform::current_owner().unwrap().into_bytes()
}

fn wider() -> HostBudget {
    HostBudget {
        max_total_memory_mib: Some(1024),
        ..budget()
    }
}

/// Whether the neighbour is counted: a 512 MiB boot fits a 1024 MiB host
/// either way, and fits a 512 MiB host only when the neighbour is not counted.
/// Neither answer may be a refusal that has nothing to do with headroom.
fn neighbour_is_counted(home: &Path) -> bool {
    HostBudgetPermit::reserve_at(home, &wider(), "unrelated", charge())
        .expect("one neighbour's evidence must never refuse an unrelated boot that fits");
    match HostBudgetPermit::reserve_at(home, &budget(), "second", charge()) {
        Ok(_) => false,
        Err(error) => {
            assert!(
                format!("{error:#}").contains("budget"),
                "only the headroom may refuse: {error:#}"
            );
            true
        }
    }
}

#[test]
fn an_unreadable_charge_record_falls_back_to_the_machines_plan() {
    for record in [&b"bad"[..], b""] {
        let home = tempfile::tempdir().unwrap();
        let marker = live_marker();
        neighbour(
            home.path(),
            "torn",
            Neighbour {
                record: Some(record),
                marker: Some(&marker),
                plan: true,
            },
        );
        assert!(
            neighbour_is_counted(home.path()),
            "a live machine whose plan names its charge stays counted"
        );
    }
}

#[test]
fn an_unreadable_charge_record_with_no_plan_hides_only_that_machine() {
    for record in [&b"bad"[..], b""] {
        let home = tempfile::tempdir().unwrap();
        let marker = live_marker();
        neighbour(
            home.path(),
            "torn",
            Neighbour {
                record: Some(record),
                marker: Some(&marker),
                plan: false,
            },
        );
        assert!(!neighbour_is_counted(home.path()));
    }
}

#[test]
fn a_live_machine_with_no_charge_record_is_counted_from_its_plan() {
    let home = tempfile::tempdir().unwrap();
    let marker = live_marker();
    neighbour(
        home.path(),
        "booting",
        Neighbour {
            record: None,
            marker: Some(&marker),
            plan: true,
        },
    );
    assert!(neighbour_is_counted(home.path()));
}

#[test]
fn a_live_machine_with_no_charge_evidence_hides_only_that_machine() {
    let home = tempfile::tempdir().unwrap();
    let marker = live_marker();
    neighbour(
        home.path(),
        "unknown",
        Neighbour {
            record: None,
            marker: Some(&marker),
            plan: false,
        },
    );
    assert!(!neighbour_is_counted(home.path()));
}

#[test]
fn a_charge_record_with_no_pid_marker_is_not_a_live_machine() {
    let home = tempfile::tempdir().unwrap();
    let record = serde_json::to_vec(&charge()).unwrap();
    neighbour(
        home.path(),
        "stopped",
        Neighbour {
            record: Some(&record),
            marker: None,
            plan: true,
        },
    );
    assert!(!neighbour_is_counted(home.path()));
}

#[test]
fn unreadable_pid_evidence_keeps_the_machine_counted() {
    let home = tempfile::tempdir().unwrap();
    let record = serde_json::to_vec(&charge()).unwrap();
    neighbour(
        home.path(),
        "unprovable",
        Neighbour {
            record: Some(&record),
            marker: Some(b"2147483647 corrupt"),
            plan: false,
        },
    );
    assert!(neighbour_is_counted(home.path()));
}

#[test]
fn a_held_machine_with_a_torn_charge_record_is_counted_once_through_its_hold() {
    let home = tempfile::tempdir().unwrap();
    let permit = HostBudgetPermit::reserve_at(home.path(), &budget(), "held", charge()).unwrap();
    let plan = plan("held");
    permit.bind_plan(&plan).unwrap();
    permit.mark_dispatching(&plan).unwrap();
    let marker = live_marker();
    neighbour(
        home.path(),
        "held",
        Neighbour {
            record: Some(b"bad"),
            marker: Some(&marker),
            plan: true,
        },
    );
    assert!(neighbour_is_counted(home.path()));
    let roomier = HostBudget {
        max_total_memory_mib: Some(1536),
        ..budget()
    };
    let _unrelated = HostBudgetPermit::reserve_at(home.path(), &wider(), "unrelated", charge());
    assert!(
        HostBudgetPermit::reserve_at(home.path(), &roomier, "third", charge()).is_ok(),
        "the hold and its torn record are one machine, not two"
    );
}

#[test]
fn retiring_a_dead_machine_with_a_torn_charge_record_does_not_refuse_the_next_boot() {
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
    drop(permit);
    child.kill().unwrap();
    child.wait().unwrap();
    std::fs::write(directory.join(super::super::CHARGE_FILE), b"").unwrap();
    assert!(
        HostBudgetPermit::reserve_at(home.path(), &budget(), "second", charge()).is_ok(),
        "a dead machine's unreadable record must not stand between the host and its next boot"
    );
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
