use std::sync::{Arc, Barrier};

use super::*;
use crate::host_interface::recovery_custody::{
    CustodyEvent, RecoveryCustody, RecoveryCustodyError, RecoveryStoreLimits,
};

fn limits() -> RecoveryStoreLimits {
    RecoveryStoreLimits::new(16, 64 * 1024).unwrap()
}

fn established(fixture: &Fixture, home: &std::path::Path) -> RecoveryCustody {
    let mut ledger = crate::host_interface::workload::WorkloadLedger::default();
    for _ in 0..3 {
        ledger.replace("workload");
    }
    ledger.save_at(home).unwrap();
    let custody = RecoveryCustody::at(home, limits());
    let _ = custody
        .establish(fixture.verify(clock(150, 10)).unwrap(), fixture.history())
        .unwrap();
    custody
}

fn reserved(
    fixture: &Fixture,
    home: &std::path::Path,
) -> (
    RecoveryCustody,
    crate::host_interface::recovery::TransitionBinding,
) {
    let custody = established(fixture, home);
    let status = custody
        .reserve(
            fixture.verify(clock(150, 10)).unwrap(),
            request(),
            clock(150, 10),
        )
        .unwrap();
    (custody, status.current.unwrap().binding)
}

fn finish(
    custody: &RecoveryCustody,
    fixture: &Fixture,
    binding: &crate::host_interface::recovery::TransitionBinding,
    now: ClockEvidence,
) {
    for event in [
        CustodyEvent::BeginFence,
        CustodyEvent::Retired,
        CustodyEvent::Activate,
        CustodyEvent::ActivationCommitted,
        CustodyEvent::Ready,
    ] {
        let _ = custody
            .record(fixture.verify(now).unwrap(), binding, event, now)
            .unwrap();
    }
}

#[test]
fn missing_managed_history_refuses_without_changing_local_default() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let custody = RecoveryCustody::at(home.path(), limits());
    assert!(matches!(
        custody.status(fixture.companion_id(), "workload"),
        Err(RecoveryCustodyError::HistoryMissing)
    ));
    assert_eq!(
        crate::host_interface::workload::WorkloadLedger::load_at(home.path())
            .unwrap()
            .entry("ordinary")
            .epoch,
        ExecutionEpoch(1)
    );
}

#[test]
fn managed_epoch_never_bypasses_the_managed_admission_path() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    established(&fixture, home.path());
    let ledger = crate::host_interface::workload::WorkloadLedger::load_at(home.path()).unwrap();
    assert_eq!(
        ledger.authorize("workload", ExecutionEpoch(4)),
        Err(Denial::Offline(OfflineRefusal::ManagedAdmissionRequired))
    );
    assert!(ledger.authorize("ordinary", ExecutionEpoch(1)).is_ok());
}

#[test]
fn establishment_requires_verified_exact_history_and_is_idempotent() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let custody = established(&fixture, home.path());
    let before = std::fs::read(home.path().join("host-interface/workloads.json")).unwrap();
    let _ = custody
        .establish(fixture.verify(clock(150, 10)).unwrap(), fixture.history())
        .unwrap();
    assert_eq!(
        std::fs::read(home.path().join("host-interface/workloads.json")).unwrap(),
        before
    );

    let mut changed = fixture.history();
    changed.last_operation += 1;
    assert!(matches!(
        custody.establish(fixture.verify(clock(150, 10)).unwrap(), changed),
        Err(RecoveryCustodyError::Conflict)
    ));
}

#[test]
fn reservation_durably_spends_budget_and_high_water_without_activation() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let (custody, binding) = reserved(&fixture, home.path());
    let status = custody.status(fixture.companion_id(), "workload").unwrap();
    assert_eq!(status.active_epoch, ExecutionEpoch(4));
    assert_eq!(status.history.epoch_high_water, ExecutionEpoch(5));
    assert_eq!(status.history.restarts_spent, 1);
    assert_eq!(status.history.last_operation, 11);
    assert_eq!(status.current.unwrap().binding, binding);
    assert!(status.completed.is_none());
}

#[test]
fn fencing_must_be_durable_before_activation_changes_the_epoch() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let (custody, binding) = reserved(&fixture, home.path());
    for (event, phase, active) in [
        (CustodyEvent::BeginFence, RecoveryPhase::Fencing, 4),
        (CustodyEvent::Retired, RecoveryPhase::Fenced, 4),
        (CustodyEvent::Activate, RecoveryPhase::Activating, 4),
        (
            CustodyEvent::ActivationCommitted,
            RecoveryPhase::Launching,
            5,
        ),
    ] {
        let status = custody
            .record(
                fixture.verify(clock(150, 10)).unwrap(),
                &binding,
                event,
                clock(150, 10),
            )
            .unwrap();
        assert_eq!(status.current.as_ref().unwrap().phase, phase);
        assert_eq!(status.active_epoch, ExecutionEpoch(active));
        assert_eq!(
            status
                .current
                .as_ref()
                .map(|current| current.activation_committed),
            Some(phase == RecoveryPhase::Launching)
        );
        assert_eq!(
            status.action,
            if phase == RecoveryPhase::Launching {
                RecoveryAction::AdmitAndLaunch
            } else if phase == RecoveryPhase::Fencing {
                RecoveryAction::FenceOriginal
            } else if phase == RecoveryPhase::Activating {
                RecoveryAction::ActivateReserved
            } else {
                RecoveryAction::None
            }
        );
        if phase == RecoveryPhase::Launching {
            assert_eq!(
                custody
                    .record(
                        fixture.verify(clock(150, 10)).unwrap(),
                        &binding,
                        event,
                        clock(150, 10),
                    )
                    .unwrap()
                    .action,
                RecoveryAction::None,
                "only the first durable Launching transition emits dispatch"
            );
        }
    }
}

#[test]
fn no_event_bypasses_the_required_transition_order() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let (custody, binding) = reserved(&fixture, home.path());
    for event in [
        CustodyEvent::Retired,
        CustodyEvent::Activate,
        CustodyEvent::ActivationCommitted,
        CustodyEvent::Ready,
    ] {
        assert!(matches!(
            custody.record(
                fixture.verify(clock(150, 10)).unwrap(),
                &binding,
                event,
                clock(150, 10),
            ),
            Err(RecoveryCustodyError::Denied(Denial::Offline(
                OfflineRefusal::TransitionOrder
            )))
        ));
    }
    assert_eq!(
        custody
            .status(fixture.companion_id(), "workload")
            .unwrap()
            .active_epoch,
        ExecutionEpoch(4)
    );
}

#[test]
fn ready_finalizes_the_new_owner_and_permits_one_later_fresh_operation() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let (custody, binding) = reserved(&fixture, home.path());
    for event in [
        CustodyEvent::BeginFence,
        CustodyEvent::Retired,
        CustodyEvent::Activate,
        CustodyEvent::ActivationCommitted,
        CustodyEvent::Ready,
    ] {
        let _ = custody
            .record(
                fixture.verify(clock(150, 10)).unwrap(),
                &binding,
                event,
                clock(150, 10),
            )
            .unwrap();
    }
    let ready = custody.status(fixture.companion_id(), "workload").unwrap();
    assert!(ready.current.is_none());
    assert_eq!(
        ready.completed.as_ref().unwrap().phase,
        RecoveryPhase::Ready
    );
    assert_eq!(
        ready.history.original,
        Owner {
            instance: [10; 16],
            epoch: ExecutionEpoch(5)
        }
    );

    let second = RestartRequest {
        operation: 12,
        original: ready.history.original,
        proposed_epoch: ExecutionEpoch(6),
        replacement_instance: [11; 16],
    };
    let second = custody
        .reserve(
            fixture.verify(clock(151, 11)).unwrap(),
            second,
            clock(151, 11),
        )
        .unwrap();
    assert_eq!(second.history.restarts_spent, 2);
    assert_eq!(second.active_epoch, ExecutionEpoch(5));
    assert_eq!(
        second.current.unwrap().binding.request.proposed_epoch,
        ExecutionEpoch(6)
    );
}

#[test]
fn duplicates_return_recorded_state_and_changed_reuse_conflicts() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let (custody, binding) = reserved(&fixture, home.path());
    let path = home.path().join("host-interface/workloads.json");
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        custody
            .reserve(
                fixture.verify(clock(150, 10)).unwrap(),
                request(),
                clock(150, 10)
            )
            .unwrap()
            .current
            .unwrap()
            .binding,
        binding
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let mut changed = request();
    changed.replacement_instance = [12; 16];
    assert!(matches!(
        custody.reserve(
            fixture.verify(clock(150, 10)).unwrap(),
            changed,
            clock(150, 10)
        ),
        Err(RecoveryCustodyError::Conflict)
    ));
}

#[test]
fn accepted_shorter_deadline_is_persisted_across_operations() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let (custody, binding) = reserved(&fixture, home.path());
    let shortened = clock(170, 20);
    let _ = custody
        .record(
            fixture.verify(shortened).unwrap(),
            &binding,
            CustodyEvent::BeginFence,
            shortened,
        )
        .unwrap();
    let crossed = clock(171, 41);
    let status = custody
        .record(
            fixture.verify(crossed).unwrap(),
            &binding,
            CustodyEvent::Retired,
            crossed,
        )
        .unwrap();
    assert!(status.blocked);
    assert_eq!(status.current.unwrap().phase, RecoveryPhase::Blocked);
    assert_eq!(status.action, RecoveryAction::CloseAndReconcile);
}

#[test]
fn duplicate_reservation_and_ready_apply_time_invalidation_first() {
    for duplicate_ready in [false, true] {
        for bad_time in [
            clock(190, 50),
            ClockEvidence::Unknown,
            ClockEvidence::Bounded {
                earliest_unix: 151,
                latest_unix: 151,
                monotonic_seconds: 11,
                continuity: [8; 16],
            },
        ] {
            let home = tempfile::tempdir().unwrap();
            let fixture = Fixture::new();
            let (custody, binding) = reserved(&fixture, home.path());
            if duplicate_ready {
                finish(&custody, &fixture, &binding, clock(150, 10));
            }
            let status = if duplicate_ready {
                custody
                    .record(
                        fixture.verify(clock(150, 10)).unwrap(),
                        &binding,
                        CustodyEvent::Ready,
                        bad_time,
                    )
                    .unwrap()
            } else {
                custody
                    .reserve(fixture.verify(clock(150, 10)).unwrap(), request(), bad_time)
                    .unwrap()
            };
            assert!(status.blocked);
            assert_eq!(status.action, RecoveryAction::CloseAndReconcile);
            assert_eq!(
                status.current.as_ref().map(|current| current.phase),
                (!duplicate_ready).then_some(RecoveryPhase::Blocked)
            );
            if duplicate_ready {
                assert!(
                    custody
                        .resume(fixture.verify(clock(151, 11)).unwrap())
                        .is_err()
                );
            }
        }
    }
}

#[test]
fn resume_time_invalidation_after_ready_is_durable_and_never_returns_running() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let (custody, binding) = reserved(&fixture, home.path());
    finish(&custody, &fixture, &binding, clock(150, 10));
    let changed = ClockEvidence::Bounded {
        earliest_unix: 151,
        latest_unix: 151,
        monotonic_seconds: 11,
        continuity: [8; 16],
    };
    assert!(custody.resume(fixture.verify(changed).unwrap()).is_err());
    let status = custody.status(fixture.companion_id(), "workload").unwrap();
    assert!(status.blocked);
    assert!(status.current.is_none());
    assert!(
        custody
            .resume(fixture.verify(clock(151, 11)).unwrap())
            .is_err()
    );
}

#[test]
fn accepted_duplicate_clock_is_not_discarded_before_the_next_event() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let (custody, binding) = reserved(&fixture, home.path());
    let first = clock(160, 20);
    let _ = custody
        .record(
            fixture.verify(first).unwrap(),
            &binding,
            CustodyEvent::BeginFence,
            first,
        )
        .unwrap();
    let later = clock(170, 30);
    assert_eq!(
        custody
            .record(
                fixture.verify(later).unwrap(),
                &binding,
                CustodyEvent::BeginFence,
                later,
            )
            .unwrap()
            .action,
        RecoveryAction::None
    );
    let regressed = clock(165, 25);
    let status = custody
        .record(
            fixture.verify(regressed).unwrap(),
            &binding,
            CustodyEvent::Retired,
            regressed,
        )
        .unwrap();
    assert!(status.blocked);
}

#[test]
fn retained_completed_retries_do_not_replace_newer_current_custody() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let (custody, first_binding) = reserved(&fixture, home.path());
    finish(&custody, &fixture, &first_binding, clock(150, 10));
    let second_request = RestartRequest {
        operation: 12,
        original: Owner {
            instance: [10; 16],
            epoch: ExecutionEpoch(5),
        },
        proposed_epoch: ExecutionEpoch(6),
        replacement_instance: [11; 16],
    };
    let second = custody
        .reserve(
            fixture.verify(clock(151, 11)).unwrap(),
            second_request,
            clock(151, 11),
        )
        .unwrap();
    let second_binding = second.current.unwrap().binding;

    let retried = custody
        .reserve(
            fixture.verify(clock(151, 11)).unwrap(),
            request(),
            clock(151, 11),
        )
        .unwrap();
    assert_eq!(retried.current.as_ref().unwrap().binding, second_binding);
    let retried = custody
        .record(
            fixture.verify(clock(151, 11)).unwrap(),
            &first_binding,
            CustodyEvent::Ready,
            clock(151, 11),
        )
        .unwrap();
    assert_eq!(retried.current.as_ref().unwrap().binding, second_binding);
    assert_eq!(retried.action, RecoveryAction::None);

    finish(&custody, &fixture, &second_binding, clock(151, 11));
    assert!(matches!(
        custody.reserve(
            fixture.verify(clock(151, 11)).unwrap(),
            request(),
            clock(151, 11)
        ),
        Err(RecoveryCustodyError::Denied(Denial::ReplayedCommand { .. }))
    ));
}

#[test]
fn cancellation_unknown_and_blocked_never_refund_or_resume() {
    for event in [
        CustodyEvent::Cancel,
        CustodyEvent::Uncertain,
        CustodyEvent::Block,
    ] {
        let home = tempfile::tempdir().unwrap();
        let fixture = Fixture::new();
        let (custody, binding) = reserved(&fixture, home.path());
        let status = custody
            .record(
                fixture.verify(clock(150, 10)).unwrap(),
                &binding,
                event,
                clock(150, 10),
            )
            .unwrap();
        assert!(matches!(
            status.current.as_ref().unwrap().phase,
            RecoveryPhase::Cancelled | RecoveryPhase::Unknown | RecoveryPhase::Blocked
        ));
        assert_eq!(status.history.restarts_spent, 1);
        assert_eq!(status.history.epoch_high_water, ExecutionEpoch(5));
        let retry = custody.record(
            fixture.verify(clock(150, 10)).unwrap(),
            &binding,
            CustodyEvent::ActivationCommitted,
            clock(150, 10),
        );
        if event == CustodyEvent::Block {
            assert_eq!(retry.unwrap().action, RecoveryAction::CloseAndReconcile);
        } else {
            assert!(retry.is_err());
        }
    }
}

#[test]
fn terminal_state_preserves_whether_activation_committed() {
    for after_activation in [false, true] {
        let home = tempfile::tempdir().unwrap();
        let fixture = Fixture::new();
        let (custody, binding) = reserved(&fixture, home.path());
        if after_activation {
            for event in [
                CustodyEvent::BeginFence,
                CustodyEvent::Retired,
                CustodyEvent::Activate,
                CustodyEvent::ActivationCommitted,
            ] {
                let _ = custody
                    .record(
                        fixture.verify(clock(150, 10)).unwrap(),
                        &binding,
                        event,
                        clock(150, 10),
                    )
                    .unwrap();
            }
        }
        let status = custody
            .record(
                fixture.verify(clock(150, 10)).unwrap(),
                &binding,
                CustodyEvent::Uncertain,
                clock(150, 10),
            )
            .unwrap();
        let current = status.current.unwrap();
        assert_eq!(current.phase, RecoveryPhase::Unknown);
        assert_eq!(current.activation_committed, after_activation);
        assert_eq!(
            status.active_epoch,
            if after_activation {
                ExecutionEpoch(5)
            } else {
                ExecutionEpoch(4)
            }
        );
        assert_eq!(current.binding.request.original.epoch, ExecutionEpoch(4));
        assert_eq!(current.binding.request.proposed_epoch, ExecutionEpoch(5));
    }
}

#[test]
fn reload_reconstructs_each_exact_reducer_phase() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let (custody, binding) = reserved(&fixture, home.path());
    for (event, phase) in [
        (CustodyEvent::BeginFence, RecoveryPhase::Fencing),
        (CustodyEvent::Retired, RecoveryPhase::Fenced),
        (CustodyEvent::Activate, RecoveryPhase::Activating),
        (CustodyEvent::ActivationCommitted, RecoveryPhase::Launching),
    ] {
        let _ = custody
            .record(
                fixture.verify(clock(150, 10)).unwrap(),
                &binding,
                event,
                clock(150, 10),
            )
            .unwrap();
        let resumed = custody
            .resume(fixture.verify(clock(150, 10)).unwrap())
            .unwrap();
        let restored_phase = if phase == RecoveryPhase::Launching {
            RecoveryPhase::Unknown
        } else {
            phase
        };
        assert_eq!(resumed.phase(), restored_phase);
        assert_eq!(resumed.binding(), Some(&binding));
    }
}

#[test]
fn competing_changed_requests_have_one_winner() {
    const WRITERS: usize = 8;
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    established(&fixture, home.path());
    let barrier = Arc::new(Barrier::new(WRITERS));
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..WRITERS)
            .map(|n| {
                let barrier = Arc::clone(&barrier);
                let path = home.path().to_owned();
                scope.spawn(move || {
                    let fixture = Fixture::new();
                    let custody = RecoveryCustody::at(path, limits());
                    let mut candidate = request();
                    candidate.replacement_instance = [u8::try_from(n + 10).unwrap(); 16];
                    barrier.wait();
                    custody.reserve(
                        fixture.verify(clock(150, 10)).unwrap(),
                        candidate,
                        clock(150, 10),
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|error| matches!(error, RecoveryCustodyError::Conflict))
    );
}

#[test]
fn a_workload_transaction_never_changes_a_bystander() {
    let home = tempfile::tempdir().unwrap();
    let a = Fixture::new();
    let mut b = Fixture::new();
    b.companion.policy.workload_id = "bystander".into();
    b.resign();
    let custody = established(&a, home.path());
    for _ in 0..3 {
        crate::host_interface::workload::WorkloadLedger::replace_at(home.path(), "bystander")
            .unwrap();
    }
    let _ = custody
        .establish(
            b.verify_for("bystander", clock(150, 10)).unwrap(),
            b.history_for("bystander"),
        )
        .unwrap();
    let before = custody.status(b.companion_id(), "bystander").unwrap();
    let _ = custody
        .reserve(a.verify(clock(150, 10)).unwrap(), request(), clock(150, 10))
        .unwrap();
    assert_eq!(
        custody.status(b.companion_id(), "bystander").unwrap(),
        before
    );
}

#[test]
fn finite_limits_refuse_oversized_or_excess_entries() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let mut ledger = crate::host_interface::workload::WorkloadLedger::default();
    for _ in 0..3 {
        ledger.replace("workload");
    }
    ledger.save_at(home.path()).unwrap();
    let one = RecoveryCustody::at(home.path(), RecoveryStoreLimits::new(1, 64 * 1024).unwrap());
    let _ = one
        .establish(fixture.verify(clock(150, 10)).unwrap(), fixture.history())
        .unwrap();
    let mut second = Fixture::new();
    second.companion.policy.workload_id = "bystander".into();
    second.resign();
    for _ in 0..3 {
        crate::host_interface::workload::WorkloadLedger::replace_at(home.path(), "bystander")
            .unwrap();
    }
    assert!(matches!(
        one.establish(
            second.verify_for("bystander", clock(150, 10)).unwrap(),
            second.history_for("bystander")
        ),
        Err(RecoveryCustodyError::Limit)
    ));

    let tiny_home = tempfile::tempdir().unwrap();
    let mut ledger = crate::host_interface::workload::WorkloadLedger::default();
    for _ in 0..3 {
        ledger.replace("workload");
    }
    ledger.save_at(tiny_home.path()).unwrap();
    let tiny = RecoveryCustody::at(tiny_home.path(), RecoveryStoreLimits::new(1, 16).unwrap());
    assert!(matches!(
        tiny.establish(fixture.verify(clock(150, 10)).unwrap(), fixture.history()),
        Err(RecoveryCustodyError::Limit)
    ));
}

#[test]
fn failures_before_and_after_publication_are_unknown_and_require_reload() {
    for publish_first in [false, true] {
        let home = tempfile::tempdir().unwrap();
        let fixture = Fixture::new();
        let durable = established(&fixture, home.path());
        let failing = durable.with_commit_for_test(move |path, bytes| {
            if publish_first {
                crate::atomic_io::write_private(path, bytes)?;
            }
            Err(std::io::Error::other("injected commit failure"))
        });
        let error = failing
            .reserve(
                fixture.verify(clock(150, 10)).unwrap(),
                request(),
                clock(150, 10),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            RecoveryCustodyError::CommitUnknown {
                intent: crate::host_interface::recovery_custody::CommitIntent::Transition {
                    step: crate::host_interface::recovery_custody::CommitStep::Reserve,
                    ..
                },
                ..
            }
        ));
        let reloaded = durable
            .reconcile(fixture.verify(clock(150, 10)).unwrap())
            .unwrap();
        let inspected = durable.status(fixture.companion_id(), "workload").unwrap();
        assert_eq!(reloaded, inspected);
        assert_eq!(inspected.current.is_some(), publish_first);
        assert_eq!(inspected.history.restarts_spent, u32::from(publish_first));
    }
}

#[test]
fn establishment_publication_failure_carries_authority_without_inventing_history() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let mut ledger = crate::host_interface::workload::WorkloadLedger::default();
    for _ in 0..3 {
        ledger.replace("workload");
    }
    ledger.save_at(home.path()).unwrap();
    let durable = RecoveryCustody::at(home.path(), limits());
    let failing = durable
        .with_commit_for_test(|_, _| Err(std::io::Error::other("injected establishment failure")));
    let error = failing
        .establish(fixture.verify(clock(150, 10)).unwrap(), fixture.history())
        .unwrap_err();
    assert!(matches!(
        error,
        RecoveryCustodyError::CommitUnknown {
            authority_id,
            intent: crate::host_interface::recovery_custody::CommitIntent::Establish,
            ..
        } if authority_id == fixture.companion_id()
    ));
    assert!(matches!(
        durable.status(fixture.companion_id(), "workload"),
        Err(RecoveryCustodyError::HistoryMissing)
    ));
}

#[test]
fn every_forward_publication_edge_recovers_complete_old_or_new_state() {
    let events = [
        (CustodyEvent::BeginFence, RecoveryPhase::Fencing),
        (CustodyEvent::Retired, RecoveryPhase::Fenced),
        (CustodyEvent::Activate, RecoveryPhase::Activating),
        (CustodyEvent::ActivationCommitted, RecoveryPhase::Launching),
        (CustodyEvent::Ready, RecoveryPhase::Ready),
    ];
    for edge in 0..events.len() {
        for publish_first in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let fixture = Fixture::new();
            let (durable, binding) = reserved(&fixture, home.path());
            for (event, _) in &events[..edge] {
                let _ = durable
                    .record(
                        fixture.verify(clock(150, 10)).unwrap(),
                        &binding,
                        *event,
                        clock(150, 10),
                    )
                    .unwrap();
            }
            let failing = durable.with_commit_for_test(move |path, bytes| {
                if publish_first {
                    crate::atomic_io::write_private(path, bytes)?;
                }
                Err(std::io::Error::other("injected transition failure"))
            });
            assert!(matches!(
                failing.record(
                    fixture.verify(clock(150, 10)).unwrap(),
                    &binding,
                    events[edge].0,
                    clock(150, 10),
                ),
                Err(RecoveryCustodyError::CommitUnknown { .. })
            ));
            let status = durable.status(fixture.companion_id(), "workload").unwrap();
            let observed = status
                .current
                .as_ref()
                .map(|current| current.phase)
                .or_else(|| status.completed.as_ref().map(|completed| completed.phase))
                .unwrap();
            let old = if edge == 0 {
                RecoveryPhase::Reserved
            } else {
                events[edge - 1].1
            };
            assert_eq!(observed, if publish_first { events[edge].1 } else { old });
        }
    }
}

#[test]
fn ordinary_writers_share_the_lock_and_cannot_erase_managed_history() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let custody = established(&fixture, home.path());
    let before = custody.status(fixture.companion_id(), "workload").unwrap();

    let quarantined =
        crate::host_interface::workload::WorkloadLedger::quarantine_at(home.path(), "workload")
            .unwrap();
    assert!(quarantined.quarantined);
    let after = custody.status(fixture.companion_id(), "workload").unwrap();
    assert_eq!(after.history, before.history);
    assert!(after.quarantined);
    assert!(
        crate::host_interface::workload::WorkloadLedger::replace_at(home.path(), "workload")
            .is_err()
    );

    let stale = crate::host_interface::workload::WorkloadLedger::default();
    assert!(stale.save_at(home.path()).is_err());
    assert_eq!(
        custody
            .status(fixture.companion_id(), "workload")
            .unwrap()
            .history,
        before.history
    );
}

#[test]
fn restored_time_rejects_regression_and_changed_continuity() {
    for now in [
        clock(149, 11),
        clock(151, 9),
        ClockEvidence::Bounded {
            earliest_unix: 151,
            latest_unix: 151,
            monotonic_seconds: 11,
            continuity: [8; 16],
        },
    ] {
        let home = tempfile::tempdir().unwrap();
        let fixture = Fixture::new();
        let (custody, binding) = reserved(&fixture, home.path());
        let status = custody
            .record(
                fixture.verify(clock(150, 10)).unwrap(),
                &binding,
                CustodyEvent::BeginFence,
                now,
            )
            .unwrap();
        assert_eq!(status.current.unwrap().phase, RecoveryPhase::Blocked);
        assert_eq!(status.action, RecoveryAction::CloseAndReconcile);
    }
}

#[test]
fn resume_with_lost_clock_continuity_durably_blocks_progress() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let (custody, _) = reserved(&fixture, home.path());
    let changed = ClockEvidence::Bounded {
        earliest_unix: 151,
        latest_unix: 151,
        monotonic_seconds: 11,
        continuity: [8; 16],
    };
    assert!(custody.resume(fixture.verify(changed).unwrap()).is_err());
    let status = custody.status(fixture.companion_id(), "workload").unwrap();
    assert_eq!(status.current.unwrap().phase, RecoveryPhase::Blocked);
    assert_eq!(status.history.restarts_spent, 1);
}

#[test]
fn legacy_entries_round_trip_without_managed_history() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir(home.path().join("host-interface")).unwrap();
    crate::private_fs::set_mode(home.path().join("host-interface"), 0o700).unwrap();
    let path = home.path().join("host-interface/workloads.json");
    crate::atomic_io::write_private(&path, br#"{"ordinary":{"epoch":3,"quarantined":false}}"#)
        .unwrap();
    let ledger = crate::host_interface::workload::WorkloadLedger::load_at(home.path()).unwrap();
    assert_eq!(ledger.entry("ordinary").epoch, ExecutionEpoch(3));
    ledger.save_at(home.path()).unwrap();
    assert!(
        RecoveryCustody::at(home.path(), limits())
            .status([7; 32], "ordinary")
            .is_err()
    );
}

#[test]
fn malformed_completed_and_activation_state_refuse_on_reload() {
    for corruption in ["completed_not_activated", "reserved_marked_activated"] {
        let home = tempfile::tempdir().unwrap();
        let fixture = Fixture::new();
        let (custody, binding) = reserved(&fixture, home.path());
        if corruption == "completed_not_activated" {
            finish(&custody, &fixture, &binding, clock(150, 10));
        }
        let path = home.path().join("host-interface/workloads.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        match corruption {
            "completed_not_activated" => {
                value["workload"]["recovery"]["completed"]["activation_committed"] = false.into();
            }
            "reserved_marked_activated" => {
                value["workload"]["recovery"]["current"]["activation_committed"] = true.into();
            }
            _ => unreachable!(),
        }
        crate::atomic_io::write_private(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            custody.status(fixture.companion_id(), "workload"),
            Err(RecoveryCustodyError::State(_))
        ));
    }
}

#[test]
#[cfg(unix)]
fn an_existing_store_retries_parent_directory_sync_before_acknowledgement() {
    let home = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let custody = established(&fixture, home.path());
    let _ = crate::host_interface::recovery_custody::take_parent_sync_count_for_test();
    crate::host_interface::recovery_custody::fail_parent_sync_once_for_test();
    assert!(matches!(
        custody.status(fixture.companion_id(), "workload"),
        Err(RecoveryCustodyError::State(_))
    ));
    assert!(custody.status(fixture.companion_id(), "workload").is_ok());
    assert_eq!(
        crate::host_interface::recovery_custody::take_parent_sync_count_for_test(),
        2
    );
}

#[cfg(unix)]
#[test]
fn managed_open_refuses_symlink_hardlink_and_public_state() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    for attack in ["symlink", "hardlink", "public"] {
        let home = tempfile::tempdir().unwrap();
        let fixture = Fixture::new();
        let custody = established(&fixture, home.path());
        let state = home.path().join("host-interface/workloads.json");
        let saved = std::fs::read(&state).unwrap();
        match attack {
            "symlink" => {
                let outside = home.path().join("outside");
                std::fs::write(&outside, &saved).unwrap();
                std::fs::remove_file(&state).unwrap();
                symlink(outside, &state).unwrap();
            }
            "hardlink" => {
                std::fs::hard_link(&state, home.path().join("alias")).unwrap();
            }
            "public" => {
                std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            custody.status(fixture.companion_id(), "workload"),
            Err(RecoveryCustodyError::State(_))
        ));
    }
}

#[cfg(unix)]
#[test]
fn managed_open_refuses_replaced_or_public_lock_files() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    for attack in ["symlink", "hardlink", "public"] {
        let home = tempfile::tempdir().unwrap();
        let fixture = Fixture::new();
        let custody = established(&fixture, home.path());
        let lock = home.path().join("host-interface/workloads.lock");
        match attack {
            "symlink" => {
                let outside = home.path().join("outside-lock");
                std::fs::write(&outside, b"outside").unwrap();
                std::fs::remove_file(&lock).unwrap();
                symlink(outside, &lock).unwrap();
            }
            "hardlink" => {
                std::fs::hard_link(&lock, home.path().join("lock-alias")).unwrap();
            }
            "public" => {
                std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            _ => unreachable!(),
        }
        let result = custody.status(fixture.companion_id(), "workload");
        if attack == "public" {
            assert!(result.is_ok(), "an owned lock is safely tightened");
        } else {
            assert!(matches!(result, Err(RecoveryCustodyError::State(_))));
        }
    }
}
