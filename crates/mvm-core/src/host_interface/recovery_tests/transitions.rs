use super::*;

#[test]
fn either_absolute_or_fixed_monotonic_expiry_blocks_independently() {
    for now in [clock(150, 50), clock(190, 10)] {
        let mut r = Fixture::new().recovery();
        let decision = r.request(request(), now).unwrap();
        assert_eq!(decision.phase, RecoveryPhase::Blocked);
        assert_eq!(decision.refusal, Some(Denial::LeaseExpired));
        assert_eq!(decision.action, RecoveryAction::CloseAndReconcile);
        assert!(decision.binding.is_none(), "expiry precedes reservation");
    }
}

#[test]
fn safety_invalidation_with_stale_input_targets_recorded_not_supplied_owners() {
    let f = Fixture::new();
    for now in [clock(190, 50), ClockEvidence::Unknown] {
        let mut r = at_step(&f, 0);
        let recorded = r.binding().unwrap().clone();
        let mut stale = recorded.clone();
        stale.workload_id = "bystander".into();
        stale.request.original.instance = [11; 16];
        let decision = r.observe(&stale, RecoveryEvent::Ready, now).unwrap();
        assert_eq!(decision.phase, RecoveryPhase::Blocked);
        assert_eq!(decision.action, RecoveryAction::CloseAndReconcile);
        assert_eq!(decision.original, recorded.request.original);
        assert_eq!(decision.binding, Some(recorded));
    }
}

const ORDER: [RecoveryEvent; 6] = [
    RecoveryEvent::ReservationCommitted,
    RecoveryEvent::BeginFence,
    RecoveryEvent::Retired,
    RecoveryEvent::Activate,
    RecoveryEvent::ActivationCommitted,
    RecoveryEvent::Ready,
];

#[test]
fn cleanup_before_any_request_still_names_exact_owner_and_authority() {
    for trigger in 0..3 {
        let mut f = Fixture::new();
        f.companion.policy.dependency_loss = DependencyLoss::Stop;
        f.resign();
        let mut r = f.recovery();
        let decision = match trigger {
            0 => r.dependency_lost(clock(190, 50)),
            1 => r.dependency_lost(clock(150, 10)),
            2 => r.invalidate(Denial::EnforcementUnavailable),
            _ => unreachable!(),
        };
        assert!(decision.binding.is_none());
        assert_eq!(decision.authority_id, f.history().authority_id);
        assert_eq!(decision.workload_id, "workload");
        assert_eq!(decision.original, f.history().original);
        assert_eq!(decision.deadline, 50);
        assert_eq!(decision.action, RecoveryAction::CloseAndReconcile);
    }
}

fn at_step(f: &Fixture, steps: usize) -> Recovery {
    let mut r = f.recovery();
    let _ = r.request(request(), clock(150, 10)).unwrap();
    let binding = r.binding().unwrap().clone();
    for event in &ORDER[..steps] {
        let _ = r.observe(&binding, *event, clock(150, 10)).unwrap();
    }
    r
}

#[test]
fn every_phase_refuses_skipping_required_transitions() {
    let f = Fixture::new();
    for step in 0..ORDER.len() {
        for event in &ORDER[step + 1..] {
            let mut r = at_step(&f, step);
            let binding = r.binding().unwrap().clone();
            let phase = r.phase();
            assert!(
                r.observe(&binding, *event, clock(150, 10)).is_err(),
                "step {step} event {event:?}"
            );
            assert_eq!(r.phase(), phase);
        }
    }
}

#[test]
fn cancellation_at_every_edge_preserves_debit_and_forbids_late_progress() {
    let f = Fixture::new();
    for step in 0..=ORDER.len() {
        let mut r = at_step(&f, step);
        let binding = r.binding().unwrap().clone();
        let decision = r
            .observe(&binding, RecoveryEvent::Cancel, clock(150, 10))
            .unwrap();
        if step >= 5 {
            assert_eq!(decision.phase, RecoveryPhase::Unknown);
            assert_eq!(decision.action, RecoveryAction::Reconcile);
        } else {
            assert_eq!(decision.phase, RecoveryPhase::Cancelled);
            assert_eq!(decision.action, RecoveryAction::RetainReservation);
        }
        for event in ORDER {
            assert!(r.observe(&binding, event, clock(150, 10)).is_err());
        }
        assert_eq!(r.binding(), Some(&binding), "no refund at step {step}");
        assert_eq!(
            r.request(request(), clock(150, 10)).unwrap().action,
            RecoveryAction::None
        );
    }
}

#[test]
fn expired_ready_cancelled_unknown_and_running_states_still_require_cleanup() {
    let f = Fixture::new();
    for terminal in [
        None,
        Some(RecoveryEvent::Cancel),
        Some(RecoveryEvent::Uncertain),
    ] {
        let mut r = at_step(&f, ORDER.len());
        let binding = r.binding().unwrap().clone();
        if let Some(event) = terminal {
            let _ = r.observe(&binding, event, clock(150, 10)).unwrap();
        }
        let blocked = r
            .observe(&binding, RecoveryEvent::Ready, clock(190, 50))
            .unwrap();
        assert_eq!(blocked.phase, RecoveryPhase::Blocked);
        assert_eq!(blocked.action, RecoveryAction::CloseAndReconcile);
        assert_eq!(blocked.refusal, Some(Denial::LeaseExpired));
    }
    let mut r = f.recovery();
    assert_eq!(
        r.dependency_lost(clock(190, 50)).action,
        RecoveryAction::CloseAndReconcile
    );
    assert!(r.request(request(), clock(151, 11)).is_err());
}

#[test]
fn suspend_continuity_loss_and_later_clock_rollback_are_latched() {
    for bad in [
        ClockEvidence::Bounded {
            earliest_unix: 151,
            latest_unix: 151,
            monotonic_seconds: 11,
            continuity: [8; 16],
        },
        clock(151, 12),
        clock(152, 11),
    ] {
        let mut r = Fixture::new().recovery();
        let _ = r.request(request(), clock(152, 12)).unwrap();
        let binding = r.binding().unwrap().clone();
        let decision = r
            .observe(&binding, RecoveryEvent::ReservationCommitted, bad)
            .unwrap();
        assert_eq!(decision.phase, RecoveryPhase::Blocked);
        assert!(
            r.observe(
                &binding,
                RecoveryEvent::ReservationCommitted,
                clock(153, 13)
            )
            .is_err()
        );
    }
}

#[test]
fn dependency_stop_never_infers_retirement_or_recovers_after_link_returns() {
    let mut f = Fixture::new();
    f.companion.policy.dependency_loss = DependencyLoss::Stop;
    f.resign();
    for step in 0..=ORDER.len() {
        let mut r = at_step(&f, step);
        assert_eq!(
            r.dependency_lost(clock(150, 10)).action,
            RecoveryAction::CloseAndReconcile
        );
        let binding = r.binding().unwrap().clone();
        assert!(
            r.observe(&binding, RecoveryEvent::Ready, clock(150, 10))
                .is_err()
        );
        assert_eq!(
            r.request(request(), clock(150, 10)).unwrap().phase,
            RecoveryPhase::Blocked
        );
    }
}

#[test]
fn every_transition_binding_component_is_checked() {
    let f = Fixture::new();
    for component in 0..9 {
        let mut r = at_step(&f, 0);
        let mut binding = r.binding().unwrap().clone();
        match component {
            0 => binding.authority_id = [1; 32],
            1 => binding.workload_id = "other".into(),
            2 => binding.request.operation += 1,
            3 => binding.request.original.instance = [11; 16],
            4 => binding.request.original.epoch = ExecutionEpoch(3),
            5 => binding.request.proposed_epoch = ExecutionEpoch(6),
            6 => binding.request.replacement_instance = [11; 16],
            7 => binding.restart_debit = 2,
            8 => binding.original_lease_expiry += 1,
            _ => unreachable!(),
        }
        assert!(
            r.observe(
                &binding,
                RecoveryEvent::ReservationCommitted,
                clock(150, 10)
            )
            .is_err()
        );
        assert_eq!(r.phase(), RecoveryPhase::Reserving);
    }
}

#[test]
fn impossible_history_and_reissued_companion_cannot_reset_existing_budget() {
    let f = Fixture::new();
    for component in 0..5 {
        let mut history = f.history();
        match component {
            0 => history.authority_id = [0; 32],
            1 => history.original.epoch = ExecutionEpoch(0),
            2 => history.epoch_high_water = ExecutionEpoch(3),
            3 => history.restarts_spent = 3,
            4 => history.original.instance = [0; 16],
            _ => unreachable!(),
        }
        assert!(Recovery::new(f.verify(clock(150, 10)).unwrap(), Some(history)).is_err());
    }
    let history = f.history();
    let mut f = Fixture::new();
    f.companion.policy.connection_attempts = 7;
    f.resign();
    assert!(Recovery::new(f.verify(clock(150, 10)).unwrap(), Some(history)).is_err());
}

#[test]
fn one_workload_never_advances_a_bystanders_epoch_or_budget() {
    let a = Fixture::new();
    let mut b = Fixture::new();
    b.companion.policy.workload_id = "bystander".into();
    b.resign();
    let trusted = [("issuer".into(), b.key.verifying_key())];
    let mut input = b.input(&trusted);
    input.expected.workload_id = "bystander";
    let authority = VerifiedOfflineAuthority::verify(input, clock(150, 10)).unwrap();
    let mut history = b.history();
    history.workload_id = "bystander".into();
    let bystander = Recovery::new(authority, Some(history)).unwrap();
    let recovered = at_step(&a, ORDER.len());
    assert_eq!(recovered.phase(), RecoveryPhase::Ready);
    assert_eq!(bystander.phase(), RecoveryPhase::Running);
    assert!(bystander.binding().is_none());
    assert_eq!(b.history().original.epoch, ExecutionEpoch(4));
}
