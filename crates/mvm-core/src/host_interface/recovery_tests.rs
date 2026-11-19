use ed25519_dalek::{SigningKey, VerifyingKey};

mod authority;
mod custody;
mod transitions;

use super::{
    Assurance, Denial, ExecutionEpoch, HostInterface, HostPolicy, LaunchRequest, NodeState,
    SignedHostPolicy,
    error::OfflineRefusal,
    lease::{LeaseOp, OfflineLease, SignedLease},
    local::LocalHostInterface,
    offline::{
        AuthorityExpectation, AuthorityInput, ClockEvidence, DependencyLoss, OfflineCeilings,
        RecoveryPolicy, RestartAllowance, SignedRecoveryPolicy, VerifiedOfflineAuthority,
        signed_record_digest,
    },
    recovery::{
        History, Owner, Recovery, RecoveryAction, RecoveryEvent, RecoveryPhase, RestartRequest,
    },
};

fn clock(unix: u64, monotonic: u64) -> ClockEvidence {
    ClockEvidence::Bounded {
        earliest_unix: unix,
        latest_unix: unix,
        monotonic_seconds: monotonic,
        continuity: [7; 16],
    }
}

struct Fixture {
    key: SigningKey,
    lease: SignedLease,
    policy: SignedHostPolicy,
    companion: SignedRecoveryPolicy,
}

impl Fixture {
    fn new() -> Self {
        let key = SigningKey::from_bytes(&[1; 32]);
        let lease = SignedLease::sign(
            OfflineLease {
                node_id: "node".into(),
                policy_version: 4,
                issued_at: 100,
                not_after: 200,
                allowed: vec![LeaseOp::LocalLaunch, LeaseOp::Egress],
                max_queued_messages: 0,
            },
            "issuer",
            &key,
        )
        .unwrap();
        let policy = SignedHostPolicy::sign(
            HostPolicy {
                version: 4,
                not_after: Some(190),
                scope: vec!["node".into()],
                ..HostPolicy::default()
            },
            "issuer",
            &key,
        )
        .unwrap();
        let companion = SignedRecoveryPolicy::sign(
            RecoveryPolicy {
                version: 1,
                issuer: "issuer".into(),
                lease_digest: signed_record_digest(&lease).unwrap(),
                policy_digest: signed_record_digest(&policy).unwrap(),
                workload_id: "workload".into(),
                package_digest: [3; 32],
                restart: RestartAllowance::SamePackage {
                    max_restarts: 2,
                    first_epoch: ExecutionEpoch(5),
                    last_epoch: ExecutionEpoch(6),
                },
                connection_attempts: 8,
                dependency_loss: DependencyLoss::ContinueAuthorized,
            },
            &key,
        )
        .unwrap();
        Self {
            key,
            lease,
            policy,
            companion,
        }
    }

    fn resign(&mut self) {
        self.lease = SignedLease::sign(self.lease.lease.clone(), "issuer", &self.key).unwrap();
        self.policy =
            SignedHostPolicy::sign(self.policy.policy.clone(), "issuer", &self.key).unwrap();
        self.companion.policy.lease_digest = signed_record_digest(&self.lease).unwrap();
        self.companion.policy.policy_digest = signed_record_digest(&self.policy).unwrap();
        self.companion =
            SignedRecoveryPolicy::sign(self.companion.policy.clone(), &self.key).unwrap();
    }

    fn verify(&self, now: ClockEvidence) -> Result<VerifiedOfflineAuthority, Denial> {
        self.verify_for("workload", now)
    }

    fn verify_for(
        &self,
        workload: &str,
        now: ClockEvidence,
    ) -> Result<VerifiedOfflineAuthority, Denial> {
        let trusted = [("issuer".into(), self.key.verifying_key())];
        let mut input = self.input(&trusted);
        input.expected.workload_id = workload;
        VerifiedOfflineAuthority::verify(input, now)
    }

    fn input<'a>(&'a self, trusted: &'a [(String, VerifyingKey)]) -> AuthorityInput<'a> {
        AuthorityInput {
            lease: Some(&self.lease),
            policy: Some(&self.policy),
            companion: Some(&self.companion),
            lease_issuers: trusted,
            policy_issuers: trusted,
            expected: AuthorityExpectation {
                issuer: "issuer",
                node_id: "node",
                workload_id: "workload",
                package_digest: [3; 32],
                min_policy_version: 4,
                node_state: NodeState::Active,
            },
            ceilings: OfflineCeilings {
                lease_seconds: 100,
                restarts: 2,
                connection_attempts: 8,
            },
        }
    }

    fn history(&self) -> History {
        self.history_for("workload")
    }

    fn history_for(&self, workload: &str) -> History {
        History {
            authority_id: signed_record_digest(&self.companion).unwrap(),
            workload_id: workload.into(),
            original: Owner {
                instance: [9; 16],
                epoch: ExecutionEpoch(4),
            },
            epoch_high_water: ExecutionEpoch(4),
            restarts_spent: 0,
            last_operation: 10,
        }
    }

    fn companion_id(&self) -> [u8; 32] {
        signed_record_digest(&self.companion).unwrap()
    }

    fn recovery(&self) -> Recovery {
        Recovery::new(self.verify(clock(150, 10)).unwrap(), Some(self.history())).unwrap()
    }
}

fn request() -> RestartRequest {
    RestartRequest {
        operation: 11,
        original: Owner {
            instance: [9; 16],
            epoch: ExecutionEpoch(4),
        },
        proposed_epoch: ExecutionEpoch(5),
        replacement_instance: [10; 16],
    }
}

#[test]
fn verified_authority_is_bound_and_has_one_conservative_deadline() {
    let f = Fixture::new();
    let a = f.verify(clock(150, 10)).unwrap();
    assert_eq!(a.deadline(), 50, "policy expiry narrows the lease");
    assert_eq!(a.connection_attempts(), 8);
    assert!(a.permits(LeaseOp::Egress, clock(189, 49)).is_ok());
    assert_eq!(
        a.permits(LeaseOp::SecretUse, clock(150, 10)),
        Err(Denial::LeaseOpNotAllowed("secret_use"))
    );
    assert_eq!(
        a.permits(LeaseOp::Egress, clock(190, 50)),
        Err(Denial::LeaseExpired)
    );
}

#[test]
fn wrong_signed_bindings_refuse_even_with_a_valid_signature() {
    for field in ["issuer", "node", "workload", "package", "policy", "lease"] {
        let mut f = Fixture::new();
        match field {
            "issuer" => f.companion.policy.issuer = "other".into(),
            "node" => f.lease.lease.node_id = "other".into(),
            "workload" => f.companion.policy.workload_id = "other".into(),
            "package" => f.companion.policy.package_digest = [4; 32],
            "policy" => f.policy.policy.version = 5,
            "lease" => f.lease.lease.policy_version = 3,
            _ => unreachable!(),
        }
        f.resign();
        assert!(f.verify(clock(150, 10)).is_err(), "{field}");
    }
}

#[test]
fn tampering_and_rebinding_signed_records_refuse() {
    let mut f = Fixture::new();
    f.companion.policy.connection_attempts += 1;
    assert!(f.verify(clock(150, 10)).is_err());
    let mut f = Fixture::new();
    f.lease.lease.not_after = 199;
    f.lease = SignedLease::sign(f.lease.lease, "issuer", &f.key).unwrap();
    assert!(f.verify(clock(150, 10)).is_err());
    let mut f = Fixture::new();
    f.policy.policy.not_after = Some(180);
    f.policy = SignedHostPolicy::sign(f.policy.policy, "issuer", &f.key).unwrap();
    assert!(f.verify(clock(150, 10)).is_err());
}

#[test]
fn unknown_early_expired_and_overflowing_time_refuse() {
    let f = Fixture::new();
    for now in [
        ClockEvidence::Unknown,
        clock(99, 10),
        clock(200, 10),
        clock(150, u64::MAX),
        ClockEvidence::Bounded {
            earliest_unix: 151,
            latest_unix: 150,
            monotonic_seconds: 10,
            continuity: [7; 16],
        },
    ] {
        assert!(f.verify(now).is_err(), "{now:?}");
    }
}

#[test]
fn invalid_restart_ranges_and_zero_connection_budget_refuse() {
    for (count, first, last) in [(0, 5, 6), (3, 5, 6), (1, 0, 6), (1, 6, 5)] {
        let mut f = Fixture::new();
        f.companion.policy.restart = RestartAllowance::SamePackage {
            max_restarts: count,
            first_epoch: ExecutionEpoch(first),
            last_epoch: ExecutionEpoch(last),
        };
        f.resign();
        assert!(f.verify(clock(150, 10)).is_err());
    }
    let mut f = Fixture::new();
    f.companion.policy.connection_attempts = 0;
    f.resign();
    assert!(f.verify(clock(150, 10)).is_err());
}

#[test]
fn missing_history_never_becomes_local_authority() {
    let f = Fixture::new();
    assert!(matches!(
        Recovery::new(f.verify(clock(150, 10)).unwrap(), None),
        Err(Denial::Offline(OfflineRefusal::HistoryMissing))
    ));
    let mut history = f.history();
    history.workload_id = "bystander".into();
    assert!(Recovery::new(f.verify(clock(150, 10)).unwrap(), Some(history)).is_err());
}

#[test]
fn reservation_fencing_activation_and_launch_are_separate() {
    let mut r = Fixture::new().recovery();
    let requested = r.request(request(), clock(150, 10)).unwrap();
    assert_eq!(requested.action, RecoveryAction::Reserve);
    assert_eq!(requested.phase, RecoveryPhase::Reserving);
    let binding = r.binding().unwrap().clone();
    for (event, phase, action) in [
        (
            RecoveryEvent::ReservationCommitted,
            RecoveryPhase::Reserved,
            RecoveryAction::None,
        ),
        (
            RecoveryEvent::BeginFence,
            RecoveryPhase::Fencing,
            RecoveryAction::FenceOriginal,
        ),
        (
            RecoveryEvent::Retired,
            RecoveryPhase::Fenced,
            RecoveryAction::None,
        ),
        (
            RecoveryEvent::Activate,
            RecoveryPhase::Activating,
            RecoveryAction::ActivateReserved,
        ),
        (
            RecoveryEvent::ActivationCommitted,
            RecoveryPhase::Launching,
            RecoveryAction::AdmitAndLaunch,
        ),
        (
            RecoveryEvent::Ready,
            RecoveryPhase::Ready,
            RecoveryAction::None,
        ),
    ] {
        let result = r.observe(&binding, event, clock(150, 10)).unwrap();
        assert_eq!(result.phase, phase);
        assert_eq!(result.action, action);
        assert_eq!(
            r.observe(&binding, event, clock(150, 10)).unwrap().action,
            RecoveryAction::None,
            "duplicate {event:?}"
        );
    }
    assert_eq!(
        r.request(request(), clock(150, 10)).unwrap().action,
        RecoveryAction::None
    );
}

#[test]
fn no_event_can_skip_reservation_or_fencing() {
    let f = Fixture::new();
    for event in [
        RecoveryEvent::Retired,
        RecoveryEvent::Activate,
        RecoveryEvent::ActivationCommitted,
        RecoveryEvent::Ready,
    ] {
        let mut r = f.recovery();
        let _ = r.request(request(), clock(150, 10)).unwrap();
        let binding = r.binding().unwrap().clone();
        assert!(
            r.observe(&binding, event, clock(150, 10)).is_err(),
            "{event:?}"
        );
        assert_eq!(r.phase(), RecoveryPhase::Reserving);
    }
}

#[test]
fn repeated_requests_conflicts_and_stale_inputs_do_not_spend_again() {
    let mut r = Fixture::new().recovery();
    let mut stale = request();
    stale.operation = 10;
    assert!(r.request(stale, clock(150, 10)).is_err());
    let _ = r.request(request(), clock(150, 10)).unwrap();
    for _ in 0..20 {
        assert_eq!(
            r.request(request(), clock(150, 10)).unwrap().action,
            RecoveryAction::None
        );
    }
    let mut changed = request();
    changed.proposed_epoch = ExecutionEpoch(6);
    assert!(r.request(changed, clock(150, 10)).is_err());
    let mut binding = r.binding().unwrap().clone();
    binding.request.original.instance = [8; 16];
    assert!(
        r.observe(
            &binding,
            RecoveryEvent::ReservationCommitted,
            clock(150, 10)
        )
        .is_err()
    );
    assert_eq!(r.binding().unwrap().restart_debit, 1);
}

#[test]
fn exhausted_allowance_and_epoch_bounds_refuse() {
    let f = Fixture::new();
    let mut history = f.history();
    history.restarts_spent = 2;
    let mut r = Recovery::new(f.verify(clock(150, 10)).unwrap(), Some(history)).unwrap();
    assert!(r.request(request(), clock(150, 10)).is_err());
    for epoch in [0, 4, 7, u64::MAX] {
        let mut r = f.recovery();
        let mut req = request();
        req.proposed_epoch = ExecutionEpoch(epoch);
        assert!(r.request(req, clock(150, 10)).is_err());
    }
}

#[test]
fn cancellation_and_uncertain_fencing_cannot_launch() {
    for event in [RecoveryEvent::Cancel, RecoveryEvent::Uncertain] {
        let mut r = Fixture::new().recovery();
        let _ = r.request(request(), clock(150, 10)).unwrap();
        let binding = r.binding().unwrap().clone();
        let _ = r.observe(&binding, event, clock(150, 10)).unwrap();
        assert!(
            r.observe(&binding, RecoveryEvent::Retired, clock(150, 10))
                .is_err()
        );
        assert!(
            r.observe(&binding, RecoveryEvent::ActivationCommitted, clock(150, 10))
                .is_err()
        );
        assert_eq!(r.binding().unwrap().restart_debit, 1);
    }
}

#[test]
fn expiry_and_clock_correction_cannot_revive_recovery() {
    for bad_time in [
        clock(190, 50),
        clock(149, 11),
        clock(151, 9),
        ClockEvidence::Unknown,
    ] {
        let mut r = Fixture::new().recovery();
        let _ = r.request(request(), clock(150, 10)).unwrap();
        let binding = r.binding().unwrap().clone();
        let blocked = r
            .observe(&binding, RecoveryEvent::ReservationCommitted, bad_time)
            .unwrap();
        assert_eq!(blocked.phase, RecoveryPhase::Blocked);
        assert_eq!(blocked.action, RecoveryAction::CloseAndReconcile);
        assert!(
            r.observe(
                &binding,
                RecoveryEvent::ReservationCommitted,
                clock(151, 11)
            )
            .is_err()
        );
    }
}

#[test]
fn heartbeats_do_not_prove_death_or_spend_restart_allowance() {
    let mut r = Fixture::new().recovery();
    for _ in 0..100 {
        assert_eq!(
            r.dependency_lost(clock(150, 10)).action,
            RecoveryAction::None
        );
        assert_eq!(r.phase(), RecoveryPhase::Running);
    }
    assert!(r.binding().is_none());
    assert_eq!(
        r.request(request(), clock(150, 10)).unwrap().action,
        RecoveryAction::Reserve
    );
    assert_eq!(r.binding().unwrap().restart_debit, 1);
}

#[test]
fn ordinary_local_defaults_still_need_no_managed_authority() {
    let local = LocalHostInterface::new("local", HostPolicy::default(), Assurance::None, || 150);
    assert!(
        local
            .authorize_workload(&LaunchRequest {
                workload_id: "ordinary".into(),
                image_digest: "local-image".into(),
                epoch: ExecutionEpoch(1),
            })
            .is_ok()
    );
}
