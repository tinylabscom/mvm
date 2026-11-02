//! Pure lifecycle of one retained cold-HVF invocation, as the original owner sees it.
//!
//! This is the transition and refusal table only. It holds no process, key or
//! socket, authenticates nobody, and cannot be rebuilt from a request: the owner
//! creates it before the first native effect and it dies with the owner. A caller
//! must authenticate a request before [`OwnerLifecycle::apply`]; this type compares
//! public identity and ordering, which is necessary and not sufficient.

use alloc::string::String;
use core::num::NonZeroU64;

use super::hvf_owner::{RecoveryBinding, RecoveryOperation, UntrustedRecoveryRequest};

/// Where the retained operation stands. `RecoveryRequired` and `Quarantined`
/// never fall back to `Prepared`: unknown is not reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerState {
    Registered,
    Prepared,
    Active,
    Stopping,
    /// Compound terminal proof held; the result may be delivered.
    Terminal,
    /// Effects may have happened and the original owner has not proven them over.
    RecoveryRequired,
    /// The owner died. Absorbing: nothing here clears it.
    Quarantined,
}

/// The three independent halves of a successful end. Any missing half keeps the
/// operation in `RecoveryRequired`; a guest exit code is none of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalProof {
    pub completion_barrier: bool,
    pub original_generation_finalized: bool,
    pub cleanup_and_audit: bool,
}

impl TerminalProof {
    fn complete(self) -> bool {
        self.completion_barrier && self.original_generation_finalized && self.cleanup_and_audit
    }
}

/// What an accepted request observed or changed. Never a completion capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    Observed {
        state: OwnerState,
        result_revision: Option<NonZeroU64>,
    },
    /// Cancellation intent recorded; repeated ones coalesce into this one.
    CancelPending,
    /// The state was already past cancellation; nothing was changed.
    CancelMoot,
    Acknowledged,
    /// A repeated acknowledgement: no cleanup or audit is repeated.
    AlreadyAcknowledged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LifecycleRefusal {
    #[error("request names another operation, principal, tenant, incarnation or generation")]
    BindingMismatch,
    #[error("request sequence is not newer than the last accepted one")]
    StaleSequence,
    #[error("the owner is quarantined; recovery is not available")]
    Quarantined,
    #[error("result is not available for acknowledgement")]
    ResultNotReady,
    #[error("acknowledgement names another result revision")]
    ResultRevisionMismatch,
    #[error("transition is not valid from the current state")]
    InvalidTransition,
}

#[derive(Debug)]
pub struct OwnerLifecycle {
    binding: RecoveryBinding,
    state: OwnerState,
    last_sequence: u64,
    cancel_pending: bool,
    stop_attempted: bool,
    result_revision: Option<NonZeroU64>,
    acknowledged: bool,
}

impl OwnerLifecycle {
    /// Registered before any native effect, bound to the exact retained context.
    #[must_use]
    pub fn register(binding: RecoveryBinding) -> Self {
        Self {
            binding,
            state: OwnerState::Registered,
            last_sequence: 0,
            cancel_pending: false,
            stop_attempted: false,
            result_revision: None,
            acknowledged: false,
        }
    }

    #[must_use]
    pub fn state(&self) -> OwnerState {
        self.state
    }

    #[must_use]
    pub fn cancel_pending(&self) -> bool {
        self.cancel_pending
    }

    #[must_use]
    pub fn tenant_id(&self) -> &String {
        &self.binding.tenant_id
    }

    fn move_if(&mut self, from: OwnerState, to: OwnerState) -> Result<(), LifecycleRefusal> {
        if self.state == OwnerState::Quarantined {
            return Err(LifecycleRefusal::Quarantined);
        }
        if self.state != from {
            return Err(LifecycleRefusal::InvalidTransition);
        }
        self.state = to;
        Ok(())
    }

    /// Inputs frozen and admitted.
    ///
    /// # Errors
    /// Refuses unless the operation is `Registered`.
    pub fn prepared(&mut self) -> Result<(), LifecycleRefusal> {
        self.move_if(OwnerState::Registered, OwnerState::Prepared)
    }

    /// The native child exists.
    ///
    /// # Errors
    /// Refuses unless the operation is `Prepared`.
    pub fn activated(&mut self) -> Result<(), LifecycleRefusal> {
        self.move_if(OwnerState::Prepared, OwnerState::Active)
    }

    /// Preparation failed. Only a proven child-free failure releases anything;
    /// otherwise custody stays with the owner as `RecoveryRequired`.
    ///
    /// # Errors
    /// Refuses unless the operation is `Registered` or `Prepared`.
    pub fn preparation_failed(&mut self, proven_child_free: bool) -> Result<(), LifecycleRefusal> {
        if self.state == OwnerState::Quarantined {
            return Err(LifecycleRefusal::Quarantined);
        }
        if !matches!(self.state, OwnerState::Registered | OwnerState::Prepared) {
            return Err(LifecycleRefusal::InvalidTransition);
        }
        self.state = if proven_child_free {
            OwnerState::Terminal
        } else {
            OwnerState::RecoveryRequired
        };
        Ok(())
    }

    /// The owner began its one stop attempt (cancellation, disconnect or deadline).
    /// From `RecoveryRequired` the child may still run, so a stop is allowed there
    /// when none has been attempted; a second attempt is never made.
    ///
    /// # Errors
    /// Refuses unless the operation is `Active`, or `RecoveryRequired` with no
    /// earlier stop attempt.
    pub fn stop_started(&mut self) -> Result<(), LifecycleRefusal> {
        if self.state == OwnerState::Quarantined {
            return Err(LifecycleRefusal::Quarantined);
        }
        let allowed = self.state == OwnerState::Active
            || (self.state == OwnerState::RecoveryRequired && !self.stop_attempted);
        if !allowed {
            return Err(LifecycleRefusal::InvalidTransition);
        }
        self.stop_attempted = true;
        self.state = OwnerState::Stopping;
        Ok(())
    }

    /// Stop or cleanup ended, or the owner later proved a recoverable end. Only the complete compound proof reaches `Terminal`
    /// (and only then is a result revision issued); anything less stays recoverable.
    ///
    /// # Errors
    /// Refuses unless the operation is `Active`, `Stopping` or `RecoveryRequired`.
    pub fn finished(
        &mut self,
        proof: TerminalProof,
        revision: NonZeroU64,
    ) -> Result<(), LifecycleRefusal> {
        if self.state == OwnerState::Quarantined {
            return Err(LifecycleRefusal::Quarantined);
        }
        if !matches!(
            self.state,
            OwnerState::Active | OwnerState::Stopping | OwnerState::RecoveryRequired
        ) {
            return Err(LifecycleRefusal::InvalidTransition);
        }
        if proof.complete() {
            self.state = OwnerState::Terminal;
            self.result_revision = Some(revision);
        } else {
            self.state = OwnerState::RecoveryRequired;
        }
        Ok(())
    }

    /// A frontend vanished. Requests bounded cancellation; keeps custody and
    /// never infers that a detach succeeded.
    pub fn frontend_disconnected(&mut self) {
        if matches!(
            self.state,
            OwnerState::Registered
                | OwnerState::Prepared
                | OwnerState::Active
                | OwnerState::RecoveryRequired
        ) {
            self.cancel_pending = true;
        }
    }

    /// The owner died. Quarantine is absorbing and never cleared by this type.
    pub fn owner_died(&mut self) {
        self.state = OwnerState::Quarantined;
    }

    /// Apply an already-authenticated request from the original owner's connection.
    ///
    /// # Errors
    /// Refuses a quarantined owner, a binding that is not exactly this operation's
    /// (stale generation or identity included), a sequence that is not strictly
    /// newer, and early or conflicting acknowledgements.
    pub fn apply(
        &mut self,
        request: &UntrustedRecoveryRequest,
    ) -> Result<Applied, LifecycleRefusal> {
        if self.state == OwnerState::Quarantined {
            return Err(LifecycleRefusal::Quarantined);
        }
        if request.binding != self.binding {
            return Err(LifecycleRefusal::BindingMismatch);
        }
        if request.sequence.get() <= self.last_sequence {
            return Err(LifecycleRefusal::StaleSequence);
        }
        // Refused requests do not consume the sequence.
        let applied = match request.action {
            RecoveryOperation::Observe {} => Applied::Observed {
                state: self.state,
                result_revision: self.result_revision,
            },
            RecoveryOperation::CancelStop {} => self.cancel(),
            RecoveryOperation::AcknowledgeResult { revision } => self.acknowledge(revision)?,
        };
        self.last_sequence = request.sequence.get();
        Ok(applied)
    }

    fn cancel(&mut self) -> Applied {
        // RecoveryRequired is not over: the child may still run, so keep the intent.
        if self.state == OwnerState::Terminal {
            return Applied::CancelMoot;
        }
        self.cancel_pending = true;
        Applied::CancelPending
    }

    fn acknowledge(&mut self, revision: NonZeroU64) -> Result<Applied, LifecycleRefusal> {
        let ready = self
            .result_revision
            .ok_or(LifecycleRefusal::ResultNotReady)?;
        if revision != ready {
            return Err(LifecycleRefusal::ResultRevisionMismatch);
        }
        if self.acknowledged {
            return Ok(Applied::AlreadyAcknowledged);
        }
        self.acknowledged = true;
        Ok(Applied::Acknowledged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::hvf_control::HvfInstance;
    use crate::protocol::hvf_owner::{REQUEST_VERSION, RecoveryPhase};

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }

    fn binding(boot: u8) -> RecoveryBinding {
        RecoveryBinding {
            operation_id: [1; 32],
            request_digest: [2; 32],
            controlling_principal: [3; 32],
            tenant_id: "tenant-a".into(),
            owner_incarnation: [4; 32],
            phase: RecoveryPhase::Native {
                plan_digest: [5; 32],
                effective_config_digest: [7; 32],
                instance: HvfInstance {
                    vm_id: "vm-a".into(),
                    boot_nonce: [boot; 32],
                },
            },
        }
    }

    fn req(seq: u64, action: RecoveryOperation) -> UntrustedRecoveryRequest {
        UntrustedRecoveryRequest {
            version: REQUEST_VERSION,
            binding: binding(6),
            sequence: nz(seq),
            action,
        }
    }

    const FULL: TerminalProof = TerminalProof {
        completion_barrier: true,
        original_generation_finalized: true,
        cleanup_and_audit: true,
    };

    fn active() -> OwnerLifecycle {
        let mut life = OwnerLifecycle::register(binding(6));
        life.prepared().unwrap();
        life.activated().unwrap();
        life
    }

    #[test]
    fn a_stale_generation_or_identity_is_refused_and_consumes_nothing() {
        let mut life = active();
        let mut stale = req(1, RecoveryOperation::Observe {});
        stale.binding = binding(9);
        assert_eq!(life.apply(&stale), Err(LifecycleRefusal::BindingMismatch));
        let mut other_tenant = req(1, RecoveryOperation::Observe {});
        other_tenant.binding.tenant_id = "tenant-b".into();
        assert_eq!(
            life.apply(&other_tenant),
            Err(LifecycleRefusal::BindingMismatch)
        );
        assert!(life.apply(&req(1, RecoveryOperation::Observe {})).is_ok());
    }

    #[test]
    fn replayed_and_reordered_sequences_are_refused() {
        let mut life = active();
        life.apply(&req(5, RecoveryOperation::Observe {})).unwrap();
        for seq in [5, 4, 1] {
            assert_eq!(
                life.apply(&req(seq, RecoveryOperation::Observe {})),
                Err(LifecycleRefusal::StaleSequence)
            );
        }
        assert!(life.apply(&req(6, RecoveryOperation::Observe {})).is_ok());
    }

    #[test]
    fn repeated_cancellation_coalesces_and_never_completes() {
        let mut life = active();
        for seq in 1..=3 {
            assert_eq!(
                life.apply(&req(seq, RecoveryOperation::CancelStop {})),
                Ok(Applied::CancelPending)
            );
        }
        assert!(life.cancel_pending());
        assert_eq!(life.state(), OwnerState::Active);
    }

    #[test]
    fn disconnect_requests_cancellation_and_keeps_custody() {
        let mut life = active();
        life.frontend_disconnected();
        assert!(life.cancel_pending());
        assert_eq!(life.state(), OwnerState::Active);
        life.stop_started().unwrap();
        // A second disconnect while stopping changes nothing.
        life.frontend_disconnected();
        assert_eq!(life.state(), OwnerState::Stopping);
    }

    #[test]
    fn each_missing_half_of_the_terminal_proof_stays_recoverable() {
        for missing in 0..3 {
            let mut proof = FULL;
            match missing {
                0 => proof.completion_barrier = false,
                1 => proof.original_generation_finalized = false,
                _ => proof.cleanup_and_audit = false,
            }
            let mut life = active();
            life.stop_started().unwrap();
            life.finished(proof, nz(1)).unwrap();
            assert_eq!(life.state(), OwnerState::RecoveryRequired, "half {missing}");
            assert_eq!(
                life.apply(&req(
                    1,
                    RecoveryOperation::AcknowledgeResult { revision: nz(1) }
                )),
                Err(LifecycleRefusal::ResultNotReady)
            );
            // Unknown is never reset to prepared or active.
            assert_eq!(life.prepared(), Err(LifecycleRefusal::InvalidTransition));
            assert_eq!(life.activated(), Err(LifecycleRefusal::InvalidTransition));
        }
    }

    #[test]
    fn acknowledgement_is_exact_and_repeated_delivery_repeats_nothing() {
        let mut life = active();
        assert_eq!(
            life.apply(&req(
                1,
                RecoveryOperation::AcknowledgeResult { revision: nz(2) }
            )),
            Err(LifecycleRefusal::ResultNotReady)
        );
        life.finished(FULL, nz(2)).unwrap();
        assert_eq!(
            life.apply(&req(
                2,
                RecoveryOperation::AcknowledgeResult { revision: nz(1) }
            )),
            Err(LifecycleRefusal::ResultRevisionMismatch)
        );
        let ack = RecoveryOperation::AcknowledgeResult { revision: nz(2) };
        assert_eq!(life.apply(&req(3, ack)), Ok(Applied::Acknowledged));
        assert_eq!(life.apply(&req(4, ack)), Ok(Applied::AlreadyAcknowledged));
        assert_eq!(life.state(), OwnerState::Terminal);
        // Cancellation after the end is moot, not a second stop.
        assert_eq!(
            life.apply(&req(5, RecoveryOperation::CancelStop {})),
            Ok(Applied::CancelMoot)
        );
    }

    #[test]
    fn owner_death_quarantines_and_nothing_clears_it() {
        let mut life = active();
        life.owner_died();
        assert_eq!(life.state(), OwnerState::Quarantined);
        assert_eq!(
            life.apply(&req(1, RecoveryOperation::Observe {})),
            Err(LifecycleRefusal::Quarantined)
        );
        assert_eq!(
            life.finished(FULL, nz(1)),
            Err(LifecycleRefusal::Quarantined)
        );
        assert_eq!(life.prepared(), Err(LifecycleRefusal::Quarantined));
        assert_eq!(
            life.preparation_failed(true),
            Err(LifecycleRefusal::Quarantined)
        );
        assert_eq!(life.state(), OwnerState::Quarantined);
    }

    #[test]
    fn only_a_proven_child_free_preparation_failure_releases() {
        let mut free = OwnerLifecycle::register(binding(6));
        free.preparation_failed(true).unwrap();
        assert_eq!(free.state(), OwnerState::Terminal);
        let mut uncertain = OwnerLifecycle::register(binding(6));
        uncertain.prepared().unwrap();
        uncertain.preparation_failed(false).unwrap();
        assert_eq!(uncertain.state(), OwnerState::RecoveryRequired);
        // After activation a preparation failure is not a valid transition.
        let mut live = active();
        assert_eq!(
            live.preparation_failed(true),
            Err(LifecycleRefusal::InvalidTransition)
        );
        assert_eq!(live.state(), OwnerState::Active);
    }

    fn recovery_required() -> OwnerLifecycle {
        let mut life = OwnerLifecycle::register(binding(6));
        life.prepared().unwrap();
        life.preparation_failed(false).unwrap();
        life
    }

    #[test]
    fn cancel_and_disconnect_during_recovery_required_are_retained() {
        let mut life = recovery_required();
        assert_eq!(
            life.apply(&req(1, RecoveryOperation::CancelStop {})),
            Ok(Applied::CancelPending)
        );
        assert!(life.cancel_pending());
        let mut other = recovery_required();
        other.frontend_disconnected();
        assert!(other.cancel_pending());
        assert_eq!(other.state(), OwnerState::RecoveryRequired);
    }

    #[test]
    fn stop_is_attempted_at_most_once() {
        let mut fresh = recovery_required();
        fresh.stop_started().unwrap();
        assert_eq!(fresh.state(), OwnerState::Stopping);
        let mut life = active();
        life.stop_started().unwrap();
        life.finished(
            TerminalProof {
                cleanup_and_audit: false,
                ..FULL
            },
            nz(1),
        )
        .unwrap();
        assert_eq!(life.state(), OwnerState::RecoveryRequired);
        assert_eq!(
            life.stop_started(),
            Err(LifecycleRefusal::InvalidTransition)
        );
    }

    #[test]
    fn recovery_required_completes_only_with_all_three_halves() {
        let mut life = recovery_required();
        let partial = TerminalProof {
            completion_barrier: false,
            ..FULL
        };
        life.finished(partial, nz(1)).unwrap();
        assert_eq!(life.state(), OwnerState::RecoveryRequired);
        assert_eq!(
            life.apply(&req(
                1,
                RecoveryOperation::AcknowledgeResult { revision: nz(1) }
            )),
            Err(LifecycleRefusal::ResultNotReady)
        );
        life.finished(FULL, nz(1)).unwrap();
        assert_eq!(life.state(), OwnerState::Terminal);
        assert_eq!(
            life.apply(&req(
                1,
                RecoveryOperation::AcknowledgeResult { revision: nz(1) }
            )),
            Ok(Applied::Acknowledged)
        );
    }

    #[test]
    fn foreign_requests_in_recovery_required_consume_no_sequence() {
        let mut life = recovery_required();
        let mut foreign = req(1, RecoveryOperation::CancelStop {});
        foreign.binding = binding(9);
        assert_eq!(life.apply(&foreign), Err(LifecycleRefusal::BindingMismatch));
        assert!(!life.cancel_pending());
        assert!(
            life.apply(&req(1, RecoveryOperation::CancelStop {}))
                .is_ok()
        );
    }

    #[test]
    fn unsupported_transitions_refuse_without_moving() {
        let mut life = OwnerLifecycle::register(binding(6));
        assert_eq!(life.activated(), Err(LifecycleRefusal::InvalidTransition));
        assert_eq!(
            life.stop_started(),
            Err(LifecycleRefusal::InvalidTransition)
        );
        assert_eq!(
            life.finished(FULL, nz(1)),
            Err(LifecycleRefusal::InvalidTransition)
        );
        assert_eq!(life.state(), OwnerState::Registered);
    }
}
