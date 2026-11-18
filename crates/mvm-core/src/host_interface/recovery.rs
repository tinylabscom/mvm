//! Deterministic, in-memory offline recovery decisions. No I/O or epoch allocation.
//!
//! Evidence inputs are assertions by a future trusted lifecycle/history adapter,
//! not native proofs and not workload-controlled wire messages. There is no
//! production adapter. Actions require persistence, actual fencing and fresh
//! admission before execution; reconstructing a consumer from guessed history
//! is forbidden. One consumer owns one transition, with bounded constant state.

use super::{
    Denial, ExecutionEpoch,
    error::OfflineRefusal,
    lease::LeaseOp,
    offline::{ClockEvidence, DependencyLoss, VerifiedOfflineAuthority},
};

/// Exact original owner identity, supplied by the lifecycle owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    pub instance: [u8; 16],
    pub epoch: ExecutionEpoch,
}

/// Proven history input, not a persistence format or a defaultable ledger entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct History {
    pub authority_id: [u8; 32],
    pub workload_id: String,
    pub original: Owner,
    pub epoch_high_water: ExecutionEpoch,
    pub restarts_spent: u32,
    pub last_operation: u64,
}

/// Candidate allocation from the epoch owner, not an allocation by this reducer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartRequest {
    pub operation: u64,
    pub original: Owner,
    pub proposed_epoch: ExecutionEpoch,
    pub replacement_instance: [u8; 16],
}

/// Complete identity every persisted acknowledgement and ownership observation must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionBinding {
    pub authority_id: [u8; 32],
    pub workload_id: String,
    pub request: RestartRequest,
    pub restart_debit: u32,
    pub original_lease_expiry: u64,
}

/// Internal recovery phases, independent of primary node lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPhase {
    Running,
    Reserving,
    Reserved,
    Fencing,
    Fenced,
    Activating,
    Launching,
    Ready,
    Cancelled,
    Unknown,
    Blocked,
}

/// Trusted adapter inputs. Retirement covers the original VM and every effect holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryEvent {
    ReservationCommitted,
    BeginFence,
    Retired,
    Activate,
    ActivationCommitted,
    Ready,
    Cancel,
    Uncertain,
}

/// At most one obligation, never an authorization or proof of completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    None,
    /// Atomically reserve the supplied epoch and debit before side effects.
    Reserve,
    /// Fence exact original owner and all effect holders, retaining custody.
    FenceOriginal,
    /// Persist activation only after recorded retirement; not VM dispatch.
    ActivateReserved,
    /// Fresh normal admission and at most one dispatch; failure cannot blind-retry.
    AdmitAndLaunch,
    /// Retain pending/committed reservation and any in-progress cleanup obligations.
    RetainReservation,
    /// Reconcile exact owners; uncertainty never refunds or authorizes dispatch.
    Reconcile,
    /// Close effects and stop/reconcile exact owners, preserving resource charges.
    CloseAndReconcile,
}

/// One bounded decision, with the binding needed to interpret its obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct RecoveryDecision {
    /// Cleanup remains scope-bound even before there is a recovery transition.
    pub authority_id: [u8; 32],
    pub workload_id: String,
    pub original: Owner,
    /// Original monotonic deadline; no operation may reset it.
    pub deadline: u64,
    pub phase: RecoveryPhase,
    pub action: RecoveryAction,
    pub binding: Option<TransitionBinding>,
    pub refusal: Option<Denial>,
}

/// Single-transition consumer. Not clonable, serializable or crash-restorable.
#[derive(Debug)]
pub struct Recovery {
    authority: VerifiedOfflineAuthority,
    history: History,
    binding: Option<TransitionBinding>,
    phase: RecoveryPhase,
    last_event: Option<RecoveryEvent>,
    last_clock: ClockEvidence,
    refusal: Option<Denial>,
}

impl Recovery {
    /// Bind verified authority to existing, explicitly supplied workload history.
    ///
    /// # Errors
    /// Missing or inconsistent history refuses, never selecting local mode.
    pub fn new(
        authority: VerifiedOfflineAuthority,
        history: Option<History>,
    ) -> Result<Self, Denial> {
        let history = history.ok_or(OfflineRefusal::HistoryMissing)?;
        if history.authority_id != authority.id()
            || history.workload_id != authority.policy().workload_id
            || history.original.instance == [0; 16]
            || history.original.epoch.0 == 0
            || history.original.epoch > history.epoch_high_water
            || history.restarts_spent > authority.policy().restart.limit()
        {
            return Err(OfflineRefusal::HistoryInvalid.into());
        }
        let last_clock = authority.clock();
        Ok(Self {
            authority,
            history,
            binding: None,
            phase: RecoveryPhase::Running,
            last_event: None,
            last_clock,
            refusal: None,
        })
    }

    /// Request one reservation; repeated identical input never emits another action.
    ///
    /// # Errors
    /// Refuses conflicting/stale identity, exhausted allowance or invalid allocation.
    /// Time failure instead returns a blocked decision carrying safety obligations.
    pub fn request(
        &mut self,
        request: RestartRequest,
        now: ClockEvidence,
    ) -> Result<RecoveryDecision, Denial> {
        if let Some(blocked) = self.check_time(now) {
            return Ok(blocked);
        }
        if let Some(binding) = &self.binding {
            return if request == binding.request {
                Ok(self.decision(RecoveryAction::None))
            } else {
                Err(OfflineRefusal::TransitionConflict.into())
            };
        }
        if self.phase != RecoveryPhase::Running {
            return Err(OfflineRefusal::TransitionOrder.into());
        }
        self.authority.permits(LeaseOp::LocalLaunch, now)?;
        if request.original != self.history.original
            || request.replacement_instance == [0; 16]
            || request.replacement_instance == request.original.instance
        {
            return Err(OfflineRefusal::TransitionConflict.into());
        }
        if request.operation <= self.history.last_operation {
            return Err(Denial::ReplayedCommand {
                got: request.operation,
                last: self.history.last_operation,
            });
        }
        if request.proposed_epoch <= self.history.epoch_high_water {
            return Err(OfflineRefusal::EpochAllocation.into());
        }
        self.authority
            .policy()
            .restart
            .check_epoch(request.proposed_epoch)?;
        let debit = self
            .history
            .restarts_spent
            .checked_add(1)
            .ok_or(OfflineRefusal::RestartExhausted)?;
        if debit > self.authority.policy().restart.limit() {
            return Err(OfflineRefusal::RestartExhausted.into());
        }
        self.binding = Some(TransitionBinding {
            authority_id: self.authority.id(),
            workload_id: self.history.workload_id.clone(),
            request,
            restart_debit: debit,
            original_lease_expiry: self.authority.lease_expiry(),
        });
        self.phase = RecoveryPhase::Reserving;
        Ok(self.decision(RecoveryAction::Reserve))
    }

    /// Consume an exact-bound observation, preserving ordering and cleanup obligations.
    ///
    /// # Errors
    /// Refuses stale bindings, invalid ordering and progress after a terminal outcome.
    /// Duplicate acknowledgements return status without repeating side effects.
    pub fn observe(
        &mut self,
        binding: &TransitionBinding,
        event: RecoveryEvent,
        now: ClockEvidence,
    ) -> Result<RecoveryDecision, Denial> {
        if let Some(blocked) = self.check_time(now) {
            return Ok(blocked);
        }
        if self.binding.as_ref() != Some(binding) {
            return Err(OfflineRefusal::TransitionConflict.into());
        }
        if self.last_event == Some(event) {
            return Ok(self.decision(RecoveryAction::None));
        }
        if matches!(
            self.phase,
            RecoveryPhase::Blocked | RecoveryPhase::Cancelled | RecoveryPhase::Unknown
        ) {
            return Err(OfflineRefusal::TransitionOrder.into());
        }
        let (expected, next, action) = match event {
            RecoveryEvent::ReservationCommitted => (
                RecoveryPhase::Reserving,
                RecoveryPhase::Reserved,
                RecoveryAction::None,
            ),
            RecoveryEvent::BeginFence => (
                RecoveryPhase::Reserved,
                RecoveryPhase::Fencing,
                RecoveryAction::FenceOriginal,
            ),
            RecoveryEvent::Retired => (
                RecoveryPhase::Fencing,
                RecoveryPhase::Fenced,
                RecoveryAction::None,
            ),
            RecoveryEvent::Activate => (
                RecoveryPhase::Fenced,
                RecoveryPhase::Activating,
                RecoveryAction::ActivateReserved,
            ),
            RecoveryEvent::ActivationCommitted => {
                self.authority.permits(LeaseOp::LocalLaunch, now)?;
                (
                    RecoveryPhase::Activating,
                    RecoveryPhase::Launching,
                    RecoveryAction::AdmitAndLaunch,
                )
            }
            RecoveryEvent::Ready => (
                RecoveryPhase::Launching,
                RecoveryPhase::Ready,
                RecoveryAction::None,
            ),
            RecoveryEvent::Cancel => {
                self.refusal = Some(OfflineRefusal::Cancelled.into());
                if matches!(self.phase, RecoveryPhase::Launching | RecoveryPhase::Ready) {
                    (
                        self.phase,
                        RecoveryPhase::Unknown,
                        RecoveryAction::Reconcile,
                    )
                } else {
                    (
                        self.phase,
                        RecoveryPhase::Cancelled,
                        RecoveryAction::RetainReservation,
                    )
                }
            }
            RecoveryEvent::Uncertain => {
                self.refusal = Some(OfflineRefusal::OwnershipUnknown.into());
                (
                    self.phase,
                    RecoveryPhase::Unknown,
                    RecoveryAction::Reconcile,
                )
            }
        };
        if self.phase != expected {
            return Err(OfflineRefusal::TransitionOrder.into());
        }
        self.phase = next;
        self.last_event = Some(event);
        Ok(self.decision(action))
    }

    /// Link observations never supply retirement evidence or spend restart budget.
    pub fn dependency_lost(&mut self, now: ClockEvidence) -> RecoveryDecision {
        if let Some(blocked) = self.check_time(now) {
            return blocked;
        }
        match self.authority.policy().dependency_loss {
            DependencyLoss::ContinueAuthorized => self.decision(RecoveryAction::None),
            DependencyLoss::Stop => self.invalidate(OfflineRefusal::DependencyLost.into()),
        }
    }

    /// Authority/enforcement loss is irreversible and cannot suppress safety cleanup.
    pub fn invalidate(&mut self, refusal: Denial) -> RecoveryDecision {
        self.phase = RecoveryPhase::Blocked;
        self.last_event = None;
        self.refusal = Some(refusal);
        self.decision(RecoveryAction::CloseAndReconcile)
    }

    /// Current recorded phase, not a claim that native effects occurred.
    pub fn phase(&self) -> RecoveryPhase {
        self.phase
    }
    /// Retained identity and debit, including after cancellation or uncertainty.
    pub fn binding(&self) -> Option<&TransitionBinding> {
        self.binding.as_ref()
    }

    fn check_time(&mut self, now: ClockEvidence) -> Option<RecoveryDecision> {
        let valid = now
            .follows(self.last_clock)
            .and_then(|()| self.authority.check_time(now));
        if let Err(reason) = valid {
            return Some(self.invalidate(reason));
        }
        self.last_clock = now;
        None
    }

    fn decision(&self, action: RecoveryAction) -> RecoveryDecision {
        RecoveryDecision {
            authority_id: self.authority.id(),
            workload_id: self.history.workload_id.clone(),
            original: self.history.original,
            deadline: self.authority.deadline(),
            phase: self.phase,
            action,
            binding: self.binding.clone(),
            refusal: self.refusal.clone(),
        }
    }
}
