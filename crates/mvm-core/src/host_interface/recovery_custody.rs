//! Durable custody for the pure offline recovery reducer.
//!
//! This module serializes the existing per-workload ledger. It does not allocate
//! epochs, authenticate lifecycle observations, launch a VM, or clear quarantine.

use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    Denial, ExecutionEpoch,
    error::OfflineRefusal,
    offline::{ClockEvidence, VerifiedOfflineAuthority},
    recovery::{
        History, Owner, Recovery, RecoveryAction, RecoveryEvent, RecoveryPhase, RestartRequest,
        TransitionBinding,
    },
    workload::WorkloadLedger,
};

const DIRECTORY: &str = "host-interface";
const LEDGER: &str = "workloads.json";
const LOCK: &str = "workloads.lock";

#[cfg(test)]
thread_local! {
    static FAIL_PARENT_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static PARENT_SYNCS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Explicit finite storage limits supplied by host/organization policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryStoreLimits {
    max_workloads: usize,
    max_bytes: usize,
}

impl RecoveryStoreLimits {
    /// Construct nonzero limits; this type has no deployment defaults.
    ///
    /// # Errors
    /// Refuses zero limits.
    pub fn new(max_workloads: usize, max_bytes: usize) -> Result<Self, RecoveryCustodyError> {
        if max_workloads == 0 || max_bytes == 0 {
            return Err(RecoveryCustodyError::Limit);
        }
        Ok(Self {
            max_workloads,
            max_bytes,
        })
    }
}

/// Persisted authority time that prevents restart or clock correction extending a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PersistedRecoveryTime {
    effective_expiry: u64,
    monotonic_deadline: u64,
    accepted_clock: ClockEvidence,
}

/// One retained current or most-recent completed transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredRecoveryTransition {
    pub binding: TransitionBinding,
    pub phase: RecoveryPhase,
    pub activation_committed: bool,
}

/// Managed security history embedded in one existing workload-ledger entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagedRecoveryHistory {
    history: History,
    time: PersistedRecoveryTime,
    #[serde(default)]
    blocked: bool,
    current: Option<StoredRecoveryTransition>,
    completed: Option<StoredRecoveryTransition>,
}

/// Event whose durable recording precedes the corresponding external action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyEvent {
    BeginFence,
    Retired,
    Activate,
    ActivationCommitted,
    Ready,
    Cancel,
    Uncertain,
    Block,
}

/// What a failed publication was trying to commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitIntent {
    Establish,
    Ordinary,
    Transition { operation: u64, step: CommitStep },
}

/// Requested durable step named in an uncertain commit error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitStep {
    Reserve,
    Event(CustodyEvent),
}

/// Durable status. `action` is non-`None` only for the successful first commit
/// into a phase that requires a future owner action.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct RecoveryCustodyStatus {
    pub active_epoch: ExecutionEpoch,
    pub quarantined: bool,
    pub blocked: bool,
    pub history: History,
    pub current: Option<StoredRecoveryTransition>,
    pub completed: Option<StoredRecoveryTransition>,
    pub action: RecoveryAction,
}

/// Storage and transition failures with publication uncertainty kept explicit.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RecoveryCustodyError {
    #[error(transparent)]
    Denied(#[from] Denial),
    #[error("managed recovery history is missing")]
    HistoryMissing,
    #[error("recovery state conflicts with retained history")]
    Conflict,
    #[error("recovery storage limit exceeded")]
    Limit,
    #[error("protected recovery state is unavailable")]
    State(#[source] io::Error),
    #[error("recovery commit outcome is unknown")]
    CommitUnknown {
        authority_id: [u8; 32],
        workload_id: String,
        intent: CommitIntent,
        #[source]
        source: io::Error,
    },
}

type Commit = dyn Fn(&Path, &[u8]) -> io::Result<()> + Send + Sync;

/// One bounded handle to the existing per-workload ledger.
#[derive(Clone)]
pub struct RecoveryCustody {
    home: PathBuf,
    limits: RecoveryStoreLimits,
    commit: Arc<Commit>,
}

impl std::fmt::Debug for RecoveryCustody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryCustody")
            .field("home", &self.home)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl RecoveryCustody {
    /// Address the existing workload ledger with explicit finite limits.
    pub fn at(home: impl AsRef<Path>, limits: RecoveryStoreLimits) -> Self {
        Self {
            home: home.as_ref().to_owned(),
            limits,
            commit: Arc::new(crate::atomic_io::write_private),
        }
    }

    /// Persist independently trusted initial history under verified authority.
    ///
    /// This is explicit bootstrap/migration, never missing-history recovery.
    ///
    /// # Errors
    /// Refuses mismatched active state, changed existing history, bad authority,
    /// limits, protected-storage failures, or uncertain publication.
    pub fn establish(
        &self,
        authority: VerifiedOfflineAuthority,
        history: History,
    ) -> Result<RecoveryCustodyStatus, RecoveryCustodyError> {
        let authority_id = authority.id();
        let workload = authority.workload_id().to_owned();
        let time = PersistedRecoveryTime {
            effective_expiry: authority.expiry(),
            monotonic_deadline: authority.deadline(),
            accepted_clock: authority.clock(),
        };
        Recovery::new(authority, Some(history.clone()))?;
        self.mutate(
            authority_id,
            &workload.clone(),
            CommitIntent::Establish,
            move |ledger| {
                let entry = ledger
                    .entries_mut()
                    .get_mut(&workload)
                    .ok_or(RecoveryCustodyError::HistoryMissing)?;
                if entry.epoch != history.original.epoch {
                    return Err(RecoveryCustodyError::Conflict);
                }
                let expected = ManagedRecoveryHistory {
                    history,
                    time,
                    blocked: false,
                    current: None,
                    completed: None,
                };
                if let Some(existing) = &entry.recovery {
                    if existing.history == expected.history
                        && existing.time.effective_expiry == expected.time.effective_expiry
                        && existing.time.monotonic_deadline == expected.time.monotonic_deadline
                    {
                        return Ok((status(entry, RecoveryAction::None)?, false));
                    }
                    return Err(RecoveryCustodyError::Conflict);
                }
                entry.recovery = Some(expected);
                Ok((status(entry, RecoveryAction::None)?, true))
            },
        )
    }

    /// Atomically reserve the externally supplied epoch and debit before effects.
    ///
    /// # Errors
    /// Refuses missing/changed history, stale or conflicting operations, bounds,
    /// clock/authority failures, or uncertain publication.
    pub fn reserve(
        &self,
        authority: VerifiedOfflineAuthority,
        request: RestartRequest,
        now: ClockEvidence,
    ) -> Result<RecoveryCustodyStatus, RecoveryCustodyError> {
        let authority_id = authority.id();
        let workload = authority.workload_id().to_owned();
        let operation = request.operation;
        self.mutate(
            authority_id,
            &workload.clone(),
            CommitIntent::Transition {
                operation,
                step: CommitStep::Reserve,
            },
            move |ledger| {
                let entry = managed_entry_mut(ledger, &workload, authority_id)?;
                let time = entry
                    .recovery
                    .as_ref()
                    .ok_or(RecoveryCustodyError::HistoryMissing)?
                    .time;
                let authority = match constrain_authority_for(authority, &time, now) {
                    Ok(authority) => authority,
                    Err(reason) if is_time_refusal(&reason) => {
                        block_entry(entry)?;
                        return Ok((status(entry, RecoveryAction::CloseAndReconcile)?, true));
                    }
                    Err(reason) => return Err(reason.into()),
                };
                let deadline = authority.deadline();
                let managed = entry
                    .recovery
                    .as_mut()
                    .ok_or(RecoveryCustodyError::HistoryMissing)?;
                managed.time.monotonic_deadline = deadline;
                managed.time.accepted_clock = now;
                if managed.blocked {
                    return Ok((status(entry, RecoveryAction::CloseAndReconcile)?, true));
                }
                if let Some(completed) = &managed.completed {
                    if completed.binding.request == request {
                        return Ok((status(entry, RecoveryAction::None)?, true));
                    }
                    if completed.binding.request.operation == operation {
                        return Err(RecoveryCustodyError::Conflict);
                    }
                }
                if let Some(current) = &managed.current {
                    if current.binding.request == request {
                        return Ok((status(entry, RecoveryAction::None)?, true));
                    }
                    if request.operation == current.binding.request.operation {
                        return Err(RecoveryCustodyError::Conflict);
                    }
                    if request.operation <= managed.history.last_operation {
                        return Err(Denial::ReplayedCommand {
                            got: request.operation,
                            last: managed.history.last_operation,
                        }
                        .into());
                    }
                    return Err(RecoveryCustodyError::Conflict);
                }
                if request.operation <= managed.history.last_operation {
                    return Err(Denial::ReplayedCommand {
                        got: request.operation,
                        last: managed.history.last_operation,
                    }
                    .into());
                }
                let mut recovery = Recovery::new(authority, Some(managed.history.clone()))?;
                let decision = recovery.request(request, now)?;
                let binding = decision.binding.ok_or_else(|| {
                    RecoveryCustodyError::Denied(OfflineRefusal::HistoryInvalid.into())
                })?;
                if decision.phase != RecoveryPhase::Reserving {
                    return Err(RecoveryCustodyError::Denied(
                        OfflineRefusal::TransitionOrder.into(),
                    ));
                }
                managed.history.epoch_high_water = binding.request.proposed_epoch;
                managed.history.restarts_spent = binding.restart_debit;
                managed.history.last_operation = binding.request.operation;
                managed.current = Some(StoredRecoveryTransition {
                    binding,
                    phase: RecoveryPhase::Reserved,
                    activation_committed: false,
                });
                Ok((status(entry, RecoveryAction::None)?, true))
            },
        )
    }

    /// Durably advance one exact-bound transition.
    ///
    /// The first successful `ActivationCommitted` returns `AdmitAndLaunch`.
    /// Duplicates and every restored state return status without that action.
    ///
    /// # Errors
    /// Refuses changed/stale bindings, invalid ordering, bad time/authority,
    /// limits, protected-storage failures, or uncertain publication.
    pub fn record(
        &self,
        authority: VerifiedOfflineAuthority,
        binding: &TransitionBinding,
        event: CustodyEvent,
        now: ClockEvidence,
    ) -> Result<RecoveryCustodyStatus, RecoveryCustodyError> {
        let authority_id = authority.id();
        let workload = authority.workload_id().to_owned();
        let binding = binding.clone();
        self.mutate(
            authority_id,
            &workload.clone(),
            CommitIntent::Transition {
                operation: binding.request.operation,
                step: CommitStep::Event(event),
            },
            move |ledger| {
                let entry = managed_entry_mut(ledger, &workload, authority_id)?;
                let time = entry
                    .recovery
                    .as_ref()
                    .ok_or(RecoveryCustodyError::HistoryMissing)?
                    .time;
                let authority = match constrain_authority_for(authority, &time, now) {
                    Ok(authority) => authority,
                    Err(reason) if is_time_refusal(&reason) => {
                        block_entry(entry)?;
                        return Ok((status(entry, RecoveryAction::CloseAndReconcile)?, true));
                    }
                    Err(reason) => return Err(reason.into()),
                };
                let deadline = authority.deadline();
                let (history, stored) = {
                    let managed = entry
                        .recovery
                        .as_mut()
                        .ok_or(RecoveryCustodyError::HistoryMissing)?;
                    managed.time.monotonic_deadline = deadline;
                    managed.time.accepted_clock = now;
                    if managed.blocked {
                        return Ok((status(entry, RecoveryAction::CloseAndReconcile)?, true));
                    }
                    if let Some(completed) = &managed.completed {
                        if completed.binding == binding {
                            if event == CustodyEvent::Ready {
                                return Ok((status(entry, RecoveryAction::None)?, true));
                            }
                            return Err(RecoveryCustodyError::Denied(
                                OfflineRefusal::TransitionOrder.into(),
                            ));
                        }
                        if completed.binding.request.operation == binding.request.operation {
                            return Err(RecoveryCustodyError::Conflict);
                        }
                    }
                    (
                        managed.history.clone(),
                        managed
                            .current
                            .clone()
                            .ok_or(RecoveryCustodyError::Conflict)?,
                    )
                };
                if stored.binding != binding {
                    if binding.request.operation <= history.last_operation {
                        return Err(Denial::ReplayedCommand {
                            got: binding.request.operation,
                            last: history.last_operation,
                        }
                        .into());
                    }
                    return Err(RecoveryCustodyError::Conflict);
                }
                let mut recovery =
                    Recovery::restore(authority, history, binding.clone(), stored.phase)?;
                let decision = match event {
                    CustodyEvent::BeginFence => {
                        recovery.observe(&binding, RecoveryEvent::BeginFence, now)?
                    }
                    CustodyEvent::Retired => {
                        recovery.observe(&binding, RecoveryEvent::Retired, now)?
                    }
                    CustodyEvent::Activate => {
                        recovery.observe(&binding, RecoveryEvent::Activate, now)?
                    }
                    CustodyEvent::ActivationCommitted => {
                        recovery.observe(&binding, RecoveryEvent::ActivationCommitted, now)?
                    }
                    CustodyEvent::Ready => recovery.observe(&binding, RecoveryEvent::Ready, now)?,
                    CustodyEvent::Cancel => {
                        recovery.observe(&binding, RecoveryEvent::Cancel, now)?
                    }
                    CustodyEvent::Uncertain => {
                        recovery.observe(&binding, RecoveryEvent::Uncertain, now)?
                    }
                    CustodyEvent::Block => {
                        recovery.invalidate(OfflineRefusal::DependencyLost.into())
                    }
                };
                if decision.phase == stored.phase && decision.action == RecoveryAction::None {
                    return Ok((status(entry, RecoveryAction::None)?, true));
                }
                let activation_committed =
                    stored.activation_committed || decision.phase == RecoveryPhase::Launching;
                if decision.phase == RecoveryPhase::Launching {
                    entry.epoch = binding.request.proposed_epoch;
                }
                let managed = entry
                    .recovery
                    .as_mut()
                    .ok_or(RecoveryCustodyError::HistoryMissing)?;
                managed.blocked = decision.phase == RecoveryPhase::Blocked;
                managed.current = Some(StoredRecoveryTransition {
                    binding: binding.clone(),
                    phase: decision.phase,
                    activation_committed,
                });
                if decision.phase == RecoveryPhase::Ready {
                    managed.history.original = Owner {
                        instance: binding.request.replacement_instance,
                        epoch: binding.request.proposed_epoch,
                    };
                    managed.completed = managed.current.take();
                }
                Ok((status(entry, decision.action)?, true))
            },
        )
    }

    /// Read exact cleanup custody without authorizing progress.
    ///
    /// # Errors
    /// Refuses missing, corrupt, mismatched, oversized or unprotected state.
    pub fn status(
        &self,
        authority_id: [u8; 32],
        workload: &str,
    ) -> Result<RecoveryCustodyStatus, RecoveryCustodyError> {
        let (_lock, ledger) = self.locked_load()?;
        let entry = managed_entry(&ledger, workload, authority_id)?;
        status(entry, RecoveryAction::None)
    }

    /// Re-establish a definite synchronized state after `CommitUnknown`.
    ///
    /// This republishes the complete state found under the lock; it never
    /// assumes whether the failed publication committed.
    ///
    /// # Errors
    /// Refuses mismatched authority/time/history or another uncertain commit.
    pub fn reconcile(
        &self,
        authority: VerifiedOfflineAuthority,
    ) -> Result<RecoveryCustodyStatus, RecoveryCustodyError> {
        let authority_id = authority.id();
        let workload = authority.workload_id().to_owned();
        self.mutate(
            authority_id,
            &workload.clone(),
            CommitIntent::Ordinary,
            move |ledger| {
                let entry = managed_entry_mut(ledger, &workload, authority_id)?;
                let managed = entry
                    .recovery
                    .as_mut()
                    .ok_or(RecoveryCustodyError::HistoryMissing)?;
                let authority = constrain_authority(authority, &managed.time)?;
                managed.time.monotonic_deadline = authority.deadline();
                managed.time.accepted_clock = authority.clock();
                Ok((status(entry, RecoveryAction::None)?, true))
            },
        )
    }

    /// Restore reducer state without emitting an external action.
    ///
    /// A persisted `Launching` phase is first durably changed to `Unknown`
    /// because dispatch may have occurred.
    ///
    /// # Errors
    /// Refuses mismatched authority/time/history or uncertain publication.
    pub fn resume(
        &self,
        authority: VerifiedOfflineAuthority,
    ) -> Result<Recovery, RecoveryCustodyError> {
        let authority_id = authority.id();
        let workload = authority.workload_id().to_owned();
        let mut restored = None;
        let mut blocked = None;
        let _ = self.mutate(authority_id, &workload, CommitIntent::Ordinary, |ledger| {
            let entry = managed_entry_mut(ledger, &workload, authority_id)?;
            let managed = entry
                .recovery
                .as_mut()
                .ok_or(RecoveryCustodyError::HistoryMissing)?;
            if managed.blocked {
                return Err(RecoveryCustodyError::Denied(
                    OfflineRefusal::DependencyLost.into(),
                ));
            }
            let authority = match constrain_authority(authority, &managed.time) {
                Ok(authority) => authority,
                Err(reason) if is_time_refusal(&reason) => {
                    managed.blocked = true;
                    if let Some(current) = managed.current.as_mut() {
                        current.phase = RecoveryPhase::Blocked;
                    }
                    blocked = Some(reason);
                    return Ok((status(entry, RecoveryAction::CloseAndReconcile)?, true));
                }
                Err(reason) => return Err(reason.into()),
            };
            managed.time.monotonic_deadline = authority.deadline();
            managed.time.accepted_clock = authority.clock();
            let Some(current) = managed.current.as_mut() else {
                restored = Some(Recovery::new(authority, Some(managed.history.clone()))?);
                return Ok((status(entry, RecoveryAction::None)?, true));
            };
            let changed = current.phase == RecoveryPhase::Launching;
            if changed {
                current.phase = RecoveryPhase::Unknown;
            }
            restored = Some(Recovery::restore(
                authority,
                managed.history.clone(),
                current.binding.clone(),
                current.phase,
            )?);
            Ok((status(entry, RecoveryAction::None)?, true))
        })?;
        if let Some(reason) = blocked {
            return Err(reason.into());
        }
        restored.ok_or_else(|| RecoveryCustodyError::Denied(OfflineRefusal::HistoryInvalid.into()))
    }

    #[cfg(test)]
    pub(super) fn with_commit_for_test(
        &self,
        commit: impl Fn(&Path, &[u8]) -> io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self {
            home: self.home.clone(),
            limits: self.limits,
            commit: Arc::new(commit),
        }
    }

    fn locked_load(
        &self,
    ) -> Result<(crate::atomic_io::FileLock, WorkloadLedger), RecoveryCustodyError> {
        let lock = acquire_lock(&self.home)?;
        let ledger = load_protected(&self.home, self.limits)?;
        validate_ledger(&ledger)?;
        Ok((lock, ledger))
    }

    fn mutate<T>(
        &self,
        authority_id: [u8; 32],
        workload: &str,
        intent: CommitIntent,
        change: impl FnOnce(&mut WorkloadLedger) -> Result<(T, bool), RecoveryCustodyError>,
    ) -> Result<T, RecoveryCustodyError> {
        let (_lock, mut ledger) = self.locked_load()?;
        let (value, changed) = change(&mut ledger)?;
        if !changed {
            return Ok(value);
        }
        validate_ledger(&ledger)?;
        let bytes = serialize_bounded(&ledger, self.limits)?;
        let path = ledger_path(&self.home);
        (self.commit)(&path, &bytes).map_err(|source| RecoveryCustodyError::CommitUnknown {
            authority_id,
            workload_id: workload.to_owned(),
            intent,
            source,
        })?;
        Ok(value)
    }
}

fn constrain_authority(
    authority: VerifiedOfflineAuthority,
    time: &PersistedRecoveryTime,
) -> Result<VerifiedOfflineAuthority, Denial> {
    authority.constrain_restored_time(
        time.effective_expiry,
        time.monotonic_deadline,
        time.accepted_clock,
    )
}

fn constrain_authority_for(
    authority: VerifiedOfflineAuthority,
    time: &PersistedRecoveryTime,
    now: ClockEvidence,
) -> Result<VerifiedOfflineAuthority, Denial> {
    let authority = constrain_authority(authority, time)?;
    authority.check_time(now)?;
    Ok(authority)
}

fn is_time_refusal(denial: &Denial) -> bool {
    matches!(
        denial,
        Denial::LeaseExpired
            | Denial::Offline(OfflineRefusal::ClockUncertain | OfflineRefusal::ClockRegression)
    )
}

fn block_entry(entry: &mut super::workload::WorkloadEntry) -> Result<(), RecoveryCustodyError> {
    let managed = entry
        .recovery
        .as_mut()
        .ok_or(RecoveryCustodyError::HistoryMissing)?;
    managed.blocked = true;
    if let Some(current) = managed.current.as_mut() {
        current.phase = RecoveryPhase::Blocked;
    }
    Ok(())
}

fn status(
    entry: &super::workload::WorkloadEntry,
    action: RecoveryAction,
) -> Result<RecoveryCustodyStatus, RecoveryCustodyError> {
    let managed = entry
        .recovery
        .as_ref()
        .ok_or(RecoveryCustodyError::HistoryMissing)?;
    Ok(RecoveryCustodyStatus {
        active_epoch: entry.epoch,
        quarantined: entry.quarantined,
        blocked: managed.blocked,
        history: managed.history.clone(),
        current: managed.current.clone(),
        completed: managed.completed.clone(),
        action,
    })
}

fn managed_entry<'a>(
    ledger: &'a WorkloadLedger,
    workload: &str,
    authority_id: [u8; 32],
) -> Result<&'a super::workload::WorkloadEntry, RecoveryCustodyError> {
    let entry = ledger
        .entries()
        .get(workload)
        .ok_or(RecoveryCustodyError::HistoryMissing)?;
    let managed = entry
        .recovery
        .as_ref()
        .ok_or(RecoveryCustodyError::HistoryMissing)?;
    if managed.history.authority_id != authority_id || managed.history.workload_id != workload {
        return Err(RecoveryCustodyError::Conflict);
    }
    Ok(entry)
}

fn managed_entry_mut<'a>(
    ledger: &'a mut WorkloadLedger,
    workload: &str,
    authority_id: [u8; 32],
) -> Result<&'a mut super::workload::WorkloadEntry, RecoveryCustodyError> {
    let entry = ledger
        .entries_mut()
        .get_mut(workload)
        .ok_or(RecoveryCustodyError::HistoryMissing)?;
    let managed = entry
        .recovery
        .as_ref()
        .ok_or(RecoveryCustodyError::HistoryMissing)?;
    if managed.history.authority_id != authority_id || managed.history.workload_id != workload {
        return Err(RecoveryCustodyError::Conflict);
    }
    Ok(entry)
}

fn validate_ledger(ledger: &WorkloadLedger) -> Result<(), RecoveryCustodyError> {
    for (workload, entry) in ledger.entries() {
        if entry.epoch.0 == 0 {
            return Err(RecoveryCustodyError::State(io::Error::new(
                io::ErrorKind::InvalidData,
                "workload epoch is zero",
            )));
        }
        let Some(managed) = &entry.recovery else {
            continue;
        };
        if managed.history.workload_id != *workload
            || managed.history.authority_id == [0; 32]
            || managed.history.original.instance == [0; 16]
            || managed.history.original.epoch.0 == 0
            || managed.history.original.epoch > managed.history.epoch_high_water
            || managed.time.effective_expiry == 0
            || managed.time.monotonic_deadline == 0
        {
            return Err(invalid_state("managed recovery history is inconsistent"));
        }
        if let Some(current) = &managed.current {
            validate_transition(entry.epoch, &managed.history, current)?;
        } else if entry.epoch != managed.history.original.epoch {
            return Err(invalid_state(
                "active epoch disagrees with managed owner history",
            ));
        }
        if let Some(completed) = &managed.completed {
            if completed.phase != RecoveryPhase::Ready || !completed.activation_committed {
                return Err(invalid_state("completed recovery transition is not ready"));
            }
            if completed.binding.authority_id != managed.history.authority_id
                || completed.binding.workload_id != *workload
                || completed.binding.request.replacement_instance
                    != managed.history.original.instance
                || completed.binding.request.proposed_epoch != managed.history.original.epoch
            {
                return Err(invalid_state("completed recovery binding is inconsistent"));
            }
            if let Some(current) = &managed.current {
                if completed.binding.request.operation >= managed.history.last_operation
                    || completed.binding.request.operation >= current.binding.request.operation
                    || completed.binding.restart_debit >= managed.history.restarts_spent
                    || completed.binding.request.proposed_epoch
                        != current.binding.request.original.epoch
                {
                    return Err(invalid_state(
                        "completed recovery binding is not the current predecessor",
                    ));
                }
            } else if completed.binding.request.operation != managed.history.last_operation
                || completed.binding.request.proposed_epoch != managed.history.epoch_high_water
                || completed.binding.restart_debit != managed.history.restarts_spent
                || completed.binding.request.proposed_epoch != entry.epoch
            {
                return Err(invalid_state(
                    "completed recovery binding disagrees with current history",
                ));
            }
        }
        if let (Some(current), Some(completed)) = (&managed.current, &managed.completed)
            && current.binding.request.operation <= completed.binding.request.operation
        {
            return Err(invalid_state("current recovery operation is not fresh"));
        }
    }
    Ok(())
}

fn validate_transition(
    active_epoch: ExecutionEpoch,
    history: &History,
    transition: &StoredRecoveryTransition,
) -> Result<(), RecoveryCustodyError> {
    let binding = &transition.binding;
    if binding.authority_id != history.authority_id
        || binding.workload_id != history.workload_id
        || binding.request.original != history.original
        || binding.request.operation != history.last_operation
        || binding.request.proposed_epoch != history.epoch_high_water
        || binding.restart_debit != history.restarts_spent
        || binding.request.replacement_instance == [0; 16]
    {
        return Err(invalid_state("current recovery binding is inconsistent"));
    }
    let expected_epoch = if transition.activation_committed {
        binding.request.proposed_epoch
    } else {
        binding.request.original.epoch
    };
    if active_epoch != expected_epoch {
        return Err(invalid_state(
            "active epoch disagrees with transition phase",
        ));
    }
    let phase_requires_activation = transition.phase == RecoveryPhase::Launching;
    if phase_requires_activation != transition.activation_committed
        && !matches!(
            transition.phase,
            RecoveryPhase::Cancelled | RecoveryPhase::Unknown | RecoveryPhase::Blocked
        )
    {
        return Err(invalid_state(
            "activation flag disagrees with transition phase",
        ));
    }
    if matches!(
        transition.phase,
        RecoveryPhase::Running | RecoveryPhase::Reserving | RecoveryPhase::Ready
    ) {
        return Err(invalid_state("invalid current recovery phase"));
    }
    Ok(())
}

fn invalid_state(message: &'static str) -> RecoveryCustodyError {
    RecoveryCustodyError::State(io::Error::new(io::ErrorKind::InvalidData, message))
}

fn store_dir(home: &Path) -> PathBuf {
    home.join(DIRECTORY)
}

fn ledger_path(home: &Path) -> PathBuf {
    store_dir(home).join(LEDGER)
}

fn ensure_store_dir(home: &Path) -> Result<PathBuf, RecoveryCustodyError> {
    std::fs::symlink_metadata(home).map_err(RecoveryCustodyError::State)?;
    crate::private_fs::create_owned_private_dir(home).map_err(RecoveryCustodyError::State)?;
    let directory = store_dir(home);
    crate::private_fs::create_owned_private_dir(&directory).map_err(RecoveryCustodyError::State)?;
    // Existence alone does not prove a predecessor durably published this name.
    sync_store_parent(home).map_err(RecoveryCustodyError::State)?;
    Ok(directory)
}

fn sync_store_parent(home: &Path) -> io::Result<()> {
    #[cfg(test)]
    {
        PARENT_SYNCS.set(PARENT_SYNCS.get().saturating_add(1));
        if FAIL_PARENT_SYNC.replace(false) {
            return Err(io::Error::other(
                "injected host-interface parent sync failure",
            ));
        }
    }
    crate::atomic_io::sync_dir(home).map_err(io::Error::other)
}

#[cfg(test)]
pub(super) fn fail_parent_sync_once_for_test() {
    FAIL_PARENT_SYNC.set(true);
}

#[cfg(test)]
pub(super) fn take_parent_sync_count_for_test() -> usize {
    PARENT_SYNCS.replace(0)
}

#[cfg(unix)]
fn acquire_lock(home: &Path) -> Result<crate::atomic_io::FileLock, RecoveryCustodyError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let directory = ensure_store_dir(home)?;
    let path = directory.join(LOCK);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(RecoveryCustodyError::State)?;
    let metadata = file.metadata().map_err(RecoveryCustodyError::State)?;
    crate::private_fs::require_current_owner(&metadata).map_err(RecoveryCustodyError::State)?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(invalid_state("workload lock is not a private regular file"));
    }
    if metadata.mode() & 0o777 != 0o600 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(RecoveryCustodyError::State)?;
    }
    crate::atomic_io::FileLock::acquire_opened(file)
        .map_err(|error| RecoveryCustodyError::State(io::Error::other(error)))
}

#[cfg(not(unix))]
fn acquire_lock(home: &Path) -> Result<crate::atomic_io::FileLock, RecoveryCustodyError> {
    Err(RecoveryCustodyError::State(
        crate::private_fs::unsupported_platform_error(home),
    ))
}

#[cfg(unix)]
fn load_protected(
    home: &Path,
    limits: RecoveryStoreLimits,
) -> Result<WorkloadLedger, RecoveryCustodyError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    if !validate_store_dir_if_present(home)? {
        return Ok(WorkloadLedger::default());
    }
    let path = ledger_path(home);
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(WorkloadLedger::default());
        }
        Err(error) => return Err(RecoveryCustodyError::State(error)),
    };
    let metadata = file.metadata().map_err(RecoveryCustodyError::State)?;
    crate::private_fs::require_current_owner(&metadata).map_err(RecoveryCustodyError::State)?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o600
    {
        return Err(invalid_state(
            "workload ledger is not a private regular file",
        ));
    }
    let maximum = u64::try_from(limits.max_bytes).map_err(|_| RecoveryCustodyError::Limit)?;
    if metadata.len() > maximum {
        return Err(RecoveryCustodyError::Limit);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| RecoveryCustodyError::Limit)?,
    );
    std::io::Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(RecoveryCustodyError::State)?;
    if bytes.len() > limits.max_bytes {
        return Err(RecoveryCustodyError::Limit);
    }
    let ledger: WorkloadLedger = serde_json::from_slice(&bytes)
        .map_err(|error| RecoveryCustodyError::State(io::Error::other(error)))?;
    if ledger.entries().len() > limits.max_workloads {
        return Err(RecoveryCustodyError::Limit);
    }
    Ok(ledger)
}

#[cfg(unix)]
fn validate_store_dir_if_present(home: &Path) -> Result<bool, RecoveryCustodyError> {
    use std::os::unix::fs::MetadataExt as _;

    let directory = store_dir(home);
    let metadata = match std::fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(RecoveryCustodyError::State(error)),
    };
    crate::private_fs::require_current_owner(&metadata).map_err(RecoveryCustodyError::State)?;
    if !metadata.file_type().is_dir() || metadata.mode() & 0o777 != 0o700 {
        return Err(invalid_state(
            "host-interface state is not an owner-only plain directory",
        ));
    }
    Ok(true)
}

#[cfg(not(unix))]
fn load_protected(
    home: &Path,
    _limits: RecoveryStoreLimits,
) -> Result<WorkloadLedger, RecoveryCustodyError> {
    Err(RecoveryCustodyError::State(
        crate::private_fs::unsupported_platform_error(home),
    ))
}

pub(super) fn load_ordinary_at(home: &Path) -> Result<WorkloadLedger, super::HostInterfaceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        let path = ledger_path(home);
        let mut file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(WorkloadLedger::default());
            }
            Err(error) => return Err(super::workload::unreadable(&path, &error.to_string())),
        };
        let metadata = file
            .metadata()
            .map_err(|error| super::workload::unreadable(&path, &error.to_string()))?;
        crate::private_fs::require_current_owner(&metadata)
            .map_err(|error| super::workload::unreadable(&path, &error.to_string()))?;
        if !metadata.file_type().is_file() || metadata.nlink() != 1 {
            return Err(super::workload::unreadable(
                &path,
                "ledger is not an owned regular file with one link",
            ));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| super::workload::unreadable(&path, &error.to_string()))?;
        let ledger: WorkloadLedger = serde_json::from_slice(&bytes)
            .map_err(|error| super::workload::unreadable(&path, &error.to_string()))?;
        let managed = ledger
            .entries()
            .values()
            .any(|entry| entry.recovery.is_some());
        if managed {
            let protected_directory = validate_store_dir_if_present(home)
                .map_err(|error| super::workload::unreadable(&path, &error.to_string()))?;
            if metadata.mode() & 0o777 != 0o600 || !protected_directory {
                return Err(super::workload::unreadable(
                    &path,
                    "managed ledger is not in protected storage",
                ));
            }
        }
        validate_ledger(&ledger)
            .map_err(|error| super::workload::unreadable(&path, &error.to_string()))?;
        Ok(ledger)
    }
    #[cfg(not(unix))]
    {
        let path = ledger_path(home);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| super::workload::unreadable(&path, &error.to_string())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(WorkloadLedger::default()),
            Err(error) => Err(super::workload::unreadable(&path, &error.to_string())),
        }
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    maximum: usize,
    exceeded: bool,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self.maximum.saturating_sub(self.bytes.len());
        if bytes.len() > remaining {
            self.exceeded = true;
            return Err(io::Error::other("recovery serialization exceeds limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialize_bounded(
    ledger: &WorkloadLedger,
    limits: RecoveryStoreLimits,
) -> Result<Vec<u8>, RecoveryCustodyError> {
    if ledger.entries().len() > limits.max_workloads {
        return Err(RecoveryCustodyError::Limit);
    }
    let mut writer = BoundedWriter {
        bytes: Vec::with_capacity(limits.max_bytes.min(4096)),
        maximum: limits.max_bytes,
        exceeded: false,
    };
    if let Err(error) = serde_json::to_writer_pretty(&mut writer, ledger) {
        if writer.exceeded {
            return Err(RecoveryCustodyError::Limit);
        }
        return Err(RecoveryCustodyError::State(io::Error::other(error)));
    }
    Ok(writer.bytes)
}

pub(super) fn save_legacy_at(
    home: &Path,
    proposed: &WorkloadLedger,
) -> Result<(), RecoveryCustodyError> {
    let limits = RecoveryStoreLimits {
        max_workloads: usize::MAX,
        max_bytes: usize::MAX,
    };
    let _lock = acquire_lock(home)?;
    let current = load_protected(home, limits)?;
    if current
        .entries()
        .values()
        .any(|entry| entry.recovery.is_some())
        || proposed
            .entries()
            .values()
            .any(|entry| entry.recovery.is_some())
    {
        return Err(RecoveryCustodyError::Conflict);
    }
    let bytes = serialize_bounded(proposed, limits)?;
    crate::atomic_io::write_private(&ledger_path(home), &bytes).map_err(|source| {
        RecoveryCustodyError::CommitUnknown {
            authority_id: [0; 32],
            workload_id: "local-ledger".to_string(),
            intent: CommitIntent::Ordinary,
            source,
        }
    })
}

pub(super) fn mutate_ordinary_at<T, E>(
    home: &Path,
    workload: &str,
    change: impl FnOnce(&mut WorkloadLedger) -> Result<T, E>,
) -> Result<T, E>
where
    E: From<RecoveryCustodyError>,
{
    let limits = RecoveryStoreLimits {
        max_workloads: usize::MAX,
        max_bytes: usize::MAX,
    };
    let _lock = acquire_lock(home).map_err(E::from)?;
    let mut ledger = load_protected(home, limits).map_err(E::from)?;
    let result = change(&mut ledger)?;
    validate_ledger(&ledger).map_err(E::from)?;
    let bytes = serialize_bounded(&ledger, limits).map_err(E::from)?;
    crate::atomic_io::write_private(&ledger_path(home), &bytes).map_err(|source| {
        E::from(RecoveryCustodyError::CommitUnknown {
            authority_id: [0; 32],
            workload_id: workload.to_owned(),
            intent: CommitIntent::Ordinary,
            source,
        })
    })?;
    Ok(result)
}
