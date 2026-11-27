//! One post-launch rollback and failure-audit policy for all admission callers.

use anyhow::{Context, Result};
use mvm_contract::grants::Grants;
use mvm_contract::protocol::resource_controls::EnforcedGrants;
use mvm_core::vm_backend::VmId;
use mvm_runtime::AnyBackend;

use super::AdmittedPlan;

/// What rolling a launch back needs to know. A struct rather than seven
/// positional arguments, so a caller cannot silently swap the stage label for
/// the reason.
pub(super) struct UndoLaunch<'a> {
    pub(super) backend: &'a AnyBackend,
    pub(super) vm_id: &'a VmId,
    pub(super) admitted: &'a AdmittedPlan,
    pub(super) emitter: Option<&'a crate::audit::emitter::AuditEmitter>,
    /// Wire label of the stage that refused, for the terminal audit entry.
    pub(super) stage: &'static str,
    /// Human-readable clause naming what went wrong, for the stop-failure log.
    pub(super) reason: &'static str,
    pub(super) err: anyhow::Error,
}

/// Stop a VM that started but must not keep running, emit the terminal
/// `plan.failed` entry, and hand the original error back.
///
/// One helper for both post-start refusals: leaving a VM up whose bounds were
/// never established would mean the only record of the run claims it was
/// bounded when it was not.
pub(super) fn undo_launch(undo: UndoLaunch<'_>) -> anyhow::Error {
    let backend = undo.backend;
    let vm_id = undo.vm_id;
    undo_launch_with(
        undo,
        || backend.stop(vm_id).map(|_| ()),
        FailureAuditPolicy::LegacyImmediate,
    )
}

pub(super) fn undo_cli_launch(undo: UndoLaunch<'_>) -> anyhow::Error {
    let backend = undo.backend;
    let vm_id = undo.vm_id;
    undo_launch_with(
        undo,
        || backend.stop(vm_id).map(|_| ()),
        FailureAuditPolicy::OwnedAfterConfirmedRollback,
    )
}

/// The host budget refused to spend an admission's hold at dispatch, so no
/// backend was started.
#[derive(Debug, thiserror::Error)]
#[error("host-budget dispatch refused")]
pub struct HostBudgetRefused;

/// A post-start refusal whose compensating stop could not be confirmed.
#[derive(Debug, thiserror::Error)]
#[error("{primary:#}; rollback remains unconfirmed: {stop:#}")]
pub struct UndoLaunchFailure {
    #[source]
    primary: anyhow::Error,
    stop: anyhow::Error,
}

impl UndoLaunchFailure {
    /// Classify an already-attempted compensating stop as uncertain custody.
    pub(crate) fn unconfirmed(primary: anyhow::Error, stop: anyhow::Error) -> Self {
        Self { primary, stop }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum FailureAuditPolicy {
    LegacyImmediate,
    OwnedAfterConfirmedRollback,
}

pub(super) fn undo_launch_with(
    undo: UndoLaunch<'_>,
    rollback: impl FnOnce() -> Result<()>,
    audit_policy: FailureAuditPolicy,
) -> anyhow::Error {
    let stopped = rollback();
    if let Err(stop_err) = &stopped {
        tracing::warn!(
            error = %stop_err,
            "stopping a VM whose {reason} failed; it may still be running",
            reason = undo.reason,
        );
    }
    if (audit_policy == FailureAuditPolicy::LegacyImmediate || stopped.is_ok())
        && let Some(emitter) = undo.emitter
        && let Err(e) = emitter.emit_failed(
            undo.admitted.plan(),
            undo.stage,
            &format!("{err:#}", err = undo.err),
        )
    {
        tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
    }
    match stopped {
        Ok(()) => undo.err,
        Err(stop) => anyhow::Error::new(UndoLaunchFailure {
            primary: undo.err,
            stop,
        }),
    }
}

/// Apply the admitted plan's grants to the VM that is now running, and report
/// what the backend achieved.
///
/// After `start` rather than before, because a control needs something to
/// attach to; the backends that bound CPU do it by placing the VMM process
/// itself, which does not exist until then.
///
/// Not best-effort. A workload whose bounds could not be applied is running
/// unbounded, so the launch is undone rather than completed alongside a record
/// that says otherwise — the same posture the supervisor's own launch path
/// takes.
fn apply_admitted_grants(
    backend: &AnyBackend,
    vm_id: &VmId,
    admitted: &AdmittedPlan,
) -> Result<EnforcedGrants> {
    let undeclared = Grants::default();
    let grants = admitted.plan().grants.as_ref().unwrap_or(&undeclared);
    let mut enforced = backend
        .as_vm_backend()
        .apply_grants(vm_id, grants)
        .context("applying the admitted plan's grants to the started VM")?;
    super::placement::check_placement_readback(admitted.allowed_cpus(), &mut enforced)
        .context("confining the started VM to the host cores it was placed on")?;
    if admitted.allowed_cpus().is_some() {
        // A later topology admission reads this to tell this unit's own
        // machine from one that would keep running on cores it is handing out.
        crate::topology_admission::placement::record_owner(
            &mvm_core::config::vm_state_dir(&vm_id.0),
            &crate::topology_admission::placement::PlacementOwner {
                tenant: admitted.plan().tenant.clone(),
                workload: admitted.plan().workload.clone(),
                exclusive: admitted.holds_cores_exclusively(),
            },
        )?;
    }
    Ok(enforced)
}

/// Apply the admitted plan's grants to a VM that has just started, and undo
/// the launch if they cannot be applied.
///
/// Every launch path that starts a VM itself and then applies its grants goes
/// through here, so they share one failure posture: a backend that cannot
/// report what bounded the VM stops it, the chain records `plan.failed` at the
/// `grants` stage, and the error comes back. A caller never gets to substitute
/// an all-`Declared` answer for a failed application, because that answer
/// would then be signed into `plan.grants_enforced` as if it were the tier
/// the host achieved.
///
/// `Declared` is still a legitimate *successful* answer: a host with no
/// mechanism for a dimension reports it that way, and the boot proceeds. Only
/// an application that errored refuses.
///
/// `backend` must be the object that started `vm_id`. A backend rebuilt from a
/// name is a different object, and one that keeps per-run state in memory has
/// nothing to read back for a VM it did not start.
pub fn apply_admitted_grants_or_undo_launch(
    backend: &AnyBackend,
    vm_id: &VmId,
    admitted: &AdmittedPlan,
    emitter: Option<&crate::audit::emitter::AuditEmitter>,
) -> Result<EnforcedGrants> {
    apply_admitted_grants_with_rollback(
        backend,
        vm_id,
        admitted,
        emitter,
        || backend.stop(vm_id).map(|_| ()),
        FailureAuditPolicy::LegacyImmediate,
    )
}

/// Apply grants for a client-owned persistent start; a failed stop remains unsealed.
pub fn apply_persistent_grants_or_undo_launch(
    backend: &AnyBackend,
    vm_id: &VmId,
    admitted: &AdmittedPlan,
    emitter: Option<&crate::audit::emitter::AuditEmitter>,
) -> Result<EnforcedGrants> {
    apply_admitted_grants_with_rollback(
        backend,
        vm_id,
        admitted,
        emitter,
        || backend.stop(vm_id).map(|_| ()),
        FailureAuditPolicy::OwnedAfterConfirmedRollback,
    )
}

pub(super) fn apply_entrypoint_grants_or_undo_launch(
    backend: &AnyBackend,
    vm_id: &VmId,
    admitted: &AdmittedPlan,
    emitter: Option<&crate::audit::emitter::AuditEmitter>,
) -> Result<EnforcedGrants> {
    apply_admitted_grants_with_rollback(
        backend,
        vm_id,
        admitted,
        emitter,
        || backend.stop(vm_id).map(|_| ()),
        FailureAuditPolicy::OwnedAfterConfirmedRollback,
    )
}

pub(super) fn apply_admitted_grants_with_rollback(
    backend: &AnyBackend,
    vm_id: &VmId,
    admitted: &AdmittedPlan,
    emitter: Option<&crate::audit::emitter::AuditEmitter>,
    rollback: impl FnOnce() -> Result<()>,
    audit_policy: FailureAuditPolicy,
) -> Result<EnforcedGrants> {
    apply_admitted_grants(backend, vm_id, admitted).map_err(|err| {
        undo_launch_with(
            UndoLaunch {
                backend,
                vm_id,
                admitted,
                emitter,
                stage: "grants",
                reason: "grants could not be applied",
                err,
            },
            rollback,
            audit_policy,
        )
    })
}

/// Record what this boot committed against the host budget, rolling the
/// launch back when the record cannot be written.
///
/// A missing per-VM record makes a running machine invisible to later budget
/// admissions, so recording failure is fatal. `vm_name` keys the charge while
/// `vm_id` identifies the machine to stop; callers must provide both.
pub fn record_charge_or_undo_launch(
    backend: &AnyBackend,
    vm_id: &VmId,
    vm_name: &str,
    admitted: &AdmittedPlan,
    emitter: Option<&crate::audit::emitter::AuditEmitter>,
) -> Result<()> {
    record_charge_with_rollback(
        backend,
        vm_id,
        vm_name,
        admitted,
        emitter,
        || backend.stop(vm_id).map(|_| ()),
        FailureAuditPolicy::LegacyImmediate,
    )
}

/// Record a persistent charge; a failed stop remains unsealed.
pub fn record_persistent_charge_or_undo_launch(
    backend: &AnyBackend,
    vm_id: &VmId,
    vm_name: &str,
    admitted: &AdmittedPlan,
    emitter: Option<&crate::audit::emitter::AuditEmitter>,
) -> Result<()> {
    record_charge_with_owned_rollback(backend, vm_id, vm_name, admitted, emitter, || {
        backend.stop(vm_id).map(|_| ())
    })
}

pub(super) fn record_entrypoint_charge_or_undo_launch(
    backend: &AnyBackend,
    vm_id: &VmId,
    vm_name: &str,
    admitted: &AdmittedPlan,
    emitter: Option<&crate::audit::emitter::AuditEmitter>,
) -> Result<()> {
    record_charge_with_rollback(
        backend,
        vm_id,
        vm_name,
        admitted,
        emitter,
        || backend.stop(vm_id).map(|_| ()),
        FailureAuditPolicy::OwnedAfterConfirmedRollback,
    )
}

/// Share budget policy while the host receiver keeps original native custody.
pub fn record_charge_with_owned_rollback(
    backend: &AnyBackend,
    vm_id: &VmId,
    vm_name: &str,
    admitted: &AdmittedPlan,
    emitter: Option<&crate::audit::emitter::AuditEmitter>,
    rollback: impl FnOnce() -> Result<()>,
) -> Result<()> {
    record_charge_with_rollback(
        backend,
        vm_id,
        vm_name,
        admitted,
        emitter,
        rollback,
        FailureAuditPolicy::OwnedAfterConfirmedRollback,
    )
}

fn record_charge_with_rollback(
    backend: &AnyBackend,
    vm_id: &VmId,
    vm_name: &str,
    admitted: &AdmittedPlan,
    emitter: Option<&crate::audit::emitter::AuditEmitter>,
    rollback: impl FnOnce() -> Result<()>,
    audit_policy: FailureAuditPolicy,
) -> Result<()> {
    admitted.host_budget.record_started(vm_name).map_err(|err| {
        undo_launch_with(
            UndoLaunch {
                backend,
                vm_id,
                admitted,
                emitter,
                stage: "host-budget",
                reason: "its admitted charge could not be recorded",
                err,
            },
            rollback,
            audit_policy,
        )
    })
}

pub(super) fn stop_actor(
    slot: &mut Option<&mut Option<mvm_runtime::actor_teardown::ActorOwner>>,
) -> Result<()> {
    let owner = slot
        .as_mut()
        .and_then(|slot| slot.as_mut())
        .ok_or_else(|| anyhow::anyhow!("original actor owner missing"))?;
    let _proof = owner.stop_and_reap()?;
    Ok(())
}

pub(super) fn undo_start(
    undo: UndoLaunch<'_>,
    slot: &mut Option<&mut Option<mvm_runtime::actor_teardown::ActorOwner>>,
) -> anyhow::Error {
    if slot.is_some() {
        undo_launch_with(
            undo,
            || stop_actor(slot),
            FailureAuditPolicy::OwnedAfterConfirmedRollback,
        )
    } else {
        undo_launch(undo)
    }
}
