//! Second read of the workload ledger once a launch has a live VM.
//!
//! Admission reads the ledger before the VM exists, so a quarantine or a
//! replacement committed after that read would otherwise let the launch finish.
//! Reading again after the VM is registered closes the gap: either the
//! operator's stop sees the VM, or this read sees the commit.

use anyhow::{Context, Result};
use mvm_core::plan::ExecutionPlan;

/// Fail closed unless the workload is still admitted at the plan's epoch.
/// Any failure, including an unreadable ledger, refuses.
pub(crate) fn still_admitted(plan: &ExecutionPlan) -> Result<()> {
    let home = super::host_gates::mvm_home_path();
    super::host_gates::load_gate_and_admit(plan, &home)
        .map(|_| ())
        .context("the workload ledger no longer admits this launch")
}

/// The rollback of a launch refused by [`still_admitted`]: the VM is live, so
/// it is stopped and the launch is recorded as failed, never as launched.
pub(super) fn undo<'a>(
    backend: &'a mvm_runtime::AnyBackend,
    vm_id: &'a mvm_core::vm_backend::VmId,
    admitted: &'a super::AdmittedPlan,
    emitter: Option<&'a crate::audit::emitter::AuditEmitter>,
    err: anyhow::Error,
) -> super::rollback::UndoLaunch<'a> {
    super::rollback::UndoLaunch {
        backend,
        vm_id,
        admitted,
        emitter,
        stage: "workload-contained",
        reason: "the workload ledger stopped admitting the launch while it was in flight",
        err,
    }
}

/// Stop a warm child claimed under an admission the ledger no longer honours,
/// before the caller can take custody of it.
pub(super) fn stop_claimed(
    backend: &mvm_runtime::AnyBackend,
    owned: mvm_runtime::backend::OwnedWarmClaim,
    error: anyhow::Error,
) -> anyhow::Error {
    let (id, _lifecycle) = owned.into_parts();
    match backend.stop(&id) {
        Ok(_) => error,
        Err(stop) => super::start::CliStartFailure::UncertainStop(error.context(format!(
            "stopping the contained warm child failed: {stop:#}"
        )))
        .into(),
    }
}
