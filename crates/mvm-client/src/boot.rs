//! Host-local VMM dispatch for a fully-prepared boot.
//!
//! The CLI resolves everything a workload needs (rootfs, kernel, verity,
//! overlay, admission) into a `VmStartConfig`, then hands it here. This owns the
//! VMM-selection + start dispatch so the CLI stays off
//! `mvm_runtime::backend::AnyBackend`. The signed-plan admission gate (a
//! mvm-hostd concern) and the launched/failed audit emits stay CLI-side — this
//! seam is only the backend start. It is a host-local free function, not an
//! `MvmClient` trait method: it carries a runtime `VmStartConfig`, which the
//! REST-facing trait deliberately cannot.

use crate::{MvmError, Result};
use mvm_core::protocol::vm_backend::{VmId, VmStatus};

/// Select the VMM for `backend_name`, verify it supports workloads, and start
/// the fully-prepared config. Mirrors the CLI's former inline
/// `from_hypervisor → require_workload_backend → start` triple exactly (both
/// failure arms carried the same `backend-start` reason). The underlying error
/// chain is preserved in the reason so the caller can surface and audit it.
pub fn start_prepared(
    backend_name: &str,
    config: &mvm_core::vm_backend::VmStartConfig,
) -> Result<()> {
    let backend = mvm_runtime::backend::AnyBackend::from_hypervisor(backend_name);
    mvm_runtime::workload_backend::require_workload_backend(&backend).map_err(|e| {
        MvmError::Backend {
            reason: format!("{e:#}"),
        }
    })?;
    backend.start(config).map_err(|e| MvmError::Backend {
        reason: format!("{e:#}"),
    })?;
    Ok(())
}

/// Report what actually bounded the VM [`start_prepared`] just started.
///
/// This is the seam that puts `VmBackend::apply_grants` on the path `mvmctl`
/// boots. Without a caller here the read-back is computed correctly and
/// reported to nobody, which from the outside is indistinguishable from a bound
/// that was never applied — a bounded CLI boot emitted no `plan.grants_enforced`
/// and `machine inspect` showed only the request.
///
/// Separate from [`start_prepared`] rather than folded into its return, because
/// the two answer different questions and only one of them can fail: the start
/// either happened or errored, while the tier is a read-back off the live
/// control that always has an honest answer (`Declared` for a host whose
/// mechanism is absent). Folding them would make a degraded — but successful —
/// boot look like a failure mode of starting.
///
/// `grants` is the request the plan was admitted under. It is passed because the
/// backend seam takes it; a backend derives its tier from the control, never
/// from what was asked for.
pub fn enforced_grants_after_start(
    backend_name: &str,
    vm_name: &str,
    grants: &mvm_contract::grants::Grants,
) -> Result<mvm_contract::protocol::resource_controls::EnforcedGrants> {
    let backend = mvm_runtime::backend::AnyBackend::from_hypervisor(backend_name);
    backend
        .as_vm_backend()
        .apply_grants(&VmId(vm_name.to_string()), grants)
        .map_err(|e| MvmError::Backend {
            reason: format!("{e:#}"),
        })
}

/// The typed tier behind a hypervisor name.
///
/// Admission measures a workload's declared grants against the mechanisms its
/// backend actually has, and that question has to be asked of a `BackendKind`
/// rather than of a string: a name is a label, and a gate that parsed one would
/// be deciding which resource controls apply from whatever the caller typed.
/// The conversion lives here, at the seam that already owns name-to-backend
/// resolution, so a caller holding only a name still never touches
/// `AnyBackend` itself.
pub fn backend_kind_for(hypervisor: &str) -> mvm_core::protocol::vm_backend::BackendKind {
    mvm_runtime::backend::AnyBackend::from_hypervisor(hypervisor).kind()
}

/// Whether the named VM is currently `Running` on `hypervisor`. A status-query
/// error (VM absent) reads as not-running — mirrors the CLI's former inline
/// `from_hypervisor(...).status(...)` check.
pub fn backend_is_running(hypervisor: &str, name: &str) -> bool {
    let backend = mvm_runtime::backend::AnyBackend::from_hypervisor(hypervisor);
    matches!(
        backend.status(&VmId(name.to_string())),
        Ok(VmStatus::Running)
    )
}

/// Stop the named VM on `hypervisor` at the VMM level only — no name-registry
/// deregistration. This is the raw pre-recreate / post-failed-init cleanup stop
/// the CLI ran inline, deliberately distinct from the lifecycle
/// [`crate::MvmClient::stop_machine`], which also deregisters.
pub fn backend_stop_by_name(hypervisor: &str, name: &str) -> Result<()> {
    let backend = mvm_runtime::backend::AnyBackend::from_hypervisor(hypervisor);
    backend
        .stop(&VmId(name.to_string()))
        .map_err(|e| MvmError::Backend {
            reason: format!("{e:#}"),
        })
}

/// Refuse a `--hypervisor` name the current build cannot select (e.g. `mock`
/// on a build without the `test-support` feature) before any machine
/// construction — mirrors the CLI's former inline
/// `AnyBackend::require_hypervisor_selectable` guard.
pub fn require_hypervisor_selectable(name: &str) -> Result<()> {
    mvm_runtime::backend::AnyBackend::require_hypervisor_selectable(name).map_err(|e| {
        MvmError::Backend {
            reason: format!("{e:#}"),
        }
    })
}
