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
