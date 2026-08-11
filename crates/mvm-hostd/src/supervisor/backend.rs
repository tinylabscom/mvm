//! Backend launcher slot — what the supervisor calls to actually
//! start a VM once it's verified the plan.
//!
//! This `BackendLauncher` trait is the supervisor's own seam, kept so
//! `Supervisor::launch(plan)` is testable without a real Firecracker. It is
//! deliberately separate from the runtime backend stack: runtime behavior is
//! `mvm_core::vm_backend::VmBackend`, backend discovery is the compile-time
//! descriptor registry in `mvm_runtime::catalog`, and
//! `mvm_runtime::backend::AnyBackend` is the closed enum for backend-specific
//! dispatch. There is no dynamic backend registry — the descriptor table is
//! static.

use async_trait::async_trait;
use mvm_core::plan::{ExecutionPlan, PlanId};
use mvm_core::vm_backend::EnforcedGrants;
use mvm_runtime::base::config::VmSlot;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("backend not wired (Noop slot)")]
    NotWired,

    #[error("backend launch failed: {0}")]
    LaunchFailed(String),

    #[error("backend launch preparation failed: {0}")]
    PrepareFailed(String),

    #[error("backend stop failed: {0}")]
    StopFailed(String),

    #[error("backend not aware of plan {plan_id:?}")]
    UnknownPlan { plan_id: PlanId },
}

/// Runtime metadata the backend owns before the supervisor installs
/// host-side policy. The VM slot is the canonical source for VM
/// identity and backend allocation metadata; callers must not synthesize those
/// values separately.
#[derive(Debug, Clone)]
pub struct BackendLaunchSpec {
    pub vm_slot: VmSlot,
}

impl BackendLaunchSpec {
    pub fn new(vm_slot: VmSlot) -> Self {
        Self { vm_slot }
    }
}

/// Async because real backends drive Firecracker's HTTP API or
/// Apple Container's vsock RPC, both of which the supervisor will
/// eventually pump from a tokio runtime.
#[async_trait]
pub trait BackendLauncher: Send + Sync {
    /// Reserve or derive runtime metadata needed before backend
    /// launch. This must not start tenant code. The supervisor uses
    /// the returned slot to install firewall policy before calling
    /// [`BackendLauncher::launch`].
    async fn prepare_launch(&self, plan: &ExecutionPlan)
    -> Result<BackendLaunchSpec, BackendError>;

    /// Issue the start request. Returns when the backend has
    /// accepted the request — not necessarily when the guest is
    /// ready. The supervisor's state machine separately transitions
    /// `Launched -> Running` after the guest agent pings.
    async fn launch(&self, plan: &ExecutionPlan) -> Result<(), BackendError>;

    /// Stop the workload identified by `plan_id`.
    async fn stop(&self, plan_id: &PlanId) -> Result<(), BackendError>;

    /// Apply the plan's grants to the VM this launcher just started and report
    /// which mechanism actually bounded each dimension.
    ///
    /// Called after [`launch`](BackendLauncher::launch), because a cgroup or a
    /// timer needs a process to attach to. A real launcher forwards to
    /// [`mvm_core::vm_backend::VmBackend::apply_grants`] on the backend it
    /// wraps; the default here answers `Declared` across the board, which is
    /// the honest answer for a launcher that bounds nothing.
    ///
    /// The returned tiers — never the requested grants — are what the
    /// supervisor records. A grant is a request; a tier is what happened.
    async fn apply_grants(&self, _plan: &ExecutionPlan) -> Result<EnforcedGrants, BackendError> {
        Ok(EnforcedGrants::all_declared())
    }
}

/// Fail-closed default. A supervisor wired with `NoopBackendLauncher`
/// can't start any workload — the launch attempt errors with
/// `BackendError::NotWired` before the supervisor transitions to
/// `Launched`.
pub struct NoopBackendLauncher;

#[async_trait]
impl BackendLauncher for NoopBackendLauncher {
    async fn prepare_launch(
        &self,
        _plan: &ExecutionPlan,
    ) -> Result<BackendLaunchSpec, BackendError> {
        Err(BackendError::NotWired)
    }

    async fn launch(&self, _plan: &ExecutionPlan) -> Result<(), BackendError> {
        Err(BackendError::NotWired)
    }

    async fn stop(&self, _plan_id: &PlanId) -> Result<(), BackendError> {
        Err(BackendError::NotWired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_backend_launcher_is_constructable() {
        let _: Box<dyn BackendLauncher> = Box::new(NoopBackendLauncher);
    }
}
