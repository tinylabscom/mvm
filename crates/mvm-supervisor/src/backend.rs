//! Backend launcher slot — what the supervisor calls to actually
//! start a VM once it's verified the plan.
//!
//! Plan 37 §3.1 specifies an open `BackendRegistry`; for Wave 1.4
//! we just need an abstraction so `Supervisor::launch(plan)` can
//! be tested without a real Firecracker. The registry + concrete
//! `FirecrackerBackend` / `AppleContainerBackend` impls land in
//! a follow-up that lifts today's `mvm-runtime/src/vm/backend.rs`
//! `AnyBackend` enum behind this trait.

use async_trait::async_trait;
use mvm_plan::{ExecutionPlan, PlanId};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("backend not wired (Noop slot)")]
    NotWired,

    #[error("backend launch failed: {0}")]
    LaunchFailed(String),

    #[error("backend stop failed: {0}")]
    StopFailed(String),

    #[error("backend not aware of plan {plan_id:?}")]
    UnknownPlan { plan_id: PlanId },
}

/// Async because real backends drive Firecracker's HTTP API or
/// Apple Container's vsock RPC, both of which the supervisor will
/// eventually pump from a tokio runtime.
#[async_trait]
pub trait BackendLauncher: Send + Sync {
    /// Issue the start request. Returns when the backend has
    /// accepted the request — not necessarily when the guest is
    /// ready. The supervisor's state machine separately transitions
    /// `Launched -> Running` after the guest agent pings (Wave 2).
    async fn launch(&self, plan: &ExecutionPlan) -> Result<(), BackendError>;

    /// Stop the workload identified by `plan_id`.
    async fn stop(&self, plan_id: &PlanId) -> Result<(), BackendError>;
}

/// Fail-closed default. A supervisor wired with `NoopBackendLauncher`
/// can't start any workload — the launch attempt errors with
/// `BackendError::NotWired` before the supervisor transitions to
/// `Launched`.
pub struct NoopBackendLauncher;

#[async_trait]
impl BackendLauncher for NoopBackendLauncher {
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
