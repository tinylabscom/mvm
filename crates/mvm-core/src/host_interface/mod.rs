//! Transport-independent host interface between a microVM and the services
//! that admit, constrain, observe and recover it.
//!
//! The local adapter ([`local::LocalHostInterface`]) is the default and needs
//! no central identity, `mvmd` or hardware attestation. A managed
//! implementation of the same [`HostInterface`] trait lives with `mvmd`.
//! Nothing here is wired into the launch path yet: this slice fixes the
//! contract, the fail-closed preflight and the state/epoch rules.

pub mod error;
pub mod local;
pub mod policy;
pub mod preflight;
pub mod state;
pub mod store;
#[cfg(test)]
mod tests;

pub use error::{Denial, HostInterfaceError};
pub use policy::{
    Assurance, AssuranceRequirement, HostPolicy, NamedVolumeGrant, SignedHostPolicy, VolumeMode,
};
pub use preflight::{CheckKind, PreflightCheck, PreflightReport, run_preflight};
pub use state::{Conditions, ExecutionEpoch, NodeState};

/// What a launch asks the host interface to authorize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    pub workload_id: String,
    pub image_digest: String,
    pub epoch: ExecutionEpoch,
}

/// Proof that every required check passed before the VMM was started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchAuthorization {
    pub workload_id: String,
    pub epoch: ExecutionEpoch,
    pub policy_version: u64,
    pub assurance: Assurance,
}

/// The one contract a microVM's host exposes. Local and remote
/// implementations are interchangeable; the guest cannot tell them apart.
pub trait HostInterface: Send + Sync {
    /// Current primary lifecycle state of this node.
    fn node_state(&self) -> NodeState;
    /// The effective, already-verified policy.
    fn policy(&self) -> Result<HostPolicy, HostInterfaceError>;
    /// Run launch preflight. `Ok` is the only value that permits a start.
    fn authorize_workload(
        &self,
        request: &LaunchRequest,
    ) -> Result<LaunchAuthorization, HostInterfaceError>;
    /// Quarantine, revoke or otherwise change node state; audited by callers.
    fn transition(&self, to: NodeState) -> Result<(), HostInterfaceError>;
}
