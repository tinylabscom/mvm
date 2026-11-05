use thiserror::Error;

/// Why a launch was refused. Each variant names one failed requirement so an
/// operator sees the cause, never a generic "denied".
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Denial {
    #[error("policy signature invalid")]
    PolicySignature,
    #[error("policy issuer not trusted")]
    PolicyIssuer,
    #[error("policy expired")]
    PolicyExpired,
    #[error("policy version {got} is older than accepted {min}")]
    PolicyRollback { got: u64, min: u64 },
    #[error("policy scope does not cover this node")]
    PolicyScope,
    #[error("image digest not admitted")]
    ImageDigest,
    #[error("enforcement provider unavailable or modified")]
    EnforcementUnavailable,
    #[error("node is {0}")]
    NodeNotActive(&'static str),
    #[error("stale execution epoch {got}; current is {current}")]
    StaleEpoch { got: u64, current: u64 },
    #[error("invalid volume grant: {0}")]
    VolumeGrant(String),
    #[error("resource reservation failed")]
    Resources,
    #[error("required secret provider unavailable")]
    SecretProvider,
    #[error("required hardware attestation unavailable (assurance: {0:?})")]
    AttestationRequired(super::policy::Assurance),
    #[error("host-interface state unreadable: {0}")]
    StateUnreadable(String),
    #[error("required check {0} did not complete")]
    CheckMissing(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HostInterfaceError {
    /// Launch is refused; the microVM must not start.
    #[error("launch denied: {0}")]
    Denied(#[from] Denial),
    #[error("invalid state transition {from:?} -> {to:?}")]
    InvalidTransition {
        from: super::state::NodeState,
        to: super::state::NodeState,
    },
}
