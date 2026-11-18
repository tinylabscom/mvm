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
    #[error("required bound audit sink cannot append to its journal")]
    AuditUnavailable,
    #[error("required hardware attestation unavailable (assurance: {0:?})")]
    AttestationRequired(super::policy::Assurance),
    #[error("workload {0} is quarantined")]
    WorkloadQuarantined(String),
    #[error("offline lease invalid: {0}")]
    LeaseInvalid(&'static str),
    #[error("offline lease expired")]
    LeaseExpired,
    #[error("operation {0} is not allowed by the offline lease")]
    LeaseOpNotAllowed(&'static str),
    #[error("command sequence {got} replays or reorders (last accepted {last})")]
    ReplayedCommand { got: u64, last: u64 },
    #[error("fresh reauthentication required before authorization returns")]
    ReauthRequired,
    #[error("host-interface state unreadable: {0}")]
    StateUnreadable(String),
    #[error("required check {0} did not complete")]
    CheckMissing(&'static str),
    #[error("offline recovery refused: {0}")]
    Offline(#[from] OfflineRefusal),
}

/// Refusals specific to verified offline recovery, independent of any backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum OfflineRefusal {
    #[error("managed authority is missing")]
    AuthorityMissing,
    #[error("companion version is unsupported")]
    Version,
    #[error("issuer mapping is missing, ambiguous or mismatched")]
    Issuer,
    #[error("companion signature is invalid")]
    Signature,
    #[error("authority binding does not match")]
    Binding,
    #[error("finite authority bounds are invalid or exceed the ceiling")]
    Bounds,
    #[error("clock validity or continuity is uncertain")]
    ClockUncertain,
    #[error("clock observation moved backwards")]
    ClockRegression,
    #[error("required workload history is missing")]
    HistoryMissing,
    #[error("workload history is inconsistent")]
    HistoryInvalid,
    #[error("restart is not permitted or its allowance is exhausted")]
    RestartExhausted,
    #[error("proposed epoch is outside its allocation")]
    EpochAllocation,
    #[error("transition identity conflicts with recorded input")]
    TransitionConflict,
    #[error("transition input is out of order or terminal")]
    TransitionOrder,
    #[error("ownership or dispatch is uncertain")]
    OwnershipUnknown,
    #[error("recovery was cancelled")]
    Cancelled,
    #[error("required dependency was lost")]
    DependencyLost,
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
