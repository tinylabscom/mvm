//! Fail-closed reasons a warm-pool claim can be refused, and the outcome type
//! the bind gate returns. Kept separate from the crate-wide `anyhow::Result`
//! convention: refusals here are a closed set the caller must exhaustively
//! handle (audit, retry, or surface to the operator), not an open-ended error
//! bag.

use mvm_core::vm_backend::VmId;

#[derive(Debug, thiserror::Error)]
pub enum ClaimRefusal {
    #[error("parent is not in a claimable state")]
    ParentNotClaimable,
    #[error("parent has no signed audit entry; refusing to fork an un-audited parent")]
    ParentUnaudited,
    #[error("parent record drifted from its sealed content; refusing a tampered parent")]
    ParentTampered,
    #[error("child plan is outside its validity window")]
    PlanExpired,
    #[error("child plan nonce was already seen; refusing a replayed claim")]
    PlanReplayed,
    #[error("plan image digest {expected} does not match parent rootfs digest {got}")]
    PlanParentMismatch { expected: String, got: String },
    #[error("refusing to run a workload directly on a warm parent")]
    ParentPromotionRefused,
}

#[derive(Debug)]
pub enum ClaimOutcome {
    Claimed(VmId),
    Refused(ClaimRefusal),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_reasons_are_distinct_and_described() {
        let m = ClaimRefusal::PlanParentMismatch {
            expected: "sha256:aa".into(),
            got: "sha256:bb".into(),
        };
        assert!(m.to_string().contains("sha256:aa"));
        assert!(m.to_string().contains("sha256:bb"));
        // Distinct variants must not compare equal.
        assert_ne!(
            ClaimRefusal::ParentUnaudited.to_string(),
            ClaimRefusal::ParentTampered.to_string()
        );
    }
}
