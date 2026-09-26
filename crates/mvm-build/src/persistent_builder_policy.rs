//! When a live persistent builder session should stop, and whether one may
//! be reused: the residency policy's idle rules, and the rule that a session
//! booted with other builder binaries than this process's is not.

use std::time::Duration;

use crate::persistent_builder::SessionRecord;

/// Whether a session runs the builder binaries this process would boot it
/// with.
///
/// A session keeps whatever `mvm-host-vm-init` and `mvm-builderd` it booted
/// with for as long as it lives, so an `mvmctl` carrying different ones must
/// not dispatch into it. With no payload of its own (`current` is `None`), a
/// process cannot tell, and keeps the session.
pub fn session_payload_is_current(recorded: Option<&str>, current: Option<&str>) -> bool {
    match current {
        None => true,
        Some(current) => recorded == Some(current),
    }
}

/// Why the invocation-driven keeper should stop the persistent builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderSessionTeardownReason {
    /// `MVM_RESIDENCY=cold` means no resident builder should remain alive.
    ColdPolicy,
    /// Policy requested a parked snapshot after idle, but this libkrun-backed
    /// persistent-builder session has no memory snapshot primitive.
    SnapshotUnavailable,
}

/// Pure decision for a live persistent-builder session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderSessionPolicyDecision {
    Keep,
    Teardown(BuilderSessionTeardownReason),
}

/// Decide what the keeper should do with a live persistent-builder session.
///
/// A real snapshot path for the HVF dev-builder is not wired yet; this hidden
/// `persistent-builder` session is currently libkrun-backed, so a policy-level
/// `Park` decision degrades to teardown rather than pretending a snapshot was
/// captured.
pub fn decide_builder_session_policy(
    record: &SessionRecord,
    policy: &mvm_core::residency::ResidencyPolicy,
    now_unix_secs: u64,
) -> BuilderSessionPolicyDecision {
    if matches!(policy.kind(), mvm_core::residency::ResidencyKind::Cold) {
        return BuilderSessionPolicyDecision::Teardown(BuilderSessionTeardownReason::ColdPolicy);
    }

    let Some(threshold) = builder_session_idle_threshold(policy) else {
        return BuilderSessionPolicyDecision::Keep;
    };
    let idle = session_idle_duration(record, now_unix_secs);
    match mvm_core::residency::decide_builder_residency_action(policy.kind(), idle, threshold) {
        mvm_core::residency::BuilderResidencyAction::Keep => BuilderSessionPolicyDecision::Keep,
        mvm_core::residency::BuilderResidencyAction::Park => {
            BuilderSessionPolicyDecision::Teardown(
                BuilderSessionTeardownReason::SnapshotUnavailable,
            )
        }
        mvm_core::residency::BuilderResidencyAction::Teardown => {
            BuilderSessionPolicyDecision::Teardown(BuilderSessionTeardownReason::ColdPolicy)
        }
    }
}

fn builder_session_idle_threshold(
    policy: &mvm_core::residency::ResidencyPolicy,
) -> Option<Duration> {
    match policy.kind() {
        mvm_core::residency::ResidencyKind::Cold => Some(Duration::ZERO),
        mvm_core::residency::ResidencyKind::Parked => Some(Duration::ZERO),
        mvm_core::residency::ResidencyKind::Warm => policy.idle_timeout(),
    }
}

fn session_idle_duration(record: &SessionRecord, now_unix_secs: u64) -> Duration {
    let last = record.last_activity_unix_secs.unwrap_or(now_unix_secs);
    Duration::from_secs(now_unix_secs.saturating_sub(last))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session keeps the builder binaries it booted with. One booted with a
    /// different payload, or with its image's own binaries, is replaced; one
    /// booted with this process's payload is reused.
    #[test]
    fn a_session_is_reused_only_when_it_runs_this_payload() {
        let ours = "a".repeat(64);
        let theirs = "b".repeat(64);
        assert!(session_payload_is_current(Some(&ours), Some(&ours)));
        assert!(!session_payload_is_current(Some(&theirs), Some(&ours)));
        assert!(!session_payload_is_current(None, Some(&ours)));
        // A process with no payload of its own cannot judge, and keeps it.
        assert!(session_payload_is_current(Some(&theirs), None));
        assert!(session_payload_is_current(None, None));
    }
}
