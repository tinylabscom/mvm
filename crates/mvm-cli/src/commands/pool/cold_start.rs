//! What a launch's claim attempt came to: a claimed standby, or a cold boot
//! and the reason for it.
//!
//! A cold boot is never an error. It is declared on stderr when the launch was
//! one a standby could have served, and its reason is recorded on the
//! chain-signed log, so a slow start can be told apart from a broken one.

use anyhow::Result;
use mvm_core::vm_backend::{VmId, VmStartConfig, WarmClaimRefusal};

/// The result of trying to serve a launch from a standby.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarmClaimOutcome {
    /// A standby was claimed and the VM now runs under this id.
    Claimed(VmId),
    /// The launch boots cold, for this reason.
    Cold(ColdStartReason),
}

/// Why a launch booted cold instead of claiming a standby.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdStartReason {
    /// The launch could have claimed a standby but none was ready: the first
    /// run of this image on this host, a run after its standby was claimed and
    /// not yet replaced, or released after sitting idle, or a run that lost
    /// the only one to a concurrent launch.
    NoStandbyReady,
    /// The caller named the machine, and a claimed standby runs under its own
    /// id.
    Named,
    /// A shape a shared parent cannot serve: extra volumes, guest egress, or
    /// boot assets pinned by a bundle.
    IneligibleShape,
    /// This host keeps no standbys (`MVM_RESIDENCY=cold`).
    StandbysDisabled,
    /// The backend has no standby pool.
    BackendUnsupported,
    /// The launch carries no admitted plan, so there is nothing to bind a
    /// claimed child to.
    Unadmitted,
}

impl ColdStartReason {
    /// The label recorded on the chain-signed log.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::NoStandbyReady => "no_standby_ready",
            Self::Named => "named",
            Self::IneligibleShape => "ineligible_shape",
            Self::StandbysDisabled => "standbys_disabled",
            Self::BackendUnsupported => "backend_unsupported",
            Self::Unadmitted => "unadmitted",
        }
    }

    /// Whether a run that booted cold for this reason leaves a standby behind
    /// for the next run of the same image. Only a launch a standby could have
    /// served does: replenishing for a named run or an ineligible shape would
    /// prepare something no later launch of that shape can claim.
    #[must_use]
    pub fn leaves_a_standby(self) -> bool {
        matches!(self, Self::NoStandbyReady)
    }

    /// The line a launch prints when it boots cold for this reason, or `None`
    /// when the cold boot is the shape's normal path and there is nothing to
    /// say.
    #[must_use]
    pub fn declaration(self) -> Option<&'static str> {
        match self {
            Self::NoStandbyReady => Some(
                "No standby of this image is ready, so this run boots cold. \
                 A standby is prepared after it, and the next run of the image claims it.",
            ),
            Self::Named
            | Self::IneligibleShape
            | Self::StandbysDisabled
            | Self::BackendUnsupported
            | Self::Unadmitted => None,
        }
    }
}

/// Whether this launch may be served by a standby at all, or the reason it
/// boots cold without looking. The order is the order a reader asks in: a
/// named machine is never a claim, a shape a shared parent cannot serve is
/// never a claim, and a host that keeps no standbys has nothing to claim.
pub(super) fn claim_gate(
    cfg: &VmStartConfig,
    user_named: bool,
    late_volume_slots: u8,
) -> Result<(), ColdStartReason> {
    if user_named {
        return Err(ColdStartReason::Named);
    }
    if !super::warm_eligible_launch(cfg, late_volume_slots) {
        return Err(ColdStartReason::IneligibleShape);
    }
    if cfg.warm_pool_size == 0 {
        return Err(ColdStartReason::StandbysDisabled);
    }
    Ok(())
}

/// Whether a claim that found no usable standby must fail the launch instead
/// of booting it cold. Only the bench's required-claim lane asks for that: it
/// measures warm claims, and a cold boot counted as one would be a lie.
pub(super) fn claim_required() -> bool {
    std::env::var("MVM_HVF_WARM_REQUIRE_CLAIM").as_deref() == Ok("1")
}

/// Turn the claim's typed refusal into this launch's outcome.
///
/// Only an absence boots cold: no standby of this shape exists yet, another
/// launch reserved the one that did, or the backend keeps none. A standby
/// that exists and cannot be claimed — it failed verification, the backend
/// could not fork it, the claim could not be prepared — fails the launch with
/// the refusal. Booting cold there would turn a broken warm path into a
/// permanently slow one that nothing reports.
pub(super) fn outcome_for_refusal(
    refusal: WarmClaimRefusal,
    required: bool,
) -> Result<WarmClaimOutcome> {
    if required {
        return Err(anyhow::Error::new(refusal));
    }
    match refusal {
        WarmClaimRefusal::NoCompatibleParent => {
            Ok(WarmClaimOutcome::Cold(ColdStartReason::NoStandbyReady))
        }
        WarmClaimRefusal::BackendUnsupported { .. } => {
            Ok(WarmClaimOutcome::Cold(ColdStartReason::BackendUnsupported))
        }
        WarmClaimRefusal::ClaimRejected { ref reason } if lost_the_reservation(reason) => {
            Ok(WarmClaimOutcome::Cold(ColdStartReason::NoStandbyReady))
        }
        other => Err(anyhow::Error::new(other)),
    }
}

/// Whether a rejected claim lost its parent to a concurrent launch, which the
/// runner reports as the parent no longer being claimable. That parent is
/// serving the other launch; this one simply found none ready.
fn lost_the_reservation(reason: &str) -> bool {
    reason.contains(&super::ClaimRefusal::ParentNotClaimable.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [ColdStartReason; 6] = [
        ColdStartReason::NoStandbyReady,
        ColdStartReason::Named,
        ColdStartReason::IneligibleShape,
        ColdStartReason::StandbysDisabled,
        ColdStartReason::BackendUnsupported,
        ColdStartReason::Unadmitted,
    ];

    #[test]
    fn every_reason_has_a_distinct_label() {
        let mut labels: Vec<_> = ALL.iter().map(|r| r.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), ALL.len());
    }

    #[test]
    fn only_a_launch_a_standby_could_serve_leaves_one_and_says_so() {
        for reason in ALL {
            assert_eq!(
                reason.leaves_a_standby(),
                reason.declaration().is_some(),
                "{reason:?}"
            );
        }
        assert!(ColdStartReason::NoStandbyReady.leaves_a_standby());
        assert!(!ColdStartReason::Named.leaves_a_standby());
        assert!(!ColdStartReason::StandbysDisabled.leaves_a_standby());
    }
}
