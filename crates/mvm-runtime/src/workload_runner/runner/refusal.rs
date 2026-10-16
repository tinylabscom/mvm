//! Fail-closed verdicts a claim renders on a forked child and its parent.
//!
//! Three pure judgements, kept together and out of the runner body because they
//! share one property: each turns evidence into a *refusal reason*, and the
//! reason is the whole product. A claim that refuses for the wrong stated reason
//! sends an operator to fix something that is not broken, so these are unit
//! tested on their own rather than only through a claim.

use super::{ClaimRefusal, PostRestoreOutcome, StandbyError};

/// Judge a forked child's own report of what it did with its fresh generation
/// token. Every flag must hold: `acknowledged` says the guest answered at all,
/// `reseeded` says it rotated its generation identity (and so reseeded the CSPRNG
/// it inherited from the parent's memory image), and `clock_resynced` says it
/// took the host's wall clock instead of the parent's frozen one.
///
/// Any false flag is a refusal rather than a warning: a restored child that
/// cannot prove it left the parent's random state behind is indistinguishable
/// from a sibling that will produce the same "random" values, which is precisely
/// what a fresh identity exists to rule out.
pub(super) fn require_fresh_child_identity(
    child_vm_name: &str,
    outcome: &PostRestoreOutcome,
) -> std::result::Result<(), StandbyError> {
    let reported = || {
        outcome
            .detail
            .as_deref()
            .map(|detail| format!(" (guest reported: {detail})"))
            .unwrap_or_default()
    };
    let unproven = if !outcome.acknowledged {
        format!("did not acknowledge the post-restore signal{}", reported())
    } else if !outcome.reseeded {
        // The guest's own account decides the advice: an image without a
        // reseed helper has to be rebuilt, and a failed reseed may be retried.
        format!(
            "cannot be admitted as a fresh clone: {}",
            mvm_agentd::vsock::describe_missing_reseed(
                outcome.reseed_shortfall,
                outcome.detail.as_deref(),
            )
        )
    } else if !outcome.clock_resynced {
        format!(
            "acknowledged without resynchronizing its wall clock{}",
            reported()
        )
    } else {
        return Ok(());
    };
    Err(StandbyError::ClaimFailed(format!(
        "forked child '{child_vm_name}' {unproven}; refusing to admit a child that cannot prove \
         it left its parent's random state and clock behind"
    )))
}

/// The seccomp tier a claimed child must run its workload under: the one its
/// signed plan admits.
pub(super) fn admitted_seccomp_tier(
    plan: &mvm_core::plan::ExecutionPlan,
) -> mvm_core::crypto::seccomp::SeccompTier {
    plan.admission_profile.seccomp_tier.into()
}

/// Judge the forked child's report of which seccomp tier it now holds against
/// the tier it was handed. A child restored out of a standby parent holds no
/// tier until this handshake gives it one, so a report of none — or of another
/// tier — means its workload would run under a filter nobody admitted, or none
/// at all, and the claim is refused.
pub(super) fn require_admitted_seccomp_tier(
    child_vm_name: &str,
    requested: Option<mvm_core::crypto::seccomp::SeccompTier>,
    outcome: &PostRestoreOutcome,
) -> std::result::Result<(), StandbyError> {
    let Some(requested) = requested else {
        return Ok(());
    };
    if outcome.seccomp_tier == Some(requested) {
        return Ok(());
    }
    let held = outcome
        .seccomp_tier
        .map_or_else(|| "no tier".to_string(), |tier| format!("tier {tier}"));
    Err(StandbyError::ClaimFailed(format!(
        "forked child '{child_vm_name}' reports {held} where its plan admits seccomp tier \
         {requested}; refusing to admit a child whose workload would not run under the \
         admitted filter"
    )))
}

/// Refuse a child that did not mount every late volume its claim attached.
/// An agent too old to take them refuses the request outright; one that took
/// them must report exactly the count it was handed.
pub(super) fn require_late_volumes_mounted(
    child_vm_name: &str,
    requested: usize,
    outcome: &PostRestoreOutcome,
) -> std::result::Result<(), StandbyError> {
    if requested == 0 || outcome.volumes_mounted == Some(requested as u32) {
        return Ok(());
    }
    let mounted = outcome
        .volumes_mounted
        .map_or_else(|| "none".to_string(), |count| count.to_string());
    Err(StandbyError::ClaimFailed(format!(
        "forked child '{child_vm_name}' mounted {mounted} of the {requested} read-only volumes \
         its claim attached; refusing a child whose workload would start without them"
    )))
}

/// Map a fail-closed [`ClaimRefusal`] onto the transport-agnostic
/// [`StandbyError`] the claim seam returns. The refusal reasons stay distinct in
/// the message so a caller can tell an un-audited parent from a plan mismatch.
pub(super) fn refuse(refusal: ClaimRefusal) -> StandbyError {
    StandbyError::ClaimFailed(refusal.to_string())
}

/// Distinguish the three fail-closed reasons by the lineage verifier's own
/// message, so the caller sees the specific one: a parent with no signed
/// creation entry, a ledger too damaged to say either way, or a parent that
/// drifted from its sealed content. The unverifiable-ledger arm must come first
/// — it is the case that used to be reported as un-audited, which sent the
/// operator to re-capture a parent when the real finding was a broken chain.
pub(super) fn map_lineage_refusal(err: &anyhow::Error) -> ClaimRefusal {
    let msg = err.to_string();
    if msg.contains(crate::lineage::LEDGER_UNVERIFIABLE) {
        ClaimRefusal::LedgerUnverifiable
    } else if msg.contains(crate::lineage::NO_SIGNED_ENTRY) {
        ClaimRefusal::ParentUnaudited
    } else {
        ClaimRefusal::ParentTampered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The verdict itself, without a claim around it: every flag is required, and
    /// the refusal names which one the guest failed to prove.
    #[test]
    fn fresh_child_identity_requires_every_flag() {
        let proven = PostRestoreOutcome {
            acknowledged: true,
            detail: None,
            reseeded: true,
            clock_resynced: true,
            reseed_shortfall: None,
            seccomp_tier: None,
            volumes_mounted: None,
        };
        assert!(require_fresh_child_identity("vm-a", &proven).is_ok());

        for (mutate, expected) in [
            (
                (|o: &mut PostRestoreOutcome| o.acknowledged = false)
                    as fn(&mut PostRestoreOutcome),
                "did not acknowledge",
            ),
            (
                |o: &mut PostRestoreOutcome| o.reseeded = false,
                "did not rotate its generation identity",
            ),
            (
                |o: &mut PostRestoreOutcome| o.clock_resynced = false,
                "without resynchronizing its wall clock",
            ),
        ] {
            let mut outcome = proven.clone();
            mutate(&mut outcome);
            let err = require_fresh_child_identity("vm-a", &outcome)
                .expect_err("a false flag must refuse");
            assert!(
                err.to_string().contains(expected),
                "refusal must name the unproven flag ({expected}): {err}"
            );
        }
    }

    /// The child must report holding exactly the tier it was handed; a report
    /// of none (an agent that took no tier) or of another tier refuses.
    #[test]
    fn a_child_must_report_holding_the_admitted_seccomp_tier() {
        use mvm_core::crypto::seccomp::SeccompTier;
        let reporting = |seccomp_tier| PostRestoreOutcome {
            acknowledged: true,
            detail: None,
            reseeded: true,
            clock_resynced: true,
            reseed_shortfall: None,
            seccomp_tier,
            volumes_mounted: None,
        };
        assert!(
            require_admitted_seccomp_tier(
                "vm-a",
                Some(SeccompTier::Standard),
                &reporting(Some(SeccompTier::Standard))
            )
            .is_ok()
        );
        let none =
            require_admitted_seccomp_tier("vm-a", Some(SeccompTier::Standard), &reporting(None))
                .expect_err("a child holding no tier is refused");
        assert!(none.to_string().contains("reports no tier"), "{none}");
        let other = require_admitted_seccomp_tier(
            "vm-a",
            Some(SeccompTier::Standard),
            &reporting(Some(SeccompTier::Unrestricted)),
        )
        .expect_err("a child holding another tier is refused");
        assert!(
            other.to_string().contains("tier unrestricted")
                && other.to_string().contains("admits seccomp tier standard"),
            "{other}"
        );
        assert!(
            require_admitted_seccomp_tier("vm-a", None, &reporting(None)).is_ok(),
            "a handshake that delivered no tier has nothing to check"
        );
    }

    /// An image with no reseed helper and a reseed that failed are refused
    /// with different advice, and each carries the guest's own reason.
    #[test]
    fn an_unreseeded_child_is_refused_with_advice_that_matches_the_cause() {
        use mvm_agentd::vsock::ReseedShortfall;
        let refusal = |shortfall, detail: &str| {
            let outcome = PostRestoreOutcome {
                acknowledged: true,
                detail: Some(detail.to_string()),
                reseeded: false,
                clock_resynced: true,
                reseed_shortfall: Some(shortfall),
                seccomp_tier: None,
                volumes_mounted: None,
            };
            let err = require_fresh_child_identity("vm-a", &outcome)
                .expect_err("an unreseeded child must be refused");
            assert!(matches!(err, StandbyError::ClaimFailed(_)), "{err}");
            err.to_string()
        };

        let missing = refusal(ReseedShortfall::HelperMissing, "no reseed helper");
        assert!(
            missing.contains("rebuild the image") && missing.contains("no reseed helper"),
            "{missing}"
        );
        assert!(!missing.contains("did not acknowledge"), "{missing}");

        let failed = refusal(ReseedShortfall::Failed, "RNDRESEEDCRNG: EPERM");
        assert!(
            failed.contains("retry") && failed.contains("RNDRESEEDCRNG: EPERM"),
            "{failed}"
        );
        assert!(!failed.contains("rebuild"), "{failed}");
    }

    /// The three fail-closed reasons must stay distinguishable, and the
    /// unverifiable-ledger one must not collapse into either neighbour. It used
    /// to be reported as un-audited, which sends the operator to re-capture a
    /// parent when the real finding is a damaged chain; falling through to
    /// tampered would be the opposite error, blaming a parent that may be fine.
    #[test]
    fn lineage_refusals_separate_an_unreadable_ledger_from_unaudited_and_tampered() {
        let unreadable = anyhow::anyhow!(
            "{}: 1 audit chain(s) unverifiable: /audit-root/local.jsonl",
            crate::lineage::LEDGER_UNVERIFIABLE
        );
        assert!(matches!(
            map_lineage_refusal(&unreadable),
            ClaimRefusal::LedgerUnverifiable
        ));

        let unaudited = anyhow::anyhow!(
            "checkpoint 'cp-1' has {} to anchor its content-address",
            crate::lineage::NO_SIGNED_ENTRY
        );
        assert!(matches!(
            map_lineage_refusal(&unaudited),
            ClaimRefusal::ParentUnaudited
        ));

        let tampered =
            anyhow::anyhow!("checkpoint 'cp-1' meta_digest drift: stored abc, recomputed def");
        assert!(matches!(
            map_lineage_refusal(&tampered),
            ClaimRefusal::ParentTampered
        ));
    }
}
