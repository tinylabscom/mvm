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
    let unproven = if !outcome.acknowledged {
        "did not acknowledge the post-restore signal"
    } else if !outcome.reseeded {
        "acknowledged without rotating its generation identity"
    } else if !outcome.clock_resynced {
        "acknowledged without resynchronizing its wall clock"
    } else {
        return Ok(());
    };
    Err(StandbyError::ClaimFailed(format!(
        "forked child '{child_vm_name}' {unproven}; refusing to admit a child that cannot prove \
         it left its parent's random state and clock behind"
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
                "without rotating its generation identity",
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
