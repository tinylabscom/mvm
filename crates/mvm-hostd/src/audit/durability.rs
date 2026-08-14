//! Whether a run's admission record is a control or a note.
//!
//! The chain proves that nothing was altered among the entries it holds. It
//! cannot notice an entry that was never written, because a missing entry
//! leaves no gap to find — the line after it links to the line before it, and
//! the chain verifies clean. So the only moment the absence of an admission
//! record is observable is the moment the write fails, and the only place that
//! can be turned into a refusal is here.
//!
//! That is the difference between a receipt that is a record and a receipt
//! that is a control. Under [`AuditDurability::Required`], a workload cannot
//! run unless its admission reached the chain; without it, a workload that ran
//! unaudited is afterwards indistinguishable from one that never ran at all.
//!
//! Execution receipts, written by the separate [`crate::audit::receipt_store`],
//! are explicitly records, not controls. They cache signed receipts that were
//! already emitted to the audit chain; a failure to write or persist a receipt
//! is logged and the boot continues. The audit chain remains the source of
//! truth and the only durability boundary that can refuse a run.

use anyhow::{Context, Result};
use mvm_core::plan::ExecutionPlan;

use crate::audit::emitter::AuditEmitter;

/// How a run treats a failure to persist its `plan.admitted` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditDurability {
    /// The boot may not proceed unless the admission reached the chain. A
    /// missing emitter counts as a failure: a run with nowhere to record its
    /// admission has not recorded it.
    Required,
    /// Record the admission if possible; a failure is logged and the boot
    /// continues. Dev runs take this so a broken audit directory is an
    /// annoyance rather than an outage.
    BestEffort,
}

impl AuditDurability {
    /// Resolve from the sealed-production posture — the same
    /// `restrict_agent_verbs` signal the shell-entrypoint refusal keys on,
    /// which is this codebase's existing "non-interactive, non-ad-hoc,
    /// non-dev, sealed image" tier. A run that is trusted enough to be sealed
    /// is a run that has to be able to prove it was admitted.
    pub fn for_sealed_production(sealed: bool) -> Self {
        if sealed {
            Self::Required
        } else {
            Self::BestEffort
        }
    }

    /// True when a failed admission record must refuse the boot.
    pub fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }
}

/// Record a run's admission, applying its durability to the outcome.
///
/// This is the single place the "was it audited?" question is decided, so a
/// caller cannot accidentally reintroduce warn-and-continue on the sealed
/// tier by writing the emit call by hand.
pub fn record_admission(
    emitter: Option<&AuditEmitter>,
    plan: &ExecutionPlan,
    signer_id: &str,
    durability: AuditDurability,
) -> Result<()> {
    let Some(emitter) = emitter else {
        if durability.is_required() {
            anyhow::bail!(
                "this run is sealed-production and has no audit chain to record its \
                 admission in; refusing to boot a workload that cannot be shown to \
                 have been admitted"
            );
        }
        tracing::warn!("no audit emitter wired; admission not recorded");
        return Ok(());
    };

    match emitter.emit_admitted(plan, signer_id) {
        Ok(()) => Ok(()),
        Err(e) if durability.is_required() => Err(e).context(
            "recording the admission in the chain-signed audit log; refusing to boot a \
             sealed-production workload whose admission cannot be proven afterwards",
        ),
        Err(e) => {
            tracing::warn!(error = %e, "audit emit_admitted failed (non-fatal, dev tier)");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn fresh_emitter(dir: &std::path::Path) -> AuditEmitter {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        AuditEmitter::with_dir(SigningKey::from_bytes(&seed), dir).expect("emitter")
    }

    fn plan() -> ExecutionPlan {
        mvm_core::plan::test_support::PlanFixture::new().build()
    }

    #[test]
    fn sealed_production_requires_the_record_and_dev_does_not() {
        assert_eq!(
            AuditDurability::for_sealed_production(true),
            AuditDurability::Required
        );
        assert_eq!(
            AuditDurability::for_sealed_production(false),
            AuditDurability::BestEffort
        );
    }

    #[test]
    fn a_working_chain_records_the_admission_under_either_durability() {
        for durability in [AuditDurability::Required, AuditDurability::BestEffort] {
            let dir = tempfile::tempdir().unwrap();
            let emitter = fresh_emitter(dir.path());
            record_admission(Some(&emitter), &plan(), "host:test", durability)
                .expect("a healthy chain records cleanly");
            let written = std::fs::read_to_string(dir.path().join("local.jsonl")).unwrap();
            assert!(written.contains("plan.admitted"));
        }
    }

    /// The property the whole module exists for: a sealed run whose admission
    /// cannot be written does not proceed.
    #[test]
    fn a_sealed_run_refuses_when_the_admission_cannot_be_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let emitter = fresh_emitter(dir.path());
        // Make the tenant chain unwritable by putting a directory where its
        // file belongs.
        std::fs::create_dir(dir.path().join("local.jsonl")).unwrap();

        let err = record_admission(
            Some(&emitter),
            &plan(),
            "host:test",
            AuditDurability::Required,
        )
        .expect_err("a sealed run must not boot unaudited");
        assert!(
            format!("{err:#}").contains("cannot be proven"),
            "the refusal must say why: {err:#}"
        );
    }

    #[test]
    fn a_dev_run_continues_when_the_admission_cannot_be_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let emitter = fresh_emitter(dir.path());
        std::fs::create_dir(dir.path().join("local.jsonl")).unwrap();

        record_admission(
            Some(&emitter),
            &plan(),
            "host:test",
            AuditDurability::BestEffort,
        )
        .expect("a dev run is not blocked by a broken audit chain");
    }

    /// Having nowhere to record an admission is not better than failing to
    /// record it — a sealed run must refuse both.
    #[test]
    fn a_sealed_run_refuses_when_no_emitter_is_wired() {
        let err = record_admission(None, &plan(), "host:test", AuditDurability::Required)
            .expect_err("no chain is not an excuse");
        assert!(
            format!("{err:#}").contains("no audit chain"),
            "the refusal must name the cause: {err:#}"
        );

        record_admission(None, &plan(), "host:test", AuditDurability::BestEffort)
            .expect("a dev run may boot without a chain");
    }
}
