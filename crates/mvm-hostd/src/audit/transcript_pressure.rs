//! Family ownership and destructive pressure reconciliation.
use super::*;
use mvm_core::transcript::GenerationBudget;
use mvm_core::transcript::evidence_pressure::Candidate;
pub use mvm_core::transcript::evidence_pressure::{
    GenerationReservation, PressureEvidence, event_labels,
};
use std::path::PathBuf;

/// Hold through discovery, reservation, append, rotation and retirement.
pub struct BudgetOwner {
    _lease: CaptureDirectory,
    root: PathBuf,
    tenant: String,
    vm: String,
    budget: GenerationBudget,
}

impl BudgetOwner {
    pub fn acquire(root: &Path, tenant: &str, vm: &str, budget: GenerationBudget) -> Result<Self> {
        ensure!(
            budget.max_plaintext_bytes > 0 && budget.max_chunks > 0,
            "empty generation budget"
        );
        Ok(Self {
            _lease: CaptureDirectory::for_writer(root)
                .context("managed family budget is busy or untrusted")?,
            root: root.to_owned(),
            tenant: tenant.to_owned(),
            vm: vm.to_owned(),
            budget,
        })
    }
}

/// The owner must discover all retained enrolled generations while holding the
/// family lease. Only terminal, authenticated manifests enter the accounting.
pub fn reconcile_pressure(
    context: RetirementContext<'_>,
    owner: &BudgetOwner,
    candidates: &[TranscriptManifest],
    incoming: GenerationReservation,
    now: u64,
) -> Result<RetirementOutcome> {
    ensure!(
        context.root == owner.root && context.tenant == owner.tenant && context.vm == owner.vm,
        "budget owner scope mismatch"
    );
    ensure!(candidates.len() <= 4096, "too many pressure candidates");
    let mut proof = PressureEvidence {
        budget: owner.budget,
        candidates: Vec::new(),
        incoming,
    };
    let mut target = None;
    for manifest in candidates {
        ensure!(
            manifest.binding.tenant_id == owner.tenant
                && manifest.binding.vm_name == owner.vm
                && manifest.generation_budget == Some(owner.budget),
            "conflicting generation scope or budget"
        );
        manifest
            .sealed_unix_secs
            .context("pressure cannot retire an active generation")?;
        manifest.check_retention_clock_at(now)?;
        ensure!(
            !authenticated_retirement(
                context.emitter.audit_dir(),
                &context.emitter.verifying_key(),
                manifest
            )?,
            "pressure accounting includes an already retired generation"
        );
        if manifest.capture_id == context.capture_id {
            target = Some(manifest);
        }
        proof.candidates.push(Candidate {
            capture_id: manifest.capture_id.clone(),
            root: manifest.sealed_root_hex.clone(),
            opened: manifest.created_unix_secs,
            plaintext_bytes: manifest.retained_plaintext_bytes()?,
            chunks: manifest.chunks.len() as u64,
        });
    }
    proof
        .candidates
        .sort_by(|a, b| (a.opened, &a.capture_id).cmp(&(b.opened, &b.capture_id)));
    proof.validate(target.context("pressure target missing from authenticated candidates")?)?;
    reconcile_inner(context, now, Some(&proof))
}
