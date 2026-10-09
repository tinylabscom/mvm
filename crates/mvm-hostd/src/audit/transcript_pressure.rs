//! Aggregate budget authorization, kept separate from age retirement.
use super::*;
use mvm_core::transcript::{GenerationBudget, GenerationFamily};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;

const PRESSURE_REASON: &str = "generation_byte_pressure";
const PROOF_LABEL: &str = "retention.pressure";

/// Exclusive family-level owner. Hold through discovery, reservations, append,
/// rotation and retirement. Every cooperating owner must use the same root.
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

/// Capacity for the next encoded plaintext admission, not a caller-supplied
/// retained total. The owner must reserve before enqueueing durable work.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationReservation {
    pub plaintext_bytes: u64,
    pub chunks: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    capture_id: String,
    root: String,
    opened: u64,
    plaintext_bytes: u64,
    chunks: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PressureEvidence {
    budget: GenerationBudget,
    candidates: Vec<Candidate>,
    incoming: GenerationReservation,
}

impl PressureEvidence {
    fn validate(&self, target: &TranscriptManifest) -> Result<()> {
        ensure!(
            target.generation_budget == Some(self.budget),
            "generation budget policy conflict"
        );
        ensure!(
            self.budget.family == GenerationFamily::WorkloadOutput,
            "unsupported generation family"
        );
        ensure!(
            !self.candidates.is_empty() && self.candidates.len() <= 4096,
            "invalid pressure candidate count"
        );
        ensure!(
            self.incoming.plaintext_bytes > 0
                && self.incoming.chunks > 0
                && self.incoming.plaintext_bytes <= self.budget.max_plaintext_bytes
                && self.incoming.chunks <= self.budget.max_chunks,
            "invalid generation reservation"
        );
        let mut ids = BTreeSet::new();
        let mut bytes = self.incoming.plaintext_bytes;
        let mut chunks = self.incoming.chunks;
        let mut previous = None;
        for candidate in &self.candidates {
            ensure!(
                ids.insert(&candidate.capture_id),
                "duplicate pressure candidate"
            );
            let order = (candidate.opened, candidate.capture_id.as_str());
            ensure!(
                previous.is_none_or(|previous| previous <= order),
                "pressure candidates not oldest first"
            );
            previous = Some(order);
            ensure!(
                candidate.root.len() == 64 && candidate.root.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid candidate root"
            );
            bytes = bytes
                .checked_add(candidate.plaintext_bytes)
                .context("pressure byte accounting overflow")?;
            chunks = chunks
                .checked_add(candidate.chunks)
                .context("pressure chunk accounting overflow")?;
        }
        ensure!(
            bytes > self.budget.max_plaintext_bytes || chunks > self.budget.max_chunks,
            "authenticated generation accounting does not require retirement"
        );
        let first = &self.candidates[0];
        ensure!(
            first.capture_id == target.capture_id
                && first.root == target.sealed_root_hex
                && first.plaintext_bytes == target.retained_plaintext_bytes()?
                && first.chunks == target.chunks.len() as u64,
            "retirement target is not the oldest authenticated generation"
        );
        Ok(())
    }
}

/// Retire only the oldest sealed generation to make a checked reservation fit.
/// Seal/anchor the active generation before calling: snapshots are not authority.
/// The caller must discover all retained enrolled generations under the held
/// family owner, and keep reservations serialized through durable enqueue.
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
        let sealed = manifest
            .sealed_unix_secs
            .context("pressure cannot retire an active generation")?;
        ensure!(
            now >= sealed && now >= manifest.created_unix_secs,
            "backward pressure clock"
        );
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

pub(super) fn event_labels(
    manifest: &TranscriptManifest,
    pressure: Option<&PressureEvidence>,
) -> Result<BTreeMap<String, String>> {
    let mut result = labels(manifest)?;
    if let Some(proof) = pressure {
        proof.validate(manifest)?;
        result.insert("retention.reason".into(), PRESSURE_REASON.into());
        result.insert(PROOF_LABEL.into(), serde_json::to_string(proof)?);
    }
    Ok(result)
}

pub(super) fn verify_labels(
    manifest: &TranscriptManifest,
    actual: &BTreeMap<String, String>,
) -> Result<()> {
    let proof: Option<PressureEvidence> = actual
        .get(PROOF_LABEL)
        .map(|raw| {
            ensure!(
                raw.len() <= 2 * 1024 * 1024,
                "pressure proof exceeds bounded size"
            );
            Ok(serde_json::from_str(raw)?)
        })
        .transpose()?;
    ensure!(
        *actual == event_labels(manifest, proof.as_ref())?,
        "conflicting transcript retirement"
    );
    Ok(())
}
