//! Canonical aggregate pressure proof, shared by writers and read-only verifiers.
use super::evidence::labels;
use super::{GenerationBudget, GenerationFamily, TranscriptManifest};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const PRESSURE_REASON: &str = "generation_byte_pressure";
const PROOF_LABEL: &str = "retention.pressure";

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
pub struct Candidate {
    pub capture_id: String,
    pub root: String,
    pub opened: u64,
    pub plaintext_bytes: u64,
    pub chunks: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PressureEvidence {
    pub budget: GenerationBudget,
    pub candidates: Vec<Candidate>,
    pub incoming: GenerationReservation,
}

impl PressureEvidence {
    pub fn validate(&self, target: &TranscriptManifest) -> Result<()> {
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

pub fn event_labels(
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
