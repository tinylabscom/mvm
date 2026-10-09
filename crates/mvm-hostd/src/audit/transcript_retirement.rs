//! Authenticated one-capture retirement. No enumeration or producer recovery.
use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::VerifyingKey;
use mvm_core::plan::ExecutionPlan;
use mvm_core::transcript::secure_cleanup::CaptureDirectory;
use mvm_core::transcript::{TranscriptManifest, verify_sealed_root};

use super::emitter::AuditEmitter;
use super::evidence::EvidenceReceipt;
use crate::supervisor::audit::{
    LABEL_CAPTURE_ID, LABEL_CHUNK_COUNT, LABEL_TRANSCRIPT_ROOT, LABEL_VM_NAME,
    TRANSCRIPT_SEALED_EVENT, for_plan,
};

pub const TRANSCRIPT_RETIRED_EVENT: &str = "transcript.retired";
const REASON: &str = "sealed_payload_retention_elapsed";

#[path = "transcript_pressure.rs"]
mod pressure;
pub use pressure::{BudgetOwner, GenerationReservation, reconcile_pressure};

/// Caller-selected, known managed capture under a trusted configured root.
/// The caller owns discovery and producer-death recovery; this API never
/// promotes an integrity snapshot to a terminal seal.
#[derive(Clone, Copy)]
pub struct RetirementContext<'a> {
    pub root: &'a Path,
    pub relative_capture: &'a Path,
    pub capture_id: &'a str,
    pub plan: &'a ExecutionPlan,
    pub emitter: &'a AuditEmitter,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RetirementOutcome {
    LegacyIneligible,
    NotSealed,
    NotDue,
    Retired { removed_segments: usize },
}

fn labels(manifest: &TranscriptManifest) -> Result<BTreeMap<String, String>> {
    let policy = manifest
        .at_rest
        .context("legacy capture is not retirement eligible")?;
    let deadline = manifest
        .retention_deadline()?
        .context("capture is not terminally sealed")?;
    Ok([
        (LABEL_CAPTURE_ID.to_string(), manifest.capture_id.clone()),
        (LABEL_VM_NAME.to_string(), manifest.binding.vm_name.clone()),
        (
            LABEL_TRANSCRIPT_ROOT.to_string(),
            manifest.sealed_root_hex.clone(),
        ),
        (
            "retention.payload_after_seal_secs".to_string(),
            policy.payload_after_seal_secs.to_string(),
        ),
        (
            "retention.max_generation_secs".to_string(),
            policy.max_generation_secs.to_string(),
        ),
        (
            "retention.opened_unix_secs".to_string(),
            manifest.created_unix_secs.to_string(),
        ),
        (
            "retention.sealed_unix_secs".to_string(),
            manifest
                .sealed_unix_secs
                .context("missing seal time")?
                .to_string(),
        ),
        (
            "retention.deadline_unix_secs".to_string(),
            deadline.to_string(),
        ),
        ("retention.reason".to_string(), REASON.to_string()),
    ]
    .into())
}

/// Verify the entire host chain, including rotated segments, and require one
/// exact original seal. A matching retirement authorizes idempotent recovery;
/// any duplicate or conflicting record refuses rather than choosing a winner.
/// Matching evidence is synced before it can authorize any unlink.
pub fn authenticated_retirement(
    audit_dir: &Path,
    trusted_key: &VerifyingKey,
    manifest: &TranscriptManifest,
) -> Result<bool> {
    authenticated_retirement_at(audit_dir, trusted_key, manifest, None)
}

fn authenticated_retirement_at(
    audit_dir: &Path,
    trusted_key: &VerifyingKey,
    manifest: &TranscriptManifest,
    now: Option<u64>,
) -> Result<bool> {
    verify_sealed_root(manifest)?;
    let segments = crate::supervisor::audit_set::read_verified_set(
        audit_dir,
        &manifest.binding.tenant_id,
        trusted_key,
    )
    .context("verifying transcript audit chain")?;
    let mut seals = 0;
    let mut retired = 0;
    let expected_chunks = manifest.chunks.len().to_string();
    for segment in segments {
        let mut matched = false;
        for entry in segment.entries.unwrap_or_default() {
            if entry.labels.get(LABEL_CAPTURE_ID) != Some(&manifest.capture_id)
                || !matches!(
                    entry.event.as_str(),
                    TRANSCRIPT_SEALED_EVENT | TRANSCRIPT_RETIRED_EVENT
                )
            {
                continue;
            }
            ensure!(
                entry.tenant.0 == manifest.binding.tenant_id,
                "transcript audit tenant conflict"
            );
            if entry.event == TRANSCRIPT_SEALED_EVENT {
                ensure!(
                    entry.labels.get(LABEL_TRANSCRIPT_ROOT) == Some(&manifest.sealed_root_hex)
                        && entry.labels.get(LABEL_VM_NAME) == Some(&manifest.binding.vm_name)
                        && entry.labels.get(LABEL_CHUNK_COUNT) == Some(&expected_chunks),
                    "conflicting original transcript seal"
                );
                seals += 1;
            } else {
                ensure!(
                    seals == 1,
                    "retirement must follow exactly one original seal"
                );
                pressure::verify_labels(manifest, &entry.labels)?;
                if entry.labels.get("retention.reason").map(String::as_str) == Some(REASON)
                    && let Some(now) = now
                {
                    ensure!(
                        Some(now) >= manifest.retention_deadline()?,
                        "retention clock predates signed expiry"
                    );
                }
                retired += 1;
            }
            matched = true;
        }
        if matched {
            std::fs::File::open(&segment.path)?.sync_all()?;
        }
    }
    ensure!(
        seals == 1,
        "expected exactly one original host-signed transcript seal"
    );
    ensure!(retired <= 1, "duplicate transcript retirement evidence");
    std::fs::File::open(audit_dir)?.sync_all()?;
    Ok(retired == 1)
}

/// Synchronous maintenance door for explicit operator recovery and supervisor
/// ticks. A live writer's exclusive capture lease makes this refuse before
/// audit or payload mutation. The immutable manifest and envelope are retained.
pub fn reconcile_capture(context: RetirementContext<'_>, now: u64) -> Result<RetirementOutcome> {
    reconcile_inner(context, now, None)
}

fn reconcile_inner(
    context: RetirementContext<'_>,
    now: u64,
    pressure: Option<&pressure::PressureEvidence>,
) -> Result<RetirementOutcome> {
    reconcile_with(context, now, pressure, |entry| {
        context
            .emitter
            .emit_entry_for_evidence(entry, EvidenceReceipt::Omitted)?;
        Ok(())
    })
}

fn reconcile_with(
    context: RetirementContext<'_>,
    now: u64,
    pressure: Option<&pressure::PressureEvidence>,
    sign: impl FnOnce(&crate::supervisor::audit::PlanAuditEntry) -> Result<()>,
) -> Result<RetirementOutcome> {
    let capture = CaptureDirectory::open(context.root, context.relative_capture)
        .context("acquiring exclusive managed capture lease")?;
    let manifest = capture.read_manifest()?;
    verify_sealed_root(&manifest)?;
    ensure!(
        manifest.capture_id == context.capture_id
            && manifest.binding.tenant_id == context.plan.tenant.0
            && manifest.binding.vm_name == context.plan.workload.0,
        "managed capture does not match its admitted identity"
    );
    if manifest.at_rest.is_none() {
        return Ok(RetirementOutcome::LegacyIneligible);
    }
    let Some(deadline) = manifest.retention_deadline()? else {
        return Ok(RetirementOutcome::NotSealed);
    };
    if now < manifest.created_unix_secs || manifest.sealed_unix_secs.is_some_and(|seal| now < seal)
    {
        bail!("invalid or backward retention clock");
    }
    let already_retired = authenticated_retirement_at(
        context.emitter.audit_dir(),
        &context.emitter.verifying_key(),
        &manifest,
        Some(now),
    )?;
    if now < deadline && pressure.is_none() && !already_retired {
        return Ok(RetirementOutcome::NotDue);
    }
    let payload = capture
        .prepare_payload(&manifest, already_retired)
        .context("preflighting authenticated ciphertext payload")?;
    if !already_retired {
        let mut entry = for_plan(context.plan, None, TRANSCRIPT_RETIRED_EVENT, []);
        // Free-form plan labels are not retirement metadata.
        entry.labels = pressure::event_labels(&manifest, pressure)?;
        sign(&entry).context("durably signing transcript retirement before unlink")?;
    }
    // Re-read and sync even an existing record: visibility is not durability,
    // and emitters may be inside a larger deferred-sync batch.
    ensure!(
        authenticated_retirement(
            context.emitter.audit_dir(),
            &context.emitter.verifying_key(),
            &manifest,
        )?,
        "retirement evidence absent after signing"
    );
    let removed_segments = capture.unlink_payload(payload)?;
    Ok(RetirementOutcome::Retired { removed_segments })
}

#[cfg(test)]
#[path = "transcript_retirement_tests.rs"]
mod tests;
