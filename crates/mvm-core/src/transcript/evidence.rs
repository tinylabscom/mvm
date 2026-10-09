//! Read-only authenticated capture evidence, independent of host signers.
use std::collections::BTreeMap;
use std::path::Path;

use super::evidence_pressure as pressure;
use super::{TranscriptManifest, verify_sealed_root};
use crate::audit_verify::PlanAuditEntry;
use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;

pub const TRANSCRIPT_SEALED_EVENT: &str = "gateway.transcript_sealed";
pub const TRANSCRIPT_OPENED_EVENT: &str = "transcript.opened";
pub const LABEL_CAPTURE_ID: &str = "capture_id";
pub const LABEL_VM_NAME: &str = "vm_name";
pub const LABEL_TRANSCRIPT_ROOT: &str = "transcript_root";
pub const LABEL_CHUNK_COUNT: &str = "chunk_count";
pub const TRANSCRIPT_RETIRED_EVENT: &str = "transcript.retired";
const REASON: &str = "sealed_payload_retention_elapsed";

/// Canonical empty seed commitment; no free-form plan labels are permitted.
pub fn opening_labels(seed: &TranscriptManifest) -> Result<BTreeMap<String, String>> {
    verify_sealed_root(seed)?;
    ensure!(
        seed.at_rest.is_some()
            && seed.sealed_unix_secs.is_none()
            && seed.chunks.is_empty()
            && !seed.adopted
            && seed.refused_chunks == 0
            && seed.refused_bytes == 0
            && seed.evicted_chunks == 0
            && seed.evicted_bytes == 0,
        "opening authority requires an empty protected seed"
    );
    seed.check_retention_clock_at(seed.created_unix_secs)?;
    Ok([
        (LABEL_CAPTURE_ID.into(), seed.capture_id.clone()),
        (LABEL_VM_NAME.into(), seed.binding.vm_name.clone()),
        (LABEL_TRANSCRIPT_ROOT.into(), seed.sealed_root_hex.clone()),
    ]
    .into())
}

/// Verify original admission attribution for an abandoned generation. This is
/// not terminal-seal or deletion authority. The lifecycle owner must separately
/// establish producer quiescence/death before recovering the supplied seed.
pub fn authenticate_opening(
    audit_dir: &Path,
    trusted_key: &VerifyingKey,
    seed: &TranscriptManifest,
) -> Result<PlanAuditEntry> {
    let expected = opening_labels(seed)?;
    let segments = crate::audit_verify::set::read_verified_set(
        audit_dir,
        &seed.binding.tenant_id,
        trusted_key,
    )?;
    let mut opening = None;
    for segment in segments {
        let mut matched = false;
        for entry in segment.entries.unwrap_or_default() {
            if entry.event != TRANSCRIPT_OPENED_EVENT
                || entry.labels.get(LABEL_CAPTURE_ID) != Some(&seed.capture_id)
            {
                continue;
            }
            ensure!(opening.is_none(), "duplicate original transcript opening");
            ensure!(
                entry.tenant.0 == seed.binding.tenant_id && entry.labels == expected,
                "conflicting original transcript opening"
            );
            opening = Some(entry);
            matched = true;
        }
        if matched {
            std::fs::File::open(&segment.path)?.sync_all()?;
        }
    }
    std::fs::File::open(audit_dir)?.sync_all()?;
    opening.context("expected exactly one original host-signed transcript opening")
}

/// Build a recovered terminal entry only from authenticated opening attribution.
/// The caller must hold lifecycle ownership and establish producer death or
/// quiescence before recovery; neither a clock deadline nor this proof does so.
pub fn recovered_seal_entry(
    audit_dir: &Path,
    trusted_key: &VerifyingKey,
    seed: &TranscriptManifest,
    recovered: &TranscriptManifest,
) -> Result<PlanAuditEntry> {
    verify_sealed_root(recovered)?;
    ensure!(
        recovered.adopted && recovered.retention_deadline()?.is_some(),
        "recovered seal requires terminal incomplete manifest"
    );
    let mut original = recovered.clone();
    original.chunks.clear();
    original.sealed_unix_secs = None;
    original.adopted = false;
    original.refused_chunks = 0;
    original.refused_bytes = 0;
    original.evicted_chunks = 0;
    original.evicted_bytes = 0;
    original.sealed_root_hex = super::sealed_root_hex(&original)?;
    ensure!(
        &original == seed,
        "recovery changed original capture configuration"
    );
    let mut entry = authenticate_opening(audit_dir, trusted_key, seed)?;
    entry.timestamp = chrono::Utc::now();
    entry.event = TRANSCRIPT_SEALED_EVENT.into();
    entry.labels = [
        (LABEL_CAPTURE_ID.into(), recovered.capture_id.clone()),
        (LABEL_VM_NAME.into(), recovered.binding.vm_name.clone()),
        (
            LABEL_TRANSCRIPT_ROOT.into(),
            recovered.sealed_root_hex.clone(),
        ),
        (LABEL_CHUNK_COUNT.into(), recovered.chunks.len().to_string()),
        ("adopted".into(), "true".into()),
    ]
    .into();
    Ok(entry)
}

pub fn labels(manifest: &TranscriptManifest) -> Result<BTreeMap<String, String>> {
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
    authenticated_retirement_at(audit_dir, trusted_key, manifest, None).map(|proof| proof.1)
}

pub fn authenticated_retirement_at(
    audit_dir: &Path,
    trusted_key: &VerifyingKey,
    manifest: &TranscriptManifest,
    now: Option<u64>,
) -> Result<(PlanAuditEntry, bool)> {
    verify_sealed_root(manifest)?;
    let segments = crate::audit_verify::set::read_verified_set(
        audit_dir,
        &manifest.binding.tenant_id,
        trusted_key,
    )
    .context("verifying transcript audit chain")?;
    let mut seal = None;
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
                ensure!(seal.is_none(), "duplicate original transcript seal");
                seal = Some(entry.clone());
            } else {
                let mut expected = seal
                    .clone()
                    .context("retirement must follow exactly one original seal")?;
                expected.timestamp = entry.timestamp;
                expected.event = entry.event.clone();
                expected.labels = entry.labels.clone();
                ensure!(
                    entry == expected,
                    "retirement attribution differs from original seal"
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
    let seal = seal.context("expected exactly one original host-signed transcript seal")?;
    ensure!(retired <= 1, "duplicate transcript retirement evidence");
    std::fs::File::open(audit_dir)?.sync_all()?;
    Ok((seal, retired == 1))
}
