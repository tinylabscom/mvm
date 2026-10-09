//! Authenticated one-capture retirement. No enumeration or producer recovery.
use super::emitter::AuditEmitter;
use super::evidence::EvidenceReceipt;
use anyhow::{Context, Result, ensure};
use mvm_core::transcript::evidence::authenticated_retirement_at;
#[cfg(test)]
use mvm_core::transcript::evidence::labels;
pub use mvm_core::transcript::evidence::{TRANSCRIPT_RETIRED_EVENT, authenticated_retirement};
use mvm_core::transcript::secure_cleanup::CaptureDirectory;
use mvm_core::transcript::{TranscriptManifest, verify_sealed_root};
use std::path::Path;

#[path = "transcript_pressure.rs"]
mod pressure;
pub use pressure::{BudgetOwner, GenerationReservation, reconcile_pressure};

/// Requested scope is authenticated against the original signed seal.
/// The caller owns discovery and producer-death recovery.
#[derive(Clone, Copy)]
pub struct RetirementContext<'a> {
    pub root: &'a Path,
    pub relative_capture: &'a Path,
    pub capture_id: &'a str,
    pub tenant: &'a str,
    pub vm: &'a str,
    pub emitter: &'a AuditEmitter,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RetirementOutcome {
    LegacyIneligible,
    NotSealed,
    NotDue,
    Retired { removed_segments: usize },
}

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
            && manifest.binding.tenant_id == context.tenant
            && manifest.binding.vm_name == context.vm,
        "managed capture does not match its admitted identity"
    );
    if manifest.at_rest.is_none() {
        return Ok(RetirementOutcome::LegacyIneligible);
    }
    let Some(deadline) = manifest.retention_deadline()? else {
        return Ok(RetirementOutcome::NotSealed);
    };
    manifest.check_retention_clock_at(now)?;
    let (original_seal, already_retired) = authenticated_retirement_at(
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
        let mut entry = original_seal;
        entry.timestamp = chrono::Utc::now();
        entry.event = TRANSCRIPT_RETIRED_EVENT.into();
        entry.labels = pressure::event_labels(&manifest, pressure)?;
        sign(&entry).context("durably signing transcript retirement before unlink")?;
    }
    // The verifier syncs evidence even when already present: visible is not durable.
    ensure!(
        authenticated_retirement(
            context.emitter.audit_dir(),
            &context.emitter.verifying_key(),
            &manifest
        )?,
        "retirement evidence absent after signing"
    );
    let removed_segments = capture.unlink_payload(payload)?;
    Ok(RetirementOutcome::Retired { removed_segments })
}

#[cfg(test)]
#[path = "transcript_retirement_tests.rs"]
mod tests;
