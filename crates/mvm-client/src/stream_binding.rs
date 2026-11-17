//! Read-only binding of an existing sealed capture to a host-authenticated run.

use std::path::Path;

use ed25519_dalek::VerifyingKey;
use mvm_core::audit_verify::set::{SegmentSetError, verify_segment_entries};
use mvm_core::transcript::evidence::{
    LABEL_CAPTURE_ID, LABEL_CHUNK_COUNT, LABEL_TRANSCRIPT_ROOT, LABEL_VM_NAME,
    TRANSCRIPT_SEALED_EVENT,
};
use mvm_core::transcript::{TranscriptError, TranscriptManifest, verify_sealed_root};
use mvm_hostd::supervisor::audit::signer::LABEL_ADOPTED;

/// Whether the supplied capture has an authenticated anchor for the exact requested run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutputAuditBinding {
    /// The manifest root and all existing seal labels match a signed run-bound anchor.
    Bound,
    /// No matching anchor was available; this says nothing about whether output existed.
    Unbound,
}

/// Audit binding and the sealed capture's declared loss, not complete-run coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OutputBindingReport {
    /// Authentication result under the caller's trusted key and exact run identity.
    pub binding: OutputAuditBinding,
    /// The manifest declares refused/evicted chunks or reconstruction without its writer.
    /// False does not establish that every byte produced by the run was captured.
    pub truncated: bool,
    /// Reconstruction means the loss counters are only a floor.
    pub adopted: bool,
}

/// A refusal to authenticate the supplied output's run binding.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyOutputBindingError {
    /// The manifest's own commitment did not verify.
    #[error("invalid sealed output manifest: {0}")]
    Manifest(#[from] TranscriptError),
    /// The available audit chain could not be authenticated.
    #[error("output audit chain verification failed: {0}")]
    Audit(#[from] SegmentSetError),
    /// The expected identity is empty or disagrees with the manifest.
    #[error("output manifest does not match the expected tenant and vm identity")]
    IdentityMismatch,
    /// A seal for this capture conflicts with the requested run or manifest.
    #[error("conflicting or duplicate output audit anchor")]
    AnchorMismatch,
    /// The supplied audit path cannot identify a chain segment set.
    #[error("output audit path must name a jsonl chain")]
    InvalidAuditPath,
}

/// Verify a supplied sealed manifest against the authenticated audit segment set.
///
/// `audit_path` names the active `<base>.jsonl` file; rotated segments are also
/// verified by the existing audit reader. `trusted_key` must come from the
/// caller's trust authority, not from the untrusted capture. Tenant, exact plan
/// id (never a prefix or image alias), and VM name are explicit expectations.
/// No keys are loaded or minted and no storage is modified.
///
/// Success authenticates only the existing host assertion binding this capture
/// to that plan. It does not prove epoch binding, full-run coverage, payload
/// availability/decryption, or append-only freshness against an earlier view.
/// Chunk bytes are deliberately not opened: use the existing output reader's
/// chunk verification separately. An unbound report is not proof of no output
/// or of anchor absence in an earlier/pruned history. A compromised trusted
/// signer can fabricate assertions.
///
/// # Errors
///
/// Refuses invalid manifest roots, invalid audit chains, identity mismatches,
/// and duplicate or conflicting anchors. Missing audit chains or anchors yield
/// [`OutputAuditBinding::Unbound`], never a binding success.
pub fn verify_output_audit_binding(
    manifest: &TranscriptManifest,
    audit_path: &Path,
    trusted_key: &VerifyingKey,
    tenant: &str,
    plan_id: &str,
    vm_name: &str,
) -> Result<OutputBindingReport, VerifyOutputBindingError> {
    verify_sealed_root(manifest)?;
    if tenant.is_empty()
        || plan_id.is_empty()
        || vm_name.is_empty()
        || manifest.capture_id.is_empty()
        || manifest.binding.tenant_id != tenant
        || manifest.binding.vm_name != vm_name
    {
        return Err(VerifyOutputBindingError::IdentityMismatch);
    }
    let dir = audit_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(VerifyOutputBindingError::InvalidAuditPath)?;
    let base = audit_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .ok_or(VerifyOutputBindingError::InvalidAuditPath)?;
    if audit_path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
        return Err(VerifyOutputBindingError::InvalidAuditPath);
    }
    let entries = match verify_segment_entries(dir, base, trusted_key) {
        Ok(entries) => entries,
        Err(SegmentSetError::NoChain { .. }) => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    let chunk_count = manifest.chunks.len().to_string();
    let adopted = manifest.adopted.to_string();
    let mut binding = OutputAuditBinding::Unbound;
    for entry in entries {
        if entry.event != TRANSCRIPT_SEALED_EVENT
            || entry.labels.get(LABEL_CAPTURE_ID) != Some(&manifest.capture_id)
        {
            continue;
        }
        if binding == OutputAuditBinding::Bound
            || entry.tenant.0 != tenant
            || entry.plan_id.0 != plan_id
            || entry.labels.get(LABEL_VM_NAME) != Some(&manifest.binding.vm_name)
            || entry.labels.get(LABEL_TRANSCRIPT_ROOT) != Some(&manifest.sealed_root_hex)
            || entry.labels.get(LABEL_CHUNK_COUNT) != Some(&chunk_count)
            || entry.labels.get(LABEL_ADOPTED) != Some(&adopted)
        {
            return Err(VerifyOutputBindingError::AnchorMismatch);
        }
        binding = OutputAuditBinding::Bound;
    }
    Ok(OutputBindingReport {
        binding,
        truncated: manifest.is_truncated(),
        adopted: manifest.adopted,
    })
}
