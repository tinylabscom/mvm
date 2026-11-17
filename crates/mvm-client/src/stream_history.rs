//! Current-run sealed output, authenticated before any payload is exposed.

use std::collections::BTreeMap;
use std::path::Path;

use ed25519_dalek::VerifyingKey;
use mvm_core::stream_client::{
    OutputLocator, OutputRecord, OutputRequest, StreamError, VmOutputStream, open_sealed_output_at,
};
use mvm_core::transcript::evidence::{LABEL_CAPTURE_ID, TRANSCRIPT_SEALED_EVENT};

use crate::stream_binding::{self, OutputAuditBinding, VerifyOutputBindingError};

/// Trust, exact identity, and retained-window selection for verified readback.
#[derive(Debug, Clone)]
pub struct VerifiedOutputRequest<'a> {
    /// Expected tenant, never inferred from an untrusted manifest.
    pub tenant: &'a str,
    /// Exact plan identifier; aliases and prefixes are not resolved.
    pub plan_id: &'a str,
    /// Existing caller-trusted host public key.
    pub trusted_key: &'a VerifyingKey,
    /// Channel and retained-record window. Follow is refused.
    pub output: OutputRequest,
}

/// Scope of the authenticated snapshot, not complete execution coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedOutputReport {
    /// Current routing identifier, not a canonical epoch.
    pub run: String,
    /// Number of sealed generations authenticated, including empty/retired ones.
    pub generations: usize,
    /// Number of authenticated generations whose payload is unavailable by retention.
    pub retired_generations: usize,
}

/// Verified retained history and its scope; loss/adoption remain on the stream.
pub struct VerifiedOutput {
    stream: VmOutputStream,
    report: VerifiedOutputReport,
}

impl VerifiedOutput {
    /// What was authenticated before exposing the stream.
    pub fn report(&self) -> &VerifiedOutputReport {
        &self.report
    }

    /// Read-only output metadata, including loss and adoption notices.
    pub fn stream(&self) -> &VmOutputStream {
        &self.stream
    }

    /// Deliver the next verified record, rechecking existing retention/custody.
    ///
    /// # Errors
    /// Refuses delivery if retention expires or custody can no longer authenticate.
    pub fn next_output(&mut self) -> Result<Option<OutputRecord>, StreamError> {
        self.stream.next_output()
    }

    /// Consume the verified wrapper, discarding its report/stream pairing.
    pub fn into_stream(self) -> VmOutputStream {
        self.stream
    }
}

/// A refusal to expose current-run output.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifiedOutputError {
    /// Protected capture selection, integrity, or retention authentication failed.
    #[error(transparent)]
    History(#[from] StreamError),
    /// Manifest identity or signed audit binding failed.
    #[error(transparent)]
    Binding(#[from] VerifyOutputBindingError),
    /// A selected capture has no authenticated seal for the exact requested plan.
    #[error("selected protected capture has no authenticated plan-bound seal")]
    Unbound,
}

/// Open only the currently routed protected run, with exact plan authentication.
///
/// No broker connection, console fallback, recovery, signing, or key creation
/// occurs. This is not historical discovery, epoch binding, or a complete-run
/// claim. A compromised trusted host/signer remains outside this guarantee.
///
/// # Errors
/// Refuses missing, legacy, unsealed, invalid, conflicting, or unbound history.
pub fn open_verified_output(
    vm: &str,
    request: VerifiedOutputRequest<'_>,
) -> Result<VerifiedOutput, VerifiedOutputError> {
    mvm_core::crypto::keystore::validate_shell_id(request.tenant)
        .map_err(|_| VerifyOutputBindingError::IdentityMismatch)?;
    mvm_core::naming::validate_vm_name(vm)
        .map_err(|_| VerifyOutputBindingError::IdentityMismatch)?;
    open_verified_output_at(
        &OutputLocator::for_vm(vm),
        &mvm_core::config::mvm_audit_dir().join(format!("{}.jsonl", request.tenant)),
        request,
    )
}

/// Open verified current-run output using explicit storage and audit locations.
///
/// All selected manifests bind against one output-binding chain scan, using the
/// exact immutable snapshots used for reading payloads. Existing retention checks
/// independently authenticate custody at open and at delivery; these may fsync
/// existing audit files/directories, but append nothing and create no keys.
///
/// # Errors
/// Same refusals as [`open_verified_output`], including a malformed audit path.
pub fn open_verified_output_at(
    locator: &OutputLocator,
    audit_path: &Path,
    request: VerifiedOutputRequest<'_>,
) -> Result<VerifiedOutput, VerifiedOutputError> {
    let entries = stream_binding::verified_entries(audit_path, request.trusted_key)?;
    let audit_dir = audit_path
        .parent()
        .ok_or(VerifyOutputBindingError::InvalidAuditPath)?;
    let snapshot = open_sealed_output_at(locator, request.output, audit_dir)?;
    // Index only selected capture ids; unrelated audit entries need no second copy.
    let mut anchors: BTreeMap<&str, Vec<_>> = snapshot
        .manifests()
        .iter()
        .map(|manifest| (manifest.capture_id.as_str(), Vec::new()))
        .collect();
    if anchors.len() != snapshot.manifests().len() {
        return Err(VerifyOutputBindingError::AnchorMismatch.into());
    }
    for entry in &entries {
        if entry.event == TRANSCRIPT_SEALED_EVENT
            && let Some(capture) = entry.labels.get(LABEL_CAPTURE_ID)
            && let Some(selected) = anchors.get_mut(capture.as_str())
        {
            selected.push(entry);
        }
    }
    for manifest in snapshot.manifests() {
        stream_binding::validate_manifest(manifest, request.tenant, request.plan_id, &locator.vm)?;
        let report = stream_binding::evaluate_entries(
            manifest,
            anchors[manifest.capture_id.as_str()].iter().copied(),
            request.tenant,
            request.plan_id,
        )?;
        if report.binding != OutputAuditBinding::Bound {
            return Err(VerifiedOutputError::Unbound);
        }
    }
    Ok(VerifiedOutput {
        report: VerifiedOutputReport {
            run: snapshot.run().to_owned(),
            generations: snapshot.manifests().len(),
            retired_generations: snapshot.retired_generations(),
        },
        stream: snapshot.into_stream(),
    })
}
