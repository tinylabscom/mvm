//! The assurance ledger: what a campaign may later cite as evidence.
//!
//! An assurance outcome is only as good as the records behind it, so this
//! module exists to make the citations in an [`MvmBinding`] real. Every
//! reference it hands back was produced by an emit that succeeded — the
//! emitter's ordinary path treats receipts as a derived cache and swallows
//! their errors, which is right when nothing cites them and wrong here.
//!
//! # References resolve
//!
//! An audit reference is `mvm:audit:<hex>`, where the hex is SHA-256 of the
//! exact bytes the entry was signed as. The envelope stores those same bytes in
//! its `canonical` field, so [`resolve_audit_ref`] can find the line by
//! hashing what is on disk. A reference that cannot be resolved is a reference
//! that should never have been written, and the round-trip is asserted by test
//! rather than assumed.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_contract::assurance::{
    AssuranceId, EvidenceRef, MvmBinding, Sha256Digest, TrialOutcome, TrialVerdict,
};
use mvm_core::plan::ExecutionPlan;
use sha2::{Digest, Sha256};

use super::emitter::AuditEmitter;
use super::evidence::{EmittedEvidence, EvidenceReceipt, audit_entry_digest_hex};
use crate::supervisor::{PlanAuditEntry, for_plan};

/// Audit event emitted when a session is opened against an admitted plan.
pub const EVENT_SESSION_OPENED: &str = "assurance.session_opened";
/// Audit event emitted for one declared probe.
pub const EVENT_PROBE: &str = "assurance.probe";
/// Audit event emitted when a trial's outcome is derived.
pub const EVENT_TRIAL_COMPLETED: &str = "assurance.trial_completed";

/// Build the resolvable reference for an audit entry.
pub fn audit_ref(entry: &PlanAuditEntry) -> Result<EvidenceRef> {
    let digest = audit_entry_digest_hex(entry)?;
    EvidenceRef::parse(format!("mvm:audit:{digest}"))
        .map_err(|error| anyhow::anyhow!("audit reference is not well formed: {error}"))
}

/// Build the reference for a receipt content address.
pub fn receipt_ref(receipt_id: &str) -> Result<EvidenceRef> {
    EvidenceRef::parse(format!("mvm:receipt:{receipt_id}"))
        .map_err(|error| anyhow::anyhow!("receipt reference is not well formed: {error}"))
}

/// Find the audit entry a reference names, by hashing what is on disk.
///
/// Returns `Ok(None)` when the chain holds no matching line — which is the
/// answer a verifier needs, and is distinct from a malformed chain.
pub fn resolve_audit_ref(chain_path: &Path, reference: &EvidenceRef) -> Result<Option<String>> {
    let Some(want) = reference.as_str().strip_prefix("mvm:audit:") else {
        return Ok(None);
    };
    let body = std::fs::read_to_string(chain_path)
        .with_context(|| format!("reading audit chain {}", chain_path.display()))?;
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        let envelope: serde_json::Value =
            serde_json::from_str(line).context("parsing an audit chain line")?;
        // Prefer the exact signed bytes the envelope carries; fall back to
        // re-serializing for lines written before `canonical` existed.
        let bytes = match envelope
            .get("canonical")
            .and_then(serde_json::Value::as_str)
        {
            Some(encoded) => {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(encoded)
                    .context("decoding an audit line's canonical bytes")?
            }
            None => serde_json::to_vec(
                envelope
                    .get("entry")
                    .ok_or_else(|| anyhow::anyhow!("audit line carries no entry"))?,
            )
            .context("re-serializing an audit entry")?,
        };
        if hex::encode(Sha256::digest(&bytes)) == want {
            return Ok(Some(line.to_string()));
        }
    }
    Ok(None)
}

/// Identity one assurance session runs under.
#[derive(Debug, Clone)]
pub struct SessionIdentity {
    pub session_id: AssuranceId,
    pub campaign_id: AssuranceId,
    pub trial_id: AssuranceId,
    pub source_digest: Sha256Digest,
}

/// What an emit produced, in the form a binding cites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRefs {
    pub audit: EvidenceRef,
    pub receipt: Option<EvidenceRef>,
}

impl LedgerRefs {
    fn from_emitted(entry: &PlanAuditEntry, emitted: &EmittedEvidence) -> Result<Self> {
        let _ = entry;
        let audit = EvidenceRef::parse(format!("mvm:audit:{}", emitted.audit_digest))
            .map_err(|error| anyhow::anyhow!("audit reference is not well formed: {error}"))?;
        let receipt = match &emitted.receipt_id {
            Some(id) => Some(receipt_ref(id)?),
            None => None,
        };
        Ok(Self { audit, receipt })
    }
}

/// Writes the records an assurance campaign cites.
pub struct AssuranceLedger<'a> {
    emitter: &'a AuditEmitter,
    plan: &'a ExecutionPlan,
}

impl<'a> AssuranceLedger<'a> {
    /// Bind a ledger to one admitted plan.
    #[must_use]
    pub fn new(emitter: &'a AuditEmitter, plan: &'a ExecutionPlan) -> Self {
        Self { emitter, plan }
    }

    /// Record that a session opened, and return what a binding may cite.
    ///
    /// Labels carry identifiers and digests only. No prompt bytes, no probe
    /// arguments, and no policy contents cross into the chain.
    pub fn open_session(&self, identity: &SessionIdentity) -> Result<LedgerRefs> {
        let labels = [
            (
                "assurance_session".to_string(),
                identity.session_id.to_string(),
            ),
            (
                "assurance_campaign".to_string(),
                identity.campaign_id.to_string(),
            ),
            ("assurance_trial".to_string(), identity.trial_id.to_string()),
            (
                "assurance_source_digest".to_string(),
                identity.source_digest.to_string(),
            ),
        ];
        self.emit(EVENT_SESSION_OPENED, labels, EvidenceReceipt::Required)
    }

    /// Record one probe decision.
    ///
    /// `decision` is the closed token the host produced (`allowed`,
    /// `deny_all`, `not_in_allowlist`), never a message and never the
    /// destination behind the label.
    pub fn record_probe(&self, probe: &ProbeRecord<'_>) -> Result<LedgerRefs> {
        let labels = [
            (
                "assurance_session".to_string(),
                probe.session_id.to_string(),
            ),
            ("assurance_trial".to_string(), probe.trial_id.to_string()),
            ("assurance_probe".to_string(), probe.probe_id.to_string()),
            ("assurance_decision".to_string(), probe.decision.to_string()),
            (
                "assurance_idempotency_key".to_string(),
                probe.idempotency_key.to_string(),
            ),
            ("assurance_admitted".to_string(), probe.admitted.to_string()),
            (
                "assurance_edge".to_string(),
                probe.destination_label.to_string(),
            ),
        ];
        // Audit only: a probe is fine-grained, and the receipt a campaign
        // publishes is the trial's, not each attempt's.
        self.emit(EVENT_PROBE, labels, EvidenceReceipt::Omitted)
    }

    /// Record the derived outcome of a trial.
    ///
    /// The reason is recorded for every non-claim outcome, so a later reader
    /// can tell "we proved nothing because the observer was missing" from
    /// "we proved nothing because the model contradicted it".
    pub fn complete_trial(
        &self,
        identity: &SessionIdentity,
        verdict: &TrialVerdict,
    ) -> Result<LedgerRefs> {
        let mut labels = vec![
            (
                "assurance_session".to_string(),
                identity.session_id.to_string(),
            ),
            (
                "assurance_campaign".to_string(),
                identity.campaign_id.to_string(),
            ),
            ("assurance_trial".to_string(), identity.trial_id.to_string()),
            (
                "assurance_outcome".to_string(),
                verdict.outcome.as_str().to_string(),
            ),
            (
                "assurance_certifying".to_string(),
                verdict.outcome.is_certifying_claim().to_string(),
            ),
        ];
        if let Some(reason) = verdict.reason {
            labels.push((
                "assurance_reason".to_string(),
                serde_json::to_value(reason)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_string))
                    .unwrap_or_else(|| "unknown".to_string()),
            ));
        }
        self.emit(EVENT_TRIAL_COMPLETED, labels, EvidenceReceipt::Required)
    }

    fn emit<I>(&self, event: &str, labels: I, receipt: EvidenceReceipt) -> Result<LedgerRefs>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let entry = for_plan(self.plan, None, event, labels);
        let emitted = self
            .emitter
            .emit_entry_for_evidence(&entry, receipt)
            .with_context(|| format!("emitting assurance event {event}"))?;
        LedgerRefs::from_emitted(&entry, &emitted)
    }
}

/// One probe's audit-visible facts.
#[derive(Debug, Clone)]
pub struct ProbeRecord<'a> {
    pub session_id: &'a AssuranceId,
    pub trial_id: &'a AssuranceId,
    pub probe_id: &'a str,
    pub decision: &'a str,
    pub idempotency_key: &'a AssuranceId,
    pub admitted: bool,
    /// The declared label that was probed. The label is a synthetic
    /// identifier; what it resolves to stays host-side, so recording it ties
    /// the entry to a blocked edge without naming a destination.
    pub destination_label: &'a AssuranceId,
}

/// Attach ledger references to a binding under construction.
///
/// A binding refuses to build without at least one audit and one receipt
/// reference, so this is the step that makes an assurance session bindable at
/// all: no successful emit, no session.
pub fn cite(
    builder: mvm_contract::assurance::MvmBindingBuilder,
    refs: &LedgerRefs,
) -> mvm_contract::assurance::MvmBindingBuilder {
    let builder = builder.audit_ref(refs.audit.clone());
    match &refs.receipt {
        Some(receipt) => builder.receipt_ref(receipt.clone()),
        None => builder,
    }
}

/// Whether a binding's citations all resolve against `chain_path`.
///
/// Receipts are content-addressed and verified by their own store, so this
/// checks the audit half — the half whose reference is only as good as the
/// bytes it was derived from.
pub fn audit_citations_resolve(binding: &MvmBinding, chain_path: &Path) -> Result<bool> {
    for reference in &binding.audit_refs {
        if resolve_audit_ref(chain_path, reference)?.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether an outcome is one a campaign may publish as a claim.
#[must_use]
pub fn is_publishable_claim(outcome: TrialOutcome) -> bool {
    outcome.is_certifying_claim()
}
