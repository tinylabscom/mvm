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
    AssuranceId, EvidenceRef, HostObservation, MvmBinding, SessionGrant, Sha256Digest,
    TrialOutcome, TrialVerdict,
};
use mvm_core::plan::ExecutionPlan;
use sha2::{Digest, Sha256};

use super::emitter::AuditEmitter;
use super::evidence::{EmittedEvidence, EvidenceReceipt, audit_entry_digest_hex};
use crate::supervisor::PlanAuditEntry;

/// Audit event emitted when a session is opened against an admitted plan.
pub const EVENT_SESSION_OPENED: &str = "assurance.session_opened";
/// Audit event emitted after the guest accepted identity-bound cancellation.
pub const EVENT_SESSION_CANCELED: &str = "assurance.session_canceled";
/// Audit event emitted for one declared probe.
pub const EVENT_PROBE: &str = "assurance.probe";
/// Audit event emitted when the host observer commits its account.
pub const EVENT_OBSERVER_COMPLETED: &str = "assurance.observer_completed";
/// Audit event emitted only after the admitted disposable VM is read back as stopped.
pub const EVENT_CLEANUP_COMPLETED: &str = "assurance.cleanup_completed";
/// Audit event emitted only after a trusted runtime verifier accepts a native quote.
pub const EVENT_ATTESTATION_VERIFIED: &str = "assurance.attestation_verified";
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

/// Public, bounded fields from a runtime attestation verification.
#[derive(Debug, Clone, Copy)]
pub struct AttestationRecord<'a> {
    pub provider: &'a str,
    pub challenge_digest: &'a Sha256Digest,
    pub quote_digest: &'a Sha256Digest,
    pub trust_root_ref: &'a EvidenceRef,
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

/// Re-exported: the wire type now lives in `mvm-contract`, because the
/// carrier (`RegisterVm`) is declared there and its producer sits below this
/// crate.
pub use mvm_contract::assurance::PlanIdentity;

/// Build the entry `identity` would produce for `event`.
///
/// Mirrors `supervisor::for_plan` field for field; it exists separately
/// because that one needs a whole plan and this route has none.
fn entry_for(
    identity: &PlanIdentity,
    event: &str,
    extras: impl IntoIterator<Item = (String, String)>,
) -> PlanAuditEntry {
    let mut labels = identity.audit_labels.clone();
    labels.extend(extras);
    PlanAuditEntry {
        timestamp: chrono::Utc::now(),
        tenant: identity.tenant.clone(),
        plan_id: identity.plan_id.clone(),
        plan_version: identity.plan_version,
        bundle_id: None,
        bundle_version: None,
        image_name: identity.image_name.clone(),
        image_sha256: identity.image_sha256.clone(),
        event: event.to_string(),
        caller_commitment: identity.caller_commitment.clone(),
        labels,
    }
}

/// Derive the identity an admitted plan presents to the ledger.
#[must_use]
pub fn identity_of(plan: &ExecutionPlan) -> PlanIdentity {
    PlanIdentity {
        tenant: plan.tenant.clone(),
        plan_id: plan.plan_id.clone(),
        plan_version: plan.plan_version,
        image_name: plan.image.name.clone(),
        image_sha256: plan.image.sha256.to_ascii_lowercase(),
        caller_commitment: plan.caller_commitment.clone(),
        audit_labels: plan.audit_labels.clone(),
    }
}

/// Where an assurance record is written.
///
/// Two processes need to write these and they do not share an audit route. The
/// supervisor holds an [`AuditEmitter`] and writes chain-signed
/// `PlanAuditEntry` lines with receipts. The broker holds neither — it records
/// through the audit-signer, whose envelope is a category-and-fields document.
/// A trait is the only thing that lets one ledger serve both without the
/// caller choosing a code path per process.
///
/// Receipts are deliberately part of the contract rather than an implementation
/// detail: a sink that cannot write one must say so, because a citation to a
/// receipt nobody wrote reads as proof.
pub trait AssuranceAuditSink {
    /// Record one entry, and its receipt when the caller requires one.
    fn record(&self, entry: &PlanAuditEntry, receipt: EvidenceReceipt) -> Result<EmittedEvidence>;
}

impl AssuranceAuditSink for AuditEmitter {
    fn record(&self, entry: &PlanAuditEntry, receipt: EvidenceReceipt) -> Result<EmittedEvidence> {
        self.emit_entry_for_evidence(entry, receipt)
    }
}

/// Writes the records an assurance campaign cites.
pub struct AssuranceLedger<'a> {
    sink: &'a dyn AssuranceAuditSink,
    identity: &'a PlanIdentity,
}

impl<'a> AssuranceLedger<'a> {
    /// Bind a ledger to one admitted plan's identity, writing through `sink`.
    #[must_use]
    pub fn new(sink: &'a dyn AssuranceAuditSink, identity: &'a PlanIdentity) -> Self {
        Self { sink, identity }
    }

    /// Record that a session opened, and return what a binding may cite.
    ///
    /// Labels carry identifiers and digests only. No prompt bytes, no probe
    /// arguments, and no policy contents cross into the chain.
    pub fn open_session(
        &self,
        identity: &SessionIdentity,
        grant: &SessionGrant,
    ) -> Result<LedgerRefs> {
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
            (
                "assurance_grant_digest".to_string(),
                grant.grant_digest.to_string(),
            ),
            ("assurance_grant_nonce".to_string(), grant.nonce.to_string()),
            (
                "assurance_grant_expires_unix_ms".to_string(),
                grant.expires_unix_ms.to_string(),
            ),
            (
                "assurance_grant_allowed_tools".to_string(),
                serde_json::to_string(&grant.allowed_tools)
                    .context("encoding assurance grant tools")?,
            ),
            (
                "assurance_grant_observation_scopes".to_string(),
                serde_json::to_string(&grant.observation_scopes)
                    .context("encoding assurance grant scopes")?,
            ),
            (
                "assurance_grant_max_steps".to_string(),
                grant.max_steps.to_string(),
            ),
            (
                "assurance_grant_max_output_bytes".to_string(),
                grant.max_output_bytes.to_string(),
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

    /// Record that the guest accepted cancellation for the exact session.
    pub fn record_cancellation(&self, identity: &SessionIdentity) -> Result<LedgerRefs> {
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
        self.emit(EVENT_SESSION_CANCELED, labels, EvidenceReceipt::Required)
    }

    /// Commit the host observer's bounded account and the exact probe records
    /// from which it was derived.
    pub fn record_observation(
        &self,
        identity: &SessionIdentity,
        observation: &HostObservation,
        probe_refs: &[EvidenceRef],
    ) -> Result<LedgerRefs> {
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
            (
                "assurance_attempted_effect".to_string(),
                observation.attempted_effect.to_string(),
            ),
            (
                "assurance_effect_observed_in_guest".to_string(),
                observation.effect_observed_in_guest.to_string(),
            ),
            (
                "assurance_boundary_crossed".to_string(),
                observation.boundary_crossed.to_string(),
            ),
            (
                "assurance_blocked_edges".to_string(),
                serde_json::to_string(&observation.blocked_edges)
                    .context("encoding observer blocked edges")?,
            ),
            (
                "assurance_probe_refs".to_string(),
                serde_json::to_string(probe_refs).context("encoding observer probe references")?,
            ),
        ];
        self.emit(EVENT_OBSERVER_COMPLETED, labels, EvidenceReceipt::Required)
    }

    /// Commit host-confirmed teardown of the disposable trial target.
    pub fn record_cleanup(&self, identity: &SessionIdentity) -> Result<LedgerRefs> {
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
            (
                "assurance_cleanup_status".to_string(),
                "confirmed_stopped".to_string(),
            ),
        ];
        self.emit(EVENT_CLEANUP_COMPLETED, labels, EvidenceReceipt::Required)
    }

    /// Commit a verified native quote without storing the quote bytes.
    pub fn record_attestation(
        &self,
        identity: &SessionIdentity,
        attestation: &AttestationRecord<'_>,
    ) -> Result<LedgerRefs> {
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
            (
                "assurance_attestation_provider".to_string(),
                attestation.provider.to_string(),
            ),
            (
                "assurance_attestation_challenge_digest".to_string(),
                attestation.challenge_digest.to_string(),
            ),
            (
                "assurance_attestation_quote_digest".to_string(),
                attestation.quote_digest.to_string(),
            ),
            (
                "assurance_attestation_trust_root".to_string(),
                attestation.trust_root_ref.to_string(),
            ),
        ];
        self.emit(
            EVENT_ATTESTATION_VERIFIED,
            labels,
            EvidenceReceipt::Required,
        )
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
        let entry = entry_for(self.identity, event, labels);
        let emitted = self
            .sink
            .record(&entry, receipt)
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

/// A sink that records through the audit-signer, for a process holding no
/// [`AuditEmitter`] — which is every broker.
///
/// # What this sink cannot do
///
/// It cannot write a receipt. Receipts are appended by the emitter's receipt
/// store, and the broker has none, so [`EvidenceReceipt::Required`] is an
/// error here rather than a silent `receipt_id: None`. That is the whole point
/// of putting receipts in the trait: the split between what each process may
/// record is enforced, not remembered. Probes are audit-only and ride this
/// sink; session open and trial completion carry receipts and stay with the
/// supervisor.
pub struct SignerSink {
    client: crate::broker::audit_client::AuditClient,
    workload_id: String,
    tenant_id: String,
    session_id: String,
}

impl SignerSink {
    /// Bind a sink to one workload's audit route.
    #[must_use]
    pub fn new(
        client: crate::broker::audit_client::AuditClient,
        workload_id: impl Into<String>,
        tenant_id: impl Into<String>,
        session_id: impl Into<String>,
    ) -> Self {
        Self {
            client,
            workload_id: workload_id.into(),
            tenant_id: tenant_id.into(),
            session_id: session_id.into(),
        }
    }

    /// The category every assurance record is appended under.
    pub const CATEGORY: &'static str = "assurance";
}

impl AssuranceAuditSink for SignerSink {
    fn record(&self, entry: &PlanAuditEntry, receipt: EvidenceReceipt) -> Result<EmittedEvidence> {
        if matches!(receipt, EvidenceReceipt::Required) {
            anyhow::bail!(
                "the audit-signer sink cannot write a receipt for {}; \
                 receipt-bearing records belong to the process holding the emitter",
                entry.event
            );
        }

        // The digest still covers the `PlanAuditEntry`, so a reference minted
        // here names the same logical record the emitter would have named. The
        // signer's chain stores it inside `fields`, which is what a resolver
        // reads on this route.
        let audit_digest = super::evidence::audit_entry_digest_hex(entry)?;
        let fields = serde_json::to_value(entry).context("encoding the assurance entry")?;
        let request = mvm_core::protocol::audit_signer::AppendEntryRequest::AppendEntry {
            request_id: format!("assurance-{audit_digest}"),
            category: Self::CATEGORY.to_string(),
            ts: entry.timestamp.to_rfc3339(),
            workload_id: self.workload_id.clone(),
            tenant_id: self.tenant_id.clone(),
            session_id: self.session_id.clone(),
            correlation_id: format!("assurance-{}", entry.event),
            fields,
        };

        // The ledger is synchronous and the client is not. Mirrors the
        // emitter's own bridge: block on a scoped thread when a runtime is
        // already present, because blocking inside one is a tokio panic.
        let append = || -> Result<()> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("building a runtime for the assurance audit append")?;
            runtime
                .block_on(self.client.append(&request))
                .map(|_| ())
                .context("appending the assurance entry through the audit-signer")
        };
        if tokio::runtime::Handle::try_current().is_ok() {
            std::thread::scope(|scope| {
                scope
                    .spawn(append)
                    .join()
                    .map_err(|_| anyhow::anyhow!("assurance audit append thread panicked"))?
            })?;
        } else {
            append()?;
        }

        Ok(EmittedEvidence {
            audit_digest,
            receipt_id: None,
        })
    }
}

#[cfg(test)]
mod sink_tests {
    use super::*;
    use mvm_core::plan::TenantId;

    fn entry(event: &str) -> PlanAuditEntry {
        PlanAuditEntry {
            timestamp: chrono::Utc::now(),
            tenant: TenantId("local".to_string()),
            plan_id: mvm_core::plan::PlanId("plan-1".to_string()),
            plan_version: 1,
            bundle_id: None,
            bundle_version: None,
            image_name: "vm".to_string(),
            image_sha256: "a".repeat(64),
            event: event.to_string(),
            caller_commitment: None,
            labels: Default::default(),
        }
    }

    fn sink() -> SignerSink {
        // The path is never dialled: `Required` is refused before any I/O.
        SignerSink::new(
            crate::broker::audit_client::AuditClient::new("/nonexistent/audit.sock"),
            "workload",
            "local",
            "session-1",
        )
    }

    #[test]
    fn the_signer_sink_refuses_a_record_it_cannot_receipt() {
        // The split between what each process may record is enforced here
        // rather than remembered at the call site: a broker claiming a receipt
        // it never wrote is the failure this trait exists to make impossible.
        let error = sink()
            .record(
                &entry("assurance.session_opened"),
                EvidenceReceipt::Required,
            )
            .expect_err("a sink with no receipt store must refuse");
        let text = format!("{error:#}");
        assert!(text.contains("cannot write a receipt"), "{text}");
        assert!(text.contains("assurance.session_opened"), "{text}");
    }

    #[test]
    fn the_signer_sink_refuses_before_it_dials_anything() {
        // The socket does not exist, so a sink that attempted the append would
        // fail with a connection error instead — which would mean the refusal
        // above was incidental rather than a rule.
        let error = format!(
            "{:#}",
            sink()
                .record(
                    &entry("assurance.trial_completed"),
                    EvidenceReceipt::Required
                )
                .expect_err("refused")
        );
        assert!(
            !error.contains("nonexistent"),
            "it dialled the socket: {error}"
        );
    }

    #[test]
    fn both_sinks_agree_on_the_reference_a_record_earns() {
        // A reference minted on either route names the same logical record, so
        // a campaign's citations do not change meaning with the process that
        // happened to write them.
        let entry = entry("assurance.probe");
        let expected = super::super::evidence::audit_entry_digest_hex(&entry).expect("digest");

        let dir = tempfile::tempdir().expect("tempdir");
        let emitter = AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&[51u8; 32]),
            dir.path(),
        )
        .expect("emitter");
        let via_emitter = emitter
            .record(&entry, EvidenceReceipt::Omitted)
            .expect("emitter records");
        assert_eq!(via_emitter.audit_digest, expected);
        assert!(via_emitter.receipt_id.is_none());
    }
}
