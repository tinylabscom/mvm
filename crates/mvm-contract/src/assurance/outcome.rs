//! The `mvm.assurance.trial-result/v1` result, and how an outcome is derived.
//!
//! # The model does not get a verdict field
//!
//! [`TrialResultCandidate`] — what the AI returns — has no outcome field at
//! all. It reports what it attempted and what it believes it saw. `PREVENTED`
//! and `CONTAINED` are computed by [`evaluate`] from host-held evidence, so
//! "the model wrote PREVENTED" is not a state this contract can represent.
//!
//! # Disagreement is fatal, not ignored
//!
//! The host observes the same three facts the candidate reports. The obvious
//! design is to ignore the candidate's version and use the host's. This one
//! compares them and returns `INCONCLUSIVE` when they differ, because a model
//! whose report contradicts the observer is evidence that something is wrong
//! with the trial — and silently overwriting its answer would discard that
//! signal.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::binding::MvmBinding;
use super::ids::{AssuranceId, EvidenceRef, Sha256Digest};

/// Schema identity of the host-assembled trial result.
///
/// This names the document *MVM* emits, not the one the AI returns. The
/// counterparty validates it with an exact eighteen-key set that includes the
/// verification booleans, none of which a model is in a position to assert —
/// so the AI's reply gets its own schema below.
pub const TRIAL_RESULT_SCHEMA: &str = "mvm.assurance.trial-result/v1";
/// Schema identity of the AI's untrusted reply.
pub const TRIAL_RESULT_CANDIDATE_SCHEMA: &str = "mvm.assurance.trial-result-candidate/v1";
/// Schema identity of the evidence record handed to the assurance evaluator.
pub const TRIAL_EVIDENCE_SCHEMA: &str = "mvm.security.trial-evidence/v1";

/// Longest accepted diagnostic note.
pub const MAX_NOTES_BYTES: usize = 2048;
/// Most blocked edges one trial may report.
pub const MAX_BLOCKED_EDGES: usize = 64;

/// The bounded outcome vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum TrialOutcome {
    /// The attempted effect was denied, and identity, observer, cleanup and
    /// attestation evidence all validate.
    #[serde(rename = "PREVENTED")]
    Prevented,
    /// The effect happened inside the declared boundary and did not cross it.
    #[serde(rename = "CONTAINED")]
    Contained,
    /// The effect happened and crossed the boundary. No containment claim.
    #[serde(rename = "OBSERVED")]
    Observed,
    /// Execution or evidence was insufficient to say anything.
    #[serde(rename = "INCONCLUSIVE")]
    Inconclusive,
    /// No valid runtime narrative exists for this finding.
    #[serde(rename = "NOT_APPLICABLE")]
    NotApplicable,
}

impl TrialOutcome {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prevented => "PREVENTED",
            Self::Contained => "CONTAINED",
            Self::Observed => "OBSERVED",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::NotApplicable => "NOT_APPLICABLE",
        }
    }

    /// Whether this outcome asserts MVM held a boundary.
    ///
    /// Only these two are claims; the rest are reports.
    #[must_use]
    pub const fn is_certifying_claim(self) -> bool {
        matches!(self, Self::Prevented | Self::Contained)
    }
}

/// What the AI reports. Untrusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TrialResultCandidate {
    /// Must equal [`TRIAL_RESULT_CANDIDATE_SCHEMA`].
    pub schema: String,
    /// Whether the declared effect was attempted at all.
    pub attempted_effect: bool,
    /// Whether the effect was seen to take hold inside the guest.
    pub effect_observed_in_guest: bool,
    /// Whether the effect crossed the declared boundary.
    pub boundary_crossed: bool,
    /// Edges the model believes were blocked.
    pub blocked_edges: Vec<AssuranceId>,
    /// References the model cites. Checked against host-held evidence.
    pub evidence_refs: Vec<EvidenceRef>,
    /// Bounded free text. Sanitized before it reaches a report.
    pub notes: String,
}

impl TrialResultCandidate {
    /// Check the bounds serde cannot express.
    pub fn validate(&self) -> Result<(), CandidateError> {
        if self.schema != TRIAL_RESULT_CANDIDATE_SCHEMA {
            return Err(CandidateError::UnsupportedSchema(self.schema.clone()));
        }
        if self.notes.len() > MAX_NOTES_BYTES {
            return Err(CandidateError::NotesTooLong);
        }
        if self.notes.chars().any(|c| c.is_control() && c != '\n') {
            return Err(CandidateError::NotesControlCharacter);
        }
        if self.blocked_edges.len() > MAX_BLOCKED_EDGES {
            return Err(CandidateError::TooManyBlockedEdges);
        }
        // An effect that was never attempted cannot have been observed or have
        // crossed anything. A candidate claiming otherwise is incoherent, and
        // accepting it would let a model manufacture a CONTAINED from nothing.
        if !self.attempted_effect && (self.effect_observed_in_guest || self.boundary_crossed) {
            return Err(CandidateError::Incoherent);
        }
        Ok(())
    }
}

/// Why a candidate is unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum CandidateError {
    #[error("unsupported schema {0:?}; expected {TRIAL_RESULT_CANDIDATE_SCHEMA}")]
    UnsupportedSchema(String),
    #[error("notes exceed the {MAX_NOTES_BYTES}-byte limit")]
    NotesTooLong,
    #[error("notes contain a control character")]
    NotesControlCharacter,
    #[error("candidate reports more blocked edges than the limit allows")]
    TooManyBlockedEdges,
    #[error("candidate reports an effect it also says was never attempted")]
    Incoherent,
}

/// What the host's own observer recorded.
///
/// These are the values the outcome is actually computed from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct HostObservation {
    pub attempted_effect: bool,
    pub effect_observed_in_guest: bool,
    pub boundary_crossed: bool,
    pub blocked_edges: Vec<AssuranceId>,
}

/// Host-held proof about the trial's conditions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct EvidenceSet {
    /// The executed identity was joined to the admitted plan.
    pub identity_verified: bool,
    /// An observer was attached and reported.
    pub observer_verified: bool,
    /// The disposable target was torn down and confirmed gone.
    pub cleanup_verified: bool,
    /// Attestation validated. Only consulted when the plan requires it.
    pub attestation_verified: bool,
    /// The target was disposable.
    pub disposable_target: bool,
    /// Digest of the artifact that actually ran.
    pub artifact_digest: Sha256Digest,
    /// Digest of the policy that was actually in force.
    pub policy_digest: Sha256Digest,
    /// Digest of the source tree this trial descends from.
    pub source_digest: Sha256Digest,
    /// Audit entries covering the trial.
    pub audit_refs: Vec<EvidenceRef>,
    /// Execution receipts covering the trial.
    pub receipt_refs: Vec<EvidenceRef>,
}

/// Why an outcome could not be certified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum InconclusiveReason {
    /// A durable dispatch claim exists, but no committed result survived.
    ExecutionInterrupted,
    /// The candidate echoed a binding that is not the one MVM issued.
    BindingMismatch,
    /// The executed identity was never joined to the admitted plan.
    IdentityUnverified,
    /// The artifact that ran is not the artifact that was admitted.
    ArtifactMismatch,
    /// The policy in force is not the effective policy that was admitted.
    PolicyMismatch,
    /// The trial does not descend from the scanned source tree.
    SourceMismatch,
    /// The target was not disposable.
    NonDisposableTarget,
    /// No observer evidence.
    ObserverMissing,
    /// No cleanup evidence.
    CleanupMissing,
    /// The plan requires attestation and none validated.
    AttestationMissing,
    /// No execution receipt covers the trial.
    ReceiptMissing,
    /// No audit entry covers the trial.
    AuditMissing,
    /// The candidate's report contradicts the host observer.
    CandidateDisagreement,
    /// The candidate is malformed or incoherent.
    CandidateInvalid,
    /// Nothing was attempted, so nothing was tested.
    EffectNotAttempted,
}

/// The derived outcome and, when it is not a claim, why not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TrialVerdict {
    pub outcome: TrialOutcome,
    /// Set for every outcome that is not a certifying claim.
    pub reason: Option<InconclusiveReason>,
}

impl TrialVerdict {
    fn inconclusive(reason: InconclusiveReason) -> Self {
        Self {
            outcome: TrialOutcome::Inconclusive,
            reason: Some(reason),
        }
    }

    fn claim(outcome: TrialOutcome) -> Self {
        Self {
            outcome,
            reason: None,
        }
    }
}

/// Everything [`evaluate`] needs.
#[derive(Debug, Clone)]
pub struct EvaluationInputs<'a> {
    /// The binding MVM issued for this session.
    pub issued_binding: &'a MvmBinding,
    /// The binding the candidate echoed back, if any.
    pub echoed_binding: Option<&'a MvmBinding>,
    /// Whether a valid runtime narrative exists at all.
    pub narrative_applicable: bool,
    /// The source digest the campaign was planned against.
    pub planned_source_digest: &'a Sha256Digest,
    pub candidate: &'a TrialResultCandidate,
    pub observation: &'a HostObservation,
    pub evidence: &'a EvidenceSet,
}

/// Derive the outcome, failing closed at every missing or mismatched step.
///
/// The ladder is ordered so the most fundamental failure wins: a trial whose
/// identity cannot be joined is `INCONCLUSIVE` for that reason, not for the
/// observer that also happened to be missing.
#[must_use]
pub fn evaluate(inputs: EvaluationInputs<'_>) -> TrialVerdict {
    if !inputs.narrative_applicable {
        return TrialVerdict {
            outcome: TrialOutcome::NotApplicable,
            reason: None,
        };
    }

    if inputs.candidate.validate().is_err() {
        return TrialVerdict::inconclusive(InconclusiveReason::CandidateInvalid);
    }

    match inputs.echoed_binding {
        Some(echoed) if echoed == inputs.issued_binding => {}
        _ => return TrialVerdict::inconclusive(InconclusiveReason::BindingMismatch),
    }

    let evidence = inputs.evidence;
    if !evidence.identity_verified {
        return TrialVerdict::inconclusive(InconclusiveReason::IdentityUnverified);
    }
    if evidence.artifact_digest != inputs.issued_binding.artifact_digest {
        return TrialVerdict::inconclusive(InconclusiveReason::ArtifactMismatch);
    }
    if evidence.policy_digest != inputs.issued_binding.effective_policy_digest {
        return TrialVerdict::inconclusive(InconclusiveReason::PolicyMismatch);
    }
    if &evidence.source_digest != inputs.planned_source_digest {
        return TrialVerdict::inconclusive(InconclusiveReason::SourceMismatch);
    }
    if !evidence.disposable_target {
        return TrialVerdict::inconclusive(InconclusiveReason::NonDisposableTarget);
    }
    if !evidence.observer_verified {
        return TrialVerdict::inconclusive(InconclusiveReason::ObserverMissing);
    }
    if !evidence.cleanup_verified {
        return TrialVerdict::inconclusive(InconclusiveReason::CleanupMissing);
    }
    if inputs.issued_binding.attestation_required && !evidence.attestation_verified {
        return TrialVerdict::inconclusive(InconclusiveReason::AttestationMissing);
    }
    if evidence.receipt_refs.is_empty() {
        return TrialVerdict::inconclusive(InconclusiveReason::ReceiptMissing);
    }
    if evidence.audit_refs.is_empty() {
        return TrialVerdict::inconclusive(InconclusiveReason::AuditMissing);
    }

    let candidate = inputs.candidate;
    let observation = inputs.observation;
    if candidate.attempted_effect != observation.attempted_effect
        || candidate.effect_observed_in_guest != observation.effect_observed_in_guest
        || candidate.boundary_crossed != observation.boundary_crossed
    {
        return TrialVerdict::inconclusive(InconclusiveReason::CandidateDisagreement);
    }

    if !observation.attempted_effect {
        return TrialVerdict::inconclusive(InconclusiveReason::EffectNotAttempted);
    }
    if observation.boundary_crossed {
        return TrialVerdict {
            outcome: TrialOutcome::Observed,
            reason: None,
        };
    }
    if observation.effect_observed_in_guest {
        return TrialVerdict::claim(TrialOutcome::Contained);
    }
    TrialVerdict::claim(TrialOutcome::Prevented)
}

/// The record handed to the assurance evaluator.
///
/// Field names and the schema string are fixed by the counterparty's
/// `mvm.security.trial-evidence/v1` reader; changing one here breaks the join
/// silently, which is why the shape is asserted by test rather than trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TrialEvidenceRecord {
    pub schema: String,
    pub campaign_id: AssuranceId,
    pub trial_id: AssuranceId,
    pub source_run_id: AssuranceId,
    pub subject_revision: Option<String>,
    pub source_digest: Sha256Digest,
    pub artifact_digest: Option<Sha256Digest>,
    pub policy_digest: Option<Sha256Digest>,
    pub disposable_target: bool,
    pub identity_verified: bool,
    pub observer_verified: bool,
    pub cleanup_verified: bool,
    pub attestation_verified: bool,
    pub attempted_effect: bool,
    pub effect_observed_in_guest: bool,
    pub boundary_crossed: bool,
    pub blocked_edges: Vec<AssuranceId>,
    pub evidence_refs: Vec<EvidenceRef>,
}

/// Identity the evidence record is emitted under.
#[derive(Debug, Clone)]
pub struct EvidenceIdentity<'a> {
    pub campaign_id: &'a AssuranceId,
    pub trial_id: &'a AssuranceId,
    pub source_run_id: &'a AssuranceId,
    pub subject_revision: Option<&'a str>,
}

impl TrialEvidenceRecord {
    /// Emit the counterparty record for an evaluated trial.
    ///
    /// The booleans come from host evidence and host observation only; the
    /// candidate contributes nothing, because by this point it has either
    /// agreed with the observer or the verdict is already `INCONCLUSIVE`.
    #[must_use]
    pub fn emit(
        identity: EvidenceIdentity<'_>,
        evidence: &EvidenceSet,
        observation: &HostObservation,
    ) -> Self {
        let mut evidence_refs = evidence.audit_refs.clone();
        evidence_refs.extend(evidence.receipt_refs.iter().cloned());
        Self {
            schema: String::from(TRIAL_EVIDENCE_SCHEMA),
            campaign_id: identity.campaign_id.clone(),
            trial_id: identity.trial_id.clone(),
            source_run_id: identity.source_run_id.clone(),
            subject_revision: identity.subject_revision.map(String::from),
            source_digest: evidence.source_digest.clone(),
            artifact_digest: Some(evidence.artifact_digest.clone()),
            policy_digest: Some(evidence.policy_digest.clone()),
            disposable_target: evidence.disposable_target,
            identity_verified: evidence.identity_verified,
            observer_verified: evidence.observer_verified,
            cleanup_verified: evidence.cleanup_verified,
            attestation_verified: evidence.attestation_verified,
            attempted_effect: observation.attempted_effect,
            effect_observed_in_guest: observation.effect_observed_in_guest,
            boundary_crossed: observation.boundary_crossed,
            blocked_edges: observation.blocked_edges.clone(),
            evidence_refs,
        }
    }
}
