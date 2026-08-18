//! Exact documents the assurance evaluator reads.
//!
//! The counterparty validates these with *exact* key sets — a key it does not
//! know is an error, not something it ignores — so these are deliberately flat
//! projections rather than the richer host-side types. Two consequences worth
//! stating plainly:
//!
//! - The host-side [`MvmBinding`] carries more than the wire form does
//!   (`plan_version`, `tenant`, `workload`, `attestation_required`, and the
//!   audit/receipt reference lists). Those stay host-side; adding them to the
//!   document would fail the far end's key check.
//! - The `authority` block on the wire is the *effective* authority, not the
//!   requested one. The model should be told what it actually has, and the
//!   counterparty rejects the `deadline_unix_ms: 0` that a request may carry
//!   to mean "none set".

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::authority::EffectiveAuthority;
use super::binding::MvmBinding;
use super::ids::{AssuranceId, EvidenceRef, Sha256Digest};
use super::input::{ObservationScope, ToolId};
use super::outcome::{EvidenceSet, HostObservation};

/// The `mvm_binding` block, in the counterparty's exact shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct MvmBindingWire {
    pub session_id: AssuranceId,
    pub plan_id: AssuranceId,
    pub workload_digest: Sha256Digest,
    pub artifact_digest: Sha256Digest,
    pub effective_policy_digest: Sha256Digest,
    pub session_grant_digest: Sha256Digest,
    pub expires_at_unix_ms: u64,
    pub nonce: AssuranceId,
    pub allowed_tools: Vec<ToolId>,
    pub backend: AssuranceId,
}

impl From<&MvmBinding> for MvmBindingWire {
    fn from(binding: &MvmBinding) -> Self {
        Self {
            session_id: binding.session_id.clone(),
            plan_id: binding.plan_id.clone(),
            workload_digest: binding.workload_digest.clone(),
            artifact_digest: binding.artifact_digest.clone(),
            effective_policy_digest: binding.effective_policy_digest.clone(),
            session_grant_digest: binding.grant.grant_digest.clone(),
            expires_at_unix_ms: binding.grant.expires_unix_ms,
            nonce: binding.grant.nonce.clone(),
            allowed_tools: binding.grant.allowed_tools.clone(),
            backend: binding.runtime.backend.clone(),
        }
    }
}

/// The `authority` block, carrying effective rather than requested values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AuthorityWire {
    pub allowed_tools: Vec<ToolId>,
    pub observation_scopes: Vec<ObservationScope>,
    pub max_steps: u32,
    pub max_output_bytes: u32,
    pub deadline_unix_ms: u64,
}

impl From<&EffectiveAuthority> for AuthorityWire {
    fn from(authority: &EffectiveAuthority) -> Self {
        Self {
            allowed_tools: authority.tools(),
            observation_scopes: authority.scopes(),
            max_steps: authority.max_steps(),
            max_output_bytes: authority.max_output_bytes(),
            deadline_unix_ms: authority.deadline_unix_ms(),
        }
    }
}

/// Identity block of a trial result.
///
/// Differs from the input envelope's `session`: it drops `idempotency_key` and
/// adds `session_id` and `plan_id`, both of which only exist after admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TrialResultSession {
    pub session_id: AssuranceId,
    pub request_id: AssuranceId,
    pub source_run_id: AssuranceId,
    pub campaign_id: AssuranceId,
    pub trial_id: AssuranceId,
    pub plan_id: AssuranceId,
}

/// The host-assembled `mvm.assurance.trial-result/v1` document.
///
/// Note what is absent: there is no outcome field. The counterparty derives
/// `PREVENTED`/`CONTAINED` from these facts, and neither the AI nor this
/// projection can shortcut that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TrialResultDocument {
    pub schema: String,
    pub session: TrialResultSession,
    pub subject_revision: Option<String>,
    pub source_digest: Sha256Digest,
    pub artifact_digest: Sha256Digest,
    pub policy_digest: Sha256Digest,
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
    pub receipt_refs: Vec<EvidenceRef>,
    pub audit_refs: Vec<EvidenceRef>,
}

/// Identity a trial result is emitted under.
#[derive(Debug, Clone)]
pub struct TrialResultIdentity<'a> {
    pub request_id: &'a AssuranceId,
    pub source_run_id: &'a AssuranceId,
    pub campaign_id: &'a AssuranceId,
    pub trial_id: &'a AssuranceId,
    pub subject_revision: Option<&'a str>,
}

impl TrialResultDocument {
    /// Assemble the host record.
    ///
    /// Every boolean comes from host evidence or the host observer. The AI
    /// candidate is not an input, by construction: it has already been
    /// reconciled against the observer by the evaluator, or the trial is
    /// inconclusive and this record says so through its own fields.
    #[must_use]
    pub fn assemble(
        identity: TrialResultIdentity<'_>,
        binding: &MvmBinding,
        evidence: &EvidenceSet,
        observation: &HostObservation,
    ) -> Self {
        Self {
            schema: super::outcome::TRIAL_RESULT_SCHEMA.to_string(),
            session: TrialResultSession {
                session_id: binding.session_id.clone(),
                request_id: identity.request_id.clone(),
                source_run_id: identity.source_run_id.clone(),
                campaign_id: identity.campaign_id.clone(),
                trial_id: identity.trial_id.clone(),
                plan_id: binding.plan_id.clone(),
            },
            subject_revision: identity.subject_revision.map(String::from),
            source_digest: evidence.source_digest.clone(),
            artifact_digest: evidence.artifact_digest.clone(),
            policy_digest: evidence.policy_digest.clone(),
            disposable_target: evidence.disposable_target,
            identity_verified: evidence.identity_verified,
            observer_verified: evidence.observer_verified,
            cleanup_verified: evidence.cleanup_verified,
            attestation_verified: evidence.attestation_verified,
            attempted_effect: observation.attempted_effect,
            effect_observed_in_guest: observation.effect_observed_in_guest,
            boundary_crossed: observation.boundary_crossed,
            blocked_edges: observation.blocked_edges.clone(),
            evidence_refs: evidence.audit_refs.clone(),
            receipt_refs: evidence.receipt_refs.clone(),
            audit_refs: evidence.audit_refs.clone(),
        }
    }
}

/// The envelope as a workload reads it.
///
/// [`super::input::AiSessionInput`] is serialize-only on purpose: the host must
/// never be able to parse admission facts out of provider bytes. The guest has
/// the opposite problem — it only ever *receives* an envelope, and needs the
/// binding and effective authority to make a call at all — so reading is a
/// separate type with a separate direction.
///
/// This is safe precisely because it is guest-side. Nothing the guest believes
/// about its own binding is authoritative; the host re-derives every gate from
/// the session it opened. A workload that forged one of these would be lying
/// only to itself.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DeliveredSession {
    pub schema: String,
    pub session: super::input::SessionRef,
    pub source: super::input::SourceRef,
    pub narrative: super::input::Narrative,
    pub authority: AuthorityWire,
    pub synthetic_inputs: super::input::SyntheticInputs,
    pub output_contract: super::input::OutputContract,
    pub mvm_binding: MvmBindingWire,
}

/// Why a delivered envelope is unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum DeliveredSessionError {
    #[error("delivered envelope exceeds the size limit")]
    TooLarge,
    #[error("delivered envelope is not valid for this schema: {0}")]
    Malformed(String),
    #[error("unsupported schema {0:?}")]
    UnsupportedSchema(String),
    #[error("the delivered envelope grants no tool")]
    NoTools,
}

impl DeliveredSession {
    /// Parse an envelope handed to this workload.
    pub fn parse_json(bytes: &[u8]) -> Result<Self, DeliveredSessionError> {
        if bytes.len() > super::input::MAX_SESSION_INPUT_BYTES {
            return Err(DeliveredSessionError::TooLarge);
        }
        let parsed: Self = serde_json::from_slice(bytes)
            .map_err(|error| DeliveredSessionError::Malformed(alloc::format!("{error}")))?;
        if parsed.schema != super::input::AI_SESSION_INPUT_SCHEMA {
            return Err(DeliveredSessionError::UnsupportedSchema(parsed.schema));
        }
        if parsed.authority.allowed_tools.is_empty() {
            return Err(DeliveredSessionError::NoTools);
        }
        Ok(parsed)
    }

    /// Whether `label` is one this campaign declared.
    #[must_use]
    pub fn declares_destination(&self, label: &AssuranceId) -> bool {
        self.synthetic_inputs.destination_labels.contains(label)
    }

    /// Whether `tool` survived into effective authority.
    #[must_use]
    pub fn permits_tool(&self, tool: ToolId) -> bool {
        self.authority.allowed_tools.contains(&tool)
    }
}
