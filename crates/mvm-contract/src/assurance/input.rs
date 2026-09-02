//! The `mvm.assurance.ai-session-input/v1` envelope.
//!
//! # Why this is two types and not one
//!
//! The envelope handed to an AI workload has two halves with different trust
//! roots. [`AssuranceSessionRequest`] is supplied by the external assurance
//! provider and is untrusted. [`MvmBinding`] states which plan was actually
//! admitted, and is only obtainable from an admitted plan.
//!
//! Keeping them in one deserializable struct would mean the parser that reads
//! provider bytes is also the parser that can populate the binding, and the
//! only thing standing between a provider and a forged `plan_id` would be a
//! runtime check somebody has to remember to write. So the request half derives
//! `Deserialize` with `deny_unknown_fields` — which makes a provider that sends
//! an `mvm_binding` key fail parsing outright — and the assembled
//! [`AiSessionInput`] is serialize-only, constructible solely through
//! [`AiSessionInput::bind`]. A forged binding is not a check that can fail; it
//! is a value that cannot be built.
//!
//! # Depth
//!
//! There is no recursive type and no free-form `Value` anywhere in this
//! envelope, so nesting depth is fixed by the schema itself rather than
//! enforced by a counter. The remaining unbounded axes — collection lengths,
//! string lengths, and total encoded size — are what [`validate`] bounds.
//!
//! [`validate`]: AssuranceSessionRequest::validate

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::authority::EffectiveAuthority;
use super::binding::MvmBinding;
use super::ids::{AssuranceId, EvidenceRef, Sha256Digest};
use super::wire::{AuthorityWire, MvmBindingWire};

/// Schema identity of the input envelope.
pub const AI_SESSION_INPUT_SCHEMA: &str = "mvm.assurance.ai-session-input/v1";
/// Schema identity of the untrusted pre-admission request.
pub const AI_SESSION_REQUEST_SCHEMA: &str = "mvm.assurance.ai-session-request/v1";

/// Largest accepted encoded request.
pub const MAX_SESSION_INPUT_BYTES: usize = 64 * 1024;
/// Longest accepted free-prose field.
pub const MAX_PROSE_BYTES: usize = 512;
/// Longest accepted source location.
pub const MAX_LOCATION_BYTES: usize = 256;
/// Longest accepted operator-declared artifact locator.
pub const MAX_LOCATOR_BYTES: usize = 512;
/// Most tools one session may be granted.
pub const MAX_ALLOWED_TOOLS: usize = 16;
/// Most observation scopes one session may be granted.
pub const MAX_OBSERVATION_SCOPES: usize = 16;
/// Most evidence references one source finding may cite.
pub const MAX_EVIDENCE_REFS: usize = 64;
/// Most capabilities one narrative may require.
pub const MAX_REQUIRED_CAPABILITIES: usize = 16;
/// Most synthetic canaries one session may declare.
pub const MAX_CANARY_IDS: usize = 32;
/// Most synthetic destination labels one session may declare.
pub const MAX_DESTINATION_LABELS: usize = 32;
/// Most fields an output contract may require.
pub const MAX_MUST_INCLUDE: usize = 32;
/// Most reasoning steps one trial may take.
pub const MAX_STEPS_CEILING: u32 = 64;
/// Largest output budget one trial may be granted.
pub const MAX_OUTPUT_BYTES_CEILING: u32 = 1024 * 1024;

/// What kind of thing was scanned upstream.
///
/// A closed vocabulary: an unrecognised kind fails deserialization rather than
/// being carried through as an opaque string, because every downstream identity
/// check is written against a kind it understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum SubjectKind {
    /// A repository or directory on the operator's machine.
    LocalRepository,
}

/// Severity carried over from the source finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A tool the AI is permitted to select.
///
/// The AI picks a variant; it never supplies a tool name. Adding a tool is a
/// change to this enum and therefore to the host code that dispatches it, which
/// is the property that keeps "the model asked for an undeclared tool" out of
/// the reachable state space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ToolId {
    /// The one declared assurance probe verb.
    #[serde(rename = "campaign_probe.v1")]
    CampaignProbeV1,
}

/// An observation channel the session may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ObservationScope {
    /// A digest of guest stdout — never the bytes.
    #[serde(rename = "guest.stdout.digest")]
    GuestStdoutDigest,
    /// References into the chain-signed audit log — never its contents.
    #[serde(rename = "host.audit.refs")]
    HostAuditRefs,
}

/// Identity of the trial within the campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionRef {
    /// Provider-side request identity.
    pub request_id: AssuranceId,
    /// Retry key. Two requests carrying this key must execute at most once.
    pub idempotency_key: AssuranceId,
    /// The upstream scan run this trial descends from.
    pub source_run_id: AssuranceId,
    /// The campaign this trial belongs to.
    pub campaign_id: AssuranceId,
    /// This trial.
    pub trial_id: AssuranceId,
}

/// The source finding under test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SourceRef {
    pub subject_kind: SubjectKind,
    /// Bounded operator-declared subject locator. This is correlation input,
    /// never a host path the workload may open.
    pub subject_locator: String,
    /// Revision of the scanned subject, when the subject had one.
    pub subject_revision: Option<String>,
    pub source_digest: Sha256Digest,
    pub finding_id: AssuranceId,
    pub group_id: AssuranceId,
    pub rule_id: AssuranceId,
    pub category: AssuranceId,
    pub severity: Severity,
    /// Where the finding sits, as reported upstream (`path:line:col`).
    pub location: String,
    pub evidence_refs: Vec<EvidenceRef>,
    /// The artifact the operator declared for this campaign, if any. This is an
    /// admission *input*; what was actually admitted is in [`MvmBinding`].
    pub artifact_locator: Option<String>,
    /// Digest of the policy inputs the provider asked for. Again an input: the
    /// effective policy is in [`MvmBinding`].
    pub requested_policy_digest: Sha256Digest,
}

/// What the trial is supposed to attempt, and where the boundary is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Narrative {
    pub narrative_id: AssuranceId,
    pub objective: String,
    pub expected_boundary: String,
    pub required_capabilities: Vec<AssuranceId>,
}

/// The ceiling on what this session may do.
///
/// This is the *requested* authority. Effective authority is the intersection
/// of this with the host ceiling and the signed grant; see
/// [`super::authority::EffectiveAuthority`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RequestedAuthority {
    pub allowed_tools: Vec<ToolId>,
    pub observation_scopes: Vec<ObservationScope>,
    pub max_steps: u32,
    pub max_output_bytes: u32,
    /// Wall-clock deadline. `0` means "the provider set none"; the host
    /// substitutes its own bound rather than treating it as unbounded.
    pub deadline_unix_ms: u64,
}

/// Synthetic stand-ins used in place of anything real.
///
/// Identifiers and labels only. A canary *value* never appears here, which is
/// why the model can be told to look for a canary without being told what it
/// is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SyntheticInputs {
    pub canary_ids: Vec<AssuranceId>,
    pub destination_labels: Vec<AssuranceId>,
}

/// The shape the trial result must take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct OutputContract {
    pub kind: String,
    pub required_fields: Vec<String>,
}

/// The provider-supplied half of the envelope. Untrusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AssuranceSessionRequest {
    /// Must equal [`AI_SESSION_REQUEST_SCHEMA`].
    pub schema: String,
    pub session: SessionRef,
    pub source: SourceRef,
    pub narrative: Narrative,
    pub authority: RequestedAuthority,
    pub synthetic_inputs: SyntheticInputs,
    pub output_contract: OutputContract,
}

/// Why a provider request is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum SessionInputError {
    #[error("encoded request exceeds the {MAX_SESSION_INPUT_BYTES}-byte limit")]
    TooLarge,
    #[error("request is not valid JSON for this schema: {0}")]
    Malformed(String),
    #[error("unsupported schema {0:?}; expected {AI_SESSION_REQUEST_SCHEMA}")]
    UnsupportedSchema(String),
    #[error("field {field} exceeds its length limit")]
    FieldTooLong { field: &'static str },
    #[error("field {field} is empty")]
    FieldEmpty { field: &'static str },
    #[error("collection {field} exceeds its element limit")]
    TooManyElements { field: &'static str },
    #[error("field {field} is outside its permitted range")]
    OutOfRange { field: &'static str },
    #[error("field {field} contains a control character")]
    ControlCharacter { field: &'static str },
}

impl AssuranceSessionRequest {
    /// Parse and validate a provider request from its encoded form.
    ///
    /// The size check runs before the parser so an oversized body is refused
    /// without being deserialized.
    pub fn parse_json(bytes: &[u8]) -> Result<Self, SessionInputError> {
        if bytes.len() > MAX_SESSION_INPUT_BYTES {
            return Err(SessionInputError::TooLarge);
        }
        let parsed: Self = serde_json::from_slice(bytes)
            .map_err(|error| SessionInputError::Malformed(alloc::format!("{error}")))?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Check every bound serde cannot express.
    pub fn validate(&self) -> Result<(), SessionInputError> {
        if self.schema != AI_SESSION_REQUEST_SCHEMA {
            return Err(SessionInputError::UnsupportedSchema(self.schema.clone()));
        }

        bounded_prose("narrative.objective", &self.narrative.objective)?;
        bounded_prose(
            "narrative.expected_boundary",
            &self.narrative.expected_boundary,
        )?;
        bounded("source.location", &self.source.location, MAX_LOCATION_BYTES)?;
        bounded(
            "source.subject_locator",
            &self.source.subject_locator,
            MAX_LOCATOR_BYTES,
        )?;
        if let Some(locator) = &self.source.artifact_locator {
            bounded("source.artifact_locator", locator, MAX_LOCATOR_BYTES)?;
        }
        if let Some(revision) = &self.source.subject_revision {
            bounded("source.subject_revision", revision, MAX_PROSE_BYTES)?;
        }
        bounded(
            "output_contract.kind",
            &self.output_contract.kind,
            MAX_PROSE_BYTES,
        )?;
        if self.output_contract.kind != super::outcome::TRIAL_RESULT_SCHEMA {
            return Err(SessionInputError::OutOfRange {
                field: "output_contract.kind",
            });
        }
        for field in &self.output_contract.required_fields {
            bounded("output_contract.required_fields[]", field, MAX_PROSE_BYTES)?;
        }

        limit(
            "source.evidence_refs",
            self.source.evidence_refs.len(),
            MAX_EVIDENCE_REFS,
        )?;
        limit(
            "narrative.required_capabilities",
            self.narrative.required_capabilities.len(),
            MAX_REQUIRED_CAPABILITIES,
        )?;
        limit(
            "authority.allowed_tools",
            self.authority.allowed_tools.len(),
            MAX_ALLOWED_TOOLS,
        )?;
        limit(
            "authority.observation_scopes",
            self.authority.observation_scopes.len(),
            MAX_OBSERVATION_SCOPES,
        )?;
        limit(
            "synthetic_inputs.canary_ids",
            self.synthetic_inputs.canary_ids.len(),
            MAX_CANARY_IDS,
        )?;
        limit(
            "synthetic_inputs.destination_labels",
            self.synthetic_inputs.destination_labels.len(),
            MAX_DESTINATION_LABELS,
        )?;
        limit(
            "output_contract.required_fields",
            self.output_contract.required_fields.len(),
            MAX_MUST_INCLUDE,
        )?;

        for required in [
            "source_digest",
            "artifact_digest",
            "policy_digest",
            "attempted_effect",
            "effect_observed_in_guest",
            "boundary_crossed",
            "blocked_edges",
            "evidence_refs",
        ] {
            if !self
                .output_contract
                .required_fields
                .iter()
                .any(|field| field == required)
            {
                return Err(SessionInputError::FieldEmpty {
                    field: "output_contract.required_fields",
                });
            }
        }

        if self.authority.max_steps == 0 || self.authority.max_steps > MAX_STEPS_CEILING {
            return Err(SessionInputError::OutOfRange {
                field: "authority.max_steps",
            });
        }
        if self.authority.max_output_bytes == 0
            || self.authority.max_output_bytes > MAX_OUTPUT_BYTES_CEILING
        {
            return Err(SessionInputError::OutOfRange {
                field: "authority.max_output_bytes",
            });
        }
        // A session with no tool can do nothing but burn a deadline; a session
        // with no observation scope can see nothing it could report on. Both
        // are refused as malformed rather than run to a guaranteed
        // INCONCLUSIVE.
        if self.authority.allowed_tools.is_empty() {
            return Err(SessionInputError::FieldEmpty {
                field: "authority.allowed_tools",
            });
        }
        if self.authority.observation_scopes.is_empty() {
            return Err(SessionInputError::FieldEmpty {
                field: "authority.observation_scopes",
            });
        }
        reject_duplicates("source.evidence_refs", &self.source.evidence_refs)?;
        reject_duplicates("authority.allowed_tools", &self.authority.allowed_tools)?;
        reject_duplicates(
            "authority.observation_scopes",
            &self.authority.observation_scopes,
        )?;
        reject_duplicates(
            "narrative.required_capabilities",
            &self.narrative.required_capabilities,
        )?;
        reject_duplicates(
            "synthetic_inputs.canary_ids",
            &self.synthetic_inputs.canary_ids,
        )?;
        reject_duplicates(
            "synthetic_inputs.destination_labels",
            &self.synthetic_inputs.destination_labels,
        )?;
        reject_duplicates(
            "output_contract.required_fields",
            &self.output_contract.required_fields,
        )?;
        Ok(())
    }
}

fn reject_duplicates<T: PartialEq>(
    field: &'static str,
    values: &[T],
) -> Result<(), SessionInputError> {
    if values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
    {
        return Err(SessionInputError::OutOfRange { field });
    }
    Ok(())
}

fn bounded_prose(field: &'static str, value: &str) -> Result<(), SessionInputError> {
    bounded(field, value, MAX_PROSE_BYTES)
}

fn bounded(field: &'static str, value: &str, max: usize) -> Result<(), SessionInputError> {
    if value.is_empty() {
        return Err(SessionInputError::FieldEmpty { field });
    }
    if value.len() > max {
        return Err(SessionInputError::FieldTooLong { field });
    }
    // Prose is copied into prompts and audit text; a control byte there can
    // terminate a record or forge a line break in a rendered report.
    if value.chars().any(char::is_control) {
        return Err(SessionInputError::ControlCharacter { field });
    }
    Ok(())
}

fn limit(field: &'static str, len: usize, max: usize) -> Result<(), SessionInputError> {
    if len > max {
        return Err(SessionInputError::TooManyElements { field });
    }
    Ok(())
}

/// The complete envelope an AI workload receives.
///
/// Serialize-only by construction, and shaped to the counterparty's exact key
/// set. See the module docs for why there is no `Deserialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AiSessionInput {
    schema: String,
    session: SessionRef,
    source: SourceRef,
    narrative: Narrative,
    /// Effective authority, not the requested authority.
    authority: AuthorityWire,
    synthetic_inputs: SyntheticInputs,
    output_contract: OutputContract,
    mvm_binding: MvmBindingWire,
}

impl AiSessionInput {
    /// Join a validated provider request to an admitted binding and the
    /// authority that survived the intersection.
    ///
    /// This is the only way to build the envelope, so every envelope in
    /// existence names a plan that was really admitted and states an authority
    /// that was really granted.
    pub fn bind(
        request: AssuranceSessionRequest,
        binding: &MvmBinding,
        effective: &EffectiveAuthority,
    ) -> Result<Self, SessionInputError> {
        request.validate()?;
        Ok(Self {
            schema: String::from(AI_SESSION_INPUT_SCHEMA),
            session: request.session,
            source: request.source,
            narrative: request.narrative,
            authority: AuthorityWire::from(effective),
            synthetic_inputs: request.synthetic_inputs,
            output_contract: request.output_contract,
            mvm_binding: MvmBindingWire::from(binding),
        })
    }

    /// The admitted half, as it appears on the wire.
    #[must_use]
    pub fn binding(&self) -> &MvmBindingWire {
        &self.mvm_binding
    }

    /// The effective authority, as it appears on the wire.
    #[must_use]
    pub fn authority(&self) -> &AuthorityWire {
        &self.authority
    }

    /// The trial identity.
    #[must_use]
    pub fn session(&self) -> &SessionRef {
        &self.session
    }

    /// The validated source identity, as it appears on the wire.
    #[must_use]
    pub fn source(&self) -> &SourceRef {
        &self.source
    }

    /// Encode the envelope for delivery.
    pub fn to_json(&self) -> Result<alloc::string::String, SessionInputError> {
        let encoded = serde_json::to_string(self)
            .map_err(|error| SessionInputError::Malformed(alloc::format!("{error}")))?;
        if encoded.len() > MAX_SESSION_INPUT_BYTES {
            return Err(SessionInputError::TooLarge);
        }
        Ok(encoded)
    }
}
