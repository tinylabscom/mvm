//! The one declared probe surface an AI workload may call.
//!
//! # Why the AI sends a label and not a destination
//!
//! A probe invocation names a *declared label* — `undeclared.synthetic.
//! destination` — which the host resolves against the campaign's
//! operator-declared destination table. The model never states a host, a port,
//! a path, or a command. Resolution failing is a refusal, not a fallback, so a
//! label the campaign did not declare cannot reach the policy engine at all.
//!
//! # Why the invocation is an enum and not a bag of arguments
//!
//! [`ProbeInvocation`] is internally tagged, so each probe carries exactly its
//! own arguments and nothing else. A payload with the wrong argument shape for
//! its probe does not deserialize, which removes "handler forgot to validate
//! argument X for probe Y" from the failure space.

use alloc::string::String;
use alloc::vec;

use serde::{Deserialize, Serialize};

use super::ids::{AssuranceId, Sha256Digest};
use super::input::ToolId;
use crate::protocol::agent_capability::{
    ArgumentConstraint, ArgumentRule, CapabilityDescriptor, CapabilityId, CapabilityLimits,
    SchemaRef, payload_digest,
};
use crate::protocol::broker::ServiceId;

/// Schema identity of a probe request.
pub const PROBE_REQUEST_SCHEMA: &str = "mvm.assurance.probe-request/v1";
/// Schema identity of a probe observation.
pub const PROBE_OBSERVATION_SCHEMA: &str = "mvm.assurance.probe-observation/v1";
/// Broker service carrying the typed probe capability.
pub const HOST_ASSURANCE_SERVICE: &str = "host.assurance.v1";

/// Canonical typed descriptor shared by pack admission, the guest client, and
/// the host registry. One owner prevents a digest mismatch from silently
/// making an admitted capability unusable.
#[must_use]
pub fn probe_capability_descriptor() -> CapabilityDescriptor {
    let service = ServiceId::parse(HOST_ASSURANCE_SERVICE)
        .expect("host.assurance.v1 is a valid service identity");
    let input = payload_digest(&serde_json::json!({
        "schema": PROBE_REQUEST_SCHEMA,
        "type": "object",
        "additionalProperties": false
    }));
    let output = payload_digest(&serde_json::json!({
        "schema": PROBE_OBSERVATION_SCHEMA,
        "type": "object",
        "additionalProperties": false
    }));
    CapabilityDescriptor::builder()
        .id(CapabilityId::new(service, "probe").expect("probe capability identity"))
        .description("execute one admitted assurance probe using declared labels")
        .input_schema(
            SchemaRef::new("mvm.assurance.probe-request.v1", input).expect("probe input schema"),
        )
        .output_schema(
            SchemaRef::new("mvm.assurance.probe-observation.v1", output)
                .expect("probe output schema"),
        )
        .limits(CapabilityLimits::new(16 * 1024, 16 * 1024, 30_000).expect("probe limits"))
        .argument_policy(vec![ArgumentRule {
            pointer: "/invocation/destination_label".into(),
            constraint: ArgumentConstraint::MaxLen { bytes: 128 },
        }])
        .build()
        .expect("probe descriptor")
}

/// A declared probe and its arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "probe", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ProbeInvocation {
    /// Ask whether the workload's admitted egress policy would admit a
    /// declared destination. This is the claim-10 decision point, consulted
    /// through the same function the egress broker uses.
    #[serde(rename = "egress.admission.v1")]
    EgressAdmission {
        /// A label from the session's declared destination table.
        destination_label: AssuranceId,
    },
}

impl ProbeInvocation {
    /// Stable identity for audit and step accounting.
    #[must_use]
    pub const fn probe_id(&self) -> &'static str {
        match self {
            Self::EgressAdmission { .. } => "egress.admission.v1",
        }
    }
}

/// One bounded probe call.
///
/// `session_id` is present so a mismatch against the supervisor-supplied
/// context can be *detected*; it is never the value the handler trusts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProbeRequest {
    /// Must equal [`PROBE_REQUEST_SCHEMA`].
    pub schema: String,
    pub session_id: AssuranceId,
    /// Provider request this operation descends from.
    pub request_id: AssuranceId,
    /// Campaign this operation belongs to.
    pub campaign_id: AssuranceId,
    pub trial_id: AssuranceId,
    /// Exact admitted plan quoted by the session binding.
    pub plan_id: AssuranceId,
    /// Retry identity of the campaign session itself. This is distinct from
    /// the per-operation key below.
    pub campaign_idempotency_key: AssuranceId,
    /// Digest of the host-minted grant under which this call is made.
    pub session_grant_digest: Sha256Digest,
    /// Stable nonce in that grant. `nonce` below remains the single-use call
    /// nonce, so a multi-step campaign does not replay the grant nonce.
    pub session_grant_nonce: AssuranceId,
    /// Retry key. A repeat returns the first result without re-executing.
    pub idempotency_key: AssuranceId,
    /// Single-use value. A repeat is a replay and is refused.
    pub nonce: AssuranceId,
    /// The tool being exercised. Checked against effective authority.
    pub tool: ToolId,
    /// The declared probe and its arguments.
    ///
    /// A nested field rather than a flattened one: serde's
    /// `deny_unknown_fields` does not compose with `flatten`, and an unknown
    /// key silently surviving is exactly the failure this contract cannot
    /// afford.
    pub invocation: ProbeInvocation,
}

/// What the host observed. Bounded, and free of policy internals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProbeObservation {
    /// Always [`PROBE_OBSERVATION_SCHEMA`].
    pub schema: String,
    /// Which probe produced this.
    pub probe: String,
    /// Whether the declared destination was admitted.
    pub admitted: bool,
    /// The edge that was blocked, when it was blocked.
    pub blocked_edge: Option<AssuranceId>,
    /// Stable decision token (`allowed`, `deny_all`, `not_in_allowlist`).
    /// A token rather than a message so nothing about the policy's contents
    /// leaks into the session.
    pub decision: String,
    /// Steps left in this session's budget after this call.
    pub steps_remaining: u32,
}

/// Why a typed observation cannot be joined to the invocation that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ProbeObservationError {
    /// The response uses a different observation schema.
    #[error("probe observation schema is not supported")]
    UnsupportedSchema,
    /// The response names a different probe.
    #[error("probe observation identity does not match the invocation")]
    ProbeMismatch,
    /// The response's admitted/blocked edge facts do not describe the invoked label.
    #[error("probe observation blocked edge does not match the invoked label")]
    BlockedEdgeMismatch,
}

impl ProbeObservation {
    /// Join this response to the exact typed invocation before a workload uses it.
    pub fn validate_for(&self, invocation: &ProbeInvocation) -> Result<(), ProbeObservationError> {
        if self.schema != PROBE_OBSERVATION_SCHEMA {
            return Err(ProbeObservationError::UnsupportedSchema);
        }
        if self.probe != invocation.probe_id() {
            return Err(ProbeObservationError::ProbeMismatch);
        }
        match invocation {
            ProbeInvocation::EgressAdmission { destination_label } => {
                let edge_matches = match (&self.blocked_edge, self.admitted) {
                    (None, true) => true,
                    (Some(blocked), false) => blocked == destination_label,
                    (None, false) | (Some(_), true) => false,
                };
                if !edge_matches {
                    return Err(ProbeObservationError::BlockedEdgeMismatch);
                }
            }
        }
        Ok(())
    }
}

/// Why a probe call was refused.
///
/// A closed vocabulary: these strings reach the model, so they must say what
/// happened without describing the policy, the host, or the other sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ProbeRefusal {
    #[error("probe request schema is not supported")]
    UnsupportedSchema,
    #[error("no assurance session is bound to this workload session")]
    NoSession,
    #[error("the request names a different session than the one it arrived on")]
    SessionMismatch,
    #[error("the request names a different provider request than the opened session")]
    RequestMismatch,
    #[error("the request names a different campaign than the opened session")]
    CampaignMismatch,
    #[error("the request names a different trial than the session was opened for")]
    TrialMismatch,
    #[error("the request names a different admitted plan than the opened session")]
    PlanMismatch,
    #[error("the request names a different campaign idempotency key")]
    CampaignIdempotencyMismatch,
    #[error("the request does not carry the grant digest issued for this session")]
    GrantMismatch,
    #[error("the request does not carry the grant nonce issued for this session")]
    GrantNonceMismatch,
    #[error("effective authority does not permit this tool")]
    ToolNotPermitted,
    #[error("the session grant has expired")]
    GrantExpired,
    #[error("the session step budget is exhausted")]
    StepBudgetExhausted,
    #[error("this nonce was already used")]
    NonceReplay,
    #[error("the destination label was not declared for this campaign")]
    UndeclaredDestination,
    #[error("the probe could not be recorded, so it was not run")]
    AuditUnavailable,
}

impl ProbeRefusal {
    /// Stable token for audit.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::UnsupportedSchema => "unsupported_schema",
            Self::NoSession => "no_session",
            Self::SessionMismatch => "session_mismatch",
            Self::RequestMismatch => "request_mismatch",
            Self::CampaignMismatch => "campaign_mismatch",
            Self::TrialMismatch => "trial_mismatch",
            Self::PlanMismatch => "plan_mismatch",
            Self::CampaignIdempotencyMismatch => "campaign_idempotency_mismatch",
            Self::GrantMismatch => "grant_mismatch",
            Self::GrantNonceMismatch => "grant_nonce_mismatch",
            Self::ToolNotPermitted => "tool_not_permitted",
            Self::GrantExpired => "grant_expired",
            Self::StepBudgetExhausted => "step_budget_exhausted",
            Self::NonceReplay => "nonce_replay",
            Self::UndeclaredDestination => "undeclared_destination",
            Self::AuditUnavailable => "audit_unavailable",
        }
    }
}

impl ProbeRequest {
    /// Check the schema string. Shape is already enforced by the parser.
    pub fn validate(&self) -> Result<(), ProbeRefusal> {
        if self.schema != PROBE_REQUEST_SCHEMA {
            return Err(ProbeRefusal::UnsupportedSchema);
        }
        Ok(())
    }

    /// The tool this request exercises.
    #[must_use]
    pub const fn tool(&self) -> ToolId {
        self.tool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(value: &str) -> AssuranceId {
        AssuranceId::parse(value).expect("valid assurance label")
    }

    fn denied_observation(destination: &str) -> ProbeObservation {
        ProbeObservation {
            schema: PROBE_OBSERVATION_SCHEMA.to_string(),
            probe: "egress.admission.v1".to_string(),
            admitted: false,
            blocked_edge: Some(label(destination)),
            decision: "deny_all".to_string(),
            steps_remaining: 3,
        }
    }

    #[test]
    fn observation_validation_joins_the_exact_probe_and_declared_edge() {
        let invocation = ProbeInvocation::EgressAdmission {
            destination_label: label("synthetic-destination"),
        };
        assert_eq!(
            denied_observation("synthetic-destination").validate_for(&invocation),
            Ok(())
        );
    }

    #[test]
    fn observation_validation_refuses_schema_probe_and_edge_mismatch() {
        let invocation = ProbeInvocation::EgressAdmission {
            destination_label: label("synthetic-destination"),
        };
        let mut wrong_schema = denied_observation("synthetic-destination");
        wrong_schema.schema = "mvm.assurance.probe-observation/v0".to_string();
        assert_eq!(
            wrong_schema.validate_for(&invocation),
            Err(ProbeObservationError::UnsupportedSchema)
        );

        let mut wrong_probe = denied_observation("synthetic-destination");
        wrong_probe.probe = "foreign.probe.v1".to_string();
        assert_eq!(
            wrong_probe.validate_for(&invocation),
            Err(ProbeObservationError::ProbeMismatch)
        );

        assert_eq!(
            denied_observation("foreign-destination").validate_for(&invocation),
            Err(ProbeObservationError::BlockedEdgeMismatch)
        );
    }

    #[test]
    fn probe_descriptor_digest_is_the_extension_abi_identity() {
        assert_eq!(
            probe_capability_descriptor().digest(),
            [
                123, 184, 93, 249, 63, 124, 137, 227, 66, 96, 83, 243, 165, 78, 168, 110, 12, 1,
                103, 185, 65, 12, 94, 196, 213, 131, 140, 37, 51, 195, 221, 100,
            ]
        );
    }
}
