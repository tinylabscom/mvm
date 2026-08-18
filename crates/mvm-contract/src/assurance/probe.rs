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

use serde::{Deserialize, Serialize};

use super::ids::AssuranceId;
use super::input::ToolId;

/// Schema identity of a probe request.
pub const PROBE_REQUEST_SCHEMA: &str = "mvm.assurance.probe-request/v1";
/// Schema identity of a probe observation.
pub const PROBE_OBSERVATION_SCHEMA: &str = "mvm.assurance.probe-observation/v1";

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
    pub trial_id: AssuranceId,
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
    #[error("the request names a different trial than the session was opened for")]
    TrialMismatch,
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
}

impl ProbeRefusal {
    /// Stable token for audit.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::UnsupportedSchema => "unsupported_schema",
            Self::NoSession => "no_session",
            Self::SessionMismatch => "session_mismatch",
            Self::TrialMismatch => "trial_mismatch",
            Self::ToolNotPermitted => "tool_not_permitted",
            Self::GrantExpired => "grant_expired",
            Self::StepBudgetExhausted => "step_budget_exhausted",
            Self::NonceReplay => "nonce_replay",
            Self::UndeclaredDestination => "undeclared_destination",
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
