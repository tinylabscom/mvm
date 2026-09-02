//! Effective authority: the intersection, never the union.
//!
//! Five things have an opinion about what a session may do — what the
//! extension can offer at all, what the request asked for, what host/tenant
//! policy permits, what the signed grant authorizes, and what an operator
//! explicitly approved. Effective authority is the intersection of all five.
//!
//! The intersection is computed once, into [`EffectiveAuthority`], and that
//! value is what dispatch consults. The alternative — five checks spread across
//! the call path — fails open the moment someone adds a sixth caller and
//! forgets one of them.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::binding::SessionGrant;
use super::input::{ObservationScope, RequestedAuthority, ToolId};

/// A bound on what may be granted, from one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AuthorityCeiling {
    pub tools: BTreeSet<ToolId>,
    pub scopes: BTreeSet<ObservationScope>,
    pub max_steps: u32,
    pub max_output_bytes: u32,
}

impl AuthorityCeiling {
    /// The widest ceiling this build can offer.
    ///
    /// Everything the extension implements. Nothing may exceed it, and adding
    /// a tool here without implementing its dispatch arm will not compile.
    #[must_use]
    pub fn extension_maximum() -> Self {
        Self {
            tools: [ToolId::CampaignProbeV1].into_iter().collect(),
            scopes: [
                ObservationScope::GuestStdoutDigest,
                ObservationScope::HostAuditRefs,
            ]
            .into_iter()
            .collect(),
            max_steps: super::input::MAX_STEPS_CEILING,
            max_output_bytes: super::input::MAX_OUTPUT_BYTES_CEILING,
        }
    }
}

impl ToolId {
    /// Whether an operator must approve this tool explicitly.
    ///
    /// A campaign probe runs a declared attack narrative against a real guest.
    /// Policy permitting it is not the same as an operator asking for it, and
    /// the assurance contract treats campaigns as explicitly authorized work.
    #[must_use]
    pub const fn requires_explicit_approval(self) -> bool {
        match self {
            Self::CampaignProbeV1 => true,
        }
    }
}

/// Tools an operator approved for this session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ApprovalSet {
    approved: BTreeSet<ToolId>,
}

impl ApprovalSet {
    /// An empty set. Every approval-requiring tool is refused.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Record an operator approval.
    #[must_use]
    pub fn with(mut self, tool: ToolId) -> Self {
        self.approved.insert(tool);
        self
    }

    /// Whether `tool` may proceed under this set.
    #[must_use]
    pub fn permits(&self, tool: ToolId) -> bool {
        !tool.requires_explicit_approval() || self.approved.contains(&tool)
    }
}

/// The five inputs to the intersection.
#[derive(Debug, Clone)]
pub struct AuthorityInputs<'a> {
    pub extension_maximum: &'a AuthorityCeiling,
    pub requested: &'a RequestedAuthority,
    pub policy_ceiling: &'a AuthorityCeiling,
    pub grant: &'a SessionGrant,
    pub approvals: &'a ApprovalSet,
}

/// What a session may actually do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct EffectiveAuthority {
    tools: BTreeSet<ToolId>,
    scopes: BTreeSet<ObservationScope>,
    max_steps: u32,
    max_output_bytes: u32,
    deadline_unix_ms: u64,
}

/// Why no usable authority remains.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum AuthorityError {
    #[error("no tool survives the intersection")]
    NoToolsRemain,
    #[error("no observation scope survives the intersection")]
    NoScopesRemain,
    #[error("the session grant expired before the session started")]
    GrantExpired,
    #[error("the intersected step or output budget is zero")]
    EmptyBudget,
}

impl EffectiveAuthority {
    /// Intersect all five sources.
    pub fn intersect(
        inputs: AuthorityInputs<'_>,
        now_unix_ms: u64,
    ) -> Result<Self, AuthorityError> {
        if !inputs.grant.is_live_at(now_unix_ms) {
            return Err(AuthorityError::GrantExpired);
        }

        let requested_tools: BTreeSet<ToolId> =
            inputs.requested.allowed_tools.iter().copied().collect();
        let granted_tools: BTreeSet<ToolId> = inputs.grant.allowed_tools.iter().copied().collect();
        let tools: BTreeSet<ToolId> = requested_tools
            .iter()
            .copied()
            .filter(|tool| inputs.extension_maximum.tools.contains(tool))
            .filter(|tool| inputs.policy_ceiling.tools.contains(tool))
            .filter(|tool| granted_tools.contains(tool))
            .filter(|tool| inputs.approvals.permits(*tool))
            .collect();
        if tools.is_empty() {
            return Err(AuthorityError::NoToolsRemain);
        }

        let requested_scopes: BTreeSet<ObservationScope> = inputs
            .requested
            .observation_scopes
            .iter()
            .copied()
            .collect();
        let granted_scopes: BTreeSet<ObservationScope> =
            inputs.grant.observation_scopes.iter().copied().collect();
        let scopes: BTreeSet<ObservationScope> = requested_scopes
            .iter()
            .copied()
            .filter(|scope| inputs.extension_maximum.scopes.contains(scope))
            .filter(|scope| inputs.policy_ceiling.scopes.contains(scope))
            .filter(|scope| granted_scopes.contains(scope))
            .collect();
        if scopes.is_empty() {
            return Err(AuthorityError::NoScopesRemain);
        }

        let max_steps = inputs
            .requested
            .max_steps
            .min(inputs.extension_maximum.max_steps)
            .min(inputs.policy_ceiling.max_steps)
            .min(inputs.grant.max_steps);
        let max_output_bytes = inputs
            .requested
            .max_output_bytes
            .min(inputs.extension_maximum.max_output_bytes)
            .min(inputs.policy_ceiling.max_output_bytes)
            .min(inputs.grant.max_output_bytes);
        if max_steps == 0 || max_output_bytes == 0 {
            return Err(AuthorityError::EmptyBudget);
        }

        // A requested deadline of zero means the provider set none. That is not
        // "unbounded" — the grant's expiry is the bound in that case.
        let deadline_unix_ms = if inputs.requested.deadline_unix_ms == 0 {
            inputs.grant.expires_unix_ms
        } else {
            inputs
                .requested
                .deadline_unix_ms
                .min(inputs.grant.expires_unix_ms)
        };

        Ok(Self {
            tools,
            scopes,
            max_steps,
            max_output_bytes,
            deadline_unix_ms,
        })
    }

    /// Whether `tool` may be dispatched.
    #[must_use]
    pub fn permits_tool(&self, tool: ToolId) -> bool {
        self.tools.contains(&tool)
    }

    /// Whether `scope` may be read.
    #[must_use]
    pub fn permits_scope(&self, scope: ObservationScope) -> bool {
        self.scopes.contains(&scope)
    }

    /// Tools in stable order.
    #[must_use]
    pub fn tools(&self) -> Vec<ToolId> {
        self.tools.iter().copied().collect()
    }

    /// Scopes in stable order.
    #[must_use]
    pub fn scopes(&self) -> Vec<ObservationScope> {
        self.scopes.iter().copied().collect()
    }

    #[must_use]
    pub fn max_steps(&self) -> u32 {
        self.max_steps
    }

    #[must_use]
    pub fn max_output_bytes(&self) -> u32 {
        self.max_output_bytes
    }

    #[must_use]
    pub fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }
}
