//! Typed policy evaluation and durable human-approval lifecycle.
//!
//! Policy evaluation is deliberately transport-neutral. It requires a
//! verified admission binding, applies deterministic deny/ask/allow rules,
//! and exposes only digests and bounded identifiers to the approval journal.
//! The journal is hosted by `AgentSessionJournal`, so approvals share the
//! session cursor and do not create a second request/response stream.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::agent_session::{
    AgentSessionErrorCode, AgentSessionEvent, AgentSessionEventEnvelope, AgentSessionId,
    AgentSessionJournal, DurableAgentSessionEvent, IdempotencyKey,
};

/// Maximum number of rules in one policy set.
pub const MAX_POLICY_RULES: usize = 256;
/// Maximum number of operators authorized for one approval.
pub const MAX_AUTHORIZED_OPERATORS: usize = 16;
/// Maximum approval lifetime accepted by the contract.
pub const MAX_APPROVAL_TTL_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_ID_BYTES: usize = 128;

macro_rules! bounded_id {
    ($name:ident, $error:ident, $label:literal) => {
        #[doc = $label]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
        pub struct $name(String);

        impl $name {
            /// Parse a lower-case public identifier.
            pub fn parse(raw: impl Into<String>) -> Result<Self, $error> {
                let raw = raw.into();
                if raw.is_empty() {
                    return Err($error::Empty);
                }
                if raw.len() > MAX_ID_BYTES {
                    return Err($error::TooLong);
                }
                if !raw.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                }) {
                    return Err($error::IllegalCharacter);
                }
                if raw.starts_with('.')
                    || raw.ends_with('.')
                    || raw.contains("..")
                    || raw.contains('/')
                {
                    return Err($error::InvalidBoundary);
                }
                Ok(Self(raw))
            }

            /// Borrow the canonical wire representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl TryFrom<String> for $name {
            type Error = $error;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
        #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
        pub enum $error {
            #[error("identifier is empty")]
            Empty,
            #[error("identifier exceeds the public length limit")]
            TooLong,
            #[error("identifier contains an illegal character")]
            IllegalCharacter,
            #[error("identifier has an invalid boundary")]
            InvalidBoundary,
        }
    };
}

bounded_id!(
    ApprovalRequestId,
    ApprovalRequestIdError,
    "Stable public approval identifier."
);
bounded_id!(
    OperatorId,
    OperatorIdError,
    "Stable public operator identifier."
);

/// Capability being evaluated. The enum prevents policy callsites from
/// inventing unreviewed stringly-typed operation classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PolicyCapability {
    FilesystemRead,
    FilesystemWrite,
    NetworkConnect,
    ProcessSpawn,
    ProcessSignal,
    EnvironmentRead,
    AgentInvoke,
}

/// Rule effect after static signed admission has been verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PolicyEffect {
    Deny,
    Ask,
    Allow,
}

/// One deterministic policy rule. `resource_digest = None` is a wildcard;
/// `Some` is more specific and wins over a wildcard at the same priority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PolicyRule {
    /// Typed capability covered by the rule.
    pub capability: PolicyCapability,
    /// Optional SHA-256 digest of the protected resource or target.
    pub resource_digest: Option<[u8; 32]>,
    /// Higher priority wins after specificity is considered.
    pub priority: u16,
    /// Static effect of this matching rule.
    pub effect: PolicyEffect,
}

/// Bounded static policy rule set. An empty set is deny-all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PolicySet {
    /// Ordered rules; order breaks otherwise identical ties.
    pub rules: Vec<PolicyRule>,
}

impl PolicySet {
    /// Validate and construct a policy set.
    pub fn new(rules: Vec<PolicyRule>) -> Result<Self, PolicyError> {
        if rules.len() > MAX_POLICY_RULES {
            return Err(PolicyError::LimitExceeded);
        }
        Ok(Self { rules })
    }

    /// Compute the stable digest used by approval requests and audit records.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for rule in &self.rules {
            hasher.update([capability_tag(rule.capability)]);
            hasher.update(rule.resource_digest.unwrap_or([0; 32]));
            hasher.update([u8::from(rule.resource_digest.is_some())]);
            hasher.update(rule.priority.to_be_bytes());
            hasher.update([effect_tag(rule.effect)]);
        }
        hasher.finalize().into()
    }

    /// Evaluate an operation after verifying its admission binding.
    #[must_use]
    pub fn evaluate(&self, request: &PolicyRequest) -> PolicyEvaluation {
        let policy_digest = self.digest();
        let base = |decision: PolicyDecision, matched_rule| PolicyEvaluation {
            capability: request.capability,
            resource_digest: request.resource_digest,
            request_digest: request.request_digest,
            admission_plan_digest: request
                .admission
                .as_ref()
                .map(|binding| binding.plan_digest),
            policy_digest,
            matched_rule,
            decision,
        };

        let Some(admission) = request.admission else {
            return base(PolicyDecision::Deny(PolicyReason::NotAdmitted), None);
        };
        if admission.capability_digest != request.capability_digest() {
            return base(PolicyDecision::Deny(PolicyReason::AdmissionMismatch), None);
        }

        let mut best: Option<(usize, &PolicyRule)> = None;
        for (index, rule) in self.rules.iter().enumerate() {
            if rule.capability != request.capability
                || rule
                    .resource_digest
                    .is_some_and(|digest| digest != request.resource_digest)
            {
                continue;
            }
            let replace = best.is_none_or(|(_, best_rule)| {
                (
                    rule.resource_digest.is_some() as u8,
                    rule.priority,
                    effect_rank(rule.effect),
                ) > (
                    best_rule.resource_digest.is_some() as u8,
                    best_rule.priority,
                    effect_rank(best_rule.effect),
                )
            });
            if replace {
                best = Some((index, rule));
            }
        }

        match best {
            Some((index, rule)) => base(rule.effect.into(), Some(index as u32)),
            None => base(PolicyDecision::Deny(PolicyReason::DefaultDeny), None),
        }
    }
}

/// Binding supplied only after signed plan admission and capability checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SignedAdmission {
    /// Content digest of the verified signed execution plan.
    pub plan_digest: [u8; 32],
    /// Digest of the exact capability/resource pair admitted by the plan.
    pub capability_digest: [u8; 32],
}

/// Operation input to policy evaluation. Raw operation bytes stay outside the
/// contract; callers provide a digest instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PolicyRequest {
    /// Typed operation being requested.
    pub capability: PolicyCapability,
    /// SHA-256 digest of the protected resource or target.
    pub resource_digest: [u8; 32],
    /// SHA-256 digest of the request payload.
    pub request_digest: [u8; 32],
    /// Verified admission binding, absent until static admission succeeds.
    pub admission: Option<SignedAdmission>,
}

impl PolicyRequest {
    /// Digest the exact capability/resource pair used by admission binding.
    #[must_use]
    pub fn capability_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([capability_tag(self.capability)]);
        hasher.update(self.resource_digest);
        hasher.finalize().into()
    }
}

/// Result of static policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PolicyDecision {
    Allow,
    Deny(PolicyReason),
    Ask(PolicyReason),
}

impl PolicyDecision {
    /// Map a static decision to the existing audit sink without exposing
    /// operation bytes or human-readable resource names.
    #[must_use]
    pub fn audit_action(self) -> crate::policy::audit::AuditAction {
        match self {
            Self::Allow => crate::policy::audit::AuditAction::PolicyAllowed,
            Self::Deny(_) => crate::policy::audit::AuditAction::PolicyDenied,
            Self::Ask(_) => crate::policy::audit::AuditAction::PolicyApprovalRequired,
        }
    }
}

impl From<PolicyEffect> for PolicyDecision {
    fn from(value: PolicyEffect) -> Self {
        match value {
            PolicyEffect::Allow => Self::Allow,
            PolicyEffect::Deny => Self::Deny(PolicyReason::ExplicitDeny),
            PolicyEffect::Ask => Self::Ask(PolicyReason::ApprovalRequired),
        }
    }
}

/// Closed reason vocabulary safe for audit and approval metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PolicyReason {
    NotAdmitted,
    AdmissionMismatch,
    DefaultDeny,
    ExplicitDeny,
    ApprovalRequired,
}

/// Complete deterministic evaluation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PolicyEvaluation {
    /// Operation evaluated.
    pub capability: PolicyCapability,
    /// Protected resource digest.
    pub resource_digest: [u8; 32],
    /// Request digest.
    pub request_digest: [u8; 32],
    /// Verified plan digest, when admission was present.
    pub admission_plan_digest: Option<[u8; 32]>,
    /// Policy-set digest used for the decision.
    pub policy_digest: [u8; 32],
    /// Matching rule index, if one matched.
    pub matched_rule: Option<u32>,
    /// Allow, deny, or ask result.
    pub decision: PolicyDecision,
}

/// Stable policy construction/evaluation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PolicyError {
    #[error("policy rule limit exceeded")]
    LimitExceeded,
}

/// Why an approval was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ApprovalReason {
    PolicyRule,
    ExplicitOperatorReview,
}

/// Durable approval request metadata. It contains no command, path, secret,
/// or human-readable diagnostic text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ApprovalRequest {
    pub approval_id: ApprovalRequestId,
    pub session_id: AgentSessionId,
    pub idempotency_key: IdempotencyKey,
    pub capability: PolicyCapability,
    pub resource_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub admission_plan_digest: [u8; 32],
    pub reason: ApprovalReason,
    pub authorized_operators: Vec<OperatorId>,
    pub expires_at_unix_ms: u64,
}

impl ApprovalRequest {
    fn validate(&self, now_unix_ms: u64) -> Result<(), AgentApprovalError> {
        if self.session_id.as_str().is_empty()
            || self.authorized_operators.is_empty()
            || self.authorized_operators.len() > MAX_AUTHORIZED_OPERATORS
            || self.expires_at_unix_ms <= now_unix_ms
            || self.expires_at_unix_ms.saturating_sub(now_unix_ms) > MAX_APPROVAL_TTL_MS
        {
            return Err(AgentApprovalError::InvalidRequest);
        }
        Ok(())
    }
}

/// Response submitted by an authorized operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ApprovalResponse {
    pub approval_id: ApprovalRequestId,
    pub operator_id: OperatorId,
    pub outcome: ApprovalOutcome,
    pub response_nonce: u64,
    /// Free-form rationale for the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional ticket / incident / change-request reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_ref: Option<String>,
}

/// Terminal operator outcome. Rationale is now carried in `ApprovalResponse.reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ApprovalOutcome {
    Approved,
    Denied,
}

/// Approval lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Expired,
    Canceled,
}

/// Durable approval lifecycle event embedded in the agent-session journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum AgentApprovalEvent {
    Requested {
        request: Box<ApprovalRequest>,
    },
    Responded {
        approval_id: ApprovalRequestId,
        operator_id: OperatorId,
        outcome: ApprovalOutcome,
        response_nonce: u64,
        /// Rationale recorded by the operator.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        /// Optional ticket / incident / change-request reference.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ticket_ref: Option<String>,
    },
    Expired {
        approval_id: ApprovalRequestId,
    },
    Canceled {
        approval_id: ApprovalRequestId,
    },
}

impl AgentApprovalEvent {
    /// Validate bounded event fields without consulting mutable state.
    pub fn validate(&self) -> Result<(), AgentSessionErrorCode> {
        match self {
            Self::Requested { request } => {
                if request.authorized_operators.is_empty()
                    || request.authorized_operators.len() > MAX_AUTHORIZED_OPERATORS
                    || request.expires_at_unix_ms == 0
                {
                    return Err(AgentSessionErrorCode::LimitExceeded);
                }
            }
            Self::Responded { response_nonce, .. } if *response_nonce == 0 => {
                return Err(AgentSessionErrorCode::MalformedEvent);
            }
            Self::Responded { .. } | Self::Expired { .. } | Self::Canceled { .. } => {}
        }
        Ok(())
    }

    /// Map a durable lifecycle event to the existing audit sink.
    #[must_use]
    pub fn audit_action(&self) -> crate::policy::audit::AuditAction {
        match self {
            Self::Requested { .. } => crate::policy::audit::AuditAction::ApprovalRequested,
            Self::Responded { outcome, .. } => match outcome {
                ApprovalOutcome::Approved => crate::policy::audit::AuditAction::ApprovalApproved,
                ApprovalOutcome::Denied => crate::policy::audit::AuditAction::ApprovalDenied,
            },
            Self::Expired { .. } => crate::policy::audit::AuditAction::ApprovalExpired,
            Self::Canceled { .. } => crate::policy::audit::AuditAction::ApprovalCanceled,
        }
    }
}

#[derive(Debug, Clone)]
struct ApprovalRecord {
    request: ApprovalRequest,
    state: ApprovalState,
}

/// Result of creating or retrying an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalRequestOutcome {
    pub created: bool,
    pub state: ApprovalState,
}

/// Reference approval ledger backed by the agent-session durable journal.
#[derive(Debug, Clone)]
pub struct ApprovalLedger {
    session_id: AgentSessionId,
    records: Vec<ApprovalRecord>,
}

impl ApprovalLedger {
    /// Create an empty ledger for an existing agent session.
    pub fn new(session_id: AgentSessionId) -> Self {
        Self {
            session_id,
            records: Vec::new(),
        }
    }

    /// Rebuild approval state from the session's durable event history.
    pub fn from_history(
        session_id: AgentSessionId,
        history: &[AgentSessionEventEnvelope],
    ) -> Result<Self, AgentApprovalError> {
        let mut ledger = Self::new(session_id.clone());
        for envelope in history {
            envelope
                .validate()
                .map_err(|_| AgentApprovalError::MalformedHistory)?;
            if envelope.session_id != session_id {
                return Err(AgentApprovalError::MalformedHistory);
            }
            if let AgentSessionEvent::Durable {
                event: DurableAgentSessionEvent::Approval { event },
            } = &envelope.event
            {
                ledger.apply_replayed_event(event)?;
            }
        }
        Ok(ledger)
    }

    /// Record a new approval request only for an `Ask` evaluation.
    pub fn request(
        &mut self,
        journal: &mut AgentSessionJournal,
        evaluation: &PolicyEvaluation,
        request: ApprovalRequest,
        now_unix_ms: u64,
    ) -> Result<ApprovalRequestOutcome, AgentApprovalError> {
        if request.session_id != self.session_id
            || evaluation.policy_digest != request.policy_digest
            || evaluation.capability != request.capability
            || evaluation.resource_digest != request.resource_digest
            || evaluation.request_digest != request.request_digest
            || evaluation.admission_plan_digest != Some(request.admission_plan_digest)
        {
            return Err(AgentApprovalError::AdmissionMismatch);
        }
        if !matches!(evaluation.decision, PolicyDecision::Ask(_)) {
            return Err(AgentApprovalError::PolicyDenied);
        }
        request.validate(now_unix_ms)?;
        if let Some(existing) = self.find(&request.approval_id) {
            if existing.request == request {
                return Ok(ApprovalRequestOutcome {
                    created: false,
                    state: existing.state,
                });
            }
            return Err(AgentApprovalError::DuplicateRequest);
        }
        journal
            .record_approval_event(
                AgentApprovalEvent::Requested {
                    request: Box::new(request.clone()),
                },
                now_unix_ms,
            )
            .map_err(AgentApprovalError::Session)?;
        self.records.push(ApprovalRecord {
            request,
            state: ApprovalState::Pending,
        });
        Ok(ApprovalRequestOutcome {
            created: true,
            state: ApprovalState::Pending,
        })
    }

    /// Apply the first authorized response. Later responses are duplicates.
    pub fn respond(
        &mut self,
        journal: &mut AgentSessionJournal,
        response: ApprovalResponse,
        now_unix_ms: u64,
    ) -> Result<ApprovalState, AgentApprovalError> {
        let index = self.index(&response.approval_id)?;
        let record = &self.records[index];
        if !record
            .request
            .authorized_operators
            .contains(&response.operator_id)
        {
            return Err(AgentApprovalError::UnauthorizedResponder);
        }
        if response.response_nonce == 0 {
            return Err(AgentApprovalError::MalformedResponse);
        }
        if record.state != ApprovalState::Pending {
            return Err(AgentApprovalError::DuplicateResponse);
        }
        if now_unix_ms >= record.request.expires_at_unix_ms {
            self.expire_record(journal, index, now_unix_ms)?;
            return Err(AgentApprovalError::Expired);
        }
        journal
            .record_approval_event(
                AgentApprovalEvent::Responded {
                    approval_id: response.approval_id,
                    operator_id: response.operator_id,
                    outcome: response.outcome,
                    response_nonce: response.response_nonce,
                    reason: response.reason.clone(),
                    ticket_ref: response.ticket_ref.clone(),
                },
                now_unix_ms,
            )
            .map_err(AgentApprovalError::Session)?;
        let state = match response.outcome {
            ApprovalOutcome::Approved => ApprovalState::Approved,
            ApprovalOutcome::Denied => ApprovalState::Denied,
        };
        self.records[index].state = state;
        Ok(state)
    }

    /// Expire a pending approval once its deadline has passed.
    pub fn expire(
        &mut self,
        journal: &mut AgentSessionJournal,
        approval_id: &ApprovalRequestId,
        now_unix_ms: u64,
    ) -> Result<(), AgentApprovalError> {
        let index = self.index(approval_id)?;
        if self.records[index].state != ApprovalState::Pending {
            return Err(AgentApprovalError::InvalidState);
        }
        if now_unix_ms < self.records[index].request.expires_at_unix_ms {
            return Err(AgentApprovalError::NotExpired);
        }
        self.expire_record(journal, index, now_unix_ms)
    }

    /// Cancel a pending approval without granting its capability.
    pub fn cancel(
        &mut self,
        journal: &mut AgentSessionJournal,
        approval_id: &ApprovalRequestId,
        now_unix_ms: u64,
    ) -> Result<(), AgentApprovalError> {
        let index = self.index(approval_id)?;
        if self.records[index].state != ApprovalState::Pending {
            return Err(AgentApprovalError::InvalidState);
        }
        journal
            .record_approval_event(
                AgentApprovalEvent::Canceled {
                    approval_id: approval_id.clone(),
                },
                now_unix_ms,
            )
            .map_err(AgentApprovalError::Session)?;
        self.records[index].state = ApprovalState::Canceled;
        Ok(())
    }

    /// Return the current state of an approval.
    pub fn state(
        &self,
        approval_id: &ApprovalRequestId,
    ) -> Result<ApprovalState, AgentApprovalError> {
        self.index(approval_id)
            .map(|index| self.records[index].state)
    }

    /// Content-address the ledger's decision state.
    ///
    /// A session records this at park time and a resume compares against it, so
    /// what it covers is what a resume treats as "the ledger has not moved":
    /// every record's identity, the capability it was asked about, and the
    /// state it reached. Timestamps are deliberately excluded — two ledgers
    /// that made the same decisions hash alike however long ago they were
    /// asked, so a session cannot refuse itself for the passage of time.
    ///
    /// Not covered: `resource_digest`, `policy_digest`, `admission_plan_digest`,
    /// and `authorized_operators` play no part in the hash. That is in spec —
    /// the head names the decision, not every input that produced it — but is
    /// worth stating plainly since this is a persistence contract the moment a
    /// caller records one.
    ///
    /// The hash is order-dependent: records fold in `self.records`' iteration
    /// order. That is safe today because records are append-only (`request`
    /// pushes, nothing reorders or removes), but a future rebuild path that
    /// reconstructed a ledger's records in a different order would move the
    /// head even though the decisions were identical.
    #[must_use]
    pub fn head(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.session_id.as_str().as_bytes());
        hasher.update([0u8]); // terminator: ids cannot run together
        for record in &self.records {
            hasher.update(record.request.approval_id.as_str().as_bytes());
            hasher.update([0u8]); // terminator: ids cannot run together
            hasher.update([capability_tag(record.request.capability)]);
            hasher.update([state_tag(record.state)]);
        }
        hasher.finalize().into()
    }

    fn expire_record(
        &mut self,
        journal: &mut AgentSessionJournal,
        index: usize,
        now_unix_ms: u64,
    ) -> Result<(), AgentApprovalError> {
        let approval_id = self.records[index].request.approval_id.clone();
        journal
            .record_approval_event(AgentApprovalEvent::Expired { approval_id }, now_unix_ms)
            .map_err(AgentApprovalError::Session)?;
        self.records[index].state = ApprovalState::Expired;
        Ok(())
    }

    fn find(&self, approval_id: &ApprovalRequestId) -> Option<&ApprovalRecord> {
        self.records
            .iter()
            .find(|record| record.request.approval_id == *approval_id)
    }

    fn index(&self, approval_id: &ApprovalRequestId) -> Result<usize, AgentApprovalError> {
        self.records
            .iter()
            .position(|record| record.request.approval_id == *approval_id)
            .ok_or(AgentApprovalError::NotFound)
    }

    fn apply_replayed_event(
        &mut self,
        event: &AgentApprovalEvent,
    ) -> Result<(), AgentApprovalError> {
        event
            .validate()
            .map_err(AgentApprovalError::EventValidation)?;
        match event {
            AgentApprovalEvent::Requested { request } => {
                if request.session_id != self.session_id
                    || self.find(&request.approval_id).is_some()
                {
                    return Err(AgentApprovalError::MalformedHistory);
                }
                self.records.push(ApprovalRecord {
                    request: request.as_ref().clone(),
                    state: ApprovalState::Pending,
                });
            }
            AgentApprovalEvent::Responded {
                approval_id,
                operator_id,
                outcome,
                ..
            } => {
                let index = self.index(approval_id)?;
                let record = &mut self.records[index];
                if record.state != ApprovalState::Pending
                    || !record.authorized_operator(operator_id)
                {
                    return Err(AgentApprovalError::MalformedHistory);
                }
                record.state = match outcome {
                    ApprovalOutcome::Approved => ApprovalState::Approved,
                    ApprovalOutcome::Denied => ApprovalState::Denied,
                };
            }
            AgentApprovalEvent::Expired { approval_id } => {
                let index = self.index(approval_id)?;
                if self.records[index].state != ApprovalState::Pending {
                    return Err(AgentApprovalError::MalformedHistory);
                }
                self.records[index].state = ApprovalState::Expired;
            }
            AgentApprovalEvent::Canceled { approval_id } => {
                let index = self.index(approval_id)?;
                if self.records[index].state != ApprovalState::Pending {
                    return Err(AgentApprovalError::MalformedHistory);
                }
                self.records[index].state = ApprovalState::Canceled;
            }
        }
        Ok(())
    }
}

impl ApprovalRecord {
    fn authorized_operator(&self, operator_id: &OperatorId) -> bool {
        self.request.authorized_operators.contains(operator_id)
    }
}

/// Typed approval failure vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum AgentApprovalError {
    #[error("approval request is invalid or outside the bounded lifetime")]
    InvalidRequest,
    #[error("approval response is malformed")]
    MalformedResponse,
    #[error("approval event history is malformed")]
    MalformedHistory,
    #[error("approval event failed validation: {0:?}")]
    EventValidation(AgentSessionErrorCode),
    #[error("approval is not authorized for this operator")]
    UnauthorizedResponder,
    #[error("approval is not authorized by static policy admission")]
    AdmissionMismatch,
    #[error("policy did not produce an approval-required decision")]
    PolicyDenied,
    #[error("approval request was duplicated with different metadata")]
    DuplicateRequest,
    #[error("approval response was duplicated or arrived after a terminal state")]
    DuplicateResponse,
    #[error("approval request was not found")]
    NotFound,
    #[error("approval request has expired")]
    Expired,
    #[error("approval request has not expired")]
    NotExpired,
    #[error("approval request is not pending")]
    InvalidState,
    #[error("session journal refused the approval event: {0}")]
    Session(#[from] crate::protocol::agent_session::AgentSessionError),
}

impl AgentApprovalError {
    /// Map a refused operation to the existing audit sink. Callers attach
    /// only digests and bounded identifiers to the resulting audit detail.
    #[must_use]
    pub fn audit_action(&self) -> crate::policy::audit::AuditAction {
        crate::policy::audit::AuditAction::ApprovalRefused
    }
}

fn capability_tag(capability: PolicyCapability) -> u8 {
    match capability {
        PolicyCapability::FilesystemRead => 1,
        PolicyCapability::FilesystemWrite => 2,
        PolicyCapability::NetworkConnect => 3,
        PolicyCapability::ProcessSpawn => 4,
        PolicyCapability::ProcessSignal => 5,
        PolicyCapability::EnvironmentRead => 6,
        PolicyCapability::AgentInvoke => 7,
    }
}

fn effect_tag(effect: PolicyEffect) -> u8 {
    match effect {
        PolicyEffect::Deny => 1,
        PolicyEffect::Ask => 2,
        PolicyEffect::Allow => 3,
    }
}

/// Stable tag per approval state. Written out rather than derived so renaming a
/// variant cannot silently move every recorded head.
fn state_tag(state: ApprovalState) -> u8 {
    match state {
        ApprovalState::Pending => 0,
        ApprovalState::Approved => 1,
        ApprovalState::Denied => 2,
        ApprovalState::Expired => 3,
        ApprovalState::Canceled => 4,
    }
}

fn effect_rank(effect: PolicyEffect) -> u8 {
    match effect {
        PolicyEffect::Allow => 1,
        PolicyEffect::Ask => 2,
        PolicyEffect::Deny => 3,
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::protocol::agent_session::{AgentSessionState, RetentionPolicy};

    fn session() -> AgentSessionId {
        AgentSessionId::parse("approval-session").expect("valid session")
    }

    fn approval_id(raw: &str) -> ApprovalRequestId {
        ApprovalRequestId::parse(raw).expect("valid approval id")
    }

    fn operator(raw: &str) -> OperatorId {
        OperatorId::parse(raw).expect("valid operator id")
    }

    fn request(capability: PolicyCapability, digest: [u8; 32]) -> PolicyRequest {
        let unsigned = PolicyRequest {
            capability,
            resource_digest: digest,
            request_digest: [8; 32],
            admission: None,
        };
        PolicyRequest {
            admission: Some(SignedAdmission {
                plan_digest: [9; 32],
                capability_digest: unsigned.capability_digest(),
            }),
            ..unsigned
        }
    }

    fn ask_evaluation() -> (PolicyRequest, PolicyEvaluation) {
        let request = request(PolicyCapability::FilesystemWrite, [4; 32]);
        let policy = PolicySet::new(vec![PolicyRule {
            capability: PolicyCapability::FilesystemWrite,
            resource_digest: None,
            priority: 10,
            effect: PolicyEffect::Ask,
        }])
        .expect("policy");
        let evaluation = policy.evaluate(&request);
        assert!(matches!(evaluation.decision, PolicyDecision::Ask(_)));
        (request, evaluation)
    }

    fn approval_request(request: &PolicyRequest, evaluation: &PolicyEvaluation) -> ApprovalRequest {
        ApprovalRequest {
            approval_id: approval_id("approval-1"),
            session_id: session(),
            idempotency_key: IdempotencyKey::parse("approval-retry-1").expect("key"),
            capability: request.capability,
            resource_digest: request.resource_digest,
            request_digest: request.request_digest,
            policy_digest: evaluation.policy_digest,
            admission_plan_digest: [9; 32],
            reason: ApprovalReason::PolicyRule,
            authorized_operators: vec![operator("ops-a")],
            expires_at_unix_ms: 10_000,
        }
    }

    fn journal() -> AgentSessionJournal {
        AgentSessionJournal::open(session(), [1; 32], 1, RetentionPolicy::default())
            .expect("open")
            .0
    }

    #[test]
    fn no_admission_and_default_policy_deny() {
        let request = PolicyRequest {
            capability: PolicyCapability::NetworkConnect,
            resource_digest: [1; 32],
            request_digest: [2; 32],
            admission: None,
        };
        let evaluation = PolicySet::default().evaluate(&request);
        assert_eq!(
            evaluation.decision,
            PolicyDecision::Deny(PolicyReason::NotAdmitted)
        );
    }

    #[test]
    fn specific_deny_beats_wildcard_allow_and_ask() {
        let request = request(PolicyCapability::NetworkConnect, [3; 32]);
        let policy = PolicySet::new(vec![
            PolicyRule {
                capability: PolicyCapability::NetworkConnect,
                resource_digest: None,
                priority: 100,
                effect: PolicyEffect::Allow,
            },
            PolicyRule {
                capability: PolicyCapability::NetworkConnect,
                resource_digest: Some([3; 32]),
                priority: 1,
                effect: PolicyEffect::Deny,
            },
            PolicyRule {
                capability: PolicyCapability::NetworkConnect,
                resource_digest: None,
                priority: 100,
                effect: PolicyEffect::Ask,
            },
        ])
        .expect("policy");
        assert_eq!(
            policy.evaluate(&request).decision,
            PolicyDecision::Deny(PolicyReason::ExplicitDeny)
        );
    }

    #[test]
    fn policy_and_approval_wire_shapes_project_to_audit_actions() {
        let (request, evaluation) = ask_evaluation();
        assert_eq!(
            evaluation.decision.audit_action(),
            crate::policy::audit::AuditAction::PolicyApprovalRequired
        );
        let approval = approval_request(&request, &evaluation);
        let requested = AgentApprovalEvent::Requested {
            request: Box::new(approval),
        };
        let json = serde_json::to_string(&requested).expect("serialize approval");
        let roundtrip: AgentApprovalEvent =
            serde_json::from_str(&json).expect("deserialize approval");
        assert_eq!(roundtrip, requested);
        assert_eq!(
            roundtrip.audit_action(),
            crate::policy::audit::AuditAction::ApprovalRequested
        );
        assert_eq!(
            AgentApprovalError::UnauthorizedResponder.audit_action(),
            crate::policy::audit::AuditAction::ApprovalRefused
        );
    }

    #[test]
    fn approval_is_durable_authorized_first_response_and_restartable() {
        let (request, evaluation) = ask_evaluation();
        let mut journal = journal();
        let mut ledger = ApprovalLedger::new(session());
        let approval = approval_request(&request, &evaluation);
        let created = ledger
            .request(&mut journal, &evaluation, approval.clone(), 1_000)
            .expect("request approval");
        assert!(created.created);
        let unauthorized = ledger.respond(
            &mut journal,
            ApprovalResponse {
                approval_id: approval.approval_id.clone(),
                operator_id: operator("ops-b"),
                outcome: ApprovalOutcome::Approved,
                response_nonce: 1,
                reason: None,
                ticket_ref: None,
            },
            1_001,
        );
        assert_eq!(
            unauthorized.expect_err("unauthorized response").to_string(),
            "approval is not authorized for this operator"
        );
        assert_eq!(
            ledger
                .respond(
                    &mut journal,
                    ApprovalResponse {
                        approval_id: approval.approval_id.clone(),
                        operator_id: operator("ops-a"),
                        outcome: ApprovalOutcome::Approved,
                        response_nonce: 2,
                        reason: None,
                        ticket_ref: None,
                    },
                    1_002,
                )
                .expect("authorized response"),
            ApprovalState::Approved
        );
        let history = journal.history(None, 32).expect("history");
        let rebuilt_journal = AgentSessionJournal::from_history(
            session(),
            history.events.clone(),
            RetentionPolicy::default(),
        )
        .expect("restart journal");
        assert_eq!(rebuilt_journal.state(), AgentSessionState::Ready);
        let rebuilt = ApprovalLedger::from_history(session(), &history.events).expect("restart");
        assert_eq!(
            rebuilt.state(&approval.approval_id).expect("state"),
            ApprovalState::Approved
        );
        assert!(history.events.iter().all(|event| {
            !serde_json::to_string(event)
                .expect("json")
                .contains("secret")
        }));
    }

    #[test]
    fn expired_and_canceled_approvals_cannot_be_released() {
        let (request, evaluation) = ask_evaluation();
        let mut journal = journal();
        let mut ledger = ApprovalLedger::new(session());
        let mut approval = approval_request(&request, &evaluation);
        approval.expires_at_unix_ms = 2_000;
        ledger
            .request(&mut journal, &evaluation, approval.clone(), 1_000)
            .expect("request");
        ledger
            .expire(&mut journal, &approval.approval_id, 2_000)
            .expect("expire");
        assert_eq!(
            ledger
                .respond(
                    &mut journal,
                    ApprovalResponse {
                        approval_id: approval.approval_id.clone(),
                        operator_id: operator("ops-a"),
                        outcome: ApprovalOutcome::Approved,
                        response_nonce: 1,
                        reason: None,
                        ticket_ref: None,
                    },
                    2_001,
                )
                .expect_err("late response")
                .to_string(),
            "approval response was duplicated or arrived after a terminal state"
        );

        let mut canceled = approval_request(&request, &evaluation);
        canceled.approval_id = approval_id("approval-2");
        canceled.idempotency_key = IdempotencyKey::parse("approval-retry-2").expect("key");
        canceled.expires_at_unix_ms = 10_000;
        ledger
            .request(&mut journal, &evaluation, canceled.clone(), 2_001)
            .expect("second request");
        ledger
            .cancel(&mut journal, &canceled.approval_id, 2_002)
            .expect("cancel");
        assert_eq!(
            ledger
                .respond(
                    &mut journal,
                    ApprovalResponse {
                        approval_id: canceled.approval_id,
                        operator_id: operator("ops-a"),
                        outcome: ApprovalOutcome::Approved,
                        response_nonce: 2,
                        reason: None,
                        ticket_ref: None,
                    },
                    2_003,
                )
                .expect_err("canceled response")
                .to_string(),
            "approval response was duplicated or arrived after a terminal state"
        );
    }

    #[test]
    fn an_empty_ledger_has_a_stable_head() {
        // On its own this would pass against a `head()` that returns a fixed
        // constant — it only pins that two independently constructed empty
        // ledgers agree, not that `head()` is a function of any real input.
        // `a_decision_moves_the_head` is what rules out constancy; the
        // `_do_not_collide` / `_differ` tests below are what rule out a hash
        // that is a function of state alone.
        let a = ApprovalLedger::new(AgentSessionId::parse("sess-a").unwrap());
        let b = ApprovalLedger::new(AgentSessionId::parse("sess-a").unwrap());
        assert_eq!(a.head(), b.head());
    }

    #[test]
    fn a_decision_moves_the_head() {
        let (request, evaluation) = ask_evaluation();
        let mut journal = journal();
        let mut ledger = ApprovalLedger::new(session());
        let approval = approval_request(&request, &evaluation);
        ledger
            .request(&mut journal, &evaluation, approval.clone(), 1_000)
            .expect("request approval");
        let pending_head = ledger.head();
        ledger
            .respond(
                &mut journal,
                ApprovalResponse {
                    approval_id: approval.approval_id.clone(),
                    operator_id: operator("ops-a"),
                    outcome: ApprovalOutcome::Approved,
                    response_nonce: 1,
                    reason: None,
                    ticket_ref: None,
                },
                1_001,
            )
            .expect("authorized response");
        assert_ne!(
            pending_head,
            ledger.head(),
            "an answered request must not hash the same as a pending one"
        );
    }

    #[test]
    fn the_head_ignores_when_a_decision_was_made() {
        let (request, evaluation) = ask_evaluation();

        let mut journal_a = journal();
        let mut ledger_a = ApprovalLedger::new(session());
        let mut approval_a = approval_request(&request, &evaluation);
        approval_a.expires_at_unix_ms = 5_000;
        ledger_a
            .request(&mut journal_a, &evaluation, approval_a.clone(), 1_000)
            .expect("request approval a");
        ledger_a
            .respond(
                &mut journal_a,
                ApprovalResponse {
                    approval_id: approval_a.approval_id.clone(),
                    operator_id: operator("ops-a"),
                    outcome: ApprovalOutcome::Approved,
                    response_nonce: 1,
                    reason: None,
                    ticket_ref: None,
                },
                1_001,
            )
            .expect("response a");

        let mut journal_b = journal();
        let mut ledger_b = ApprovalLedger::new(session());
        let mut approval_b = approval_request(&request, &evaluation);
        approval_b.expires_at_unix_ms = 50_000;
        ledger_b
            .request(&mut journal_b, &evaluation, approval_b.clone(), 1_000)
            .expect("request approval b");
        ledger_b
            .respond(
                &mut journal_b,
                ApprovalResponse {
                    approval_id: approval_b.approval_id.clone(),
                    operator_id: operator("ops-a"),
                    outcome: ApprovalOutcome::Approved,
                    response_nonce: 1,
                    reason: None,
                    ticket_ref: None,
                },
                1_001,
            )
            .expect("response b");

        assert_eq!(
            ledger_a.head(),
            ledger_b.head(),
            "identical decisions at different expiry timestamps must hash alike"
        );
    }

    #[test]
    fn two_different_decisions_do_not_collide() {
        let (request, evaluation) = ask_evaluation();

        let mut journal_a = journal();
        let mut ledger_a = ApprovalLedger::new(session());
        let approval_a = approval_request(&request, &evaluation);
        ledger_a
            .request(&mut journal_a, &evaluation, approval_a.clone(), 1_000)
            .expect("request approval a");
        ledger_a
            .respond(
                &mut journal_a,
                ApprovalResponse {
                    approval_id: approval_a.approval_id.clone(),
                    operator_id: operator("ops-a"),
                    outcome: ApprovalOutcome::Approved,
                    response_nonce: 1,
                    reason: None,
                    ticket_ref: None,
                },
                1_001,
            )
            .expect("response a");

        let mut journal_b = journal();
        let mut ledger_b = ApprovalLedger::new(session());
        let approval_b = approval_request(&request, &evaluation);
        ledger_b
            .request(&mut journal_b, &evaluation, approval_b.clone(), 1_000)
            .expect("request approval b");
        ledger_b
            .respond(
                &mut journal_b,
                ApprovalResponse {
                    approval_id: approval_b.approval_id.clone(),
                    operator_id: operator("ops-a"),
                    outcome: ApprovalOutcome::Denied,
                    response_nonce: 1,
                    reason: None,
                    ticket_ref: None,
                },
                1_001,
            )
            .expect("response b");

        assert_ne!(
            ledger_a.head(),
            ledger_b.head(),
            "an approved and a denied request over the same capability must not collide"
        );
    }

    #[test]
    fn a_different_approval_id_moves_the_head() {
        // The fence's own motivating scenario: same record count, same
        // capability, same (pending) state — only the identity of *which*
        // approval is pending differs. Session parks with X pending over
        // capability C; while parked X is canceled and a fresh Y is opened
        // pending over the same C. If `head()` did not cover `approval_id`,
        // those two ledgers would hash identically and a resume would not
        // notice the swap.
        let (request, evaluation) = ask_evaluation();

        let mut journal_a = journal();
        let mut ledger_a = ApprovalLedger::new(session());
        let approval_a = approval_request(&request, &evaluation);
        ledger_a
            .request(&mut journal_a, &evaluation, approval_a.clone(), 1_000)
            .expect("request approval a");

        let mut journal_b = journal();
        let mut ledger_b = ApprovalLedger::new(session());
        let mut approval_b = approval_request(&request, &evaluation);
        approval_b.approval_id = approval_id("approval-2");
        approval_b.idempotency_key = IdempotencyKey::parse("approval-retry-2").expect("key");
        ledger_b
            .request(&mut journal_b, &evaluation, approval_b.clone(), 1_000)
            .expect("request approval b");

        assert_ne!(
            ledger_a.head(),
            ledger_b.head(),
            "two different pending approval ids over the same capability must not collide"
        );
    }

    #[test]
    fn a_different_capability_moves_the_head() {
        // Same approval id, same (pending) state — only the capability the
        // approval was asked over differs.
        let (request_a, evaluation_a) = ask_evaluation();
        let approval_a = approval_request(&request_a, &evaluation_a);
        let mut journal_a = journal();
        let mut ledger_a = ApprovalLedger::new(session());
        ledger_a
            .request(&mut journal_a, &evaluation_a, approval_a.clone(), 1_000)
            .expect("request approval a");

        let request_b = request(PolicyCapability::NetworkConnect, [4; 32]);
        let policy_b = PolicySet::new(vec![PolicyRule {
            capability: PolicyCapability::NetworkConnect,
            resource_digest: None,
            priority: 10,
            effect: PolicyEffect::Ask,
        }])
        .expect("policy");
        let evaluation_b = policy_b.evaluate(&request_b);
        assert!(matches!(evaluation_b.decision, PolicyDecision::Ask(_)));
        let approval_b = approval_request(&request_b, &evaluation_b);
        let mut journal_b = journal();
        let mut ledger_b = ApprovalLedger::new(session());
        ledger_b
            .request(&mut journal_b, &evaluation_b, approval_b.clone(), 1_000)
            .expect("request approval b");

        assert_ne!(
            ledger_a.head(),
            ledger_b.head(),
            "the same approval id over two different capabilities must not collide"
        );
    }

    #[test]
    fn a_different_session_id_moves_the_head() {
        // Same approval id, same capability, same (pending) state — only the
        // owning session differs.
        let (request_shape, evaluation) = ask_evaluation();

        let mut journal_a = journal();
        let mut ledger_a = ApprovalLedger::new(session());
        let approval_a = approval_request(&request_shape, &evaluation);
        ledger_a
            .request(&mut journal_a, &evaluation, approval_a.clone(), 1_000)
            .expect("request approval a");

        let session_b = AgentSessionId::parse("approval-session-b").expect("valid session");
        let mut journal_b =
            AgentSessionJournal::open(session_b.clone(), [1; 32], 1, RetentionPolicy::default())
                .expect("open")
                .0;
        let mut ledger_b = ApprovalLedger::new(session_b.clone());
        let mut approval_b = approval_request(&request_shape, &evaluation);
        approval_b.session_id = session_b.clone();
        ledger_b
            .request(&mut journal_b, &evaluation, approval_b.clone(), 1_000)
            .expect("request approval b");

        assert_ne!(
            ledger_a.head(),
            ledger_b.head(),
            "the same approval decision under two different sessions must not collide"
        );
    }
}
