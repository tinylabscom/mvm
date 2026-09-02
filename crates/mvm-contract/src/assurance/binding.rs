//! What MVM admitted, as opposed to what the provider asked for.
//!
//! Every field here is derived from a signed [`ExecutionPlan`] or from a
//! short-lived grant the host minted. None of it is copyable from a provider
//! request, which is the whole point: the provider states an *intent*
//! (`artifact_locator`, `requested_policy_digest`) and this states the *fact*.
//! Correlation downstream compares the two, and a disagreement is a reason to
//! refuse rather than a discrepancy to paper over.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::ids::{AssuranceId, EvidenceRef, Sha256Digest};
use super::input::{ObservationScope, ToolId};
use crate::plan::execution_plan::ExecutionPlan;
use crate::plan::types::AttestationMode;

/// The short-lived grant a session runs under.
///
/// Separate from the plan because it expires on a different clock: the plan is
/// admitted once, the grant is minted per session and must be re-checked on
/// every call. A call arriving after `expires_unix_ms` is refused even though
/// the plan that admitted it is still perfectly valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionGrant {
    /// Digest of the signed grant document. The grant itself stays host-side.
    pub grant_digest: Sha256Digest,
    /// Wall-clock expiry.
    pub expires_unix_ms: u64,
    /// Single-use nonce. A second call presenting it is a replay.
    pub nonce: AssuranceId,
    /// Tools this grant authorizes, already intersected down from the request.
    pub allowed_tools: Vec<ToolId>,
    /// Observation channels this grant authorizes.
    pub observation_scopes: Vec<ObservationScope>,
    /// Maximum campaign steps this grant authorizes.
    pub max_steps: u32,
    /// Maximum candidate/output bytes this grant authorizes.
    pub max_output_bytes: u32,
}

impl SessionGrant {
    /// Whether the grant is still live at `now_unix_ms`.
    ///
    /// Expiry is exclusive: a call landing exactly on the boundary is refused,
    /// matching how the plan validity window treats `valid_until`.
    #[must_use]
    pub fn is_live_at(&self, now_unix_ms: u64) -> bool {
        now_unix_ms < self.expires_unix_ms
    }
}

/// Which runtime actually ran the workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RuntimeIdentity {
    /// The plan's runtime profile.
    pub runtime_profile: String,
    /// The backend the profile resolved to.
    pub backend: AssuranceId,
}

/// The authoritative, admission-derived half of a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct MvmBinding {
    /// Host-minted session identity.
    pub session_id: AssuranceId,
    /// Content address of the admitted plan.
    ///
    /// An [`AssuranceId`] rather than a `String` because the counterparty
    /// validates it as an identifier; a plan id that could not survive that
    /// check must fail here, where the plan is in hand, and not at the far end
    /// of the join.
    pub plan_id: AssuranceId,
    /// Revision of the workload identity this plan carries.
    pub plan_version: u32,
    pub tenant: String,
    pub workload: String,
    /// Digest of the signed image that booted.
    pub workload_digest: Sha256Digest,
    /// Digest of the artifact actually admitted.
    pub artifact_digest: Sha256Digest,
    /// Digest of the effective policy/configuration.
    pub effective_policy_digest: Sha256Digest,
    pub grant: SessionGrant,
    pub runtime: RuntimeIdentity,
    /// Whether the plan demands attestation. Drives whether missing
    /// attestation evidence is fatal to the outcome.
    pub attestation_required: bool,
    /// References into the chain-signed audit log.
    pub audit_refs: Vec<EvidenceRef>,
    /// References to execution receipts.
    pub receipt_refs: Vec<EvidenceRef>,
}

/// Why a binding could not be assembled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum BindingError {
    #[error("binding is missing {0}")]
    MissingField(&'static str),
    #[error("the admitted plan carries an unusable image digest")]
    UnusableImageDigest,
    #[error("the admitted plan carries a plan id that is not an identifier")]
    UnusablePlanId,
    #[error("the resolved backend name is not an identifier")]
    UnusableBackend,
    #[error("a session must cite at least one audit reference")]
    NoAuditReference,
    #[error("a session must cite at least one execution receipt")]
    NoReceiptReference,
    #[error("the grant authorizes no tool")]
    EmptyGrant,
}

/// Render a plan's content address in the counterparty's identifier grammar.
///
/// A plan id is `sha256:<hex>`, and the `:` is not legal in an identifier the
/// far end will accept — so a binding built from any real plan would be refused
/// while the `fixture-plan` test id sailed through. The scheme separator
/// becomes a `-`, which is unambiguous (hex carries no `-`) and reversible, so
/// the value still names exactly one plan.
fn identifier_safe_plan_id(plan_id: &str) -> String {
    plan_id.replace(':', "-")
}

impl MvmBinding {
    /// Begin assembling a binding from an admitted plan.
    #[must_use]
    pub fn builder() -> MvmBindingBuilder {
        MvmBindingBuilder::default()
    }
}

/// Builder for [`MvmBinding`].
///
/// A builder rather than a constructor because the value has a dozen fields
/// drawn from three different sources, and because `plan()` is what makes the
/// admission-derived fields underivable by hand.
#[derive(Debug, Default)]
pub struct MvmBindingBuilder {
    session_id: Option<AssuranceId>,
    from_plan: Option<PlanDerived>,
    artifact_digest: Option<Sha256Digest>,
    effective_policy_digest: Option<Sha256Digest>,
    grant: Option<SessionGrant>,
    backend: Option<String>,
    audit_refs: Vec<EvidenceRef>,
    receipt_refs: Vec<EvidenceRef>,
}

/// The subset of an admitted plan a binding quotes.
#[derive(Debug, Clone)]
struct PlanDerived {
    plan_id: AssuranceId,
    plan_version: u32,
    tenant: String,
    workload: String,
    workload_digest: Sha256Digest,
    runtime_profile: String,
    attestation_required: bool,
}

impl MvmBindingBuilder {
    /// Set the host-minted session identity.
    #[must_use]
    pub fn session_id(mut self, session_id: AssuranceId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Quote the admitted plan.
    ///
    /// Takes the plan by reference so the caller must already hold one that
    /// passed verification; there is no way to supply these fields loose.
    pub fn plan(mut self, plan: &ExecutionPlan) -> Result<Self, BindingError> {
        let workload_digest = Sha256Digest::parse(alloc::format!("sha256:{}", plan.image.sha256))
            .map_err(|_| BindingError::UnusableImageDigest)?;
        let plan_id = AssuranceId::parse(identifier_safe_plan_id(&plan.plan_id.0))
            .map_err(|_| BindingError::UnusablePlanId)?;
        self.from_plan = Some(PlanDerived {
            plan_id,
            plan_version: plan.plan_version,
            tenant: plan.tenant.0.clone(),
            workload: plan.workload.0.clone(),
            workload_digest,
            runtime_profile: plan.runtime_profile.0.clone(),
            attestation_required: !matches!(plan.attestation.mode, AttestationMode::Noop),
        });
        Ok(self)
    }

    /// Set the digest of the artifact actually admitted.
    #[must_use]
    pub fn artifact_digest(mut self, digest: Sha256Digest) -> Self {
        self.artifact_digest = Some(digest);
        self
    }

    /// Set the digest of the effective policy/configuration.
    #[must_use]
    pub fn effective_policy_digest(mut self, digest: Sha256Digest) -> Self {
        self.effective_policy_digest = Some(digest);
        self
    }

    /// Set the short-lived session grant.
    #[must_use]
    pub fn grant(mut self, grant: SessionGrant) -> Self {
        self.grant = Some(grant);
        self
    }

    /// Set the resolved backend name.
    #[must_use]
    pub fn backend(mut self, backend: impl Into<String>) -> Self {
        self.backend = Some(backend.into());
        self
    }

    /// Cite an audit-log entry.
    #[must_use]
    pub fn audit_ref(mut self, reference: EvidenceRef) -> Self {
        self.audit_refs.push(reference);
        self
    }

    /// Cite an execution receipt.
    #[must_use]
    pub fn receipt_ref(mut self, reference: EvidenceRef) -> Self {
        self.receipt_refs.push(reference);
        self
    }

    /// Validate and assemble.
    pub fn build(self) -> Result<MvmBinding, BindingError> {
        let plan = self
            .from_plan
            .ok_or(BindingError::MissingField("admitted plan"))?;
        let grant = self.grant.ok_or(BindingError::MissingField("grant"))?;
        if grant.allowed_tools.is_empty() {
            return Err(BindingError::EmptyGrant);
        }
        // A session with no audit or receipt reference cannot be evaluated as
        // anything but INCONCLUSIVE later, so refusing here turns a guaranteed
        // dead end into an error at the point the mistake was made.
        if self.audit_refs.is_empty() {
            return Err(BindingError::NoAuditReference);
        }
        if self.receipt_refs.is_empty() {
            return Err(BindingError::NoReceiptReference);
        }
        Ok(MvmBinding {
            session_id: self
                .session_id
                .ok_or(BindingError::MissingField("session_id"))?,
            plan_id: plan.plan_id,
            plan_version: plan.plan_version,
            tenant: plan.tenant,
            workload: plan.workload,
            workload_digest: plan.workload_digest,
            artifact_digest: self
                .artifact_digest
                .ok_or(BindingError::MissingField("artifact_digest"))?,
            effective_policy_digest: self
                .effective_policy_digest
                .ok_or(BindingError::MissingField("effective_policy_digest"))?,
            grant,
            runtime: RuntimeIdentity {
                runtime_profile: plan.runtime_profile,
                backend: AssuranceId::parse(
                    self.backend.ok_or(BindingError::MissingField("backend"))?,
                )
                .map_err(|_| BindingError::UnusableBackend)?,
            },
            attestation_required: plan.attestation_required,
            audit_refs: self.audit_refs,
            receipt_refs: self.receipt_refs,
        })
    }
}
