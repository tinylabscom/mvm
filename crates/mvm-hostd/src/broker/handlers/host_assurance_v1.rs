//! `host.assurance.v1` — the declared campaign-probe surface.
//!
//! This is the production-safe alternative to handing an AI workload the
//! dev-only `Exec` verb. It exposes exactly one tool, and that tool takes a
//! declared label rather than anything the model composed: no command, no
//! path, no host, no port.
//!
//! A session must be opened host-side, from an admitted plan, before any probe
//! can land. An unopened session answers `NoSession`, which is also what the
//! registry's binding gate produces for a workload whose plan never named the
//! service — so the two refusals compose rather than shadowing each other.

use std::collections::{BTreeMap, BTreeSet};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mvm_contract::assurance::{
    AssuranceId, EffectiveAuthority, EvidenceRef, HostObservation, MvmBinding,
    PROBE_OBSERVATION_SCHEMA, ProbeInvocation, ProbeObservation, ProbeRefusal, ProbeRequest,
    SessionRef, Sha256Digest, TrialVerdict, probe_capability_descriptor,
};
use mvm_contract::protocol::agent_capability::CapabilityDescriptor;

use crate::audit::assurance::{
    AssuranceAuditSink, AssuranceLedger, AttestationRecord, LedgerRefs, PlanIdentity, ProbeRecord,
    SessionIdentity,
};
use mvm_core::egress_broker::{EgressRequest, EgressVerdict, decide_egress};
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::policy::security::AgentProfile;
use mvm_core::protocol::broker::{AuditDurability, Idempotency, ServiceErrorCode, ServiceId};
use mvm_core::protocol::handler::{
    ServiceCallCtx, ServiceDispatchResult, ServiceError, ServiceHandler,
};

/// Wire name of this service.
pub use mvm_contract::assurance::HOST_ASSURANCE_SERVICE;

/// A destination the operator declared for a campaign.
///
/// The host holds the host/port; the session only ever sees the label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredDestination {
    pub label: AssuranceId,
    pub host: String,
    pub port: u16,
}

/// Everything needed to open one assurance session.
#[derive(Clone)]
pub struct AssuranceSessionSpec {
    /// The workload session the supervisor will report in `ServiceCallCtx`.
    pub workload_session_id: String,
    /// The admitted binding this session runs under.
    pub binding: MvmBinding,
    /// Provider/campaign identity joined to this admitted session.
    pub session: SessionRef,
    /// Scanned source identity joined during admission.
    pub source_digest: Sha256Digest,
    /// Authority already intersected down from all five sources.
    pub authority: EffectiveAuthority,
    /// The trial this session is opened for.
    pub trial_id: AssuranceId,
    /// The workload's admitted egress policy.
    pub policy: NetworkPolicy,
    /// Destinations the campaign declared.
    pub destinations: Vec<DeclaredDestination>,
    /// The admitted plan's identity — the only part of it a record quotes.
    pub identity: PlanIdentity,
    /// Where probe records go. `None` disables recording, which also disables
    /// probing: an unrecorded boundary attempt is not one this service will
    /// perform.
    pub sink: Option<Arc<dyn AssuranceAuditSink + Send + Sync>>,
}

struct AssuranceSession {
    binding: MvmBinding,
    session: SessionRef,
    source_digest: Sha256Digest,
    authority: EffectiveAuthority,
    trial_id: AssuranceId,
    policy: NetworkPolicy,
    destinations: BTreeMap<AssuranceId, (String, u16)>,
    steps_used: u32,
    nonces: BTreeSet<AssuranceId>,
    results: BTreeMap<AssuranceId, ProbeObservation>,
    blocked_edges: Vec<AssuranceId>,
    attempted_effect: bool,
    effect_observed_in_guest: bool,
    boundary_crossed: bool,
    identity: PlanIdentity,
    sink: Option<Arc<dyn AssuranceAuditSink + Send + Sync>>,
    evidence_refs: Vec<EvidenceRef>,
}

impl std::fmt::Debug for AssuranceSessionSpec {
    /// The emitter owns a signing key and has no `Debug` of its own; only its
    /// presence is printed, which is the diagnostically interesting part.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AssuranceSessionSpec")
            .field("workload_session_id", &self.workload_session_id)
            .field("trial_id", &self.trial_id)
            .field("destinations", &self.destinations)
            .field("recording", &self.sink.is_some())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AssuranceSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AssuranceSession")
            .field("trial_id", &self.trial_id)
            .field("steps_used", &self.steps_used)
            .field("blocked_edges", &self.blocked_edges)
            .field("recording", &self.sink.is_some())
            .finish_non_exhaustive()
    }
}

impl AssuranceSession {
    fn steps_remaining(&self) -> u32 {
        self.authority.max_steps().saturating_sub(self.steps_used)
    }

    fn matches_open_identity(
        &self,
        binding: &MvmBinding,
        session: &SessionRef,
        source_digest: &Sha256Digest,
    ) -> bool {
        &self.binding == binding
            && &self.session == session
            && self.trial_id == session.trial_id
            && &self.source_digest == source_digest
    }
}

/// Handler for `host.assurance.v1`.
pub struct HostAssuranceV1Handler {
    sessions: Mutex<BTreeMap<String, AssuranceSession>>,
}

/// Host-authored observer evidence for one exact assurance session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedObservation {
    pub observation: HostObservation,
    pub probe_refs: Vec<EvidenceRef>,
    pub audit_ref: EvidenceRef,
    pub receipt_ref: EvidenceRef,
}

impl HostAssuranceV1Handler {
    /// Construct a handler with no open sessions.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(BTreeMap::new()),
        }
    }

    /// Typed descriptor for the single production assurance verb. Semantic
    /// destination authorization remains session-specific in the handler;
    /// this descriptor additionally bounds the label before dispatch.
    pub fn capability_descriptor() -> CapabilityDescriptor {
        probe_capability_descriptor()
    }

    /// Open a session from an admitted plan. Host-side only.
    pub fn open_session(&self, spec: AssuranceSessionSpec) {
        let destinations = spec
            .destinations
            .into_iter()
            .map(|declared| (declared.label, (declared.host, declared.port)))
            .collect();
        let session = AssuranceSession {
            binding: spec.binding,
            session: spec.session,
            source_digest: spec.source_digest,
            authority: spec.authority,
            trial_id: spec.trial_id,
            policy: spec.policy,
            destinations,
            steps_used: 0,
            nonces: BTreeSet::new(),
            results: BTreeMap::new(),
            blocked_edges: Vec::new(),
            attempted_effect: false,
            effect_observed_in_guest: false,
            boundary_crossed: false,
            identity: spec.identity,
            sink: spec.sink,
            evidence_refs: Vec::new(),
        };
        self.sessions
            .lock()
            .expect("assurance session map is not poisoned")
            .insert(spec.workload_session_id, session);
    }

    /// The binding a session was opened under.
    #[must_use]
    pub fn binding_for(&self, workload_session_id: &str) -> Option<MvmBinding> {
        self.sessions
            .lock()
            .expect("assurance session map is not poisoned")
            .get(workload_session_id)
            .map(|session| session.binding.clone())
    }

    /// Verify the complete provider/campaign identity before a controller
    /// sends any guest-side cancellation effect.
    pub(crate) fn verify_open_identity(
        &self,
        workload_session_id: &str,
        binding: &MvmBinding,
        session_ref: &SessionRef,
        source_digest: &Sha256Digest,
    ) -> anyhow::Result<()> {
        let sessions = self
            .sessions
            .lock()
            .expect("assurance session map is not poisoned");
        let session = sessions
            .get(workload_session_id)
            .ok_or_else(|| anyhow::anyhow!("the assurance session is not open"))?;
        if !session.matches_open_identity(binding, session_ref, source_digest) {
            anyhow::bail!("cancellation identity does not match the open session");
        }
        Ok(())
    }

    /// Effective authority stored for a session. Host-controller only.
    #[must_use]
    pub fn authority_for(&self, workload_session_id: &str) -> Option<EffectiveAuthority> {
        self.sessions
            .lock()
            .expect("assurance session map is not poisoned")
            .get(workload_session_id)
            .map(|session| session.authority.clone())
    }

    /// What the host observed across the session, for the evaluator.
    ///
    /// This is the observer's account, assembled from the host's own probe
    /// decisions rather than from anything the model reported.
    #[must_use]
    pub fn observation_for(&self, workload_session_id: &str) -> Option<HostObservation> {
        self.sessions
            .lock()
            .expect("assurance session map is not poisoned")
            .get(workload_session_id)
            .map(|session| HostObservation {
                attempted_effect: session.attempted_effect,
                effect_observed_in_guest: session.effect_observed_in_guest,
                boundary_crossed: session.boundary_crossed,
                blocked_edges: session.blocked_edges.clone(),
            })
    }

    /// References this session's probes actually produced.
    #[must_use]
    pub fn evidence_refs_for(&self, workload_session_id: &str) -> Vec<EvidenceRef> {
        self.sessions
            .lock()
            .expect("assurance session map is not poisoned")
            .get(workload_session_id)
            .map(|session| session.evidence_refs.clone())
            .unwrap_or_default()
    }

    /// Record a conservative completion for a dispatch recovered after a
    /// controller or host crash.
    ///
    /// Every identity is rejoined to the currently open admitted session
    /// before the signed record is emitted. A stale marker therefore cannot
    /// manufacture evidence for a different session or plan.
    pub(crate) fn complete_trial(
        &self,
        workload_session_id: &str,
        binding: &MvmBinding,
        identity: &SessionIdentity,
        verdict: &TrialVerdict,
    ) -> anyhow::Result<LedgerRefs> {
        let (sink, plan_identity) = {
            let sessions = self
                .sessions
                .lock()
                .expect("assurance session map is not poisoned");
            let session = sessions
                .get(workload_session_id)
                .ok_or_else(|| anyhow::anyhow!("the assurance session is not open"))?;
            if session.binding.session_id != identity.session_id
                || session.session.campaign_id != identity.campaign_id
                || session.trial_id != identity.trial_id
                || session.source_digest != identity.source_digest
                || &session.binding != binding
            {
                anyhow::bail!("recovered dispatch identity does not match the open session");
            }
            let sink = session
                .sink
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("assurance audit recording is unavailable"))?;
            (Arc::clone(sink), session.identity.clone())
        };
        AssuranceLedger::new(sink.as_ref(), &plan_identity).complete_trial(identity, verdict)
    }

    /// Commit the observation accumulated by the typed host broker.
    ///
    /// The caller cannot supply observed booleans or evidence references; it
    /// supplies only the identities to rejoin, and this method snapshots the
    /// values the host recorded while mediating probe calls.
    pub(crate) fn finalize_observation(
        &self,
        workload_session_id: &str,
        binding: &MvmBinding,
        identity: &SessionIdentity,
    ) -> anyhow::Result<VerifiedObservation> {
        let (sink, plan_identity, observation, probe_refs) = {
            let sessions = self
                .sessions
                .lock()
                .expect("assurance session map is not poisoned");
            let session = sessions
                .get(workload_session_id)
                .ok_or_else(|| anyhow::anyhow!("the assurance session is not open"))?;
            if &session.binding != binding
                || session.binding.session_id != identity.session_id
                || session.session.campaign_id != identity.campaign_id
                || session.trial_id != identity.trial_id
                || session.source_digest != identity.source_digest
            {
                anyhow::bail!("observer identity does not match the open session");
            }
            let sink = session
                .sink
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("assurance audit recording is unavailable"))?;
            let observation = HostObservation {
                attempted_effect: session.attempted_effect,
                effect_observed_in_guest: session.effect_observed_in_guest,
                boundary_crossed: session.boundary_crossed,
                blocked_edges: session.blocked_edges.clone(),
            };
            (
                Arc::clone(sink),
                session.identity.clone(),
                observation,
                session.evidence_refs.clone(),
            )
        };
        let refs = AssuranceLedger::new(sink.as_ref(), &plan_identity).record_observation(
            identity,
            &observation,
            &probe_refs,
        )?;
        let receipt_ref = refs
            .receipt
            .ok_or_else(|| anyhow::anyhow!("observer completion produced no receipt"))?;
        Ok(VerifiedObservation {
            observation,
            probe_refs: probe_refs.to_vec(),
            audit_ref: refs.audit,
            receipt_ref,
        })
    }

    /// Sign cancellation only after the guest acknowledged the exact active
    /// invocation and every session identity rejoins.
    pub(crate) fn record_cancellation(
        &self,
        workload_session_id: &str,
        binding: &MvmBinding,
        identity: &SessionIdentity,
    ) -> anyhow::Result<LedgerRefs> {
        let (sink, plan_identity) = {
            let sessions = self
                .sessions
                .lock()
                .expect("assurance session map is not poisoned");
            let session = sessions
                .get(workload_session_id)
                .ok_or_else(|| anyhow::anyhow!("the assurance session is not open"))?;
            if &session.binding != binding
                || session.binding.session_id != identity.session_id
                || session.session.campaign_id != identity.campaign_id
                || session.trial_id != identity.trial_id
                || session.source_digest != identity.source_digest
            {
                anyhow::bail!("cancellation identity does not match the open session");
            }
            let sink = session
                .sink
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("assurance audit recording is unavailable"))?;
            (Arc::clone(sink), session.identity.clone())
        };
        AssuranceLedger::new(sink.as_ref(), &plan_identity).record_cancellation(identity)
    }

    /// Sign cleanup evidence after the caller has stopped and read back the
    /// exact admitted VM. This method still rejoins every session identity;
    /// the runtime confirmation alone cannot be applied to another trial.
    pub(crate) fn record_confirmed_cleanup(
        &self,
        workload_session_id: &str,
        binding: &MvmBinding,
        identity: &SessionIdentity,
    ) -> anyhow::Result<LedgerRefs> {
        let (sink, plan_identity) = {
            let sessions = self
                .sessions
                .lock()
                .expect("assurance session map is not poisoned");
            let session = sessions
                .get(workload_session_id)
                .ok_or_else(|| anyhow::anyhow!("the assurance session is not open"))?;
            if &session.binding != binding
                || session.binding.session_id != identity.session_id
                || session.session.campaign_id != identity.campaign_id
                || session.trial_id != identity.trial_id
                || session.source_digest != identity.source_digest
            {
                anyhow::bail!("cleanup identity does not match the open session");
            }
            let sink = session
                .sink
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("assurance audit recording is unavailable"))?;
            (Arc::clone(sink), session.identity.clone())
        };
        AssuranceLedger::new(sink.as_ref(), &plan_identity).record_cleanup(identity)
    }

    /// Sign attestation evidence after the trusted runtime verifier has
    /// accepted a quote for the exact open session.
    pub(crate) fn record_verified_attestation(
        &self,
        workload_session_id: &str,
        binding: &MvmBinding,
        identity: &SessionIdentity,
        attestation: &AttestationRecord<'_>,
    ) -> anyhow::Result<LedgerRefs> {
        let (sink, plan_identity) = {
            let sessions = self
                .sessions
                .lock()
                .expect("assurance session map is not poisoned");
            let session = sessions
                .get(workload_session_id)
                .ok_or_else(|| anyhow::anyhow!("the assurance session is not open"))?;
            if &session.binding != binding
                || session.binding.session_id != identity.session_id
                || session.session.campaign_id != identity.campaign_id
                || session.trial_id != identity.trial_id
                || session.source_digest != identity.source_digest
            {
                anyhow::bail!("attestation identity does not match the open session");
            }
            let sink = session
                .sink
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("assurance audit recording is unavailable"))?;
            (Arc::clone(sink), session.identity.clone())
        };
        AssuranceLedger::new(sink.as_ref(), &plan_identity)
            .record_attestation(identity, attestation)
    }

    /// Close a session, dropping its nonce ledger and recorded results.
    pub fn close_session(&self, workload_session_id: &str) {
        self.sessions
            .lock()
            .expect("assurance session map is not poisoned")
            .remove(workload_session_id);
    }

    pub(crate) fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }

    fn probe(&self, ctx: &ServiceCallCtx, payload: serde_json::Value) -> ServiceDispatchResult {
        let request: ProbeRequest = serde_json::from_value(payload)
            .map_err(|error| ServiceError::new(ServiceErrorCode::BadRequest, error.to_string()))?;
        let observation = self
            .decide(ctx, &request, Self::now_unix_ms())
            .map_err(refusal_to_error)?;
        serde_json::to_value(observation).map_err(|error| {
            ServiceError::new(
                ServiceErrorCode::InternalError,
                format!("{HOST_ASSURANCE_SERVICE} response encode failed: {error}"),
            )
        })
    }

    /// The whole decision, separated from transport so it is directly testable.
    fn decide(
        &self,
        ctx: &ServiceCallCtx,
        request: &ProbeRequest,
        now_unix_ms: u64,
    ) -> Result<ProbeObservation, ProbeRefusal> {
        request.validate()?;

        let mut sessions = self
            .sessions
            .lock()
            .expect("assurance session map is not poisoned");
        let session = sessions
            .get_mut(&ctx.session_id)
            .ok_or(ProbeRefusal::NoSession)?;

        // Two identifiers, deliberately: the supervisor's `ctx.session_id` is
        // the authoritative *lookup* key and is never supplied by the guest,
        // while `binding.session_id` is the assurance identity the guest was
        // told in its envelope. The request claims the latter, so that is what
        // it is checked against — comparing it to the lookup key instead only
        // worked while a test used one string for both.
        if request.session_id != session.binding.session_id {
            return Err(ProbeRefusal::SessionMismatch);
        }
        if request.request_id != session.session.request_id {
            return Err(ProbeRefusal::RequestMismatch);
        }
        if request.campaign_id != session.session.campaign_id {
            return Err(ProbeRefusal::CampaignMismatch);
        }
        if request.trial_id != session.trial_id {
            return Err(ProbeRefusal::TrialMismatch);
        }
        if request.plan_id != session.binding.plan_id {
            return Err(ProbeRefusal::PlanMismatch);
        }
        if request.campaign_idempotency_key != session.session.idempotency_key {
            return Err(ProbeRefusal::CampaignIdempotencyMismatch);
        }
        if request.session_grant_digest != session.binding.grant.grant_digest {
            return Err(ProbeRefusal::GrantMismatch);
        }
        if request.session_grant_nonce != session.binding.grant.nonce {
            return Err(ProbeRefusal::GrantNonceMismatch);
        }

        // Idempotency precedes every other check that could mutate state: a
        // retry must return the first answer, not re-run the probe and not
        // consume a second step.
        if let Some(previous) = session.results.get(&request.idempotency_key) {
            return Ok(previous.clone());
        }

        if !session.authority.permits_tool(request.tool()) {
            return Err(ProbeRefusal::ToolNotPermitted);
        }
        if now_unix_ms >= session.authority.deadline_unix_ms() {
            return Err(ProbeRefusal::GrantExpired);
        }
        if session.steps_remaining() == 0 {
            return Err(ProbeRefusal::StepBudgetExhausted);
        }
        if !session.nonces.insert(request.nonce.clone()) {
            return Err(ProbeRefusal::NonceReplay);
        }

        // Decide first, record second, commit third. The decision is a pure
        // policy query with no side effect, so a failure to record it can still
        // refuse the probe outright rather than leave an unrecorded attempt
        // behind — which is the whole point of recording it.
        let (admitted, decision, destination_label) = match &request.invocation {
            ProbeInvocation::EgressAdmission { destination_label } => {
                let (host, port) = session
                    .destinations
                    .get(destination_label)
                    .cloned()
                    .ok_or(ProbeRefusal::UndeclaredDestination)?;
                let verdict = decide_egress(&session.policy, &EgressRequest::new(host, port));
                let (admitted, decision) = match &verdict {
                    EgressVerdict::Allowed { .. } => (true, "allowed"),
                    EgressVerdict::Denied { reason } => (false, reason.label()),
                };
                (admitted, decision, destination_label.clone())
            }
        };

        let recorded = Self::record(session, request, decision, admitted, &destination_label)?;

        session.attempted_effect = true;
        if admitted {
            // The policy admitted the destination, so the edge the campaign was
            // probing is reachable: the effect crossed.
            session.boundary_crossed = true;
            session.effect_observed_in_guest = true;
        } else if !session.blocked_edges.contains(&destination_label) {
            session.blocked_edges.push(destination_label.clone());
        }
        session.evidence_refs.extend(recorded);
        session.steps_used = session.steps_used.saturating_add(1);

        let observation = ProbeObservation {
            schema: PROBE_OBSERVATION_SCHEMA.to_string(),
            probe: request.invocation.probe_id().to_string(),
            admitted,
            blocked_edge: (!admitted).then(|| destination_label.clone()),
            decision: decision.to_string(),
            steps_remaining: session.steps_remaining(),
        };
        session
            .results
            .insert(request.idempotency_key.clone(), observation.clone());
        Ok(observation)
    }

    /// Write the probe's audit record, returning the references it produced.
    ///
    /// A session with no emitter records nothing and therefore probes nothing:
    /// the refusal is `AuditUnavailable` either way, so "recording is off" and
    /// "recording failed" are not distinguishable to the caller, and neither
    /// yields a boundary attempt that happened without a record of it.
    fn record(
        session: &AssuranceSession,
        request: &ProbeRequest,
        decision: &str,
        admitted: bool,
        destination_label: &AssuranceId,
    ) -> Result<Vec<EvidenceRef>, ProbeRefusal> {
        let sink = session
            .sink
            .as_ref()
            .ok_or(ProbeRefusal::AuditUnavailable)?;
        let ledger = AssuranceLedger::new(sink.as_ref(), &session.identity);
        let refs = ledger
            .record_probe(&ProbeRecord {
                session_id: &request.session_id,
                trial_id: &request.trial_id,
                probe_id: request.invocation.probe_id(),
                decision,
                idempotency_key: &request.idempotency_key,
                admitted,
                destination_label,
            })
            .map_err(|error| {
                tracing::warn!(error = %error, "assurance probe record failed; refusing the probe");
                ProbeRefusal::AuditUnavailable
            })?;
        let mut out = vec![refs.audit];
        if let Some(receipt) = refs.receipt {
            out.push(receipt);
        }
        Ok(out)
    }
}

impl Default for HostAssuranceV1Handler {
    fn default() -> Self {
        Self::new()
    }
}

/// Map a refusal onto the broker's error vocabulary.
///
/// Everything the model could have done differently is `BadRequest`; an
/// expired grant is `Unavailable` because retrying the same call cannot fix it.
fn refusal_to_error(refusal: ProbeRefusal) -> ServiceError {
    let code = match refusal {
        ProbeRefusal::NoSession | ProbeRefusal::GrantExpired => ServiceErrorCode::Unavailable,
        _ => ServiceErrorCode::BadRequest,
    };
    ServiceError::new(code, refusal.label())
}

impl ServiceHandler for HostAssuranceV1Handler {
    fn id(&self) -> ServiceId {
        ServiceId::parse(HOST_ASSURANCE_SERVICE).expect("host.assurance.v1 is a valid ServiceId")
    }

    fn profiles(&self) -> &[AgentProfile] {
        // Sealed production is the tier the campaign is meant to characterize;
        // Builder is excluded because a builder VM carries no workload claim.
        &[AgentProfile::SealedProd, AgentProfile::Dev]
    }

    fn audit_durability(&self) -> AuditDurability {
        // Every probe is a boundary attempt, and the audit entry is the
        // evidence. Batching would let a crash lose the record of an attempt
        // that already happened.
        AuditDurability::PerCall
    }

    fn idempotency(&self) -> Idempotency {
        Idempotency::MintFresh
    }

    fn call_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn dispatch<'a>(
        &'a self,
        ctx: &'a ServiceCallCtx,
        verb: &'a str,
        payload: serde_json::Value,
    ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
        Box::pin(async move {
            match verb {
                "probe" => self.probe(ctx, payload),
                other => Err(ServiceError::new(
                    ServiceErrorCode::NotImplemented,
                    format!("{HOST_ASSURANCE_SERVICE}: unknown verb `{other}`"),
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::audit::assurance::identity_of;
    use crate::audit::assurance::{audit_citations_resolve, resolve_audit_ref};
    use crate::audit::emitter::AuditEmitter;
    use mvm_contract::assurance::{
        ApprovalSet, AuthorityCeiling, AuthorityInputs, EvidenceRef, ObservationScope,
        PROBE_REQUEST_SCHEMA, RequestedAuthority, SessionGrant, Sha256Digest, ToolId,
    };
    use mvm_contract::policy::network_policy::HostPort;
    use mvm_core::plan::ExecutionPlan;
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_core::protocol::broker::CorrelationId;

    const ARTIFACT_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const POLICY_DIGEST: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const SOURCE_DIGEST: &str =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    const GRANT_DIGEST: &str =
        "sha256:4444444444444444444444444444444444444444444444444444444444444444";

    const SESSION: &str = "session-1";
    const NOW_MS: u64 = 1_000_000;
    const EXPIRY_MS: u64 = 2_000_000;

    fn id(raw: &str) -> AssuranceId {
        AssuranceId::parse(raw).expect("identifier")
    }

    fn digest(raw: &str) -> Sha256Digest {
        Sha256Digest::parse(raw).expect("digest")
    }

    fn grant() -> SessionGrant {
        grant_expiring_at(EXPIRY_MS)
    }

    fn grant_expiring_at(expires_unix_ms: u64) -> SessionGrant {
        SessionGrant {
            grant_digest: digest(GRANT_DIGEST),
            expires_unix_ms,
            nonce: id("grant-nonce"),
            allowed_tools: vec![ToolId::CampaignProbeV1],
            observation_scopes: vec![ObservationScope::HostAuditRefs],
            max_steps: 64,
            max_output_bytes: 1024 * 1024,
        }
    }

    fn authority(max_steps: u32) -> EffectiveAuthority {
        authority_expiring_at(max_steps, EXPIRY_MS, NOW_MS)
    }

    fn authority_expiring_at(max_steps: u32, expiry: u64, now: u64) -> EffectiveAuthority {
        let ceiling = AuthorityCeiling::extension_maximum();
        let requested = RequestedAuthority {
            allowed_tools: vec![ToolId::CampaignProbeV1],
            observation_scopes: vec![ObservationScope::HostAuditRefs],
            max_steps,
            max_output_bytes: 4096,
            deadline_unix_ms: expiry,
        };
        let approvals = ApprovalSet::none().with(ToolId::CampaignProbeV1);
        EffectiveAuthority::intersect(
            AuthorityInputs {
                extension_maximum: &ceiling,
                requested: &requested,
                policy_ceiling: &ceiling,
                grant: &grant_expiring_at(expiry),
                approvals: &approvals,
            },
            now,
        )
        .expect("authority")
    }

    /// A handler whose grant is live against the real wall clock, for the
    /// tests that go through `dispatch` rather than the injected-clock seam.
    fn live_handler(policy: NetworkPolicy, max_steps: u32) -> HostAssuranceV1Handler {
        let now = HostAssuranceV1Handler::now_unix_ms();
        let expiry = now + 3_600_000;
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let emitter = AuditEmitter::with_dir(key, dir.path())
            .expect("emitter")
            .with_receipts();
        let handler = HostAssuranceV1Handler::new();
        let mut session = spec(policy, max_steps);
        session.authority = authority_expiring_at(max_steps, expiry, now);
        session.sink = Some(Arc::new(emitter) as Arc<dyn AssuranceAuditSink + Send + Sync>);
        handler.open_session(session);
        // The tempdir is deliberately leaked: these tests only assert on the
        // dispatch result, and keeping the guard alive would mean threading it
        // through every caller for nothing.
        std::mem::forget(dir);
        handler
    }

    fn binding() -> MvmBinding {
        MvmBinding::builder()
            .session_id(id(SESSION))
            .plan(&PlanFixture::new().build())
            .expect("plan")
            .artifact_digest(digest(ARTIFACT_DIGEST))
            .effective_policy_digest(digest(POLICY_DIGEST))
            .grant(grant())
            .backend("firecracker")
            .audit_ref(EvidenceRef::parse("mvm:audit:a").expect("ref"))
            .receipt_ref(EvidenceRef::parse("mvm:receipt:r").expect("ref"))
            .build()
            .expect("binding")
    }

    fn spec(policy: NetworkPolicy, max_steps: u32) -> AssuranceSessionSpec {
        AssuranceSessionSpec {
            workload_session_id: SESSION.to_string(),
            binding: binding(),
            session: session_ref(),
            source_digest: digest(SOURCE_DIGEST),
            authority: authority(max_steps),
            trial_id: id("trial-1"),
            policy,
            destinations: vec![DeclaredDestination {
                label: id("undeclared.synthetic.destination"),
                host: "attacker.example.com".to_string(),
                port: 443,
            }],
            identity: identity_of(&PlanFixture::new().build()),
            sink: None,
        }
    }

    /// A handler whose probes are recorded to a real chain, with the tempdir
    /// kept alive for the caller.
    fn audited(
        policy: NetworkPolicy,
        max_steps: u32,
    ) -> (HostAssuranceV1Handler, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let emitter = AuditEmitter::with_dir(key, dir.path())
            .expect("emitter")
            .with_receipts();
        let handler = HostAssuranceV1Handler::new();
        let mut session = spec(policy, max_steps);
        session.sink = Some(Arc::new(emitter) as Arc<dyn AssuranceAuditSink + Send + Sync>);
        handler.open_session(session);
        (handler, dir)
    }

    fn chain_path(dir: &tempfile::TempDir, plan: &ExecutionPlan) -> std::path::PathBuf {
        dir.path().join(format!("{}.jsonl", plan.tenant.0))
    }

    fn handler(policy: NetworkPolicy, max_steps: u32) -> HostAssuranceV1Handler {
        let handler = HostAssuranceV1Handler::new();
        handler.open_session(spec(policy, max_steps));
        handler
    }

    fn session_ref() -> SessionRef {
        SessionRef {
            request_id: id("mvm-request-1"),
            idempotency_key: id("campaign-retry-1"),
            source_run_id: id("scout-1"),
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
        }
    }

    fn context() -> ServiceCallCtx {
        ServiceCallCtx {
            workload_id: "workload".into(),
            tenant_id: "tenant".into(),
            correlation_id: CorrelationId::new("correlation"),
            session_id: SESSION.to_string(),
            profile: AgentProfile::SealedProd,
            composition_depth: 0,
            composition_width: 0,
        }
    }

    fn identity() -> SessionIdentity {
        SessionIdentity {
            session_id: id(SESSION),
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
            source_digest: digest(SOURCE_DIGEST),
        }
    }

    #[test]
    fn cancellation_identity_is_fully_joined_before_the_guest_effect() {
        let handler = handler(NetworkPolicy::deny_all(), 1);
        handler
            .verify_open_identity(SESSION, &binding(), &session_ref(), &digest(SOURCE_DIGEST))
            .expect("exact identity joins");

        let mut foreign_request = session_ref();
        foreign_request.request_id = id("mvm-request-foreign");
        assert!(
            handler
                .verify_open_identity(
                    SESSION,
                    &binding(),
                    &foreign_request,
                    &digest(SOURCE_DIGEST),
                )
                .is_err()
        );
        assert!(
            handler
                .verify_open_identity(SESSION, &binding(), &session_ref(), &digest(POLICY_DIGEST))
                .is_err()
        );
    }

    fn request(idempotency: &str, nonce: &str, label: &str) -> ProbeRequest {
        ProbeRequest {
            schema: PROBE_REQUEST_SCHEMA.to_string(),
            session_id: id(SESSION),
            request_id: id("mvm-request-1"),
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
            plan_id: id("fixture-plan"),
            campaign_idempotency_key: id("campaign-retry-1"),
            session_grant_digest: digest(GRANT_DIGEST),
            session_grant_nonce: id("grant-nonce"),
            idempotency_key: id(idempotency),
            nonce: id(nonce),
            tool: ToolId::CampaignProbeV1,
            invocation: ProbeInvocation::EgressAdmission {
                destination_label: id(label),
            },
        }
    }

    #[tokio::test]
    async fn admitted_probe_crosses_the_controller_proxy_and_records_host_evidence() {
        use mvm_contract::protocol::agent_capability::CapabilityInvocation;
        use mvm_contract::protocol::agent_session::AgentRequestId;

        use crate::broker::controller_proxy::prepare_controller_service;
        use crate::broker::registry::{CancellationToken, Registry};
        use crate::broker::service_proxy::ControllerServiceProxy;

        let env_dir = tempfile::tempdir().expect("environment tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", env_dir.path());
        let handler = Arc::new(live_handler(NetworkPolicy::deny_all(), 4));
        let descriptor = HostAssuranceV1Handler::capability_descriptor();
        let binding = descriptor.binding();
        let endpoint = prepare_controller_service(SESSION, handler, vec![descriptor.clone()])
            .expect("prepare controller service");
        let proxy = Arc::new(ControllerServiceProxy::new(endpoint).expect("resident proxy"));
        let as_handler: Arc<dyn ServiceHandler> = proxy;
        let mut registry = Registry::new();
        registry
            .admit_capabilities([binding.clone()])
            .expect("admit capability");
        registry.register(Arc::clone(&as_handler));
        registry.require_capability(as_handler.id());
        registry
            .register_capability(as_handler, descriptor)
            .expect("register proxy capability");

        let request = request("proxy-k1", "proxy-n1", "undeclared.synthetic.destination");
        let payload = serde_json::to_value(&request).expect("encode probe");
        let invocation = CapabilityInvocation::from_payload(
            binding,
            AgentRequestId::parse("proxy-probe-1").expect("request id"),
            &payload,
        )
        .expect("capability invocation");
        let mut ctx = context();
        ctx.workload_id = SESSION.to_string();
        let output = registry
            .dispatch_capability(
                &ctx,
                &ServiceId::parse(HOST_ASSURANCE_SERVICE).expect("service"),
                "probe",
                &invocation,
                payload,
                &CancellationToken::new(),
            )
            .await
            .expect("proxied probe");
        let observation: ProbeObservation =
            serde_json::from_value(output).expect("decode observation");
        assert!(!observation.admitted);
        assert_eq!(observation.decision, "deny_all");
    }

    #[test]
    fn a_deny_all_policy_refuses_the_declared_destination_and_records_a_blocked_edge() {
        let (handler, _dir) = audited(NetworkPolicy::deny_all(), 4);
        let observation = handler
            .decide(
                &context(),
                &request("k1", "n1", "undeclared.synthetic.destination"),
                NOW_MS,
            )
            .expect("probe runs");

        assert!(!observation.admitted);
        assert_eq!(observation.decision, "deny_all");
        assert_eq!(
            observation.blocked_edge,
            Some(id("undeclared.synthetic.destination"))
        );
        assert_eq!(observation.steps_remaining, 3);

        let observed = handler.observation_for(SESSION).expect("observation");
        assert!(observed.attempted_effect);
        assert!(!observed.boundary_crossed);
        assert!(!observed.effect_observed_in_guest);
        assert_eq!(
            observed.blocked_edges,
            vec![id("undeclared.synthetic.destination")]
        );
    }

    #[test]
    fn an_allowlisted_destination_records_a_crossed_boundary() {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("attacker.example.com", 443)]);
        let (handler, _dir) = audited(policy, 4);
        let observation = handler
            .decide(
                &context(),
                &request("k1", "n1", "undeclared.synthetic.destination"),
                NOW_MS,
            )
            .expect("probe runs");

        assert!(observation.admitted);
        assert_eq!(observation.decision, "allowed");
        assert_eq!(observation.blocked_edge, None);

        let observed = handler.observation_for(SESSION).expect("observation");
        assert!(observed.boundary_crossed);
        assert!(observed.blocked_edges.is_empty());
    }

    #[test]
    fn a_retry_with_the_same_idempotency_key_returns_the_first_result_and_burns_no_step() {
        let (handler, _dir) = audited(NetworkPolicy::deny_all(), 4);
        let first = handler
            .decide(
                &context(),
                &request("k1", "n1", "undeclared.synthetic.destination"),
                NOW_MS,
            )
            .expect("first");
        // A retry carries a fresh nonce, as a real retry would; the
        // idempotency key is what makes it the same call.
        let second = handler
            .decide(
                &context(),
                &request("k1", "n2", "undeclared.synthetic.destination"),
                NOW_MS,
            )
            .expect("retry");

        assert_eq!(first, second);
        assert_eq!(
            second.steps_remaining, 3,
            "the retry must not consume a step"
        );
    }

    #[test]
    fn a_replayed_nonce_under_a_new_idempotency_key_is_refused() {
        let (handler, _dir) = audited(NetworkPolicy::deny_all(), 4);
        handler
            .decide(
                &context(),
                &request("k1", "n1", "undeclared.synthetic.destination"),
                NOW_MS,
            )
            .expect("first");
        assert_eq!(
            handler.decide(
                &context(),
                &request("k2", "n1", "undeclared.synthetic.destination"),
                NOW_MS
            ),
            Err(ProbeRefusal::NonceReplay)
        );
    }

    #[test]
    fn an_undeclared_destination_label_never_reaches_the_policy_engine() {
        let handler = handler(NetworkPolicy::unrestricted(), 4);
        assert_eq!(
            handler.decide(&context(), &request("k1", "n1", "some.other.host"), NOW_MS),
            Err(ProbeRefusal::UndeclaredDestination)
        );
        // Nothing was attempted, so an unrestricted policy did not become a
        // crossed boundary by accident.
        let observed = handler.observation_for(SESSION).expect("observation");
        assert!(!observed.attempted_effect);
    }

    #[test]
    fn a_probe_against_an_unopened_session_is_refused() {
        let handler = HostAssuranceV1Handler::new();
        assert_eq!(
            handler.decide(
                &context(),
                &request("k1", "n1", "undeclared.synthetic.destination"),
                NOW_MS
            ),
            Err(ProbeRefusal::NoSession)
        );
    }

    #[test]
    fn a_request_naming_another_session_is_refused() {
        let handler = handler(NetworkPolicy::deny_all(), 4);
        let mut probe = request("k1", "n1", "undeclared.synthetic.destination");
        probe.session_id = id("session-2");
        assert_eq!(
            handler.decide(&context(), &probe, NOW_MS),
            Err(ProbeRefusal::SessionMismatch)
        );
    }

    #[test]
    fn a_request_naming_another_trial_is_refused() {
        let handler = handler(NetworkPolicy::deny_all(), 4);
        let mut probe = request("k1", "n1", "undeclared.synthetic.destination");
        probe.trial_id = id("trial-2");
        assert_eq!(
            handler.decide(&context(), &probe, NOW_MS),
            Err(ProbeRefusal::TrialMismatch)
        );
    }

    #[test]
    fn the_step_budget_is_enforced() {
        let (handler, _dir) = audited(NetworkPolicy::deny_all(), 1);
        handler
            .decide(
                &context(),
                &request("k1", "n1", "undeclared.synthetic.destination"),
                NOW_MS,
            )
            .expect("first step");
        assert_eq!(
            handler.decide(
                &context(),
                &request("k2", "n2", "undeclared.synthetic.destination"),
                NOW_MS
            ),
            Err(ProbeRefusal::StepBudgetExhausted)
        );
    }

    #[test]
    fn a_call_at_or_past_the_deadline_is_refused() {
        let handler = handler(NetworkPolicy::deny_all(), 4);
        assert_eq!(
            handler.decide(
                &context(),
                &request("k1", "n1", "undeclared.synthetic.destination"),
                EXPIRY_MS
            ),
            Err(ProbeRefusal::GrantExpired)
        );
    }

    #[test]
    fn an_unsupported_probe_schema_is_refused() {
        let handler = handler(NetworkPolicy::deny_all(), 4);
        let mut probe = request("k1", "n1", "undeclared.synthetic.destination");
        probe.schema = "mvm.assurance.probe-request/v2".to_string();
        assert_eq!(
            handler.decide(&context(), &probe, NOW_MS),
            Err(ProbeRefusal::UnsupportedSchema)
        );
    }

    #[test]
    fn an_unknown_field_in_a_probe_payload_fails_to_parse() {
        let body = serde_json::json!({
            "schema": PROBE_REQUEST_SCHEMA,
            "session_id": SESSION,
            "trial_id": "trial-1",
            "idempotency_key": "k1",
            "nonce": "n1",
            "tool": "campaign_probe.v1",
            "invocation": {
                "probe": "egress.admission.v1",
                "destination_label": "undeclared.synthetic.destination"
            },
            "command": "/bin/sh"
        });
        let error = serde_json::from_value::<ProbeRequest>(body).expect_err("must fail closed");
        assert!(error.to_string().contains("command"), "{error}");
    }

    #[test]
    fn an_undeclared_probe_name_fails_to_parse() {
        let body = serde_json::json!({
            "schema": PROBE_REQUEST_SCHEMA,
            "session_id": SESSION,
            "trial_id": "trial-1",
            "idempotency_key": "k1",
            "nonce": "n1",
            "tool": "campaign_probe.v1",
            "invocation": { "probe": "process.exec.v1", "command": "/bin/sh" }
        });
        assert!(serde_json::from_value::<ProbeRequest>(body).is_err());
    }

    #[tokio::test]
    async fn the_dispatch_surface_exposes_only_the_probe_verb() {
        let handler = live_handler(NetworkPolicy::deny_all(), 4);
        let error = handler
            .dispatch(&context(), "exec", serde_json::json!({}))
            .await
            .expect_err("exec must not exist");
        assert_eq!(error.code, ServiceErrorCode::NotImplemented);
    }

    #[tokio::test]
    async fn a_probe_round_trips_through_dispatch() {
        let handler = live_handler(NetworkPolicy::deny_all(), 4);
        let payload = serde_json::to_value(request("k1", "n1", "undeclared.synthetic.destination"))
            .expect("payload");
        let response = handler
            .dispatch(&context(), "probe", payload)
            .await
            .expect("probe dispatches");
        let observation: ProbeObservation =
            serde_json::from_value(response).expect("typed observation");
        assert!(!observation.admitted);
        assert_eq!(observation.decision, "deny_all");
    }

    #[test]
    fn closing_a_session_drops_its_state() {
        let handler = handler(NetworkPolicy::deny_all(), 4);
        assert!(handler.binding_for(SESSION).is_some());
        handler.close_session(SESSION);
        assert!(handler.binding_for(SESSION).is_none());
        assert!(handler.observation_for(SESSION).is_none());
    }

    #[test]
    fn a_session_that_cannot_record_does_not_probe() {
        // `spec()` attaches no emitter, so recording is off.
        let handler = handler(NetworkPolicy::deny_all(), 4);
        assert_eq!(
            handler.decide(
                &context(),
                &request("k1", "n1", "undeclared.synthetic.destination"),
                NOW_MS
            ),
            Err(ProbeRefusal::AuditUnavailable)
        );
        // The refusal must leave no trace of an attempt: a boundary probe that
        // could not be recorded must not later read as one that happened.
        let observed = handler.observation_for(SESSION).expect("observation");
        assert!(!observed.attempted_effect);
        assert!(observed.blocked_edges.is_empty());
        assert!(handler.evidence_refs_for(SESSION).is_empty());
    }

    #[test]
    fn a_recorded_probe_produces_a_reference_that_resolves_to_its_chain_line() {
        let (handler, dir) = audited(NetworkPolicy::deny_all(), 4);
        handler
            .decide(
                &context(),
                &request("k1", "n1", "undeclared.synthetic.destination"),
                NOW_MS,
            )
            .expect("probe runs");

        let refs = handler.evidence_refs_for(SESSION);
        assert_eq!(refs.len(), 1, "a probe records audit only, not a receipt");

        let plan = PlanFixture::new().build();
        let path = chain_path(&dir, &plan);
        let line = resolve_audit_ref(&path, &refs[0])
            .expect("chain readable")
            .expect("the reference must resolve to a line on disk");
        assert!(line.contains("assurance.probe"), "{line}");
    }

    #[test]
    fn the_host_observer_commits_the_exact_probe_evidence_under_the_session_identity() {
        let (handler, dir) = audited(NetworkPolicy::deny_all(), 4);
        handler
            .decide(
                &context(),
                &request("k1", "n1", "undeclared.synthetic.destination"),
                NOW_MS,
            )
            .expect("probe runs");

        let verified = handler
            .finalize_observation(SESSION, &binding(), &identity())
            .expect("observer evidence commits");
        assert!(verified.observation.attempted_effect);
        assert!(!verified.observation.boundary_crossed);
        assert_eq!(
            verified.observation.blocked_edges,
            vec![id("undeclared.synthetic.destination")]
        );
        assert_eq!(verified.probe_refs.len(), 1);
        assert!(verified.receipt_ref.as_str().starts_with("mvm:receipt:"));

        let path = chain_path(&dir, &PlanFixture::new().build());
        let line = resolve_audit_ref(&path, &verified.audit_ref)
            .expect("chain readable")
            .expect("observer reference resolves");
        assert!(line.contains("assurance.observer_completed"), "{line}");
        assert!(line.contains(verified.probe_refs[0].as_str()), "{line}");
        assert!(line.contains(SOURCE_DIGEST), "{line}");
    }

    #[test]
    fn the_host_observer_refuses_a_foreign_identity_without_emitting() {
        let (handler, dir) = audited(NetworkPolicy::deny_all(), 4);
        handler
            .decide(
                &context(),
                &request("k1", "n1", "undeclared.synthetic.destination"),
                NOW_MS,
            )
            .expect("probe runs");
        let path = chain_path(&dir, &PlanFixture::new().build());
        let chain_before = std::fs::read_to_string(&path).expect("chain");
        let mut foreign = identity();
        foreign.trial_id = id("trial-foreign");

        let error = handler
            .finalize_observation(SESSION, &binding(), &foreign)
            .expect_err("foreign identity must fail closed");
        assert!(error.to_string().contains("identity does not match"));
        assert_eq!(std::fs::read_to_string(&path).expect("chain"), chain_before);
    }

    #[test]
    fn a_probe_record_carries_no_destination_host_or_port() {
        let (handler, dir) = audited(NetworkPolicy::deny_all(), 4);
        handler
            .decide(
                &context(),
                &request("k1", "n1", "undeclared.synthetic.destination"),
                NOW_MS,
            )
            .expect("probe runs");

        let plan = PlanFixture::new().build();
        let chain = std::fs::read_to_string(chain_path(&dir, &plan)).expect("chain");
        let line = chain.lines().next().expect("one line");
        let envelope: serde_json::Value = serde_json::from_str(line).expect("parse");
        let labels = envelope["entry"]["labels"]
            .as_object()
            .expect("labels")
            .clone();

        // Assert over the decoded labels rather than the raw file: the file
        // also carries a base64 copy of the same entry, and a digit sequence
        // can appear inside base64 by coincidence, which would make this pass
        // or fail for a reason unrelated to what crossed.
        let rendered = serde_json::to_string(&labels).expect("labels json");
        assert!(
            rendered.contains("undeclared.synthetic.destination"),
            "{rendered}"
        );
        assert!(!rendered.contains("attacker.example.com"), "{rendered}");
        assert!(!rendered.contains("443"), "{rendered}");
        // Only identifiers and closed decision tokens are recorded.
        assert_eq!(labels["assurance_decision"], "deny_all");
        assert_eq!(labels["assurance_probe"], "egress.admission.v1");
    }

    #[test]
    fn a_reference_from_one_chain_does_not_resolve_against_another() {
        let (handler, dir) = audited(NetworkPolicy::deny_all(), 4);
        handler
            .decide(
                &context(),
                &request("k1", "n1", "undeclared.synthetic.destination"),
                NOW_MS,
            )
            .expect("probe runs");
        let refs = handler.evidence_refs_for(SESSION);

        let other = tempfile::tempdir().expect("tempdir");
        let empty = other.path().join("empty.jsonl");
        std::fs::write(&empty, "").expect("write");
        assert!(
            resolve_audit_ref(&empty, &refs[0])
                .expect("readable")
                .is_none(),
            "a citation must not resolve against a chain that never carried it"
        );
        drop(dir);
    }

    #[test]
    fn a_trial_completion_records_its_outcome_and_a_receipt() {
        use mvm_contract::assurance::{InconclusiveReason, TrialOutcome, TrialVerdict};

        let dir = tempfile::tempdir().expect("tempdir");
        let key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let emitter = AuditEmitter::with_dir(key, dir.path())
            .expect("emitter")
            .with_receipts();
        let plan = PlanFixture::new().build();
        let identity = identity_of(&plan);
        let ledger = AssuranceLedger::new(&emitter, &identity);
        let identity = crate::audit::assurance::SessionIdentity {
            session_id: id(SESSION),
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
            source_digest: Sha256Digest::parse(format!("sha256:{}", "3".repeat(64)))
                .expect("digest"),
        };

        let refs = ledger
            .complete_trial(
                &identity,
                &TrialVerdict {
                    outcome: TrialOutcome::Inconclusive,
                    reason: Some(InconclusiveReason::ObserverMissing),
                },
            )
            .expect("trial recorded");
        assert!(
            refs.receipt.is_some(),
            "a published trial outcome must carry a receipt"
        );

        let chain = std::fs::read_to_string(chain_path(&dir, &plan)).expect("chain");
        assert!(chain.contains("assurance.trial_completed"), "{chain}");
        assert!(chain.contains("INCONCLUSIVE"), "{chain}");
        assert!(chain.contains("observer_missing"), "{chain}");
        // An inconclusive outcome is explicitly not a claim.
        assert!(
            chain.contains("\"assurance_certifying\":\"false\""),
            "{chain}"
        );
    }

    #[test]
    fn a_binding_citing_recorded_evidence_resolves_end_to_end() {
        use crate::audit::assurance::{SessionIdentity, cite};

        let dir = tempfile::tempdir().expect("tempdir");
        let key = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
        let emitter = AuditEmitter::with_dir(key, dir.path())
            .expect("emitter")
            .with_receipts();
        let plan = PlanFixture::new().build();
        let identity = identity_of(&plan);
        let ledger = AssuranceLedger::new(&emitter, &identity);
        let refs = ledger
            .open_session(
                &SessionIdentity {
                    session_id: id(SESSION),
                    campaign_id: id("mvm-campaign-1"),
                    trial_id: id("trial-1"),
                    source_digest: Sha256Digest::parse(format!("sha256:{}", "3".repeat(64)))
                        .expect("digest"),
                },
                &grant(),
            )
            .expect("session recorded");
        assert!(refs.receipt.is_some());

        let bound = cite(
            MvmBinding::builder()
                .session_id(id(SESSION))
                .plan(&plan)
                .expect("plan")
                .artifact_digest(digest(ARTIFACT_DIGEST))
                .effective_policy_digest(digest(POLICY_DIGEST))
                .grant(grant())
                .backend("firecracker"),
            &refs,
        )
        .build()
        .expect("a binding citing recorded evidence builds");

        assert!(
            audit_citations_resolve(&bound, &chain_path(&dir, &plan)).expect("readable"),
            "every audit citation on the binding must resolve"
        );
    }

    #[test]
    fn only_a_bound_service_registers_its_handler() {
        use crate::broker::handlers::register_bound_handlers;
        use crate::broker::registry::Registry;

        let mut registry = Registry::new();
        let bound = register_bound_handlers(&mut registry, &[]);
        assert!(
            bound.assurance.is_none(),
            "an unbound plan must not get the assurance handler"
        );

        let mut registry = Registry::new();
        let service = ServiceId::parse(HOST_ASSURANCE_SERVICE).expect("service id");
        let bound = register_bound_handlers(&mut registry, &[service]);
        assert!(bound.assurance.is_some());
    }
}
