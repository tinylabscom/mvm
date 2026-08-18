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
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mvm_contract::assurance::{
    AssuranceId, EffectiveAuthority, HostObservation, MvmBinding, PROBE_OBSERVATION_SCHEMA,
    ProbeInvocation, ProbeObservation, ProbeRefusal, ProbeRequest,
};
use mvm_core::egress_broker::{EgressRequest, EgressVerdict, decide_egress};
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::policy::security::AgentProfile;
use mvm_core::protocol::broker::{AuditDurability, Idempotency, ServiceErrorCode, ServiceId};
use mvm_core::protocol::handler::{
    ServiceCallCtx, ServiceDispatchResult, ServiceError, ServiceHandler,
};

/// Wire name of this service.
pub const HOST_ASSURANCE_SERVICE: &str = "host.assurance.v1";

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
#[derive(Debug, Clone)]
pub struct AssuranceSessionSpec {
    /// The workload session the supervisor will report in `ServiceCallCtx`.
    pub workload_session_id: String,
    /// The admitted binding this session runs under.
    pub binding: MvmBinding,
    /// Authority already intersected down from all five sources.
    pub authority: EffectiveAuthority,
    /// The trial this session is opened for.
    pub trial_id: AssuranceId,
    /// The workload's admitted egress policy.
    pub policy: NetworkPolicy,
    /// Destinations the campaign declared.
    pub destinations: Vec<DeclaredDestination>,
}

#[derive(Debug)]
struct AssuranceSession {
    binding: MvmBinding,
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
}

impl AssuranceSession {
    fn steps_remaining(&self) -> u32 {
        self.authority.max_steps().saturating_sub(self.steps_used)
    }
}

/// Handler for `host.assurance.v1`.
pub struct HostAssuranceV1Handler {
    sessions: Mutex<BTreeMap<String, AssuranceSession>>,
}

impl HostAssuranceV1Handler {
    /// Construct a handler with no open sessions.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(BTreeMap::new()),
        }
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

    /// Close a session, dropping its nonce ledger and recorded results.
    pub fn close_session(&self, workload_session_id: &str) {
        self.sessions
            .lock()
            .expect("assurance session map is not poisoned")
            .remove(workload_session_id);
    }

    fn now_unix_ms() -> u64 {
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

        // The supervisor's context is authoritative. The request's own
        // session_id exists only so a disagreement is visible.
        if request.session_id.as_str() != ctx.session_id {
            return Err(ProbeRefusal::SessionMismatch);
        }
        if request.trial_id != session.trial_id {
            return Err(ProbeRefusal::TrialMismatch);
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

        let observation = match &request.invocation {
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

                session.attempted_effect = true;
                if admitted {
                    // The policy admitted the destination, so the edge the
                    // campaign was probing is reachable: the effect crossed.
                    session.boundary_crossed = true;
                    session.effect_observed_in_guest = true;
                } else if !session.blocked_edges.contains(destination_label) {
                    session.blocked_edges.push(destination_label.clone());
                }

                ProbeObservation {
                    schema: PROBE_OBSERVATION_SCHEMA.to_string(),
                    probe: request.invocation.probe_id().to_string(),
                    admitted,
                    blocked_edge: (!admitted).then(|| destination_label.clone()),
                    decision: decision.to_string(),
                    steps_remaining: 0,
                }
            }
        };

        session.steps_used = session.steps_used.saturating_add(1);
        let observation = ProbeObservation {
            steps_remaining: session.steps_remaining(),
            ..observation
        };
        session
            .results
            .insert(request.idempotency_key.clone(), observation.clone());
        Ok(observation)
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

    use mvm_contract::assurance::{
        ApprovalSet, AuthorityCeiling, AuthorityInputs, EvidenceRef, ObservationScope,
        PROBE_REQUEST_SCHEMA, RequestedAuthority, SessionGrant, Sha256Digest, ToolId,
    };
    use mvm_contract::policy::network_policy::HostPort;
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_core::protocol::broker::CorrelationId;

    const ARTIFACT_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const POLICY_DIGEST: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";
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
        let handler = HostAssuranceV1Handler::new();
        let mut session = spec(policy, max_steps);
        session.authority = authority_expiring_at(max_steps, expiry, now);
        handler.open_session(session);
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
            authority: authority(max_steps),
            trial_id: id("trial-1"),
            policy,
            destinations: vec![DeclaredDestination {
                label: id("undeclared.synthetic.destination"),
                host: "attacker.example.com".to_string(),
                port: 443,
            }],
        }
    }

    fn handler(policy: NetworkPolicy, max_steps: u32) -> HostAssuranceV1Handler {
        let handler = HostAssuranceV1Handler::new();
        handler.open_session(spec(policy, max_steps));
        handler
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

    fn request(idempotency: &str, nonce: &str, label: &str) -> ProbeRequest {
        ProbeRequest {
            schema: PROBE_REQUEST_SCHEMA.to_string(),
            session_id: id(SESSION),
            trial_id: id("trial-1"),
            idempotency_key: id(idempotency),
            nonce: id(nonce),
            tool: ToolId::CampaignProbeV1,
            invocation: ProbeInvocation::EgressAdmission {
                destination_label: id(label),
            },
        }
    }

    #[test]
    fn a_deny_all_policy_refuses_the_declared_destination_and_records_a_blocked_edge() {
        let handler = handler(NetworkPolicy::deny_all(), 4);
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
        let handler = handler(policy, 4);
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
        let handler = handler(NetworkPolicy::deny_all(), 4);
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
        let handler = handler(NetworkPolicy::deny_all(), 4);
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
        let handler = handler(NetworkPolicy::deny_all(), 1);
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
