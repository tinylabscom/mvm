//! Opening and closing an assurance session against an admitted plan.
//!
//! This is the seam that makes the probe surface reachable outside a test. It
//! mirrors the workload input plane: a process-global registry installed when
//! the broker registry is built, and one entry point that takes an
//! [`AdmittedPlan`] and decides whether a session may exist at all.
//!
//! # The operator declares the campaign, not the workload
//!
//! Every value a probe could be steered by — which destinations exist, what
//! they resolve to, which tools an operator approved — arrives in a
//! [`CampaignDeclaration`] supplied host-side. The workload receives labels.
//! The declaration is deliberately *not* part of the signed plan: a campaign is
//! chosen per run against a plan that may be reused, and putting it in the plan
//! would mean re-admitting a workload to re-point a probe.
//!
//! What the plan *does* decide is whether any of this is permitted: a plan that
//! does not bind `host.assurance.v1` gets no session, regardless of what the
//! declaration asks for. Both must agree.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use mvm_contract::assurance::{
    ApprovalSet, AssuranceId, AuthorityCeiling, AuthorityInputs, EffectiveAuthority, MvmBinding,
    ObservationScope, RequestedAuthority, SessionGrant, Sha256Digest, ToolId, TrialVerdict,
};
use mvm_core::plan::ExecutionPlan;
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::protocol::broker::ServiceId;
use sha2::{Digest, Sha256};

use crate::audit::assurance::{AssuranceLedger, SessionIdentity, cite};
use crate::audit::emitter::AuditEmitter;
use crate::broker::handlers::host_assurance_v1::{
    AssuranceSessionSpec, DeclaredDestination, HOST_ASSURANCE_SERVICE, HostAssuranceV1Handler,
};
use crate::plan_admission::AdmittedPlan;

/// A destination an operator declared for one campaign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredEdge {
    pub label: AssuranceId,
    pub host: String,
    pub port: u16,
}

/// What an operator authorized for one campaign against one workload.
#[derive(Debug, Clone)]
pub struct CampaignDeclaration {
    pub campaign_id: AssuranceId,
    pub trial_id: AssuranceId,
    pub source_run_id: AssuranceId,
    pub source_digest: Sha256Digest,
    /// Destinations the campaign may probe, by label.
    pub edges: Vec<DeclaredEdge>,
    /// Tools the operator explicitly approved.
    pub approvals: ApprovalSet,
    /// What the campaign asked for. Narrowed by every other bound.
    pub requested: RequestedAuthority,
    /// How long the session's grant is live.
    pub grant_ttl_ms: u64,
}

/// Why no session was opened.
#[derive(Debug, thiserror::Error)]
pub enum SessionRefusal {
    #[error("the admitted plan does not bind {HOST_ASSURANCE_SERVICE}")]
    ServiceNotBound,
    #[error("this process holds no assurance plane")]
    NoPlane,
    #[error("the campaign declares no destination")]
    NoEdges,
    #[error("effective authority is empty: {0}")]
    NoAuthority(String),
    #[error("the session could not be recorded, so it was not opened: {0}")]
    NotRecorded(String),
    #[error("the admitted plan cannot be bound: {0}")]
    Unbindable(String),
}

/// Install the assurance plane for this process.
///
/// Idempotent, and returns whether this call installed it — mirroring the
/// stream plane, so a binary with more than one entry point can register
/// defensively at each.
pub fn install_host_assurance_plane(handler: Arc<HostAssuranceV1Handler>) -> bool {
    HOST_ASSURANCE_PLANE.set(handler).is_ok()
}

/// The plane [`install_host_assurance_plane`] registered.
///
/// `None` in a process that never built a broker registry binding the service,
/// which is every embedder that does not run assurance campaigns.
#[must_use]
pub fn host_assurance_plane() -> Option<Arc<HostAssuranceV1Handler>> {
    HOST_ASSURANCE_PLANE.get().map(Arc::clone)
}

static HOST_ASSURANCE_PLANE: OnceLock<Arc<HostAssuranceV1Handler>> = OnceLock::new();

/// Whether `plan` admits the assurance service at all.
#[must_use]
pub fn plan_binds_assurance(plan: &ExecutionPlan) -> bool {
    ServiceId::parse(HOST_ASSURANCE_SERVICE)
        .ok()
        .is_some_and(|service| plan.services.contains(&service))
}

/// Derive this session's stable identifiers.
///
/// Content-addressed over the plan, the VM and the campaign rather than random:
/// re-opening the same campaign against the same admitted plan yields the same
/// session id, which makes a duplicate open visible instead of silently
/// producing a second session, and makes the whole path reproducible in a test.
fn derive_ids(plan_id: &str, vm: &str, decl: &CampaignDeclaration) -> (AssuranceId, AssuranceId) {
    let mut hasher = Sha256::new();
    hasher.update(plan_id.as_bytes());
    hasher.update([0]);
    hasher.update(vm.as_bytes());
    hasher.update([0]);
    hasher.update(decl.campaign_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(decl.trial_id.as_str().as_bytes());
    let digest = hex::encode(hasher.finalize());
    let session = AssuranceId::parse(format!("s-{}", &digest[..32]))
        .expect("a hex-derived identifier is always well formed");
    let nonce = AssuranceId::parse(format!("gn-{}", &digest[32..64]))
        .expect("a hex-derived identifier is always well formed");
    (session, nonce)
}

/// Mint the grant a session runs under.
///
/// The digest is over the grant's own content, so it is an identity rather than
/// a label: two grants that differ anywhere cannot share one, and the guest
/// cannot be handed a digest that names a grant the host did not mint.
fn mint_grant(
    session_id: &AssuranceId,
    nonce: AssuranceId,
    now_unix_ms: u64,
    decl: &CampaignDeclaration,
) -> SessionGrant {
    let expires_unix_ms = now_unix_ms.saturating_add(decl.grant_ttl_ms);
    let tools: Vec<ToolId> = decl.requested.allowed_tools.clone();
    let scopes: Vec<ObservationScope> = decl.requested.observation_scopes.clone();

    let mut hasher = Sha256::new();
    hasher.update(session_id.as_str().as_bytes());
    hasher.update(nonce.as_str().as_bytes());
    hasher.update(expires_unix_ms.to_be_bytes());
    for tool in &tools {
        hasher.update(serde_json::to_vec(tool).unwrap_or_default());
    }
    for scope in &scopes {
        hasher.update(serde_json::to_vec(scope).unwrap_or_default());
    }
    let grant_digest = Sha256Digest::from_bytes(&hasher.finalize().into());

    SessionGrant {
        grant_digest,
        expires_unix_ms,
        nonce,
        allowed_tools: tools,
        observation_scopes: scopes,
    }
}

/// Everything one open needs.
pub struct OpenSession<'a> {
    pub vm: &'a str,
    pub admitted: &'a AdmittedPlan,
    pub declaration: &'a CampaignDeclaration,
    pub emitter: &'a Arc<AuditEmitter>,
    /// The host's own ceiling. Narrows the request; never widens it.
    pub policy_ceiling: &'a AuthorityCeiling,
    /// The workload's admitted egress policy, which the probe consults.
    pub policy: NetworkPolicy,
    /// Backend the plan resolved to.
    pub backend: &'a str,
    pub now_unix_ms: u64,
}

/// Open an assurance session, or refuse and open nothing.
///
/// The order matters: authority is intersected before anything is recorded, and
/// the session is recorded before it is opened. A session that exists but was
/// never written down would let a probe run against a binding that cites an
/// audit entry nobody wrote.
pub fn open(request: OpenSession<'_>) -> Result<MvmBinding, SessionRefusal> {
    let plane = host_assurance_plane().ok_or(SessionRefusal::NoPlane)?;
    open_on(&plane, request)
}

/// Open against an explicit plane.
///
/// The process-global is a convenience for the one production caller, not the
/// mechanism. Taking the plane as an argument keeps the whole decision path
/// reachable from a test without installing a `OnceLock` that a second test in
/// the same process could never replace.
pub fn open_on(
    plane: &Arc<HostAssuranceV1Handler>,
    request: OpenSession<'_>,
) -> Result<MvmBinding, SessionRefusal> {
    let plan = request.admitted.plan();
    if !plan_binds_assurance(plan) {
        return Err(SessionRefusal::ServiceNotBound);
    }
    if request.declaration.edges.is_empty() {
        return Err(SessionRefusal::NoEdges);
    }

    let (session_id, grant_nonce) = derive_ids(
        request.admitted.plan_id().0.as_str(),
        request.vm,
        request.declaration,
    );
    let grant = mint_grant(
        &session_id,
        grant_nonce,
        request.now_unix_ms,
        request.declaration,
    );

    let extension = AuthorityCeiling::extension_maximum();
    let authority = EffectiveAuthority::intersect(
        AuthorityInputs {
            extension_maximum: &extension,
            requested: &request.declaration.requested,
            policy_ceiling: request.policy_ceiling,
            grant: &grant,
            approvals: &request.declaration.approvals,
        },
        request.now_unix_ms,
    )
    .map_err(|error| SessionRefusal::NoAuthority(error.to_string()))?;

    let identity = SessionIdentity {
        session_id: session_id.clone(),
        campaign_id: request.declaration.campaign_id.clone(),
        trial_id: request.declaration.trial_id.clone(),
        source_digest: request.declaration.source_digest.clone(),
    };
    let ledger = AssuranceLedger::new(request.emitter, plan);
    let refs = ledger
        .open_session(&identity)
        .map_err(|error| SessionRefusal::NotRecorded(error.to_string()))?;

    // The artifact and policy digests a campaign is evaluated against. Both are
    // derived from what was admitted, never from the declaration: the
    // declaration states an intent, and correlation compares the two.
    let artifact_digest = Sha256Digest::parse(format!("sha256:{}", plan.image.sha256))
        .map_err(|error| SessionRefusal::Unbindable(format!("{error}")))?;
    let effective_policy_digest = policy_digest(plan);

    let binding = cite(
        MvmBinding::builder()
            .session_id(session_id)
            .plan(plan)
            .map_err(|error| SessionRefusal::Unbindable(error.to_string()))?
            .artifact_digest(artifact_digest)
            .effective_policy_digest(effective_policy_digest)
            .grant(grant)
            .backend(request.backend),
        &refs,
    )
    .build()
    .map_err(|error| SessionRefusal::Unbindable(error.to_string()))?;

    plane.open_session(AssuranceSessionSpec {
        workload_session_id: request.vm.to_string(),
        binding: binding.clone(),
        authority,
        trial_id: request.declaration.trial_id.clone(),
        policy: request.policy,
        destinations: request
            .declaration
            .edges
            .iter()
            .map(|edge| DeclaredDestination {
                label: edge.label.clone(),
                host: edge.host.clone(),
                port: edge.port,
            })
            .collect(),
        plan: plan.clone(),
        emitter: Some(Arc::clone(request.emitter)),
    });
    Ok(binding)
}

/// Digest the policy references a campaign is evaluated under.
///
/// The plan carries policy by reference rather than by value, so this is a
/// digest over the exact references admitted — enough to detect that the policy
/// in force is not the one a campaign claims, which is what the evaluator's
/// mismatch check needs.
fn policy_digest(plan: &ExecutionPlan) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(plan.network_policy.0.as_bytes());
    hasher.update([0]);
    hasher.update(plan.egress_policy.0.as_bytes());
    hasher.update([0]);
    hasher.update(plan.fs_policy.0.as_bytes());
    hasher.update([0]);
    hasher.update(plan.tool_policy.0.as_bytes());
    Sha256Digest::from_bytes(&hasher.finalize().into())
}

/// Record a trial's outcome and drop the session.
///
/// The record is written before the state is dropped, so a teardown that fails
/// to record leaves the session in place rather than losing both.
pub fn close(
    vm: &str,
    admitted: &AdmittedPlan,
    emitter: &AuditEmitter,
    identity: &SessionIdentity,
    verdict: &TrialVerdict,
) -> Result<()> {
    let plane = host_assurance_plane()
        .ok_or_else(|| anyhow::anyhow!("this process holds no assurance plane"))?;
    close_on(&plane, admitted, emitter, identity, verdict)?;
    plane.close_session(vm);
    Ok(())
}

/// Record a trial's outcome against an explicit plane.
pub fn close_on(
    plane: &Arc<HostAssuranceV1Handler>,
    admitted: &AdmittedPlan,
    emitter: &AuditEmitter,
    identity: &SessionIdentity,
    verdict: &TrialVerdict,
) -> Result<()> {
    let _ = plane;
    AssuranceLedger::new(emitter, admitted.plan())
        .complete_trial(identity, verdict)
        .context("recording the trial outcome")?;
    Ok(())
}

/// The host ceiling applied when no operator configuration narrows it further.
///
/// Deliberately the extension maximum: the ceiling exists so a deployment *can*
/// narrow, and inventing a tighter default here would silently disagree with
/// the declaration an operator wrote without telling them why.
#[must_use]
pub fn default_policy_ceiling() -> AuthorityCeiling {
    AuthorityCeiling::extension_maximum()
}

/// Edges keyed by label, for a caller that wants to check its own declaration.
#[must_use]
pub fn edges_by_label(decl: &CampaignDeclaration) -> BTreeMap<AssuranceId, (String, u16)> {
    decl.edges
        .iter()
        .map(|edge| (edge.label.clone(), (edge.host.clone(), edge.port)))
        .collect()
}

/// An operator-declared campaign, with everything the open needs that the
/// admit path does not already hold.
///
/// The emitter is an `Arc` because the opened session outlives this call: it
/// records every probe for as long as the workload runs, so a borrow would tie
/// the session's lifetime to the boot call that opened it.
pub struct CampaignRequest<'a> {
    pub declaration: &'a CampaignDeclaration,
    pub emitter: Arc<AuditEmitter>,
    pub policy_ceiling: AuthorityCeiling,
    /// The workload's admitted egress policy, which the probe consults.
    pub policy: NetworkPolicy,
    pub backend: String,
    pub now_unix_ms: u64,
}

/// Open a declared campaign against a booted VM, using this process's plane.
pub fn open_for_boot(
    campaign: &CampaignRequest<'_>,
    vm: &str,
    admitted: &AdmittedPlan,
) -> Result<MvmBinding> {
    let plane = host_assurance_plane().ok_or_else(|| {
        anyhow::anyhow!(
            "this process holds no assurance plane, so the declared campaign has nowhere to run"
        )
    })?;
    open_on(
        &plane,
        OpenSession {
            vm,
            admitted,
            declaration: campaign.declaration,
            emitter: &campaign.emitter,
            policy_ceiling: &campaign.policy_ceiling,
            policy: campaign.policy.clone(),
            backend: &campaign.backend,
            now_unix_ms: campaign.now_unix_ms,
        },
    )
    .map_err(|refusal| anyhow::anyhow!("{refusal}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use mvm_contract::assurance::{InconclusiveReason, TrialOutcome};
    use mvm_core::plan::test_support::PlanFixture;

    const SOURCE_DIGEST: &str =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    const NOW_MS: u64 = 1_800_000_000_000;

    fn id(raw: &str) -> AssuranceId {
        AssuranceId::parse(raw).expect("identifier")
    }

    fn declaration() -> CampaignDeclaration {
        CampaignDeclaration {
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
            source_run_id: id("scout-1"),
            source_digest: Sha256Digest::parse(SOURCE_DIGEST).expect("digest"),
            edges: vec![DeclaredEdge {
                label: id("undeclared.synthetic.destination"),
                host: "attacker.example.com".to_string(),
                port: 443,
            }],
            approvals: ApprovalSet::none().with(ToolId::CampaignProbeV1),
            requested: RequestedAuthority {
                allowed_tools: vec![ToolId::CampaignProbeV1],
                observation_scopes: vec![ObservationScope::HostAuditRefs],
                max_steps: 8,
                max_output_bytes: 4096,
                deadline_unix_ms: 0,
            },
            grant_ttl_ms: 600_000,
        }
    }

    fn bound_plan() -> ExecutionPlan {
        let service = ServiceId::parse(HOST_ASSURANCE_SERVICE).expect("service");
        PlanFixture::new().services(vec![service]).build()
    }

    #[test]
    fn identifiers_are_derived_and_therefore_reproducible() {
        let decl = declaration();
        let a = derive_ids("plan-1", "vm-a", &decl);
        let b = derive_ids("plan-1", "vm-a", &decl);
        assert_eq!(
            a, b,
            "the same campaign against the same plan is one session"
        );

        // Anything that distinguishes the run distinguishes the session.
        assert_ne!(a, derive_ids("plan-2", "vm-a", &decl));
        assert_ne!(a, derive_ids("plan-1", "vm-b", &decl));
        let mut other = declaration();
        other.trial_id = id("trial-2");
        assert_ne!(a, derive_ids("plan-1", "vm-a", &other));
    }

    #[test]
    fn the_grant_digest_is_an_identity_not_a_label() {
        let decl = declaration();
        let (session, nonce) = derive_ids("plan-1", "vm-a", &decl);
        let grant = mint_grant(&session, nonce.clone(), NOW_MS, &decl);
        assert_eq!(grant.expires_unix_ms, NOW_MS + decl.grant_ttl_ms);

        // A grant that expires differently is a different grant.
        let later = mint_grant(&session, nonce.clone(), NOW_MS + 1, &decl);
        assert_ne!(grant.grant_digest, later.grant_digest);

        // And one granting fewer scopes is too.
        let mut narrower = declaration();
        narrower.requested.observation_scopes.clear();
        let narrowed = mint_grant(&session, nonce, NOW_MS, &narrower);
        assert_ne!(grant.grant_digest, narrowed.grant_digest);
    }

    #[test]
    fn a_plan_that_does_not_bind_the_service_is_refused_before_anything_else() {
        assert!(!plan_binds_assurance(&PlanFixture::new().build()));
        assert!(plan_binds_assurance(&bound_plan()));
    }

    #[test]
    fn the_policy_digest_moves_when_a_policy_reference_moves() {
        let base = bound_plan();
        let mut changed = bound_plan();
        changed.egress_policy = mvm_core::plan::PolicyRef("other-egress".to_string());
        assert_ne!(policy_digest(&base), policy_digest(&changed));
    }

    #[test]
    fn the_default_ceiling_narrows_nothing_on_its_own() {
        // The ceiling exists so a deployment can narrow. A default that
        // narrowed would disagree with an operator's declaration silently.
        let ceiling = default_policy_ceiling();
        assert!(ceiling.tools.contains(&ToolId::CampaignProbeV1));
        assert_eq!(ceiling, AuthorityCeiling::extension_maximum());
    }

    #[test]
    fn a_campaign_without_operator_approval_yields_no_authority() {
        let decl = CampaignDeclaration {
            approvals: ApprovalSet::none(),
            ..declaration()
        };
        let (session, nonce) = derive_ids("plan-1", "vm-a", &decl);
        let grant = mint_grant(&session, nonce, NOW_MS, &decl);
        let extension = AuthorityCeiling::extension_maximum();
        let result = EffectiveAuthority::intersect(
            AuthorityInputs {
                extension_maximum: &extension,
                requested: &decl.requested,
                policy_ceiling: &default_policy_ceiling(),
                grant: &grant,
                approvals: &decl.approvals,
            },
            NOW_MS,
        );
        assert!(result.is_err(), "an unapproved campaign must not open");
    }

    #[test]
    fn a_declared_edge_table_keys_by_label() {
        let table = edges_by_label(&declaration());
        assert_eq!(
            table.get(&id("undeclared.synthetic.destination")),
            Some(&("attacker.example.com".to_string(), 443))
        );
    }

    #[test]
    fn a_verdict_carries_its_reason_into_the_completion_record() {
        // The close path's record is the ledger's; this pins the shape the
        // caller hands it, so a non-claim outcome always names why.
        let verdict = TrialVerdict {
            outcome: TrialOutcome::Inconclusive,
            reason: Some(InconclusiveReason::ObserverMissing),
        };
        assert!(!verdict.outcome.is_certifying_claim());
        assert!(verdict.reason.is_some());
    }

    // ---------------------------------------------------------------------
    // Lifecycle, end to end: open against an admitted plan, probe through the
    // real dispatch path, close.
    // ---------------------------------------------------------------------

    use ed25519_dalek::SigningKey as EdKey;
    use mvm_contract::assurance::{
        PROBE_REQUEST_SCHEMA, ProbeInvocation, ProbeObservation, ProbeRequest,
    };
    use mvm_core::plan::signing::sign_plan as sign;
    use mvm_core::policy::security::AgentProfile;
    use mvm_core::protocol::broker::CorrelationId;
    use mvm_core::protocol::handler::{ServiceCallCtx, ServiceHandler};

    fn admitted_for(plan: ExecutionPlan) -> AdmittedPlan {
        let signer_id = "host:test".to_string();
        let signed = sign(&plan, &EdKey::from_bytes(&[7u8; 32]), &signer_id);
        AdmittedPlan::for_test(plan, signer_id, signed)
    }

    struct Opened {
        plane: Arc<HostAssuranceV1Handler>,
        admitted: AdmittedPlan,
        emitter: Arc<AuditEmitter>,
        dir: tempfile::TempDir,
        result: Result<MvmBinding, SessionRefusal>,
    }

    fn open_against(plan: ExecutionPlan) -> Opened {
        let dir = tempfile::tempdir().expect("tempdir");
        let emitter = Arc::new(
            AuditEmitter::with_dir(EdKey::from_bytes(&[21u8; 32]), dir.path())
                .expect("emitter")
                .with_receipts(),
        );
        let admitted = admitted_for(plan);
        let plane = Arc::new(HostAssuranceV1Handler::new());
        let ceiling = default_policy_ceiling();
        let result = open_on(
            &plane,
            OpenSession {
                vm: "vm-a",
                admitted: &admitted,
                declaration: &declaration(),
                emitter: &emitter,
                policy_ceiling: &ceiling,
                policy: NetworkPolicy::deny_all(),
                backend: "firecracker",
                now_unix_ms: NOW_MS,
            },
        );
        Opened {
            plane,
            admitted,
            emitter,
            dir,
            result,
        }
    }

    fn ctx() -> ServiceCallCtx {
        ServiceCallCtx {
            workload_id: "workload".into(),
            tenant_id: "tenant".into(),
            correlation_id: CorrelationId::new("c"),
            session_id: "vm-a".to_string(),
            profile: AgentProfile::SealedProd,
            composition_depth: 0,
            composition_width: 0,
        }
    }

    fn probe(session_id: &AssuranceId) -> ProbeRequest {
        ProbeRequest {
            schema: PROBE_REQUEST_SCHEMA.to_string(),
            session_id: session_id.clone(),
            trial_id: id("trial-1"),
            idempotency_key: id("k1"),
            nonce: id("n1"),
            tool: ToolId::CampaignProbeV1,
            invocation: ProbeInvocation::EgressAdmission {
                destination_label: id("undeclared.synthetic.destination"),
            },
        }
    }

    fn chain_of(opened: &Opened) -> String {
        let tenant = opened.admitted.plan().tenant.0.clone();
        std::fs::read_to_string(opened.dir.path().join(format!("{tenant}.jsonl")))
            .expect("chain readable")
    }

    #[test]
    fn an_unbound_plan_opens_nothing() {
        let opened = open_against(PlanFixture::new().build());
        assert!(matches!(
            opened.result,
            Err(SessionRefusal::ServiceNotBound)
        ));
        assert!(opened.plane.binding_for("vm-a").is_none());
    }

    #[test]
    fn a_campaign_declaring_no_edge_opens_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let emitter = Arc::new(
            AuditEmitter::with_dir(EdKey::from_bytes(&[22u8; 32]), dir.path()).expect("emitter"),
        );
        let admitted = admitted_for(bound_plan());
        let plane = Arc::new(HostAssuranceV1Handler::new());
        let ceiling = default_policy_ceiling();
        let declaration = CampaignDeclaration {
            edges: Vec::new(),
            ..declaration()
        };
        let result = open_on(
            &plane,
            OpenSession {
                vm: "vm-a",
                admitted: &admitted,
                declaration: &declaration,
                emitter: &emitter,
                policy_ceiling: &ceiling,
                policy: NetworkPolicy::deny_all(),
                backend: "firecracker",
                now_unix_ms: NOW_MS,
            },
        );
        assert!(matches!(result, Err(SessionRefusal::NoEdges)));
    }

    #[test]
    fn a_bound_plan_opens_a_session_whose_binding_quotes_it() {
        let opened = open_against(bound_plan());
        let binding = opened.result.as_ref().expect("session opens").clone();

        assert_eq!(binding.plan_id.as_str(), opened.admitted.plan_id().0);
        assert_eq!(binding.runtime.backend.as_str(), "firecracker");
        // The citation requirement is met by real emission, not a stub.
        assert!(!binding.audit_refs.is_empty());
        assert!(!binding.receipt_refs.is_empty());
        assert_eq!(opened.plane.binding_for("vm-a").as_ref(), Some(&binding));
        assert!(chain_of(&opened).contains("assurance.session_opened"));
    }

    #[tokio::test]
    async fn the_opened_session_is_the_one_the_probe_verb_dispatches_against() {
        // The point of this workstream: a probe reaches a session the admit
        // path opened, not one a test constructed by hand.
        let opened = open_against(bound_plan());
        let binding = opened.result.as_ref().expect("session opens").clone();

        let payload = serde_json::to_value(probe(&binding.session_id)).expect("payload");
        let reply = opened
            .plane
            .dispatch(&ctx(), "probe", payload)
            .await
            .expect("the probe reaches the opened session");
        let observation: ProbeObservation = serde_json::from_value(reply).expect("observation");
        assert!(!observation.admitted, "deny-all must refuse the edge");
        assert_eq!(observation.decision, "deny_all");

        let observed = opened.plane.observation_for("vm-a").expect("observation");
        assert!(observed.attempted_effect);
        assert!(!observed.boundary_crossed);

        let chain = chain_of(&opened);
        assert!(chain.contains("assurance.session_opened"), "{chain}");
        assert!(chain.contains("assurance.probe"), "{chain}");
    }

    #[tokio::test]
    async fn a_probe_naming_another_session_does_not_reach_this_one() {
        let opened = open_against(bound_plan());
        let _ = opened.result.as_ref().expect("session opens");

        let payload = serde_json::to_value(probe(&id("s-deadbeef"))).expect("payload");
        let error = opened
            .plane
            .dispatch(&ctx(), "probe", payload)
            .await
            .expect_err("a mismatched session id must be refused");
        assert_eq!(error.message, "session_mismatch");
    }

    #[test]
    fn closing_records_the_outcome_and_drops_the_session() {
        let opened = open_against(bound_plan());
        let binding = opened.result.as_ref().expect("session opens").clone();

        let identity = SessionIdentity {
            session_id: binding.session_id.clone(),
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
            source_digest: Sha256Digest::parse(SOURCE_DIGEST).expect("digest"),
        };
        close_on(
            &opened.plane,
            &opened.admitted,
            &opened.emitter,
            &identity,
            &TrialVerdict {
                outcome: TrialOutcome::Inconclusive,
                reason: Some(InconclusiveReason::ObserverMissing),
            },
        )
        .expect("close records the outcome");
        opened.plane.close_session("vm-a");

        assert!(opened.plane.binding_for("vm-a").is_none());
        let chain = chain_of(&opened);
        assert!(chain.contains("assurance.trial_completed"), "{chain}");
        assert!(chain.contains("observer_missing"), "{chain}");
    }
}
