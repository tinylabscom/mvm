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

use crate::audit::assurance::{
    AssuranceAuditSink, AssuranceLedger, PlanIdentity, SessionIdentity, cite,
};
use crate::audit::emitter::AuditEmitter;
use crate::broker::handlers::host_assurance_v1::{
    AssuranceSessionSpec, DeclaredDestination, HOST_ASSURANCE_SERVICE, HostAssuranceV1Handler,
};
use crate::plan_admission::AdmittedPlan;

/// A destination an operator declared for one campaign.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredEdge {
    pub label: AssuranceId,
    pub host: String,
    pub port: u16,
}

/// What an operator authorized for one campaign against one workload.
///
/// Deserializable so an operator can hand one to `machine run` as a file. It is
/// authored by a human or by the assurance planner, never by the workload, and
/// `deny_unknown_fields` means a key this build does not understand refuses the
/// campaign rather than being silently dropped — a dropped destination or a
/// dropped approval is exactly the kind of quiet widening this contract exists
/// to prevent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Largest campaign declaration accepted from disk.
pub const MAX_DECLARATION_BYTES: u64 = 64 * 1024;

/// Read an operator-authored campaign declaration.
///
/// Size-checked before parsing, so an oversized file is refused without being
/// deserialized.
pub fn load_declaration(path: &std::path::Path) -> Result<CampaignDeclaration> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading campaign declaration {}", path.display()))?;
    if metadata.len() > MAX_DECLARATION_BYTES {
        anyhow::bail!(
            "campaign declaration {} is larger than the {MAX_DECLARATION_BYTES}-byte limit",
            path.display()
        );
    }
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("reading campaign declaration {}", path.display()))?;
    let declaration: CampaignDeclaration = serde_json::from_str(&body)
        .with_context(|| format!("parsing campaign declaration {}", path.display()))?;
    if declaration.edges.is_empty() {
        anyhow::bail!(
            "campaign declaration {} declares no destination, so it can probe nothing",
            path.display()
        );
    }
    Ok(declaration)
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
    let plan_identity = PlanIdentity::from(plan);
    let ledger = AssuranceLedger::new(request.emitter.as_ref(), &plan_identity);
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
        identity: PlanIdentity::from(plan),
        sink: Some(Arc::clone(request.emitter) as Arc<dyn AssuranceAuditSink + Send + Sync>),
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
    AssuranceLedger::new(emitter, &PlanIdentity::from(admitted.plan()))
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
pub struct CampaignRequest {
    /// Owned rather than borrowed: the request is assembled by a caller that
    /// reads the declaration from disk and then hands it down through the
    /// launch path, so tying it to that caller's frame would force a leak to
    /// satisfy the lifetime.
    pub declaration: CampaignDeclaration,
    pub emitter: Arc<AuditEmitter>,
    pub policy_ceiling: AuthorityCeiling,
    /// The workload's admitted egress policy, which the probe consults.
    pub policy: NetworkPolicy,
    pub backend: String,
    pub now_unix_ms: u64,
}

/// Open a declared campaign against a booted VM, using this process's plane.
pub fn open_for_boot(
    campaign: &CampaignRequest,
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
            declaration: &campaign.declaration,
            emitter: &campaign.emitter,
            policy_ceiling: &campaign.policy_ceiling,
            policy: campaign.policy.clone(),
            backend: &campaign.backend,
            now_unix_ms: campaign.now_unix_ms,
        },
    )
    .map_err(|refusal| anyhow::anyhow!("{refusal}"))
}

/// What the host can attest about a finished trial.
///
/// Every field is read from something the host itself did or can check now —
/// the probes it recorded, the plan it admitted, the state dir it can look at.
/// Nothing here is taken from the workload or from the declaration, which is
/// what makes the resulting [`EvidenceSet`] evidence rather than a claim.
pub struct CollectEvidence<'a> {
    pub vm: &'a str,
    pub admitted: &'a AdmittedPlan,
    pub binding: &'a MvmBinding,
    /// The campaign's source digest, for the join back to the scan.
    pub source_digest: &'a Sha256Digest,
    /// Where per-VM state lives, so teardown can be confirmed.
    pub mvm_home: &'a std::path::Path,
}

/// Assemble the evidence a trial is evaluated against.
///
/// The three verification flags are deliberately conservative:
///
/// - `observer_verified` is true only when the host actually recorded a probe
///   for this session. A session that opened and was never exercised observed
///   nothing, and saying otherwise would let an untested trial certify.
/// - `cleanup_verified` is true only when the workload's state dir no longer
///   carries a live process, checked through the same probe the admission
///   budget trusts. A VM still running has not been cleaned up, whatever the
///   plan intended.
/// - `attestation_verified` stays false: no attestation provider is wired, and
///   the evaluator only consults it when the plan demands attestation, so a
///   `Noop` plan is unaffected and a demanding one correctly fails closed.
#[must_use]
pub fn collect_evidence(request: CollectEvidence<'_>) -> mvm_contract::assurance::EvidenceSet {
    let plan = request.admitted.plan();
    let plane = host_assurance_plane();
    let probe_refs = plane
        .as_ref()
        .map(|plane| plane.evidence_refs_for(request.vm))
        .unwrap_or_default();
    let observed = plane
        .as_ref()
        .and_then(|plane| plane.observation_for(request.vm));

    // A recorded probe *and* an attempt: a session whose every probe was
    // refused before it ran has references but observed no effect.
    let observer_verified = !probe_refs.is_empty() && observed.is_some_and(|o| o.attempted_effect);

    let state_dir = mvm_core::config::vm_state_dir_at(request.mvm_home, request.vm);
    let cleanup_verified = !mvm_vmm::host::process_liveness::state_dir_has_live_process(&state_dir);

    let mut audit_refs = request.binding.audit_refs.clone();
    audit_refs.extend(probe_refs);

    mvm_contract::assurance::EvidenceSet {
        identity_verified: request.binding.plan_id.as_str()
            == request.admitted.plan_id().0.replace(':', "-"),
        observer_verified,
        cleanup_verified,
        attestation_verified: false,
        disposable_target: plan.post_run.destroy_on_exit,
        artifact_digest: request.binding.artifact_digest.clone(),
        policy_digest: request.binding.effective_policy_digest.clone(),
        source_digest: request.source_digest.clone(),
        audit_refs,
        receipt_refs: request.binding.receipt_refs.clone(),
    }
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

    fn declaration_json() -> String {
        serde_json::to_string_pretty(&declaration()).expect("a declaration serializes")
    }

    #[test]
    fn an_operator_declaration_round_trips_through_a_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("campaign.json");
        std::fs::write(&path, declaration_json()).expect("write");

        let loaded = load_declaration(&path).expect("a well-formed declaration loads");
        assert_eq!(loaded.campaign_id, declaration().campaign_id);
        assert_eq!(loaded.edges.len(), 1);
        assert_eq!(loaded.edges[0].host, "attacker.example.com");
        assert!(loaded.approvals.permits(ToolId::CampaignProbeV1));
    }

    #[test]
    fn a_declaration_with_an_unknown_key_is_refused() {
        // A key this build does not understand must refuse the campaign rather
        // than be dropped: a silently ignored destination or approval is the
        // quiet widening this contract exists to prevent.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("campaign.json");
        let body = declaration_json().replace(
            "{\n  \"campaign_id\"",
            "{\n  \"escalate\": true,\n  \"campaign_id\"",
        );
        std::fs::write(&path, body).expect("write");
        assert!(load_declaration(&path).is_err());
    }

    #[test]
    fn a_declaration_naming_no_destination_is_refused_at_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("campaign.json");
        let empty = CampaignDeclaration {
            edges: Vec::new(),
            ..declaration()
        };
        std::fs::write(&path, serde_json::to_string(&empty).expect("json")).expect("write");
        let error = load_declaration(&path).expect_err("a campaign that can probe nothing");
        assert!(format!("{error:#}").contains("no destination"), "{error:#}");
    }

    #[test]
    fn an_oversized_declaration_is_refused_before_it_is_parsed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("campaign.json");
        std::fs::write(&path, "x".repeat(MAX_DECLARATION_BYTES as usize + 1)).expect("write");
        let error = load_declaration(&path).expect_err("oversized");
        assert!(format!("{error:#}").contains("larger than"), "{error:#}");
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

    // ---------------------------------------------------------------------
    // Evidence collection
    // ---------------------------------------------------------------------

    fn evidence_for(
        home: &std::path::Path,
        vm: &str,
        binding: &MvmBinding,
        admitted: &AdmittedPlan,
    ) -> mvm_contract::assurance::EvidenceSet {
        collect_evidence(CollectEvidence {
            vm,
            admitted,
            binding,
            source_digest: &Sha256Digest::parse(SOURCE_DIGEST).expect("digest"),
            mvm_home: home,
        })
    }

    #[test]
    fn an_unexercised_session_observes_nothing_and_cannot_certify() {
        let opened = open_against(bound_plan());
        let binding = opened.result.as_ref().expect("session opens").clone();
        let home = tempfile::tempdir().expect("tempdir");

        // Opened, never probed. The plane is per-test here, so nothing this
        // session did was recorded — which is exactly the case that must not
        // read as an observer having watched.
        let evidence = evidence_for(home.path(), "vm-a", &binding, &opened.admitted);
        assert!(
            !evidence.observer_verified,
            "a session that ran no probe observed nothing"
        );
        assert!(evidence.identity_verified);
    }

    #[test]
    fn cleanup_is_verified_only_when_no_live_process_remains() {
        let opened = open_against(bound_plan());
        let binding = opened.result.as_ref().expect("session opens").clone();
        let home = tempfile::tempdir().expect("tempdir");

        // No state dir at all: nothing is running, so cleanup holds.
        let gone = evidence_for(home.path(), "vm-a", &binding, &opened.admitted);
        assert!(gone.cleanup_verified);

        // A pid marker pointing at this very process is unambiguously live.
        let dir = mvm_core::config::vm_state_dir_at(home.path(), "vm-a");
        std::fs::create_dir_all(&dir).expect("state dir");
        std::fs::write(dir.join("libkrun.pid"), std::process::id().to_string())
            .expect("pid marker");
        let live = evidence_for(home.path(), "vm-a", &binding, &opened.admitted);
        assert!(
            !live.cleanup_verified,
            "a VM still running has not been cleaned up, whatever the plan intended"
        );
    }

    #[test]
    fn attestation_is_never_asserted_without_a_provider() {
        let opened = open_against(bound_plan());
        let binding = opened.result.as_ref().expect("session opens").clone();
        let home = tempfile::tempdir().expect("tempdir");
        let evidence = evidence_for(home.path(), "vm-a", &binding, &opened.admitted);
        // Nothing attests today. The evaluator only consults this when the
        // plan demands attestation, so a Noop plan is unaffected and a
        // demanding one fails closed rather than being waved through.
        assert!(!evidence.attestation_verified);
    }

    #[test]
    fn the_collected_evidence_quotes_the_binding_not_the_declaration() {
        let opened = open_against(bound_plan());
        let binding = opened.result.as_ref().expect("session opens").clone();
        let home = tempfile::tempdir().expect("tempdir");
        let evidence = evidence_for(home.path(), "vm-a", &binding, &opened.admitted);

        assert_eq!(evidence.artifact_digest, binding.artifact_digest);
        assert_eq!(evidence.policy_digest, binding.effective_policy_digest);
        assert!(!evidence.receipt_refs.is_empty());
        assert!(!evidence.audit_refs.is_empty());
    }

    #[test]
    fn a_non_disposable_plan_is_reported_as_such() {
        let mut plan = bound_plan();
        plan.post_run.destroy_on_exit = false;
        let opened = open_against(plan);
        let binding = opened.result.as_ref().expect("session opens").clone();
        let home = tempfile::tempdir().expect("tempdir");
        let evidence = evidence_for(home.path(), "vm-a", &binding, &opened.admitted);
        assert!(!evidence.disposable_target);
    }

    #[test]
    fn evidence_from_a_real_session_still_evaluates_inconclusive_today() {
        // The honest end state: everything the host can attest is assembled,
        // and the trial is still INCONCLUSIVE because no observer ran. This
        // pins that the gap is the observer, not the plumbing.
        use mvm_contract::assurance::{
            EvaluationInputs, HostObservation, InconclusiveReason, TRIAL_RESULT_CANDIDATE_SCHEMA,
            TrialOutcome, TrialResultCandidate,
        };

        let opened = open_against(bound_plan());
        let binding = opened.result.as_ref().expect("session opens").clone();
        let home = tempfile::tempdir().expect("tempdir");
        let evidence = evidence_for(home.path(), "vm-a", &binding, &opened.admitted);

        let candidate = TrialResultCandidate {
            schema: TRIAL_RESULT_CANDIDATE_SCHEMA.to_string(),
            attempted_effect: true,
            effect_observed_in_guest: false,
            boundary_crossed: false,
            blocked_edges: Vec::new(),
            evidence_refs: Vec::new(),
            notes: String::new(),
        };
        let observation = HostObservation {
            attempted_effect: true,
            effect_observed_in_guest: false,
            boundary_crossed: false,
            blocked_edges: Vec::new(),
        };
        let verdict = mvm_contract::assurance::evaluate(EvaluationInputs {
            issued_binding: &binding,
            echoed_binding: Some(&binding),
            narrative_applicable: true,
            planned_source_digest: &Sha256Digest::parse(SOURCE_DIGEST).expect("digest"),
            candidate: &candidate,
            observation: &observation,
            evidence: &evidence,
        });
        assert_eq!(verdict.outcome, TrialOutcome::Inconclusive);
        assert_eq!(verdict.reason, Some(InconclusiveReason::ObserverMissing));
    }
}
