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
    AiSessionInput, ApprovalSet, AssuranceId, AssuranceSessionRequest, AuthorityCeiling,
    AuthorityInputs, EffectiveAuthority, EvaluationInputs, EvidenceIdentity, EvidenceRef,
    EvidenceSet, InconclusiveReason, MvmBinding, ObservationScope, RequestedAuthority,
    SessionGrant, SessionRef, Sha256Digest, ToolId, TrialEvidenceRecord, TrialOutcome,
    TrialResultCandidate, TrialResultDocument, TrialResultIdentity, TrialVerdict, evaluate,
    policy_digest_from_refs, probe_capability_descriptor,
};
use mvm_core::plan::ExecutionPlan;
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::protocol::broker::ServiceId;
use sha2::{Digest, Sha256};
use std::io::Write as _;

use crate::assurance_attestation::AttestationEvidence;
use crate::audit::assurance::{
    AssuranceAuditSink, AssuranceLedger, SessionIdentity, cite, identity_of,
};
use crate::audit::emitter::{AuditEmitter, write_atomic};
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignDeclaration {
    pub request_id: AssuranceId,
    pub idempotency_key: AssuranceId,
    pub campaign_id: AssuranceId,
    pub trial_id: AssuranceId,
    pub source_run_id: AssuranceId,
    pub source_digest: Sha256Digest,
    /// Exact workload artifact the operator authorized for this campaign.
    pub artifact_digest: Sha256Digest,
    /// Destinations the campaign may probe, by label.
    pub edges: Vec<DeclaredEdge>,
    /// Tools the operator explicitly approved.
    pub approvals: ApprovalSet,
    /// What the campaign asked for. Narrowed by every other bound.
    pub requested: RequestedAuthority,
    /// How long the session's grant is live.
    pub grant_ttl_ms: u64,
}

/// Signed-plan label that binds a run to the Scout source run.
pub const SOURCE_RUN_LABEL: &str = "assurance.source_run_id";
/// Signed-plan label that binds a run to the scanned source digest.
pub const SOURCE_DIGEST_LABEL: &str = "assurance.source_digest";
/// Largest operator declaration accepted from disk.
pub const MAX_DECLARATION_BYTES: u64 = 64 * 1024;
/// Most host-resolved labels one campaign may declare.
pub const MAX_DECLARED_EDGES: usize = 32;
/// Longest grant a declaration may request.
pub const MAX_GRANT_TTL_MS: u64 = 60 * 60 * 1_000;

/// Read and validate an operator-authored declaration.
pub fn load_declaration(path: &std::path::Path) -> Result<CampaignDeclaration> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading campaign declaration {}", path.display()))?;
    if metadata.len() > MAX_DECLARATION_BYTES {
        anyhow::bail!(
            "campaign declaration {} exceeds the {MAX_DECLARATION_BYTES}-byte limit",
            path.display()
        );
    }
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("reading campaign declaration {}", path.display()))?;
    let declaration: CampaignDeclaration = serde_json::from_str(&body)
        .with_context(|| format!("parsing campaign declaration {}", path.display()))?;
    validate_declaration(&declaration)?;
    Ok(declaration)
}

fn validate_declaration(declaration: &CampaignDeclaration) -> Result<()> {
    if declaration.edges.is_empty() || declaration.edges.len() > MAX_DECLARED_EDGES {
        anyhow::bail!("campaign declaration must name 1..={MAX_DECLARED_EDGES} destinations");
    }
    if declaration.grant_ttl_ms == 0 || declaration.grant_ttl_ms > MAX_GRANT_TTL_MS {
        anyhow::bail!("campaign grant TTL is outside the supported bounds");
    }
    let mut labels = std::collections::BTreeSet::new();
    for edge in &declaration.edges {
        if !labels.insert(edge.label.clone()) {
            anyhow::bail!(
                "campaign declaration repeats destination label {}",
                edge.label
            );
        }
        if edge.port == 0
            || edge.host.is_empty()
            || edge.host.len() > 253
            || edge.host.chars().any(char::is_control)
        {
            anyhow::bail!("campaign declaration contains an invalid destination");
        }
    }
    Ok(())
}

/// Why no session was opened.
#[derive(Debug, thiserror::Error)]
pub enum SessionRefusal {
    #[error("the admitted plan does not bind {HOST_ASSURANCE_SERVICE}")]
    ServiceNotBound,
    #[error("the admitted plan does not bind an extension providing the assurance probe")]
    ExtensionNotBound,
    #[error("this process holds no assurance plane")]
    NoPlane,
    #[error("the campaign declares no destination")]
    NoEdges,
    #[error("the admitted plan does not bind the campaign source identity")]
    SourceNotBound,
    #[error("the admitted plan does not require destruction of the trial target")]
    NonDisposableTarget,
    #[error("the provider request does not match the operator declaration: {0}")]
    RequestMismatch(&'static str),
    #[error("the requested artifact or policy identity does not match admission: {0}")]
    IdentityMismatch(&'static str),
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

/// Prepare the controller-owned assurance handler before the VM's resident
/// broker registration is created. Ordinary launches never call this path.
pub fn prepare_controller_proxy(
    vm: &str,
) -> Result<mvm_contract::protocol::broker_control::ServiceProxyBinding> {
    let plane = match host_assurance_plane() {
        Some(plane) => plane,
        None => {
            let candidate = Arc::new(HostAssuranceV1Handler::new());
            let _ = install_host_assurance_plane(candidate);
            host_assurance_plane().ok_or_else(|| {
                anyhow::anyhow!("failed to install the controller assurance plane")
            })?
        }
    };
    let handler: Arc<dyn mvm_core::protocol::handler::ServiceHandler> = plane;
    crate::broker::controller_proxy::prepare_controller_service(
        vm,
        handler,
        vec![HostAssuranceV1Handler::capability_descriptor()],
    )
}

static HOST_ASSURANCE_PLANE: OnceLock<Arc<HostAssuranceV1Handler>> = OnceLock::new();

/// Whether `plan` admits the assurance service at all.
#[must_use]
pub fn plan_binds_assurance(plan: &ExecutionPlan) -> bool {
    ServiceId::parse(HOST_ASSURANCE_SERVICE)
        .ok()
        .is_some_and(|service| plan.services.contains(&service))
}

fn plan_binds_assurance_extension(plan: &ExecutionPlan) -> bool {
    let binding = probe_capability_descriptor().binding();
    plan.extensions
        .iter()
        .flat_map(|extension| &extension.capabilities)
        .any(|admitted| admitted == &binding)
}

fn plan_binds_source(plan: &ExecutionPlan, declaration: &CampaignDeclaration) -> bool {
    plan.audit_labels
        .get(SOURCE_RUN_LABEL)
        .is_some_and(|value| value == declaration.source_run_id.as_str())
        && plan
            .audit_labels
            .get(SOURCE_DIGEST_LABEL)
            .is_some_and(|value| value == declaration.source_digest.as_str())
}

/// Derive this session's stable identifiers.
///
/// Content-addressed over the plan, the VM and the campaign rather than random:
/// re-opening the same campaign against the same admitted plan yields the same
/// session id, which makes a duplicate open visible instead of silently
/// producing a second session, and makes the whole path reproducible in a test.
pub(crate) fn derive_ids(
    plan_id: &str,
    vm: &str,
    decl: &CampaignDeclaration,
) -> (AssuranceId, AssuranceId) {
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
        hasher.update(
            serde_json::to_vec(tool).expect("closed assurance tool identifiers always encode"),
        );
    }
    for scope in &scopes {
        hasher.update(
            serde_json::to_vec(scope).expect("closed assurance observation scopes always encode"),
        );
    }
    hasher.update(decl.requested.max_steps.to_be_bytes());
    hasher.update(decl.requested.max_output_bytes.to_be_bytes());
    let grant_digest = Sha256Digest::from_bytes(&hasher.finalize().into());

    SessionGrant {
        grant_digest,
        expires_unix_ms,
        nonce,
        allowed_tools: tools,
        observation_scopes: scopes,
        max_steps: decl.requested.max_steps,
        max_output_bytes: decl.requested.max_output_bytes,
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
    if !plan_binds_assurance_extension(plan) {
        return Err(SessionRefusal::ExtensionNotBound);
    }
    if request.declaration.edges.is_empty() {
        return Err(SessionRefusal::NoEdges);
    }
    validate_declaration(request.declaration).map_err(|_| SessionRefusal::NoEdges)?;
    if !plan_binds_source(plan, request.declaration) {
        return Err(SessionRefusal::SourceNotBound);
    }
    if !plan.post_run.destroy_on_exit {
        return Err(SessionRefusal::NonDisposableTarget);
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
    let plan_identity = identity_of(plan);
    let ledger = AssuranceLedger::new(request.emitter.as_ref(), &plan_identity);
    let refs = ledger
        .open_session(&identity, &grant)
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
        session: SessionRef {
            request_id: request.declaration.request_id.clone(),
            idempotency_key: request.declaration.idempotency_key.clone(),
            source_run_id: request.declaration.source_run_id.clone(),
            campaign_id: request.declaration.campaign_id.clone(),
            trial_id: request.declaration.trial_id.clone(),
        },
        source_digest: request.declaration.source_digest.clone(),
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
        identity: plan_identity,
        sink: Some(Arc::clone(request.emitter) as Arc<dyn AssuranceAuditSink + Send + Sync>),
    });
    Ok(binding)
}

/// Open and assemble the exact prompt envelope delivered to an AI workload.
///
/// The provider half and operator declaration must agree before admission
/// facts are injected. The requested policy digest is then compared with the
/// digest derived from the admitted plan; disagreement refuses the session.
pub fn open_ai_session_on(
    plane: &Arc<HostAssuranceV1Handler>,
    provider: AssuranceSessionRequest,
    request: OpenSession<'_>,
) -> Result<AiSessionInput, SessionRefusal> {
    validate_ai_session_request(&provider, request.admitted, request.declaration)?;
    let workload_session_id = request.vm.to_string();
    let admitted = request.admitted;
    let declaration = request.declaration;
    open_on(plane, request)?;
    match bind_ai_session_on(plane, provider, &workload_session_id, admitted, declaration) {
        Ok(input) => Ok(input),
        Err(refusal) => {
            plane.close_session(&workload_session_id);
            Err(refusal)
        }
    }
}

/// Join a provider request to an assurance session opened by admitted boot.
///
/// The boot path opens the session only after the signed plan is admitted and
/// the VM is running. This helper adds the provider half without reopening or
/// replacing that host-owned session.
pub fn bind_ai_session_on(
    plane: &Arc<HostAssuranceV1Handler>,
    provider: AssuranceSessionRequest,
    vm: &str,
    admitted: &AdmittedPlan,
    declaration: &CampaignDeclaration,
) -> Result<AiSessionInput, SessionRefusal> {
    validate_ai_session_request(&provider, admitted, declaration)?;
    let binding = plane
        .binding_for(vm)
        .ok_or(SessionRefusal::RequestMismatch(
            "admitted session disappeared",
        ))?;
    let authority = plane
        .authority_for(vm)
        .ok_or(SessionRefusal::RequestMismatch(
            "admitted authority disappeared",
        ))?;
    AiSessionInput::bind(provider, &binding, &authority)
        .map_err(|_| SessionRefusal::RequestMismatch("input envelope"))
}

fn validate_ai_session_request(
    provider: &AssuranceSessionRequest,
    admitted: &AdmittedPlan,
    declaration: &CampaignDeclaration,
) -> Result<(), SessionRefusal> {
    provider
        .validate()
        .map_err(|_| SessionRefusal::RequestMismatch("invalid request"))?;
    if provider.session.request_id != declaration.request_id {
        return Err(SessionRefusal::RequestMismatch("request_id"));
    }
    if provider.session.idempotency_key != declaration.idempotency_key {
        return Err(SessionRefusal::RequestMismatch("idempotency_key"));
    }
    if provider.session.source_run_id != declaration.source_run_id {
        return Err(SessionRefusal::RequestMismatch("source_run_id"));
    }
    if provider.session.campaign_id != declaration.campaign_id {
        return Err(SessionRefusal::RequestMismatch("campaign_id"));
    }
    if provider.session.trial_id != declaration.trial_id {
        return Err(SessionRefusal::RequestMismatch("trial_id"));
    }
    if provider.source.source_digest != declaration.source_digest {
        return Err(SessionRefusal::RequestMismatch("source_digest"));
    }
    if provider.authority != declaration.requested {
        return Err(SessionRefusal::RequestMismatch("authority"));
    }
    let declared_labels: std::collections::BTreeSet<_> =
        declaration.edges.iter().map(|edge| &edge.label).collect();
    let requested_labels: std::collections::BTreeSet<_> = provider
        .synthetic_inputs
        .destination_labels
        .iter()
        .collect();
    if requested_labels != declared_labels {
        return Err(SessionRefusal::RequestMismatch("destination_labels"));
    }
    let admitted_artifact = Sha256Digest::parse(format!("sha256:{}", admitted.plan().image.sha256))
        .map_err(|error| SessionRefusal::Unbindable(error.to_string()))?;
    if declaration.artifact_digest != admitted_artifact {
        return Err(SessionRefusal::IdentityMismatch("artifact_digest"));
    }
    let admitted_policy = policy_digest(admitted.plan());
    if provider.source.requested_policy_digest != admitted_policy {
        return Err(SessionRefusal::IdentityMismatch("policy_digest"));
    }
    Ok(())
}

/// Ephemeral output of one generic extension invocation. Raw bytes never
/// enter durable session state; only their digests and the strict candidate
/// survive this call.
#[derive(Debug)]
pub enum AiSessionRun {
    /// The generic extension ran and returned an untrusted candidate.
    Executed(Box<ExecutedAiSessionRun>),
    /// A previous durable claim had no committed result, so MVM refused to
    /// execute it again and produced a signed inconclusive completion.
    RecoveredInterrupted {
        verdict: TrialVerdict,
        audit_ref: EvidenceRef,
        receipt_ref: EvidenceRef,
    },
}

/// Host-owned evidence produced by a fresh generic extension dispatch.
#[derive(Debug)]
pub struct ExecutedAiSessionRun {
    pub candidate: Option<TrialResultCandidate>,
    pub candidate_error: Option<String>,
    pub stdout_digest: Sha256Digest,
    pub stderr_digest: Sha256Digest,
    pub terminal: mvm_agentd::vsock::EntrypointEvent,
    pub observation: mvm_contract::assurance::HostObservation,
    pub probe_evidence_refs: Vec<EvidenceRef>,
    pub observer_audit_ref: EvidenceRef,
    pub observer_receipt_ref: EvidenceRef,
}

/// Deliver an admission-bound envelope to the generic extension that owns the
/// assurance probe capability.
pub fn dispatch_ai_session(
    vm: &str,
    admitted: &AdmittedPlan,
    declaration: &CampaignDeclaration,
    input: &AiSessionInput,
) -> Result<AiSessionRun> {
    let extension = admitted
        .extensions()
        .iter()
        .find(|extension| {
            extension
                .binding
                .capabilities
                .contains(&probe_capability_descriptor().binding())
        })
        .ok_or_else(|| anyhow::anyhow!("no admitted extension provides the assurance probe"))?;
    let plane = host_assurance_plane()
        .ok_or_else(|| anyhow::anyhow!("this process holds no assurance plane"))?;
    let binding = plane
        .binding_for(vm)
        .ok_or_else(|| anyhow::anyhow!("the assurance session is not open"))?;
    let now_unix_ms = HostAssuranceV1Handler::now_unix_ms();
    if !binding.grant.is_live_at(now_unix_ms) {
        anyhow::bail!("the assurance session grant is stale");
    }
    let payload = serde_json::to_vec(input).context("encoding AI session envelope")?;
    let payload_limit =
        usize::try_from(extension.binding.budgets.max_payload_bytes).expect("u32 fits in usize");
    if payload.len() > payload_limit {
        anyhow::bail!("AI session envelope exceeds admitted extension payload budget");
    }
    match claim_campaign_dispatch(
        &plane,
        vm,
        declaration,
        &binding,
        &extension.binding,
        &payload,
    )? {
        DispatchClaim::Fresh => {}
        DispatchClaim::Recovered {
            verdict,
            audit_ref,
            receipt_ref,
        } => {
            return Ok(AiSessionRun::RecoveredInterrupted {
                verdict,
                audit_ref,
                receipt_ref,
            });
        }
    }

    let transport = mvm_runtime::vsock_transport::for_vm(vm)
        .with_context(|| format!("selecting extension transport for {vm}"))?;
    let mut stream = transport
        .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
        .with_context(|| format!("connecting to the extension guest agent for {vm}"))?;
    let dispatch = mvm_agentd::vsock::ExtensionDispatch {
        extension_id: extension.binding.extension_id.clone(),
        pack_digest: extension.binding.pack_digest,
        contract_digest: extension.binding.contract_digest,
        request_id: declaration.request_id.clone(),
        session_id: binding.session_id.clone(),
        campaign_id: declaration.campaign_id.clone(),
        trial_id: declaration.trial_id.clone(),
        plan_id: binding.plan_id.clone(),
        idempotency_key: declaration.idempotency_key.clone(),
        grant_digest: binding.grant.grant_digest.clone(),
        nonce: binding.grant.nonce.clone(),
        input: payload,
    };
    let output_limit =
        usize::try_from(extension.binding.budgets.max_output_bytes).expect("u32 fits in usize");
    let mut stdout = Vec::new();
    let mut stdout_hasher = Sha256::new();
    let mut stderr_hasher = Sha256::new();
    let terminal =
        mvm_agentd::vsock::send_run_extension(&mut stream, dispatch, |event| match event {
            mvm_agentd::vsock::EntrypointEvent::Stdout { chunk } => {
                stdout_hasher.update(chunk);
                if stdout.len().saturating_add(chunk.len()) <= output_limit {
                    stdout.extend_from_slice(chunk);
                }
            }
            mvm_agentd::vsock::EntrypointEvent::Stderr { chunk } => stderr_hasher.update(chunk),
            _ => {}
        })
        .context("running admitted extension")?;
    let stdout_digest = Sha256Digest::from_bytes(&stdout_hasher.finalize().into());
    let stderr_digest = Sha256Digest::from_bytes(&stderr_hasher.finalize().into());
    let parsed = serde_json::from_slice::<TrialResultCandidate>(&stdout)
        .map_err(|error| format!("candidate response is not valid trial-result JSON: {error}"))
        .and_then(|candidate| {
            candidate
                .validate()
                .map_err(|error| format!("candidate response failed validation: {error}"))?;
            Ok(candidate)
        });
    let (candidate, candidate_error) = match parsed {
        Ok(candidate) => (Some(candidate), None),
        Err(error) => (None, Some(error)),
    };
    let identity = SessionIdentity {
        session_id: binding.session_id.clone(),
        campaign_id: declaration.campaign_id.clone(),
        trial_id: declaration.trial_id.clone(),
        source_digest: declaration.source_digest.clone(),
    };
    let observer = plane
        .finalize_observation(vm, &binding, &identity)
        .context("committing host observer evidence")?;
    Ok(AiSessionRun::Executed(Box::new(ExecutedAiSessionRun {
        candidate,
        candidate_error,
        stdout_digest,
        stderr_digest,
        terminal,
        observation: observer.observation,
        probe_evidence_refs: observer.probe_refs,
        observer_audit_ref: observer.audit_ref,
        observer_receipt_ref: observer.receipt_ref,
    })))
}

/// Cancel the exact active generic-extension invocation for this admitted
/// session. Cancellation carries identities only; it cannot select a PID,
/// signal, command, path, destination, or cleanup scope.
pub fn cancel_ai_session(
    vm: &str,
    admitted: &AdmittedPlan,
    declaration: &CampaignDeclaration,
) -> Result<CancellationEvidence> {
    let extension = admitted
        .extensions()
        .iter()
        .find(|extension| {
            extension
                .binding
                .capabilities
                .contains(&probe_capability_descriptor().binding())
        })
        .ok_or_else(|| anyhow::anyhow!("no admitted extension provides the assurance probe"))?;
    let plane = host_assurance_plane()
        .ok_or_else(|| anyhow::anyhow!("this process holds no assurance plane"))?;
    let binding = plane
        .binding_for(vm)
        .ok_or_else(|| anyhow::anyhow!("the assurance session is not open"))?;
    if binding.plan_id.as_str() != admitted.plan_id().0.replace(':', "-") {
        anyhow::bail!("the assurance cancellation plan identity does not match admission");
    }
    let session_ref = mvm_contract::assurance::SessionRef {
        request_id: declaration.request_id.clone(),
        idempotency_key: declaration.idempotency_key.clone(),
        source_run_id: declaration.source_run_id.clone(),
        campaign_id: declaration.campaign_id.clone(),
        trial_id: declaration.trial_id.clone(),
    };
    plane
        .verify_open_identity(vm, &binding, &session_ref, &declaration.source_digest)
        .context("joining cancellation to the open assurance session")?;
    verify_finalization_identity(&binding, admitted, declaration)
        .context("joining cancellation to signed admission")?;
    let cancellation = mvm_agentd::vsock::ExtensionCancellation {
        extension_id: extension.binding.extension_id.clone(),
        pack_digest: extension.binding.pack_digest,
        contract_digest: extension.binding.contract_digest,
        request_id: declaration.request_id.clone(),
        session_id: binding.session_id.clone(),
        campaign_id: declaration.campaign_id.clone(),
        trial_id: declaration.trial_id.clone(),
        plan_id: binding.plan_id.clone(),
        idempotency_key: declaration.idempotency_key.clone(),
        grant_digest: binding.grant.grant_digest.clone(),
        nonce: binding.grant.nonce.clone(),
    };
    let transport = mvm_runtime::vsock_transport::for_vm(vm)
        .with_context(|| format!("selecting extension transport for {vm}"))?;
    let mut stream = transport
        .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
        .with_context(|| format!("connecting to the extension guest agent for {vm}"))?;
    mvm_agentd::vsock::send_cancel_extension(&mut stream, cancellation)
        .context("canceling admitted extension")?;
    let identity = SessionIdentity {
        session_id: binding.session_id.clone(),
        campaign_id: declaration.campaign_id.clone(),
        trial_id: declaration.trial_id.clone(),
        source_digest: declaration.source_digest.clone(),
    };
    let refs = plane
        .record_cancellation(vm, &binding, &identity)
        .context("recording assurance cancellation")?;
    let receipt_ref = refs
        .receipt
        .ok_or_else(|| anyhow::anyhow!("cancellation produced no receipt"))?;
    Ok(CancellationEvidence {
        session_id: identity.session_id,
        campaign_id: identity.campaign_id,
        trial_id: identity.trial_id,
        source_digest: identity.source_digest,
        audit_ref: refs.audit,
        receipt_ref,
    })
}

/// Signed host evidence that the guest accepted cancellation for the exact
/// admitted extension invocation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationEvidence {
    pub session_id: AssuranceId,
    pub campaign_id: AssuranceId,
    pub trial_id: AssuranceId,
    pub source_digest: Sha256Digest,
    pub audit_ref: EvidenceRef,
    pub receipt_ref: EvidenceRef,
}

const DISPATCH_MARKER_SCHEMA: &str = "mvm.assurance.dispatch-marker/v1";
const MAX_DISPATCH_MARKER_BYTES: u64 = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchIdentity {
    session_id: AssuranceId,
    plan_id: AssuranceId,
    request_id: AssuranceId,
    source_run_id: AssuranceId,
    campaign_id: AssuranceId,
    trial_id: AssuranceId,
    idempotency_key: AssuranceId,
    source_digest: Sha256Digest,
    workload_digest: Sha256Digest,
    artifact_digest: Sha256Digest,
    policy_digest: Sha256Digest,
    grant_digest: Sha256Digest,
    grant_expires_unix_ms: u64,
    grant_nonce: AssuranceId,
    backend: AssuranceId,
    extension_id: mvm_contract::protocol::extension_pack::ExtensionId,
    pack_digest: Sha256Digest,
    contract_digest: Sha256Digest,
    payload_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum DispatchStatus {
    Claimed,
    RecoveredInterrupted {
        audit_ref: EvidenceRef,
        receipt_ref: EvidenceRef,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchMarker {
    schema: String,
    identity: DispatchIdentity,
    state: DispatchStatus,
}

#[derive(Debug)]
enum DispatchClaim {
    Fresh,
    Recovered {
        verdict: TrialVerdict,
        audit_ref: EvidenceRef,
        receipt_ref: EvidenceRef,
    },
}

fn claim_campaign_dispatch(
    plane: &Arc<HostAssuranceV1Handler>,
    vm: &str,
    declaration: &CampaignDeclaration,
    binding: &MvmBinding,
    extension: &mvm_contract::protocol::extension_pack::ExtensionPlanBinding,
    payload: &[u8],
) -> Result<DispatchClaim> {
    let mut key = Sha256::new();
    key.update(binding.plan_id.as_str().as_bytes());
    key.update([0]);
    key.update(declaration.idempotency_key.as_str().as_bytes());
    let key = hex::encode(key.finalize());
    let directory = mvm_core::config::vm_state_dir(vm).join("assurance-dispatch");
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("creating assurance dispatch state for {vm}"))?;
    let path = directory.join(format!("{key}.json"));
    let expected = DispatchIdentity {
        session_id: binding.session_id.clone(),
        plan_id: binding.plan_id.clone(),
        request_id: declaration.request_id.clone(),
        source_run_id: declaration.source_run_id.clone(),
        campaign_id: declaration.campaign_id.clone(),
        trial_id: declaration.trial_id.clone(),
        idempotency_key: declaration.idempotency_key.clone(),
        source_digest: declaration.source_digest.clone(),
        workload_digest: binding.workload_digest.clone(),
        artifact_digest: binding.artifact_digest.clone(),
        policy_digest: binding.effective_policy_digest.clone(),
        grant_digest: binding.grant.grant_digest.clone(),
        grant_expires_unix_ms: binding.grant.expires_unix_ms,
        grant_nonce: binding.grant.nonce.clone(),
        backend: binding.runtime.backend.clone(),
        extension_id: extension.extension_id.clone(),
        pack_digest: Sha256Digest::from_bytes(&extension.pack_digest),
        contract_digest: Sha256Digest::from_bytes(&extension.contract_digest),
        payload_digest: Sha256Digest::from_bytes(&Sha256::digest(payload).into()),
    };
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return recover_campaign_dispatch(plane, vm, &path, expected, binding);
        }
        Err(error) => return Err(error).context("creating assurance dispatch marker"),
    };
    let marker = DispatchMarker {
        schema: DISPATCH_MARKER_SCHEMA.to_string(),
        identity: expected,
        state: DispatchStatus::Claimed,
    };
    serde_json::to_writer(&mut file, &marker).context("writing assurance dispatch marker")?;
    file.write_all(b"\n")
        .context("terminating assurance dispatch marker")?;
    file.sync_all()
        .context("committing assurance dispatch marker")?;
    Ok(DispatchClaim::Fresh)
}

fn recover_campaign_dispatch(
    plane: &Arc<HostAssuranceV1Handler>,
    vm: &str,
    path: &std::path::Path,
    expected: DispatchIdentity,
    binding: &MvmBinding,
) -> Result<DispatchClaim> {
    let metadata = std::fs::metadata(path).context("reading assurance dispatch marker metadata")?;
    if metadata.len() > MAX_DISPATCH_MARKER_BYTES {
        anyhow::bail!("assurance dispatch marker exceeds its size limit");
    }
    let bytes = std::fs::read(path).context("reading assurance dispatch marker")?;
    let mut marker: DispatchMarker =
        serde_json::from_slice(&bytes).context("parsing assurance dispatch marker")?;
    if marker.schema != DISPATCH_MARKER_SCHEMA {
        anyhow::bail!("unsupported assurance dispatch marker schema");
    }
    if marker.identity != expected {
        anyhow::bail!("assurance dispatch marker identity does not match this request");
    }
    if let DispatchStatus::RecoveredInterrupted {
        audit_ref,
        receipt_ref,
    } = &marker.state
    {
        return Ok(DispatchClaim::Recovered {
            verdict: interrupted_verdict(),
            audit_ref: audit_ref.clone(),
            receipt_ref: receipt_ref.clone(),
        });
    }

    let identity = SessionIdentity {
        session_id: binding.session_id.clone(),
        campaign_id: marker.identity.campaign_id.clone(),
        trial_id: marker.identity.trial_id.clone(),
        source_digest: marker.identity.source_digest.clone(),
    };
    let verdict = interrupted_verdict();
    let refs = plane
        .complete_trial(vm, binding, &identity, &verdict)
        .context("recording interrupted assurance dispatch")?;
    let receipt_ref = refs
        .receipt
        .ok_or_else(|| anyhow::anyhow!("interrupted dispatch completion produced no receipt"))?;
    marker.state = DispatchStatus::RecoveredInterrupted {
        audit_ref: refs.audit.clone(),
        receipt_ref: receipt_ref.clone(),
    };
    let mut encoded = serde_json::to_vec(&marker).context("encoding recovered dispatch marker")?;
    encoded.push(b'\n');
    write_atomic(path, &encoded).context("committing recovered dispatch marker")?;
    Ok(DispatchClaim::Recovered {
        verdict,
        audit_ref: refs.audit,
        receipt_ref,
    })
}

fn interrupted_verdict() -> TrialVerdict {
    TrialVerdict {
        outcome: TrialOutcome::Inconclusive,
        reason: Some(InconclusiveReason::ExecutionInterrupted),
    }
}

/// Digest the policy references a campaign is evaluated under.
///
/// The plan carries policy by reference rather than by value, so this is a
/// digest over the exact references admitted — enough to detect that the policy
/// in force is not the one a campaign claims, which is what the evaluator's
/// mismatch check needs.
fn policy_digest(plan: &ExecutionPlan) -> Sha256Digest {
    policy_digest_from_refs(
        &plan.network_policy.0,
        &plan.egress_policy.0,
        &plan.fs_policy.0,
        &plan.tool_policy.0,
    )
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
    let plan_identity = identity_of(admitted.plan());
    AssuranceLedger::new(emitter, &plan_identity)
        .complete_trial(identity, verdict)
        .context("recording the trial outcome")?;
    Ok(())
}

/// Inputs required to turn an actual backend teardown into cleanup evidence.
pub struct CleanupRequest<'a> {
    pub plane: &'a Arc<HostAssuranceV1Handler>,
    pub backend: &'a mvm_runtime::AnyBackend,
    pub vm_id: &'a mvm_core::vm_backend::VmId,
    pub admitted: &'a AdmittedPlan,
    pub identity: &'a SessionIdentity,
}

/// Signed references proving the admitted disposable target was confirmed gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupEvidence {
    pub session_id: AssuranceId,
    pub campaign_id: AssuranceId,
    pub trial_id: AssuranceId,
    pub source_digest: Sha256Digest,
    pub audit_ref: EvidenceRef,
    pub receipt_ref: EvidenceRef,
}

/// Stop the exact admitted VM, read its backend state back, then sign cleanup.
///
/// Merely requesting teardown cannot construct [`CleanupEvidence`]. Failure to
/// stop, failure to read state, any identity mismatch, or any state other than
/// `Stopped` returns an error without a cleanup record.
pub fn stop_and_confirm_cleanup(request: CleanupRequest<'_>) -> Result<CleanupEvidence> {
    let binding = request
        .plane
        .binding_for(&request.vm_id.0)
        .ok_or_else(|| anyhow::anyhow!("the assurance session is not open"))?;
    let plan = request.admitted.plan();
    if !plan.post_run.destroy_on_exit {
        anyhow::bail!("the admitted assurance target is not disposable");
    }
    if binding.plan_id.as_str() != request.admitted.plan_id().0.replace(':', "-")
        || binding.workload_digest.as_str() != format!("sha256:{}", plan.image.sha256)
        || binding.runtime.backend.as_str() != request.backend.name()
        || binding.session_id != request.identity.session_id
    {
        anyhow::bail!("cleanup target does not match the admitted assurance session");
    }
    request
        .backend
        .stop(request.vm_id)
        .context("stopping the admitted assurance target")?;
    let status = request
        .backend
        .status(request.vm_id)
        .context("reading back assurance target state after teardown")?;
    if status != mvm_core::vm_backend::VmStatus::Stopped {
        anyhow::bail!("assurance target teardown was not confirmed");
    }
    let refs = request
        .plane
        .record_confirmed_cleanup(&request.vm_id.0, &binding, request.identity)
        .context("recording confirmed assurance cleanup")?;
    let receipt_ref = refs
        .receipt
        .ok_or_else(|| anyhow::anyhow!("cleanup completion produced no receipt"))?;
    Ok(CleanupEvidence {
        session_id: request.identity.session_id.clone(),
        campaign_id: request.identity.campaign_id.clone(),
        trial_id: request.identity.trial_id.clone(),
        source_digest: request.identity.source_digest.clone(),
        audit_ref: refs.audit,
        receipt_ref,
    })
}

/// Host-controlled inputs for final trial evidence assembly.
pub struct FinalizeTrial<'a> {
    pub plane: &'a Arc<HostAssuranceV1Handler>,
    pub vm: &'a str,
    pub admitted: &'a AdmittedPlan,
    pub declaration: &'a CampaignDeclaration,
    pub subject_revision: Option<&'a str>,
    pub run: &'a AiSessionRun,
    pub cancellation: Option<&'a CancellationEvidence>,
    pub cleanup: Option<&'a CleanupEvidence>,
    pub attestation: Option<&'a AttestationEvidence>,
    pub narrative_applicable: bool,
}

/// Host-derived completion artifacts returned to the controller provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedTrial {
    pub verdict: TrialVerdict,
    pub result: TrialResultDocument,
    pub evidence: TrialEvidenceRecord,
}

/// Derive and sign a trial result from host observer and cleanup evidence.
///
/// No verification boolean is accepted from a provider, extension, or model.
/// Attestation becomes true only when the trusted runtime-verifier path has
/// rejoined a fresh native quote and produced signed ledger references.
pub fn finalize_trial(request: FinalizeTrial<'_>) -> Result<FinalizedTrial> {
    let binding = request
        .plane
        .binding_for(request.vm)
        .ok_or_else(|| anyhow::anyhow!("the assurance session is not open"))?;
    let identity = SessionIdentity {
        session_id: binding.session_id.clone(),
        campaign_id: request.declaration.campaign_id.clone(),
        trial_id: request.declaration.trial_id.clone(),
        source_digest: request.declaration.source_digest.clone(),
    };
    verify_finalization_identity(&binding, request.admitted, request.declaration)?;

    let (observation, candidate, mut audit_refs, mut receipt_refs, recovered_verdict) =
        match request.run {
            AiSessionRun::Executed(executed) => {
                let mut audits = binding.audit_refs.clone();
                audits.extend(executed.probe_evidence_refs.iter().cloned());
                audits.push(executed.observer_audit_ref.clone());
                let mut receipts = binding.receipt_refs.clone();
                receipts.push(executed.observer_receipt_ref.clone());
                (
                    executed.observation.clone(),
                    executed.candidate.as_ref(),
                    audits,
                    receipts,
                    None,
                )
            }
            AiSessionRun::RecoveredInterrupted {
                verdict,
                audit_ref,
                receipt_ref,
            } => {
                let mut audits = binding.audit_refs.clone();
                audits.push(audit_ref.clone());
                let mut receipts = binding.receipt_refs.clone();
                receipts.push(receipt_ref.clone());
                (
                    mvm_contract::assurance::HostObservation {
                        attempted_effect: false,
                        effect_observed_in_guest: false,
                        boundary_crossed: false,
                        blocked_edges: Vec::new(),
                    },
                    None,
                    audits,
                    receipts,
                    Some(verdict.clone()),
                )
            }
        };

    let cleanup_verified = match request.cleanup {
        Some(cleanup)
            if cleanup.session_id == identity.session_id
                && cleanup.campaign_id == identity.campaign_id
                && cleanup.trial_id == identity.trial_id
                && cleanup.source_digest == identity.source_digest =>
        {
            audit_refs.push(cleanup.audit_ref.clone());
            receipt_refs.push(cleanup.receipt_ref.clone());
            true
        }
        Some(_) if matches!(request.run, AiSessionRun::Executed(_)) => {
            anyhow::bail!("cleanup evidence identity does not match the trial");
        }
        Some(_) | None => false,
    };

    if let Some(cancellation) = request.cancellation {
        if cancellation.session_id != identity.session_id
            || cancellation.campaign_id != identity.campaign_id
            || cancellation.trial_id != identity.trial_id
            || cancellation.source_digest != identity.source_digest
        {
            anyhow::bail!("cancellation evidence identity does not match the trial");
        }
        if !audit_refs.contains(&cancellation.audit_ref) {
            audit_refs.push(cancellation.audit_ref.clone());
        }
        if !receipt_refs.contains(&cancellation.receipt_ref) {
            receipt_refs.push(cancellation.receipt_ref.clone());
        }
    }

    let attestation_verified = match request.attestation {
        Some(attestation)
            if attestation.session_id == identity.session_id
                && attestation.campaign_id == identity.campaign_id
                && attestation.trial_id == identity.trial_id
                && attestation.source_digest == identity.source_digest =>
        {
            audit_refs.push(attestation.audit_ref.clone());
            receipt_refs.push(attestation.receipt_ref.clone());
            true
        }
        Some(_) => anyhow::bail!("attestation evidence identity does not match the trial"),
        None => false,
    };

    let observer_verified = matches!(request.run, AiSessionRun::Executed(_));
    let evidence_set = EvidenceSet {
        identity_verified: true,
        observer_verified,
        cleanup_verified,
        attestation_verified,
        disposable_target: request.admitted.plan().post_run.destroy_on_exit,
        artifact_digest: binding.artifact_digest.clone(),
        policy_digest: binding.effective_policy_digest.clone(),
        source_digest: request.declaration.source_digest.clone(),
        audit_refs: audit_refs.clone(),
        receipt_refs: receipt_refs.clone(),
    };
    let recovered = recovered_verdict.is_some();
    let verdict = match recovered_verdict {
        Some(verdict) => verdict,
        None => derive_executed_verdict(
            &binding,
            request.declaration,
            request.narrative_applicable,
            candidate,
            &observation,
            &evidence_set,
        ),
    };

    if !recovered {
        let refs = request
            .plane
            .complete_trial(request.vm, &binding, &identity, &verdict)
            .context("recording final assurance verdict")?;
        audit_refs.push(refs.audit);
        receipt_refs.push(
            refs.receipt
                .ok_or_else(|| anyhow::anyhow!("trial completion produced no receipt"))?,
        );
    }
    let completed_evidence = EvidenceSet {
        audit_refs,
        receipt_refs,
        ..evidence_set
    };
    let evidence = TrialEvidenceRecord::emit(
        EvidenceIdentity {
            campaign_id: &request.declaration.campaign_id,
            trial_id: &request.declaration.trial_id,
            source_run_id: &request.declaration.source_run_id,
            subject_revision: request.subject_revision,
        },
        &completed_evidence,
        &observation,
    );
    let result = TrialResultDocument::assemble(
        TrialResultIdentity {
            request_id: &request.declaration.request_id,
            source_run_id: &request.declaration.source_run_id,
            campaign_id: &request.declaration.campaign_id,
            trial_id: &request.declaration.trial_id,
            subject_revision: request.subject_revision,
        },
        &binding,
        &completed_evidence,
        &observation,
    );
    request.plane.close_session(request.vm);
    Ok(FinalizedTrial {
        verdict,
        result,
        evidence,
    })
}

fn derive_executed_verdict(
    binding: &MvmBinding,
    declaration: &CampaignDeclaration,
    narrative_applicable: bool,
    candidate: Option<&TrialResultCandidate>,
    observation: &mvm_contract::assurance::HostObservation,
    evidence: &EvidenceSet,
) -> TrialVerdict {
    let Some(candidate) = candidate else {
        return TrialVerdict {
            outcome: TrialOutcome::Inconclusive,
            reason: Some(InconclusiveReason::CandidateInvalid),
        };
    };
    if candidate.evidence_refs.iter().any(|reference| {
        !evidence.audit_refs.contains(reference) && !evidence.receipt_refs.contains(reference)
    }) {
        return TrialVerdict {
            outcome: TrialOutcome::Inconclusive,
            reason: Some(InconclusiveReason::CandidateDisagreement),
        };
    }
    evaluate(EvaluationInputs {
        issued_binding: binding,
        echoed_binding: Some(binding),
        narrative_applicable,
        planned_source_digest: &declaration.source_digest,
        candidate,
        observation,
        evidence,
    })
}

fn verify_finalization_identity(
    binding: &MvmBinding,
    admitted: &AdmittedPlan,
    declaration: &CampaignDeclaration,
) -> Result<()> {
    let plan = admitted.plan();
    if binding.plan_id.as_str() != admitted.plan_id().0.replace(':', "-") {
        anyhow::bail!("trial finalization plan identity does not match admission");
    }
    if binding.workload_digest.as_str() != format!("sha256:{}", plan.image.sha256) {
        anyhow::bail!("trial finalization workload identity does not match admission");
    }
    if binding.artifact_digest != declaration.artifact_digest {
        anyhow::bail!("trial finalization artifact identity does not match admission");
    }
    if declaration.source_digest.as_str()
        != plan
            .audit_labels
            .get(SOURCE_DIGEST_LABEL)
            .map_or("", String::as_str)
    {
        anyhow::bail!("trial finalization source identity does not match admission");
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    use mvm_contract::assurance::{InconclusiveReason, TrialOutcome};
    use mvm_contract::protocol::extension_pack::{
        ExtensionBudgets, ExtensionId, ExtensionPlacement, ExtensionPlanBinding, ExtensionVersion,
    };
    use mvm_core::plan::test_support::PlanFixture;

    const SOURCE_DIGEST: &str =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    const NOW_MS: u64 = 1_800_000_000_000;

    fn id(raw: &str) -> AssuranceId {
        AssuranceId::parse(raw).expect("identifier")
    }

    fn declaration() -> CampaignDeclaration {
        CampaignDeclaration {
            request_id: id("mvm-request-1"),
            idempotency_key: id("trial-retry-1"),
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
            source_run_id: id("scout-1"),
            source_digest: Sha256Digest::parse(SOURCE_DIGEST).expect("digest"),
            artifact_digest: Sha256Digest::parse(format!("sha256:{}", "a".repeat(64)))
                .expect("artifact digest"),
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
        let extension = ExtensionPlanBinding {
            extension_id: ExtensionId::parse("org.example.assurance-extension").expect("id"),
            version: ExtensionVersion::parse("1.0.0").expect("version"),
            pack_digest: [1; 32],
            contract_digest: [2; 32],
            placement: ExtensionPlacement::GuestWorkload,
            artifact: "extension.ext4".to_string(),
            entrypoint: "bin/assurance-extension".to_string(),
            capabilities: vec![probe_capability_descriptor().binding()],
            budgets: ExtensionBudgets {
                cpu_millis: 500,
                memory_bytes: 128 * 1024 * 1024,
                duration_ms: 600_000,
                max_steps: 12,
                max_concurrency: 1,
                max_payload_bytes: 16 * 1024,
                max_output_bytes: 16 * 1024,
                max_artifact_bytes: 1024 * 1024,
            },
        };
        PlanFixture::new()
            .services(vec![service])
            .extensions(vec![extension])
            .audit_labels(BTreeMap::from([
                (SOURCE_RUN_LABEL.to_string(), "scout-1".to_string()),
                (SOURCE_DIGEST_LABEL.to_string(), SOURCE_DIGEST.to_string()),
            ]))
            .build()
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
        let narrowed = mint_grant(&session, nonce.clone(), NOW_MS, &narrower);
        assert_ne!(grant.grant_digest, narrowed.grant_digest);

        let mut budgeted = declaration();
        budgeted.requested.max_steps -= 1;
        let budgeted = mint_grant(&session, nonce, NOW_MS, &budgeted);
        assert_ne!(grant.grant_digest, budgeted.grant_digest);
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
        TRIAL_RESULT_CANDIDATE_SCHEMA,
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
        open_against_backend(plan, "firecracker")
    }

    fn open_against_backend(plan: ExecutionPlan, backend: &str) -> Opened {
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
                backend,
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

    fn probe(binding: &MvmBinding) -> ProbeRequest {
        ProbeRequest {
            schema: PROBE_REQUEST_SCHEMA.to_string(),
            request_id: id("mvm-request-1"),
            session_id: binding.session_id.clone(),
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
            plan_id: binding.plan_id.clone(),
            campaign_idempotency_key: id("trial-retry-1"),
            session_grant_digest: binding.grant.grant_digest.clone(),
            session_grant_nonce: binding.grant.nonce.clone(),
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
    fn a_service_binding_without_an_admitted_extension_opens_nothing() {
        let service = ServiceId::parse(HOST_ASSURANCE_SERVICE).expect("service");
        let plan = PlanFixture::new()
            .services(vec![service])
            .audit_labels(BTreeMap::from([
                (SOURCE_RUN_LABEL.to_string(), "scout-1".to_string()),
                (SOURCE_DIGEST_LABEL.to_string(), SOURCE_DIGEST.to_string()),
            ]))
            .build();
        let opened = open_against(plan);
        assert!(matches!(
            opened.result,
            Err(SessionRefusal::ExtensionNotBound)
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
    fn a_non_disposable_plan_opens_no_assurance_session() {
        let mut plan = bound_plan();
        plan.post_run.destroy_on_exit = false;
        let opened = open_against(plan);
        assert!(matches!(
            opened.result,
            Err(SessionRefusal::NonDisposableTarget)
        ));
        assert!(opened.plane.binding_for("vm-a").is_none());
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
        let chain = chain_of(&opened);
        assert!(chain.contains("assurance.session_opened"));
        assert!(chain.contains(binding.grant.grant_digest.as_str()));
        assert!(chain.contains("assurance_grant_allowed_tools"));
    }

    #[tokio::test]
    async fn the_opened_session_is_the_one_the_probe_verb_dispatches_against() {
        // The point of this workstream: a probe reaches a session the admit
        // path opened, not one a test constructed by hand.
        let opened = open_against(bound_plan());
        let binding = opened.result.as_ref().expect("session opens").clone();

        let payload = serde_json::to_value(probe(&binding)).expect("payload");
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

        let mut request = probe(opened.plane.binding_for("vm-a").as_ref().expect("binding"));
        request.session_id = id("s-deadbeef");
        let payload = serde_json::to_value(request).expect("payload");
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

    #[test]
    fn dispatch_claim_is_durable_idempotent_and_stores_no_prompt_bytes() {
        let state = tempfile::tempdir().expect("state dir");
        let mut environment = mvm_core::util::test_env::TestEnv::new();
        environment.set("MVM_HOME", state.path());
        let opened = open_against(bound_plan());
        let binding = opened.result.as_ref().expect("session opens");
        let extension = opened
            .admitted
            .plan()
            .extensions
            .first()
            .expect("extension binding");
        let prompt = br#"{"objective":"SENSITIVE-PROMPT-BYTES"}"#;

        assert!(matches!(
            claim_campaign_dispatch(
                &opened.plane,
                "vm-a",
                &declaration(),
                binding,
                extension,
                prompt
            )
            .expect("first claim is committed"),
            DispatchClaim::Fresh
        ));
        let marker_dir = mvm_core::config::vm_state_dir("vm-a").join("assurance-dispatch");
        let markers = std::fs::read_dir(&marker_dir)
            .expect("marker directory")
            .collect::<std::io::Result<Vec<_>>>()
            .expect("marker entries");
        assert_eq!(markers.len(), 1);
        let durable = std::fs::read_to_string(markers[0].path()).expect("marker");
        assert!(durable.contains("payload_digest"));
        assert!(!durable.contains("SENSITIVE-PROMPT-BYTES"));
        let mut unknown: serde_json::Value = serde_json::from_str(&durable).expect("JSON marker");
        unknown
            .as_object_mut()
            .expect("marker object")
            .insert("untrusted".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<DispatchMarker>(unknown).is_err());

        let replay = claim_campaign_dispatch(
            &opened.plane,
            "vm-a",
            &declaration(),
            binding,
            extension,
            prompt,
        )
        .expect("a replay becomes an interrupted recovery result");
        let DispatchClaim::Recovered {
            verdict,
            audit_ref,
            receipt_ref,
        } = replay
        else {
            panic!("a durable claim must never execute twice");
        };
        assert_eq!(verdict.outcome, TrialOutcome::Inconclusive);
        assert_eq!(
            verdict.reason,
            Some(InconclusiveReason::ExecutionInterrupted)
        );
        assert!(audit_ref.as_str().starts_with("mvm:audit:"));
        assert!(receipt_ref.as_str().starts_with("mvm:receipt:"));
        let chain = chain_of(&opened);
        assert!(chain.contains("assurance.trial_completed"), "{chain}");
        assert!(chain.contains("execution_interrupted"), "{chain}");

        let chain_before_second_recovery = chain;
        let repeated = claim_campaign_dispatch(
            &opened.plane,
            "vm-a",
            &declaration(),
            binding,
            extension,
            prompt,
        )
        .expect("a committed recovery is idempotent");
        assert!(matches!(repeated, DispatchClaim::Recovered { .. }));
        assert_eq!(chain_of(&opened), chain_before_second_recovery);
    }

    #[test]
    fn dispatch_recovery_refuses_an_identity_mismatch_without_emitting_evidence() {
        let state = tempfile::tempdir().expect("state dir");
        let mut environment = mvm_core::util::test_env::TestEnv::new();
        environment.set("MVM_HOME", state.path());
        let opened = open_against(bound_plan());
        let binding = opened.result.as_ref().expect("session opens");
        let extension = opened
            .admitted
            .plan()
            .extensions
            .first()
            .expect("extension binding");
        let prompt = br#"{"objective":"bounded"}"#;
        claim_campaign_dispatch(
            &opened.plane,
            "vm-a",
            &declaration(),
            binding,
            extension,
            prompt,
        )
        .expect("first claim");
        let chain_before = chain_of(&opened);

        let mut mismatched = declaration();
        mismatched.source_digest =
            Sha256Digest::parse(format!("sha256:{}", "9".repeat(64))).expect("digest");
        let error = claim_campaign_dispatch(
            &opened.plane,
            "vm-a",
            &mismatched,
            binding,
            extension,
            prompt,
        )
        .expect_err("a marker from another identity must fail closed");
        assert!(
            error.to_string().contains("identity does not match"),
            "{error:#}"
        );
        assert_eq!(chain_of(&opened), chain_before);
    }

    #[test]
    fn cleanup_is_signed_only_after_the_exact_backend_confirms_the_vm_stopped() {
        let opened = open_against_backend(bound_plan(), "mock");
        let binding = opened.result.as_ref().expect("session opens");
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let vm_id = backend
            .start(&mvm_core::vm_backend::VmStartConfig {
                name: "vm-a".to_string(),
                rootfs_path: "/store/rootfs.ext4".to_string(),
                ..Default::default()
            })
            .expect("mock VM starts");
        assert_eq!(
            backend.status(&vm_id).expect("status"),
            mvm_core::vm_backend::VmStatus::Running
        );
        let identity = SessionIdentity {
            session_id: binding.session_id.clone(),
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
            source_digest: Sha256Digest::parse(SOURCE_DIGEST).expect("digest"),
        };

        let cleanup = stop_and_confirm_cleanup(CleanupRequest {
            plane: &opened.plane,
            backend: &backend,
            vm_id: &vm_id,
            admitted: &opened.admitted,
            identity: &identity,
        })
        .expect("stopped target produces cleanup evidence");

        assert_eq!(
            backend.status(&vm_id).expect("status"),
            mvm_core::vm_backend::VmStatus::Stopped
        );
        assert!(cleanup.audit_ref.as_str().starts_with("mvm:audit:"));
        assert!(cleanup.receipt_ref.as_str().starts_with("mvm:receipt:"));
        let chain = chain_of(&opened);
        assert!(chain.contains("assurance.cleanup_completed"), "{chain}");
        assert!(chain.contains("confirmed_stopped"), "{chain}");
    }

    #[test]
    fn cleanup_refuses_a_backend_identity_mismatch_before_stopping() {
        let opened = open_against(bound_plan());
        let binding = opened.result.as_ref().expect("session opens");
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let vm_id = backend
            .start(&mvm_core::vm_backend::VmStartConfig {
                name: "vm-a".to_string(),
                rootfs_path: "/store/rootfs.ext4".to_string(),
                ..Default::default()
            })
            .expect("mock VM starts");
        let identity = SessionIdentity {
            session_id: binding.session_id.clone(),
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
            source_digest: Sha256Digest::parse(SOURCE_DIGEST).expect("digest"),
        };

        let error = stop_and_confirm_cleanup(CleanupRequest {
            plane: &opened.plane,
            backend: &backend,
            vm_id: &vm_id,
            admitted: &opened.admitted,
            identity: &identity,
        })
        .expect_err("a foreign backend cannot produce cleanup evidence");

        assert!(error.to_string().contains("does not match"), "{error:#}");
        assert_eq!(
            backend.status(&vm_id).expect("status"),
            mvm_core::vm_backend::VmStatus::Running,
            "the mismatch is refused before teardown"
        );
        assert!(!chain_of(&opened).contains("assurance.cleanup_completed"));
        backend.stop(&vm_id).expect("test cleanup");
    }

    #[tokio::test]
    async fn final_evidence_is_host_assembled_from_observer_cleanup_and_signed_refs() {
        let opened = open_against_backend(bound_plan(), "mock");
        let binding = opened.result.as_ref().expect("session opens").clone();
        let payload = serde_json::to_value(probe(&binding)).expect("payload");
        opened
            .plane
            .dispatch(&ctx(), "probe", payload)
            .await
            .expect("probe runs");
        let identity = SessionIdentity {
            session_id: binding.session_id.clone(),
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
            source_digest: Sha256Digest::parse(SOURCE_DIGEST).expect("digest"),
        };
        let observer = opened
            .plane
            .finalize_observation("vm-a", &binding, &identity)
            .expect("observer commits");
        let candidate = TrialResultCandidate {
            schema: TRIAL_RESULT_CANDIDATE_SCHEMA.to_string(),
            attempted_effect: true,
            effect_observed_in_guest: false,
            boundary_crossed: false,
            blocked_edges: vec![id("undeclared.synthetic.destination")],
            evidence_refs: observer.probe_refs.clone(),
            notes: "synthetic edge was denied".to_string(),
        };
        let run = AiSessionRun::Executed(Box::new(ExecutedAiSessionRun {
            candidate: Some(candidate),
            candidate_error: None,
            stdout_digest: Sha256Digest::from_bytes(&[5; 32]),
            stderr_digest: Sha256Digest::from_bytes(&[6; 32]),
            terminal: mvm_agentd::vsock::EntrypointEvent::Exit { code: 0 },
            observation: observer.observation,
            probe_evidence_refs: observer.probe_refs,
            observer_audit_ref: observer.audit_ref,
            observer_receipt_ref: observer.receipt_ref,
        }));
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let vm_id = backend
            .start(&mvm_core::vm_backend::VmStartConfig {
                name: "vm-a".to_string(),
                rootfs_path: "/store/rootfs.ext4".to_string(),
                ..Default::default()
            })
            .expect("mock VM starts");
        let cleanup = stop_and_confirm_cleanup(CleanupRequest {
            plane: &opened.plane,
            backend: &backend,
            vm_id: &vm_id,
            admitted: &opened.admitted,
            identity: &identity,
        })
        .expect("cleanup confirms");

        let finalized = finalize_trial(FinalizeTrial {
            plane: &opened.plane,
            vm: "vm-a",
            admitted: &opened.admitted,
            declaration: &declaration(),
            subject_revision: Some("0123456789abcdef"),
            run: &run,
            cancellation: None,
            cleanup: Some(&cleanup),
            attestation: None,
            narrative_applicable: true,
        })
        .expect("trial finalizes");

        assert_eq!(finalized.verdict.outcome, TrialOutcome::Prevented);
        assert!(finalized.verdict.reason.is_none());
        assert!(finalized.result.identity_verified);
        assert!(finalized.result.observer_verified);
        assert!(finalized.result.cleanup_verified);
        assert!(!finalized.result.attestation_verified);
        assert!(finalized.evidence.identity_verified);
        assert!(finalized.evidence.observer_verified);
        assert!(finalized.evidence.cleanup_verified);
        assert!(
            finalized
                .evidence
                .evidence_refs
                .iter()
                .any(|reference| reference.as_str().starts_with("mvm:receipt:"))
        );
        assert!(opened.plane.binding_for("vm-a").is_none());
        let chain = chain_of(&opened);
        assert!(chain.contains("assurance.observer_completed"), "{chain}");
        assert!(chain.contains("assurance.cleanup_completed"), "{chain}");
        assert!(chain.contains("assurance.trial_completed"), "{chain}");
    }

    #[test]
    fn missing_cleanup_maps_to_inconclusive_instead_of_a_prevention_claim() {
        let opened = open_against(bound_plan());
        let binding = opened.result.as_ref().expect("session opens").clone();
        let observer = opened
            .plane
            .finalize_observation(
                "vm-a",
                &binding,
                &SessionIdentity {
                    session_id: binding.session_id.clone(),
                    campaign_id: id("mvm-campaign-1"),
                    trial_id: id("trial-1"),
                    source_digest: Sha256Digest::parse(SOURCE_DIGEST).expect("digest"),
                },
            )
            .expect("observer commits");
        let run = AiSessionRun::Executed(Box::new(ExecutedAiSessionRun {
            candidate: Some(TrialResultCandidate {
                schema: TRIAL_RESULT_CANDIDATE_SCHEMA.to_string(),
                attempted_effect: false,
                effect_observed_in_guest: false,
                boundary_crossed: false,
                blocked_edges: Vec::new(),
                evidence_refs: Vec::new(),
                notes: String::new(),
            }),
            candidate_error: None,
            stdout_digest: Sha256Digest::from_bytes(&[0; 32]),
            stderr_digest: Sha256Digest::from_bytes(&[0; 32]),
            terminal: mvm_agentd::vsock::EntrypointEvent::Exit { code: 0 },
            observation: observer.observation,
            probe_evidence_refs: observer.probe_refs,
            observer_audit_ref: observer.audit_ref,
            observer_receipt_ref: observer.receipt_ref,
        }));

        let finalized = finalize_trial(FinalizeTrial {
            plane: &opened.plane,
            vm: "vm-a",
            admitted: &opened.admitted,
            declaration: &declaration(),
            subject_revision: None,
            run: &run,
            cancellation: None,
            cleanup: None,
            attestation: None,
            narrative_applicable: true,
        })
        .expect("missing evidence still produces an explicit result");

        assert_eq!(finalized.verdict.outcome, TrialOutcome::Inconclusive);
        assert_eq!(
            finalized.verdict.reason,
            Some(InconclusiveReason::CleanupMissing)
        );
        assert!(!finalized.evidence.cleanup_verified);
    }

    #[test]
    fn recovered_dispatch_cannot_promote_unjoined_cleanup_evidence() {
        let opened = open_against(bound_plan());
        let audit_ref = EvidenceRef::parse("mvm:audit:interrupted").expect("audit reference");
        let receipt_ref = EvidenceRef::parse("mvm:receipt:interrupted").expect("receipt reference");
        let run = AiSessionRun::RecoveredInterrupted {
            verdict: interrupted_verdict(),
            audit_ref: audit_ref.clone(),
            receipt_ref: receipt_ref.clone(),
        };
        let cleanup = CleanupEvidence {
            session_id: id("foreign-session"),
            campaign_id: id("foreign-campaign"),
            trial_id: id("foreign-trial"),
            source_digest: Sha256Digest::from_bytes(&[9; 32]),
            audit_ref: EvidenceRef::parse("mvm:audit:foreign-cleanup")
                .expect("cleanup audit reference"),
            receipt_ref: EvidenceRef::parse("mvm:receipt:foreign-cleanup")
                .expect("cleanup receipt reference"),
        };

        let finalized = finalize_trial(FinalizeTrial {
            plane: &opened.plane,
            vm: "vm-a",
            admitted: &opened.admitted,
            declaration: &declaration(),
            subject_revision: None,
            run: &run,
            cancellation: None,
            cleanup: Some(&cleanup),
            attestation: None,
            narrative_applicable: true,
        })
        .expect("recovered dispatch remains explicitly inconclusive");

        assert_eq!(finalized.verdict.outcome, TrialOutcome::Inconclusive);
        assert_eq!(
            finalized.verdict.reason,
            Some(InconclusiveReason::ExecutionInterrupted)
        );
        assert!(!finalized.result.observer_verified);
        assert!(!finalized.result.cleanup_verified);
        assert!(!finalized.evidence.cleanup_verified);
        assert!(finalized.evidence.evidence_refs.contains(&audit_ref));
        assert!(finalized.evidence.evidence_refs.contains(&receipt_ref));
        assert!(
            !finalized
                .evidence
                .evidence_refs
                .contains(&cleanup.audit_ref)
        );
        assert!(
            !finalized
                .evidence
                .evidence_refs
                .contains(&cleanup.receipt_ref)
        );
    }

    #[test]
    fn cancellation_refs_are_joined_and_foreign_cancellation_is_refused() {
        let opened = open_against(bound_plan());
        let binding = opened.result.as_ref().expect("session opens").clone();
        let audit_ref = EvidenceRef::parse("mvm:audit:interrupted").expect("audit reference");
        let receipt_ref = EvidenceRef::parse("mvm:receipt:interrupted").expect("receipt reference");
        let run = AiSessionRun::RecoveredInterrupted {
            verdict: interrupted_verdict(),
            audit_ref,
            receipt_ref,
        };
        let cancellation = CancellationEvidence {
            session_id: binding.session_id.clone(),
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
            source_digest: Sha256Digest::parse(SOURCE_DIGEST).expect("source digest"),
            audit_ref: EvidenceRef::parse("mvm:audit:canceled").expect("cancel audit reference"),
            receipt_ref: EvidenceRef::parse("mvm:receipt:canceled")
                .expect("cancel receipt reference"),
        };

        let finalized = finalize_trial(FinalizeTrial {
            plane: &opened.plane,
            vm: "vm-a",
            admitted: &opened.admitted,
            declaration: &declaration(),
            subject_revision: None,
            run: &run,
            cancellation: Some(&cancellation),
            cleanup: None,
            attestation: None,
            narrative_applicable: true,
        })
        .expect("joined cancellation finalizes as interrupted");
        assert_eq!(finalized.verdict.outcome, TrialOutcome::Inconclusive);
        assert_eq!(
            finalized.verdict.reason,
            Some(InconclusiveReason::ExecutionInterrupted)
        );
        assert!(
            finalized
                .evidence
                .evidence_refs
                .contains(&cancellation.audit_ref)
        );
        assert!(
            finalized
                .evidence
                .evidence_refs
                .contains(&cancellation.receipt_ref)
        );

        let foreign = open_against(bound_plan());
        let foreign_run = AiSessionRun::RecoveredInterrupted {
            verdict: interrupted_verdict(),
            audit_ref: EvidenceRef::parse("mvm:audit:foreign-interrupted")
                .expect("audit reference"),
            receipt_ref: EvidenceRef::parse("mvm:receipt:foreign-interrupted")
                .expect("receipt reference"),
        };
        let mut mismatched = cancellation;
        mismatched.trial_id = id("trial-foreign");
        let error = finalize_trial(FinalizeTrial {
            plane: &foreign.plane,
            vm: "vm-a",
            admitted: &foreign.admitted,
            declaration: &declaration(),
            subject_revision: None,
            run: &foreign_run,
            cancellation: Some(&mismatched),
            cleanup: None,
            attestation: None,
            narrative_applicable: true,
        })
        .expect_err("foreign cancellation evidence must fail closed");
        assert!(
            error.to_string().contains("cancellation evidence identity"),
            "{error:#}"
        );
        assert!(foreign.plane.binding_for("vm-a").is_some());
    }

    #[test]
    fn operator_declaration_rejects_unknown_keys() {
        let directory = tempfile::tempdir().expect("declaration directory");
        let path = directory.path().join("campaign.json");
        let mut document = serde_json::to_value(declaration()).expect("declaration JSON");
        document
            .as_object_mut()
            .expect("declaration object")
            .insert("unexpected_authority".to_string(), serde_json::json!(true));
        std::fs::write(
            &path,
            serde_json::to_vec(&document).expect("encoded declaration"),
        )
        .expect("write declaration");

        let error = load_declaration(&path).expect_err("unknown declaration key must refuse");
        assert!(format!("{error:#}").contains("unexpected_authority"));
    }

    #[test]
    fn operator_declaration_rejects_oversized_documents_before_parsing() {
        let directory = tempfile::tempdir().expect("declaration directory");
        let path = directory.path().join("campaign.json");
        let body = vec![b' '; usize::try_from(MAX_DECLARATION_BYTES).expect("test bound") + 1];
        std::fs::write(&path, body).expect("write oversized declaration");

        let error = load_declaration(&path).expect_err("oversized declaration must refuse");
        assert!(error.to_string().contains("exceeds"));
    }
}
