//! Contract tests for the assurance session.
//!
//! The negative cases carry the weight here. Each one names a way a provider,
//! a model, or a missing piece of evidence could produce a result that looks
//! like proof and is not.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::plan::execution_plan::minimal_plan;

const ARTIFACT_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const POLICY_DIGEST: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const SOURCE_DIGEST: &str =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const GRANT_DIGEST: &str =
    "sha256:4444444444444444444444444444444444444444444444444444444444444444";

const NOW_MS: u64 = 1_000_000;
const EXPIRY_MS: u64 = 2_000_000;

fn id(raw: &str) -> AssuranceId {
    AssuranceId::parse(raw).expect("identifier")
}

fn digest(raw: &str) -> Sha256Digest {
    Sha256Digest::parse(raw).expect("digest")
}

fn evidence_ref(raw: &str) -> EvidenceRef {
    EvidenceRef::parse(raw).expect("evidence ref")
}

fn request_json() -> String {
    include_str!("../../fixtures/assurance-ai-session-request-v1.json").to_string()
}

fn request() -> AssuranceSessionRequest {
    AssuranceSessionRequest::parse_json(request_json().as_bytes()).expect("valid request")
}

fn grant() -> SessionGrant {
    SessionGrant {
        grant_digest: digest(GRANT_DIGEST),
        expires_unix_ms: EXPIRY_MS,
        nonce: id("nonce-1"),
        allowed_tools: vec![ToolId::CampaignProbeV1],
        observation_scopes: vec![
            ObservationScope::GuestStdoutDigest,
            ObservationScope::HostAuditRefs,
        ],
        max_steps: 12,
        max_output_bytes: 65_536,
    }
}

fn binding() -> MvmBinding {
    MvmBinding::builder()
        .session_id(id("session-1"))
        .plan(&minimal_plan())
        .expect("plan is bindable")
        .artifact_digest(digest(ARTIFACT_DIGEST))
        .effective_policy_digest(digest(POLICY_DIGEST))
        .grant(grant())
        .backend("firecracker")
        .audit_ref(evidence_ref("mvm:audit:entry-1"))
        .receipt_ref(evidence_ref("mvm:receipt:receipt-1"))
        .build()
        .expect("binding")
}

fn evidence() -> EvidenceSet {
    EvidenceSet {
        identity_verified: true,
        observer_verified: true,
        cleanup_verified: true,
        attestation_verified: false,
        disposable_target: true,
        artifact_digest: digest(ARTIFACT_DIGEST),
        policy_digest: digest(POLICY_DIGEST),
        source_digest: digest(SOURCE_DIGEST),
        audit_refs: vec![evidence_ref("mvm:audit:entry-1")],
        receipt_refs: vec![evidence_ref("mvm:receipt:receipt-1")],
    }
}

fn observation(attempted: bool, in_guest: bool, crossed: bool) -> HostObservation {
    HostObservation {
        attempted_effect: attempted,
        effect_observed_in_guest: in_guest,
        boundary_crossed: crossed,
        blocked_edges: vec![id("undeclared.synthetic.destination")],
    }
}

fn candidate(attempted: bool, in_guest: bool, crossed: bool) -> TrialResultCandidate {
    TrialResultCandidate {
        schema: TRIAL_RESULT_CANDIDATE_SCHEMA.to_string(),
        attempted_effect: attempted,
        effect_observed_in_guest: in_guest,
        boundary_crossed: crossed,
        blocked_edges: vec![id("undeclared.synthetic.destination")],
        evidence_refs: vec![evidence_ref("mvm:audit:entry-1")],
        notes: "probe refused at the substitution endpoint".to_string(),
    }
}

/// Evaluate with everything healthy except what the caller perturbs.
fn verdict_with(
    bound: &MvmBinding,
    evidence: &EvidenceSet,
    observation: &HostObservation,
    candidate: &TrialResultCandidate,
) -> TrialVerdict {
    evaluate(EvaluationInputs {
        issued_binding: bound,
        echoed_binding: Some(bound),
        narrative_applicable: true,
        planned_source_digest: &digest(SOURCE_DIGEST),
        candidate,
        observation,
        evidence,
    })
}

// ---------------------------------------------------------------------------
// Input contract
// ---------------------------------------------------------------------------

#[test]
fn the_documented_envelope_parses() {
    let parsed = request();
    assert_eq!(parsed.session.trial_id.as_str(), "trial-1");
    assert_eq!(parsed.source.severity, Severity::Critical);
    assert_eq!(parsed.source.subject_kind, SubjectKind::LocalRepository);
    assert_eq!(
        parsed.authority.allowed_tools,
        vec![ToolId::CampaignProbeV1]
    );
    assert_eq!(parsed.source.finding_id.as_str(), "SCOUT-RCE-001");
}

#[test]
fn a_provider_cannot_smuggle_an_mvm_binding_through_the_request_parser() {
    // This is the attack the two-type split exists to stop: a provider that
    // supplies its own admission facts.
    let forged = request_json().replace(
        "\"schema\": \"mvm.assurance.ai-session-request/v1\",",
        "\"schema\": \"mvm.assurance.ai-session-request/v1\",\n  \"mvm_binding\": {\"plan_id\": \"forged\"},",
    );
    let error = AssuranceSessionRequest::parse_json(forged.as_bytes())
        .expect_err("an mvm_binding key must be refused");
    match error {
        SessionInputError::Malformed(message) => {
            assert!(message.contains("mvm_binding"), "{message}");
        }
        other => panic!("expected a parse refusal, got {other:?}"),
    }
}

#[test]
fn an_unknown_field_anywhere_fails_closed() {
    let forged = request_json().replace(
        "\"max_steps\": 12,",
        "\"max_steps\": 12,\n    \"escalate\": true,",
    );
    assert!(matches!(
        AssuranceSessionRequest::parse_json(forged.as_bytes()),
        Err(SessionInputError::Malformed(_))
    ));
}

#[test]
fn an_incomplete_or_duplicated_output_contract_is_refused() {
    let missing = request_json().replace("      \"source_digest\",\n", "");
    assert_eq!(
        AssuranceSessionRequest::parse_json(missing.as_bytes()),
        Err(SessionInputError::FieldEmpty {
            field: "output_contract.required_fields"
        })
    );

    let duplicated = request_json().replace(
        "      \"source_digest\",",
        "      \"source_digest\",\n      \"source_digest\",",
    );
    assert_eq!(
        AssuranceSessionRequest::parse_json(duplicated.as_bytes()),
        Err(SessionInputError::OutOfRange {
            field: "output_contract.required_fields"
        })
    );
}

#[test]
fn an_oversized_body_is_refused_before_it_is_parsed() {
    let body = vec![b'x'; input::MAX_SESSION_INPUT_BYTES + 1];
    assert_eq!(
        AssuranceSessionRequest::parse_json(&body),
        Err(SessionInputError::TooLarge)
    );
}

#[test]
fn an_unsupported_schema_is_refused() {
    let forged = request_json().replace(
        "mvm.assurance.ai-session-request/v1",
        "mvm.assurance.ai-session-request/v2",
    );
    // The schema string appears twice; only the envelope's own matters here.
    let error = AssuranceSessionRequest::parse_json(forged.as_bytes()).expect_err("v2 is unknown");
    assert!(matches!(error, SessionInputError::UnsupportedSchema(_)));
}

#[test]
fn a_malformed_digest_is_refused() {
    let forged = request_json().replace(SOURCE_DIGEST, "sha256:not-hex");
    assert!(matches!(
        AssuranceSessionRequest::parse_json(forged.as_bytes()),
        Err(SessionInputError::Malformed(_))
    ));
}

#[test]
fn an_undeclared_tool_name_is_refused() {
    let forged = request_json().replace("campaign_probe.v1", "shell.v1");
    assert!(matches!(
        AssuranceSessionRequest::parse_json(forged.as_bytes()),
        Err(SessionInputError::Malformed(_))
    ));
}

#[test]
fn an_undeclared_observation_scope_is_refused() {
    let forged = request_json().replace("guest.stdout.digest", "host.filesystem.raw");
    assert!(matches!(
        AssuranceSessionRequest::parse_json(forged.as_bytes()),
        Err(SessionInputError::Malformed(_))
    ));
}

#[test]
fn budgets_outside_their_range_are_refused() {
    let zero_steps = request_json().replace("\"max_steps\": 12,", "\"max_steps\": 0,");
    assert_eq!(
        AssuranceSessionRequest::parse_json(zero_steps.as_bytes()),
        Err(SessionInputError::OutOfRange {
            field: "authority.max_steps"
        })
    );

    let huge_steps = request_json().replace("\"max_steps\": 12,", "\"max_steps\": 65,");
    assert_eq!(
        AssuranceSessionRequest::parse_json(huge_steps.as_bytes()),
        Err(SessionInputError::OutOfRange {
            field: "authority.max_steps"
        })
    );

    let huge_output = request_json().replace(
        "\"max_output_bytes\": 65536,",
        "\"max_output_bytes\": 2097152,",
    );
    assert_eq!(
        AssuranceSessionRequest::parse_json(huge_output.as_bytes()),
        Err(SessionInputError::OutOfRange {
            field: "authority.max_output_bytes"
        })
    );
}

#[test]
fn a_session_granted_no_tool_or_no_scope_is_refused() {
    let no_tools = request_json().replace("[\"campaign_probe.v1\"]", "[]");
    assert_eq!(
        AssuranceSessionRequest::parse_json(no_tools.as_bytes()),
        Err(SessionInputError::FieldEmpty {
            field: "authority.allowed_tools"
        })
    );

    let no_scopes = request_json().replace("[\"guest.stdout.digest\", \"host.audit.refs\"]", "[]");
    assert_eq!(
        AssuranceSessionRequest::parse_json(no_scopes.as_bytes()),
        Err(SessionInputError::FieldEmpty {
            field: "authority.observation_scopes"
        })
    );
}

#[test]
fn prose_carrying_a_control_character_is_refused() {
    let forged = request_json().replace(
        "attempt the declared process effect",
        "attempt the declared process effect\\u0000injected",
    );
    assert_eq!(
        AssuranceSessionRequest::parse_json(forged.as_bytes()),
        Err(SessionInputError::ControlCharacter {
            field: "narrative.objective"
        })
    );
}

#[test]
fn over_long_prose_is_refused() {
    let long = "a".repeat(input::MAX_PROSE_BYTES + 1);
    let forged = request_json().replace("attempt the declared process effect", &long);
    assert_eq!(
        AssuranceSessionRequest::parse_json(forged.as_bytes()),
        Err(SessionInputError::FieldTooLong {
            field: "narrative.objective"
        })
    );
}

#[test]
fn too_many_evidence_refs_are_refused() {
    let many: Vec<String> = (0..input::MAX_EVIDENCE_REFS + 1)
        .map(|index| alloc::format!("\"scout:finding:F{index}\""))
        .collect();
    let forged = request_json().replace(
        "[\"scout:finding:SCOUT-RCE-001\"]",
        &alloc::format!("[{}]", many.join(",")),
    );
    assert_eq!(
        AssuranceSessionRequest::parse_json(forged.as_bytes()),
        Err(SessionInputError::TooManyElements {
            field: "source.evidence_refs"
        })
    );
}

// ---------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------

#[test]
fn the_binding_quotes_the_admitted_plan_rather_than_the_request() {
    let plan = minimal_plan();
    let bound = binding();
    assert_eq!(bound.plan_id.as_str(), plan.plan_id.0);
    // A real plan id is `sha256:<hex>`; the separator is rendered so the value
    // survives the counterparty's identifier grammar.
    let mut real = minimal_plan();
    real.plan_id = crate::plan::types::PlanId(alloc::format!("sha256:{}", "ab".repeat(32)));
    let bound_real = MvmBinding::builder()
        .session_id(id("session-1"))
        .plan(&real)
        .expect("a content-addressed plan id is bindable")
        .artifact_digest(digest(ARTIFACT_DIGEST))
        .effective_policy_digest(digest(POLICY_DIGEST))
        .grant(grant())
        .backend("firecracker")
        .audit_ref(evidence_ref("mvm:audit:a"))
        .receipt_ref(evidence_ref("mvm:receipt:r"))
        .build()
        .expect("binding");
    assert_eq!(
        bound_real.plan_id.as_str(),
        alloc::format!("sha256-{}", "ab".repeat(32))
    );
    assert_eq!(bound.plan_version, plan.plan_version);
    assert_eq!(bound.tenant, plan.tenant.0);
    assert_eq!(bound.workload, plan.workload.0);
    assert_eq!(
        bound.workload_digest,
        digest(&alloc::format!("sha256:{}", plan.image.sha256))
    );
    assert_eq!(bound.runtime.runtime_profile, plan.runtime_profile.0);
    // The fixture plan attests Noop, so attestation evidence is not required.
    assert!(!bound.attestation_required);
}

#[test]
fn a_binding_without_a_plan_cannot_be_built() {
    let error = MvmBinding::builder()
        .session_id(id("session-1"))
        .artifact_digest(digest(ARTIFACT_DIGEST))
        .effective_policy_digest(digest(POLICY_DIGEST))
        .grant(grant())
        .backend("firecracker")
        .audit_ref(evidence_ref("mvm:audit:entry-1"))
        .receipt_ref(evidence_ref("mvm:receipt:receipt-1"))
        .build()
        .expect_err("no plan means no binding");
    assert_eq!(error, BindingError::MissingField("admitted plan"));
}

#[test]
fn a_binding_citing_no_audit_or_receipt_is_refused() {
    let base = || {
        MvmBinding::builder()
            .session_id(id("session-1"))
            .plan(&minimal_plan())
            .expect("plan")
            .artifact_digest(digest(ARTIFACT_DIGEST))
            .effective_policy_digest(digest(POLICY_DIGEST))
            .grant(grant())
            .backend("firecracker")
    };
    assert_eq!(
        base()
            .receipt_ref(evidence_ref("mvm:receipt:r"))
            .build()
            .expect_err("no audit ref"),
        BindingError::NoAuditReference
    );
    assert_eq!(
        base()
            .audit_ref(evidence_ref("mvm:audit:a"))
            .build()
            .expect_err("no receipt ref"),
        BindingError::NoReceiptReference
    );
}

#[test]
fn a_plan_requiring_attestation_marks_the_binding() {
    let mut plan = minimal_plan();
    plan.attestation.mode = crate::plan::types::AttestationMode::Tpm2;
    let bound = MvmBinding::builder()
        .session_id(id("session-1"))
        .plan(&plan)
        .expect("plan")
        .artifact_digest(digest(ARTIFACT_DIGEST))
        .effective_policy_digest(digest(POLICY_DIGEST))
        .grant(grant())
        .backend("firecracker")
        .audit_ref(evidence_ref("mvm:audit:a"))
        .receipt_ref(evidence_ref("mvm:receipt:r"))
        .build()
        .expect("binding");
    assert!(bound.attestation_required);
}

fn effective_for_envelope() -> EffectiveAuthority {
    let ceiling = AuthorityCeiling::extension_maximum();
    let parsed = request();
    let approvals = ApprovalSet::none().with(ToolId::CampaignProbeV1);
    EffectiveAuthority::intersect(
        AuthorityInputs {
            extension_maximum: &ceiling,
            requested: &parsed.authority,
            policy_ceiling: &ceiling,
            grant: &grant(),
            approvals: &approvals,
        },
        NOW_MS,
    )
    .expect("authority")
}

fn keys_of(value: &serde_json::Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().expect("object").keys().cloned().collect();
    keys.sort();
    keys
}

fn sorted(names: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = names.iter().map(|name| name.to_string()).collect();
    out.sort();
    out
}

#[test]
fn the_envelope_matches_the_counterparty_key_set_exactly() {
    // The counterparty validates with exact key sets, so an extra key is a
    // hard failure at the far end rather than something it ignores. These
    // lists mirror `apps/mvm-security/src/ai_session.rs`.
    let envelope =
        AiSessionInput::bind(request(), &binding(), &effective_for_envelope()).expect("envelope");
    let value: serde_json::Value =
        serde_json::from_str(&envelope.to_json().expect("encode")).expect("parse");

    assert_eq!(value["schema"], AI_SESSION_INPUT_SCHEMA);

    assert_eq!(
        keys_of(&value),
        sorted(&[
            "schema",
            "session",
            "source",
            "narrative",
            "authority",
            "synthetic_inputs",
            "output_contract",
            "mvm_binding",
        ])
    );
    assert_eq!(
        keys_of(&value["session"]),
        sorted(&[
            "request_id",
            "idempotency_key",
            "source_run_id",
            "campaign_id",
            "trial_id",
        ])
    );
    assert_eq!(
        keys_of(&value["mvm_binding"]),
        sorted(&[
            "session_id",
            "plan_id",
            "workload_digest",
            "artifact_digest",
            "effective_policy_digest",
            "session_grant_digest",
            "expires_at_unix_ms",
            "nonce",
            "allowed_tools",
            "backend",
        ])
    );
    assert_eq!(
        keys_of(&value["authority"]),
        sorted(&[
            "allowed_tools",
            "observation_scopes",
            "max_steps",
            "max_output_bytes",
            "deadline_unix_ms",
        ])
    );
    assert_eq!(
        keys_of(&value["source"]),
        sorted(&[
            "subject_kind",
            "subject_locator",
            "subject_revision",
            "source_digest",
            "finding_id",
            "group_id",
            "rule_id",
            "category",
            "severity",
            "location",
            "evidence_refs",
            "artifact_locator",
            "requested_policy_digest",
        ])
    );
    assert_eq!(
        keys_of(&value["output_contract"]),
        sorted(&["kind", "required_fields"])
    );
}

#[test]
fn the_envelope_reports_effective_authority_and_a_real_deadline() {
    // The request carried `deadline_unix_ms: 0` meaning "none set". The
    // counterparty requires >= 1, so a raw copy would be refused.
    let envelope =
        AiSessionInput::bind(request(), &binding(), &effective_for_envelope()).expect("envelope");
    assert_eq!(request().authority.deadline_unix_ms, 0);
    assert_eq!(envelope.authority().deadline_unix_ms, EXPIRY_MS);
    assert!(envelope.authority().deadline_unix_ms >= 1);
}

#[test]
fn the_envelope_carries_the_admitted_plan_and_no_synthetic_values() {
    let envelope =
        AiSessionInput::bind(request(), &binding(), &effective_for_envelope()).expect("envelope");
    let json = envelope.to_json().expect("encode");

    assert!(json.contains(&minimal_plan().plan_id.0), "{json}");
    assert!(json.contains("SCOUT-RCE-001"), "{json}");
    // Canary identifiers cross; canary values do not exist in this type at all.
    assert!(json.contains("canary.synthetic.secret.1"), "{json}");
    assert_eq!(envelope.binding().session_id.as_str(), "session-1");
    assert_eq!(envelope.session().campaign_id.as_str(), "mvm-campaign-1");
    assert_eq!(envelope.source().source_digest.as_str(), SOURCE_DIGEST);
    // The grant is referenced by digest; the grant document never crosses.
    assert!(json.contains("session_grant_digest"), "{json}");
}

#[test]
fn the_assembled_trial_result_matches_the_counterparty_key_set_exactly() {
    let bound = binding();
    let document = TrialResultDocument::assemble(
        TrialResultIdentity {
            request_id: &id("mvm-request-1"),
            source_run_id: &id("scout-1"),
            campaign_id: &id("mvm-campaign-1"),
            trial_id: &id("trial-1"),
            subject_revision: Some("0123456789abcdef"),
        },
        &bound,
        &evidence(),
        &observation(true, false, false),
    );
    let value = serde_json::to_value(&document).expect("serialize");

    assert_eq!(
        keys_of(&value),
        sorted(&[
            "schema",
            "session",
            "subject_revision",
            "source_digest",
            "artifact_digest",
            "policy_digest",
            "disposable_target",
            "identity_verified",
            "observer_verified",
            "cleanup_verified",
            "attestation_verified",
            "attempted_effect",
            "effect_observed_in_guest",
            "boundary_crossed",
            "blocked_edges",
            "evidence_refs",
            "receipt_refs",
            "audit_refs",
        ])
    );
    assert_eq!(
        keys_of(&value["session"]),
        sorted(&[
            "session_id",
            "request_id",
            "source_run_id",
            "campaign_id",
            "trial_id",
            "plan_id",
        ])
    );
    assert_eq!(value["schema"], TRIAL_RESULT_SCHEMA);
    // No outcome field: the counterparty derives the verdict, and this record
    // cannot short-circuit it.
    assert!(value.get("outcome").is_none());
}

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

fn permissive_ceiling() -> AuthorityCeiling {
    AuthorityCeiling::extension_maximum()
}

fn intersect(
    policy_ceiling: &AuthorityCeiling,
    grant: &SessionGrant,
    approvals: &ApprovalSet,
    now: u64,
) -> Result<EffectiveAuthority, AuthorityError> {
    let extension = AuthorityCeiling::extension_maximum();
    let parsed = request();
    EffectiveAuthority::intersect(
        AuthorityInputs {
            extension_maximum: &extension,
            requested: &parsed.authority,
            policy_ceiling,
            grant,
            approvals,
        },
        now,
    )
}

#[test]
fn effective_authority_is_the_intersection_and_takes_the_lowest_budget() {
    let mut ceiling = permissive_ceiling();
    ceiling.max_steps = 4;
    ceiling.max_output_bytes = 1024;
    let approvals = ApprovalSet::none().with(ToolId::CampaignProbeV1);

    let effective = intersect(&ceiling, &grant(), &approvals, NOW_MS).expect("authority");
    assert!(effective.permits_tool(ToolId::CampaignProbeV1));
    assert_eq!(effective.max_steps(), 4, "the ceiling, not the request");
    assert_eq!(effective.max_output_bytes(), 1024);
    // The request set no deadline, so the grant expiry becomes the bound.
    assert_eq!(effective.deadline_unix_ms(), EXPIRY_MS);
}

#[test]
fn the_short_lived_grant_can_narrow_step_and_output_budgets() {
    let mut narrow_grant = grant();
    narrow_grant.max_steps = 3;
    narrow_grant.max_output_bytes = 768;
    let approvals = ApprovalSet::none().with(ToolId::CampaignProbeV1);

    let effective = intersect(&permissive_ceiling(), &narrow_grant, &approvals, NOW_MS)
        .expect("narrow grant remains usable");
    assert_eq!(effective.max_steps(), 3);
    assert_eq!(effective.max_output_bytes(), 768);
}

#[test]
fn a_tool_the_policy_ceiling_omits_does_not_survive() {
    let mut ceiling = permissive_ceiling();
    ceiling.tools.clear();
    let approvals = ApprovalSet::none().with(ToolId::CampaignProbeV1);
    assert_eq!(
        intersect(&ceiling, &grant(), &approvals, NOW_MS),
        Err(AuthorityError::NoToolsRemain)
    );
}

#[test]
fn a_tool_the_grant_omits_does_not_survive() {
    let mut grant = grant();
    grant.allowed_tools.clear();
    let approvals = ApprovalSet::none().with(ToolId::CampaignProbeV1);
    assert_eq!(
        intersect(&permissive_ceiling(), &grant, &approvals, NOW_MS),
        Err(AuthorityError::NoToolsRemain)
    );
}

#[test]
fn a_campaign_probe_without_explicit_approval_does_not_survive() {
    assert!(ToolId::CampaignProbeV1.requires_explicit_approval());
    assert_eq!(
        intersect(
            &permissive_ceiling(),
            &grant(),
            &ApprovalSet::none(),
            NOW_MS
        ),
        Err(AuthorityError::NoToolsRemain)
    );
}

#[test]
fn a_scope_the_grant_omits_does_not_survive() {
    let mut grant = grant();
    grant.observation_scopes.clear();
    let approvals = ApprovalSet::none().with(ToolId::CampaignProbeV1);
    assert_eq!(
        intersect(&permissive_ceiling(), &grant, &approvals, NOW_MS),
        Err(AuthorityError::NoScopesRemain)
    );
}

#[test]
fn an_expired_grant_refuses_before_anything_else_is_considered() {
    let approvals = ApprovalSet::none().with(ToolId::CampaignProbeV1);
    assert_eq!(
        intersect(&permissive_ceiling(), &grant(), &approvals, EXPIRY_MS),
        Err(AuthorityError::GrantExpired),
        "expiry is exclusive: landing exactly on the boundary is refused"
    );
    assert_eq!(
        intersect(&permissive_ceiling(), &grant(), &approvals, EXPIRY_MS + 1),
        Err(AuthorityError::GrantExpired)
    );
}

#[test]
fn a_requested_deadline_earlier_than_the_grant_wins() {
    let extension = AuthorityCeiling::extension_maximum();
    let mut parsed = request();
    parsed.authority.deadline_unix_ms = EXPIRY_MS - 500;
    let approvals = ApprovalSet::none().with(ToolId::CampaignProbeV1);
    let effective = EffectiveAuthority::intersect(
        AuthorityInputs {
            extension_maximum: &extension,
            requested: &parsed.authority,
            policy_ceiling: &extension,
            grant: &grant(),
            approvals: &approvals,
        },
        NOW_MS,
    )
    .expect("authority");
    assert_eq!(effective.deadline_unix_ms(), EXPIRY_MS - 500);
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

#[test]
fn a_denied_effect_with_complete_evidence_is_prevented() {
    let verdict = verdict_with(
        &binding(),
        &evidence(),
        &observation(true, false, false),
        &candidate(true, false, false),
    );
    assert_eq!(verdict.outcome, TrialOutcome::Prevented);
    assert_eq!(verdict.reason, None);
    assert!(verdict.outcome.is_certifying_claim());
}

#[test]
fn an_effect_that_stayed_inside_the_boundary_is_contained() {
    let verdict = verdict_with(
        &binding(),
        &evidence(),
        &observation(true, true, false),
        &candidate(true, true, false),
    );
    assert_eq!(verdict.outcome, TrialOutcome::Contained);
}

#[test]
fn an_effect_that_crossed_the_boundary_is_observed_and_is_not_a_claim() {
    let verdict = verdict_with(
        &binding(),
        &evidence(),
        &observation(true, true, true),
        &candidate(true, true, true),
    );
    assert_eq!(verdict.outcome, TrialOutcome::Observed);
    assert!(!verdict.outcome.is_certifying_claim());
}

#[test]
fn a_model_claiming_prevention_against_the_observer_gets_inconclusive() {
    // The observer saw the effect cross. The model reports a clean block.
    let verdict = verdict_with(
        &binding(),
        &evidence(),
        &observation(true, true, true),
        &candidate(true, false, false),
    );
    assert_eq!(verdict.outcome, TrialOutcome::Inconclusive);
    assert_eq!(
        verdict.reason,
        Some(InconclusiveReason::CandidateDisagreement)
    );
}

#[test]
fn each_missing_piece_of_evidence_produces_its_own_inconclusive_reason() {
    let cases: Vec<(&str, EvidenceSet, InconclusiveReason)> = vec![
        (
            "identity",
            EvidenceSet {
                identity_verified: false,
                ..evidence()
            },
            InconclusiveReason::IdentityUnverified,
        ),
        (
            "artifact",
            EvidenceSet {
                artifact_digest: digest(GRANT_DIGEST),
                ..evidence()
            },
            InconclusiveReason::ArtifactMismatch,
        ),
        (
            "policy",
            EvidenceSet {
                policy_digest: digest(GRANT_DIGEST),
                ..evidence()
            },
            InconclusiveReason::PolicyMismatch,
        ),
        (
            "source",
            EvidenceSet {
                source_digest: digest(GRANT_DIGEST),
                ..evidence()
            },
            InconclusiveReason::SourceMismatch,
        ),
        (
            "disposable",
            EvidenceSet {
                disposable_target: false,
                ..evidence()
            },
            InconclusiveReason::NonDisposableTarget,
        ),
        (
            "observer",
            EvidenceSet {
                observer_verified: false,
                ..evidence()
            },
            InconclusiveReason::ObserverMissing,
        ),
        (
            "cleanup",
            EvidenceSet {
                cleanup_verified: false,
                ..evidence()
            },
            InconclusiveReason::CleanupMissing,
        ),
        (
            "receipt",
            EvidenceSet {
                receipt_refs: Vec::new(),
                ..evidence()
            },
            InconclusiveReason::ReceiptMissing,
        ),
        (
            "audit",
            EvidenceSet {
                audit_refs: Vec::new(),
                ..evidence()
            },
            InconclusiveReason::AuditMissing,
        ),
    ];

    for (label, perturbed, expected) in cases {
        let verdict = verdict_with(
            &binding(),
            &perturbed,
            &observation(true, false, false),
            &candidate(true, false, false),
        );
        assert_eq!(
            verdict.outcome,
            TrialOutcome::Inconclusive,
            "{label} should not certify"
        );
        assert_eq!(verdict.reason, Some(expected), "{label}");
    }
}

#[test]
fn a_plan_requiring_attestation_is_inconclusive_without_it() {
    let mut plan = minimal_plan();
    plan.attestation.mode = crate::plan::types::AttestationMode::Tpm2;
    let bound = MvmBinding::builder()
        .session_id(id("session-1"))
        .plan(&plan)
        .expect("plan")
        .artifact_digest(digest(ARTIFACT_DIGEST))
        .effective_policy_digest(digest(POLICY_DIGEST))
        .grant(grant())
        .backend("firecracker")
        .audit_ref(evidence_ref("mvm:audit:a"))
        .receipt_ref(evidence_ref("mvm:receipt:r"))
        .build()
        .expect("binding");

    let verdict = verdict_with(
        &bound,
        &evidence(),
        &observation(true, false, false),
        &candidate(true, false, false),
    );
    assert_eq!(verdict.reason, Some(InconclusiveReason::AttestationMissing));

    let attested = EvidenceSet {
        attestation_verified: true,
        ..evidence()
    };
    let verdict = verdict_with(
        &bound,
        &attested,
        &observation(true, false, false),
        &candidate(true, false, false),
    );
    assert_eq!(verdict.outcome, TrialOutcome::Prevented);
}

#[test]
fn a_mismatched_or_absent_echoed_binding_is_inconclusive() {
    let issued = binding();
    let mut other = binding();
    other.session_id = id("session-2");

    for echoed in [None, Some(&other)] {
        let verdict = evaluate(EvaluationInputs {
            issued_binding: &issued,
            echoed_binding: echoed,
            narrative_applicable: true,
            planned_source_digest: &digest(SOURCE_DIGEST),
            candidate: &candidate(true, false, false),
            observation: &observation(true, false, false),
            evidence: &evidence(),
        });
        assert_eq!(verdict.reason, Some(InconclusiveReason::BindingMismatch));
    }
}

#[test]
fn an_inapplicable_narrative_is_not_applicable_rather_than_a_pass() {
    let issued = binding();
    let verdict = evaluate(EvaluationInputs {
        issued_binding: &issued,
        echoed_binding: Some(&issued),
        narrative_applicable: false,
        planned_source_digest: &digest(SOURCE_DIGEST),
        candidate: &candidate(true, false, false),
        observation: &observation(true, false, false),
        evidence: &evidence(),
    });
    assert_eq!(verdict.outcome, TrialOutcome::NotApplicable);
}

#[test]
fn nothing_attempted_is_inconclusive_and_never_prevented() {
    let verdict = verdict_with(
        &binding(),
        &evidence(),
        &observation(false, false, false),
        &candidate(false, false, false),
    );
    assert_eq!(verdict.outcome, TrialOutcome::Inconclusive);
    assert_eq!(verdict.reason, Some(InconclusiveReason::EffectNotAttempted));
}

#[test]
fn an_incoherent_or_malformed_candidate_is_inconclusive() {
    let mut incoherent = candidate(false, false, false);
    incoherent.boundary_crossed = true;
    assert_eq!(incoherent.validate(), Err(CandidateError::Incoherent));

    let verdict = verdict_with(
        &binding(),
        &evidence(),
        &observation(false, false, true),
        &incoherent,
    );
    assert_eq!(verdict.reason, Some(InconclusiveReason::CandidateInvalid));

    let mut wrong_schema = candidate(true, false, false);
    wrong_schema.schema = "mvm.assurance.trial-result/v1".to_string();
    let verdict = verdict_with(
        &binding(),
        &evidence(),
        &observation(true, false, false),
        &wrong_schema,
    );
    assert_eq!(verdict.reason, Some(InconclusiveReason::CandidateInvalid));
}

#[test]
fn a_candidate_carrying_an_outcome_field_fails_to_parse() {
    // The type has no outcome field, so `deny_unknown_fields` is what stops a
    // model from asserting a verdict directly.
    let body = r#"{
      "schema": "mvm.assurance.trial-result-candidate/v1",
      "attempted_effect": true,
      "effect_observed_in_guest": false,
      "boundary_crossed": false,
      "blocked_edges": [],
      "evidence_refs": [],
      "notes": "",
      "outcome": "PREVENTED"
    }"#;
    let error =
        serde_json::from_str::<TrialResultCandidate>(body).expect_err("outcome must be unknown");
    assert!(error.to_string().contains("outcome"), "{error}");
}

#[test]
fn over_long_notes_are_refused() {
    let mut oversized = candidate(true, false, false);
    oversized.notes = "n".repeat(outcome::MAX_NOTES_BYTES + 1);
    assert_eq!(oversized.validate(), Err(CandidateError::NotesTooLong));
}

// ---------------------------------------------------------------------------
// Counterparty wire shape
// ---------------------------------------------------------------------------

#[test]
fn the_emitted_record_matches_the_counterparty_field_set() {
    let record = TrialEvidenceRecord::emit(
        EvidenceIdentity {
            campaign_id: &id("mvm-campaign-1"),
            trial_id: &id("trial-1"),
            source_run_id: &id("scout-1"),
            subject_revision: Some("0123456789abcdef"),
        },
        &evidence(),
        &observation(true, false, false),
    );

    let value = serde_json::to_value(&record).expect("serialize");
    let object = value.as_object().expect("object");

    // Exactly the keys `mvm.security.trial-evidence/v1` reads. A rename on
    // either side breaks the join, and this is what catches it.
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut expected = vec![
        "schema",
        "campaign_id",
        "trial_id",
        "source_run_id",
        "subject_revision",
        "source_digest",
        "artifact_digest",
        "policy_digest",
        "disposable_target",
        "identity_verified",
        "observer_verified",
        "cleanup_verified",
        "attestation_verified",
        "attempted_effect",
        "effect_observed_in_guest",
        "boundary_crossed",
        "blocked_edges",
        "evidence_refs",
    ];
    expected.sort_unstable();
    assert_eq!(keys, expected);

    assert_eq!(object["schema"], TRIAL_EVIDENCE_SCHEMA);
    // The record reports the observer's booleans, never the candidate's.
    assert_eq!(object["attempted_effect"], true);
    assert_eq!(object["boundary_crossed"], false);
    // Audit and receipt references are merged into the one array the
    // counterparty reads.
    assert_eq!(record.evidence_refs.len(), 2);
}

#[test]
fn the_envelope_the_host_writes_is_the_one_the_guest_reads() {
    // The host half is serialize-only and the guest half is deserialize-only,
    // so nothing but a test proves they describe the same document.
    let envelope =
        AiSessionInput::bind(request(), &binding(), &effective_for_envelope()).expect("envelope");
    let json = envelope.to_json().expect("encode");

    let delivered = wire::DeliveredSession::parse_json(json.as_bytes()).expect("guest parses");
    assert_eq!(delivered.mvm_binding, *envelope.binding());
    assert_eq!(delivered.authority, *envelope.authority());
    assert_eq!(delivered.session.trial_id.as_str(), "trial-1");
    assert_eq!(
        delivered.mvm_binding.plan_id.as_str(),
        minimal_plan().plan_id.0
    );
    assert!(delivered.permits_tool(ToolId::CampaignProbeV1));
    assert!(delivered.declares_destination(&id("undeclared.synthetic.destination")));
    assert!(!delivered.declares_destination(&id("some.other.label")));
}

#[test]
fn the_guest_reader_fails_closed_on_a_foreign_or_oversized_envelope() {
    let bad_schema = request_json();
    assert!(matches!(
        wire::DeliveredSession::parse_json(bad_schema.as_bytes()),
        // No `mvm_binding` key at all, so this fails as malformed before the
        // schema check — either way it does not yield a session.
        Err(wire::DeliveredSessionError::Malformed(_)
            | wire::DeliveredSessionError::UnsupportedSchema(_))
    ));

    let oversized = vec![b'x'; input::MAX_SESSION_INPUT_BYTES + 1];
    assert_eq!(
        wire::DeliveredSession::parse_json(&oversized),
        Err(wire::DeliveredSessionError::TooLarge)
    );
}

#[test]
fn a_provider_request_alone_is_not_a_deliverable_session() {
    // The request half carries no binding, so a workload handed one directly
    // — rather than one the host assembled — cannot read it as a session.
    assert!(matches!(
        wire::DeliveredSession::parse_json(request_json().as_bytes()),
        Err(wire::DeliveredSessionError::Malformed(_))
    ));
}

#[test]
fn the_outcome_vocabulary_matches_the_counterparty_spelling() {
    for (outcome, spelling) in [
        (TrialOutcome::Prevented, "PREVENTED"),
        (TrialOutcome::Contained, "CONTAINED"),
        (TrialOutcome::Observed, "OBSERVED"),
        (TrialOutcome::Inconclusive, "INCONCLUSIVE"),
        (TrialOutcome::NotApplicable, "NOT_APPLICABLE"),
    ] {
        assert_eq!(outcome.as_str(), spelling);
        assert_eq!(
            serde_json::to_string(&outcome).expect("serialize"),
            alloc::format!("\"{spelling}\"")
        );
    }
}
