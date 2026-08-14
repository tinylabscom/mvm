//! BDD witnesses for typed policy decisions and durable human approval.

use cucumber::{given, then, when};
use mvm_contract::policy::approval::{
    AgentApprovalEvent, ApprovalLedger, ApprovalOutcome, ApprovalRequest, ApprovalRequestId,
    ApprovalResponse, ApprovalState, OperatorId, PolicyCapability, PolicyDecision, PolicyEffect,
    PolicyRequest, PolicyRule, PolicySet, SignedAdmission,
};
use mvm_contract::protocol::agent_session::{
    AgentSessionId, AgentSessionJournal, IdempotencyKey, RetentionPolicy,
};

use crate::world::CliWorld;

fn session_id() -> AgentSessionId {
    AgentSessionId::parse("bdd-approval-session").expect("valid approval session")
}

fn operator(raw: &str) -> OperatorId {
    OperatorId::parse(raw).expect("valid operator")
}

fn approval_id(raw: &str) -> ApprovalRequestId {
    ApprovalRequestId::parse(raw).expect("valid approval")
}

fn admitted_request(capability: PolicyCapability) -> PolicyRequest {
    let unsigned = PolicyRequest {
        capability,
        resource_digest: [4; 32],
        request_digest: [5; 32],
        admission: None,
    };
    PolicyRequest {
        admission: Some(SignedAdmission {
            plan_digest: [6; 32],
            capability_digest: unsigned.capability_digest(),
        }),
        ..unsigned
    }
}

fn approval_request(
    evaluation: &mvm_contract::policy::approval::PolicyEvaluation,
    request: &PolicyRequest,
    approval_id: ApprovalRequestId,
    expires_at_unix_ms: u64,
) -> ApprovalRequest {
    ApprovalRequest {
        approval_id,
        session_id: session_id(),
        idempotency_key: IdempotencyKey::parse("bdd-approval-retry").expect("valid retry key"),
        capability: request.capability,
        resource_digest: request.resource_digest,
        request_digest: request.request_digest,
        policy_digest: evaluation.policy_digest,
        admission_plan_digest: [6; 32],
        reason: mvm_contract::policy::approval::ApprovalReason::PolicyRule,
        authorized_operators: vec![operator("ops-a")],
        expires_at_unix_ms,
    }
}

fn journal(world: &mut CliWorld) -> &mut AgentSessionJournal {
    world
        .agent_session_journal
        .as_mut()
        .expect("approval journal must be open")
}

fn ledger(world: &mut CliWorld) -> &mut ApprovalLedger {
    world
        .approval_ledger
        .as_mut()
        .expect("approval ledger must be initialized")
}

fn ledger_and_journal(world: &mut CliWorld) -> (&mut ApprovalLedger, &mut AgentSessionJournal) {
    let ledger = world
        .approval_ledger
        .as_mut()
        .expect("approval ledger must be initialized");
    let journal = world
        .agent_session_journal
        .as_mut()
        .expect("approval journal must be open");
    (ledger, journal)
}

#[given("an unadmitted policy request")]
fn unadmitted_policy_request(world: &mut CliWorld) {
    let request = PolicyRequest {
        capability: PolicyCapability::NetworkConnect,
        resource_digest: [1; 32],
        request_digest: [2; 32],
        admission: None,
    };
    let evaluation = PolicySet::default().evaluate(&request);
    world.approval_evaluation = Some(evaluation);
    world.approval_error = None;
}

#[then("policy denies it without an approval request")]
fn unadmitted_request_is_denied(world: &mut CliWorld) {
    assert_eq!(
        world.approval_evaluation.expect("evaluation").decision,
        PolicyDecision::Deny(mvm_contract::policy::approval::PolicyReason::NotAdmitted)
    );
    assert!(world.approval_ledger.is_none());
}

#[given("a signed-admission policy requiring approval")]
fn signed_policy_requires_approval(world: &mut CliWorld) {
    let (journal, _) =
        AgentSessionJournal::open(session_id(), [7; 32], 1_000, RetentionPolicy::default())
            .expect("open approval journal");
    let request = admitted_request(PolicyCapability::FilesystemWrite);
    let policy = PolicySet::new(vec![PolicyRule {
        capability: request.capability,
        resource_digest: None,
        priority: 10,
        effect: PolicyEffect::Ask,
    }])
    .expect("valid policy");
    let evaluation = policy.evaluate(&request);
    assert!(matches!(evaluation.decision, PolicyDecision::Ask(_)));
    world.agent_session_journal = Some(journal);
    world.approval_evaluation = Some(evaluation);
    world.approval_ledger = Some(ApprovalLedger::new(session_id()));
    world.approval_id = Some(approval_id("bdd-approval-1"));
    world.approval_error = None;
    world.approval_state = None;
}

#[when("I create the approval request")]
fn create_approval_request(world: &mut CliWorld) {
    let evaluation = world.approval_evaluation.expect("evaluation");
    let request = admitted_request(evaluation.capability);
    let id = world.approval_id.clone().expect("approval id");
    let approval = approval_request(&evaluation, &request, id, 2_000);
    let result = {
        let (ledger, journal) = ledger_and_journal(world);
        ledger.request(journal, &evaluation, approval, 1_001)
    };
    match result {
        Ok(outcome) => world.approval_state = Some(outcome.state),
        Err(error) => world.approval_error = Some(error.to_string()),
    }
}

#[when("an unauthorized operator responds")]
fn unauthorized_operator_responds(world: &mut CliWorld) {
    let id = world.approval_id.clone().expect("approval id");
    let result = {
        let (ledger, journal) = ledger_and_journal(world);
        ledger.respond(
            journal,
            ApprovalResponse {
                approval_id: id,
                operator_id: operator("ops-b"),
                outcome: ApprovalOutcome::Approved,
                response_nonce: 1,
                reason: None,
                ticket_ref: None,
            },
            1_002,
        )
    };
    world.approval_error = Some(result.expect_err("unauthorized response").to_string());
}

#[then("the response is refused without changing approval state")]
fn response_is_refused(world: &mut CliWorld) {
    let id = world.approval_id.clone().expect("approval id");
    assert_eq!(
        world.approval_error.as_deref(),
        Some("approval is not authorized for this operator")
    );
    assert_eq!(
        ledger(world).state(&id).expect("approval state"),
        ApprovalState::Pending
    );
}

#[when("the authorized operator approves")]
fn authorized_operator_approves(world: &mut CliWorld) {
    let id = world.approval_id.clone().expect("approval id");
    let result = {
        let (ledger, journal) = ledger_and_journal(world);
        ledger.respond(
            journal,
            ApprovalResponse {
                approval_id: id,
                operator_id: operator("ops-a"),
                outcome: ApprovalOutcome::Approved,
                response_nonce: 2,
                reason: None,
                ticket_ref: None,
            },
            1_003,
        )
    };
    match result {
        Ok(state) => world.approval_state = Some(state),
        Err(error) => world.approval_error = Some(error.to_string()),
    }
}

#[then("the approval is durable and approved")]
fn approval_is_durable(world: &mut CliWorld) {
    assert_eq!(world.approval_state, Some(ApprovalState::Approved));
    let page = journal(world).history(None, 32).expect("approval history");
    assert!(
        page.events.iter().any(|envelope| {
            match &envelope.event {
                mvm_contract::protocol::agent_session::AgentSessionEvent::Durable {
                    event:
                        mvm_contract::protocol::agent_session::DurableAgentSessionEvent::Approval {
                            event,
                        },
                } => matches!(event.as_ref(), AgentApprovalEvent::Responded { .. }),
                _ => false,
            }
        })
    );
    let rebuilt = ApprovalLedger::from_history(session_id(), &page.events).expect("restart");
    world.approval_restarted_state = Some(
        rebuilt
            .state(world.approval_id.as_ref().expect("approval id"))
            .expect("restarted state"),
    );
    assert_eq!(
        world.approval_restarted_state,
        Some(ApprovalState::Approved)
    );
}

#[when("the approval expires")]
fn approval_expires(world: &mut CliWorld) {
    let id = world.approval_id.clone().expect("approval id");
    let result = {
        let (ledger, journal) = ledger_and_journal(world);
        ledger.expire(journal, &id, 2_000)
    };
    match result {
        Ok(()) => world.approval_state = Some(ApprovalState::Expired),
        Err(error) => world.approval_error = Some(error.to_string()),
    }
}

#[when("a late authorized operator responds")]
fn late_authorized_operator_responds(world: &mut CliWorld) {
    let id = world.approval_id.clone().expect("approval id");
    let result = {
        let (ledger, journal) = ledger_and_journal(world);
        ledger.respond(
            journal,
            ApprovalResponse {
                approval_id: id,
                operator_id: operator("ops-a"),
                outcome: ApprovalOutcome::Approved,
                response_nonce: 3,
                reason: None,
                ticket_ref: None,
            },
            2_001,
        )
    };
    world.approval_error = Some(result.expect_err("late response").to_string());
}

#[then("the late response is refused")]
fn late_response_is_refused(world: &mut CliWorld) {
    assert_eq!(
        world.approval_error.as_deref(),
        Some("approval response was duplicated or arrived after a terminal state")
    );
    assert_eq!(world.approval_state, Some(ApprovalState::Expired));
}

#[then("restart keeps the approval expired")]
fn restart_keeps_expired(world: &mut CliWorld) {
    let page = journal(world).history(None, 32).expect("approval history");
    let rebuilt = ApprovalLedger::from_history(session_id(), &page.events).expect("restart");
    world.approval_restarted_state = Some(
        rebuilt
            .state(world.approval_id.as_ref().expect("approval id"))
            .expect("restarted state"),
    );
    assert_eq!(world.approval_restarted_state, Some(ApprovalState::Expired));
}
