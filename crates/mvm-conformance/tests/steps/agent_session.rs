//! BDD witnesses for the durable agent session contract.

use cucumber::{given, then, when};
use mvm_contract::protocol::agent_session::{
    self, AgentRequestId, AgentSessionCommand, AgentSessionId, AgentSessionState, IdempotencyKey,
    PromptResult, RetentionPolicy,
};

use crate::world::CliWorld;

fn session_id() -> AgentSessionId {
    AgentSessionId::parse("bdd-agent-session").expect("BDD session id is valid")
}

fn request_id(raw: &str) -> AgentRequestId {
    AgentRequestId::parse(raw).expect("BDD request id is valid")
}

fn idempotency_key(raw: &str) -> IdempotencyKey {
    IdempotencyKey::parse(raw).expect("BDD idempotency key is valid")
}

fn journal(world: &mut CliWorld) -> &mut agent_session::AgentSessionJournal {
    world
        .agent_session_journal
        .as_mut()
        .expect("an agent session must be opened first")
}

#[given("a newly opened durable agent session")]
fn open_agent_session(world: &mut CliWorld) {
    let (journal, _) = agent_session::AgentSessionJournal::open(
        session_id(),
        [3; 32],
        1_000,
        RetentionPolicy::default(),
    )
    .expect("open agent session");
    world.agent_session_journal = Some(journal);
}

#[when(expr = "I submit the private prompt {string}")]
fn submit_private_prompt(world: &mut CliWorld, prompt: String) {
    let command = AgentSessionCommand::Prompt {
        request_id: request_id("bdd-request-1"),
        idempotency_key: idempotency_key("bdd-retry-1"),
        prompt: prompt.into_bytes(),
    };
    world.agent_session_outcome =
        Some(journal(world).apply(command, 1_001).expect("submit prompt"));
}

#[when("I retry the same prompt")]
fn retry_private_prompt(world: &mut CliWorld) {
    let command = AgentSessionCommand::Prompt {
        request_id: request_id("bdd-request-1"),
        idempotency_key: idempotency_key("bdd-retry-1"),
        prompt: b"private credential".to_vec(),
    };
    world.agent_session_outcome = Some(journal(world).apply(command, 1_002).expect("retry prompt"));
}

#[then("the prompt retry is acknowledged without re-execution")]
fn retry_is_idempotent(world: &mut CliWorld) {
    let outcome = world.agent_session_outcome.as_ref().expect("retry result");
    assert!(!outcome.applied);
    assert_eq!(outcome.state, AgentSessionState::Running);
}

#[then("durable history excludes prompt bytes")]
fn durable_history_excludes_prompt(world: &mut CliWorld) {
    let page = journal(world).history(None, 32).expect("history");
    let json = serde_json::to_string(&page).expect("serialize history");
    assert!(!json.contains("private credential"));
    assert!(json.contains("prompt_digest"));
    world.agent_session_history_json = Some(json);
}

#[when("I complete the prompt successfully")]
fn complete_prompt(world: &mut CliWorld) {
    journal(world)
        .complete_prompt(request_id("bdd-request-1"), PromptResult::Succeeded, 1_003)
        .expect("complete prompt");
}

#[when("I reconnect from the durable cursor")]
fn reconnect_from_cursor(world: &mut CliWorld) {
    let first = journal(world).history(None, 2).expect("first history page");
    let second = journal(world)
        .history(Some(first.next_cursor.clone()), 32)
        .expect("second history page");
    let events = [first.events.clone(), second.events.clone()].concat();
    let rebuilt = agent_session::AgentSessionJournal::from_history(
        session_id(),
        events,
        RetentionPolicy::default(),
    )
    .expect("restart from durable history");
    world.agent_session_restarted_state = Some(rebuilt.state());
    world.agent_session_history = Some(second);
}

#[then("adapter restart restores the completed state")]
fn restart_restores_completed_state(world: &mut CliWorld) {
    assert_eq!(
        world.agent_session_restarted_state,
        Some(AgentSessionState::Completed)
    );
}

#[when(expr = "I emit the live delta {string}")]
fn emit_live_delta(world: &mut CliWorld, delta: String) {
    world.agent_session_live = Some(
        journal(world)
            .live_delta(delta.into_bytes(), 1_004)
            .expect("live delta"),
    );
}

#[then("the live delta is absent from durable history")]
fn live_delta_is_ephemeral(world: &mut CliWorld) {
    let page = journal(world).history(None, 32).expect("history");
    assert!(page.events.iter().all(|event| {
        !matches!(
            event.event,
            agent_session::AgentSessionEvent::Ephemeral { .. }
        )
    }));
    assert!(world.agent_session_live.is_some());
}

#[when("I cancel and confirm the session")]
fn cancel_and_confirm(world: &mut CliWorld) {
    journal(world)
        .apply(
            AgentSessionCommand::Cancel {
                request_id: request_id("bdd-cancel-1"),
                idempotency_key: idempotency_key("bdd-cancel-retry-1"),
            },
            1_005,
        )
        .expect("request cancellation");
    journal(world)
        .confirm_cancel(1_006)
        .expect("confirm cancellation");
}

#[then("the durable session state is canceled")]
fn session_is_canceled(world: &mut CliWorld) {
    assert_eq!(journal(world).state(), AgentSessionState::Canceled);
}
