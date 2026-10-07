use std::cell::RefCell;

use ed25519_dalek::SigningKey;
use mvm_core::checkpoint::{CheckpointClass, CheckpointMeta};
use mvm_core::plan::VerbId;
use mvm_hostd::audit::emitter::AuditEmitter;
use mvm_hostd::stream::ShownChunk;

use super::*;
use crate::entrypoint::dispatch::{CallOutcome, CallTerminal};

const VM: &str = "agent-vm";

/// Every store a delivery touches, under one temp root.
struct Fixture {
    _root: tempfile::TempDir,
    audit_dir: std::path::PathBuf,
    plan: ExecutionPlan,
    audit: AuditEmitter,
    store: AgentSessionStore,
    inputs: ReplayInputStore,
    checkpoints: CheckpointStore,
}

impl Fixture {
    fn new(agent_verbs: Option<&[&str]>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let audit_dir = root.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        let mut plan = mvm_core::plan::signing::test_support::sample_plan();
        plan.agent_verbs =
            agent_verbs.map(|verbs| verbs.iter().map(|v| VerbId::new(v).unwrap()).collect());
        let audit = AuditEmitter::with_dir(SigningKey::from_bytes(&[3; 32]), &audit_dir).unwrap();
        Self {
            store: AgentSessionStore::at(root.path().join("sessions")),
            inputs: ReplayInputStore::at(root.path().join("sessions"), root.path().join("keys")),
            checkpoints: CheckpointStore::at(root.path().join("checkpoints")),
            audit_dir,
            plan,
            audit,
            _root: root,
        }
    }

    fn host<'a>(
        &'a self,
        transport: &'a dyn PromptTransport,
        checkpointer: Option<&'a dyn StepCheckpointer>,
    ) -> PromptHost<'a> {
        PromptHost {
            plan: &self.plan,
            audit: &self.audit,
            store: &self.store,
            inputs: &self.inputs,
            checkpoints: &self.checkpoints,
            transport,
            checkpointer,
        }
    }

    fn chain(&self) -> Vec<serde_json::Value> {
        let path = self.audit_dir.join(format!("{}.jsonl", self.plan.tenant.0));
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["entry"].clone())
            .collect()
    }

    fn events(&self) -> Vec<String> {
        self.chain()
            .iter()
            .map(|entry| entry["event"].as_str().unwrap().to_string())
            .collect()
    }
}

/// A guest whose agent answers every prompt with `answer` and exit `code`.
struct FakeAgent {
    seen: RefCell<Vec<Vec<u8>>>,
    code: i32,
    fail_transport: bool,
}

impl FakeAgent {
    fn answering(code: i32) -> Self {
        Self {
            seen: RefCell::new(Vec::new()),
            code,
            fail_transport: false,
        }
    }
}

impl PromptTransport for FakeAgent {
    fn deliver(
        &self,
        vm_name: &str,
        prompt: Vec<u8>,
        _timeout_secs: u64,
        _observer: &mut dyn CallObserver,
    ) -> Result<CallOutcome> {
        assert_eq!(vm_name, VM);
        self.seen.borrow_mut().push(prompt);
        if self.fail_transport {
            bail!("the guest went away");
        }
        Ok(CallOutcome {
            terminal: CallTerminal::Exited { code: self.code },
            capture: None,
        })
    }
}

/// Writes a step checkpoint exactly as the capture path would: durable in the
/// store, carrying the binding and parent it was handed.
struct FakeCheckpointer<'a> {
    store: &'a CheckpointStore,
    taken: RefCell<u32>,
}

impl StepCheckpointer for FakeCheckpointer<'_> {
    fn capture(&self, step: StepCapture<'_>) -> Result<CheckpointMeta> {
        let mut taken = self.taken.borrow_mut();
        *taken += 1;
        let meta = CheckpointMeta::builder(
            CheckpointId::new(format!("step-{taken}")),
            CheckpointClass::VmFull,
            step.vm_name,
        )
        .created_unix(u64::from(*taken))
        .supervisor_config_digest("config")
        .parent(step.parent)
        .session(Some(step.session))
        .build();
        self.store.write_meta(&meta)?;
        Ok(meta)
    }
}

struct Silent;

impl CallObserver for Silent {
    fn output(&mut self, _chunk: &ShownChunk) {}
    fn control(&mut self, _header: &str, _payload_len: usize) {}
}

fn prompt(text: &str, key: &str) -> AgentPrompt {
    AgentPrompt::builder(VM, text.as_bytes().to_vec())
        .request_id(key)
        .build()
        .unwrap()
}

#[test]
fn a_plan_that_lists_verbs_without_agent_prompt_refuses_and_records_the_refusal() {
    let fixture = Fixture::new(Some(&["run-entrypoint", "ping"]));
    let agent = FakeAgent::answering(0);

    let err = deliver(
        &fixture.host(&agent, None),
        &prompt("delete the backups", "p-1"),
        &mut Silent,
    )
    .expect_err("an ungranted prompt is refused");

    assert!(
        matches!(
            err.downcast_ref::<PromptRefusal>(),
            Some(PromptRefusal::NotGranted { .. })
        ),
        "{err:#}"
    );
    assert!(
        agent.seen.borrow().is_empty(),
        "the prompt reached the guest"
    );
    let chain = fixture.chain();
    assert_eq!(fixture.events(), ["verb_denied"]);
    assert_eq!(chain[0]["labels"]["verb"], AGENT_PROMPT_VERB);
    let session = AgentSessionId::parse(VM).unwrap();
    assert!(
        !fixture.store.session_dir(&session).exists(),
        "a refused prompt left a session or a recorded input behind"
    );
}

#[test]
fn grant_follows_the_plan_verb_list() {
    let mut plan = mvm_core::plan::signing::test_support::sample_plan();
    plan.agent_verbs = None;
    assert!(
        plan_grants_prompts(&plan),
        "a permissive dev plan grants every verb"
    );
    plan.agent_verbs = Some(vec![VerbId::new("run-entrypoint").unwrap()]);
    assert!(!plan_grants_prompts(&plan));
    plan.agent_verbs = Some(vec![VerbId::new(AGENT_PROMPT_VERB).unwrap()]);
    assert!(plan_grants_prompts(&plan));
}

#[test]
fn a_delivered_prompt_is_journaled_recorded_audited_and_committed_as_a_step() {
    let fixture = Fixture::new(Some(&[AGENT_PROMPT_VERB]));
    let agent = FakeAgent::answering(0);
    let checkpointer = FakeCheckpointer {
        store: &fixture.checkpoints,
        taken: RefCell::new(0),
    };
    let secret_prompt = "summarize the incident without naming the customer";

    let outcome = deliver(
        &fixture.host(&agent, Some(&checkpointer)),
        &prompt(secret_prompt, "p-1"),
        &mut Silent,
    )
    .expect("delivered");

    let PromptOutcome::Delivered {
        journal_cursor,
        call,
        step,
    } = outcome
    else {
        panic!("expected a delivery, got {outcome:?}");
    };
    assert_eq!(call.exit_code(), 0);
    assert_eq!(agent.seen.borrow().as_slice(), [secret_prompt.as_bytes()]);
    let StepRecord::Committed { checkpoint } = step else {
        panic!("the step was not committed: {step:?}");
    };
    // The first prompt into a session is preceded by the session's base, the
    // state the step is replayed from.
    assert_eq!(checkpoint.as_str(), "step-2");
    let base = fixture
        .checkpoints
        .read_meta(&CheckpointId::new("step-1"))
        .unwrap();
    let base_binding = base.session.clone().unwrap();
    assert!(base_binding.replay_input_digest.is_none());
    assert!(base_binding.journal_cursor < journal_cursor);

    let session = AgentSessionId::parse(VM).unwrap();
    let record = fixture.store.load(&session).unwrap();
    assert_eq!(record.journal_cursor, journal_cursor);
    assert_eq!(record.members, [VM]);
    let step_meta = fixture.checkpoints.read_meta(&checkpoint).unwrap();
    assert_eq!(
        record.parent_checkpoint,
        Some(step_meta.meta_digest.clone())
    );
    assert_eq!(step_meta.parent, Some(base.meta_digest.clone()));

    let recorded = fixture
        .inputs
        .after(&session, record.generation, 0)
        .unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        fixture.inputs.load(&recorded[0]).unwrap().as_slice(),
        secret_prompt.as_bytes()
    );
    assert_eq!(
        step_meta.session.unwrap().replay_input_digest.as_deref(),
        Some(recorded[0].artifact_digest.as_str())
    );

    let history =
        std::fs::read_to_string(fixture.store.session_dir(&session).join(HISTORY_FILE)).unwrap();
    assert!(
        !history.contains("without naming"),
        "prompt bytes in history"
    );
    let chain = std::fs::read_to_string(fixture.audit_dir.join("tenant-a.jsonl")).unwrap();
    assert!(
        !chain.contains("without naming"),
        "prompt bytes in the chain"
    );
    assert_eq!(
        fixture.events(),
        ["agent.prompt_delivered", "agent.prompt_completed"]
    );
    assert_eq!(
        fixture.chain()[0]["labels"]["journal_cursor"],
        journal_cursor.to_string()
    );
}

#[test]
fn a_repeated_idempotency_key_is_not_delivered_twice() {
    let fixture = Fixture::new(None);
    let agent = FakeAgent::answering(0);
    let host = fixture.host(&agent, None);

    let first = deliver(&host, &prompt("once", "p-1"), &mut Silent).unwrap();
    let again = deliver(&host, &prompt("once", "p-1"), &mut Silent).unwrap();

    let PromptOutcome::Delivered { journal_cursor, .. } = first else {
        panic!("first prompt was not delivered: {first:?}");
    };
    assert_eq!(again, PromptOutcome::Duplicate { journal_cursor });
    assert_eq!(agent.seen.borrow().len(), 1);
}

#[test]
fn successive_steps_extend_one_hash_linked_timeline() {
    let fixture = Fixture::new(None);
    let agent = FakeAgent::answering(0);
    let checkpointer = FakeCheckpointer {
        store: &fixture.checkpoints,
        taken: RefCell::new(0),
    };
    let host = fixture.host(&agent, Some(&checkpointer));

    deliver(&host, &prompt("first", "p-1"), &mut Silent).unwrap();
    let second = deliver(&host, &prompt("second", "p-2"), &mut Silent).unwrap();

    let PromptOutcome::Delivered {
        journal_cursor,
        step: StepRecord::Committed { checkpoint },
        ..
    } = second
    else {
        panic!("second step not committed: {second:?}");
    };
    let first = fixture
        .checkpoints
        .read_meta(&CheckpointId::new("step-2"))
        .unwrap();
    let second = fixture.checkpoints.read_meta(&checkpoint).unwrap();
    assert_eq!(second.parent, Some(first.meta_digest));
    let session = AgentSessionId::parse(VM).unwrap();
    assert_eq!(
        fixture.store.load(&session).unwrap().journal_cursor,
        journal_cursor
    );
}

#[test]
fn a_failed_delivery_is_closed_in_the_journal_and_the_chain() {
    let fixture = Fixture::new(None);
    let agent = FakeAgent {
        fail_transport: true,
        ..FakeAgent::answering(0)
    };
    let host = fixture.host(&agent, None);

    deliver(&host, &prompt("lost", "p-1"), &mut Silent).expect_err("transport failed");

    let chain = fixture.chain();
    assert_eq!(chain[1]["event"], "agent.prompt_completed");
    assert_eq!(chain[1]["labels"]["outcome"], "failed:transport");
    // The session is usable again: a closed failure does not leave it running.
    let healthy = FakeAgent::answering(0);
    let next = deliver(
        &fixture.host(&healthy, None),
        &prompt("next", "p-2"),
        &mut Silent,
    )
    .unwrap();
    assert!(matches!(next, PromptOutcome::Delivered { .. }));
}

#[test]
fn a_prompt_left_in_flight_by_a_crash_is_closed_not_resent() {
    let fixture = Fixture::new(None);
    let session = AgentSessionId::parse(VM).unwrap();
    fixture
        .store
        .write(&AgentSessionRecord::opened(
            session.clone(),
            vec![VM.into()],
            None,
            1,
        ))
        .unwrap();
    let path = fixture.store.session_dir(&session).join(HISTORY_FILE);
    let mut crashed =
        DurableHistory::open(&path, &session, workload_digest(&fixture.plan).unwrap(), 1).unwrap();
    crashed
        .journal
        .apply(
            AgentSessionCommand::Prompt {
                request_id: AgentRequestId::parse("p-crashed").unwrap(),
                idempotency_key: IdempotencyKey::parse("p-crashed").unwrap(),
                prompt: b"half sent".to_vec(),
            },
            2,
        )
        .unwrap();
    crashed.persist().unwrap();
    drop(crashed);

    let agent = FakeAgent::answering(0);
    let host = fixture.host(&agent, None);
    let retried = deliver(&host, &prompt("half sent", "p-crashed"), &mut Silent).unwrap();
    assert!(
        matches!(retried, PromptOutcome::Duplicate { .. }),
        "an interrupted prompt was re-sent: {retried:?}"
    );
    let fresh = deliver(&host, &prompt("again", "p-new"), &mut Silent)
        .unwrap_or_else(|error| panic!("{error:#}"));
    assert!(matches!(fresh, PromptOutcome::Delivered { .. }));
    assert_eq!(agent.seen.borrow().as_slice(), [b"again".as_slice()]);
}

#[test]
fn a_session_for_another_machine_is_refused() {
    let fixture = Fixture::new(None);
    let session = AgentSessionId::parse("shared").unwrap();
    fixture
        .store
        .write(&AgentSessionRecord::opened(
            session,
            vec!["other-vm".into()],
            None,
            1,
        ))
        .unwrap();
    let agent = FakeAgent::answering(0);
    let request = AgentPrompt::builder(VM, b"hi".to_vec())
        .session("shared")
        .build()
        .unwrap();

    let err = deliver(&fixture.host(&agent, None), &request, &mut Silent).unwrap_err();
    assert!(err.to_string().contains("does not include"), "{err:#}");
    assert!(agent.seen.borrow().is_empty());
}

#[test]
fn the_builder_refuses_empty_oversized_and_unnamed_prompts() {
    assert!(AgentPrompt::builder(VM, Vec::new()).build().is_err());
    assert!(
        AgentPrompt::builder(VM, vec![b'x'; MAX_PROMPT_BYTES + 1])
            .build()
            .is_err()
    );
    assert!(
        AgentPrompt::builder(VM, b"hi".to_vec())
            .session("Not A Session")
            .build()
            .is_err()
    );
    let built = AgentPrompt::builder(VM, b"hi".to_vec()).build().unwrap();
    assert_eq!(built.session_id().as_str(), VM);
    assert_eq!(
        built.idempotency_key().as_str(),
        built.request_id.as_str(),
        "the retry key defaults to the request id"
    );
}

#[test]
fn outcome_labels_are_a_closed_vocabulary() {
    assert_eq!(outcome_label(&CallTerminal::Exited { code: 3 }), "exited:3");
    assert_eq!(
        outcome_label(&CallTerminal::Failed {
            kind: mvm_agentd::vsock::RunEntrypointError::Timeout,
            message: "the agent said something private".into(),
        }),
        "failed:timeout"
    );
}

/// Accepts every checkpoint as recorded in the chain, so planning exercises the
/// timeline and input checks without a signed audit log.
struct RecordedAnchor;

impl mvm_runtime::checkpoint::CheckpointChainAnchor for RecordedAnchor {
    fn recorded_creation_digest(
        &self,
        meta: &CheckpointMeta,
    ) -> Result<Option<mvm_core::checkpoint::CheckpointDigest>> {
        Ok(Some(meta.meta_digest.clone()))
    }

    fn recorded_creation_tenant(&self, _meta: &CheckpointMeta) -> Result<Option<String>> {
        Ok(Some("tenant-a".to_string()))
    }
}

/// Record `prompts` against the fixture's machine, each as a committed step.
fn recorded_session(fixture: &Fixture, prompts: &[&str]) -> AgentSessionRecord {
    let agent = FakeAgent::answering(0);
    let checkpointer = FakeCheckpointer {
        store: &fixture.checkpoints,
        taken: RefCell::new(0),
    };
    let host = fixture.host(&agent, Some(&checkpointer));
    for (turn, text) in prompts.iter().enumerate() {
        deliver(&host, &prompt(text, &format!("p-{turn}")), &mut Silent).unwrap();
    }
    fixture
        .store
        .load(&AgentSessionId::parse(VM).unwrap())
        .unwrap()
}

fn replay_target<'a>(
    fixture: &'a Fixture,
    agent: &'a FakeAgent,
    observer: &'a mut Silent,
    state_dir: &std::path::Path,
) -> replay::PromptReplayTarget<'a> {
    replay::PromptReplayTarget {
        vm_name: VM,
        plan: &fixture.plan,
        audit: &fixture.audit,
        transport: agent,
        observer,
        state_dir: state_dir.to_path_buf(),
        timeout_secs: 30,
    }
}

#[test]
fn a_recorded_prompt_sequence_replays_in_order_from_the_session_base() {
    let fixture = Fixture::new(None);
    let record = recorded_session(&fixture, &["first", "second", "third"]);
    let base =
        mvm_runtime::agent_session::replay::timeline_base(&fixture.checkpoints, &record).unwrap();
    assert_eq!(base.as_str(), "step-1", "the base precedes every step");

    let plan = mvm_runtime::agent_session::replay::prepare_replay(
        &fixture.checkpoints,
        &fixture.inputs,
        &base,
        &record,
        &RecordedAnchor,
    )
    .unwrap();
    assert_eq!(plan.inputs.len(), 3);

    let fork_state = tempfile::tempdir().unwrap();
    let agent = FakeAgent::answering(0);
    let mut observer = Silent;
    let mut dispatcher = replay::PromptReplayDispatcher::new(replay_target(
        &fixture,
        &agent,
        &mut observer,
        fork_state.path(),
    ))
    .unwrap();
    let report = plan.dispatch(&fixture.inputs, &mut dispatcher).unwrap();

    assert_eq!(report.applied, 3);
    assert_eq!(
        agent.seen.borrow().as_slice(),
        [
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice()
        ]
    );
    let replayed: Vec<_> = fixture
        .chain()
        .into_iter()
        .filter(|entry| entry["labels"]["delivery"] == "replay")
        .collect();
    assert_eq!(
        replayed.len(),
        6,
        "a delivered and a completed entry per prompt"
    );
    assert!(
        replayed
            .iter()
            .all(|entry| !entry.to_string().contains("second")),
        "a replayed prompt reached the chain"
    );

    // Re-running the same plan against the same fork delivers nothing twice.
    let again_agent = FakeAgent::answering(0);
    let mut again_observer = Silent;
    let mut again = replay::PromptReplayDispatcher::new(replay_target(
        &fixture,
        &again_agent,
        &mut again_observer,
        fork_state.path(),
    ))
    .unwrap();
    let report = plan.dispatch(&fixture.inputs, &mut again).unwrap();
    assert_eq!((report.applied, report.duplicates), (0, 3));
    assert!(again_agent.seen.borrow().is_empty());
}

#[test]
fn a_replay_onto_a_fork_whose_plan_refuses_prompts_sends_nothing() {
    let fixture = Fixture::new(Some(&["run-entrypoint"]));
    let fork_state = tempfile::tempdir().unwrap();
    let agent = FakeAgent::answering(0);
    let mut observer = Silent;
    let refused = replay::PromptReplayDispatcher::new(replay_target(
        &fixture,
        &agent,
        &mut observer,
        fork_state.path(),
    ));
    assert!(refused.is_err());
    assert_eq!(fixture.events(), ["verb_denied"]);
}

#[test]
fn a_prompt_recorded_without_a_step_stops_the_replay_before_it() {
    let fixture = Fixture::new(None);
    let record = recorded_session(&fixture, &["first"]);
    // A prompt whose step capture failed: recorded, but on no checkpoint.
    let agent = FakeAgent::answering(0);
    deliver(
        &fixture.host(&agent, None),
        &prompt("unstepped", "p-unstepped"),
        &mut Silent,
    )
    .unwrap();
    let checkpointer = FakeCheckpointer {
        store: &fixture.checkpoints,
        taken: RefCell::new(2),
    };
    deliver(
        &fixture.host(&agent, Some(&checkpointer)),
        &prompt("after", "p-after"),
        &mut Silent,
    )
    .unwrap();
    let record_now = fixture.store.load(&record.session_id).unwrap();
    let base = mvm_runtime::agent_session::replay::timeline_base(&fixture.checkpoints, &record_now)
        .unwrap();

    let err = mvm_runtime::agent_session::replay::prepare_replay(
        &fixture.checkpoints,
        &fixture.inputs,
        &base,
        &record_now,
        &RecordedAnchor,
    )
    .unwrap_err();
    assert!(err.to_string().contains("no step checkpoint"), "{err:#}");
}
