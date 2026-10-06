//! Prompts for the agent resident in a running machine.
//!
//! One prompt is one `AgentPrompt` request over the machine's authenticated
//! vsock control session. The guest runs the program the image names in
//! `/etc/mvm/entrypoint` with the prompt as its complete stdin and streams the
//! answer back, exactly as it serves a function call; what differs is the
//! verb, which the signed plan grants separately.
//!
//! Around that one request, every prompt is:
//!
//! - **granted** by the machine's admitted plan: a plan whose `agent_verbs`
//!   list omits `agent-prompt` is refused here, before anything is recorded,
//!   and the guest refuses it again against its pinned grant. Both refusals
//!   land in the chain-signed log as `verb_denied`;
//! - **journaled** as an `AgentSessionCommand::Prompt` in the agent session's
//!   durable history, which carries the prompt's digest and never its bytes;
//! - **recorded** encrypted, at the journal cursor it was accepted at, in the
//!   session's replay-input store;
//! - **audited** as `agent.prompt_delivered` before it is sent and
//!   `agent.prompt_completed` once it is answered, by digest and size only;
//! - **checkpointed**, when the caller supplies a [`StepCheckpointer`]: a
//!   `vm_full` checkpoint bound to the session, the cursor and the recorded
//!   input, committed as the session's new resume point. A session's first
//!   checkpointed prompt is preceded by a base checkpoint of the machine as it
//!   stood before the prompt. That chain, base first, is what a replay
//!   re-delivers prompts along.
//!
//! `mvmctl machine prompt` and the host library's `machine.prompt` both call
//! [`send_prompt`], so a prompt from either is granted, recorded and audited
//! identically.

use std::path::Path;

use anyhow::{Context, Result, bail};
use mvm_contract::protocol::agent_session::{
    AgentRequestId, AgentSessionCommand, AgentSessionId, AgentSessionState, IdempotencyKey,
    PromptResult,
};
use mvm_core::checkpoint::{ApprovalHead, CheckpointDigest, CheckpointId, CheckpointMeta};
use mvm_core::plan::ExecutionPlan;
use mvm_hostd::audit::emitter::AuditEmitter;
use mvm_hostd::audit::emitter::agent_prompt_audit::{
    PromptAuditBinding, PromptDelivery, PromptFingerprint,
};
use mvm_runtime::agent_session::history::{DurableHistory, load_history};
use mvm_runtime::agent_session::replay_input::{
    MAX_REPLAY_INPUT_BYTES, ReplayInputBinding, ReplayInputRef, ReplayInputStore,
};
use mvm_runtime::agent_session::{AgentSessionRecord, AgentSessionStore, SandboxResidency};
use mvm_runtime::checkpoint::CheckpointStore;

use crate::entrypoint::dispatch::{
    CallObserver, CallOutcome, CallTerminal, DispatchStdin, EntrypointDispatch,
    ONE_SHOT_PAYLOAD_LIMIT, dispatch, error_label,
};

/// The verb a plan's `agent_verbs` must list for its workload to take prompts.
pub const AGENT_PROMPT_VERB: &str = "agent-prompt";

/// The largest prompt delivered: it must fit the request frame and the replay
/// store, whichever is smaller.
pub const MAX_PROMPT_BYTES: usize = if ONE_SHOT_PAYLOAD_LIMIT < MAX_REPLAY_INPUT_BYTES {
    ONE_SHOT_PAYLOAD_LIMIT
} else {
    MAX_REPLAY_INPUT_BYTES
};

/// The answer window when a caller names none.
pub const DEFAULT_PROMPT_TIMEOUT_SECS: u64 = 120;

const HISTORY_FILE: &str = "history.jsonl";
const PROMPT_LOCK: &str = "prompt";

/// Whether `plan` lets its workload take prompts.
///
/// A plan with no `agent_verbs` list is a permissive dev plan — every verb
/// its profile allows is granted, and the guest applies no list either. A
/// plan with a list grants prompts only by naming `agent-prompt`.
#[must_use]
pub fn plan_grants_prompts(plan: &ExecutionPlan) -> bool {
    plan.agent_verbs
        .as_ref()
        .is_none_or(|verbs| verbs.iter().any(|verb| verb.as_str() == AGENT_PROMPT_VERB))
}

/// One prompt for one machine's resident agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPrompt {
    vm_name: String,
    session_id: AgentSessionId,
    request_id: AgentRequestId,
    idempotency_key: IdempotencyKey,
    prompt: Vec<u8>,
    timeout_secs: u64,
}

impl AgentPrompt {
    /// A prompt for `vm_name`'s agent. See [`AgentPromptBuilder`] for what
    /// each unset field defaults to.
    #[must_use]
    pub fn builder(vm_name: impl Into<String>, prompt: Vec<u8>) -> AgentPromptBuilder {
        AgentPromptBuilder {
            vm_name: vm_name.into(),
            prompt,
            session_id: None,
            request_id: None,
            idempotency_key: None,
            timeout_secs: DEFAULT_PROMPT_TIMEOUT_SECS,
        }
    }

    /// The machine being prompted.
    #[must_use]
    pub fn vm_name(&self) -> &str {
        &self.vm_name
    }

    /// The agent session the prompt is journaled under.
    #[must_use]
    pub fn session_id(&self) -> &AgentSessionId {
        &self.session_id
    }

    /// The caller's retry key.
    #[must_use]
    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
}

/// Builder for [`AgentPrompt`].
pub struct AgentPromptBuilder {
    vm_name: String,
    prompt: Vec<u8>,
    session_id: Option<String>,
    request_id: Option<String>,
    idempotency_key: Option<String>,
    timeout_secs: u64,
}

impl AgentPromptBuilder {
    /// The agent session to journal under. Defaults to the machine's name.
    #[must_use]
    pub fn session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// The request id. Defaults to one derived from the current time and the
    /// prompt's digest.
    #[must_use]
    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// The retry key. A second prompt under a key already accepted is not
    /// delivered again. Defaults to the request id.
    #[must_use]
    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    /// How long the agent has to answer.
    #[must_use]
    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Validate every identifier and the prompt's size.
    ///
    /// # Errors
    /// An invalid machine name or identifier, an empty prompt, a prompt
    /// larger than [`MAX_PROMPT_BYTES`], or a zero timeout.
    pub fn build(self) -> Result<AgentPrompt> {
        mvm_core::naming::validate_vm_name(&self.vm_name)
            .with_context(|| format!("invalid machine name {:?}", self.vm_name))?;
        if self.prompt.is_empty() {
            bail!("the prompt is empty");
        }
        if self.prompt.len() > MAX_PROMPT_BYTES {
            bail!(
                "the prompt is {} bytes; the limit is {MAX_PROMPT_BYTES}",
                self.prompt.len()
            );
        }
        if self.timeout_secs == 0 {
            bail!("the prompt timeout must be > 0 seconds");
        }
        let session_raw = self.session_id.unwrap_or_else(|| self.vm_name.clone());
        let session_id = AgentSessionId::parse(session_raw.clone()).with_context(|| {
            format!(
                "{session_raw:?} is not a valid agent session id; name one with lowercase \
                 letters, digits, '-', '_' or '.'"
            )
        })?;
        let request_raw = self
            .request_id
            .unwrap_or_else(|| default_request_id(&self.prompt));
        let request_id = AgentRequestId::parse(request_raw.clone())
            .with_context(|| format!("invalid request id {request_raw:?}"))?;
        let key_raw = self.idempotency_key.unwrap_or(request_raw);
        let idempotency_key = IdempotencyKey::parse(key_raw.clone())
            .with_context(|| format!("invalid idempotency key {key_raw:?}"))?;
        Ok(AgentPrompt {
            vm_name: self.vm_name,
            session_id,
            request_id,
            idempotency_key,
            prompt: self.prompt,
            timeout_secs: self.timeout_secs,
        })
    }
}

fn default_request_id(prompt: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = hex::encode(sha2::Sha256::digest(prompt));
    format!(
        "prompt-{}-{}",
        mvm_core::util::time::now_unix_millis(),
        &digest[..12]
    )
}

/// The checkpoint a step is captured as: bound to its session, cursor and
/// recorded input, and hash-linked to the session's previous resume point.
pub struct StepCapture<'a> {
    /// The machine whose state the step freezes.
    pub vm_name: &'a str,
    /// The session's resume point before this step.
    pub parent: Option<CheckpointDigest>,
    /// The session, cursor and input the step is bound to.
    pub session: mvm_core::checkpoint::SessionBinding,
}

/// Captures a `vm_full` checkpoint of a running machine for one step.
///
/// A seam rather than a direct call because capture is owned by the caller's
/// checkpoint machinery; a caller without one delivers prompts that are
/// recorded but cannot be replayed.
pub trait StepCheckpointer {
    /// Capture the step and return its durable metadata.
    ///
    /// # Errors
    /// The backend cannot capture, or the checkpoint could not be written.
    fn capture(&self, step: StepCapture<'_>) -> Result<CheckpointMeta>;
}

/// Sends a granted prompt into a machine and streams the answer.
pub trait PromptTransport {
    /// Deliver `prompt` and return how the agent's run ended.
    ///
    /// # Errors
    /// The agent was unreachable, refused the verb, or the stream broke.
    fn deliver(
        &self,
        vm_name: &str,
        prompt: Vec<u8>,
        timeout_secs: u64,
        observer: &mut dyn CallObserver,
    ) -> Result<CallOutcome>;
}

/// The production transport: one `AgentPrompt` over the machine's vsock
/// control session, through the same dispatch every entrypoint call uses, so
/// the answer is captured, redacted and recorded like any workload output and
/// a guest refusal is audited as `verb_denied`.
pub struct GuestPromptTransport;

impl PromptTransport for GuestPromptTransport {
    fn deliver(
        &self,
        vm_name: &str,
        prompt: Vec<u8>,
        timeout_secs: u64,
        observer: &mut dyn CallObserver,
    ) -> Result<CallOutcome> {
        dispatch(
            EntrypointDispatch {
                vm_name,
                stdin: DispatchStdin::Prompt(prompt),
                timeout_secs,
                session_id: None,
            },
            observer,
        )
    }
}

/// Whether the delivered prompt's step became a replayable resume point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepRecord {
    /// The step checkpoint was captured and committed as the session's
    /// resume point.
    Committed {
        /// The step checkpoint.
        checkpoint: CheckpointId,
    },
    /// No step checkpoint was committed. The prompt is recorded, but a replay
    /// cannot pass this step.
    NotCaptured {
        /// Why.
        reason: String,
    },
}

/// How one prompt ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptOutcome {
    /// The prompt was delivered and the agent's run ended.
    Delivered {
        /// The journal cursor the prompt was accepted at.
        journal_cursor: u64,
        /// How the agent's run ended.
        call: CallOutcome,
        /// Whether the step is replayable.
        step: StepRecord,
    },
    /// A prompt under the same idempotency key was already accepted, and
    /// nothing was sent again.
    Duplicate {
        /// The journal cursor the original was accepted at.
        journal_cursor: u64,
    },
}

/// Why a prompt was refused before it was sent.
#[derive(Debug, thiserror::Error)]
pub enum PromptRefusal {
    /// The admitted plan's verb grant does not include prompts.
    #[error(
        "the plan {vm} was admitted under does not grant agent prompts: its agent-verb \
         list omits `{AGENT_PROMPT_VERB}`. Boot it with `--agent-verb {AGENT_PROMPT_VERB}` \
         among its verbs to accept prompts"
    )]
    NotGranted {
        /// The machine.
        vm: String,
    },
}

/// Deliver one prompt to a running machine's resident agent.
///
/// Loads the machine's admitted plan and the host signer, then runs the
/// grant check, journal, encrypted record, audit, delivery and step capture
/// described in the module documentation. Pass a `checkpointer` to make the
/// step replayable.
///
/// # Errors
/// A machine that is not running or has no admitted plan, a refused grant
/// (a [`PromptRefusal`] in the chain), a session that cannot take the prompt,
/// an unwritable record or audit entry, or a failed delivery.
pub fn send_prompt(
    prompt: &AgentPrompt,
    observer: &mut dyn CallObserver,
    checkpointer: Option<&dyn StepCheckpointer>,
) -> Result<PromptOutcome> {
    if !mvm_runtime::checkpoint::vm_is_running(&prompt.vm_name) {
        bail!(
            "machine {:?} is not running; start it before prompting its agent",
            prompt.vm_name
        );
    }
    let plan = mvm_hostd::audit::plan_persist::read_plan(&prompt.vm_name).with_context(|| {
        format!(
            "reading the plan {:?} was admitted under; a prompt is granted by it",
            prompt.vm_name
        )
    })?;
    let signer = mvm_hostd::audit::host_keypair::load_or_init()
        .context("loading the host signer for the prompt audit")?;
    let audit = AuditEmitter::new(signer.signing).context("opening the audit chain")?;
    let store = AgentSessionStore::open();
    let inputs = ReplayInputStore::open();
    let checkpoints = CheckpointStore::open();
    deliver(
        &PromptHost {
            plan: &plan,
            audit: &audit,
            store: &store,
            inputs: &inputs,
            checkpoints: &checkpoints,
            transport: &GuestPromptTransport,
            checkpointer,
        },
        prompt,
        observer,
    )
}

/// Everything one delivery touches, gathered so the delivery itself runs
/// against any store, chain and transport.
pub(crate) struct PromptHost<'a> {
    pub(crate) plan: &'a ExecutionPlan,
    pub(crate) audit: &'a AuditEmitter,
    pub(crate) store: &'a AgentSessionStore,
    pub(crate) inputs: &'a ReplayInputStore,
    pub(crate) checkpoints: &'a CheckpointStore,
    pub(crate) transport: &'a dyn PromptTransport,
    pub(crate) checkpointer: Option<&'a dyn StepCheckpointer>,
}

pub(crate) fn deliver(
    host: &PromptHost<'_>,
    prompt: &AgentPrompt,
    observer: &mut dyn CallObserver,
) -> Result<PromptOutcome> {
    require_grant(host, &prompt.vm_name)?;

    let session_dir = host.store.session_dir(&prompt.session_id);
    std::fs::create_dir_all(&session_dir)
        .with_context(|| format!("creating agent session {}", session_dir.display()))?;
    // A session's cursor, history and resume point move together; two
    // prompts into one session from two processes must take turns.
    let _turn = mvm_core::util::atomic_io::FileLock::acquire(&session_dir.join(PROMPT_LOCK))
        .context("waiting for the agent session's prompt lock")?;

    let record = active_session(host.store, prompt)?;
    let now_ms = mvm_core::util::time::now_unix_millis();
    let mut history = DurableHistory::open(
        &session_dir.join(HISTORY_FILE),
        &prompt.session_id,
        workload_digest(host.plan)?,
        now_ms,
    )?;
    fail_interrupted_prompt(&mut history, now_ms)?;
    // Where the session stands before this prompt: a base checkpoint, if one
    // is taken, is bound here, below the cursor the prompt is accepted at.
    let base_cursor = history.committed_sequence();

    let accepted = history
        .journal
        .apply(
            AgentSessionCommand::Prompt {
                request_id: prompt.request_id.clone(),
                idempotency_key: prompt.idempotency_key.clone(),
                prompt: prompt.prompt.clone(),
            },
            now_ms,
        )
        .context("accepting the prompt into the agent session journal")?;
    history.persist()?;
    let journal_cursor = accepted
        .first_sequence
        .context("an accepted prompt has no journal cursor")?;
    if !accepted.applied {
        return Ok(PromptOutcome::Duplicate { journal_cursor });
    }
    // Before anything reaches the guest, so the base is the state the first
    // recorded prompt was delivered into.
    let (record, base_failure) = establish_base(host, prompt, record, base_cursor, &session_dir);

    let binding = PromptAuditBinding {
        vm_name: prompt.vm_name.clone(),
        session_id: prompt.session_id.to_string(),
        generation: record.generation,
        journal_cursor,
        delivery: PromptDelivery::Live,
    };
    let recorded = match record_and_announce(host, prompt, &record, &binding) {
        Ok(recorded) => recorded,
        Err(error) => {
            finish(&mut history, prompt, PromptResult::Failed)?;
            return Err(error);
        }
    };

    let delivered = host.transport.deliver(
        &prompt.vm_name,
        prompt.prompt.clone(),
        prompt.timeout_secs,
        observer,
    );
    let result = match &delivered {
        Ok(call) if call.exit_code() == 0 => PromptResult::Succeeded,
        _ => PromptResult::Failed,
    };
    finish(&mut history, prompt, result)?;
    let outcome_label = match &delivered {
        Ok(call) => outcome_label(&call.terminal),
        Err(_) => "failed:transport".to_string(),
    };
    host.audit
        .emit_agent_prompt_completed(host.plan, &binding, &outcome_label)
        .context("recording the prompt's completion in the audit chain")?;
    let call = delivered?;

    let step = match base_failure {
        Some(reason) => StepRecord::NotCaptured { reason },
        None => commit_step(host, prompt, &record, &recorded, &session_dir),
    };
    Ok(PromptOutcome::Delivered {
        journal_cursor,
        call,
        step,
    })
}

/// Refuse, and record the refusal, when the plan does not grant prompts.
fn require_grant(host: &PromptHost<'_>, vm_name: &str) -> Result<()> {
    if plan_grants_prompts(host.plan) {
        return Ok(());
    }
    // Recorded before the refusal is returned, and load-bearing: a refusal
    // the chain cannot hold is reported as that, not as a plain refusal.
    host.audit
        .emit_verb_denied(host.plan, AGENT_PROMPT_VERB)
        .context("recording the refused prompt in the audit chain")?;
    Err(PromptRefusal::NotGranted {
        vm: vm_name.to_string(),
    }
    .into())
}

/// Load the prompt's session, opening it for this machine on first use.
fn active_session(store: &AgentSessionStore, prompt: &AgentPrompt) -> Result<AgentSessionRecord> {
    if !store.exists(&prompt.session_id) {
        let record = AgentSessionRecord::opened(
            prompt.session_id.clone(),
            vec![prompt.vm_name.clone()],
            None,
            mvm_core::util::time::now_unix_secs(),
        );
        store.write(&record)?;
        return Ok(record);
    }
    let record = store.load(&prompt.session_id)?;
    if record.state != SandboxResidency::Active {
        bail!(
            "agent session {} is not active; resume it before prompting",
            prompt.session_id
        );
    }
    if !record
        .members
        .iter()
        .any(|member| member == &prompt.vm_name)
    {
        bail!(
            "agent session {} does not include machine {:?}; prompt it under its own session",
            prompt.session_id,
            prompt.vm_name
        );
    }
    Ok(record)
}

/// A journal recovered with a prompt still in flight belongs to a delivery
/// that crashed. Whether that prompt reached the agent is unknowable, so it
/// is closed as failed rather than re-sent; its caller retries under a new
/// key if it wants the prompt delivered.
fn fail_interrupted_prompt(history: &mut DurableHistory, now_ms: u64) -> Result<()> {
    if history.journal.state() != AgentSessionState::Running {
        return Ok(());
    }
    let interrupted = history
        .journal
        .active_request()
        .cloned()
        .context("a running agent session journal names no active prompt")?;
    history
        .journal
        .complete_prompt(interrupted, PromptResult::Failed, now_ms)
        .context("closing an interrupted prompt")?;
    history.persist()
}

fn finish(history: &mut DurableHistory, prompt: &AgentPrompt, result: PromptResult) -> Result<()> {
    history
        .journal
        .complete_prompt(
            prompt.request_id.clone(),
            result,
            mvm_core::util::time::now_unix_millis(),
        )
        .context("completing the prompt in the agent session journal")?;
    history.persist()
}

/// Record the prompt encrypted, then put its delivery on the chain. The
/// prompt is sent only once both have succeeded.
fn record_and_announce(
    host: &PromptHost<'_>,
    prompt: &AgentPrompt,
    record: &AgentSessionRecord,
    binding: &PromptAuditBinding,
) -> Result<ReplayInputRef> {
    let recorded = host
        .inputs
        .record(
            ReplayInputBinding {
                session_id: prompt.session_id.clone(),
                generation: record.generation,
                journal_cursor: binding.journal_cursor,
            },
            &prompt.prompt,
        )
        .context("recording the prompt for replay")?;
    host.audit
        .emit_agent_prompt_delivered(
            host.plan,
            binding,
            &PromptFingerprint::of(&prompt.prompt, &recorded.artifact_digest),
        )
        .context("recording the prompt's delivery in the audit chain")?;
    Ok(recorded)
}

/// Give a session with no resume point its base: a checkpoint of the machine
/// before the prompt, so the first recorded step has a state to be replayed
/// from. Returns the record to extend, and why no base was taken when one was
/// needed and could not be.
fn establish_base(
    host: &PromptHost<'_>,
    prompt: &AgentPrompt,
    record: AgentSessionRecord,
    base_cursor: u64,
    session_dir: &Path,
) -> (AgentSessionRecord, Option<String>) {
    let Some(checkpointer) = host.checkpointer else {
        return (record, None);
    };
    if record.parent_checkpoint.is_some() {
        return (record, None);
    }
    let based = approval_head(&session_dir.join(HISTORY_FILE), &prompt.session_id)
        .and_then(|approval_head| {
            checkpointer.capture(StepCapture {
                vm_name: &prompt.vm_name,
                parent: None,
                session: mvm_core::checkpoint::SessionBinding {
                    session_id: prompt.session_id.clone(),
                    generation: record.generation,
                    journal_cursor: base_cursor,
                    approval_head,
                    replay_input_digest: None,
                },
            })
        })
        .and_then(|meta| {
            host.store.commit_session_base(
                host.checkpoints,
                &meta,
                mvm_core::util::time::now_unix_secs(),
            )
        });
    match based {
        Ok(based) => (based, None),
        Err(error) => (
            record,
            Some(format!("the session's base checkpoint failed: {error:#}")),
        ),
    }
}

/// Capture and commit the step. Never fails the prompt: the agent has
/// already answered, and the caller is told whether the step is replayable.
fn commit_step(
    host: &PromptHost<'_>,
    prompt: &AgentPrompt,
    record: &AgentSessionRecord,
    recorded: &ReplayInputRef,
    session_dir: &Path,
) -> StepRecord {
    let Some(checkpointer) = host.checkpointer else {
        return StepRecord::NotCaptured {
            reason: "no step checkpoint was requested".to_string(),
        };
    };
    match capture_and_commit(host, checkpointer, prompt, record, recorded, session_dir) {
        Ok(checkpoint) => StepRecord::Committed { checkpoint },
        Err(error) => StepRecord::NotCaptured {
            reason: format!("{error:#}"),
        },
    }
}

fn capture_and_commit(
    host: &PromptHost<'_>,
    checkpointer: &dyn StepCheckpointer,
    prompt: &AgentPrompt,
    record: &AgentSessionRecord,
    recorded: &ReplayInputRef,
    session_dir: &Path,
) -> Result<CheckpointId> {
    let meta = checkpointer.capture(StepCapture {
        vm_name: &prompt.vm_name,
        parent: record.parent_checkpoint.clone(),
        session: mvm_core::checkpoint::SessionBinding {
            session_id: prompt.session_id.clone(),
            generation: record.generation,
            journal_cursor: recorded.binding.journal_cursor,
            approval_head: approval_head(&session_dir.join(HISTORY_FILE), &prompt.session_id)?,
            replay_input_digest: Some(recorded.artifact_digest.clone()),
        },
    })?;
    host.store.commit_replayable_step(
        host.checkpoints,
        host.inputs,
        recorded,
        &meta,
        mvm_core::util::time::now_unix_secs(),
    )?;
    Ok(meta.id)
}

/// The session's approval-ledger head, rebuilt from its durable history:
/// approval events share the session's cursor, so the history is the ledger.
fn approval_head(history: &Path, session_id: &AgentSessionId) -> Result<ApprovalHead> {
    let events = load_history(history)?;
    let ledger =
        mvm_contract::policy::approval::ApprovalLedger::from_history(session_id.clone(), &events)
            .map_err(|error| anyhow::anyhow!("rebuilding the session's approval ledger: {error}"))?;
    Ok(ApprovalHead::from_bytes(&ledger.head()))
}

/// The plan's image digest, which pins the session history to one workload.
fn workload_digest(plan: &ExecutionPlan) -> Result<[u8; 32]> {
    let mut digest = [0u8; 32];
    hex::decode_to_slice(&plan.image.sha256, &mut digest)
        .context("the admitted plan's image digest is not 32 bytes of hex")?;
    Ok(digest)
}

/// A closed-vocabulary label for how a run ended: never agent output.
#[must_use]
pub fn outcome_label(terminal: &CallTerminal) -> String {
    match terminal {
        CallTerminal::Exited { code } => format!("exited:{code}"),
        CallTerminal::Failed { kind, .. } => format!("failed:{}", error_label(*kind)),
    }
}

pub mod replay;

#[cfg(test)]
mod tests;
