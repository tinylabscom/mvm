//! Re-delivering a session's recorded prompts onto a fork of one of its
//! checkpoints.
//!
//! [`mvm_runtime::agent_session::replay::prepare_replay`] verifies the
//! checkpoint and its step timeline against the signed audit chain, and that
//! every recorded prompt on it is intact; [`ReplayPlan::dispatch`] decrypts
//! each one in journal order and hands it here. This dispatcher sends it to the fork's
//! resident agent through the same grant check, audit entries and transport a
//! live prompt takes, marked `delivery=replay`.
//!
//! The fork is not the session's machine, and its prompts are not journaled
//! into the session: a replay reproduces a timeline, it does not extend the
//! one it was taken from.

use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{Context, Result};
use mvm_core::plan::ExecutionPlan;
use mvm_hostd::audit::emitter::AuditEmitter;
use mvm_hostd::audit::emitter::agent_prompt_audit::{
    PromptAuditBinding, PromptDelivery, PromptFingerprint,
};
use mvm_runtime::agent_session::replay::{
    ReplayDispatchOutcome, ReplayDispatcher, ReplayPlan, ReplayReport,
};
use mvm_runtime::agent_session::replay_input::{ReplayInputRef, ReplayInputStore};

use super::{
    AGENT_PROMPT_VERB, CallObserver, GuestPromptTransport, PromptRefusal, PromptTransport,
    outcome_label, plan_grants_prompts,
};

/// The record of which recorded prompts a fork has already been sent: one
/// replay artifact content address per line. Written before each delivery, so a replay interrupted
/// after the agent answered and before the caller recorded progress never
/// sends the same prompt twice.
const LEDGER_FILE: &str = "replayed-prompts";

/// Sends recorded prompts to one fork.
pub struct PromptReplayDispatcher<'a> {
    vm_name: &'a str,
    plan: &'a ExecutionPlan,
    audit: &'a AuditEmitter,
    transport: &'a dyn PromptTransport,
    observer: &'a mut dyn CallObserver,
    ledger: PathBuf,
    timeout_secs: u64,
    answers: Vec<(u64, i32)>,
}

/// Everything a replay onto one fork needs besides the recorded prompts.
pub struct PromptReplayTarget<'a> {
    /// The fork the prompts are re-delivered to.
    pub vm_name: &'a str,
    /// The plan the fork was admitted under; it must grant prompts.
    pub plan: &'a ExecutionPlan,
    /// The chain each re-delivery is recorded in.
    pub audit: &'a AuditEmitter,
    /// How a prompt reaches the fork.
    pub transport: &'a dyn PromptTransport,
    /// Where the agent's answers go.
    pub observer: &'a mut dyn CallObserver,
    /// The fork's state directory, which holds the delivery ledger.
    pub state_dir: PathBuf,
    /// How long the agent has to answer each prompt.
    pub timeout_secs: u64,
}

impl<'a> PromptReplayDispatcher<'a> {
    /// Re-deliver onto `target`, refusing up front when its plan does not
    /// grant prompts. The refusal is recorded as `verb_denied`.
    ///
    /// # Errors
    /// The fork's plan does not grant prompts, or the refusal could not be
    /// recorded.
    pub fn new(target: PromptReplayTarget<'a>) -> Result<Self> {
        if !plan_grants_prompts(target.plan) {
            target
                .audit
                .emit_verb_denied(target.plan, AGENT_PROMPT_VERB)
                .context("recording the refused replay in the audit chain")?;
            return Err(PromptRefusal::NotGranted {
                vm: target.vm_name.to_string(),
            }
            .into());
        }
        Ok(Self {
            vm_name: target.vm_name,
            plan: target.plan,
            audit: target.audit,
            transport: target.transport,
            observer: target.observer,
            ledger: target.state_dir.join(LEDGER_FILE),
            timeout_secs: target.timeout_secs,
            answers: Vec::new(),
        })
    }

    /// The journal cursor and the agent's exit status of each prompt this
    /// dispatcher delivered, in delivery order.
    #[must_use]
    pub fn answers(&self) -> &[(u64, i32)] {
        &self.answers
    }

    fn already_sent(&self, digest: &str) -> Result<bool> {
        match std::fs::read_to_string(&self.ledger) {
            Ok(body) => Ok(body.lines().any(|line| line == digest)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error)
                .with_context(|| format!("reading the replay ledger {}", self.ledger.display())),
        }
    }

    fn mark_sent(&self, digest: &str) -> Result<()> {
        if let Some(parent) = self.ledger.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.ledger)
            .with_context(|| format!("opening the replay ledger {}", self.ledger.display()))?;
        writeln!(file, "{digest}").context("recording the replayed prompt")?;
        file.sync_all().context("committing the replay ledger")
    }
}

impl ReplayDispatcher for PromptReplayDispatcher<'_> {
    fn dispatch(
        &mut self,
        reference: &ReplayInputRef,
        input: &[u8],
    ) -> Result<ReplayDispatchOutcome> {
        if self.already_sent(&reference.artifact_digest)? {
            return Ok(ReplayDispatchOutcome::Duplicate);
        }
        let binding = PromptAuditBinding {
            vm_name: self.vm_name.to_string(),
            session_id: reference.binding.session_id.to_string(),
            generation: reference.binding.generation,
            journal_cursor: reference.binding.journal_cursor,
            delivery: PromptDelivery::Replay,
        };
        // At most once: the ledger names the prompt before it is sent, so a
        // crash between the agent's answer and the caller's progress record
        // cannot deliver it a second time.
        self.mark_sent(&reference.artifact_digest)?;
        self.audit
            .emit_agent_prompt_delivered(
                self.plan,
                &binding,
                &PromptFingerprint::of(input, &reference.artifact_digest),
            )
            .context("recording the replayed prompt in the audit chain")?;
        let delivered = self.transport.deliver(
            self.vm_name,
            input.to_vec(),
            self.timeout_secs,
            &mut *self.observer,
        );
        let label = match &delivered {
            Ok(call) => outcome_label(&call.terminal),
            Err(_) => "failed:transport".to_string(),
        };
        self.audit
            .emit_agent_prompt_completed(self.plan, &binding, &label)
            .context("recording the replayed prompt's completion in the audit chain")?;
        let call = delivered.with_context(|| {
            format!(
                "re-delivering the prompt recorded at journal cursor {}",
                reference.binding.journal_cursor
            )
        })?;
        self.answers
            .push((reference.binding.journal_cursor, call.exit_code()));
        Ok(ReplayDispatchOutcome::Applied)
    }
}

/// What one replay onto a fork did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayedPrompts {
    /// How many prompts were delivered, and how many had been already.
    pub report: ReplayReport,
    /// The prompts whose agent answered with a non-zero exit status, by
    /// journal cursor.
    pub nonzero_exits: Vec<(u64, i32)>,
}

/// Re-deliver `plan`'s recorded prompts onto the running fork `vm_name`,
/// under the plan that fork was admitted under.
///
/// # Errors
/// The fork has no readable admitted plan or does not grant prompts, the
/// host signer is unavailable, or a delivery or its audit entry failed.
pub fn replay_onto(
    vm_name: &str,
    plan: &ReplayPlan,
    inputs: &ReplayInputStore,
    timeout_secs: u64,
    observer: &mut dyn CallObserver,
) -> Result<ReplayedPrompts> {
    let admitted = mvm_hostd::audit::plan_persist::read_plan(vm_name)
        .with_context(|| format!("reading the plan {vm_name:?} was admitted under"))?;
    let signer = mvm_hostd::audit::host_keypair::load_or_init()
        .context("loading the host signer for the replay audit")?;
    let audit = AuditEmitter::new(signer.signing).context("opening the audit chain")?;
    let mut dispatcher = PromptReplayDispatcher::new(PromptReplayTarget {
        vm_name,
        plan: &admitted,
        audit: &audit,
        transport: &GuestPromptTransport,
        observer,
        state_dir: mvm_core::config::vm_state_dir(vm_name),
        timeout_secs,
    })?;
    let report = plan.dispatch(inputs, &mut dispatcher)?;
    let nonzero_exits = dispatcher
        .answers()
        .iter()
        .copied()
        .filter(|(_, code)| *code != 0)
        .collect();
    Ok(ReplayedPrompts {
        report,
        nonzero_exits,
    })
}
