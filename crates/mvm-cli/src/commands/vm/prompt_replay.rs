//! `mvmctl agent-session replay <session>` — re-deliver a session's recorded
//! prompts onto a fork of one of its checkpoints.
//!
//! 1. `prepare_replay` verifies the checkpoint and the session's whole step
//!    timeline against the signed audit chain, and checks every recorded
//!    prompt after it is on that timeline and decrypts;
//! 2. the checkpoint is fork-booted exactly like `machine replay` and
//!    `machine revert` do — a fresh, re-admitted machine whose state is the
//!    checkpoint's frozen copy;
//! 3. `ReplayPlan::dispatch` decrypts the prompts in journal order and the
//!    prompt replay dispatcher sends each to the fork's resident agent,
//!    granted, audited and deduplicated, printing the answers.
//!
//! The session and the machine it was recorded on are never touched: replay
//! is a fork. A mid-replay failure leaves the fork running at the last prompt
//! it answered.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use mvm_client::agent_prompt::DEFAULT_PROMPT_TIMEOUT_SECS;
use mvm_contract::protocol::agent_session::AgentSessionId;
use mvm_runtime::agent_session::AgentSessionStore;
use mvm_runtime::agent_session::replay::{ReplayPlan, prepare_replay, timeline_base};
use mvm_runtime::agent_session::replay_input::ReplayInputStore;
use mvm_runtime::checkpoint::CheckpointStore;

use super::checkpoint::{self, SignedChainAnchor, validated_checkpoint_id};
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ReplayArgs {
    /// Session id, as `agent-session ls` prints it
    pub session_id: String,
    /// Checkpoint to replay from (default: the session's base checkpoint, so
    /// every recorded prompt is replayed)
    #[arg(long, value_name = "CHECKPOINT")]
    pub from: Option<String>,
    /// Name for the replayed machine (default: auto-named)
    #[arg(long = "as", value_name = "NAME")]
    pub as_name: Option<String>,
    /// Report the replay plan without forking or delivering anything
    #[arg(long)]
    pub dry_run: bool,
    /// Seconds the agent has to answer each replayed prompt
    #[arg(long, value_name = "SECS", default_value_t = DEFAULT_PROMPT_TIMEOUT_SECS)]
    pub timeout: u64,
}

pub(in crate::commands) fn run(args: &ReplayArgs) -> Result<()> {
    let session_id = AgentSessionId::parse(args.session_id.clone())
        .map_err(|e| anyhow::anyhow!("invalid session id '{}': {e}", args.session_id))?;
    let record = AgentSessionStore::open().load(&session_id)?;
    let checkpoints = CheckpointStore::open();
    let inputs = ReplayInputStore::open();
    let from = match &args.from {
        Some(raw) => validated_checkpoint_id(raw)?,
        None => timeline_base(&checkpoints, &record)?,
    };
    let anchor = SignedChainAnchor::load().context("loading the signed audit chain")?;
    let plan = prepare_replay(&checkpoints, &inputs, &from, &record, &anchor)
        .with_context(|| format!("planning the replay of session {session_id}"))?;

    let fork_name = super::replay::fork_name(&from, args.as_name.as_deref())?;
    if args.dry_run {
        print_plan(&plan, &fork_name);
        return Ok(());
    }

    checkpoint::fork(checkpoint::ForkCmdParams {
        id: from.as_str(),
        new_id: Some(fork_name.clone()),
        boot: true,
        hypervisor: "",
        cpus: None,
        memory: None,
        declared_secrets: &[],
        allow_secret_drop: false,
        json: false,
        intent: checkpoint::ForkIntent::Ordinary,
    })
    .with_context(|| format!("restoring checkpoint {:?} for replay", from.as_str()))?;

    let replayed = super::invoke::replay_prompts(&fork_name, &plan, &inputs, args.timeout)?;
    ui::success(&format!(
        "replayed {} prompt(s) from {} onto {fork_name:?}; the machine is running",
        replayed.report.applied,
        from.as_str(),
    ));
    if replayed.report.duplicates > 0 {
        ui::info(&format!(
            "{} prompt(s) had already been delivered to {fork_name:?} and were not sent again",
            replayed.report.duplicates
        ));
    }
    for (cursor, code) in &replayed.nonzero_exits {
        ui::warn(&format!(
            "the prompt recorded at journal cursor {cursor} was answered with exit status {code}"
        ));
    }
    Ok(())
}

fn print_plan(plan: &ReplayPlan, fork_name: &str) {
    println!(
        "replay session {} from {} onto {fork_name:?}",
        plan.session_id,
        plan.checkpoint.as_str()
    );
    for input in &plan.inputs {
        println!(
            "  prompt at journal cursor {}: {}",
            input.binding.journal_cursor, input.artifact_digest
        );
    }
    println!("  {} prompt(s)", plan.inputs.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invalid_session_id_is_refused_before_any_store_is_read() {
        let args = ReplayArgs {
            session_id: "Not A Session".into(),
            from: None,
            as_name: None,
            dry_run: true,
            timeout: 1,
        };
        assert!(
            run(&args)
                .unwrap_err()
                .to_string()
                .contains("invalid session id")
        );
    }
}
