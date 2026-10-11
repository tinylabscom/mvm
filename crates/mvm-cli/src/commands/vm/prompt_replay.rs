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

use anyhow::Result;
use clap::Args as ClapArgs;
use mvm_client::agent_prompt::DEFAULT_PROMPT_TIMEOUT_SECS;
use mvm_client::replay::{SessionReplayRequest, SessionReplayRunRequest, SessionReplaySummary};

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
    let report = super::invoke::replay_prompts(&SessionReplayRunRequest {
        selection: SessionReplayRequest {
            session_id: args.session_id.clone(),
            from: args.from.clone(),
            as_name: args.as_name.clone(),
        },
        dry_run: args.dry_run,
        timeout_secs: args.timeout,
        tenant: super::tenant_resolution::resolve_tenant(None),
    })?;
    let plan = &report.summary;
    let from = &plan.checkpoint;
    let fork_name = &plan.restored_name;
    let Some(replayed) = report.execution else {
        print_plan(plan, fork_name);
        return Ok(());
    };
    ui::notice(&format!(
        "replayed {} prompt(s) from {} onto {fork_name:?}; the machine is running",
        replayed.applied,
        from.as_str(),
    ));
    if replayed.duplicates > 0 {
        ui::info(&format!(
            "{} prompt(s) had already been delivered to {fork_name:?} and were not sent again",
            replayed.duplicates
        ));
    }
    for (cursor, code) in &replayed.nonzero_exits {
        ui::warn(&format!(
            "the prompt recorded at journal cursor {cursor} was answered with exit status {code}"
        ));
    }
    Ok(())
}

fn print_plan(plan: &SessionReplaySummary, fork_name: &str) {
    print!("{}", render_plan(plan, fork_name));
}

fn render_plan(plan: &SessionReplaySummary, fork_name: &str) -> String {
    let mut lines = vec![format!(
        "replay session {} from {} onto {fork_name:?}",
        plan.session_id,
        plan.checkpoint.as_str()
    )];
    for input in &plan.inputs {
        lines.push(format!(
            "  prompt at journal cursor {}: {}",
            input.journal_cursor, input.artifact_digest
        ));
    }
    lines.push(format!("  {} prompt(s)", plan.inputs.len()));
    format!("{}\n", lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_arguments_preserve_defaults_and_dry_run_selection() {
        use clap::Parser;
        #[derive(Parser)]
        struct Command {
            #[command(flatten)]
            args: ReplayArgs,
        }
        let parsed = Command::try_parse_from([
            "replay",
            "session-one",
            "--from",
            "base",
            "--as",
            "fork-one",
            "--dry-run",
        ])
        .unwrap();
        assert_eq!(parsed.args.session_id, "session-one");
        assert_eq!(parsed.args.from.as_deref(), Some("base"));
        assert_eq!(parsed.args.as_name.as_deref(), Some("fork-one"));
        assert!(parsed.args.dry_run);
        assert_eq!(parsed.args.timeout, DEFAULT_PROMPT_TIMEOUT_SECS);
    }

    #[test]
    fn replay_dry_run_renders_only_summary_metadata() {
        let summary = SessionReplaySummary {
            checkpoint: mvm_core::checkpoint::CheckpointId::new("base"),
            session_id: "session-one".into(),
            generation: 2,
            checkpoint_cursor: 4,
            restored_name: "fork-one".into(),
            inputs: vec![mvm_client::replay::SessionReplayInput {
                journal_cursor: 7,
                artifact_digest: "sha256:artifact".into(),
            }],
        };
        assert_eq!(
            render_plan(&summary, &summary.restored_name),
            "replay session session-one from base onto \"fork-one\"\n  prompt at journal cursor 7: sha256:artifact\n  1 prompt(s)\n"
        );
    }

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
