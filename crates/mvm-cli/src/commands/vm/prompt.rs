//! `mvmctl machine prompt <name> [PROMPT]` — send one prompt to a running
//! machine's resident agent and print its answer.
//!
//! The agent is the program the image names in `/etc/mvm/entrypoint`; the
//! prompt is its complete stdin. Everything else — the plan grant, the
//! agent-session journal, the encrypted replay record, the chain-signed
//! delivery and completion entries — is `mvm_client::agent_prompt`, the same
//! function the host library's `machine.prompt` calls. This verb adds the one
//! thing only the CLI holds: the `vm_full` checkpoint each step is captured
//! as, which is what makes a recorded prompt replayable.

use std::io::Read;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use mvm_client::agent_prompt::{
    AgentPrompt, DEFAULT_PROMPT_TIMEOUT_SECS, MAX_PROMPT_BYTES, PromptOutcome, StepCheckpointer,
    StepRecord,
};
use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::checkpoint::VmFullStepCheckpointer;
use super::shared::clap_vm_name;
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the running machine whose agent is prompted
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// The prompt. Omit it, or pass `-`, to read the prompt from stdin
    #[arg(value_name = "PROMPT")]
    pub prompt: Option<String>,
    /// Agent session to journal the prompt under (default: the machine's
    /// name; opened on first use)
    #[arg(long, value_name = "ID")]
    pub session: Option<String>,
    /// Request id recorded in the session journal (default: derived from
    /// the time and the prompt's digest)
    #[arg(long, value_name = "ID")]
    pub request_id: Option<String>,
    /// Retry key: a prompt sent again under a key already accepted is not
    /// delivered twice (default: the request id)
    #[arg(long, value_name = "KEY")]
    pub idempotency_key: Option<String>,
    /// Seconds the agent has to answer
    #[arg(long, value_name = "SECS", default_value_t = DEFAULT_PROMPT_TIMEOUT_SECS)]
    pub timeout: u64,
    /// Do not checkpoint the step. The prompt is still recorded, but a
    /// replay of the session cannot pass it
    #[arg(long)]
    pub no_step_checkpoint: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let text = read_prompt(args.prompt.as_deref(), std::io::stdin())?;
    let prompt = build_prompt(&args, text)?;
    let checkpointer: Option<&dyn StepCheckpointer> = if args.no_step_checkpoint {
        None
    } else {
        Some(&VmFullStepCheckpointer)
    };
    let outcome = super::invoke::prompt_machine(&prompt, checkpointer)?;
    match outcome {
        PromptOutcome::Duplicate { journal_cursor } => {
            ui::info(&format!(
                "a prompt under idempotency key {} was already accepted at journal cursor \
                 {journal_cursor}; it was not sent again",
                prompt.idempotency_key()
            ));
            Ok(())
        }
        PromptOutcome::Delivered {
            journal_cursor,
            call,
            step,
        } => {
            report_step(&step, journal_cursor, args.no_step_checkpoint);
            let code = call.exit_code();
            if code != 0 {
                mvm_observability::exit(code);
            }
            Ok(())
        }
    }
}

fn build_prompt(args: &Args, text: Vec<u8>) -> Result<AgentPrompt> {
    let mut builder = AgentPrompt::builder(args.name.clone(), text).timeout_secs(args.timeout);
    if let Some(session) = &args.session {
        builder = builder.session(session.clone());
    }
    if let Some(request_id) = &args.request_id {
        builder = builder.request_id(request_id.clone());
    }
    if let Some(key) = &args.idempotency_key {
        builder = builder.idempotency_key(key.clone());
    }
    builder.build()
}

/// The prompt as given, or stdin read to its end. Reading stops one byte past
/// the limit, so an oversized prompt is refused without buffering all of it.
fn read_prompt(positional: Option<&str>, stdin: impl Read) -> Result<Vec<u8>> {
    match positional {
        Some(text) if text != "-" => Ok(text.as_bytes().to_vec()),
        _ => {
            let mut bytes = Vec::new();
            stdin
                .take(MAX_PROMPT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .context("reading the prompt from stdin")?;
            Ok(bytes)
        }
    }
}

fn report_step(step: &StepRecord, journal_cursor: u64, skipped: bool) {
    match step {
        StepRecord::Committed { checkpoint } => ui::info(&format!(
            "prompt recorded at journal cursor {journal_cursor}; step checkpoint {}",
            checkpoint.as_str()
        )),
        StepRecord::NotCaptured { .. } if skipped => ui::info(&format!(
            "prompt recorded at journal cursor {journal_cursor}; no step checkpoint was taken"
        )),
        StepRecord::NotCaptured { reason } => ui::warn(&format!(
            "prompt recorded at journal cursor {journal_cursor}, but its step checkpoint \
             failed ({reason}); a replay of this session cannot pass this step"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(prompt: Option<&str>) -> Args {
        Args {
            name: "agent-vm".into(),
            prompt: prompt.map(str::to_string),
            session: None,
            request_id: None,
            idempotency_key: None,
            timeout: DEFAULT_PROMPT_TIMEOUT_SECS,
            no_step_checkpoint: false,
        }
    }

    #[test]
    fn a_positional_prompt_is_used_verbatim_and_stdin_is_not_read() {
        let stdin = std::io::Cursor::new(b"ignored".to_vec());
        assert_eq!(read_prompt(Some("hello"), stdin).unwrap(), b"hello");
    }

    #[test]
    fn a_dash_or_no_prompt_reads_stdin_to_its_end() {
        for positional in [None, Some("-")] {
            let stdin = std::io::Cursor::new(b"from a pipe\n".to_vec());
            assert_eq!(read_prompt(positional, stdin).unwrap(), b"from a pipe\n");
        }
    }

    #[test]
    fn an_oversized_stdin_prompt_is_refused_by_the_builder() {
        let stdin = std::io::repeat(b'x');
        let text = read_prompt(None, stdin).unwrap();
        assert_eq!(
            text.len(),
            MAX_PROMPT_BYTES + 1,
            "read stops past the limit"
        );
        assert!(build_prompt(&args(None), text).is_err());
    }

    #[test]
    fn flags_reach_the_prompt() {
        let mut a = args(Some("hi"));
        a.session = Some("review".into());
        a.idempotency_key = Some("retry-1".into());
        let prompt = build_prompt(&a, b"hi".to_vec()).unwrap();
        assert_eq!(prompt.session_id().as_str(), "review");
        assert_eq!(prompt.idempotency_key().as_str(), "retry-1");
        assert_eq!(prompt.vm_name(), "agent-vm");
    }
}
