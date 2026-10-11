//! Argument parsing and rendering for verified time-travel restores.
use super::timeline::LineageKind;
use anyhow::Result;
pub(in crate::commands) use checkpoint::{RevertImageSource, RevertRunImage};
use mvm_client::checkpoint::{self, AdvanceRequest, RevertRequest};

#[derive(clap::Args, Debug, Clone)]
pub(in crate::commands) struct RevertArgs {
    /// Checkpoint id or image lineage digest to restore.
    pub target: String,
    /// Disambiguate a digest present in both stores.
    #[arg(long, value_enum)]
    pub kind: Option<LineageKind>,
    /// Hypervisor backend for the restored VM.
    #[arg(long, default_value = "firecracker")]
    pub hypervisor: String,
    /// Name for the restored VM (checkpoint restores only).
    #[arg(long, value_parser = super::super::shared::clap_vm_name)]
    pub new_id: Option<String>,
    /// Emit the result as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args, Debug, Clone)]
pub(in crate::commands) struct AdvanceArgs {
    /// Checkpoint id or image lineage digest whose child to restore.
    pub target: String,
    /// Child digest, required at a fork.
    #[arg(long)]
    pub to: Option<String>,
    #[arg(long, value_enum)]
    pub kind: Option<LineageKind>,
    #[arg(long, default_value = "firecracker")]
    pub hypervisor: String,
    #[arg(long, value_parser = super::super::shared::clap_vm_name)]
    pub new_id: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug)]
pub(in crate::commands) enum RevertOutcome {
    Done,
    RunImage(RevertRunImage),
}

fn render(outcome: checkpoint::RevertOutcome, json: bool, via: &str) -> Result<RevertOutcome> {
    match outcome {
        checkpoint::RevertOutcome::Done(report) => {
            if json {
                crate::json_out::emit_json(&report)?;
            } else {
                crate::ui::success(&format!(
                    "{via} {} -> restored vm '{}' (re-admitted from checkpoint)",
                    report.parent_id.as_str(),
                    report.child_vm_name
                ));
            }
            Ok(RevertOutcome::Done)
        }
        checkpoint::RevertOutcome::RunImage(run) => Ok(RevertOutcome::RunImage(run)),
    }
}

impl From<RevertArgs> for RevertRequest {
    fn from(args: RevertArgs) -> Self {
        Self {
            target: args.target,
            kind: args.kind.map(Into::into),
            hypervisor: args.hypervisor,
            new_id: args.new_id,
            json: args.json,
        }
    }
}

pub(in crate::commands) fn run_revert(args: RevertArgs) -> Result<RevertOutcome> {
    let json = args.json;
    render(
        checkpoint::Checkpoints::open().revert(
            &args.into(),
            &mut mvm_client::entrypoint::CapturedOutput::default(),
        )?,
        json,
        "revert",
    )
}
pub(in crate::commands) fn run_rewind(args: RevertArgs) -> Result<RevertOutcome> {
    let json = args.json;
    render(
        checkpoint::Checkpoints::open().rewind(
            &args.into(),
            &mut mvm_client::entrypoint::CapturedOutput::default(),
        )?,
        json,
        "rewind",
    )
}
pub(in crate::commands) fn run_advance(args: AdvanceArgs) -> Result<RevertOutcome> {
    let json = args.json;
    render(
        checkpoint::Checkpoints::open().advance(
            &AdvanceRequest {
                target: args.target,
                to: args.to,
                kind: args.kind.map(Into::into),
                hypervisor: args.hypervisor,
                new_id: args.new_id,
                json,
            },
            &mut mvm_client::entrypoint::CapturedOutput::default(),
        )?,
        json,
        "advance",
    )
}
