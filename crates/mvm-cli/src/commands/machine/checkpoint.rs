//! Machine checkpoint arguments and rendering; orchestration lives in the client.
use anyhow::Result;
pub(in crate::commands) use checkpoint::{
    ForkMachineInput, ForkVmFullMachineInput, RestoreMachineInput,
};
use mvm_client::checkpoint;

pub(in crate::commands) fn fork_machine(input: ForkMachineInput) -> Result<()> {
    let json = input.json;
    let report = checkpoint::Checkpoints::open().fork_machine(
        input,
        &mut mvm_client::entrypoint::CapturedOutput::default(),
    )?;
    if json && report.children.len() > 1 {
        crate::json_out::emit_json(&report)?;
    } else {
        for child in &report.children {
            render(child, json)?;
        }
    }
    Ok(())
}

pub(in crate::commands) fn restore_machine(input: RestoreMachineInput) -> Result<()> {
    let json = input.json;
    render(
        &checkpoint::Checkpoints::open().restore_machine(
            input,
            &mut mvm_client::entrypoint::CapturedOutput::default(),
        )?,
        json,
    )
}

pub(in crate::commands) fn fork_vm_full_machine(
    input: ForkVmFullMachineInput,
) -> Result<mvm_core::checkpoint::CheckpointMeta> {
    let json = input.json;
    let report = checkpoint::Checkpoints::open().fork_vm_full_machine(
        input,
        &mut mvm_client::entrypoint::CapturedOutput::default(),
    )?;
    render(&report, json)?;
    Ok(report.checkpoint)
}

fn render(report: &checkpoint::ForkReport, json: bool) -> Result<()> {
    if json {
        crate::json_out::emit_json(report)?;
    } else {
        crate::ui::success(&format!(
            "forked {} -> vm '{}' (booted)",
            report.parent_id.as_str(),
            report.child_vm_name
        ));
    }
    Ok(())
}
