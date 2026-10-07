//! Agent-prompt steps captured as session-bound `vm_full` checkpoints.

use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};
use mvm_core::config::vm_state_dir;
use mvm_runtime::checkpoint::{CheckpointStore, vm_is_running};

use super::{
    CaptureVmFullArgs, SessionStep, backend_for_vm, bind_checkpoint_created,
    capture_vm_full_for_running_vm, ensure_save_restore_supported, lock_machine_input_cursor,
    now_unix, seal_machine_input_cursor,
};

/// Captures each agent-prompt step as a `vm_full` checkpoint of the prompted
/// machine, through the same pause/save/resume path and the same chain-signed
/// `checkpoint.created` binding as `checkpoint create --class vm-full`.
pub(in crate::commands) struct VmFullStepCheckpointer;

impl mvm_client::agent_prompt::StepCheckpointer for VmFullStepCheckpointer {
    fn capture(&self, step: mvm_client::agent_prompt::StepCapture<'_>) -> Result<CheckpointMeta> {
        let name = step.vm_name;
        let backend = backend_for_vm(name);
        ensure_save_restore_supported("checkpoint a prompt step", &backend)?;
        if !vm_is_running(name) {
            bail!("a prompt step checkpoint requires a running VM; '{name}' is not running");
        }
        let state_dir = vm_state_dir(name);
        let (_input_lock, input_cursor) = lock_machine_input_cursor(name)?;
        let store = CheckpointStore::open();
        let now = now_unix();
        let cursor = step.session.journal_cursor;
        let meta = capture_vm_full_for_running_vm(CaptureVmFullArgs {
            name,
            state_dir: &state_dir,
            store: &store,
            backend: &backend,
            id: CheckpointId::new(format!("ckpt-{name}-prompt-{cursor}-{now}")),
            tag: Some(format!("prompt-step-{cursor}")),
            created_unix: now,
            step: Some(SessionStep {
                parent: step.parent,
                session: step.session,
            }),
        })
        .with_context(|| format!("capturing the prompt step checkpoint of {name:?}"))?;
        let meta = seal_machine_input_cursor(&store, &meta, input_cursor)?;
        bind_checkpoint_created(name, &meta);
        Ok(meta)
    }
}
