//! User-facing warm fork/restore surface for `mvmctl machine warm-restore`.
//!
//! This routes into the Firecracker vm_full fork helpers in
//! `commands::vm::checkpoint`, but presents a focused, backend-agnostic
//! machine-level verb.

use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::{CheckpointClass, CheckpointId};
use mvm_core::config::vm_state_dir;
use mvm_runtime::checkpoint::CheckpointStore;

/// User-facing input to [`fork_vm_full_machine`].
pub(in crate::commands) struct ForkVmFullMachineInput {
    /// Checkpoint id to warm-restore.
    pub checkpoint_id: String,
    /// Desired child VM name; auto-generated if omitted.
    pub child_vm_name: Option<String>,
    /// Emit machine-readable JSON instead of human text.
    pub json: bool,
}

/// User-facing Firecracker vm_full warm fork/restore.
///
/// Validates the checkpoint, generates a fresh child identity, admits a new
/// claim-8 plan, restores the saved machine state through the FC fork path,
/// and delivers the post-restore generation token. The user-facing verb
/// implicitly opts into the experimental Firecracker vm_full fork path, so
/// the lower-level env-var guard is bypassed here.
pub(in crate::commands) fn fork_vm_full_machine(input: ForkVmFullMachineInput) -> Result<()> {
    let checkpoint = crate::commands::vm::checkpoint::validated_checkpoint_id(&input.checkpoint_id)
        .with_context(|| format!("invalid checkpoint id {:?}", input.checkpoint_id))?;
    let store = CheckpointStore::open();
    let parent_meta = store
        .read_meta(&checkpoint)
        .with_context(|| format!("reading checkpoint {}", input.checkpoint_id))?;

    if parent_meta.class != CheckpointClass::VmFull {
        bail!(
            "checkpoint '{}' is class {:?}; warm-restore only supports vm_full checkpoints",
            input.checkpoint_id,
            parent_meta.class,
        );
    }

    let now = crate::commands::vm::checkpoint::now_unix();
    let child_vm_name = input
        .child_vm_name
        .unwrap_or_else(|| format!("{}-warm-{now}", checkpoint.as_str()));
    mvm_core::naming::validate_vm_name(&child_vm_name)
        .with_context(|| format!("invalid child VM name {child_vm_name:?}"))?;
    let dest_dir = vm_state_dir(&child_vm_name);
    let child_id = CheckpointId::new(format!("fork-{child_vm_name}-{now}"));

    crate::commands::vm::checkpoint::fork_vm_full_arm_fc(
        crate::commands::vm::checkpoint::ForkVmFullArmFcParams {
            store: &store,
            checkpoint: &checkpoint,
            parent_meta,
            child_vm_name,
            dest_dir,
            child_id,
            now,
            json: input.json,
            bypass_experimental_guard: true,
        },
    )?;
    Ok(())
}
