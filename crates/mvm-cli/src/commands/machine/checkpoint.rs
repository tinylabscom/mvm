//! User-facing fork/restore surface for `mvmctl machine fork` and
//! `mvmctl machine restore`.
//!
//! These verbs sit on top of the consolidated `VmBackend`/checkpoint seam:
//! `fork` captures a running machine as a vm_full checkpoint and then branches
//! it into a fresh child VM; `restore` branches an existing vm_full checkpoint
//! into a fresh child VM. Both deliver new identity, authority, and
//! per-instance secrets through the same admit-and-boot path used by
//! `machine warm-restore`.

use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::CheckpointClass;
use mvm_core::naming;
use mvm_runtime::checkpoint::CheckpointStore;

/// User-facing input to [`fork_machine`].
pub(in crate::commands) struct ForkMachineInput {
    /// Parent machine name (must be running).
    pub parent_name: String,
    /// Explicit child VM name (`--as`).
    pub child_name: Option<String>,
    /// Branch slug for auto-naming (`--branch`).
    pub branch: Option<String>,
    /// Secret bindings explicitly declared for the child.
    pub declared_secrets: Vec<mvm_core::plan::SecretBinding>,
    /// Whether omitting a parent binding is intentional.
    pub allow_secret_drop: bool,
    /// Emit machine-readable JSON instead of human text.
    pub json: bool,
}

/// User-facing input to [`restore_machine`].
pub(in crate::commands) struct RestoreMachineInput {
    /// vm_full checkpoint id to restore.
    pub checkpoint_id: String,
    /// Explicit child VM name (`--as`).
    pub child_name: Option<String>,
    /// Branch slug for auto-naming (`--branch`).
    pub branch: Option<String>,
    /// Secret bindings explicitly declared for the child.
    pub declared_secrets: Vec<mvm_core::plan::SecretBinding>,
    /// Whether omitting a parent binding is intentional.
    pub allow_secret_drop: bool,
    /// Emit machine-readable JSON instead of human text.
    pub json: bool,
}

/// User-facing `machine fork`: capture a running machine and branch it into a
/// fresh child VM with a new identity.
///
/// The implementation first snapshots the parent as a vm_full checkpoint via
/// the backend's pause/save/resume control, then forks that checkpoint using
/// the same path as `machine warm-restore`. The intermediate checkpoint id is
/// left in the store so the caller can inspect or remove it.
pub(in crate::commands) fn fork_machine(input: ForkMachineInput) -> Result<()> {
    naming::validate_id(&input.parent_name, "machine name")
        .with_context(|| format!("invalid parent machine name {:?}", input.parent_name))?;
    let child_name = resolve_child_name(
        &input.parent_name,
        input.child_name.as_deref(),
        input.branch.as_deref(),
        false,
    )?;
    let checkpoint_id =
        crate::commands::vm::checkpoint::capture_vm_full_for_machine(&input.parent_name, None)
            .with_context(|| format!("capturing full-VM snapshot of {}", input.parent_name))?;

    fork_vm_full_machine(ForkVmFullMachineInput {
        checkpoint_id: checkpoint_id.as_str().to_string(),
        child_vm_name: Some(child_name),
        declared_secrets: input.declared_secrets,
        allow_secret_drop: input.allow_secret_drop,
        json: input.json,
    })
    .with_context(|| format!("forking child from checkpoint {}", checkpoint_id.as_str()))?;
    Ok(())
}

/// User-facing `machine restore`: branch an existing vm_full checkpoint into a
/// fresh child VM with a new identity.
///
/// Unlike `vm checkpoint restore`, this does not resume the same identity; it
/// treats the checkpoint as an immutable parent and admits a new claim-8 plan
/// for the child.
pub(in crate::commands) fn restore_machine(input: RestoreMachineInput) -> Result<()> {
    let checkpoint = crate::commands::vm::checkpoint::validated_checkpoint_id(&input.checkpoint_id)
        .with_context(|| format!("invalid checkpoint id {:?}", input.checkpoint_id))?;
    let store = CheckpointStore::open();
    let parent_meta = store
        .read_meta(&checkpoint)
        .with_context(|| format!("reading checkpoint {}", input.checkpoint_id))?;

    if parent_meta.class != CheckpointClass::VmFull {
        bail!(
            "checkpoint '{}' is class {:?}; restore only supports vm_full checkpoints",
            input.checkpoint_id,
            parent_meta.class,
        );
    }

    let child_name = resolve_child_name(
        input.checkpoint_id.as_str(),
        input.child_name.as_deref(),
        input.branch.as_deref(),
        false,
    )?;

    fork_vm_full_machine(ForkVmFullMachineInput {
        checkpoint_id: input.checkpoint_id,
        child_vm_name: Some(child_name),
        declared_secrets: input.declared_secrets,
        allow_secret_drop: input.allow_secret_drop,
        json: input.json,
    })?;
    Ok(())
}

/// User-facing input to [`fork_vm_full_machine`].
pub(in crate::commands) struct ForkVmFullMachineInput {
    /// Checkpoint id to warm-restore.
    pub checkpoint_id: String,
    /// Desired child VM name; auto-generated if omitted.
    pub child_vm_name: Option<String>,
    /// Secret bindings explicitly declared for the child.
    pub declared_secrets: Vec<mvm_core::plan::SecretBinding>,
    /// Whether omitting a parent binding is intentional.
    pub allow_secret_drop: bool,
    /// Emit machine-readable JSON instead of human text.
    pub json: bool,
}

/// User-facing vm_full warm fork/restore.
///
/// Validates the checkpoint, generates a fresh child identity, admits a new
/// claim-8 plan, restores the saved machine state through the backend fork
/// path, and delivers the post-restore generation token. The user-facing verb
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

    let child_vm_name = input.child_vm_name.unwrap_or_else(|| {
        format!(
            "{}-warm-{}",
            checkpoint.as_str(),
            crate::commands::vm::checkpoint::now_unix()
        )
    });
    naming::validate_vm_name(&child_vm_name)
        .with_context(|| format!("invalid child VM name {child_vm_name:?}"))?;

    crate::commands::vm::checkpoint::fork_vm_full_arm(
        crate::commands::vm::checkpoint::ForkVmFullArmParams {
            store: &store,
            checkpoint: &checkpoint,
            new_id: Some(child_vm_name),
            cpus_override: None,
            memory_override: None,
            json: input.json,
            bypass_experimental_guard: true,
            declared_secrets: &input.declared_secrets,
            allow_secret_drop: input.allow_secret_drop,
        },
    )
}

/// Resolve the child VM name from explicit `--as`, `--branch`, or a default.
///
/// * `--as <name>` is used verbatim.
/// * `--branch <slug>` produces `<parent>-<slug>-<timestamp>`.
/// * Neither produces `<parent>-fork-<timestamp>` unless `require_explicit` is
///   true (used by `restore`, where a long checkpoint id is a poor default).
fn resolve_child_name(
    parent: &str,
    explicit: Option<&str>,
    branch: Option<&str>,
    require_explicit: bool,
) -> Result<String> {
    if let Some(name) = explicit {
        naming::validate_id(name, "child machine name")
            .with_context(|| format!("invalid child name {name:?}"))?;
        return Ok(name.to_string());
    }
    let now = crate::commands::vm::checkpoint::now_unix();
    if let Some(branch) = branch {
        naming::validate_id(branch, "branch name")
            .with_context(|| format!("invalid branch name {branch:?}"))?;
        return Ok(format!("{parent}-{branch}-{now}"));
    }
    if require_explicit {
        bail!("--as <NAME> or --branch <BRANCH> is required");
    }
    Ok(format!("{parent}-fork-{now}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::{
        CheckpointId, CheckpointMeta, ContentBlob, HVF_FRAME_BLOB, SUPERVISOR_CONFIG_BLOB,
    };

    fn write_vm_full_checkpoint(store: &CheckpointStore, id: &str, state_blob: &str) {
        let meta = CheckpointMeta::builder(
            CheckpointId::new(id),
            CheckpointClass::VmFull,
            "parent-machine",
        )
        .content(vec![ContentBlob {
            name: state_blob.to_string(),
            sha256: "00".repeat(32),
        }])
        .build();
        store.write_meta(&meta).unwrap();
    }

    #[test]
    fn resolve_explicit_child_name() {
        assert_eq!(
            resolve_child_name("parent", Some("child"), None, false).unwrap(),
            "child"
        );
    }

    #[test]
    fn resolve_branch_child_name() {
        let name = resolve_child_name("parent", None, Some("feature-x"), false).unwrap();
        assert!(name.starts_with("parent-feature-x-"), "got {name}");
    }

    #[test]
    fn resolve_default_child_name() {
        let name = resolve_child_name("parent", None, None, false).unwrap();
        assert!(name.starts_with("parent-fork-"), "got {name}");
    }

    #[test]
    fn resolve_restore_requires_explicit_or_branch() {
        assert!(resolve_child_name("ckpt-abc", None, None, true).is_err());
    }

    #[test]
    fn resolve_rejects_invalid_explicit() {
        assert!(resolve_child_name("parent", Some("Bad Name"), None, false).is_err());
    }

    #[test]
    fn resolve_rejects_invalid_branch() {
        assert!(resolve_child_name("parent", None, Some("bad/name"), false).is_err());
    }

    #[test]
    fn machine_restore_dispatches_hvf_checkpoint_away_from_firecracker() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let store = CheckpointStore::open();
        write_vm_full_checkpoint(&store, "hvf-parent", HVF_FRAME_BLOB);

        let error = fork_vm_full_machine(ForkVmFullMachineInput {
            checkpoint_id: "hvf-parent".to_string(),
            child_vm_name: Some("hvf-child".to_string()),
            declared_secrets: Vec::new(),
            allow_secret_drop: false,
            json: false,
        })
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            !message.contains("Firecracker machine state"),
            "an HVF checkpoint must never enter the Firecracker arm: {message}"
        );
    }

    #[test]
    fn machine_restore_refuses_retired_backend_through_shared_dispatch() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let store = CheckpointStore::open();
        write_vm_full_checkpoint(&store, "retired-parent", SUPERVISOR_CONFIG_BLOB);

        let error = fork_vm_full_machine(ForkVmFullMachineInput {
            checkpoint_id: "retired-parent".to_string(),
            child_vm_name: Some("retired-child".to_string()),
            declared_secrets: Vec::new(),
            allow_secret_drop: false,
            json: false,
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("backend that has been removed"),
            "the shared dispatcher must preserve the retired-backend refusal: {error:#}"
        );
    }
}
