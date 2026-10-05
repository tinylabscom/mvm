//! `mvmctl machine replay <checkpoint>` — re-run recorded input from a
//! checkpoint's state.
//!
//! The input journal on the machine that created the checkpoint records
//! every `machine exec` argv in order (never the output). A replay:
//!
//! 1. reads the exact input cursor sealed into the checkpoint and selects
//!    later journal entries — everything through the cursor is already part
//!    of the checkpoint's frozen state;
//! 2. fork-boots the checkpoint exactly like `machine revert` does — a
//!    fresh, re-admitted VM whose workspace images are the checkpoint's
//!    frozen copies, so the re-run starts from byte-identical state;
//! 3. re-executes each selected entry against the restored VM and takes a
//!    vm-full checkpoint after each one, so every replayed step is itself
//!    a restore point (`--step-checkpoints=false` skips this);
//! 4. leaves the restored VM running, with the step checkpoints listed
//!    under `checkpoint ls`.
//!
//! Replay never touches the original machine, its journal, or any host
//! directory: it is a fork. A mid-replay failure leaves the restored VM
//! running at the last good step; the operator stops or re-replays it.

use anyhow::{Context, Result, bail};
use clap::Args;
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;
use mvm_runtime::checkpoint::vm_is_running;

use super::checkpoint::{self, validated_checkpoint_id};
use super::workspace;
use crate::commands::machine::{MachineExecArgs, input_journal, lifecycle};

#[derive(Args, Debug, Clone)]
pub(in crate::commands) struct ReplayArgs {
    /// Checkpoint id to replay from.
    #[arg(value_name = "CHECKPOINT")]
    pub from: String,
    /// Name for the restored, replayed machine (default: auto-named).
    #[arg(long = "as", value_name = "NAME")]
    pub as_name: Option<String>,
    /// Report the replay plan (selected entries, step count) without
    /// restoring or executing anything.
    #[arg(long)]
    pub dry_run: bool,
    /// Take a vm-full checkpoint after each replayed step (default: true).
    #[arg(long = "no-step-checkpoints", action = clap::ArgAction::SetFalse)]
    pub step_checkpoints: bool,
}

pub(in crate::commands) fn run_replay(
    cli: &super::Cli,
    args: ReplayArgs,
    cfg: &MvmConfig,
) -> Result<()> {
    let id = validated_checkpoint_id(&args.from)?;
    let store = mvm_runtime::checkpoint::CheckpointStore::open();
    let meta = store
        .read_meta(&id)
        .with_context(|| format!("no checkpoint {:?} found", id.as_str()))?;

    let plan = plan_replay(&store, &meta, &args)?;

    if args.dry_run {
        print_plan(&plan);
        return Ok(());
    }
    if plan.entries.is_empty() {
        crate::ui::notice("nothing to replay: no input recorded at or after the checkpoint");
        return Ok(());
    }

    mvm_core::audit_emit!(
        MachineReplay,
        vm: &plan.restored_name,
        "action=replay.begin from={} source_vm={} entries={} step_checkpoints={}",
        id.as_str(),
        meta.vm_name,
        plan.entries.len(),
        plan.step_checkpoints
    );

    // Fork-boot the checkpoint exactly like `machine revert`: a fresh,
    // re-admitted VM whose state is the checkpoint's frozen copy.
    checkpoint::fork(checkpoint::ForkCmdParams {
        id: id.as_str(),
        new_id: Some(plan.restored_name.clone()),
        boot: true,
        hypervisor: "",
        cpus: None,
        memory: None,
        declared_secrets: &[],
        allow_secret_drop: false,
        json: false,
        intent: checkpoint::ForkIntent::Replay,
    })
    .with_context(|| format!("restoring checkpoint {:?} for replay", id.as_str()))?;

    let mut completed = 0usize;
    for entry in &plan.entries {
        let exec = MachineExecArgs {
            name: plan.restored_name.clone(),
            force: false,
            tty: false,
            interactive: false,
            tool: None,
            argv: entry.argv.clone(),
        };
        lifecycle::exec_machine(cli, exec, cfg).with_context(|| {
            format!("replaying step {} ({:?})", entry.seq, entry.argv.join(" "))
        })?;
        completed += 1;
        if plan.step_checkpoints {
            step_checkpoint(&plan.restored_name, entry.seq)?;
        }
    }

    mvm_core::audit_emit!(
        MachineReplay,
        vm: &plan.restored_name,
        "action=replay.end from={} steps={}",
        id.as_str(),
        completed
    );
    crate::ui::success(&format!(
        "replayed {} step(s) from {} onto {:?}; the machine is running",
        completed,
        id.as_str(),
        plan.restored_name
    ));
    Ok(())
}

/// The replay plan: pure enough to dry-run and unit-test.
#[derive(Debug)]
struct ReplayPlan {
    restored_name: String,
    entries: Vec<input_journal::InputEntry>,
    step_checkpoints: bool,
}

fn plan_replay(
    store: &mvm_runtime::checkpoint::CheckpointStore,
    meta: &mvm_core::checkpoint::CheckpointMeta,
    args: &ReplayArgs,
) -> Result<ReplayPlan> {
    let _ = store;
    let entries = input_journal::read(&mvm_core::config::machine_state_dir(&meta.vm_name))
        .with_context(|| format!("reading the input journal of {:?}", meta.vm_name))?;
    let cursor = meta.machine_input_cursor.with_context(|| {
        format!(
            "checkpoint {:?} predates exact machine-input cursors and cannot be replayed safely",
            meta.id.as_str()
        )
    })?;
    let selected = input_journal::select_after_cursor(&entries, cursor);
    let restored_name = match &args.as_name {
        Some(name) => {
            validate_vm_name(name).with_context(|| format!("Invalid VM name: {name:?}"))?;
            if vm_is_running(name) {
                bail!("a VM named {name:?} is already running; stop it or pick another --as name");
            }
            if mvm_runtime::machine::persist::load_machine_spec(name).is_ok() {
                bail!("a machine named {name:?} already exists; pick another --as name");
            }
            name.clone()
        }
        None => format!("replay-{}-{}", meta.id.as_str(), checkpoint::now_unix()),
    };
    Ok(ReplayPlan {
        restored_name,
        entries: selected,
        step_checkpoints: args.step_checkpoints,
    })
}

fn print_plan(plan: &ReplayPlan) {
    println!("replay onto {:?}", plan.restored_name);
    if plan.entries.is_empty() {
        println!("  no input recorded at or after the checkpoint");
        return;
    }
    for entry in &plan.entries {
        println!("  step {}: {}", entry.seq, entry.argv.join(" "));
    }
    println!(
        "  {} step(s), step checkpoints {}",
        plan.entries.len(),
        if plan.step_checkpoints { "on" } else { "off" }
    );
}

/// A per-step checkpoint of the replayed machine. The vm-full capture is
/// the preferred form — it freezes memory and every workspace volume, so
/// the step is a first-class restore point under `checkpoint ls`. A
/// backend without save/restore support falls back to a workspace-image
/// copy under the machine's state dir, and says so.
fn step_checkpoint(name: &str, seq: u64) -> Result<()> {
    match checkpoint::capture_vm_full_for_machine(name, Some(format!("replay-step-{seq}"))) {
        Ok(id) => {
            crate::ui::info(&format!("step {seq}: checkpoint {id}", id = id.as_str()));
            Ok(())
        }
        Err(capture_error) => {
            let dir = mvm_core::config::vm_state_dir(name).join("replay-steps");
            std::fs::create_dir_all(&dir)?;
            let workspaces = workspace::workspaces_of(name)?;
            if workspaces.is_empty() {
                // Nothing meaningful to snapshot beyond the memory image the
                // backend refused; surface the real error.
                return Err(capture_error).context("taking the per-step checkpoint");
            }
            for ws in &workspaces {
                let target = dir.join(format!("step-{seq}-{}.ext4", ws.volume));
                std::fs::copy(&ws.image, &target)?;
            }
            crate::ui::warn(&format!(
                "step {seq}: backend capture unsupported ({capture_error:#}); \
                 workspace images copied to {} instead",
                dir.display()
            ));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::CheckpointId;

    fn meta(vm: &str, created_unix: u64) -> mvm_core::checkpoint::CheckpointMeta {
        mvm_core::checkpoint::CheckpointMeta::builder(
            CheckpointId::new("ckpt-x"),
            mvm_core::checkpoint::CheckpointClass::VmFull,
            vm.to_string(),
        )
        .created_unix(created_unix)
        .machine_input_cursor(Some(1))
        .build()
    }

    #[test]
    fn an_explicit_name_must_be_valid_and_free() {
        let args = ReplayArgs {
            from: "ckpt-x".into(),
            as_name: Some("bad name!".into()),
            dry_run: true,
            step_checkpoints: true,
        };
        let store = mvm_runtime::checkpoint::CheckpointStore::open();
        let err = plan_replay(&store, &meta("web", 0), &args).expect_err("invalid name");
        assert!(err.to_string().contains("Invalid VM name"), "{err}");
    }

    #[test]
    fn the_default_name_carries_the_checkpoint_and_timestamp() {
        let args = ReplayArgs {
            from: "ckpt-x".into(),
            as_name: None,
            dry_run: true,
            step_checkpoints: true,
        };
        let store = mvm_runtime::checkpoint::CheckpointStore::open();
        let plan = plan_replay(&store, &meta("web", 0), &args).expect("plan");
        assert!(plan.restored_name.starts_with("replay-ckpt-x-"), "{plan:?}");
        assert!(plan.restored_name.len() > "replay-ckpt-x-".len());
    }

    #[test]
    fn selection_uses_the_checkpoint_cursor_even_with_equal_timestamps() {
        let home = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let state = mvm_core::config::machine_state_dir("web");
        std::fs::create_dir_all(&state).expect("state dir");
        {
            let _lock = input_journal::lock(&state).expect("lock");
            let first = input_journal::begin_exec(&state, &["before".into()]).expect("begin");
            input_journal::finish_exec(&state, first, true).expect("finish");
            let second = input_journal::begin_exec(&state, &["during".into()]).expect("begin");
            input_journal::finish_exec(&state, second, true).expect("finish");
        }

        let store = mvm_runtime::checkpoint::CheckpointStore::open();
        let args = ReplayArgs {
            from: "ckpt-x".into(),
            as_name: Some("replay-test-child".into()),
            dry_run: true,
            step_checkpoints: true,
        };
        let plan = plan_replay(&store, &meta("web", 100), &args).expect("plan");
        assert_eq!(plan.entries.len(), 1, "{plan:?}");
        assert_eq!(plan.entries[0].argv, ["during"]);
    }
}
