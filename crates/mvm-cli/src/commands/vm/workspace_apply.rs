//! `mvmctl machine apply|undo|redo` — the reviewed workspace apply and its
//! history navigation.
//!
//! A workspace is a private copy of a host directory; nothing the guest
//! writes reaches the host tree by itself. `apply` is the one write-back
//! path: it plans from the diff between the image the workspace began as
//! and the guest's current image, shows the operator what would change,
//! and only on confirmation snapshots every host byte it will replace into
//! a content-addressed store, journals the apply, and writes through atomic
//! renames. `undo` and `redo` walk that journal, restoring pre-images or
//! re-applying post-images — each reversal is itself a journaled apply, so
//! a crash at any point is recoverable.

use std::io::IsTerminal as _;
use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Args;
use mvm_contract::policy::protected_paths::{
    ProtectedPath, ProtectedPathSet, ProtectedPathsPolicy,
};
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;
use mvm_fs::tree_diff::Ext4Tree;
use mvm_fs::workspace_apply::store::ApplyStore;
use mvm_fs::workspace_apply::{ApplyPlan, PlanParams};
use mvm_hostd::audit::emitter::{
    AuditEmitter, WorkspaceMutationAudit, WorkspaceSnapshotAudit, workspace_audit,
};

use super::workspace::Workspace;
use super::{diff, workspace};

#[derive(Args, Debug, Clone)]
pub(in crate::commands) struct ApplyArgs {
    /// Persistent machine name.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Apply only this workspace volume (required when the machine has more
    /// than one).
    #[arg(long, value_name = "VOLUME")]
    pub volume: Option<String>,
    /// A path the apply must never write or delete (repeatable; the
    /// protected CI/build/test classes are always in force).
    #[arg(long, value_name = "GLOB")]
    pub exclude: Vec<String>,
    /// Extend the protected-path set with an operator pattern (repeatable).
    #[arg(long, value_name = "GLOB")]
    pub protected_path: Vec<String>,
    /// Apply without prompting (required when stdin is not a terminal).
    #[arg(long)]
    pub yes: bool,
    /// Plan and report without staging or writing anything.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub(in crate::commands) struct UndoArgs {
    /// Persistent machine name.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Undo the latest apply to this workspace volume.
    #[arg(long, value_name = "VOLUME")]
    pub volume: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub(in crate::commands) struct RedoArgs {
    /// Persistent machine name.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Redo the latest undone apply on this workspace volume.
    #[arg(long, value_name = "VOLUME")]
    pub volume: Option<String>,
}

pub(in crate::commands) fn run_apply(
    _cli: &super::Cli,
    args: ApplyArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;
    let selected = select_workspace(&args.name, args.volume.as_deref())?;
    let store = open_recovered_store(&args.name, &selected)?;

    // The guest's writes reach the disk before we plan: same flush the diff
    // verb performs.
    if mvm_runtime::checkpoint::vm_is_running(&args.name) {
        diff::flush_guest(&args.name)?;
    }
    let baseline = Ext4Tree::open(&workspace::baseline_image(&selected)?)?;
    let live_image = Ext4Tree::open(&selected.image)?;
    let protected = protected_set(&args.protected_path)?;
    let exclusion_paths: Vec<ProtectedPath> = args
        .exclude
        .iter()
        .map(|pattern| ProtectedPath::new(pattern.as_str()))
        .collect();
    let exclusions = ProtectedPathSet::new(exclusion_paths.iter());
    let params = PlanParams::new(&baseline, &live_image, &selected.source_dir)
        .with_protected(&protected)
        .with_exclusions(&exclusions);
    let mut plan = store.plan(&params)?;
    plan.exclusion_patterns = args.exclude.clone();

    if !plan.refused_protected.is_empty() || !plan.refused_unappliable.is_empty() {
        report_refusals(&plan);
        mvm_core::audit_emit!(
            WorkspaceApply,
            vm: &args.name,
            "action=workspace.apply outcome=refused volume={} refused={}",
            selected.volume,
            plan.refused_protected.len() + plan.refused_unappliable.len()
        );
        bail!("refusing the apply");
    }
    if plan.ops.is_empty() {
        crate::ui::notice("no changes to apply");
        return Ok(());
    }

    crate::ui::info(&format!(
        "{} change(s) to {}: {} write(s), {} removal(s){}",
        plan.ops.len(),
        selected.source_dir.display(),
        plan.ops
            .iter()
            .filter(|op| !matches!(op.action, mvm_fs::workspace_apply::OpAction::Remove))
            .count(),
        plan.ops
            .iter()
            .filter(|op| matches!(op.action, mvm_fs::workspace_apply::OpAction::Remove))
            .count(),
        if plan.skipped_excluded.is_empty() {
            String::new()
        } else {
            format!(", {} excluded", plan.skipped_excluded.len())
        }
    ));

    if args.dry_run {
        for op in &plan.ops {
            println!("  {}", op_summary(op));
        }
        crate::ui::notice("dry run: nothing staged, nothing written");
        return Ok(());
    }

    ensure_apply_authorized(args.yes, std::io::stdin().is_terminal())?;
    if !args.yes {
        print!("Apply to working tree? [y/N] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            crate::ui::notice("not applied");
            return Ok(());
        }
    }

    let emitter = workspace_audit_emitter()?;
    let staged = store.stage(plan, &selected.source_dir, &live_image, None)?;
    let snapshot_root = staged.snapshot_merkle_root();
    let snapshot_plan = workspace_audit_plan(
        &args.name,
        &selected.volume,
        "workspace:snapshot",
        &snapshot_root,
    )?;
    let audit_plan = workspace_audit_plan(
        &args.name,
        &selected.volume,
        "workspace:apply",
        staged.merkle_root(),
    )?;
    record_snapshot_then_commit(
        || {
            emitter.emit_workspace_snapshot(
                &snapshot_plan,
                WorkspaceSnapshotAudit {
                    vm_name: &args.name,
                    volume: &selected.volume,
                    apply_id: staged.id(),
                    snapshot_root: &snapshot_root,
                    manifest_root: staged.merkle_root(),
                },
            )
        },
        || {
            store
                .commit(&staged, &selected.source_dir)
                .map_err(Into::into)
        },
    )?;
    emitter
        .emit_workspace_mutation(
            &audit_plan,
            WorkspaceMutationAudit {
                event: workspace_audit::APPLIED_EVENT,
                vm_name: &args.name,
                volume: &selected.volume,
                apply_id: staged.id(),
                target_id: None,
                merkle_root: staged.merkle_root(),
            },
        )
        .context("recording the workspace apply in the signed audit chain")?;
    mvm_core::audit_emit!(
        WorkspaceApply,
        vm: &args.name,
        "action=workspace.apply outcome=applied volume={} files={} merkle_root={}",
        selected.volume,
        staged.manifest().ops.len(),
        staged.merkle_root()
    );
    crate::ui::success(&format!(
        "applied {} change(s); snapshot merkle root {}; apply manifest root {}",
        staged.manifest().ops.len(),
        snapshot_root,
        staged.merkle_root()
    ));
    Ok(())
}

/// The staged pre-images must reach the signed chain before any host write.
/// A refused audit append leaves the host tree untouched for recovery.
fn record_snapshot_then_commit(
    record_snapshot: impl FnOnce() -> Result<()>,
    commit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    record_snapshot().context("recording the host pre-apply snapshot in the signed audit chain")?;
    commit()
}

pub(in crate::commands) fn run_undo(
    _cli: &super::Cli,
    args: UndoArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;
    let selected = select_workspace(&args.name, args.volume.as_deref())?;
    let store = open_recovered_store(&args.name, &selected)?;
    let emitter = workspace_audit_emitter()?;
    let Some(applied) = store.undo_latest(&selected.source_dir)? else {
        crate::ui::notice("nothing to undo");
        return Ok(());
    };
    let audit_plan = workspace_audit_plan(
        &args.name,
        &selected.volume,
        "workspace:undo",
        &applied.merkle_root,
    )?;
    emitter
        .emit_workspace_mutation(
            &audit_plan,
            WorkspaceMutationAudit {
                event: workspace_audit::UNDONE_EVENT,
                vm_name: &args.name,
                volume: &selected.volume,
                apply_id: &applied.apply_id,
                target_id: Some(&applied.target_id),
                merkle_root: &applied.merkle_root,
            },
        )
        .context("recording the workspace undo in the signed audit chain")?;
    mvm_core::audit_emit!(
        WorkspaceUndo,
        vm: &args.name,
        "action=workspace.undo volume={} undo={} target={} merkle_root={}",
        selected.volume,
        applied.apply_id,
        applied.target_id,
        applied.merkle_root
    );
    crate::ui::success(&format!("undid apply {}", applied.target_id));
    Ok(())
}

pub(in crate::commands) fn run_redo(
    _cli: &super::Cli,
    args: RedoArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;
    let selected = select_workspace(&args.name, args.volume.as_deref())?;
    let store = open_recovered_store(&args.name, &selected)?;
    let emitter = workspace_audit_emitter()?;
    let Some(applied) = store.redo_latest(&selected.source_dir)? else {
        crate::ui::notice("nothing to redo");
        return Ok(());
    };
    let audit_plan = workspace_audit_plan(
        &args.name,
        &selected.volume,
        "workspace:redo",
        &applied.merkle_root,
    )?;
    emitter
        .emit_workspace_mutation(
            &audit_plan,
            WorkspaceMutationAudit {
                event: workspace_audit::REDONE_EVENT,
                vm_name: &args.name,
                volume: &selected.volume,
                apply_id: &applied.apply_id,
                target_id: Some(&applied.target_id),
                merkle_root: &applied.merkle_root,
            },
        )
        .context("recording the workspace redo in the signed audit chain")?;
    mvm_core::audit_emit!(
        WorkspaceRedo,
        vm: &args.name,
        "action=workspace.redo volume={} redo={} target={} merkle_root={}",
        selected.volume,
        applied.apply_id,
        applied.target_id,
        applied.merkle_root
    );
    crate::ui::success(&format!("redid apply {}", applied.target_id));
    Ok(())
}

/// The prompt gate: `--yes` always authorizes; without it a terminal is
/// required so the reviewed apply is never a silent non-interactive write.
fn ensure_apply_authorized(yes: bool, is_tty: bool) -> Result<()> {
    if yes || is_tty {
        return Ok(());
    }
    bail!("not applying without a terminal; pass --yes to apply non-interactively")
}

/// The workspace to act on: the machine's only one, or the `--volume` pick.
fn select_workspace(vm: &str, volume: Option<&str>) -> Result<Workspace> {
    let all = workspace::workspaces_of(vm)?;
    if all.is_empty() {
        bail!(
            "machine {vm:?} has no workspace volume; attach a host directory read-write with \
             `mvmctl machine volume mount {vm} --volume NAME --host DIR --guest PATH --rw`"
        );
    }
    match volume {
        Some(name) => all
            .into_iter()
            .find(|w| w.volume == name)
            .with_context(|| format!("machine {vm:?} has no workspace volume {name:?}")),
        None => {
            if all.len() > 1 {
                let names: Vec<&str> = all.iter().map(|w| w.volume.as_str()).collect();
                bail!(
                    "machine {vm:?} has several workspace volumes ({}); pass --volume",
                    names.join(", ")
                )
            }
            Ok(all.into_iter().next().expect("one workspace"))
        }
    }
}

/// The store for one workspace, with an interrupted apply rolled back first.
fn open_recovered_store(vm: &str, selected: &Workspace) -> Result<ApplyStore> {
    let store = ApplyStore::open(apply_store_root(vm, &selected.volume))?;
    if let Some(rolled_back) = store.recover_source(&selected.source_dir)? {
        crate::ui::warn(&format!(
            "rolled back an interrupted apply ({rolled_back}) before continuing"
        ));
    }
    Ok(store)
}

fn apply_store_root(vm: &str, volume: &str) -> PathBuf {
    mvm_core::config::machine_state_dir(vm)
        .join("workspace-applies")
        .join(volume)
}

fn workspace_audit_emitter() -> Result<AuditEmitter> {
    let signer = super::host_signer::load_or_init()
        .context("loading the host signer for workspace mutation audit")?;
    AuditEmitter::new(signer.signing)
        .map(AuditEmitter::with_receipts)
        .context("opening the signed audit chain for workspace mutation")
}

fn workspace_audit_plan(
    vm: &str,
    volume: &str,
    intent: &str,
    merkle_root: &str,
) -> Result<mvm_core::plan::ExecutionPlan> {
    crate::commands::build::image_lineage::build_event_plan(
        "workspace-mutation",
        intent,
        &format!("workspace-{vm}-{volume}"),
        merkle_root,
    )
    .context("building the workspace mutation audit envelope")
}

/// The protected set in force: the shipped default classes plus the
/// operator's `--protected-path` extensions. (No silent downgrade switch:
/// relaxing the gate is not part of the apply surface.)
fn protected_set(operator: &[String]) -> Result<ProtectedPathSet> {
    let policy = ProtectedPathsPolicy::default();
    let matcher = policy
        .matcher()
        .context("the default protected set is off")?;
    if operator.is_empty() {
        return Ok(matcher);
    }
    let paths: Vec<ProtectedPath> = policy
        .paths
        .iter()
        .cloned()
        .chain(operator.iter().map(|p| ProtectedPath::new(p.as_str())))
        .collect();
    Ok(ProtectedPathSet::new(paths.iter()))
}

fn report_refusals(plan: &ApplyPlan) {
    crate::ui::warn("the apply is refused:");
    for (path, class) in plan
        .refused_protected
        .iter()
        .chain(plan.refused_unappliable.iter())
    {
        println!("  {path} ({class})");
    }
}

fn op_summary(op: &mvm_fs::workspace_apply::FileOp) -> String {
    match &op.action {
        mvm_fs::workspace_apply::OpAction::WriteFile => format!("write {}", op.path),
        mvm_fs::workspace_apply::OpAction::WriteSymlink { target } => {
            format!("link {} -> {target}", op.path)
        }
        mvm_fs::workspace_apply::OpAction::Remove => format!("remove {}", op.path),
    }
}

#[cfg(test)]
mod tests {
    use super::{ensure_apply_authorized, record_snapshot_then_commit};
    use anyhow::anyhow;
    use std::cell::RefCell;

    #[test]
    fn yes_authorizes_without_a_terminal() {
        assert!(ensure_apply_authorized(true, false).is_ok());
    }

    #[test]
    fn a_terminal_authorizes_the_prompt() {
        assert!(ensure_apply_authorized(false, true).is_ok());
    }

    #[test]
    fn no_terminal_and_no_yes_refuses() {
        let err = ensure_apply_authorized(false, false).expect_err("must refuse");
        assert!(err.to_string().contains("--yes"), "{err}");
    }

    #[test]
    fn snapshot_audit_precedes_host_commit() {
        let order = RefCell::new(Vec::new());
        record_snapshot_then_commit(
            || {
                order.borrow_mut().push("snapshot");
                Ok(())
            },
            || {
                order.borrow_mut().push("commit");
                Ok(())
            },
        )
        .expect("both steps succeed");
        assert_eq!(*order.borrow(), ["snapshot", "commit"]);
    }

    #[test]
    fn snapshot_audit_failure_prevents_host_commit() {
        let committed = std::cell::Cell::new(false);
        let error = record_snapshot_then_commit(
            || Err(anyhow!("audit unavailable")),
            || {
                committed.set(true);
                Ok(())
            },
        )
        .expect_err("audit refusal must stop commit");
        assert!(!committed.get());
        assert!(error.to_string().contains("pre-apply snapshot"));
    }

    #[test]
    fn a_commit_failure_is_reported_after_the_snapshot() {
        let recorded = std::cell::Cell::new(false);
        let error = record_snapshot_then_commit(
            || {
                recorded.set(true);
                Ok(())
            },
            || Err(anyhow!("host write refused")),
        )
        .expect_err("commit error must propagate");
        assert!(recorded.get());
        assert!(error.to_string().contains("host write refused"));
    }
}
