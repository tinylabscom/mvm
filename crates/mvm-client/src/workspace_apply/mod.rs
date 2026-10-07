//! The reviewed workspace apply: the one path by which what a guest wrote in a
//! workspace volume reaches the host directory it was copied from.
//!
//! A workspace is a private copy of a host directory; nothing the guest
//! writes reaches the host tree by itself. [`review`] plans from the diff
//! between the image the workspace began as and the guest's current image,
//! and applies the protected-path gate. It writes nothing. A plan that passes
//! becomes a [`PendingApply`], and only [`WorkspaceApplier::apply`] takes one:
//! it snapshots every host byte the plan will replace into a content-addressed
//! store, records that snapshot in the signed audit chain, journals the apply,
//! writes through atomic renames, and then records the signed
//! `workspace.applied` entry — restoring the snapshot when that entry cannot
//! be shown to have been written. `undo` and `redo` walk the same journal.
//!
//! `mvmctl machine apply` and the prompt a foreground `machine run` shows when
//! it ends both go through here; [`ExitApplyRequest`] decides which of the
//! three exit outcomes a run gets.

mod exit;
#[cfg(test)]
mod tests;

use std::cell::OnceCell;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_contract::policy::protected_paths::{
    ProtectedPath, ProtectedPathSet, ProtectedPathsPolicy,
};
use mvm_fs::tree_diff::Ext4Tree;
use mvm_fs::workspace_apply::store::{ApplyStore, StagedApply};
use mvm_fs::workspace_apply::{PlanParams, plan};
use mvm_hostd::audit::emitter::{
    AuditEmitter, WorkspaceMutationAudit, WorkspaceSnapshotAudit, workspace_audit,
};

pub use exit::{ExitApply, ExitApplyRequest, apply_command, is_affirmative};
pub use mvm_fs::workspace_apply::store::AppliedRelation;
pub use mvm_fs::workspace_apply::{ApplyPlan, FileOp, OpAction};

/// One workspace volume, named by the machine and volume it belongs to and
/// the host directory an apply writes.
#[derive(Debug, Clone, Copy)]
pub struct WorkspaceTarget<'a> {
    pub vm: &'a str,
    pub volume: &'a str,
    pub source_dir: &'a Path,
}

/// The two images a review compares and the operator's path rules.
#[derive(Debug, Clone, Copy)]
pub struct ReviewRequest<'a> {
    /// The image the workspace began as.
    pub baseline_image: &'a Path,
    /// The image the guest writes.
    pub live_image: &'a Path,
    /// Paths the apply must never write or delete; recorded with the apply.
    pub exclude: &'a [String],
    /// Operator patterns added to the shipped protected classes.
    pub protected_paths: &'a [String],
}

/// What a review found.
pub enum Review {
    /// The guest changed a protected path, or a path the host cannot take in
    /// its new form; the whole apply is refused. The plan names every match.
    Refused(ApplyPlan),
    /// Nothing differs from the host tree.
    Unchanged,
    /// A plan that passed the gate, ready for [`WorkspaceApplier::apply`].
    Ready(PendingApply),
}

/// A reviewed plan and the image its post-images come from. Only [`review`]
/// makes one, so an apply cannot be handed a plan that skipped the gate.
pub struct PendingApply {
    plan: ApplyPlan,
    live: Ext4Tree,
}

impl PendingApply {
    #[must_use]
    pub fn plan(&self) -> &ApplyPlan {
        &self.plan
    }
}

/// A committed, signed apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub apply_id: String,
    pub changes: usize,
    /// Root over the host pre-images captured before the first write.
    pub snapshot_root: String,
    /// Root over the apply manifest.
    pub merkle_root: String,
}

/// Work an earlier, interrupted command left behind, settled when a
/// workspace's apply store is opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovered {
    /// An apply that began writing and never finished was rolled back.
    Interrupted(String),
    /// A committed apply with no signed entry was restored and cancelled.
    Unaudited(String),
}

/// Plan an apply of `target` and run the protected-path gate. Writes nothing
/// and opens no apply store, so it has no effect on the host tree.
///
/// A refusal is recorded in the local audit log before it is returned.
pub fn review(target: WorkspaceTarget<'_>, request: &ReviewRequest<'_>) -> Result<Review> {
    let baseline = Ext4Tree::open(request.baseline_image)?;
    let live = Ext4Tree::open(request.live_image)?;
    let protected = protected_set(request.protected_paths)?;
    let exclusion_paths: Vec<ProtectedPath> = request
        .exclude
        .iter()
        .map(|pattern| ProtectedPath::new(pattern.as_str()))
        .collect();
    let exclusions = ProtectedPathSet::new(exclusion_paths.iter());
    let params = PlanParams::new(&baseline, &live, target.source_dir)
        .with_protected(&protected)
        .with_exclusions(&exclusions);
    let mut plan = plan(&params)?;
    plan.exclusion_patterns = request.exclude.to_vec();

    if !plan.refused_protected.is_empty() || !plan.refused_unappliable.is_empty() {
        mvm_core::audit_emit!(
            WorkspaceApply,
            vm: target.vm,
            "action=workspace.apply outcome=refused volume={} refused={}",
            target.volume,
            plan.refused_protected.len() + plan.refused_unappliable.len()
        );
        return Ok(Review::Refused(plan));
    }
    if plan.ops.is_empty() {
        return Ok(Review::Unchanged);
    }
    Ok(Review::Ready(PendingApply { plan, live }))
}

/// The protected set in force: the shipped default classes plus the
/// operator's extensions. There is no switch that turns the defaults off.
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

/// The signed chain, as the apply engine uses it. [`SignedWorkspaceAudit`] is
/// the production implementation; a test substitutes one that refuses.
pub trait WorkspaceAudit {
    /// Append the pre-apply snapshot entry.
    fn record_snapshot(&self, entry: WorkspaceSnapshotAudit<'_>) -> Result<()>;
    /// Append a mutation entry under the envelope `intent` names.
    fn record_mutation(&self, intent: &str, entry: WorkspaceMutationAudit<'_>) -> Result<()>;
    /// Whether the verified, synced chain carries exactly this entry. An
    /// error means the chain could not answer.
    fn mutation_recorded(&self, entry: WorkspaceMutationAudit<'_>) -> Result<bool>;
}

/// The host-signed local audit chain. The signer is loaded on first use, so a
/// review or a dry run that never writes does not touch it.
#[derive(Default)]
pub struct SignedWorkspaceAudit {
    emitter: OnceCell<AuditEmitter>,
}

impl SignedWorkspaceAudit {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record through `emitter` instead of the host signer's default chain.
    #[must_use]
    pub fn with_emitter(emitter: AuditEmitter) -> Self {
        Self {
            emitter: OnceCell::from(emitter),
        }
    }

    fn emitter(&self) -> Result<&AuditEmitter> {
        if let Some(emitter) = self.emitter.get() {
            return Ok(emitter);
        }
        let signer = mvm_hostd::audit::host_keypair::load_or_init()
            .context("loading the host signer for workspace mutation audit")?;
        let emitter = AuditEmitter::new(signer.signing)
            .map(AuditEmitter::with_receipts)
            .context("opening the signed audit chain for workspace mutation")?;
        Ok(self.emitter.get_or_init(|| emitter))
    }
}

impl WorkspaceAudit for SignedWorkspaceAudit {
    fn record_snapshot(&self, entry: WorkspaceSnapshotAudit<'_>) -> Result<()> {
        let plan = audit_plan(
            entry.vm_name,
            entry.volume,
            "workspace:snapshot",
            entry.snapshot_root,
        )?;
        self.emitter()?.emit_workspace_snapshot(&plan, entry)
    }

    fn record_mutation(&self, intent: &str, entry: WorkspaceMutationAudit<'_>) -> Result<()> {
        let plan = audit_plan(entry.vm_name, entry.volume, intent, entry.merkle_root)?;
        self.emitter()?.emit_workspace_mutation(&plan, entry)
    }

    fn mutation_recorded(&self, entry: WorkspaceMutationAudit<'_>) -> Result<bool> {
        self.emitter()?.workspace_mutation_recorded(entry)
    }
}

fn audit_plan(
    vm: &str,
    volume: &str,
    intent: &str,
    merkle_root: &str,
) -> Result<mvm_core::plan::ExecutionPlan> {
    crate::event_plan::build_event_plan(
        "workspace-mutation",
        intent,
        &format!("workspace-{vm}-{volume}"),
        merkle_root,
    )
    .context("building the workspace mutation audit envelope")
}

/// Where a workspace's apply history lives.
#[must_use]
pub fn apply_store_root(vm: &str, volume: &str) -> PathBuf {
    mvm_core::config::machine_state_dir(vm)
        .join("workspace-applies")
        .join(volume)
}

/// One workspace's apply store, opened with interrupted work settled.
pub struct WorkspaceApplier<'a> {
    target: WorkspaceTarget<'a>,
    store: ApplyStore,
    audit: &'a dyn WorkspaceAudit,
}

impl<'a> WorkspaceApplier<'a> {
    /// Open `target`'s store under the machine's state directory. See
    /// [`Self::open_at`].
    pub fn open(
        target: WorkspaceTarget<'a>,
        audit: &'a dyn WorkspaceAudit,
    ) -> Result<(Self, Vec<Recovered>)> {
        Self::open_at(apply_store_root(target.vm, target.volume), target, audit)
    }

    /// Open the store at `root`. Before returning it rolls back an apply that
    /// began writing and never finished, repeats an interrupted audit
    /// rollback, and reconciles every commit still waiting on its signed
    /// entry: kept when the chain shows the entry, restored and cancelled when
    /// it shows none. A chain that cannot answer leaves the host restored and
    /// the store blocked, and is returned as the error.
    pub fn open_at(
        root: PathBuf,
        target: WorkspaceTarget<'a>,
        audit: &'a dyn WorkspaceAudit,
    ) -> Result<(Self, Vec<Recovered>)> {
        let store = ApplyStore::open(root)?;
        let mut recovered = Vec::new();
        if let Some(id) = store.recover_source(target.source_dir)? {
            recovered.push(Recovered::Interrupted(id));
        }
        reconcile_uncertain_signed_audits(&store, target, audit)?;
        let pending = store.pending_signed_audits()?;
        if !pending.is_empty() {
            let restored =
                reconcile_pending_signed_audits(&store, target.source_dir, pending, |staged| {
                    audit.mutation_recorded(applied_entry(target, staged))
                })?;
            recovered.extend(restored.into_iter().map(Recovered::Unaudited));
        }
        let applier = Self {
            target,
            store,
            audit,
        };
        Ok((applier, recovered))
    }

    /// Write a reviewed plan to the host tree. The order is what makes it
    /// safe: stage every pre-image, sign the snapshot root, arm a durable
    /// marker, commit, sign `workspace.applied`, then clear the marker. When
    /// the applied entry cannot be shown written, the pre-images are restored
    /// before this returns its error.
    pub fn apply(&self, pending: PendingApply) -> Result<Applied> {
        let target = self.target;
        let staged = self
            .store
            .stage(pending.plan, target.source_dir, &pending.live, None)?;
        let snapshot_root = staged.snapshot_merkle_root();
        record_snapshot_then_commit(
            || {
                self.audit.record_snapshot(WorkspaceSnapshotAudit {
                    vm_name: target.vm,
                    volume: target.volume,
                    apply_id: staged.id(),
                    snapshot_root: &snapshot_root,
                    manifest_root: staged.merkle_root(),
                })
            },
            || {
                self.store.arm_signed_audit(&staged)?;
                self.store
                    .commit(&staged, target.source_dir)
                    .map_err(Into::into)
            },
        )?;
        seal_apply_or_rollback(
            || {
                self.audit
                    .record_mutation("workspace:apply", applied_entry(target, &staged))
            },
            || self.audit.mutation_recorded(applied_entry(target, &staged)),
            |certainty| {
                match certainty {
                    AuditCertainty::Absent => {
                        self.store.rollback_unsealed(&staged, target.source_dir)
                    }
                    AuditCertainty::Unverifiable => {
                        self.store.rollback_unverifiable(&staged, target.source_dir)
                    }
                }
                .map_err(Into::into)
            },
        )?;
        self.store
            .seal_signed_audit(&staged)
            .context("clearing the reconciled workspace audit marker")?;
        mvm_core::audit_emit!(
            WorkspaceApply,
            vm: target.vm,
            "action=workspace.apply outcome=applied volume={} files={} merkle_root={}",
            target.volume,
            staged.manifest().ops.len(),
            staged.merkle_root()
        );
        Ok(Applied {
            apply_id: staged.id().to_string(),
            changes: staged.manifest().ops.len(),
            snapshot_root,
            merkle_root: staged.merkle_root().to_string(),
        })
    }

    /// Reverse the newest effective apply. `None` when there is none.
    pub fn undo(&self) -> Result<Option<AppliedRelation>> {
        let target = self.target;
        let Some(applied) = self.store.undo_latest(target.source_dir)? else {
            return Ok(None);
        };
        self.audit
            .record_mutation(
                "workspace:undo",
                WorkspaceMutationAudit {
                    event: workspace_audit::UNDONE_EVENT,
                    vm_name: target.vm,
                    volume: target.volume,
                    apply_id: &applied.apply_id,
                    target_id: Some(&applied.target_id),
                    merkle_root: &applied.merkle_root,
                },
            )
            .context("recording the workspace undo in the signed audit chain")?;
        mvm_core::audit_emit!(
            WorkspaceUndo,
            vm: target.vm,
            "action=workspace.undo volume={} undo={} target={} merkle_root={}",
            target.volume,
            applied.apply_id,
            applied.target_id,
            applied.merkle_root
        );
        Ok(Some(applied))
    }

    /// Re-apply the target of the newest undo while that undo is still the
    /// newest effective apply. `None` when there is nothing to redo.
    pub fn redo(&self) -> Result<Option<AppliedRelation>> {
        let target = self.target;
        let Some(applied) = self.store.redo_latest(target.source_dir)? else {
            return Ok(None);
        };
        self.audit
            .record_mutation(
                "workspace:redo",
                WorkspaceMutationAudit {
                    event: workspace_audit::REDONE_EVENT,
                    vm_name: target.vm,
                    volume: target.volume,
                    apply_id: &applied.apply_id,
                    target_id: Some(&applied.target_id),
                    merkle_root: &applied.merkle_root,
                },
            )
            .context("recording the workspace redo in the signed audit chain")?;
        mvm_core::audit_emit!(
            WorkspaceRedo,
            vm: target.vm,
            "action=workspace.redo volume={} redo={} target={} merkle_root={}",
            target.volume,
            applied.apply_id,
            applied.target_id,
            applied.merkle_root
        );
        Ok(Some(applied))
    }
}

/// One workspace's part in the end of a foreground run: review it, then
/// point at the command, ask, or apply, as an [`ExitApply`] decision says.
pub struct ExitSettlement<'a> {
    pub target: WorkspaceTarget<'a>,
    pub request: ReviewRequest<'a>,
    /// The workspace's apply store; [`apply_store_root`] outside tests.
    pub store_root: PathBuf,
    pub audit: &'a dyn WorkspaceAudit,
}

/// How one workspace was left when a run ended.
pub enum ExitOutcome {
    /// The guest changed nothing the host does not already have.
    Unchanged,
    /// The gate refused the plan; nothing was written.
    Refused(ApplyPlan),
    /// Changes exist and were deliberately not applied: no terminal to ask
    /// on, or machine-readable output.
    NotApplied(ApplyPlan),
    /// The operator was asked and did not answer yes.
    Declined(ApplyPlan),
    /// Applied through the signed engine.
    Applied(Applied),
}

/// An [`ExitOutcome`] and the interrupted work opening the store settled.
pub struct Settled {
    pub outcome: ExitOutcome,
    pub recovered: Vec<Recovered>,
}

impl ExitSettlement<'_> {
    /// Settle the workspace. Only [`ExitApply::Prompt`] calls `confirm`, with
    /// the reviewed plan, and only a `true` from it lets the apply proceed.
    /// [`ExitApply::Pointer`] neither opens the apply store nor writes
    /// anything; the other two open it first, so the plan is made against a
    /// host tree with any interrupted apply already rolled back.
    pub fn settle(
        self,
        decision: ExitApply,
        confirm: impl FnOnce(&ApplyPlan) -> Result<bool>,
    ) -> Result<Settled> {
        let (applier, recovered) = match decision {
            ExitApply::Pointer => (None, Vec::new()),
            ExitApply::Prompt | ExitApply::Apply => {
                let (applier, recovered) =
                    WorkspaceApplier::open_at(self.store_root, self.target, self.audit)?;
                (Some(applier), recovered)
            }
        };
        let settled = |outcome| Settled {
            outcome,
            recovered: recovered.clone(),
        };
        let pending = match review(self.target, &self.request)? {
            Review::Unchanged => return Ok(settled(ExitOutcome::Unchanged)),
            Review::Refused(plan) => return Ok(settled(ExitOutcome::Refused(plan))),
            Review::Ready(pending) => pending,
        };
        let Some(applier) = applier else {
            return Ok(settled(ExitOutcome::NotApplied(pending.plan)));
        };
        if decision == ExitApply::Prompt && !confirm(&pending.plan)? {
            return Ok(settled(ExitOutcome::Declined(pending.plan)));
        }
        let applied = applier.apply(pending)?;
        Ok(settled(ExitOutcome::Applied(applied)))
    }
}

fn applied_entry<'s>(
    target: WorkspaceTarget<'s>,
    staged: &'s StagedApply,
) -> WorkspaceMutationAudit<'s> {
    WorkspaceMutationAudit {
        event: workspace_audit::APPLIED_EVENT,
        vm_name: target.vm,
        volume: target.volume,
        apply_id: staged.id(),
        target_id: None,
        merkle_root: staged.merkle_root(),
    }
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

/// Whether a failed applied-event append can be shown not to have landed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditCertainty {
    Absent,
    Unverifiable,
}

/// A failed applied-event append must not leave unrecorded host writes behind.
fn seal_apply_or_rollback(
    record_applied: impl FnOnce() -> Result<()>,
    verify_recorded: impl FnOnce() -> Result<bool>,
    rollback: impl FnOnce(AuditCertainty) -> Result<()>,
) -> Result<()> {
    let Err(audit_error) = record_applied() else {
        return Ok(());
    };
    match verify_recorded() {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(verify_error) => return match rollback(AuditCertainty::Unverifiable) {
            Ok(()) => Err(verify_error).context(format!(
                "signed workspace append reported {audit_error}; the chain could not verify its outcome, so host pre-images were restored and a durable recovery marker retained"
            )),
            Err(rollback_error) => Err(rollback_error).context(format!(
                "signed workspace append reported {audit_error} and chain verification failed ({verify_error}); host rollback also failed and the working tree may have changed"
            )),
        },
    }
    match rollback(AuditCertainty::Absent) {
        Ok(()) => Err(audit_error)
            .context("recording the signed workspace apply failed; host pre-images were restored"),
        Err(rollback_error) => Err(rollback_error).with_context(|| {
            format!(
                "recording the signed workspace apply failed ({audit_error}); host rollback also failed and the working tree may have changed"
            )
        }),
    }
}

fn reconcile_uncertain_signed_audits(
    store: &ApplyStore,
    target: WorkspaceTarget<'_>,
    audit: &dyn WorkspaceAudit,
) -> Result<()> {
    let uncertain = store.uncertain_signed_audits()?;
    for staged in &uncertain {
        store
            .rollback_unverifiable(staged, target.source_dir)
            .context("restoring host pre-images after an interrupted audit rollback")?;
    }
    for staged in uncertain {
        if audit.mutation_recorded(applied_entry(target, &staged))? {
            let rollback = WorkspaceMutationAudit {
                event: workspace_audit::AUDIT_ROLLBACK_EVENT,
                ..applied_entry(target, &staged)
            };
            if !audit.mutation_recorded(rollback)? {
                let appended = audit.record_mutation("workspace:audit-rollback", rollback);
                if let Err(append_error) = appended
                    && !audit.mutation_recorded(rollback)?
                {
                    return Err(append_error)
                        .context("recording the signed compensation for an uncertain apply");
                }
            }
        }
        store.settle_uncertain_signed_audit(&staged)?;
    }
    Ok(())
}

fn reconcile_pending_signed_audits(
    store: &ApplyStore,
    source_dir: &Path,
    pending: Vec<StagedApply>,
    mut recorded: impl FnMut(&StagedApply) -> Result<bool>,
) -> Result<Vec<String>> {
    let mut restored = Vec::new();
    for staged in pending {
        match recorded(&staged) {
            Ok(true) => store.seal_signed_audit(&staged)?,
            Ok(false) => {
                store.rollback_unsealed(&staged, source_dir)?;
                restored.push(staged.id().to_string());
            }
            Err(audit_error) => {
                store
                    .rollback_unverifiable(&staged, source_dir)
                    .context("restoring host pre-images while the signed chain is unavailable")?;
                return Err(audit_error).context(
                    "the signed audit result is unavailable; host pre-images were restored and reconciliation remains pending",
                );
            }
        }
    }
    Ok(restored)
}
