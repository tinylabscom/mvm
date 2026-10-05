use std::cell::{Cell, RefCell};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use mvm_fs::ext4::{Node, Owner, build_image};
use mvm_fs::workspace_apply::PlanParams;
use mvm_fs::workspace_apply::store::{ApplyStore, StagedApply};
use mvm_hostd::audit::emitter::{
    AuditEmitter, WorkspaceMutationAudit, WorkspaceSnapshotAudit, workspace_audit,
};

use super::*;

const VM: &str = "agent-vm";
const VOLUME: &str = "source";

/// A host directory holding `edit.txt`, and two images of it: the baseline
/// the workspace began as and a live image in which the guest changed
/// `edit.txt` and, optionally, wrote one more file.
struct Workspace {
    home: tempfile::TempDir,
    source: PathBuf,
    baseline: PathBuf,
    live: PathBuf,
}

impl Workspace {
    fn new(extra: Option<(&str, &[u8])>) -> Self {
        let home = tempfile::tempdir().expect("home");
        let source = home.path().join("source");
        fs::create_dir(&source).expect("source");
        fs::write(source.join("edit.txt"), "before\n").expect("host pre-image");
        let baseline = image(home.path(), "baseline.ext4", &[("/edit.txt", b"before\n")]);
        let mut live_files: Vec<(&str, &[u8])> = vec![("/edit.txt", b"after\n")];
        live_files.extend(extra);
        let live = image(home.path(), "live.ext4", &live_files);
        Self {
            home,
            source,
            baseline,
            live,
        }
    }

    fn target(&self) -> WorkspaceTarget<'_> {
        WorkspaceTarget {
            vm: VM,
            volume: VOLUME,
            source_dir: &self.source,
        }
    }

    fn request(&self) -> ReviewRequest<'_> {
        ReviewRequest {
            baseline_image: &self.baseline,
            live_image: &self.live,
            exclude: &[],
            protected_paths: &[],
        }
    }

    fn store_root(&self) -> PathBuf {
        self.home.path().join("store")
    }

    fn host(&self) -> String {
        fs::read_to_string(self.source.join("edit.txt")).expect("host file")
    }

    fn signed_audit(&self) -> SignedWorkspaceAudit {
        SignedWorkspaceAudit::with_emitter(
            AuditEmitter::with_dir(
                ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
                &self.home.path().join("audit"),
            )
            .expect("emitter"),
        )
    }

    fn ready(&self) -> PendingApply {
        match review(self.target(), &self.request()).expect("review") {
            Review::Ready(pending) => pending,
            Review::Refused(plan) => panic!("refused: {:?}", plan.refused_protected),
            Review::Unchanged => panic!("nothing to apply"),
        }
    }
}

fn image(dir: &Path, name: &str, files: &[(&str, &[u8])]) -> PathBuf {
    let mut parents = std::collections::BTreeSet::new();
    for (path, _) in files {
        let mut parent = Path::new(path).parent();
        while let Some(dir) = parent.filter(|dir| *dir != Path::new("/")) {
            parents.insert(dir.to_string_lossy().into_owned());
            parent = dir.parent();
        }
    }
    let dirs = parents.into_iter().map(|path| Node::Dir {
        path,
        mode: 0o755,
        xattrs: Vec::new(),
        owner: Owner::ROOT,
    });
    let nodes = dirs
        .chain(files.iter().map(|(path, data)| Node::File {
            path: (*path).to_string(),
            mode: 0o644,
            data: data.to_vec(),
            xattrs: Vec::new(),
            owner: Owner::ROOT,
        }))
        .collect();
    let bytes = build_image(nodes, &Default::default()).expect("image");
    let path = dir.join(name);
    fs::write(&path, bytes).expect("write image");
    path
}

/// A chain whose behaviour each test scripts: which appends succeed, and
/// what a verification finds. Records the order of every call.
#[derive(Default)]
struct ScriptedAudit {
    refuse_snapshot: bool,
    refuse_mutation: bool,
    /// `None` makes verification itself fail.
    recorded: Option<bool>,
    calls: RefCell<Vec<String>>,
}

impl ScriptedAudit {
    fn verifying(recorded: bool) -> Self {
        Self {
            recorded: Some(recorded),
            ..Self::default()
        }
    }
}

impl WorkspaceAudit for ScriptedAudit {
    fn record_snapshot(&self, entry: WorkspaceSnapshotAudit<'_>) -> Result<()> {
        self.calls
            .borrow_mut()
            .push(format!("snapshot {}", entry.apply_id));
        if self.refuse_snapshot {
            return Err(anyhow!("snapshot append refused"));
        }
        Ok(())
    }

    fn record_mutation(&self, intent: &str, entry: WorkspaceMutationAudit<'_>) -> Result<()> {
        self.calls
            .borrow_mut()
            .push(format!("{intent} {}", entry.event));
        if self.refuse_mutation {
            return Err(anyhow!("audit append refused"));
        }
        Ok(())
    }

    fn mutation_recorded(&self, entry: WorkspaceMutationAudit<'_>) -> Result<bool> {
        self.calls
            .borrow_mut()
            .push(format!("verify {}", entry.event));
        self.recorded
            .ok_or_else(|| anyhow!("audit chain unavailable"))
    }
}

// ── the decision ──────────────────────────────────────────────────────────

#[test]
fn a_terminal_without_flags_is_asked() {
    let request = ExitApplyRequest {
        operator_at_terminal: true,
        ..ExitApplyRequest::default()
    };
    assert_eq!(request.decide(), ExitApply::Prompt);
}

#[test]
fn apply_applies_without_asking_with_or_without_a_terminal() {
    for operator_at_terminal in [true, false] {
        let request = ExitApplyRequest {
            apply: true,
            operator_at_terminal,
            ..ExitApplyRequest::default()
        };
        assert_eq!(request.decide(), ExitApply::Apply);
    }
}

#[test]
fn no_terminal_and_no_apply_only_points_at_the_command() {
    assert_eq!(ExitApplyRequest::default().decide(), ExitApply::Pointer);
}

#[test]
fn json_output_is_never_asked_even_on_a_terminal() {
    let request = ExitApplyRequest {
        json: true,
        operator_at_terminal: true,
        ..ExitApplyRequest::default()
    };
    assert_eq!(request.decide(), ExitApply::Pointer);
}

#[test]
fn the_pointer_is_the_machine_apply_command() {
    assert_eq!(
        apply_command("coding-agent", None),
        "mvmctl machine apply coding-agent"
    );
    assert_eq!(
        apply_command("coding-agent", Some("work")),
        "mvmctl machine apply coding-agent --volume work"
    );
}

#[test]
fn only_y_or_yes_is_a_yes() {
    for yes in ["y", "Y", "yes", "YES", " y "] {
        assert!(is_affirmative(Some(yes)), "{yes:?}");
    }
    for no in ["", "n", "no", "yy", "yes please", "s", "\u{1b}[Ay"] {
        assert!(!is_affirmative(Some(no)), "{no:?}");
    }
    assert!(!is_affirmative(None), "no answer is a no");
}

// ── review ────────────────────────────────────────────────────────────────

#[test]
fn review_writes_nothing_and_opens_no_store() {
    let workspace = Workspace::new(None);
    let pending = workspace.ready();
    assert_eq!(pending.plan().ops.len(), 1);
    assert_eq!(workspace.host(), "before\n");
    assert!(!workspace.store_root().exists());
}

#[test]
fn a_protected_path_refuses_the_review() {
    let workspace = Workspace::new(Some(("/.github/workflows/ci.yml", b"on: push\n")));
    match review(workspace.target(), &workspace.request()).expect("review") {
        Review::Refused(plan) => assert!(
            plan.refused_protected
                .iter()
                .any(|(path, _)| path.contains(".github/workflows")),
            "{:?}",
            plan.refused_protected
        ),
        _ => panic!("a guest edit of a workflow must refuse the whole apply"),
    }
}

#[test]
fn an_operator_protected_path_refuses_the_review() {
    let workspace = Workspace::new(Some(("/secrets.env", b"TOKEN=x\n")));
    let protected = ["secrets.env".to_string()];
    let request = ReviewRequest {
        protected_paths: &protected,
        ..workspace.request()
    };
    assert!(matches!(
        review(workspace.target(), &request).expect("review"),
        Review::Refused(_)
    ));
}

#[test]
fn a_workspace_the_guest_did_not_change_is_unchanged() {
    let workspace = Workspace::new(None);
    let request = ReviewRequest {
        live_image: &workspace.baseline,
        ..workspace.request()
    };
    assert!(matches!(
        review(workspace.target(), &request).expect("review"),
        Review::Unchanged
    ));
}

// ── apply through the signed chain ────────────────────────────────────────

#[test]
fn an_apply_signs_the_snapshot_then_the_applied_entry() {
    let workspace = Workspace::new(None);
    let audit = workspace.signed_audit();
    let (applier, recovered) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
            .expect("open");
    assert!(recovered.is_empty());
    let applied = applier.apply(workspace.ready()).expect("apply");

    assert_eq!(workspace.host(), "after\n");
    assert_eq!(applied.changes, 1);
    assert!(
        audit
            .mutation_recorded(WorkspaceMutationAudit {
                event: workspace_audit::APPLIED_EVENT,
                vm_name: VM,
                volume: VOLUME,
                apply_id: &applied.apply_id,
                target_id: None,
                merkle_root: &applied.merkle_root,
            })
            .expect("verify chain"),
        "the applied entry is on the verified chain"
    );
    let chain = fs::read_to_string(workspace.home.path().join("audit/local.jsonl")).expect("chain");
    let snapshot = chain
        .find(workspace_audit::SNAPSHOT_EVENT)
        .expect("snapshot entry");
    let applied_at = chain
        .find(workspace_audit::APPLIED_EVENT)
        .expect("applied entry");
    assert!(snapshot < applied_at, "the snapshot is recorded first");
    let store = ApplyStore::open(workspace.store_root()).expect("store");
    assert!(store.pending_signed_audits().expect("pending").is_empty());
}

#[test]
fn a_refused_snapshot_entry_leaves_the_host_untouched() {
    let workspace = Workspace::new(None);
    let audit = ScriptedAudit {
        refuse_snapshot: true,
        ..ScriptedAudit::verifying(false)
    };
    let (applier, _) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
            .expect("open");
    let error = applier.apply(workspace.ready()).expect_err("must refuse");
    assert!(
        format!("{error:#}").contains("pre-apply snapshot"),
        "{error:#}"
    );
    assert_eq!(workspace.host(), "before\n");
    assert!(
        !audit
            .calls
            .borrow()
            .iter()
            .any(|c| c.starts_with("workspace:apply")),
        "nothing was committed, so nothing is recorded as applied"
    );
}

#[test]
fn an_apply_whose_signed_entry_cannot_be_written_is_not_left_applied() {
    let workspace = Workspace::new(None);
    let audit = ScriptedAudit {
        refuse_mutation: true,
        ..ScriptedAudit::verifying(false)
    };
    let (applier, _) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
            .expect("open");
    let error = applier.apply(workspace.ready()).expect_err("must fail");

    assert!(
        format!("{error:#}").contains("pre-images were restored"),
        "{error:#}"
    );
    assert_eq!(workspace.host(), "before\n", "the host tree is restored");
    let store = ApplyStore::open(workspace.store_root()).expect("store");
    assert!(store.effective_applies().expect("effective").is_empty());
    assert!(store.pending_signed_audits().expect("pending").is_empty());
}

#[test]
fn an_append_error_with_the_entry_on_the_chain_keeps_the_apply() {
    let workspace = Workspace::new(None);
    let audit = ScriptedAudit {
        refuse_mutation: true,
        ..ScriptedAudit::verifying(true)
    };
    let (applier, _) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
            .expect("open");
    applier
        .apply(workspace.ready())
        .expect("verified entry settles it");
    assert_eq!(workspace.host(), "after\n");
}

#[test]
fn an_unverifiable_chain_restores_the_host_and_blocks_until_it_answers() {
    let workspace = Workspace::new(None);
    let unavailable = ScriptedAudit {
        refuse_mutation: true,
        ..ScriptedAudit::default()
    };
    let (applier, _) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &unavailable)
            .expect("open");
    let error = applier.apply(workspace.ready()).expect_err("must fail");
    assert!(
        format!("{error:#}").contains("audit chain unavailable"),
        "{error:#}"
    );
    assert_eq!(workspace.host(), "before\n");
    let store = ApplyStore::open(workspace.store_root()).expect("store");
    assert_eq!(store.uncertain_signed_audits().expect("uncertain").len(), 1);

    // While the chain still cannot answer, the store stays blocked.
    assert!(
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &unavailable)
            .is_err()
    );
    // Once it answers that nothing landed, the marker settles with the host
    // still restored and no compensation claimed.
    let answered = ScriptedAudit::verifying(false);
    WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &answered)
        .expect("settle");
    assert_eq!(workspace.host(), "before\n");
    assert!(
        store
            .uncertain_signed_audits()
            .expect("uncertain")
            .is_empty()
    );
}

#[test]
fn an_interrupted_commit_without_a_signed_entry_is_restored_on_open() {
    let workspace = Workspace::new(None);
    let staged = committed_without_signed_entry(&workspace);
    assert_eq!(workspace.host(), "after\n");

    let audit = ScriptedAudit::verifying(false);
    let (_, recovered) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
            .expect("open");
    assert_eq!(recovered, [Recovered::Unaudited(staged.id().to_string())]);
    assert_eq!(workspace.host(), "before\n");
}

#[test]
fn an_interrupted_commit_with_its_signed_entry_is_kept_on_open() {
    let workspace = Workspace::new(None);
    committed_without_signed_entry(&workspace);
    let audit = ScriptedAudit::verifying(true);
    let (_, recovered) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
            .expect("open");
    assert!(recovered.is_empty());
    assert_eq!(workspace.host(), "after\n");
}

#[test]
fn an_uncertain_apply_whose_entry_landed_gets_a_compensating_entry() {
    let workspace = Workspace::new(None);
    let audit = workspace.signed_audit();
    let staged = committed_without_signed_entry(&workspace);
    let store = ApplyStore::open(workspace.store_root()).expect("store");
    store
        .rollback_unverifiable(&staged, &workspace.source)
        .expect("restore host");
    audit
        .record_mutation(
            "workspace:apply",
            mutation_entry(workspace.target(), &staged),
        )
        .expect("the original entry did land");

    WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
        .expect("reconcile");
    let rollback = WorkspaceMutationAudit {
        event: workspace_audit::AUDIT_ROLLBACK_EVENT,
        ..mutation_entry(workspace.target(), &staged)
    };
    assert!(audit.mutation_recorded(rollback).expect("verify"));
    assert_eq!(workspace.host(), "before\n");
    assert!(
        store
            .uncertain_signed_audits()
            .expect("uncertain")
            .is_empty()
    );
}

#[test]
fn a_damaged_chain_keeps_the_restored_host_and_the_uncertain_marker() {
    let workspace = Workspace::new(None);
    let audit = workspace.signed_audit();
    let staged = committed_without_signed_entry(&workspace);
    let store = ApplyStore::open(workspace.store_root()).expect("store");
    store
        .rollback_unverifiable(&staged, &workspace.source)
        .expect("restore host");
    audit
        .record_mutation(
            "workspace:apply",
            mutation_entry(workspace.target(), &staged),
        )
        .expect("signed entry");
    let chain = workspace.home.path().join("audit/local.jsonl");
    let original = fs::read_to_string(&chain).expect("chain");
    fs::write(
        &chain,
        original.replacen("workspace.applied", "workspace.undone", 1),
    )
    .expect("tamper chain");

    assert!(WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit).is_err());
    assert_eq!(workspace.host(), "before\n");
    assert_eq!(store.uncertain_signed_audits().expect("uncertain").len(), 1);
}

#[test]
fn undo_then_redo_are_recorded_under_their_own_events() {
    let workspace = Workspace::new(None);
    let audit = workspace.signed_audit();
    let (applier, _) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
            .expect("open");
    let applied = applier.apply(workspace.ready()).expect("apply");

    let undone = applier.undo().expect("undo").expect("an apply to undo");
    assert_eq!(undone.target_id, applied.apply_id);
    assert_eq!(workspace.host(), "before\n");
    let redone = applier.redo().expect("redo").expect("an undo to redo");
    assert_eq!(workspace.host(), "after\n");

    for (event, relation) in [
        (workspace_audit::UNDONE_EVENT, &undone),
        (workspace_audit::REDONE_EVENT, &redone),
    ] {
        assert!(
            audit
                .mutation_recorded(WorkspaceMutationAudit {
                    event,
                    vm_name: VM,
                    volume: VOLUME,
                    apply_id: &relation.apply_id,
                    target_id: Some(&relation.target_id),
                    merkle_root: &relation.merkle_root,
                })
                .expect("verify"),
            "{event}"
        );
    }
    assert!(
        applier.redo().expect("redo").is_none(),
        "nothing left to redo"
    );
}

#[test]
fn the_snapshot_is_recorded_before_the_host_write() {
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
fn a_failed_rollback_warns_that_host_changes_may_remain() {
    let error = seal_apply_or_rollback(
        || Err(anyhow!("audit append refused")),
        || Ok(false),
        |_| Err(anyhow!("host restore refused")),
    )
    .expect_err("apply must fail");
    assert!(format!("{error:#}").contains("may have changed"));
    assert!(format!("{error:#}").contains("audit append refused"));
}

#[test]
fn a_signed_apply_entry_never_triggers_a_rollback() {
    let rolled_back = Cell::new(false);
    seal_apply_or_rollback(
        || Ok(()),
        || Ok(false),
        |_| {
            rolled_back.set(true);
            Ok(())
        },
    )
    .expect("signed apply");
    assert!(!rolled_back.get());
}

/// Commit an apply with its pending-audit marker armed and no signed entry:
/// the state a crash between the host commit and the append leaves.
fn committed_without_signed_entry(workspace: &Workspace) -> StagedApply {
    let baseline = Ext4Tree::open(&workspace.baseline).expect("baseline");
    let live = Ext4Tree::open(&workspace.live).expect("live");
    let store = ApplyStore::open(workspace.store_root()).expect("store");
    let plan = store
        .plan(&PlanParams::new(&baseline, &live, &workspace.source))
        .expect("plan");
    let staged = store
        .stage(plan, &workspace.source, &live, None)
        .expect("stage");
    store.arm_signed_audit(&staged).expect("arm audit");
    store.commit(&staged, &workspace.source).expect("commit");
    staged
}

// ── the end of a foreground run ───────────────────────────────────────────

fn settlement<'a>(workspace: &'a Workspace, audit: &'a dyn WorkspaceAudit) -> ExitSettlement<'a> {
    ExitSettlement {
        target: workspace.target(),
        request: workspace.request(),
        store_root: workspace.store_root(),
        audit,
    }
}

#[test]
fn at_exit_a_yes_at_the_prompt_applies_through_the_signed_engine() {
    let workspace = Workspace::new(None);
    let audit = workspace.signed_audit();
    let asked = Cell::new(false);
    let settled = settlement(&workspace, &audit)
        .settle(ExitApply::Prompt, |plan| {
            asked.set(true);
            assert_eq!(plan.ops.len(), 1, "the operator sees the reviewed plan");
            Ok(true)
        })
        .expect("settle");
    assert!(asked.get());
    let ExitOutcome::Applied(applied) = settled.outcome else {
        panic!("a yes applies");
    };
    assert_eq!(workspace.host(), "after\n");
    assert!(
        audit
            .mutation_recorded(applied_entry_of(&applied))
            .expect("verify"),
        "the prompt's apply is signed like any other"
    );
}

#[test]
fn at_exit_anything_but_a_yes_at_the_prompt_applies_nothing() {
    let workspace = Workspace::new(None);
    let audit = ScriptedAudit::verifying(false);
    let settled = settlement(&workspace, &audit)
        .settle(ExitApply::Prompt, |_| Ok(false))
        .expect("settle");
    assert!(matches!(settled.outcome, ExitOutcome::Declined(_)));
    assert_eq!(workspace.host(), "before\n");
    assert!(audit.calls.borrow().is_empty(), "nothing reached the chain");
}

#[test]
fn at_exit_apply_writes_without_asking() {
    let workspace = Workspace::new(None);
    let audit = workspace.signed_audit();
    let settled = settlement(&workspace, &audit)
        .settle(ExitApply::Apply, |_| panic!("--apply never asks"))
        .expect("settle");
    assert!(matches!(settled.outcome, ExitOutcome::Applied(_)));
    assert_eq!(workspace.host(), "after\n");
}

#[test]
fn at_exit_the_pointer_writes_nothing_and_opens_no_store() {
    let workspace = Workspace::new(None);
    let audit = ScriptedAudit::verifying(false);
    let settled = settlement(&workspace, &audit)
        .settle(ExitApply::Pointer, |_| panic!("the pointer never asks"))
        .expect("settle");
    let ExitOutcome::NotApplied(plan) = settled.outcome else {
        panic!("changes exist, so the pointer reports them");
    };
    assert_eq!(plan.ops.len(), 1);
    assert_eq!(workspace.host(), "before\n");
    assert!(!workspace.store_root().exists());
    assert!(audit.calls.borrow().is_empty());
}

#[test]
fn at_exit_a_failed_signed_entry_leaves_nothing_applied() {
    let workspace = Workspace::new(None);
    let audit = ScriptedAudit {
        refuse_mutation: true,
        ..ScriptedAudit::verifying(false)
    };
    assert!(
        settlement(&workspace, &audit)
            .settle(ExitApply::Apply, |_| Ok(true))
            .is_err()
    );
    assert_eq!(workspace.host(), "before\n");
}

#[test]
fn at_exit_the_gate_refuses_before_anything_is_asked() {
    let workspace = Workspace::new(Some(("/.github/workflows/ci.yml", b"on: push\n")));
    let audit = ScriptedAudit::verifying(false);
    let settled = settlement(&workspace, &audit)
        .settle(ExitApply::Prompt, |_| {
            panic!("a refused plan is never offered")
        })
        .expect("settle");
    assert!(matches!(settled.outcome, ExitOutcome::Refused(_)));
    assert_eq!(workspace.host(), "before\n");
}

fn applied_entry_of(applied: &Applied) -> WorkspaceMutationAudit<'_> {
    WorkspaceMutationAudit {
        event: workspace_audit::APPLIED_EVENT,
        vm_name: VM,
        volume: VOLUME,
        apply_id: &applied.apply_id,
        target_id: None,
        merkle_root: &applied.merkle_root,
    }
}

// ── undo and redo through the same signed sequence ────────────────────────

/// A workspace with one signed apply already committed to the host.
fn applied_workspace() -> Workspace {
    let workspace = Workspace::new(None);
    let audit = workspace.signed_audit();
    let (applier, _) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
            .expect("open");
    applier.apply(workspace.ready()).expect("apply");
    assert_eq!(workspace.host(), "after\n");
    workspace
}

#[test]
fn an_undo_whose_signed_entry_cannot_be_written_is_not_left_undone() {
    let workspace = applied_workspace();
    let audit = ScriptedAudit {
        refuse_mutation: true,
        ..ScriptedAudit::verifying(false)
    };
    let (applier, _) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
            .expect("open");
    let error = applier.undo().expect_err("the undo must fail");
    assert!(
        format!("{error:#}").contains("pre-images were restored"),
        "{error:#}"
    );
    assert_eq!(workspace.host(), "after\n", "the apply is back in force");
    let calls = audit.calls.borrow();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert!(calls[0].starts_with("snapshot "), "{calls:?}");
    assert_eq!(
        calls[1..],
        ["workspace:undo workspace.undone", "verify workspace.undone"],
        "the undone entry, then its verification"
    );
    drop(calls);
    let store = ApplyStore::open(workspace.store_root()).expect("store");
    assert_eq!(store.effective_applies().expect("effective").len(), 1);
}

#[test]
fn a_redo_whose_signed_entry_cannot_be_written_is_not_left_redone() {
    let workspace = applied_workspace();
    {
        let audit = workspace.signed_audit();
        let (applier, _) =
            WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
                .expect("open");
        applier.undo().expect("undo").expect("an apply to undo");
    }
    assert_eq!(workspace.host(), "before\n");
    let audit = ScriptedAudit {
        refuse_mutation: true,
        ..ScriptedAudit::verifying(false)
    };
    let (applier, _) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
            .expect("open");
    applier.redo().expect_err("the redo must fail");
    assert_eq!(workspace.host(), "before\n", "the undo is back in force");
    assert!(
        audit
            .calls
            .borrow()
            .contains(&"verify workspace.redone".to_string())
    );
}

#[test]
fn an_unverifiable_chain_restores_an_undo_and_blocks() {
    let workspace = applied_workspace();
    let audit = ScriptedAudit {
        refuse_mutation: true,
        ..ScriptedAudit::default()
    };
    let (applier, _) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
            .expect("open");
    applier.undo().expect_err("the undo must fail");
    assert_eq!(workspace.host(), "after\n");
    let store = ApplyStore::open(workspace.store_root()).expect("store");
    assert_eq!(store.uncertain_signed_audits().expect("uncertain").len(), 1);
}

/// Commit an undo with its pending-audit marker armed and no signed entry:
/// the state a crash between the host commit and the append leaves.
fn undo_committed_without_signed_entry(workspace: &Workspace) -> StagedApply {
    let store = ApplyStore::open(workspace.store_root()).expect("store");
    let undo = store
        .stage_undo(&workspace.source)
        .expect("stage undo")
        .expect("an apply to undo");
    store.arm_signed_audit(&undo).expect("arm audit");
    store.commit(&undo, &workspace.source).expect("commit");
    undo
}

#[test]
fn an_interrupted_undo_without_its_signed_entry_is_restored_on_open() {
    let workspace = applied_workspace();
    let undo = undo_committed_without_signed_entry(&workspace);
    assert_eq!(workspace.host(), "before\n");

    let audit = ScriptedAudit::verifying(false);
    let (_, recovered) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
            .expect("open");
    assert_eq!(recovered, [Recovered::Unaudited(undo.id().to_string())]);
    assert_eq!(workspace.host(), "after\n");
    assert_eq!(
        audit.calls.borrow().as_slice(),
        ["verify workspace.undone"],
        "recovery looks for the entry the undo owed, not an applied one"
    );
}

#[test]
fn an_interrupted_undo_with_its_signed_entry_is_kept_on_open() {
    let workspace = applied_workspace();
    let undo = undo_committed_without_signed_entry(&workspace);
    let audit = workspace.signed_audit();
    audit
        .record_mutation("workspace:undo", mutation_entry(workspace.target(), &undo))
        .expect("the undone entry landed");

    let (_, recovered) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
            .expect("open");
    assert!(recovered.is_empty());
    assert_eq!(workspace.host(), "before\n");
    let store = ApplyStore::open(workspace.store_root()).expect("store");
    assert!(store.pending_signed_audits().expect("pending").is_empty());
}

#[test]
fn an_undo_records_its_snapshot_before_writing() {
    let workspace = applied_workspace();
    let audit = workspace.signed_audit();
    let (applier, _) =
        WorkspaceApplier::open_at(workspace.store_root(), workspace.target(), &audit)
            .expect("open");
    let undone = applier.undo().expect("undo").expect("an apply to undo");
    let chain = fs::read_to_string(workspace.home.path().join("audit/local.jsonl")).expect("chain");
    let snapshot = chain
        .rfind(workspace_audit::SNAPSHOT_EVENT)
        .expect("the undo's snapshot entry");
    let entry = chain
        .rfind(workspace_audit::UNDONE_EVENT)
        .expect("the undone entry");
    assert!(snapshot < entry);
    assert!(chain[snapshot..].contains(&undone.apply_id));
}
