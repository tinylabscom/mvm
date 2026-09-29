//! The apply store's lifecycle: plan, stage, commit, undo, redo, and both
//! crash windows, against real ext4 images and a real host directory.

use std::fs;
use std::path::{Path, PathBuf};

use mvm_contract::policy::protected_paths::{ProtectedPath, ProtectedPathSet};

use super::store::{ApplyStore, JournalKind};
use super::*;
use crate::ext4::{Node, Owner, build_image};
use crate::tree_diff::{DiffLimits, Ext4Tree};

fn dir_node(path: &str) -> Node {
    Node::Dir {
        path: path.to_string(),
        mode: 0o755,
        xattrs: Vec::new(),
        owner: Owner::ROOT,
    }
}

fn file_node(path: &str, data: &[u8]) -> Node {
    Node::File {
        path: path.to_string(),
        mode: 0o644,
        data: data.to_vec(),
        xattrs: Vec::new(),
        owner: Owner::ROOT,
    }
}

fn image(dir: &Path, name: &str, nodes: Vec<Node>) -> PathBuf {
    let bytes = build_image(nodes, &Default::default()).expect("build image");
    let path = dir.join(name);
    fs::write(&path, bytes).expect("write image");
    path
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).expect("read file")
}

/// The canonical fixture: a host directory with three files, a baseline
/// image that mirrors it, and a live image the guest changed (one modified,
/// one added, one removed).
struct Fixture {
    home: tempfile::TempDir,
    source_dir: PathBuf,
    baseline: PathBuf,
    live: PathBuf,
    store_dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().expect("tempdir");
        let source_dir = home.path().join("host");
        fs::create_dir_all(&source_dir).expect("host dir");
        fs::write(source_dir.join("keep.txt"), "original keep\n").expect("write keep");
        fs::write(source_dir.join("edit.txt"), "original edit\n").expect("write edit");
        fs::write(source_dir.join("gone.txt"), "original gone\n").expect("write gone");

        let baseline = image(
            home.path(),
            "baseline.ext4",
            vec![
                file_node("/keep.txt", b"original keep\n"),
                file_node("/edit.txt", b"original edit\n"),
                file_node("/gone.txt", b"original gone\n"),
            ],
        );
        let live = image(
            home.path(),
            "live.ext4",
            vec![
                file_node("/keep.txt", b"original keep\n"),
                file_node("/edit.txt", b"guest edit\n"),
                file_node("/added.txt", b"guest added\n"),
            ],
        );
        let store_dir = home.path().join("store");
        Self {
            home,
            source_dir,
            baseline,
            live,
            store_dir,
        }
    }

    fn plan(&self, store: &ApplyStore) -> ApplyPlan {
        let baseline = Ext4Tree::open(&self.baseline).expect("open baseline");
        let live = Ext4Tree::open(&self.live).expect("open live");
        let params =
            PlanParams::new(&baseline, &live, &self.source_dir).with_limits(DiffLimits::default());
        store.plan(&params).expect("plan")
    }

    /// Stage + commit the fixture's plan; returns the staged manifest id.
    fn apply(&self, store: &ApplyStore) -> StagedApply {
        let live = Ext4Tree::open(&self.live).expect("open live");
        let plan = self.plan(store);
        let staged = store
            .stage(plan, &self.source_dir, &live, None)
            .expect("stage");
        store.commit(&staged, &self.source_dir).expect("commit");
        staged
    }
}

#[test]
fn apply_writes_guest_changes_and_captures_preimages() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    let plan = fixture.plan(&store);
    assert_eq!(plan.ops.len(), 3, "{plan:#?}");
    assert!(plan.refused_protected.is_empty());
    let paths: Vec<&str> = plan.ops.iter().map(|op| op.path.as_str()).collect();
    assert_eq!(paths, ["added.txt", "edit.txt", "gone.txt"]);

    let staged = fixture.apply(&store);
    assert!(!staged.merkle_root().is_empty());

    // The host tree now mirrors the guest's image.
    assert_eq!(read(&fixture.source_dir.join("edit.txt")), "guest edit\n");
    assert_eq!(read(&fixture.source_dir.join("added.txt")), "guest added\n");
    assert!(!fixture.source_dir.join("gone.txt").exists());

    // The journal names the begin and the commit with the Merkle root.
    let journal = store.journal_read().expect("journal");
    assert_eq!(journal.len(), 2);
    assert_eq!(journal[0].kind, JournalKind::Begin);
    assert_eq!(journal[1].kind, JournalKind::Commit);
    assert_eq!(
        journal[1].merkle_root.as_deref(),
        Some(staged.merkle_root())
    );

    // Blobs carry both sides of every changed file.
    let manifest = staged.manifest();
    assert!(
        manifest
            .ops
            .iter()
            .all(|op| op.pre.sha256.is_some() || matches!(op.action, ManifestAction::WriteFile))
    );
}

#[test]
fn undo_restores_preimages_and_redo_reapplies() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    fixture.apply(&store);

    let (undo_id, undone) = store
        .undo_latest(&fixture.source_dir)
        .expect("undo")
        .expect("an apply to undo");
    assert_eq!(undone, fixture_apply_id(&store, 1));
    assert!(
        store
            .effective_applies()
            .expect("effective")
            .contains(&undo_id)
    );

    // The host tree is back to exactly what it was.
    assert_eq!(
        read(&fixture.source_dir.join("keep.txt")),
        "original keep\n"
    );
    assert_eq!(
        read(&fixture.source_dir.join("edit.txt")),
        "original edit\n"
    );
    assert_eq!(
        read(&fixture.source_dir.join("gone.txt")),
        "original gone\n"
    );
    assert!(!fixture.source_dir.join("added.txt").exists());

    // Undo again: the undo itself is an apply, and undoing it restores the
    // applied state. An undo of an undo is a reversal in disguise, so there
    // is nothing further for redo to re-apply.
    let (undo2_id, undone2) = store
        .undo_latest(&fixture.source_dir)
        .expect("undo")
        .expect("an undo to undo");
    assert_eq!(undone2, undo_id);
    assert!(
        store
            .effective_applies()
            .expect("effective")
            .contains(&undo2_id)
    );
    assert_eq!(read(&fixture.source_dir.join("edit.txt")), "guest edit\n");
    assert!(!fixture.source_dir.join("gone.txt").exists());
    assert!(
        store
            .redo_latest(&fixture.source_dir)
            .expect("redo")
            .is_none()
    );
}

#[test]
fn redo_reapplies_a_forward_apply_after_its_undo() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    fixture.apply(&store);
    let (_undo_id, undone) = store
        .undo_latest(&fixture.source_dir)
        .expect("undo")
        .expect("an apply to undo");

    let (redo_id, redone) = store
        .redo_latest(&fixture.source_dir)
        .expect("redo")
        .expect("a redo");
    assert_eq!(redone, undone, "redo re-applies the undone forward apply");
    assert_eq!(read(&fixture.source_dir.join("edit.txt")), "guest edit\n");
    assert!(!fixture.source_dir.join("gone.txt").exists());
    assert_eq!(read(&fixture.source_dir.join("added.txt")), "guest added\n");
    assert!(
        store
            .effective_applies()
            .expect("effective")
            .contains(&redo_id)
    );
}

/// The first committed apply's id (journal commit order).
fn fixture_apply_id(store: &ApplyStore, index: usize) -> String {
    let journal = store.journal_read().expect("journal");
    journal
        .iter()
        .filter(|e| e.kind == JournalKind::Commit)
        .map(|e| e.apply.clone())
        .collect::<Vec<_>>()
        .get(index - 1)
        .cloned()
        .expect("commit entry")
}

#[test]
fn protected_match_refuses_the_whole_apply() {
    let fixture = Fixture::new();
    // The guest added a workflow file.
    let live = image(
        fixture.home.path(),
        "evil.ext4",
        vec![
            file_node("/keep.txt", b"original keep\n"),
            file_node("/edit.txt", b"original edit\n"),
            file_node("/gone.txt", b"original gone\n"),
            dir_node("/.github"),
            dir_node("/.github/workflows"),
            file_node("/.github/workflows/ci.yml", b"tampered: true\n"),
        ],
    );
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    let baseline = Ext4Tree::open(&fixture.baseline).expect("open baseline");
    let live_tree = Ext4Tree::open(&live).expect("open live");
    let protected = ProtectedPathSet::new([ProtectedPath::new(".github/workflows/**")].iter());
    let params =
        PlanParams::new(&baseline, &live_tree, &fixture.source_dir).with_protected(&protected);
    let plan = store.plan(&params).expect("plan");
    assert_eq!(
        plan.refused_protected.len(),
        2,
        "the workflow dir and the file it holds both match"
    );
    assert!(plan.ops.is_empty(), "a refusal plans no ops");
    let err = store
        .stage(plan, &fixture.source_dir, &live_tree, None)
        .expect_err("a refused plan cannot stage");
    assert!(err.to_string().contains("protected"), "{err}");
    // The host tree is untouched.
    assert_eq!(
        read(&fixture.source_dir.join("edit.txt")),
        "original edit\n"
    );
}

#[test]
fn excluded_paths_are_skipped_and_persisted() {
    let fixture = Fixture::new();
    // The guest wrote a .git file the operator excluded.
    let live = image(
        fixture.home.path(),
        "gitty.ext4",
        vec![
            file_node("/keep.txt", b"original keep\n"),
            file_node("/edit.txt", b"guest edit\n"),
            file_node("/gone.txt", b"original gone\n"),
            dir_node("/.git"),
            file_node("/.git/index", b"guest index\n"),
        ],
    );
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    let baseline = Ext4Tree::open(&fixture.baseline).expect("open baseline");
    let live_tree = Ext4Tree::open(&live).expect("open live");
    let exclusions = ProtectedPathSet::new([ProtectedPath::new(".git/**")].iter());
    let params =
        PlanParams::new(&baseline, &live_tree, &fixture.source_dir).with_exclusions(&exclusions);
    let mut plan = store.plan(&params).expect("plan");
    assert_eq!(plan.skipped_excluded, [".git", ".git/index"]);
    plan.exclusion_patterns = vec![".git/**".to_string()];
    let staged = store
        .stage(plan, &fixture.source_dir, &live_tree, None)
        .expect("stage");
    store.commit(&staged, &fixture.source_dir).expect("commit");

    // The exclusion persisted into the manifest, and the host .git was
    // never touched (it does not even exist here — nothing created it).
    assert_eq!(staged.manifest().exclusions, [".git/**"]);
    assert!(!fixture.source_dir.join(".git").exists());

    // Undoing later applies still never consults a rebuilt default list:
    // the recorded exclusions are the only ones in force.
    let history = store.history().expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].exclusions, [".git/**"]);
}

#[test]
fn crash_after_begin_rolls_back_the_half_applied_tree() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    let live_tree = Ext4Tree::open(&fixture.live).expect("open live");
    let plan = fixture.plan(&store);
    let staged = store
        .stage(plan, &fixture.source_dir, &live_tree, None)
        .expect("stage");
    let id = staged.id().to_string();

    // Simulate the crash window: one host write landed, the rest did not.
    fs::write(fixture.source_dir.join("edit.txt"), "guest edit\n").expect("partial write");

    // The next open rolls the half-applied tree back from the snapshot.
    let store = ApplyStore::open(&fixture.store_dir).expect("reopen store");
    let rolled_back = store
        .recover_source(&fixture.source_dir)
        .expect("recover")
        .expect("a pending apply");
    assert_eq!(rolled_back, id);
    assert_eq!(
        read(&fixture.source_dir.join("edit.txt")),
        "original edit\n"
    );
    assert!(!fixture.source_dir.join("added.txt").exists());

    let journal = store.journal_read().expect("journal");
    assert!(journal.iter().any(|e| e.kind == JournalKind::Rollback));
    // Staging is swept; nothing effective remains.
    assert!(store.effective_applies().expect("effective").is_empty());
}

#[test]
fn crash_after_done_completes_the_commit() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    let live_tree = Ext4Tree::open(&fixture.live).expect("open live");
    let plan = fixture.plan(&store);
    let staged = store
        .stage(plan, &fixture.source_dir, &live_tree, None)
        .expect("stage");
    let id = staged.id().to_string();

    // Simulate the crash window: every write landed and the done marker is
    // durable, but the journal commit never happened.
    fs::write(fixture.source_dir.join("edit.txt"), "guest edit\n").expect("write");
    fs::remove_file(fixture.source_dir.join("gone.txt")).expect("remove");
    fs::write(fixture.source_dir.join("added.txt"), "guest added\n").expect("write");
    let staging = fixture.store_dir.join("staging").join(&id);
    fs::write(staging.join("done"), id.as_bytes()).expect("done marker");

    let store = ApplyStore::open(&fixture.store_dir).expect("reopen store");
    let journal = store.journal_read().expect("journal");
    assert!(
        journal
            .iter()
            .any(|e| e.kind == JournalKind::Commit && e.apply == id),
        "open completed the commit: {journal:#?}"
    );
    assert_eq!(store.effective_applies().expect("effective"), [id]);
}

#[test]
fn nothing_to_undo_or_redo_says_so() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    assert!(
        store
            .undo_latest(&fixture.source_dir)
            .expect("undo")
            .is_none()
    );
    assert!(
        store
            .redo_latest(&fixture.source_dir)
            .expect("redo")
            .is_none()
    );
}

#[test]
fn redo_refuses_when_a_newer_apply_exists() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    fixture.apply(&store);
    store.undo_latest(&fixture.source_dir).expect("undo");

    // A second, different apply lands on the restored tree.
    let live2 = image(
        fixture.home.path(),
        "live2.ext4",
        vec![
            file_node("/keep.txt", b"original keep\n"),
            file_node("/edit.txt", b"second edit\n"),
            file_node("/gone.txt", b"original gone\n"),
        ],
    );
    let baseline2 = image(
        fixture.home.path(),
        "baseline2.ext4",
        vec![
            file_node("/keep.txt", b"original keep\n"),
            file_node("/edit.txt", b"original edit\n"),
            file_node("/gone.txt", b"original gone\n"),
        ],
    );
    let live_tree = Ext4Tree::open(&live2).expect("open live2");
    let baseline_tree = Ext4Tree::open(&baseline2).expect("open baseline2");
    let params = PlanParams::new(&baseline_tree, &live_tree, &fixture.source_dir);
    let plan = store.plan(&params).expect("plan");
    let staged = store
        .stage(plan, &fixture.source_dir, &live_tree, None)
        .expect("stage");
    store.commit(&staged, &fixture.source_dir).expect("commit");

    // The undo is no longer the newest effective apply: redo refuses.
    assert!(
        store
            .redo_latest(&fixture.source_dir)
            .expect("redo")
            .is_none()
    );
}

#[test]
fn a_missing_post_blob_is_corruption_not_a_silent_skip() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    let live_tree = Ext4Tree::open(&fixture.live).expect("open live");
    let plan = fixture.plan(&store);
    let staged = store
        .stage(plan, &fixture.source_dir, &live_tree, None)
        .expect("stage");
    // An operator (or disk loss) deletes a blob; the commit must refuse
    // rather than write something else.
    let post = staged
        .manifest()
        .ops
        .iter()
        .find_map(|op| op.post.as_ref().and_then(|p| p.sha256.clone()))
        .expect("a post blob");
    fs::remove_file(fixture.store_dir.join("blobs").join(&post)).expect("remove blob");
    let err = store
        .commit(&staged, &fixture.source_dir)
        .expect_err("commit refuses");
    assert!(err.to_string().contains("missing"), "{err}");
}
