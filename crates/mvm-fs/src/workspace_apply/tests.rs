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
fn snapshot_root_binds_only_path_ordered_host_preimages() {
    let first = ManifestOp {
        path: "edit.txt".to_string(),
        action: ManifestAction::WriteFile,
        pre: OpImage {
            sha256: Some("a".repeat(64)),
            size: 3,
        },
        pre_kind: Some(PreImageKind::File),
        post: Some(OpImage {
            sha256: Some("b".repeat(64)),
            size: 5,
        }),
    };
    let added = ManifestOp {
        path: "added.txt".to_string(),
        action: ManifestAction::WriteFile,
        pre: OpImage::default(),
        pre_kind: Some(PreImageKind::Absent),
        post: Some(OpImage {
            sha256: Some("c".repeat(64)),
            size: 7,
        }),
    };
    let expected = snapshot_merkle_root(&[first.clone(), added.clone()]);
    assert_eq!(
        expected,
        snapshot_merkle_root(&[added.clone(), first.clone()])
    );
    assert_eq!(expected.len(), 64);

    let mut different_post = first.clone();
    different_post.post.as_mut().expect("post image").size = 99;
    assert_eq!(
        expected,
        snapshot_merkle_root(&[different_post, added.clone()])
    );

    let mut different_pre = first;
    different_pre.pre.size = 4;
    assert_ne!(expected, snapshot_merkle_root(&[different_pre, added]));
}

#[test]
fn snapshot_root_distinguishes_file_bytes_from_symlink_target_bytes() {
    let file = Fixture::new();
    fs::write(file.source_dir.join("edit.txt"), "keep.txt").expect("host file");
    let file_store = ApplyStore::open(&file.store_dir).expect("file store");
    let file_live = Ext4Tree::open(&file.live).expect("file live image");
    let file_staged = file_store
        .stage(file.plan(&file_store), &file.source_dir, &file_live, None)
        .expect("stage file pre-image");

    let link = Fixture::new();
    fs::remove_file(link.source_dir.join("edit.txt")).expect("remove host file");
    std::os::unix::fs::symlink("keep.txt", link.source_dir.join("edit.txt")).expect("host symlink");
    let link_store = ApplyStore::open(&link.store_dir).expect("link store");
    let link_live = Ext4Tree::open(&link.live).expect("link live image");
    let link_staged = link_store
        .stage(link.plan(&link_store), &link.source_dir, &link_live, None)
        .expect("stage symlink pre-image");

    assert_ne!(
        file_staged.snapshot_merkle_root(),
        link_staged.snapshot_merkle_root(),
        "the signed snapshot must bind the prior path kind"
    );
}

#[test]
fn undo_and_redo_restore_a_symlink_replaced_by_a_file() {
    let fixture = Fixture::new();
    let path = fixture.source_dir.join("edit.txt");
    fs::remove_file(&path).expect("remove host file");
    std::os::unix::fs::symlink("keep.txt", &path).expect("host symlink");
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    fixture.apply(&store);
    assert!(fs::symlink_metadata(&path).expect("applied file").is_file());

    store
        .undo_latest(&fixture.source_dir)
        .expect("undo")
        .expect("prior apply");
    assert!(
        fs::symlink_metadata(&path)
            .expect("restored link")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(&path).expect("target"), Path::new("keep.txt"));

    store
        .redo_latest(&fixture.source_dir)
        .expect("redo")
        .expect("prior undo");
    assert!(
        fs::symlink_metadata(&path)
            .expect("reapplied file")
            .is_file()
    );
    assert_eq!(read(&path), "guest edit\n");
}

#[test]
fn undo_restores_a_removed_host_symlink() {
    let fixture = Fixture::new();
    let path = fixture.source_dir.join("gone.txt");
    fs::remove_file(&path).expect("remove host file");
    std::os::unix::fs::symlink("keep.txt", &path).expect("host symlink");
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    fixture.apply(&store);
    assert!(fs::symlink_metadata(&path).is_err());

    store
        .undo_latest(&fixture.source_dir)
        .expect("undo")
        .expect("prior apply");
    assert!(
        fs::symlink_metadata(&path)
            .expect("restored link")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(&path).expect("target"), Path::new("keep.txt"));
}

#[test]
fn contradictory_typed_pre_image_refuses_undo_without_host_write() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let staged = fixture.apply(&store);
    let path = fixture
        .store_dir
        .join("committed")
        .join(staged.id())
        .join("manifest.json");
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(&path).expect("read manifest")).expect("decode");
    let edited = manifest
        .ops
        .iter_mut()
        .find(|op| op.path == "edit.txt")
        .expect("edited op");
    edited.pre_kind = Some(PreImageKind::Absent);
    fs::write(&path, serde_json::to_vec(&manifest).expect("encode")).expect("corrupt manifest");

    let error = store
        .undo_latest(&fixture.source_dir)
        .expect_err("inconsistent typed image must be refused");
    assert!(
        error.to_string().contains("kind and digest disagree"),
        "{error}"
    );
    assert_eq!(read(&fixture.source_dir.join("edit.txt")), "guest edit\n");
}

#[test]
fn crash_recovery_restores_a_symlink_replaced_by_a_file() {
    let fixture = Fixture::new();
    let path = fixture.source_dir.join("edit.txt");
    fs::remove_file(&path).expect("remove host file");
    std::os::unix::fs::symlink("keep.txt", &path).expect("host symlink");
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let live = Ext4Tree::open(&fixture.live).expect("live image");
    store
        .stage(fixture.plan(&store), &fixture.source_dir, &live, None)
        .expect("stage");
    fs::remove_file(&path).expect("remove link during partial apply");
    fs::write(&path, "guest edit\n").expect("partial file write");

    let recovered = ApplyStore::open(&fixture.store_dir).expect("reopen store");
    recovered
        .recover_source(&fixture.source_dir)
        .expect("recover")
        .expect("pending apply");
    assert!(
        fs::symlink_metadata(&path)
            .expect("restored link")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(&path).expect("target"), Path::new("keep.txt"));
}

#[test]
fn undo_and_redo_restore_a_file_replaced_by_a_symlink() {
    let fixture = Fixture::new();
    let live = Ext4Tree::open(&fixture.live).expect("live");
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let plan = ApplyPlan {
        ops: vec![FileOp {
            path: "edit.txt".to_string(),
            action: OpAction::WriteSymlink {
                target: "keep.txt".to_string(),
            },
            pre: OpImage::default(),
            post: Some(OpImage {
                sha256: None,
                size: 8,
            }),
        }],
        ..ApplyPlan::default()
    };
    let staged = store
        .stage(plan, &fixture.source_dir, &live, None)
        .expect("stage");
    store.commit(&staged, &fixture.source_dir).expect("commit");
    let path = fixture.source_dir.join("edit.txt");
    assert!(
        fs::symlink_metadata(&path)
            .expect("applied link")
            .file_type()
            .is_symlink()
    );

    store
        .undo_latest(&fixture.source_dir)
        .expect("undo")
        .expect("prior apply");
    assert!(
        fs::symlink_metadata(&path)
            .expect("restored file")
            .is_file()
    );
    assert_eq!(read(&path), "original edit\n");

    store
        .redo_latest(&fixture.source_dir)
        .expect("redo")
        .expect("prior undo");
    assert!(
        fs::symlink_metadata(&path)
            .expect("reapplied link")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(&path).expect("target"), Path::new("keep.txt"));
}

#[test]
fn staging_refuses_a_host_symlink_target_that_cannot_be_restored() {
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new();
    let path = fixture.source_dir.join("edit.txt");
    fs::remove_file(&path).expect("remove host file");
    let target = std::ffi::OsString::from_vec(vec![0xff]);
    std::os::unix::fs::symlink(&target, &path).expect("host symlink");
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let live = Ext4Tree::open(&fixture.live).expect("live");
    let error = store
        .stage(fixture.plan(&store), &fixture.source_dir, &live, None)
        .expect_err("unrestorable pre-image must be refused");
    assert!(error.to_string().contains("not UTF-8"), "{error}");
    assert!(
        fs::symlink_metadata(&path)
            .expect("host link intact")
            .file_type()
            .is_symlink()
    );
}

#[test]
fn typed_pre_image_roundtrips_and_legacy_manifest_op_still_parses() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let staged = fixture.apply(&store);
    let op = staged
        .manifest()
        .ops
        .iter()
        .find(|op| op.path == "edit.txt")
        .expect("edited op");
    let encoded = serde_json::to_value(op).expect("serialize");
    let decoded: ManifestOp = serde_json::from_value(encoded.clone()).expect("typed decode");
    assert_eq!(decoded.pre_kind, Some(PreImageKind::File));

    let mut legacy = encoded.clone();
    legacy.as_object_mut().expect("object").remove("pre_kind");
    let decoded: ManifestOp = serde_json::from_value(legacy).expect("legacy decode");
    assert_eq!(decoded.pre_kind, None);

    let mut invalid = encoded;
    invalid["pre_kind"] = serde_json::json!("device");
    assert!(serde_json::from_value::<ManifestOp>(invalid).is_err());
}

#[test]
fn a_legacy_manifest_without_path_kinds_still_undoes_same_kind_files() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let staged = fixture.apply(&store);
    let path = fixture
        .store_dir
        .join("committed")
        .join(staged.id())
        .join("manifest.json");
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(&path).expect("read manifest")).expect("decode");
    for op in &mut manifest.ops {
        op.pre_kind = None;
    }
    manifest.merkle_root = manifest_merkle_root(&manifest.ops);
    fs::write(&path, serde_json::to_vec(&manifest).expect("encode")).expect("legacy manifest");

    store
        .undo_latest(&fixture.source_dir)
        .expect("legacy undo")
        .expect("prior apply");
    assert_eq!(
        read(&fixture.source_dir.join("edit.txt")),
        "original edit\n"
    );
    assert_eq!(
        read(&fixture.source_dir.join("gone.txt")),
        "original gone\n"
    );
    assert!(!fixture.source_dir.join("added.txt").exists());
}

#[test]
fn undo_restores_preimages_and_redo_reapplies() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    fixture.apply(&store);

    let undo = store
        .undo_latest(&fixture.source_dir)
        .expect("undo")
        .expect("an apply to undo");
    assert_eq!(undo.target_id, fixture_apply_id(&store, 1));
    assert_eq!(
        store
            .history()
            .expect("history")
            .last()
            .expect("undo manifest")
            .merkle_root,
        undo.merkle_root
    );
    assert!(
        store
            .effective_applies()
            .expect("effective")
            .contains(&undo.apply_id)
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
    let undo2 = store
        .undo_latest(&fixture.source_dir)
        .expect("undo")
        .expect("an undo to undo");
    assert_eq!(undo2.target_id, undo.apply_id);
    assert!(
        store
            .effective_applies()
            .expect("effective")
            .contains(&undo2.apply_id)
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
    let undo = store
        .undo_latest(&fixture.source_dir)
        .expect("undo")
        .expect("an apply to undo");

    let redo = store
        .redo_latest(&fixture.source_dir)
        .expect("redo")
        .expect("a redo");
    assert_eq!(
        redo.target_id, undo.target_id,
        "redo re-applies the undone forward apply"
    );
    assert_eq!(
        store
            .history()
            .expect("history")
            .last()
            .expect("redo manifest")
            .merkle_root,
        redo.merkle_root
    );
    assert_eq!(read(&fixture.source_dir.join("edit.txt")), "guest edit\n");
    assert!(!fixture.source_dir.join("gone.txt").exists());
    assert_eq!(read(&fixture.source_dir.join("added.txt")), "guest added\n");
    assert!(
        store
            .effective_applies()
            .expect("effective")
            .contains(&redo.apply_id)
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
fn failed_apply_audit_cancels_the_commit_and_restores_host_pre_images() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let staged = fixture.apply(&store);
    assert_eq!(read(&fixture.source_dir.join("edit.txt")), "guest edit\n");

    store
        .rollback_unsealed(&staged, &fixture.source_dir)
        .expect("restore after audit failure");
    assert_eq!(
        read(&fixture.source_dir.join("edit.txt")),
        "original edit\n"
    );
    assert_eq!(
        read(&fixture.source_dir.join("gone.txt")),
        "original gone\n"
    );
    assert!(!fixture.source_dir.join("added.txt").exists());
    assert!(store.effective_applies().expect("effective").is_empty());
    assert!(store.history().expect("history").is_empty());
    assert!(
        store
            .redo_latest(&fixture.source_dir)
            .expect("redo")
            .is_none()
    );
    let journal = store.journal_read().expect("journal");
    assert_eq!(
        journal.iter().map(|entry| entry.kind).collect::<Vec<_>>(),
        [
            JournalKind::Begin,
            JournalKind::Commit,
            JournalKind::Rollback
        ]
    );

    let reopened = ApplyStore::open(&fixture.store_dir).expect("reopen");
    assert!(reopened.effective_applies().expect("effective").is_empty());
}

#[test]
fn pending_signed_audit_survives_commit_and_blocks_a_second_stage() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let live = Ext4Tree::open(&fixture.live).expect("live image");
    let plan = fixture.plan(&store);
    let staged = store
        .stage(plan.clone(), &fixture.source_dir, &live, None)
        .expect("stage");
    store.arm_signed_audit(&staged).expect("arm audit");
    store.commit(&staged, &fixture.source_dir).expect("commit");

    let reopened = ApplyStore::open(&fixture.store_dir).expect("reopen");
    let pending = reopened.pending_signed_audits().expect("pending audits");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id(), staged.id());
    assert_eq!(pending[0].merkle_root(), staged.merkle_root());
    assert!(matches!(
        reopened.stage(plan, &fixture.source_dir, &live, None),
        Err(ApplyError::PendingApply)
    ));

    reopened.seal_signed_audit(&staged).expect("seal audit");
    assert!(
        reopened
            .pending_signed_audits()
            .expect("pending")
            .is_empty()
    );
}

#[test]
fn failed_signed_audit_rollback_is_not_recovered_as_a_pending_commit() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let live = Ext4Tree::open(&fixture.live).expect("live image");
    let staged = store
        .stage(fixture.plan(&store), &fixture.source_dir, &live, None)
        .expect("stage");
    store.arm_signed_audit(&staged).expect("arm audit");
    store.commit(&staged, &fixture.source_dir).expect("commit");
    store
        .rollback_unsealed(&staged, &fixture.source_dir)
        .expect("rollback");

    let reopened = ApplyStore::open(&fixture.store_dir).expect("reopen");
    assert!(
        reopened
            .pending_signed_audits()
            .expect("pending")
            .is_empty()
    );
    assert!(reopened.effective_applies().expect("effective").is_empty());
}

#[test]
fn unverifiable_audit_restores_host_and_blocks_until_settled() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let live = Ext4Tree::open(&fixture.live).expect("live image");
    let plan = fixture.plan(&store);
    let staged = store
        .stage(plan.clone(), &fixture.source_dir, &live, None)
        .expect("stage");
    store.arm_signed_audit(&staged).expect("arm audit");
    store.commit(&staged, &fixture.source_dir).expect("commit");

    store
        .rollback_unverifiable(&staged, &fixture.source_dir)
        .expect("restore host pre-images");
    assert_eq!(
        read(&fixture.source_dir.join("edit.txt")),
        "original edit\n"
    );
    assert!(store.effective_applies().expect("effective").is_empty());

    let reopened = ApplyStore::open(&fixture.store_dir).expect("reopen");
    let uncertain = reopened.uncertain_signed_audits().expect("uncertain");
    assert_eq!(uncertain.len(), 1);
    assert_eq!(uncertain[0].id(), staged.id());
    assert!(matches!(
        reopened.stage(plan.clone(), &fixture.source_dir, &live, None),
        Err(ApplyError::PendingApply)
    ));
    reopened
        .rollback_unverifiable(&uncertain[0], &fixture.source_dir)
        .expect("idempotent recovery");
    reopened
        .settle_uncertain_signed_audit(&uncertain[0])
        .expect("settle after chain reconciliation");
    assert!(
        reopened
            .uncertain_signed_audits()
            .expect("uncertain")
            .is_empty()
    );
    assert!(
        reopened
            .pending_signed_audits()
            .expect("pending")
            .is_empty()
    );
    assert!(
        reopened
            .stage(plan, &fixture.source_dir, &live, None)
            .is_ok()
    );
}

#[test]
fn an_interrupted_uncertain_rollback_is_repeated_from_pre_images() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let live = Ext4Tree::open(&fixture.live).expect("live image");
    let staged = store
        .stage(fixture.plan(&store), &fixture.source_dir, &live, None)
        .expect("stage");
    store.arm_signed_audit(&staged).expect("arm audit");
    store.commit(&staged, &fixture.source_dir).expect("commit");
    let marker = fixture
        .store_dir
        .join("committed")
        .join(staged.id())
        .join("signed-audit-uncertain");
    fs::write(&marker, staged.id()).expect("interrupted rollback intent");

    let reopened = ApplyStore::open(&fixture.store_dir).expect("reopen");
    let uncertain = reopened.uncertain_signed_audits().expect("uncertain");
    assert_eq!(uncertain.len(), 1);
    reopened
        .rollback_unverifiable(&uncertain[0], &fixture.source_dir)
        .expect("finish interrupted rollback");
    assert_eq!(
        read(&fixture.source_dir.join("edit.txt")),
        "original edit\n"
    );
    assert!(reopened.effective_applies().expect("effective").is_empty());
}

#[test]
fn a_non_file_uncertain_marker_is_refused_before_host_rollback() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let live = Ext4Tree::open(&fixture.live).expect("live image");
    let staged = store
        .stage(fixture.plan(&store), &fixture.source_dir, &live, None)
        .expect("stage");
    store.arm_signed_audit(&staged).expect("arm audit");
    store.commit(&staged, &fixture.source_dir).expect("commit");
    let marker = fixture
        .store_dir
        .join("committed")
        .join(staged.id())
        .join("signed-audit-uncertain");
    let target = fixture.store_dir.join("unrelated");
    fs::write(&target, staged.id()).expect("target");
    symlink(&target, &marker).expect("symlink");

    assert!(store.uncertain_signed_audits().is_err());
    assert!(
        store
            .rollback_unverifiable(&staged, &fixture.source_dir)
            .is_err()
    );
    assert_eq!(read(&fixture.source_dir.join("edit.txt")), "guest edit\n");
}

#[test]
fn a_tampered_pending_audit_marker_is_not_ignored() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let live = Ext4Tree::open(&fixture.live).expect("live image");
    let staged = store
        .stage(fixture.plan(&store), &fixture.source_dir, &live, None)
        .expect("stage");
    store.arm_signed_audit(&staged).expect("arm audit");
    store.commit(&staged, &fixture.source_dir).expect("commit");
    let marker = fixture
        .store_dir
        .join("committed")
        .join(staged.id())
        .join("signed-audit-pending");
    fs::remove_file(&marker).expect("remove marker");
    std::os::unix::fs::symlink("missing", &marker).expect("tamper marker");

    let error = store
        .pending_signed_audits()
        .expect_err("symlink marker must be refused");
    assert!(error.to_string().contains("non-file"), "{error}");
}

#[test]
fn crash_after_done_keeps_the_audit_marker_for_unsigned_commit_recovery() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let live = Ext4Tree::open(&fixture.live).expect("live image");
    let staged = store
        .stage(fixture.plan(&store), &fixture.source_dir, &live, None)
        .expect("stage");
    store.arm_signed_audit(&staged).expect("arm audit");
    let staging = fixture.store_dir.join("staging").join(staged.id());
    fs::write(fixture.source_dir.join("edit.txt"), "guest edit\n").expect("write edit");
    fs::write(fixture.source_dir.join("added.txt"), "guest added\n").expect("write added");
    fs::create_dir_all(staging.join("trash")).expect("trash");
    fs::rename(
        fixture.source_dir.join("gone.txt"),
        staging.join("trash/gone.txt"),
    )
    .expect("trash removed file");
    fs::write(staging.join("done"), staged.id()).expect("done marker");

    let reopened = ApplyStore::open(&fixture.store_dir).expect("complete commit");
    let pending = reopened.pending_signed_audits().expect("pending");
    assert_eq!(pending.len(), 1);
    reopened
        .rollback_unsealed(&pending[0], &fixture.source_dir)
        .expect("restore unsigned commit");
    assert_eq!(
        read(&fixture.source_dir.join("edit.txt")),
        "original edit\n"
    );
    assert_eq!(
        read(&fixture.source_dir.join("gone.txt")),
        "original gone\n"
    );
    assert!(!fixture.source_dir.join("added.txt").exists());
    assert!(reopened.effective_applies().expect("effective").is_empty());
}

#[test]
fn crash_after_move_before_commit_journal_keeps_audit_recovery_possible() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let live = Ext4Tree::open(&fixture.live).expect("live image");
    let staged = store
        .stage(fixture.plan(&store), &fixture.source_dir, &live, None)
        .expect("stage");
    store.arm_signed_audit(&staged).expect("arm audit");
    let staging = fixture.store_dir.join("staging").join(staged.id());
    fs::write(fixture.source_dir.join("edit.txt"), "guest edit\n").expect("write edit");
    fs::write(fixture.source_dir.join("added.txt"), "guest added\n").expect("write added");
    fs::create_dir_all(staging.join("trash")).expect("trash");
    fs::rename(
        fixture.source_dir.join("gone.txt"),
        staging.join("trash/gone.txt"),
    )
    .expect("trash removed file");
    fs::write(staging.join("done"), staged.id()).expect("done marker");
    fs::rename(
        &staging,
        fixture.store_dir.join("committed").join(staged.id()),
    )
    .expect("move before journal");

    let reopened = ApplyStore::open(&fixture.store_dir).expect("complete commit");
    assert_eq!(reopened.pending_signed_audits().expect("pending").len(), 1);
    let pending = reopened.pending_signed_audits().expect("pending");
    reopened
        .rollback_unsealed(&pending[0], &fixture.source_dir)
        .expect("restore unsigned commit");
    assert_eq!(
        read(&fixture.source_dir.join("edit.txt")),
        "original edit\n"
    );
    assert_eq!(
        read(&fixture.source_dir.join("gone.txt")),
        "original gone\n"
    );
    assert!(!fixture.source_dir.join("added.txt").exists());
}

#[test]
fn crash_before_done_with_audit_marker_uses_partial_apply_recovery() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let live = Ext4Tree::open(&fixture.live).expect("live image");
    let staged = store
        .stage(fixture.plan(&store), &fixture.source_dir, &live, None)
        .expect("stage");
    store.arm_signed_audit(&staged).expect("arm audit");
    fs::write(fixture.source_dir.join("edit.txt"), "guest edit\n").expect("partial write");

    let reopened = ApplyStore::open(&fixture.store_dir).expect("reopen");
    reopened
        .recover_source(&fixture.source_dir)
        .expect("recover")
        .expect("pending partial apply");
    assert_eq!(
        read(&fixture.source_dir.join("edit.txt")),
        "original edit\n"
    );
    assert!(
        reopened
            .pending_signed_audits()
            .expect("pending")
            .is_empty()
    );
}

#[test]
fn audit_rollback_restores_a_replaced_symlink() {
    let fixture = Fixture::new();
    let path = fixture.source_dir.join("edit.txt");
    fs::remove_file(&path).expect("remove host file");
    std::os::unix::fs::symlink("keep.txt", &path).expect("host symlink");
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let staged = fixture.apply(&store);

    store
        .rollback_unsealed(&staged, &fixture.source_dir)
        .expect("audit rollback");
    assert!(
        fs::symlink_metadata(&path)
            .expect("restored path")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(&path).expect("target"), Path::new("keep.txt"));
}

#[test]
fn audit_rollback_refuses_to_clobber_a_newer_commit() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("store");
    let first = fixture.apply(&store);
    fixture.apply(&store);

    let error = store
        .rollback_unsealed(&first, &fixture.source_dir)
        .expect_err("older apply cannot be cancelled");
    assert!(error.to_string().contains("not the latest"), "{error}");
    assert_eq!(read(&fixture.source_dir.join("edit.txt")), "guest edit\n");
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

#[test]
fn crash_mid_undo_rolls_back_to_the_applied_tree() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    let applied = fixture.apply(&store);
    let undo = store
        .stage_undo(&fixture.source_dir)
        .expect("stage undo")
        .expect("an apply to undo");

    // Simulate the crash window: one of the undo's host writes landed.
    fs::write(fixture.source_dir.join("edit.txt"), "original edit\n").expect("partial undo");

    let store = ApplyStore::open(&fixture.store_dir).expect("reopen store");
    let rolled_back = store
        .recover_source(&fixture.source_dir)
        .expect("recover")
        .expect("the interrupted undo");
    assert_eq!(rolled_back, undo.id());
    assert_eq!(read(&fixture.source_dir.join("edit.txt")), "guest edit\n");
    assert_eq!(read(&fixture.source_dir.join("added.txt")), "guest added\n");
    assert!(!fixture.source_dir.join("gone.txt").exists());
    assert_eq!(
        store.effective_applies().expect("effective"),
        [applied.id()],
        "the apply the undo targeted is still in force"
    );
}

#[test]
fn crash_after_undo_done_completes_the_undo() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    fixture.apply(&store);
    let undo = store
        .stage_undo(&fixture.source_dir)
        .expect("stage undo")
        .expect("an apply to undo");

    // Every undo write landed and the done marker is durable, but the
    // journal commit never happened.
    fs::write(fixture.source_dir.join("edit.txt"), "original edit\n").expect("write");
    fs::write(fixture.source_dir.join("gone.txt"), "original gone\n").expect("write");
    fs::remove_file(fixture.source_dir.join("added.txt")).expect("remove");
    let staging = fixture.store_dir.join("staging").join(undo.id());
    fs::write(staging.join("done"), undo.id().as_bytes()).expect("done marker");

    let store = ApplyStore::open(&fixture.store_dir).expect("reopen store");
    assert!(
        store
            .journal_read()
            .expect("journal")
            .iter()
            .any(|e| e.kind == JournalKind::Commit && e.apply == undo.id()),
        "open completed the undo's commit"
    );
    assert_eq!(store.effective_applies().expect("effective"), [undo.id()]);
    assert!(
        store
            .stage_redo(&fixture.source_dir)
            .expect("stage redo")
            .is_some(),
        "the completed undo can be redone"
    );
}

#[test]
fn crash_mid_redo_rolls_back_to_the_undone_tree() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    fixture.apply(&store);
    let undone = store
        .undo_latest(&fixture.source_dir)
        .expect("undo")
        .expect("an apply to undo");
    let redo = store
        .stage_redo(&fixture.source_dir)
        .expect("stage redo")
        .expect("an undo to redo");
    assert_eq!(
        redo.relation().expect("a redo relation").target_id,
        undone.target_id
    );

    // Simulate the crash window: one of the redo's host writes landed.
    fs::write(fixture.source_dir.join("edit.txt"), "guest edit\n").expect("partial redo");

    let store = ApplyStore::open(&fixture.store_dir).expect("reopen store");
    let rolled_back = store
        .recover_source(&fixture.source_dir)
        .expect("recover")
        .expect("the interrupted redo");
    assert_eq!(rolled_back, redo.id());
    assert_eq!(
        read(&fixture.source_dir.join("edit.txt")),
        "original edit\n"
    );
    assert_eq!(
        read(&fixture.source_dir.join("gone.txt")),
        "original gone\n"
    );
    assert!(!fixture.source_dir.join("added.txt").exists());
    assert_eq!(
        store.effective_applies().expect("effective"),
        [undone.apply_id],
        "the undo is still the newest effective apply"
    );
}

#[test]
fn a_staged_undo_names_its_target_and_writes_nothing() {
    let fixture = Fixture::new();
    let store = ApplyStore::open(&fixture.store_dir).expect("open store");
    let applied = fixture.apply(&store);
    let undo = store
        .stage_undo(&fixture.source_dir)
        .expect("stage undo")
        .expect("an apply to undo");
    let relation = undo.relation().expect("an undo relation");
    assert_eq!(relation.target_id, applied.id());
    assert_eq!(relation.apply_id, undo.id());
    assert_eq!(read(&fixture.source_dir.join("edit.txt")), "guest edit\n");
    assert!(
        applied.relation().is_none(),
        "a forward apply relates to nothing"
    );
}
