//! Plugs `mvm_fs`'s content-addressed [`SnapshotStore`] in *beneath* the
//! existing checkpoint lineage (`crate::checkpoint`), rather than building a
//! second provenance graph.
//!
//! The checkpoint stays the single lineage node: content-addressed,
//! hash-linked to its parent, and anchored to the signed audit chain. This
//! module only changes how a checkpoint's bytes are physically staged and
//! cloned — via the `SnapshotStore`'s O(1) reflink/sparse-copy primitive
//! instead of a per-blob walk — and it gates every clone on the SAME
//! fail-closed verification every other fork path uses:
//! [`crate::checkpoint::verify_content`] then
//! [`crate::checkpoint::verify_lineage`]. Nothing is cloned until both pass.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_core::checkpoint::CheckpointId;
use mvm_fs::clone::CloneStrategy;
use mvm_fs::snapshot_store::{FsSnapshotStore, SnapshotId, SnapshotStore};

use crate::checkpoint::{CheckpointChainAnchor, CheckpointStore, verify_content, verify_lineage};

/// Store a checkpoint's content dir into the content-addressed snapshot
/// store, deduplicating identical bytes with an existing snapshot. The
/// checkpoint's `meta.json` remains the sole lineage record; this only moves
/// where its bytes physically live so a later clone can materialize via
/// reflink/sparse CoW instead of per-blob copies.
pub fn stage_warm_snapshot(
    checkpoint_store: &CheckpointStore,
    snapshot_store: &FsSnapshotStore,
    id: &CheckpointId,
) -> Result<SnapshotId> {
    let content_dir = checkpoint_store.content_dir(id);
    snapshot_store
        .create_content_addressed(&content_dir)
        .with_context(|| format!("staging checkpoint '{id}' content into the snapshot store"))
}

/// Materialize a staged warm snapshot at `dst`, but only after `parent_id`
/// clears the same fail-closed lineage gate `fork_checkpoint` /
/// `fork_vm_full_fc` use: `read_meta -> verify_content -> verify_lineage`.
/// Nothing is cloned until all three succeed — a missing, un-audited, or
/// hash-mismatched parent leaves `dst` uncreated and the error propagates.
pub fn materialize_child_from_parent(
    checkpoint_store: &CheckpointStore,
    snapshot_store: &FsSnapshotStore,
    parent_id: &CheckpointId,
    staged: &SnapshotId,
    anchor: &dyn CheckpointChainAnchor,
    dst: &Path,
) -> Result<CloneStrategy> {
    let parent = checkpoint_store.read_meta(parent_id)?;
    verify_content(checkpoint_store, &parent)?;
    verify_lineage(checkpoint_store, parent_id, anchor)?;

    snapshot_store
        .materialize(staged, dst)
        .with_context(|| format!("materializing staged snapshot at {}", dst.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{CaptureFsQuickParams, capture_fs_quick};
    use mvm_core::checkpoint::{CheckpointDigest, CheckpointMeta};
    use std::collections::HashMap;
    use std::io::Write;

    /// A mock anchor whose verdict per parent digest is set up by the test:
    /// audited (echoes the real digest), un-audited (`Ok(None)`), or a fixed
    /// wrong digest (hash-mismatch / re-forge).
    #[derive(Default)]
    struct MockAnchor {
        verdicts: HashMap<String, Option<CheckpointDigest>>,
    }

    impl MockAnchor {
        fn audited(mut self, meta: &CheckpointMeta) -> Self {
            self.verdicts
                .insert(meta.id.to_string(), Some(meta.compute_meta_digest()));
            self
        }

        fn unaudited(mut self, id: &CheckpointId) -> Self {
            self.verdicts.insert(id.to_string(), None);
            self
        }
    }

    impl CheckpointChainAnchor for MockAnchor {
        fn recorded_creation_digest(
            &self,
            meta: &CheckpointMeta,
        ) -> Result<Option<CheckpointDigest>> {
            match self.verdicts.get(&meta.id.to_string()) {
                Some(v) => Ok(v.clone()),
                // Not configured for this id: treat as un-audited rather than
                // panicking, so tests only need to set up the case they exercise.
                None => Ok(None),
            }
        }
    }

    fn write_fake_rootfs(dir: &Path) -> std::path::PathBuf {
        let p = dir.join("rootfs.ext4");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"warm-parent-rootfs-bytes").unwrap();
        p
    }

    fn seed_parent(store: &CheckpointStore, tmp: &Path, id: &str) -> CheckpointMeta {
        let rootfs = write_fake_rootfs(tmp);
        capture_fs_quick(
            store,
            CaptureFsQuickParams {
                id: CheckpointId::new(id),
                vm_name: "warm-parent".into(),
                rootfs,
                supervisor_config_digest: "d".into(),
                runtime_source_policy: None,
                runtime_overlay_version: None,
                tag: None,
                created_unix: 1,
                quiesced: true,
            },
        )
        .unwrap()
    }

    #[test]
    fn positive_control_audited_parent_materializes_via_snapshot_store() {
        let tmp = tempfile::tempdir().unwrap();
        let checkpoint_store = CheckpointStore::at(tmp.path().join("checkpoints"));
        let snapshot_store = FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap();

        let parent = seed_parent(&checkpoint_store, tmp.path(), "warm-1");
        let staged = stage_warm_snapshot(&checkpoint_store, &snapshot_store, &parent.id).unwrap();

        let anchor = MockAnchor::default().audited(&parent);
        let dst = tmp.path().join("instance-rootfs-dir");
        let strategy = materialize_child_from_parent(
            &checkpoint_store,
            &snapshot_store,
            &parent.id,
            &staged,
            &anchor,
            &dst,
        )
        .expect("audited, intact parent must materialize");

        assert!(matches!(
            strategy,
            CloneStrategy::Reflink | CloneStrategy::Copied
        ));
        assert_eq!(
            std::fs::read(dst.join("rootfs.ext4")).unwrap(),
            b"warm-parent-rootfs-bytes",
            "materialized bytes must byte-equal the staged content"
        );
    }

    #[test]
    fn negative_missing_parent_refuses_before_any_clone() {
        let tmp = tempfile::tempdir().unwrap();
        let checkpoint_store = CheckpointStore::at(tmp.path().join("checkpoints"));
        let snapshot_store = FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap();

        // Never seeded: read_meta must fail before any staged snapshot exists.
        let missing_id = CheckpointId::new("does-not-exist");
        let bogus_staged = SnapshotId::new("irrelevant");
        let anchor = MockAnchor::default();
        let dst = tmp.path().join("instance-dir");

        materialize_child_from_parent(
            &checkpoint_store,
            &snapshot_store,
            &missing_id,
            &bogus_staged,
            &anchor,
            &dst,
        )
        .unwrap_err();
        assert!(!dst.exists(), "a missing parent must leave dst uncreated");
    }

    #[test]
    fn negative_unaudited_parent_refuses_before_any_clone() {
        let tmp = tempfile::tempdir().unwrap();
        let checkpoint_store = CheckpointStore::at(tmp.path().join("checkpoints"));
        let snapshot_store = FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap();

        let parent = seed_parent(&checkpoint_store, tmp.path(), "warm-2");
        let staged = stage_warm_snapshot(&checkpoint_store, &snapshot_store, &parent.id).unwrap();

        let anchor = MockAnchor::default().unaudited(&parent.id);
        let dst = tmp.path().join("instance-dir");

        let err = materialize_child_from_parent(
            &checkpoint_store,
            &snapshot_store,
            &parent.id,
            &staged,
            &anchor,
            &dst,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("no signed audit entry"),
            "expected the lineage un-audited message, got: {err}"
        );
        assert!(
            !dst.exists(),
            "an un-audited parent must leave dst uncreated"
        );
    }

    #[test]
    fn negative_tampered_parent_refuses_before_any_clone() {
        let tmp = tempfile::tempdir().unwrap();
        let checkpoint_store = CheckpointStore::at(tmp.path().join("checkpoints"));
        let snapshot_store = FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap();

        let parent = seed_parent(&checkpoint_store, tmp.path(), "warm-3");
        let staged = stage_warm_snapshot(&checkpoint_store, &snapshot_store, &parent.id).unwrap();

        // The anchor still agrees with the ORIGINAL sealed digest — modeling a
        // signed chain that was never re-signed for the tampered record — but
        // the on-disk meta.json is mutated after sealing, so its recompute no
        // longer equals its own stored `meta_digest`: drift.
        let anchor = MockAnchor::default().audited(&parent);
        let mut tampered = parent.clone();
        tampered.vm_name = "renamed-after-seal".into();
        checkpoint_store.write_meta(&tampered).unwrap();

        let dst = tmp.path().join("instance-dir");
        let err = materialize_child_from_parent(
            &checkpoint_store,
            &snapshot_store,
            &parent.id,
            &staged,
            &anchor,
            &dst,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("drift"),
            "expected a meta_digest drift message, got: {err}"
        );
        assert!(!dst.exists(), "a tampered parent must leave dst uncreated");
    }
}
