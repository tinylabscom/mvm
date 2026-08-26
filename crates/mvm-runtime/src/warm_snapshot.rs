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
use mvm_fs::trusted_snapshot::TrustedSnapshotBackend;

use crate::checkpoint::{CheckpointChainAnchor, CheckpointStore, verify_content, verify_lineage};

/// Trusted publications use a distinct ID namespace so claim can select the
/// immutable backend without trusting a mutable sidecar or configuration flag.
pub(crate) fn is_trusted_snapshot_id(id: &str) -> bool {
    id.starts_with("trusted-checkpoint-")
}

/// Materialize `parent_id`'s content at `dst`, but only after it clears the
/// same fail-closed lineage gate `fork_checkpoint` / `fork_vm_full_fc` use:
/// `read_meta -> verify_content -> verify_lineage`. Nothing is cloned until
/// all three succeed — a missing, un-audited, or hash-mismatched parent
/// leaves `dst` uncreated and the error propagates.
///
/// The staged snapshot ID is load-bearing checkpoint metadata, covered by the
/// parent's verified digest and audit lineage. A checkpoint without this
/// binding is refused rather than falling back to a latency-expensive restage.
pub fn materialize_child_from_parent(
    checkpoint_store: &CheckpointStore,
    snapshot_store: &FsSnapshotStore,
    parent_id: &CheckpointId,
    anchor: &dyn CheckpointChainAnchor,
    dst: &Path,
) -> Result<CloneStrategy> {
    let parent = checkpoint_store.read_meta(parent_id)?;
    verify_content(checkpoint_store, &parent)?;
    verify_lineage(checkpoint_store, parent_id, anchor)?;

    let snapshot_id = parent.snapshot_id.as_deref().ok_or_else(|| {
        anyhow::anyhow!("checkpoint '{parent_id}' has no staged snapshot binding")
    })?;

    snapshot_store
        .materialize(&SnapshotId::new(snapshot_id), dst)
        .with_context(|| format!("materializing staged snapshot at {}", dst.display()))
}

/// Materialize from a platform-backed immutable publication.
///
/// This is the only claim path that may omit blob hashing. The backend owns
/// the publication proof: it must seal the bytes before the checkpoint is
/// admitted and must materialize from a read view that cannot be modified by a
/// later writer. The ordinary [`materialize_child_from_parent`] path remains
/// available for unsealed backends and retains full verification.
pub fn materialize_child_from_trusted_parent(
    checkpoint_store: &CheckpointStore,
    backend: &dyn TrustedSnapshotBackend,
    parent_id: &CheckpointId,
    anchor: &dyn CheckpointChainAnchor,
    dst: &Path,
) -> Result<CloneStrategy> {
    let parent = checkpoint_store.read_meta(parent_id)?;
    verify_lineage(checkpoint_store, parent_id, anchor)?;
    let snapshot_id = parent.snapshot_id.as_deref().ok_or_else(|| {
        anyhow::anyhow!("checkpoint '{parent_id}' has no trusted snapshot binding")
    })?;

    backend
        .materialize(&SnapshotId::new(snapshot_id), dst)
        .with_context(|| {
            format!(
                "materializing trusted snapshot {snapshot_id} at {} using {}",
                dst.display(),
                backend.name()
            )
        })
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
                runtime_overlay_version: None,
                tag: None,
                created_unix: 1,
                quiesced: true,
                grants: None,
            },
        )
        .unwrap()
    }

    fn stage_parent(
        store: &CheckpointStore,
        snapshots: &FsSnapshotStore,
        parent: CheckpointMeta,
    ) -> CheckpointMeta {
        let snapshot_id = format!(
            "checkpoint-{}-content-{}",
            parent.id,
            parent.compute_content_digest()
        );
        snapshots
            .create(
                &SnapshotId::new(snapshot_id.clone()),
                &store.content_dir(&parent.id),
            )
            .unwrap();
        let sealed = parent.with_snapshot_id(snapshot_id);
        store.write_meta(&sealed).unwrap();
        sealed
    }

    #[test]
    fn positive_control_audited_parent_materializes_via_snapshot_store() {
        let tmp = tempfile::tempdir().unwrap();
        let checkpoint_store = CheckpointStore::at(tmp.path().join("checkpoints"));
        let snapshot_store = FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap();

        let parent = stage_parent(
            &checkpoint_store,
            &snapshot_store,
            seed_parent(&checkpoint_store, tmp.path(), "warm-1"),
        );

        let anchor = MockAnchor::default().audited(&parent);
        let dst = tmp.path().join("instance-rootfs-dir");
        let strategy = materialize_child_from_parent(
            &checkpoint_store,
            &snapshot_store,
            &parent.id,
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
            "materialized bytes must byte-equal the parent's content"
        );
    }

    #[test]
    fn negative_missing_parent_refuses_before_any_clone() {
        let tmp = tempfile::tempdir().unwrap();
        let checkpoint_store = CheckpointStore::at(tmp.path().join("checkpoints"));
        let snapshot_store = FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap();

        // Never seeded: read_meta must fail before anything is staged or cloned.
        let missing_id = CheckpointId::new("does-not-exist");
        let anchor = MockAnchor::default();
        let dst = tmp.path().join("instance-dir");

        materialize_child_from_parent(
            &checkpoint_store,
            &snapshot_store,
            &missing_id,
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

        let anchor = MockAnchor::default().unaudited(&parent.id);
        let dst = tmp.path().join("instance-dir");

        let err = materialize_child_from_parent(
            &checkpoint_store,
            &snapshot_store,
            &parent.id,
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

        let parent = stage_parent(
            &checkpoint_store,
            &snapshot_store,
            seed_parent(&checkpoint_store, tmp.path(), "warm-3"),
        );

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

    /// Binding-attack test: an unrelated "evil" blob is staged into the SAME
    /// snapshot store the legit parent uses, modeling a caller that has
    /// attacker-controlled content sitting around in the store. Materializing
    /// from the legit, audited parent must produce ONLY the parent's own
    /// content — proving a caller cannot substitute a different blob by
    /// controlling what else is staged, since the function derives the
    /// snapshot id from the verified parent itself rather than trusting a
    /// caller-supplied one.
    #[test]
    fn materialize_ignores_unrelated_staged_snapshot_and_uses_verified_parent_content_only() {
        let tmp = tempfile::tempdir().unwrap();
        let checkpoint_store = CheckpointStore::at(tmp.path().join("checkpoints"));
        let snapshot_store = FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap();

        // Stage attacker-controlled bytes into the store, unrelated to any
        // checkpoint's content dir.
        let evil_dir = tmp.path().join("evil-payload");
        std::fs::create_dir(&evil_dir).unwrap();
        std::fs::write(evil_dir.join("rootfs.ext4"), b"attacker-controlled-bytes").unwrap();
        snapshot_store.create_content_addressed(&evil_dir).unwrap();

        let parent = stage_parent(
            &checkpoint_store,
            &snapshot_store,
            seed_parent(&checkpoint_store, tmp.path(), "warm-4"),
        );
        let anchor = MockAnchor::default().audited(&parent);
        let dst = tmp.path().join("instance-dir");

        materialize_child_from_parent(
            &checkpoint_store,
            &snapshot_store,
            &parent.id,
            &anchor,
            &dst,
        )
        .expect("legit audited parent must materialize");

        assert_eq!(
            std::fs::read(dst.join("rootfs.ext4")).unwrap(),
            b"warm-parent-rootfs-bytes",
            "materialized bytes must be the verified parent's content, never the staged evil blob"
        );
    }

    #[test]
    fn trusted_materialization_fails_closed_without_a_platform_backend() {
        let tmp = tempfile::tempdir().unwrap();
        let checkpoint_store = CheckpointStore::at(tmp.path().join("checkpoints"));
        let parent = seed_parent(&checkpoint_store, tmp.path(), "warm-trusted");
        let anchor = MockAnchor::default().audited(&parent);
        let backend = mvm_fs::trusted_snapshot::UnsupportedTrustedSnapshotBackend;
        let dst = tmp.path().join("instance-dir");

        let error = materialize_child_from_trusted_parent(
            &checkpoint_store,
            &backend,
            &parent.id,
            &anchor,
            &dst,
        )
        .unwrap_err();
        assert!(error.to_string().contains("no trusted snapshot binding"));
        assert!(!dst.exists());
    }
}
