//! Read-only local checkpoint access for command and embedder workflows.
//!
//! Checkpoint storage layout is runtime-owned. This service keeps callers from
//! opening that store or reconstructing its content paths themselves.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};
use mvm_runtime::checkpoint::{CheckpointStore, checked_workspace_blob_name};

/// Read-only access to the local checkpoint catalog and its workspace images.
pub struct Checkpoints {
    store: CheckpointStore,
}

impl Checkpoints {
    /// Open the checkpoint catalog under the configured MVM home.
    pub fn open() -> Self {
        Self {
            store: CheckpointStore::open(),
        }
    }

    /// Open a checkpoint catalog at an explicit root.
    ///
    /// This is useful to embedders with isolated state and keeps tests from
    /// changing process-global configuration.
    pub fn at(root: impl AsRef<Path>) -> Self {
        Self {
            store: CheckpointStore::at(root.as_ref().to_path_buf()),
        }
    }

    /// Read one checkpoint, preserving the command-facing not-found context.
    pub fn read(&self, id: &CheckpointId) -> Result<CheckpointMeta> {
        let id = validated_id(id.as_str())?;
        let meta = self
            .store
            .read_meta(&id)
            .with_context(|| format!("no checkpoint {:?} found", id.as_str()))?;
        let stored_id = validated_id(meta.id.as_str()).context("checkpoint metadata id")?;
        if stored_id.as_str() != id.as_str() {
            bail!(
                "checkpoint metadata id {:?} does not match requested id {:?}",
                stored_id.as_str(),
                id.as_str()
            );
        }
        Ok(meta)
    }

    /// Resolve the frozen image for `volume` in `id`.
    ///
    /// The metadata membership check is security-relevant: callers never get
    /// an arbitrary path assembled from a volume name that the checkpoint did
    /// not declare.
    pub fn workspace_image(&self, id: &CheckpointId, volume: &str) -> Result<PathBuf> {
        let meta = self.read(id)?;
        self.workspace_image_for_meta(&meta, volume)
    }

    fn workspace_image_for_meta(&self, meta: &CheckpointMeta, volume: &str) -> Result<PathBuf> {
        let id = validated_id(meta.id.as_str()).context("checkpoint metadata id")?;
        let blob = checked_workspace_blob_name(volume)?;
        if !meta.content.iter().any(|content| content.name == blob) {
            bail!(
                "checkpoint {} did not capture volume {volume:?}: it predates the volume, or \
                 was not a full-machine checkpoint",
                meta.id.as_str()
            );
        }
        Ok(self.store.content_dir(&id).join(blob))
    }
}

/// Validate a checkpoint identifier before it becomes an on-disk directory.
pub fn validated_id(raw: &str) -> Result<CheckpointId> {
    if raw.is_empty() {
        bail!("invalid checkpoint id: empty");
    }
    let bad = raw.contains('/')
        || raw.contains('\\')
        || raw.contains("..")
        || raw.bytes().any(|byte| byte == 0 || byte.is_ascii_control());
    if bad {
        bail!(
            "invalid checkpoint id {raw:?}: must not contain '/', '\\', '..', \
             NUL, or control characters"
        );
    }
    Ok(CheckpointId::new(raw.to_string()))
}

impl Default for Checkpoints {
    fn default() -> Self {
        Self::open()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_checkpoint_is_reported_at_the_facade_boundary() {
        let root = tempfile::tempdir().expect("root");
        let checkpoints = Checkpoints::at(root.path());
        let error = checkpoints
            .read(&CheckpointId::new("missing"))
            .expect_err("missing checkpoint");
        assert!(
            format!("{error:#}").contains("no checkpoint \"missing\" found"),
            "{error:#}"
        );
    }

    #[test]
    fn checkpoint_without_the_volume_names_why() {
        let root = tempfile::tempdir().expect("root");
        let checkpoints = Checkpoints::at(root.path());
        let meta = CheckpointMeta::builder(
            CheckpointId::new("ckpt-a"),
            mvm_core::checkpoint::CheckpointClass::VmFull,
            "vm".to_string(),
        )
        .build();
        let error = checkpoints
            .workspace_image_for_meta(&meta, "src")
            .expect_err("missing volume");
        assert!(
            error.to_string().contains("did not capture volume"),
            "{error}"
        );
    }

    #[test]
    fn checkpoint_ids_cannot_escape_the_store_root() {
        let root = tempfile::tempdir().expect("root");
        let checkpoints = Checkpoints::at(root.path());
        for raw in ["", "../etc", "a/b", "a\\b", "a\0b", "a\nb"] {
            let error = checkpoints
                .read(&CheckpointId::new(raw))
                .expect_err("unsafe checkpoint id");
            assert!(
                error.to_string().contains("invalid checkpoint id"),
                "{raw:?}: {error:#}"
            );
        }
    }

    #[test]
    fn metadata_cannot_redirect_content_to_another_checkpoint() {
        let root = tempfile::tempdir().expect("root");
        let requested = CheckpointId::new("expected");
        let dir = root.path().join(requested.as_str());
        std::fs::create_dir_all(&dir).expect("checkpoint dir");
        let meta = CheckpointMeta::builder(
            CheckpointId::new("../outside"),
            mvm_core::checkpoint::CheckpointClass::VmFull,
            "vm".to_string(),
        )
        .build();
        std::fs::write(
            dir.join("meta.json"),
            serde_json::to_vec(&meta).expect("metadata"),
        )
        .expect("write mismatched metadata");

        let error = Checkpoints::at(root.path())
            .read(&requested)
            .expect_err("metadata id must not redirect path resolution");
        assert!(
            format!("{error:#}").contains("checkpoint metadata id"),
            "{error:#}"
        );
    }

    #[test]
    fn workspace_volume_names_cannot_create_nested_content_paths() {
        let root = tempfile::tempdir().expect("root");
        let checkpoints = Checkpoints::at(root.path());
        let meta = CheckpointMeta::builder(
            CheckpointId::new("ckpt-a"),
            mvm_core::checkpoint::CheckpointClass::VmFull,
            "vm".to_string(),
        )
        .content(vec![mvm_core::checkpoint::ContentBlob {
            name: "workspace-../outside.ext4".to_string(),
            sha256: "unused".to_string(),
        }])
        .build();

        let error = checkpoints
            .workspace_image_for_meta(&meta, "../outside")
            .expect_err("volume name must not become a nested path");
        assert!(
            error.to_string().contains("not a registered volume name"),
            "{error:#}"
        );
    }
}
