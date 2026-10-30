//! Host-local checkpoint access for command and embedder workflows.
//!
//! Checkpoint storage layout is runtime-owned. This service keeps callers from
//! opening that store or reconstructing its content paths themselves.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};
use mvm_core::client::MvmError;
use mvm_runtime::checkpoint::{CheckpointStore, checked_workspace_blob_name};

pub mod fs_quick;

/// Access to the local checkpoint catalog, guarded removal and workspace images.
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
    /// Catalog reads can use isolated state without changing process-global
    /// configuration. Removal still checks the configured host-wide session
    /// pins; an explicit catalog root does not select another session policy.
    pub fn at(root: impl AsRef<Path>) -> Self {
        Self {
            store: CheckpointStore::at(root.as_ref().to_path_buf()),
        }
    }

    /// List complete checkpoint metadata in ID order, without opening content.
    ///
    /// Missing catalogs are empty. Malformed, misbound or unsafe metadata fails
    /// the whole read rather than returning a misleading partial catalog.
    pub fn list(&self) -> Result<Vec<CheckpointMeta>> {
        self.store.list()
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

    /// Remove a checkpoint only after metadata, session-pin and descendant checks.
    ///
    /// An absent directory is already removed. An existing directory without
    /// readable complete metadata is not absence. Pin checks use the host-wide
    /// agent-session store selected by `MVM_HOME`, also for an explicit catalog root.
    ///
    /// These are preflight guards, not an atomic transaction: concurrent pin,
    /// lineage and path changes are not serialized with deletion.
    ///
    /// # Errors
    ///
    /// Invalid IDs return `MvmError::InvalidSpec`; pins and descendants return
    /// `MvmError::Conflict`. Observation or deletion failures return
    /// `MvmError::Backend`, without expanding parser diagnostics.
    pub fn remove(&self, id: &CheckpointId) -> Result<()> {
        let id = validated_id(id.as_str()).map_err(|_| MvmError::InvalidSpec {
            reason: "invalid checkpoint id".into(),
        })?;
        match std::fs::symlink_metadata(self.store.dir_for(&id)) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(MvmError::Backend {
                    reason: format!("inspecting checkpoint directory: {error}"),
                }
                .into());
            }
        }
        let meta = self
            .store
            .list()
            .map_err(|error| MvmError::Backend {
                reason: format!("reading checkpoint metadata: {error}"),
            })?
            .into_iter()
            .find(|meta| meta.id == id)
            .ok_or_else(|| MvmError::Backend {
                reason: format!(
                    "checkpoint '{}' has missing or incomplete metadata",
                    id.as_str()
                ),
            })?;
        let sessions = mvm_runtime::agent_session::AgentSessionStore::open();
        let pin = mvm_runtime::agent_session::pinning_session(&sessions, &meta.meta_digest)
            .map_err(|error| MvmError::Backend {
                reason: format!("listing agent sessions: {error}"),
            })?;
        if let Some(session_id) = pin {
            return Err(MvmError::Conflict {
                reason: format!(
                    "cannot remove checkpoint '{}': it is the resume point for agent session '{}'; \
                     close that session before removing the checkpoint",
                    id.as_str(),
                    session_id.as_str()
                ),
            }
            .into());
        }
        let descendants =
            mvm_runtime::checkpoint::dependent_children(&self.store, &meta).map_err(|error| {
                MvmError::Backend {
                    reason: format!(
                        "listing checkpoints that name this one as their parent: {error}"
                    ),
                }
            })?;
        if !descendants.is_empty() {
            return Err(MvmError::Conflict {
                reason: format!(
                    "cannot remove checkpoint '{}': {} through it; remove {} first",
                    id.as_str(),
                    descendants_restoring_through(&descendants),
                    if descendants.len() == 1 { "it" } else { "them" }
                ),
            }
            .into());
        }
        self.store.remove(&id).map_err(|error| {
            MvmError::Backend {
                reason: format!("removing checkpoint: {error}"),
            }
            .into()
        })
    }

    /// Resolve the frozen image for `volume` in `id`.
    ///
    /// The metadata membership check is security-relevant: callers never get
    /// an arbitrary path assembled from a volume name that the checkpoint did
    /// not declare.
    ///
    /// A protected checkpoint stores no plaintext image to point at, so its
    /// image is opened into a private directory the returned value owns and
    /// removes when dropped.
    pub fn workspace_image(&self, id: &CheckpointId, volume: &str) -> Result<WorkspaceImage> {
        let meta = self.read(id)?;
        self.workspace_image_for_meta(&meta, volume)
    }

    fn workspace_image_for_meta(
        &self,
        meta: &CheckpointMeta,
        volume: &str,
    ) -> Result<WorkspaceImage> {
        let id = validated_id(meta.id.as_str()).context("checkpoint metadata id")?;
        let blob = checked_workspace_blob_name(volume)?;
        if !meta.content.iter().any(|content| content.name == blob) {
            bail!(
                "checkpoint {} did not capture volume {volume:?}: it predates the volume, or \
                 was not a full-machine checkpoint",
                meta.id.as_str()
            );
        }
        if meta.protection.is_unprotected() {
            return Ok(WorkspaceImage::existing(
                self.store.content_dir(&id).join(blob),
            ));
        }
        let scratch = tempfile::Builder::new()
            .prefix(".open-")
            .tempdir_in(self.store.root())
            .context("creating private staging for a protected workspace image")?;
        let path =
            mvm_runtime::checkpoint::materialized_source(&self.store, meta, &blob, scratch.path())?;
        Ok(WorkspaceImage {
            path,
            _staging: Some(scratch),
        })
    }
}

/// A workspace image ready to read. When it had to be opened from a protected
/// checkpoint, the plaintext lives in private staging this value owns, and is
/// removed when it is dropped.
#[derive(Debug)]
pub struct WorkspaceImage {
    path: PathBuf,
    _staging: Option<tempfile::TempDir>,
}

impl WorkspaceImage {
    /// An image file that already exists and is owned elsewhere.
    pub fn existing(path: PathBuf) -> Self {
        Self {
            path,
            _staging: None,
        }
    }

    /// Where the image can be read.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Validate a checkpoint identifier before it becomes an on-disk directory.
pub fn validated_id(raw: &str) -> Result<CheckpointId> {
    CheckpointId::try_from_path_component(raw).map_err(Into::into)
}

fn descendants_restoring_through(ids: &[CheckpointId]) -> String {
    let quoted: Vec<String> = ids.iter().map(|id| format!("'{}'", id.as_str())).collect();
    let (noun, verb) = if ids.len() == 1 {
        ("checkpoint", "restores")
    } else {
        ("checkpoints", "restore")
    };
    format!("{noun} {} {verb}", quoted.join(", "))
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
    fn descendants_restoring_through_agrees_in_number() {
        assert_eq!(
            descendants_restoring_through(&[CheckpointId::new("a")]),
            "checkpoint 'a' restores"
        );
        assert_eq!(
            descendants_restoring_through(&[CheckpointId::new("a"), CheckpointId::new("b")]),
            "checkpoints 'a', 'b' restore"
        );
    }

    fn removal_fixture() -> (
        tempfile::TempDir,
        mvm_core::util::test_env::TestEnv,
        Checkpoints,
    ) {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        (home, env, Checkpoints::open())
    }

    fn seed_removal_record(
        checkpoints: &Checkpoints,
        id: &str,
        parent: Option<&CheckpointMeta>,
    ) -> CheckpointMeta {
        let meta = CheckpointMeta::builder(
            CheckpointId::new(id),
            mvm_core::checkpoint::CheckpointClass::FsQuick,
            "vm",
        )
        .parent(parent.map(|record| record.meta_digest.clone()))
        .build();
        checkpoints.store.write_meta(&meta).unwrap();
        meta
    }

    #[test]
    fn checkpoint_remove_preserves_missing_directory_idempotency() {
        let (_home, _env, checkpoints) = removal_fixture();
        checkpoints.remove(&CheckpointId::new("absent")).unwrap();
        assert!(!checkpoints.store.root().exists());
        let meta = seed_removal_record(&checkpoints, "present", None);
        checkpoints.remove(&meta.id).unwrap();
        checkpoints.remove(&meta.id).unwrap();
        assert!(!checkpoints.store.dir_for(&meta.id).exists());
    }

    #[test]
    fn checkpoint_remove_refuses_invalid_ids_before_effects() {
        let (_home, _env, checkpoints) = removal_fixture();
        for raw in ["", ".", "..", "../outside", "a/b", "a\\b", "a\0b", "a\nb"] {
            let error = checkpoints.remove(&CheckpointId::new(raw)).unwrap_err();
            assert!(matches!(
                error.downcast_ref::<mvm_core::client::MvmError>(),
                Some(mvm_core::client::MvmError::InvalidSpec { .. })
            ));
        }
        assert!(!checkpoints.store.root().exists());
    }

    #[test]
    fn checkpoint_remove_refuses_missing_corrupt_or_nonregular_metadata() {
        for name in ["incomplete", "corrupt", "nonregular"] {
            let (_home, _env, checkpoints) = removal_fixture();
            let id = CheckpointId::new(name);
            let directory = checkpoints.store.dir_for(&id);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("keep"), b"checkpoint content").unwrap();
            match name {
                "corrupt" => std::fs::write(directory.join("meta.json"), b"{").unwrap(),
                "nonregular" => std::fs::create_dir(directory.join("meta.json")).unwrap(),
                _ => {}
            }
            assert!(checkpoints.remove(&id).is_err(), "{name}");
            assert!(directory.join("keep").is_file(), "{name}");
        }
    }

    #[test]
    fn checkpoint_remove_refuses_a_pin_until_the_session_is_closed() {
        use mvm_contract::protocol::agent_session::AgentSessionId;
        use mvm_runtime::agent_session::{AgentSessionRecord, AgentSessionStore, SandboxResidency};

        let (_home, _env, checkpoints) = removal_fixture();
        let meta = seed_removal_record(&checkpoints, "pinned", None);
        let sessions = AgentSessionStore::open();
        let mut record = AgentSessionRecord::opened(
            AgentSessionId::parse("sess-pinned").unwrap(),
            vec!["vm".into()],
            Some(meta.meta_digest.clone()),
            0,
        );
        record.state = SandboxResidency::Hibernated;
        sessions.write(&record).unwrap();
        let error = checkpoints.remove(&meta.id).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<mvm_core::client::MvmError>(),
            Some(mvm_core::client::MvmError::Conflict { .. })
        ));
        assert!(error.to_string().contains("sess-pinned"));
        assert_eq!(checkpoints.read(&meta.id).unwrap(), meta);
        record.state = SandboxResidency::Closed;
        sessions.write(&record).unwrap();
        checkpoints.remove(&meta.id).unwrap();
        assert!(!checkpoints.store.dir_for(&meta.id).exists());
    }

    #[test]
    fn checkpoint_remove_requires_descendants_to_be_removed_first() {
        let (_home, _env, checkpoints) = removal_fixture();
        let parent = seed_removal_record(&checkpoints, "parent", None);
        let child = seed_removal_record(&checkpoints, "child", Some(&parent));
        let error = checkpoints.remove(&parent.id).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<mvm_core::client::MvmError>(),
            Some(mvm_core::client::MvmError::Conflict { .. })
        ));
        assert!(error.to_string().contains("child"));
        assert_eq!(checkpoints.read(&parent.id).unwrap(), parent);
        checkpoints.remove(&child.id).unwrap();
        checkpoints.remove(&parent.id).unwrap();
    }

    #[test]
    fn checkpoint_remove_failed_pin_lookup_leaves_checkpoint_untouched() {
        let (_home, _env, checkpoints) = removal_fixture();
        let meta = seed_removal_record(&checkpoints, "guarded", None);
        std::fs::create_dir_all(mvm_core::config::agent_sessions_dir().join("sess-incomplete"))
            .unwrap();
        assert!(checkpoints.remove(&meta.id).is_err());
        assert_eq!(checkpoints.read(&meta.id).unwrap(), meta);
        checkpoints.remove(&CheckpointId::new("absent")).unwrap();
    }

    #[test]
    fn checkpoint_remove_failed_dependency_lookup_leaves_checkpoint_untouched() {
        let (_home, _env, checkpoints) = removal_fixture();
        let meta = seed_removal_record(&checkpoints, "guarded", None);
        let other = seed_removal_record(&checkpoints, "unreadable-child", Some(&meta));
        std::fs::write(checkpoints.store.dir_for(&other.id).join("meta.json"), b"{").unwrap();
        assert!(checkpoints.remove(&meta.id).is_err());
        assert_eq!(checkpoints.read(&meta.id).unwrap(), meta);
    }

    #[test]
    fn checkpoint_remove_missing_sibling_metadata_preserves_parent_and_child_state() {
        let (_home, _env, checkpoints) = removal_fixture();
        let parent = seed_removal_record(&checkpoints, "parent", None);
        let child = seed_removal_record(&checkpoints, "child", Some(&parent));
        let parent_dir = checkpoints.store.dir_for(&parent.id);
        let child_dir = checkpoints.store.dir_for(&child.id);
        std::fs::write(parent_dir.join("keep"), b"parent content").unwrap();
        std::fs::write(child_dir.join("keep"), b"child content").unwrap();
        std::fs::remove_file(child_dir.join("meta.json")).unwrap();

        assert_eq!(checkpoints.list().unwrap(), vec![parent.clone()]);
        assert!(checkpoints.remove(&parent.id).is_err());
        assert_eq!(checkpoints.read(&parent.id).unwrap(), parent);
        assert_eq!(
            std::fs::read(parent_dir.join("keep")).unwrap(),
            b"parent content"
        );
        assert_eq!(
            std::fs::read(child_dir.join("keep")).unwrap(),
            b"child content"
        );
        assert!(!child_dir.join("meta.json").exists());
    }

    #[test]
    #[cfg(unix)]
    fn checkpoint_remove_preserves_metadata_path_guards() {
        let (home, _env, checkpoints) = removal_fixture();
        let meta = seed_removal_record(&checkpoints, "guarded", None);
        let path = checkpoints.store.dir_for(&meta.id).join("meta.json");
        let outside = home.path().join("outside.json");
        std::fs::rename(&path, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert!(checkpoints.remove(&meta.id).is_err());
        assert!(std::fs::symlink_metadata(path).unwrap().is_symlink());
        assert_eq!(
            serde_json::from_slice::<CheckpointMeta>(&std::fs::read(outside).unwrap()).unwrap(),
            meta
        );
    }

    #[test]
    fn checkpoint_list_preserves_complete_and_legacy_json() {
        let root = tempfile::tempdir().expect("root");
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/checkpoint/catalog.json"
        ))
        .unwrap();
        for record in fixture.as_array().unwrap() {
            let path = root.path().join(record["id"].as_str().unwrap());
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("meta.json"), serde_json::to_vec(record).unwrap()).unwrap();
        }
        let records = Checkpoints::at(root.path()).list().unwrap();
        assert_eq!(serde_json::to_value(&records).unwrap(), fixture);
        assert!(records[1].key_domain.is_host());
        assert!(records[1].protection.is_unprotected());
    }

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
