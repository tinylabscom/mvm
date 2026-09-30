//! The apply store: content-addressed blobs, staged manifests, the
//! append-only journal, and crash recovery.
//!
//! Layout under the store root:
//!
//! ```text
//! blobs/<sha256>            content-addressed pre- and post-images
//! staging/<apply-id>/       manifest.json, done, trash/ (pre-commit only)
//! committed/<apply-id>/     manifest.json, done
//! journal.jsonl             begin/commit/rollback entries, fsync per entry
//! ```
//!
//! Crash windows, and what recovery does about each:
//!
//! 1. After the blobs + manifest, before the journal's `begin`: an orphan
//!    `staging/` dir with no journal entry. Recovery sweeps it; the host
//!    tree was never touched.
//! 2. After `begin`, before the `done` marker: the host tree may be
//!    half-written. Recovery rolls it back from the manifest's pre-images
//!    (each write is a tmp file + atomic rename, so a torn file does not
//!    exist; each delete went to `trash/` first) and journals `rollback`.
//! 3. After `done`, before `commit`: the writes finished. Recovery moves the
//!    apply to `committed/` and journals `commit`.
//!
//! `open` performs windows 1 and 3, which need no knowledge of the host
//! tree. Window 2 is host-tree-shaped, so the caller runs
//! [`ApplyStore::recover_source`] with each workspace's source directory
//! before staging anything else.

use std::collections::HashSet;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    ApplyError, ApplyPlan, FileOp, Manifest, ManifestAction, ManifestOp, OpAction, OpImage,
    PlanParams, RelationKind, manifest_merkle_root, plan,
};

/// The durable record of one staged apply.
#[derive(Debug, Clone)]
pub struct StagedApply {
    manifest: Manifest,
}

/// One committed history traversal (undo or redo), including the content
/// root the caller must bind into its audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedRelation {
    pub apply_id: String,
    pub target_id: String,
    pub merkle_root: String,
}

impl StagedApply {
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.manifest.id
    }

    #[must_use]
    pub fn merkle_root(&self) -> &str {
        &self.manifest.merkle_root
    }
}

/// One journal line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Sequence number, 1-based, dense.
    pub seq: u64,
    pub kind: JournalKind,
    /// The apply this entry is about.
    pub apply: String,
    /// Merkle root for `commit` entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
    /// For `rollback`: why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Wall-clock seconds since the epoch (this crate carries no clock dep).
    pub at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalKind {
    /// The manifest + blobs are durable; host writes may proceed.
    Begin,
    /// The host writes are durable.
    Commit,
    /// A begun apply was rolled back (crash recovery).
    Rollback,
}

/// The store root for one machine's workspace applies.
#[derive(Debug, Clone)]
pub struct ApplyStore {
    root: PathBuf,
}

impl ApplyStore {
    /// Open (and create) the store at `root`, finishing any interrupted
    /// apply that does not need the host tree (windows 1 and 3). The caller
    /// runs [`Self::recover_source`] for each workspace before staging.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, ApplyError> {
        let store = Self { root: root.into() };
        fs::create_dir_all(store.root.join("blobs"))?;
        fs::create_dir_all(store.root.join("staging"))?;
        fs::create_dir_all(store.root.join("committed"))?;
        if let Some((id, true)) = store.pending_begin()? {
            let manifest = store.read_staging_manifest(&id)?;
            store.move_to_committed(&id)?;
            store.journal(JournalKind::Commit, &id, Some(manifest.merkle_root), None)?;
        }
        store.sweep_orphans()?;
        Ok(store)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        self.root.as_path()
    }

    /// Plan an apply from two images and the host tree.
    pub fn plan(&self, params: &PlanParams<'_>) -> Result<ApplyPlan, ApplyError> {
        plan(params)
    }

    /// Stage `plan`: copy every pre-image (host tree) and post-image (the
    /// workspace image, or an earlier apply's blobs for undo/redo) into the
    /// blob store, write the manifest, and journal `begin`. Nothing on the
    /// host tree has been touched when this returns.
    ///
    /// A plan that was refused — protected matches or unappliable forms —
    /// cannot be staged; the caller presents the refusal and stops.
    pub fn stage(
        &self,
        plan: ApplyPlan,
        source_dir: &Path,
        live: &dyn crate::tree_diff::TreeSource,
        relation: Option<(String, RelationKind)>,
    ) -> Result<StagedApply, ApplyError> {
        if self.pending_begin()?.is_some() {
            return Err(ApplyError::PendingApply);
        }
        if !plan.refused_protected.is_empty() || !plan.refused_unappliable.is_empty() {
            return Err(ApplyError::Protected(
                plan.refused_protected
                    .first()
                    .or(plan.refused_unappliable.first())
                    .map(|(p, _)| p.clone())
                    .unwrap_or_default(),
                plan.refused_protected
                    .first()
                    .or(plan.refused_unappliable.first())
                    .map(|(_, c)| c.clone())
                    .unwrap_or_default(),
            ));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let mut ops = Vec::with_capacity(plan.ops.len());
        for op in plan.ops {
            ops.push(self.stage_op(op, source_dir, live)?);
        }
        let mut manifest = Manifest {
            id: id.clone(),
            created_at: now_secs(),
            ops,
            exclusions: plan.exclusion_patterns.clone(),
            refused_protected: Vec::new(),
            refused_unappliable: Vec::new(),
            skipped_excluded: plan.skipped_excluded,
            merkle_root: String::new(),
            relation: relation.map(|(apply, kind)| super::ApplyRelation { apply, kind }),
        };
        manifest.merkle_root = manifest_merkle_root(&manifest.ops);
        self.write_manifest(&self.staging_dir(&id), &manifest)?;
        self.journal(JournalKind::Begin, &id, None, None)?;
        Ok(StagedApply { manifest })
    }

    /// Execute a staged apply on the host tree: fsync-safe writes through
    /// temp files and atomic renames, deletes through trash. Idempotent —
    /// re-running only repairs what a crash left missing.
    pub fn commit(&self, staged: &StagedApply, source_dir: &Path) -> Result<(), ApplyError> {
        let dir = self.staging_dir(&staged.manifest.id);
        fs::create_dir_all(dir.join("trash"))?;
        for op in &staged.manifest.ops {
            self.apply_op(op, source_dir, &dir)?;
        }
        sync_dir(source_dir)?;
        // Durable marker: writes complete; a later crash completes the
        // journal instead of rolling back.
        atomic_write(&dir.join("done"), staged.manifest.id.as_bytes())?;
        sync_dir(&dir)?;
        self.move_to_committed(&staged.manifest.id)?;
        self.journal(
            JournalKind::Commit,
            &staged.manifest.id,
            Some(staged.manifest.merkle_root.clone()),
            None,
        )?;
        Ok(())
    }

    /// Reverse the most recent committed, still-effective apply: stage an
    /// inverse apply — the original's pre-images become this one's
    /// post-images — and commit it. Returns the committed relation and root.
    pub fn undo_latest(&self, source_dir: &Path) -> Result<Option<AppliedRelation>, ApplyError> {
        let Some(target) = self.effective_applies()?.last().cloned() else {
            return Ok(None);
        };
        let manifest = self.committed_manifest(&target)?;
        let staged = self.stage(
            inverse_plan(&manifest),
            source_dir,
            &EmptySource,
            Some((target.clone(), RelationKind::Undoes)),
        )?;
        let result = AppliedRelation {
            apply_id: staged.id().to_string(),
            target_id: target,
            merkle_root: staged.merkle_root().to_string(),
        };
        self.commit(&staged, source_dir)?;
        Ok(Some(result))
    }

    /// Re-apply the target of the most recent undo, but only when that undo
    /// is still the newest effective apply (anything applied since changed
    /// the tree the undo restored, so redo would clobber it). Returns
    /// the committed relation and root.
    pub fn redo_latest(&self, source_dir: &Path) -> Result<Option<AppliedRelation>, ApplyError> {
        let effective = self.effective_applies()?;
        let Some(last) = effective.last().cloned() else {
            return Ok(None);
        };
        let manifest = self.committed_manifest(&last)?;
        let Some(relation) = &manifest.relation else {
            return Ok(None);
        };
        if relation.kind != RelationKind::Undoes {
            return Ok(None);
        }
        let target = self.committed_manifest(&relation.apply)?;
        // An undo of an undo (or of a redo) is already a reversal in
        // disguise; there is nothing further for a redo to re-apply. Redo
        // only stands when the undone record was itself a forward apply.
        if target.relation.is_some() {
            return Ok(None);
        }
        let staged = self.stage(
            forward_plan(&target),
            source_dir,
            &EmptySource,
            Some((target.id.clone(), RelationKind::Redoes)),
        )?;
        let result = AppliedRelation {
            apply_id: staged.id().to_string(),
            target_id: target.id.clone(),
            merkle_root: staged.merkle_root().to_string(),
        };
        self.commit(&staged, source_dir)?;
        Ok(Some(result))
    }

    /// The journal, in order.
    pub fn journal_read(&self) -> Result<Vec<JournalEntry>, ApplyError> {
        let path = self.root.join("journal.jsonl");
        let Ok(mut file) = OpenOptions::new().read(true).open(&path) else {
            return Ok(Vec::new());
        };
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        let mut entries = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: JournalEntry = serde_json::from_str(line)
                .map_err(|e| ApplyError::Corrupt(format!("journal line {}: {e}", index + 1)))?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Every committed apply's manifest, oldest first.
    pub fn history(&self) -> Result<Vec<Manifest>, ApplyError> {
        let mut out = Vec::new();
        for id in self.committed_order()? {
            out.push(self.committed_manifest(&id)?);
        }
        Ok(out)
    }

    /// The committed, still-effective apply ids in commit order: undo
    /// applies remove their target; redo applies stand on their own.
    pub fn effective_applies(&self) -> Result<Vec<String>, ApplyError> {
        let mut effective: Vec<String> = Vec::new();
        for id in self.committed_order()? {
            let manifest = self.committed_manifest(&id)?;
            if let Some(relation) = &manifest.relation {
                effective.retain(|x| x != &relation.apply);
            }
            effective.push(id);
        }
        Ok(effective)
    }

    /// Roll back a begun-but-undone apply against `source_dir` (crash
    /// window 2), then journal the rollback and sweep. Returns the rolled
    /// back apply's id.
    pub fn recover_source(&self, source_dir: &Path) -> Result<Option<String>, ApplyError> {
        let Some((id, done)) = self.pending_begin()? else {
            return Ok(None);
        };
        if done {
            return Ok(None);
        }
        let manifest = self.read_staging_manifest(&id)?;
        let dir = self.staging_dir(&id);
        for op in &manifest.ops {
            self.rollback_op(op, source_dir, &dir)?;
        }
        sync_dir(source_dir)?;
        self.journal(
            JournalKind::Rollback,
            &id,
            None,
            Some("crash recovery: begun without a done marker".into()),
        )?;
        self.sweep_orphans()?;
        Ok(Some(id))
    }

    // ── internals ──────────────────────────────────────────────────────

    fn committed_order(&self) -> Result<Vec<String>, ApplyError> {
        let journal = self.journal_read()?;
        let mut order: Vec<String> = journal
            .iter()
            .filter(|e| e.kind == JournalKind::Commit)
            .map(|e| e.apply.clone())
            .collect();
        // A commit completed by recovery may appear twice; dedup, keep order.
        let mut seen = HashSet::new();
        order.retain(|id| seen.insert(id.clone()));
        Ok(order)
    }

    fn staging_dir(&self, id: &str) -> PathBuf {
        self.root.join("staging").join(id)
    }

    fn committed_dir(&self, id: &str) -> PathBuf {
        self.root.join("committed").join(id)
    }

    fn blob_path(&self, sha: &str) -> PathBuf {
        self.root.join("blobs").join(sha)
    }

    /// Stage one op: capture the pre-image from the host tree, and the
    /// post-image from the live tree (a fresh apply) or verify it against
    /// the blob store (undo/redo, where the bytes are an earlier apply's
    /// images).
    fn stage_op(
        &self,
        op: FileOp,
        source_dir: &Path,
        live: &dyn crate::tree_diff::TreeSource,
    ) -> Result<ManifestOp, ApplyError> {
        let pre = self.stage_pre(&op, source_dir)?;
        let (action, post) = match (&op.action, op.post) {
            (OpAction::Remove, _) => (ManifestAction::Remove, None),
            (OpAction::WriteFile, Some(image)) => {
                let image = self.stage_post_file(image, live, &op.path)?;
                (ManifestAction::WriteFile, Some(image))
            }
            (OpAction::WriteSymlink { target }, Some(image)) => {
                let (image, target) = self.stage_post_symlink(image, target)?;
                (ManifestAction::WriteSymlink { target }, Some(image))
            }
            (_, None) => {
                return Err(ApplyError::Corrupt(format!(
                    "{}: write op without a post image",
                    op.path
                )));
            }
        };
        Ok(ManifestOp {
            path: op.path,
            action,
            pre,
            post,
        })
    }

    /// The pre-image from the host tree: the bytes undo restores. An absent
    /// host path stages no blob and records size zero.
    fn stage_pre(&self, op: &FileOp, source_dir: &Path) -> Result<OpImage, ApplyError> {
        let full = super::host_path(source_dir, &op.path)?;
        let meta = match fs::symlink_metadata(&full) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(OpImage::default()),
            Err(e) => return Err(e.into()),
        };
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&full)?;
            self.store_bytes(target.as_os_str().as_encoded_bytes())
        } else if meta.file_type().is_file() {
            let mut file = OpenOptions::new().read(true).open(&full)?;
            let mut sink = self.hashing_blob_sink()?;
            io::copy(&mut file, &mut sink)?;
            self.finish_streaming_blob(sink, &op.path)
        } else {
            Err(ApplyError::UnsafePath(format!(
                "{}: the host path is neither a file nor a symlink; refusing to replace it",
                op.path
            )))
        }
    }

    /// A fresh apply's post-image: stream the workspace file into the blob
    /// store. An undo/redo post-image already names its blob: verify it
    /// exists and agrees on size, never re-copy.
    fn stage_post_file(
        &self,
        image: OpImage,
        live: &dyn crate::tree_diff::TreeSource,
        path: &str,
    ) -> Result<OpImage, ApplyError> {
        match image.sha256.clone() {
            Some(sha) => {
                self.verify_blob(&sha, image.size)?;
                Ok(image)
            }
            None => {
                let mut sink = self.hashing_blob_sink()?;
                live.copy_file_to(path, &mut sink)?;
                self.finish_streaming_blob(sink, path)
            }
        }
    }

    fn stage_post_symlink(
        &self,
        image: OpImage,
        target: &str,
    ) -> Result<(OpImage, String), ApplyError> {
        match image.sha256.clone() {
            Some(sha) => {
                self.verify_blob(&sha, image.size)?;
                // The target string lives in the blob; the manifest action
                // carries it for the record and for symlink writes.
                let stored = fs::read_to_string(self.blob_path(&sha))?;
                Ok((image, stored))
            }
            None => {
                let stored = self.store_bytes(target.as_bytes())?;
                Ok((stored, target.to_string()))
            }
        }
    }

    /// Open a temp blob plus a hasher; the caller streams into the sink,
    /// then [`Self::finish_streaming_blob`] publishes it under the digest.
    fn hashing_blob_sink(&self) -> Result<HashingSink, ApplyError> {
        let tmp = self
            .root
            .join("blobs")
            .join(format!(".tmp-{}", uuid::Uuid::new_v4()));
        let file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        Ok(HashingSink {
            file,
            hasher: Some(Sha256::new()),
            size: 0,
            tmp,
            finished: false,
        })
    }

    /// Publish the streamed blob under its computed digest.
    fn finish_streaming_blob(
        &self,
        mut sink: HashingSink,
        path: &str,
    ) -> Result<OpImage, ApplyError> {
        sink.file.sync_data()?;
        let sha = hex::encode(sink.hasher.take().expect("finish runs once").finalize());
        let size = sink.size;
        // Publish before the sink drops: the tmp file is the blob until the
        // rename lands, and `Drop` removes it unless it finished.
        self.publish_blob(sink.tmp.clone(), &sha)
            .map_err(|e| match e {
                ApplyError::Corrupt(_) => ApplyError::Corrupt(format!("{path}: {e}")),
                other => other,
            })?;
        sink.finished = true;
        Ok(OpImage {
            sha256: Some(sha),
            size,
        })
    }

    fn publish_blob(&self, tmp: PathBuf, sha: &str) -> Result<(), ApplyError> {
        let target = self.blob_path(sha);
        match fs::rename(&tmp, &target) {
            Ok(()) => Ok(()),
            // Same bytes staged twice: identical content already lives under
            // this digest, so drop the duplicate.
            Err(_) if target.exists() => fs::remove_file(&tmp).map_err(ApplyError::Host),
            Err(e) => Err(e.into()),
        }
    }

    fn store_bytes(&self, bytes: &[u8]) -> Result<OpImage, ApplyError> {
        let sha = hex::encode(Sha256::digest(bytes));
        let path = self.blob_path(&sha);
        if !path.exists() {
            atomic_write(&path, bytes)?;
        }
        Ok(OpImage {
            sha256: Some(sha),
            size: bytes.len() as u64,
        })
    }

    fn verify_blob(&self, sha: &str, size: u64) -> Result<(), ApplyError> {
        let path = self.blob_path(sha);
        let meta = fs::metadata(&path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => ApplyError::Corrupt(format!("blob {sha} is missing")),
            _ => ApplyError::Host(e),
        })?;
        if meta.len() != size {
            return Err(ApplyError::Corrupt(format!(
                "blob {sha} holds {} bytes, the manifest expects {size}",
                meta.len()
            )));
        }
        Ok(())
    }

    fn write_manifest(&self, dir: &Path, manifest: &Manifest) -> Result<(), ApplyError> {
        fs::create_dir_all(dir)?;
        let json = serde_json::to_string_pretty(manifest)
            .map_err(|e| ApplyError::Corrupt(format!("manifest: {e}")))?;
        atomic_write(&dir.join("manifest.json"), json.as_bytes())?;
        sync_dir(dir)?;
        Ok(())
    }

    fn read_manifest(path: &Path, id: &str) -> Result<Manifest, ApplyError> {
        let text = fs::read_to_string(path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => ApplyError::Corrupt(format!("no manifest for apply {id}")),
            _ => ApplyError::Host(e),
        })?;
        serde_json::from_str(&text).map_err(|e| ApplyError::Corrupt(format!("apply {id}: {e}")))
    }

    fn committed_manifest(&self, id: &str) -> Result<Manifest, ApplyError> {
        Self::read_manifest(&self.committed_dir(id).join("manifest.json"), id)
    }

    fn read_staging_manifest(&self, id: &str) -> Result<Manifest, ApplyError> {
        Self::read_manifest(&self.staging_dir(id).join("manifest.json"), id)
    }

    fn move_to_committed(&self, id: &str) -> Result<(), ApplyError> {
        fs::rename(self.staging_dir(id), self.committed_dir(id))?;
        sync_dir(&self.root.join("committed"))?;
        Ok(())
    }

    fn journal(
        &self,
        kind: JournalKind,
        apply: &str,
        merkle_root: Option<String>,
        reason: Option<String>,
    ) -> Result<(), ApplyError> {
        let seq = self.journal_read()?.last().map_or(0, |e| e.seq) + 1;
        let entry = JournalEntry {
            seq,
            kind,
            apply: apply.to_string(),
            merkle_root,
            reason,
            at: now_secs(),
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("journal.jsonl"))?;
        serde_json::to_writer(&mut file, &entry)
            .map_err(|e| ApplyError::Corrupt(format!("journal: {e}")))?;
        file.write_all(b"\n")?;
        file.sync_data()?;
        sync_dir(&self.root)?;
        Ok(())
    }

    /// The begun-but-unclosed apply, if any: `(id, has_done_marker)`.
    fn pending_begin(&self) -> Result<Option<(String, bool)>, ApplyError> {
        let journal = self.journal_read()?;
        let begun: HashSet<&str> = journal
            .iter()
            .filter(|e| e.kind == JournalKind::Begin)
            .map(|e| e.apply.as_str())
            .collect();
        let closed: HashSet<&str> = journal
            .iter()
            .filter(|e| e.kind != JournalKind::Begin)
            .map(|e| e.apply.as_str())
            .collect();
        for id in begun {
            if !closed.contains(id) {
                let done = self.staging_dir(id).join("done").exists();
                return Ok(Some((id.to_string(), done)));
            }
        }
        Ok(None)
    }

    /// Drop staging dirs whose apply never reached the journal (crash
    /// before `begin`) or was closed (rolled back or swept after commit).
    fn sweep_orphans(&self) -> Result<(), ApplyError> {
        let journal = self.journal_read()?;
        let closed: HashSet<&str> = journal
            .iter()
            .filter(|e| e.kind != JournalKind::Begin)
            .map(|e| e.apply.as_str())
            .collect();
        let begun: HashSet<&str> = journal
            .iter()
            .filter(|e| e.kind == JournalKind::Begin)
            .map(|e| e.apply.as_str())
            .collect();
        for entry in fs::read_dir(self.root.join("staging"))? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().into_owned();
            if closed.contains(id.as_str()) || !begun.contains(id.as_str()) {
                fs::remove_dir_all(entry.path())?;
            }
        }
        Ok(())
    }

    /// Apply one manifest op to the host tree.
    fn apply_op(&self, op: &ManifestOp, source_dir: &Path, stage: &Path) -> Result<(), ApplyError> {
        let full = super::host_path(source_dir, &op.path)?;
        match &op.action {
            ManifestAction::WriteFile => {
                let post = op
                    .post
                    .as_ref()
                    .ok_or_else(|| ApplyError::Corrupt(format!("{}: no post image", op.path)))?;
                let sha = post
                    .sha256
                    .as_deref()
                    .ok_or_else(|| ApplyError::Corrupt(format!("{}: unstaged post", op.path)))?;
                self.verify_blob(sha, post.size)?;
                write_file_atomic(&full, &self.blob_path(sha), post.size)?;
            }
            ManifestAction::WriteSymlink { target } => {
                write_symlink_atomic(&full, target)?;
            }
            ManifestAction::Remove => {
                if full.symlink_metadata().is_ok() {
                    let trash = stage.join("trash").join(&op.path);
                    if let Some(parent) = trash.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::rename(&full, &trash)?;
                }
            }
        }
        Ok(())
    }

    /// Reverse one manifest op during a crash-recovery rollback.
    fn rollback_op(
        &self,
        op: &ManifestOp,
        source_dir: &Path,
        stage: &Path,
    ) -> Result<(), ApplyError> {
        let full = super::host_path(source_dir, &op.path)?;
        match &op.action {
            ManifestAction::WriteFile | ManifestAction::WriteSymlink { .. } => {
                match op.pre.sha256.as_deref() {
                    // The apply created this path: remove it.
                    None => remove_path(&full)?,
                    // Restore the bytes the apply replaced.
                    Some(sha) => {
                        self.verify_blob(sha, op.pre.size)?;
                        if matches!(op.action, ManifestAction::WriteFile) {
                            write_file_atomic(&full, &self.blob_path(sha), op.pre.size)?;
                        } else {
                            let target = fs::read_to_string(self.blob_path(sha))?;
                            write_symlink_atomic(&full, &target)?;
                        }
                    }
                }
            }
            ManifestAction::Remove => {
                // Move the trashed pre-image back into place.
                let trash = stage.join("trash").join(&op.path);
                if trash.symlink_metadata().is_ok() {
                    if let Some(parent) = full.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::rename(&trash, &full)?;
                }
            }
        }
        Ok(())
    }
}

/// A temp blob that hashes and counts everything written to it, then
/// publishes under the digest on [`ApplyStore::finish_streaming_blob`]. The
/// hasher sits behind `Option` because `Drop` types cannot be partially
/// moved; `finish` takes it out.
struct HashingSink {
    file: fs::File,
    hasher: Option<Sha256>,
    size: u64,
    tmp: PathBuf,
    /// Set once the blob is published: `Drop` must not delete a file that
    /// now lives under its digest.
    finished: bool,
}

impl Write for HashingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.file.write(buf)?;
        if let Some(hasher) = &mut self.hasher {
            hasher.update(&buf[..n]);
        }
        self.size += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Drop for HashingSink {
    fn drop(&mut self) {
        if !self.finished {
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

/// Write `bytes` over `target` through a temp file + atomic rename.
fn atomic_write(target: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = target.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    fs::write(&tmp, bytes)?;
    let file = OpenOptions::new().read(true).open(&tmp)?;
    file.sync_data()?;
    fs::rename(&tmp, target)?;
    Ok(())
}

/// Copy `blob` over `target` through a temp file + atomic rename, verifying
/// the staged size first: the store never applies a hash it did not store.
fn write_file_atomic(target: &Path, blob: &Path, expected_size: u64) -> Result<(), ApplyError> {
    let actual = fs::metadata(blob).map_err(ApplyError::Host)?.len();
    if actual != expected_size {
        return Err(ApplyError::Corrupt(format!(
            "blob {} holds {} bytes, the manifest expects {expected_size}",
            blob.display(),
            actual
        )));
    }
    let parent = target.parent().ok_or_else(|| {
        ApplyError::UnsafePath(format!("{}: no parent directory", target.display()))
    })?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".mvm-apply-{}", uuid::Uuid::new_v4()));
    fs::copy(blob, &tmp)?;
    let file = OpenOptions::new().read(true).open(&tmp)?;
    file.sync_data()?;
    fs::rename(&tmp, target)?;
    Ok(())
}

fn write_symlink_atomic(target: &Path, link_target: &str) -> Result<(), ApplyError> {
    let parent = target.parent().ok_or_else(|| {
        ApplyError::UnsafePath(format!("{}: no parent directory", target.display()))
    })?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".mvm-apply-{}", uuid::Uuid::new_v4()));
    std::os::unix::fs::symlink(link_target, &tmp)?;
    fs::rename(&tmp, target)?;
    Ok(())
}

fn remove_path(full: &Path) -> Result<(), ApplyError> {
    if full.symlink_metadata().is_ok() {
        if full.is_dir() {
            fs::remove_dir_all(full)?;
        } else {
            fs::remove_file(full)?;
        }
    }
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<(), ApplyError> {
    let file = OpenOptions::new().read(true).open(dir)?;
    file.sync_all()?;
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The inverse of a committed apply: the original's pre-images become this
/// one's post-images, and each op reverses. Undo consults nothing but the
/// manifest — the exclusions it recorded are the only ones in force, and a
/// restore never rebuilds a default list.
fn inverse_plan(manifest: &Manifest) -> ApplyPlan {
    let mut plan = ApplyPlan {
        exclusion_patterns: manifest.exclusions.clone(),
        ..ApplyPlan::default()
    };
    for op in &manifest.ops {
        let file_op = match &op.action {
            ManifestAction::WriteFile => match op.pre.sha256.clone() {
                Some(sha) => FileOp {
                    path: op.path.clone(),
                    action: OpAction::WriteFile,
                    pre: OpImage::default(),
                    post: Some(OpImage {
                        sha256: Some(sha),
                        size: op.pre.size,
                    }),
                },
                None => FileOp {
                    path: op.path.clone(),
                    action: OpAction::Remove,
                    pre: OpImage::default(),
                    post: None,
                },
            },
            ManifestAction::WriteSymlink { .. } => match op.pre.sha256.clone() {
                Some(sha) => FileOp {
                    path: op.path.clone(),
                    action: OpAction::WriteSymlink {
                        target: String::new(),
                    },
                    pre: OpImage::default(),
                    post: Some(OpImage {
                        sha256: Some(sha),
                        size: op.pre.size,
                    }),
                },
                None => FileOp {
                    path: op.path.clone(),
                    action: OpAction::Remove,
                    pre: OpImage::default(),
                    post: None,
                },
            },
            // The original removed the path; undo restores its pre-image.
            ManifestAction::Remove => FileOp {
                path: op.path.clone(),
                action: OpAction::WriteFile,
                pre: OpImage::default(),
                post: Some(OpImage {
                    sha256: op.pre.sha256.clone(),
                    size: op.pre.size,
                }),
            },
        };
        plan.ops.push(file_op);
    }
    plan
}

/// The forward re-application of a committed apply: its post-images, with
/// the current host state captured as the new pre-images.
fn forward_plan(manifest: &Manifest) -> ApplyPlan {
    let mut plan = ApplyPlan {
        exclusion_patterns: manifest.exclusions.clone(),
        ..ApplyPlan::default()
    };
    for op in &manifest.ops {
        let file_op = match &op.action {
            ManifestAction::WriteFile => FileOp {
                path: op.path.clone(),
                action: OpAction::WriteFile,
                pre: OpImage::default(),
                post: op.post.clone(),
            },
            ManifestAction::WriteSymlink { target } => FileOp {
                path: op.path.clone(),
                action: OpAction::WriteSymlink {
                    target: target.clone(),
                },
                pre: OpImage::default(),
                post: op.post.clone(),
            },
            ManifestAction::Remove => FileOp {
                path: op.path.clone(),
                action: OpAction::Remove,
                pre: OpImage::default(),
                post: None,
            },
        };
        plan.ops.push(file_op);
    }
    plan
}

/// An empty tree source: undo/redo staging reads post-images from blobs,
/// never from a live tree.
struct EmptySource;

impl crate::tree_diff::TreeSource for EmptySource {
    fn entries(
        &self,
        _max_entries: u64,
    ) -> Result<crate::tree_diff::Tree, crate::tree_diff::TreeDiffError> {
        Ok(crate::tree_diff::Tree::new())
    }

    fn read_prefix(
        &self,
        path: &str,
        _limit: u64,
    ) -> Result<Vec<u8>, crate::tree_diff::TreeDiffError> {
        Err(refused(path))
    }

    fn sha256(&self, path: &str) -> Result<String, crate::tree_diff::TreeDiffError> {
        Err(refused(path))
    }

    fn link_target(&self, path: &str) -> Result<String, crate::tree_diff::TreeDiffError> {
        Err(refused(path))
    }
}

fn refused(path: &str) -> crate::tree_diff::TreeDiffError {
    crate::tree_diff::TreeDiffError::Refused {
        path: path.to_string(),
        reason: "undo/redo stage from blobs, not a live tree".into(),
    }
}
