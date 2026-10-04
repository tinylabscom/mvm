//! Reviewed apply of a guest workspace back to its host directory.
//!
//! The guest's writes never reach the host tree by themselves: a workspace
//! is a private copy of a host directory, and only this reviewed path writes
//! back. An apply is planned from the diff between the image the workspace
//! began as and the guest's current image, staged into a content-addressed
//! snapshot (every overwritten or deleted host byte is copied under its
//! SHA-256 before anything is touched), committed file-by-file through
//! atomic renames, and recorded in an append-only journal that names a
//! Merkle root over the manifest.
//!
//! Every step is recoverable. A crash between the journal's begin and the
//! commit marker rolls the half-applied tree back from the snapshot; a crash
//! after the writes but before the journal entry completes the commit by
//! replaying idempotent writes. Undo and redo are inverse and forward
//! applies recorded the same way, so they inherit the same guarantees.
//!
//! The pitfalls this design answers, stated plainly: the exclusions an
//! operator declared are persisted with the apply and are the only ones
//! ever consulted; a restore never rebuilds a default list. The journal
//! means a crash mid-apply can be completed or rolled back. The blob store
//! never records a hash it did not store — a blob's name is the digest of
//! the bytes written to it, computed during the write.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use mvm_contract::policy::protected_paths::ProtectedPathSet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::tree_diff::model::{ChangeKind, DiffContent, TreeDiff};
use crate::tree_diff::{DiffLimits, TreeDiffError, TreeSource, diff_trees};

pub mod store;
pub use store::{ApplyStore, JournalEntry, JournalKind, StagedApply};

/// One planned write or removal, before any byte is staged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOp {
    /// Workspace-relative path, validated the way output collection
    /// validates guest trees (no `..`, no absolute, no NUL).
    pub path: String,
    /// What the apply does on the host.
    pub action: OpAction,
    /// The host file this op replaces, if one exists.
    pub pre: OpImage,
    /// The workspace image content this op writes, for a write.
    pub post: Option<OpImage>,
}

/// What an apply does to one host path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpAction {
    /// Write the workspace's file content over the host path.
    WriteFile,
    /// Replace the host path with the workspace's symlink.
    WriteSymlink { target: String },
    /// Remove the host path (the workspace deleted it).
    Remove,
}

/// Where an op's image bytes come from, and where a staged copy of them
/// lives once the apply is staged.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpImage {
    /// SHA-256 of the content, hex. `None` only for a not-yet-staged image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Size in bytes.
    pub size: u64,
}

/// Inputs to [`plan`]. A plain params struct keeps the call honest as the
/// set grows.
pub struct PlanParams<'a> {
    /// The image the workspace began as (the published snapshot).
    pub baseline: &'a dyn TreeSource,
    /// The guest's current workspace image.
    pub live: &'a dyn TreeSource,
    /// The host directory the workspace was copied from — the apply target.
    pub source_dir: &'a Path,
    /// Bounds on the walk, shared with the diff verb.
    pub limits: DiffLimits,
    /// Guest-authored changes here refuse the whole apply, naming every
    /// match (the protected-path gate's file-artifact semantics).
    pub protected: Option<&'a ProtectedPathSet>,
    /// Operator-declared exclusions: matching paths are never written or
    /// deleted by an apply and are recorded in the manifest.
    pub exclusions: Option<&'a ProtectedPathSet>,
}

impl<'a> PlanParams<'a> {
    pub fn new(
        baseline: &'a dyn TreeSource,
        live: &'a dyn TreeSource,
        source_dir: &'a Path,
    ) -> Self {
        Self {
            baseline,
            live,
            source_dir,
            limits: DiffLimits::default(),
            protected: None,
            exclusions: None,
        }
    }

    #[must_use]
    pub fn with_limits(mut self, limits: DiffLimits) -> Self {
        self.limits = limits;
        self
    }

    #[must_use]
    pub fn with_protected(mut self, protected: &'a ProtectedPathSet) -> Self {
        self.protected = Some(protected);
        self
    }

    #[must_use]
    pub fn with_exclusions(mut self, exclusions: &'a ProtectedPathSet) -> Self {
        self.exclusions = Some(exclusions);
        self
    }
}

/// The planned apply: the ops to run, plus the paths that refused or were
/// excluded, for the prompt and the record.
#[derive(Debug, Clone, Default)]
pub struct ApplyPlan {
    pub ops: Vec<FileOp>,
    /// The exclusion patterns in force, persisted into the manifest so no
    /// later step — an undo, a restore — ever rebuilds a default list.
    pub exclusion_patterns: Vec<String>,
    /// Protected matches that refuse the whole apply: `(path, class)`.
    pub refused_protected: Vec<(String, String)>,
    /// Paths whose new form cannot be applied safely (a directory or special
    /// file, or one left out of the comparison): `(path, reason)`. Like a
    /// protected match, one entry refuses the whole apply.
    pub refused_unappliable: Vec<(String, String)>,
    /// Excluded paths the apply will not touch, recorded for the manifest.
    pub skipped_excluded: Vec<String>,
}

impl ApplyPlan {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// Errors from planning, staging, committing, or recovering an apply.
#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("the walk could not complete: {0}")]
    Walk(#[from] TreeDiffError),
    #[error(
        "guest-authored change touches a protected path ({0} matches {1}); refusing the whole apply"
    )]
    Protected(String, String),
    #[error("a workspace path is not writable on the host: {0}")]
    UnsafePath(String),
    #[error("the host tree could not be read: {0}")]
    Host(#[from] io::Error),
    #[error("the apply store is corrupt: {0}")]
    Corrupt(String),
    #[error("nothing to undo")]
    NothingToUndo,
    #[error("nothing to redo")]
    NothingToRedo,
    #[error("an apply is already pending; recover it first")]
    PendingApply,
}

/// Plan the apply from the two images and the host tree.
///
/// Every path in the diff is checked against the protected set first — one
/// match refuses the whole apply, the output-collection semantics — and then
/// against the exclusions, which drop the path from the ops and record it.
pub fn plan(params: &PlanParams<'_>) -> Result<ApplyPlan, ApplyError> {
    let diff = diff_trees(params.baseline, params.live, params.limits)?;
    let empty;
    let (protected, exclusions) = match (params.protected, params.exclusions) {
        (Some(p), Some(e)) => (p, e),
        (Some(p), None) => {
            empty = ProtectedPathSet::new(std::iter::empty());
            (p, &empty)
        }
        (None, Some(e)) => {
            empty = ProtectedPathSet::new(std::iter::empty());
            (&empty, e)
        }
        (None, None) => {
            empty = ProtectedPathSet::new(std::iter::empty());
            (&empty, &empty)
        }
    };
    plan_from_diff(&diff, params.source_dir, params.live, protected, exclusions)
}

/// The planning core, split out so a caller holding a `TreeDiff` (the `vm
/// diff` verb already computed one) does not walk the images twice.
pub fn plan_from_diff(
    diff: &TreeDiff,
    source_dir: &Path,
    live: &dyn TreeSource,
    protected: &ProtectedPathSet,
    exclusions: &ProtectedPathSet,
) -> Result<ApplyPlan, ApplyError> {
    let mut plan = ApplyPlan::default();
    for file in &diff.files {
        if let Some(class) = protected.first_match(&file.path) {
            plan.refused_protected
                .push((file.path.clone(), class.as_str().to_string()));
            continue;
        }
        if exclusions.contains(&file.path) {
            plan.skipped_excluded.push(file.path.clone());
            continue;
        }
        match file.change {
            ChangeKind::Added | ChangeKind::Modified | ChangeKind::TypeChanged => {
                match write_op(file, live, source_dir)? {
                    Some(op) => plan.ops.push(op),
                    None => match &file.content {
                        DiffContent::ModeOnly => {}
                        _ => plan.refused_unappliable.push((
                            file.path.clone(),
                            "its new form cannot be applied safely (a directory or special                              file, or it was left out of the comparison)"
                                .to_string(),
                        )),
                    },
                }
            }
            ChangeKind::Removed => {
                plan.ops.push(FileOp {
                    path: file.path.clone(),
                    action: OpAction::Remove,
                    pre: host_image(source_dir, &file.path)?,
                    post: None,
                });
            }
        }
    }
    Ok(plan)
}

/// Build the write op for a file the workspace added or changed, reading the
/// post-image's kind from the diff and its content source from `live`.
fn write_op(
    file: &crate::tree_diff::model::FileDiff,
    live: &dyn TreeSource,
    source_dir: &Path,
) -> Result<Option<FileOp>, ApplyError> {
    let _ = live;
    let (action, size) = match &file.content {
        DiffContent::Text { .. } | DiffContent::Binary { .. } | DiffContent::TooLarge { .. } => {
            let size = file.new.as_ref().map_or(0, |info| info.size);
            (OpAction::WriteFile, size)
        }
        DiffContent::Symlink { new_target, .. } => {
            let target = new_target.clone().ok_or_else(|| {
                ApplyError::UnsafePath(format!("{}: no symlink target in the diff", file.path))
            })?;
            let size = target.len() as u64;
            (OpAction::WriteSymlink { target }, size)
        }
        DiffContent::ModeOnly => {
            // Same bytes, different permission bits: nothing to write, and
            // not a reason to refuse the apply. The caller skips it.
            return Ok(None);
        }
        DiffContent::Entry | DiffContent::Omitted => {
            return Ok(None);
        }
    };
    Ok(Some(FileOp {
        path: file.path.clone(),
        action,
        pre: host_image(source_dir, &file.path)?,
        post: Some(OpImage { sha256: None, size }),
    }))
}

/// The host pre-image for `path` under `source_dir`.
fn host_image(source_dir: &Path, path: &str) -> Result<OpImage, ApplyError> {
    let full = host_path(source_dir, path)?;
    let meta = match fs::symlink_metadata(&full) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(OpImage::default()),
        Err(e) => return Err(e.into()),
    };
    let size = if meta.file_type().is_symlink() {
        fs::read_link(&full)?.as_os_str().len() as u64
    } else if meta.file_type().is_file() {
        meta.len()
    } else {
        return Err(ApplyError::UnsafePath(format!(
            "{path}: the host path is neither a file nor a symlink; refusing to replace it"
        )));
    };
    Ok(OpImage { sha256: None, size })
}

/// Resolve `path` against `source_dir`, refusing anything that escapes it.
pub(crate) fn host_path(source_dir: &Path, path: &str) -> Result<PathBuf, ApplyError> {
    crate::output::rules::validate_relative_path(path.as_bytes())
        .map_err(|_| ApplyError::UnsafePath(format!("{path}: not a safe relative path")))?;
    let full = source_dir.join(path);
    let root = source_dir
        .canonicalize()
        .unwrap_or_else(|_| source_dir.to_path_buf());
    let parent = full.parent().unwrap_or(source_dir);
    let existing_ancestor = std::iter::successors(Some(parent), |p| p.parent())
        .find(|p| fs::symlink_metadata(p).is_ok());
    if let Some(ancestor) = existing_ancestor {
        let ancestor = ancestor.canonicalize().map_err(ApplyError::Host)?;
        if !ancestor.starts_with(&root) {
            return Err(ApplyError::UnsafePath(format!(
                "{path}: resolves outside the workspace's host directory"
            )));
        }
    }
    Ok(full)
}

/// One line of the manifest's Merkle tree: the op, both digests, both sizes.
fn merkle_leaf(op: &ManifestOp) -> String {
    let mut line = String::with_capacity(op.path.len() + 160);
    let _ = write!(
        line,
        "{}\0{}\0{}\0{}\0{}",
        op.path,
        op.action.label(),
        op.pre.sha256.as_deref().unwrap_or("-"),
        op.post
            .as_ref()
            .and_then(|p| p.sha256.as_deref())
            .unwrap_or("-"),
        op.post.as_ref().map_or(0, |p| p.size),
    );
    if let Some(kind) = op.pre_kind {
        let _ = write!(line, "\0{}", kind.label());
    }
    line
}

/// The Merkle root over a manifest's ops, path-ordered, hex-encoded.
pub(crate) fn manifest_merkle_root(ops: &[ManifestOp]) -> String {
    let mut ordered: Vec<&ManifestOp> = ops.iter().collect();
    ordered.sort_by(|a, b| a.path.cmp(&b.path));
    let leaves: Vec<String> = ordered.iter().map(|op| merkle_leaf(op)).collect();
    hex::encode(mvm_contract::merkle::merkle_root(&leaves))
}

/// The root of the host pre-images captured before an apply, independent of
/// the guest post-images. The path kind distinguishes identical file bytes
/// from symlink target bytes; absence has its own identity.
pub(crate) fn snapshot_merkle_root(ops: &[ManifestOp]) -> String {
    let mut ordered: Vec<&ManifestOp> = ops.iter().collect();
    ordered.sort_by(|a, b| a.path.cmp(&b.path));
    let leaves: Vec<String> = ordered
        .iter()
        .map(|op| {
            format!(
                "workspace-preimage-v2\0{}\0{}\0{}\0{}",
                op.path,
                op.pre_kind.map_or("legacy_unknown", PreImageKind::label),
                op.pre.sha256.as_deref().unwrap_or("-"),
                op.pre.size
            )
        })
        .collect();
    hex::encode(mvm_contract::merkle::merkle_root(&leaves))
}

/// On-disk manifest: the persisted, self-describing record of one apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Unique id (uuid v4).
    pub id: String,
    /// Wall-clock seconds since the epoch (this crate carries no clock dep).
    pub created_at: u64,
    /// The ops, in commit order.
    pub ops: Vec<ManifestOp>,
    /// The exclusions in force, persisted so no later step rebuilds them.
    pub exclusions: Vec<String>,
    /// Matches the protected set refused, if the plan was refused (no ops).
    pub refused_protected: Vec<(String, String)>,
    /// Unappliable forms that refused the apply.
    pub refused_unappliable: Vec<(String, String)>,
    /// Paths skipped as excluded.
    pub skipped_excluded: Vec<String>,
    /// Merkle root over `ops`.
    pub merkle_root: String,
    /// Another apply this one inverts (`undo`) or re-applies (`redo`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation: Option<ApplyRelation>,
}

/// How this apply relates to an earlier one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyRelation {
    /// The earlier apply's id.
    pub apply: String,
    /// What this one does to it.
    pub kind: RelationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    /// Restores the earlier apply's pre-images.
    Undoes,
    /// Re-applies the earlier apply's post-images.
    Redoes,
}

/// A manifest op: the plan op plus the staged digests both sides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestOp {
    pub path: String,
    pub action: ManifestAction,
    pub pre: OpImage,
    /// The original host path kind. Older manifests omit it and retain the
    /// historical action-based restore behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_kind: Option<PreImageKind>,
    pub post: Option<OpImage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreImageKind {
    Absent,
    File,
    Symlink,
}

impl PreImageKind {
    fn label(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::File => "file",
            Self::Symlink => "symlink",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ManifestAction {
    WriteFile,
    WriteSymlink { target: String },
    Remove,
}

impl ManifestAction {
    fn label(&self) -> &'static str {
        match self {
            Self::WriteFile => "write_file",
            Self::WriteSymlink { .. } => "write_symlink",
            Self::Remove => "remove",
        }
    }
}

impl From<OpAction> for ManifestAction {
    fn from(action: OpAction) -> Self {
        match action {
            OpAction::WriteFile => Self::WriteFile,
            OpAction::WriteSymlink { target } => Self::WriteSymlink { target },
            OpAction::Remove => Self::Remove,
        }
    }
}

/// The set of paths an apply touches, for overlap checks.
#[must_use]
pub fn op_paths(ops: &[FileOp]) -> BTreeSet<String> {
    ops.iter().map(|op| op.path.clone()).collect()
}

#[cfg(test)]
mod tests;
