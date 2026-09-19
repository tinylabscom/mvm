//! Crash-safe publication of a captured checkpoint.
//!
//! A capture writes every blob into a private staging directory under the
//! store root, never under the checkpoint's own name. It then commits in a
//! fixed order ([`commit_plan`]): every file in the content directory is
//! synced, then the content directory, then the metadata is written through a
//! synced temporary file, then the staging directory is synced. Only then is
//! the staging directory renamed to the checkpoint's name and the store root
//! synced.
//!
//! The rename is the single point at which a checkpoint appears, and it is
//! atomic. A crash before it leaves nothing under the checkpoint's name — only
//! a staging directory, which the next capture removes once the process that
//! made it is gone. A crash after it leaves a complete checkpoint whose blobs
//! were durable before the record naming them was. The store therefore never
//! holds a record whose digests disagree with its blobs because of a crash.
//!
//! Replacing a checkpoint that already exists under the same name moves the
//! old one aside, moves the new one in, then deletes the old one. A crash
//! between the two moves leaves no checkpoint under that name, never a mix of
//! the two; the old one is lost with the attempt to replace it, which is what
//! a replacement was going to do anyway.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use mvm_core::atomic_io::{atomic_write, sync_dir, sync_file};
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};

use super::CheckpointStore;

/// Directory under the store root that holds captures still being written,
/// and checkpoints being replaced. `list()` never sees it: it carries no
/// `meta.json`, and its name cannot be a checkpoint id.
pub(super) const STAGING_DIR: &str = ".staging";

const CONTENT_DIR: &str = "content";
const META_FILE: &str = "meta.json";

/// Distinguishes two captures one process starts in the same nanosecond.
static NEXT_STAGING_NONCE: AtomicU64 = AtomicU64::new(0);

/// One write-ordering step of a commit. Kept as data so the order is a pure
/// function a test can inspect, and so a test can stop a commit after any
/// prefix of it — the shape a crash takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CommitStep {
    /// Flush these files' bytes, in parallel.
    SyncFiles(Vec<PathBuf>),
    /// Flush a directory's entries.
    SyncDir(PathBuf),
    /// Write the metadata record into the staging directory.
    WriteMeta,
    /// Move a checkpoint already stored under the same name into the staging
    /// area, if there is one.
    MoveReplacedAside,
    /// Rename the staging directory to the checkpoint's own name.
    Publish,
    /// Delete the checkpoint that `Publish` moved aside, if there was one.
    DropReplaced,
}

/// The write order that makes a capture crash-safe: blobs, then the record
/// naming them, then the name under which both appear.
pub(super) fn commit_plan(
    files: Vec<PathBuf>,
    content_dir: PathBuf,
    staging_dir: PathBuf,
    store_root: PathBuf,
) -> Vec<CommitStep> {
    vec![
        CommitStep::SyncFiles(files),
        CommitStep::SyncDir(content_dir),
        CommitStep::WriteMeta,
        CommitStep::SyncDir(staging_dir),
        CommitStep::MoveReplacedAside,
        CommitStep::Publish,
        CommitStep::SyncDir(store_root),
        CommitStep::DropReplaced,
    ]
}

/// A capture in progress: a private directory the capture writes into, which
/// becomes the checkpoint only on [`StagedCapture::commit`]. Dropped without a
/// commit — on an error or a panic — it removes what it wrote.
pub(super) struct StagedCapture<'a> {
    store: &'a CheckpointStore,
    id: CheckpointId,
    dir: PathBuf,
    replaced: Option<PathBuf>,
    published: bool,
}

impl<'a> StagedCapture<'a> {
    /// Start a capture of `id`, removing any staging a dead process left.
    pub(super) fn begin(store: &'a CheckpointStore, id: &CheckpointId) -> Result<Self> {
        ensure_capturable_id(id)?;
        let staging_root = store.root().join(STAGING_DIR);
        std::fs::create_dir_all(&staging_root)
            .with_context(|| format!("creating {}", staging_root.display()))?;
        sweep_abandoned(&staging_root);
        let dir = staging_root.join(staging_name(std::process::id(), id));
        std::fs::create_dir(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let staged = Self {
            store,
            id: id.clone(),
            dir,
            replaced: None,
            published: false,
        };
        std::fs::create_dir(staged.content_dir())
            .with_context(|| format!("creating {}", staged.content_dir().display()))?;
        Ok(staged)
    }

    /// Where the capture writes its blobs.
    pub(super) fn content_dir(&self) -> PathBuf {
        self.dir.join(CONTENT_DIR)
    }

    /// Make the staged capture the checkpoint named by `meta.id`.
    pub(super) fn commit(mut self, meta: &CheckpointMeta) -> Result<()> {
        anyhow::ensure!(
            meta.id == self.id,
            "staged capture of '{}' cannot commit a record for '{}'",
            self.id,
            meta.id
        );
        for step in self.plan()? {
            self.run(&step, meta)?;
        }
        Ok(())
    }

    /// The commit order for what is staged now.
    pub(super) fn plan(&self) -> Result<Vec<CommitStep>> {
        Ok(commit_plan(
            regular_files_in(&self.content_dir())?,
            self.content_dir(),
            self.dir.clone(),
            self.store.root().to_path_buf(),
        ))
    }

    /// Carry out one commit step.
    pub(super) fn run(&mut self, step: &CommitStep, meta: &CheckpointMeta) -> Result<()> {
        match step {
            CommitStep::SyncFiles(files) => sync_files(files.clone()),
            CommitStep::SyncDir(dir) => sync_dir(dir),
            CommitStep::WriteMeta => {
                let json =
                    serde_json::to_vec_pretty(meta).context("serializing checkpoint meta")?;
                atomic_write(&self.dir.join(META_FILE), &json)
            }
            CommitStep::MoveReplacedAside => self.move_replaced_aside(),
            CommitStep::Publish => self.publish(),
            CommitStep::DropReplaced => {
                if let Some(replaced) = self.replaced.take() {
                    // The new checkpoint is already durable under its name; a
                    // failure here only leaks the old bytes until a later
                    // sweep, so it must not fail the capture.
                    if let Err(error) = std::fs::remove_dir_all(&replaced) {
                        tracing::warn!(
                            path = %replaced.display(),
                            %error,
                            "could not delete a replaced checkpoint; the next capture sweeps it"
                        );
                    }
                }
                Ok(())
            }
        }
    }

    fn move_replaced_aside(&mut self) -> Result<()> {
        let target = self.store.dir_for(&self.id);
        if !target.exists() {
            return Ok(());
        }
        let aside = self
            .dir
            .with_file_name(format!("{}.replaced", staging_file_name(&self.dir)));
        std::fs::rename(&target, &aside).with_context(|| {
            format!(
                "moving the checkpoint being replaced {} aside",
                target.display()
            )
        })?;
        self.replaced = Some(aside);
        Ok(())
    }

    fn publish(&mut self) -> Result<()> {
        let target = self.store.dir_for(&self.id);
        if let Err(error) = std::fs::rename(&self.dir, &target) {
            // Put the old checkpoint back rather than leave its name empty.
            if let Some(aside) = self.replaced.take() {
                let _ = std::fs::rename(&aside, &target);
            }
            return Err(error).with_context(|| {
                format!(
                    "publishing staged checkpoint {} as {}",
                    self.dir.display(),
                    target.display()
                )
            });
        }
        self.published = true;
        Ok(())
    }
}

impl Drop for StagedCapture<'_> {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// Refuse an id that would land outside the store root, or collide with the
/// staging directory.
fn ensure_capturable_id(id: &CheckpointId) -> Result<()> {
    let raw = id.as_str();
    anyhow::ensure!(
        !raw.is_empty() && !raw.starts_with('.') && !raw.contains('/') && !raw.contains('\\'),
        "invalid checkpoint id {raw:?}: it must be non-empty, must not start with '.', \
         and must not contain a path separator"
    );
    Ok(())
}

/// `<pid>-<nanos>-<nonce>-<id>`: the pid first so a sweep can tell whose it
/// is without parsing the id, which may itself contain `-`.
fn staging_name(pid: u32, id: &CheckpointId) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let nonce = NEXT_STAGING_NONCE.fetch_add(1, Ordering::Relaxed);
    format!("{pid}-{nanos}-{nonce}-{}", id.as_str())
}

fn staging_file_name(dir: &Path) -> String {
    dir.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The pid that owns a staging entry, or `None` for a name this module did
/// not make.
fn staging_owner(name: &str) -> Option<i32> {
    name.split_once('-')?.0.parse().ok()
}

/// Remove every staging entry whose owning process is gone: the remains of a
/// capture that crashed, or of a replaced checkpoint whose deletion did not
/// finish. An entry of a live process is left alone, and so is a name this
/// module did not make.
///
/// Best effort: a sweep that cannot remove something leaves it for the next
/// one rather than failing the capture that triggered it.
pub(super) fn sweep_abandoned(staging_root: &Path) {
    let Ok(entries) = std::fs::read_dir(staging_root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(pid) = staging_owner(&name) else {
            continue;
        };
        if mvm_vmm::host::process_liveness::pid_is_alive(pid) {
            continue;
        }
        let path = entry.path();
        if let Err(error) = std::fs::remove_dir_all(&path) {
            tracing::warn!(path = %path.display(), %error, "could not sweep abandoned checkpoint staging");
        }
    }
}

/// Every regular file directly in `dir`, sorted. The content directory is
/// flat, and syncing everything in it — not only what the manifest names —
/// also covers files a snapshot backend signs into it.
fn regular_files_in(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        if entry.file_type()?.is_file() {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

/// Sync `files` concurrently: the device can service several flushes at once,
/// and a memory image of several GiB dominates the wait either way.
fn sync_files(files: Vec<PathBuf>) -> Result<()> {
    mvm_fs::parallel::par_map(files, |path| sync_file(&path))
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plan_makes_blobs_durable_before_the_record_and_the_record_before_the_name() {
        let plan = commit_plan(
            vec![PathBuf::from("/s/content/memory.bin")],
            PathBuf::from("/s/content"),
            PathBuf::from("/s"),
            PathBuf::from("/root"),
        );
        assert_eq!(
            plan,
            vec![
                CommitStep::SyncFiles(vec![PathBuf::from("/s/content/memory.bin")]),
                CommitStep::SyncDir(PathBuf::from("/s/content")),
                CommitStep::WriteMeta,
                CommitStep::SyncDir(PathBuf::from("/s")),
                CommitStep::MoveReplacedAside,
                CommitStep::Publish,
                CommitStep::SyncDir(PathBuf::from("/root")),
                CommitStep::DropReplaced,
            ]
        );
    }

    #[test]
    fn staging_names_lead_with_the_owning_pid_whatever_the_id() {
        let name = staging_name(4242, &CheckpointId::new("ckpt-vm-1-2"));
        assert_eq!(staging_owner(&name), Some(4242));
        assert!(name.ends_with("-ckpt-vm-1-2"));
        assert_eq!(staging_owner("not-ours"), None);
        assert_eq!(staging_owner("stray"), None);
    }

    #[test]
    fn two_captures_of_one_id_in_one_process_get_distinct_staging() {
        let id = CheckpointId::new("c");
        assert_ne!(staging_name(1, &id), staging_name(1, &id));
    }

    #[test]
    fn ids_that_would_escape_or_shadow_the_staging_area_are_refused() {
        for bad in ["", ".staging", ".hidden", "a/b", "..", "a\\b"] {
            assert!(
                ensure_capturable_id(&CheckpointId::new(bad)).is_err(),
                "{bad:?} must be refused"
            );
        }
        ensure_capturable_id(&CheckpointId::new("ckpt-vm-1")).unwrap();
    }

    /// A pid far above any `pid_max`, so no live process can hold it.
    const DEAD_PID: u32 = 999_999_999;

    #[test]
    fn the_sweep_removes_a_dead_process_staging_and_keeps_a_live_one_and_strangers() {
        let tmp = tempfile::tempdir().unwrap();
        let id = CheckpointId::new("c");
        let dead = tmp.path().join(staging_name(DEAD_PID, &id));
        let dead_replaced = tmp.path().join(format!(
            "{}.replaced",
            staging_name(DEAD_PID, &CheckpointId::new("old"))
        ));
        let live = tmp.path().join(staging_name(std::process::id(), &id));
        let stranger = tmp.path().join("stranger");
        for dir in [&dead, &dead_replaced, &live, &stranger] {
            std::fs::create_dir_all(dir.join("content")).unwrap();
        }

        sweep_abandoned(tmp.path());

        assert!(!dead.exists());
        assert!(!dead_replaced.exists());
        assert!(live.exists());
        assert!(stranger.exists());
    }
}
