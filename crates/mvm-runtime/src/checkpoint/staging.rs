//! Crash-safe publication of a captured checkpoint.
//!
//! A capture writes every blob into a private staging directory under the
//! store root, never under the checkpoint's own name. It then commits in a
//! fixed order ([`commit_plan`]): every file in the content tree is synced,
//! then nested directories deepest-first, then the content directory, then
//! the metadata is written through a synced temporary file, then the staging
//! directory is synced. Only then is the staging directory renamed to the
//! checkpoint's name and the store root synced.
//!
//! The rename is the single point at which a checkpoint appears, and it is
//! atomic. A crash before it leaves nothing under the checkpoint's name — only
//! a staging directory. Local/quiescent entries with a released real lease can
//! be reclaimed; external or unclassified entries remain quarantined.
//! Capturing-process exit alone is not writer proof. A crash after publication
//! leaves a complete checkpoint whose blobs
//! were durable before the record naming them was. The store therefore never
//! holds a record whose digests disagree with its blobs because of a crash.
//!
//! Replacing a checkpoint that already exists under the same name moves the
//! old one aside, moves the new one in, then deletes the old one. A crash
//! between the two moves leaves no checkpoint under that name, never a mix of
//! the two; the old one is lost with the attempt to replace it, which is what
//! a replacement was going to do anyway.

use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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
const LEASE_FILE: &str = ".capture-lease";
const DISPOSITION_FILE: &str = ".capture-disposition.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum WriterDisposition {
    Local,
    ExternalUnconfirmed,
    Quiescent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn of(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn directory(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        anyhow::ensure!(metadata.is_dir(), "capture directory was replaced");
        Ok(Self::of(&metadata))
    }
}

fn private_owner(metadata: &std::fs::Metadata) -> bool {
    // SAFETY: geteuid only reads the identity performing these filesystem operations.
    metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DispositionRecord {
    version: u32,
    store: FileIdentity,
    directory: FileIdentity,
    lease: FileIdentity,
    disposition: WriterDisposition,
}

struct StageCustody {
    store: CheckpointStore,
    owner: Option<tempfile::TempDir>,
    lease: File,
    record: DispositionRecord,
}

/// Borrow the actual lease and store used by this cleanup, not only a copied
/// identity tuple. Revalidation also runs on the privately claimed pathname.
struct CleanupBinding<'a> {
    record: &'a DispositionRecord,
    store: &'a CheckpointStore,
    lease: &'a File,
    gc_disposition: Option<FileIdentity>,
}

impl CleanupBinding<'_> {
    fn verify(&self, path: &Path) -> Result<()> {
        self.record.matches(self.store, path, self.lease)?;
        if let Some(expected) = self.gc_disposition {
            let (current, identity) = read_disposition(path)?;
            anyhow::ensure!(
                identity == expected
                    && current == *self.record
                    && current.disposition != WriterDisposition::ExternalUnconfirmed,
                "capture disposition changed after GC inspection"
            );
        }
        Ok(())
    }
}

fn read_disposition(path: &Path) -> Result<(DispositionRecord, FileIdentity)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.join(DISPOSITION_FILE))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && private_owner(&metadata),
        "capture disposition is not private and regular"
    );
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 4096, "capture disposition exceeds bound");
    Ok((serde_json::from_slice(&bytes)?, FileIdentity::of(&metadata)))
}

impl StageCustody {
    fn matches(&self, path: &Path) -> Result<()> {
        self.record.matches(&self.store, path, &self.lease)
    }
}

impl DispositionRecord {
    fn matches(&self, store: &CheckpointStore, path: &Path, lease: &File) -> Result<()> {
        let directory_metadata = std::fs::symlink_metadata(path)?;
        let lease_metadata = std::fs::symlink_metadata(path.join(LEASE_FILE))?;
        anyhow::ensure!(
            self.version == 1
                && FileIdentity::directory(store.root())? == self.store
                && FileIdentity::directory(path)? == self.directory
                && private_owner(&directory_metadata)
                && lease_metadata.is_file()
                && private_owner(&lease_metadata)
                && FileIdentity::of(&lease_metadata) == self.lease
                && FileIdentity::of(&lease.metadata()?) == self.lease,
            "capture custody identity changed"
        );
        Ok(())
    }
}

/// An actual exclusive lease, held through final identity validation/removal.
/// It authorizes local storage cleanup only, never native lifetime claims.
pub(super) struct ReclaimableStage {
    path: PathBuf,
    lease: File,
    record: DispositionRecord,
    store: CheckpointStore,
    disposition_identity: FileIdentity,
}

impl ReclaimableStage {
    fn inspect(store: &CheckpointStore, path: PathBuf) -> Result<Option<Self>> {
        FileIdentity::directory(&path)?;
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path.join(LEASE_FILE))?;
        anyhow::ensure!(
            lease.metadata()?.is_file() && private_owner(&lease.metadata()?),
            "capture lease is not private and regular"
        );
        match lease.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }
        let (record, disposition_identity) = read_disposition(&path)?;
        record.matches(store, &path, &lease)?;
        if record.disposition == WriterDisposition::ExternalUnconfirmed {
            return Ok(None);
        }
        Ok(Some(Self {
            path,
            lease,
            record,
            store: store.clone(),
            disposition_identity,
        }))
    }

    fn remove(self) -> Result<()> {
        remove_original_directory(
            &self.path,
            CleanupBinding {
                record: &self.record,
                store: &self.store,
                lease: &self.lease,
                gc_disposition: Some(self.disposition_identity),
            },
        )
    }
}

#[cfg(test)]
pub(super) fn reclaim_after_inspection(
    store: &CheckpointStore,
    path: &Path,
    before_claim: impl FnOnce(),
) -> Result<()> {
    let claim = ReclaimableStage::inspect(store, path.to_path_buf())?
        .context("fixture has no positive original claim")?;
    reclaim_original_inode(
        &claim.path,
        CleanupBinding {
            record: &claim.record,
            store: &claim.store,
            lease: &claim.lease,
            gc_disposition: Some(claim.disposition_identity),
        },
        before_claim,
    )
}

/// Unknown roots defer object/cache collection as well as directory removal.
pub(super) struct StagingScan {
    pub(super) reclaimable: Vec<ReclaimableStage>,
    pub(super) retained: bool,
}

pub(super) fn scan(store: &CheckpointStore) -> StagingScan {
    let mut result = StagingScan {
        reclaimable: Vec::new(),
        retained: false,
    };
    let entries = match std::fs::read_dir(store.root().join(STAGING_DIR)) {
        Ok(entries) => entries,
        Err(_) => {
            result.retained = true;
            return result;
        }
    };
    for entry in entries {
        match entry {
            Ok(entry) => match ReclaimableStage::inspect(store, entry.path()) {
                Ok(Some(claim)) => result.reclaimable.push(claim),
                Ok(None) | Err(_) => result.retained = true,
            },
            Err(_) => result.retained = true,
        }
    }
    result
}

/// Claim by rename, then validate the moved inode before recursive deletion.
/// A replacement is retained, including on a race after the pathname check.
fn remove_original_directory(path: &Path, binding: CleanupBinding<'_>) -> Result<()> {
    reclaim_original_inode(path, binding, || {})
}

fn reclaim_original_inode(
    path: &Path,
    binding: CleanupBinding<'_>,
    before_claim: impl FnOnce(),
) -> Result<()> {
    binding.verify(path)?;
    before_claim();
    let parent = path.parent().context("capture directory has no parent")?;
    let claim = tempfile::Builder::new()
        .prefix(".gc-")
        .tempdir_in(parent)?
        .keep();
    let moved = claim.join("entry");
    if let Err(error) = std::fs::rename(path, &moved) {
        let _ = std::fs::remove_dir(&claim);
        return Err(error.into());
    }
    // The directory alone is insufficient: a substituted lease or store must
    // not inherit this original open lease's deletion authority.
    binding.verify(&moved)?;
    std::fs::remove_dir_all(&moved)?;
    std::fs::remove_dir(&claim)?;
    Ok(())
}

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
    nested_content_dirs: Vec<PathBuf>,
    content_dir: PathBuf,
    staging_dir: PathBuf,
    store_root: PathBuf,
) -> Vec<CommitStep> {
    let mut steps = vec![CommitStep::SyncFiles(files)];
    steps.extend(nested_content_dirs.into_iter().map(CommitStep::SyncDir));
    steps.extend([
        CommitStep::SyncDir(content_dir),
        CommitStep::WriteMeta,
        CommitStep::SyncDir(staging_dir),
        CommitStep::MoveReplacedAside,
        CommitStep::Publish,
        CommitStep::SyncDir(store_root),
        CommitStep::DropReplaced,
    ]);
    steps
}

/// A capture in progress: a private directory the capture writes into, which
/// becomes the checkpoint only on [`StagedCapture::commit`]. Dropped without a
/// commit removes local/quiescent content only through an identity-bound claim.
/// External uncertainty retains the complete original storage custody.
pub(super) struct StagedCapture {
    custody: Option<Box<StageCustody>>,
    id: CheckpointId,
    dir: PathBuf,
    replaced: Option<(PathBuf, FileIdentity)>,
    published: bool,
    disposition: Cell<WriterDisposition>,
}

impl StagedCapture {
    /// Start a capture of `id`, quarantining staging a dead process left.
    /// [`begin`](Self::begin) a capture of `vm`, refused before anything is
    /// staged when `vm`'s run carries an entered human credential: a
    /// checkpoint, and every fork built from one, would copy that session.
    pub(super) fn begin_for_vm(
        store: &CheckpointStore,
        id: &CheckpointId,
        vm: &str,
    ) -> Result<Self> {
        crate::vm::human_credential::refuse_capture_after_entry(vm)?;
        Self::begin(store, id)
    }

    pub(super) fn begin(store: &CheckpointStore, id: &CheckpointId) -> Result<Self> {
        ensure_capturable_id(id)?;
        let staging_root = admit_private_staging(store)?;
        sweep_abandoned(store);
        let prefix = staging_name(std::process::id(), id);
        let directory_owner = tempfile::Builder::new()
            .prefix(&prefix)
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(&staging_root)?;
        let dir = directory_owner.path().to_path_buf();
        let lease = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dir.join(LEASE_FILE))?;
        lease.lock()?;
        let record = DispositionRecord {
            version: 1,
            store: FileIdentity::directory(store.root())?,
            directory: FileIdentity::directory(&dir)?,
            lease: FileIdentity::of(&lease.metadata()?),
            disposition: WriterDisposition::Local,
        };
        let staged = Self {
            // This clones strong ownership of the SAME original custody and
            // storage objects. It does not reopen a store or recover by name.
            custody: Some(Box::new(StageCustody {
                store: store.clone(),
                owner: Some(directory_owner),
                lease,
                record,
            })),
            id: id.clone(),
            dir,
            replaced: None,
            published: false,
            disposition: Cell::new(WriterDisposition::Local),
        };
        staged.persist_disposition(WriterDisposition::Local)?;
        staged.custody().lease.sync_all()?;
        sync_dir(&staged.dir)?;
        sync_dir(&staging_root)?;
        sync_dir(store.root())?;
        if let Some(parent) = store.root().parent().filter(|p| !p.as_os_str().is_empty()) {
            sync_dir(parent)?;
        }
        create_private_dir_new(&staged.content_dir())?;
        Ok(staged)
    }

    fn custody(&self) -> &StageCustody {
        self.custody
            .as_ref()
            .expect("original staging custody present")
    }

    fn persist_disposition(&self, disposition: WriterDisposition) -> Result<()> {
        self.custody().matches(&self.dir)?;
        let record = DispositionRecord {
            disposition,
            ..self.custody().record
        };
        mvm_core::atomic_io::atomic_write_durable(
            &self.dir.join(DISPOSITION_FILE),
            &serde_json::to_vec(&record)?,
        )?;
        self.custody().matches(&self.dir)
    }

    pub(super) fn arm_writer(&self) -> Result<()> {
        let previous = self
            .disposition
            .replace(WriterDisposition::ExternalUnconfirmed);
        if let Err(error) = self.persist_disposition(WriterDisposition::ExternalUnconfirmed) {
            // Explicit returned failure preceded the delegated effect. Panic
            // instead leaves the original custody armed for conservative Drop.
            self.disposition.set(previous);
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn writer_completed(&self) -> Result<()> {
        // The caller has observed its actual synchronous writer finish.
        self.disposition.set(WriterDisposition::Quiescent);
        self.persist_disposition(WriterDisposition::Quiescent)
    }

    #[cfg(test)]
    /// Keep fixture bytes while actually closing its creator lease. This is
    /// data-only test mechanics, not process death or native quiescence.
    pub(super) fn release_lease_for_gc_fixture(mut self) -> PathBuf {
        let custody = self.custody.take().expect("fixture owns real custody");
        let StageCustody { owner, lease, .. } = *custody;
        let path = owner.expect("fixture owns original directory").keep();
        drop(lease);
        path
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
        let (files, nested_dirs) = content_tree_entries(&self.content_dir())?;
        Ok(commit_plan(
            files,
            nested_dirs,
            self.content_dir(),
            self.dir.clone(),
            self.custody().store.root().to_path_buf(),
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
                if let Some((replaced, identity)) = self.replaced.take() {
                    // The new checkpoint is already durable under its name; a
                    // failure here only leaks the old bytes until a later
                    // sweep, so it must not fail the capture.
                    let cleanup = (|| {
                        anyhow::ensure!(
                            FileIdentity::directory(&replaced)? == identity,
                            "replaced checkpoint identity changed"
                        );
                        let claim =
                            ReclaimableStage::inspect(&self.custody().store, replaced.clone())?
                                .context("replaced checkpoint has no local cleanup claim")?;
                        claim.remove()
                    })();
                    if let Err(error) = cleanup {
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
        self.custody().matches(&self.dir)?;
        let target = self.custody().store.dir_for(&self.id);
        if !target.exists() {
            return Ok(());
        }
        let aside = self
            .dir
            .with_file_name(format!("{}.replaced", staging_file_name(&self.dir)));
        let identity = FileIdentity::directory(&target)?;
        anyhow::ensure!(!aside.exists(), "replacement staging name already exists");
        std::fs::rename(&target, &aside).with_context(|| {
            format!(
                "moving the checkpoint being replaced {} aside",
                target.display()
            )
        })?;
        anyhow::ensure!(
            FileIdentity::directory(&aside)? == identity,
            "replacement changed while moving aside"
        );
        self.replaced = Some((aside, identity));
        Ok(())
    }

    fn publish(&mut self) -> Result<()> {
        self.custody().matches(&self.dir)?;
        let target = self.custody().store.dir_for(&self.id);
        if let Err(error) = std::fs::rename(&self.dir, &target) {
            // Put the old checkpoint back rather than leave its name empty.
            if let Some((aside, identity)) = self.replaced.take()
                && FileIdentity::directory(&aside).is_ok_and(|actual| actual == identity)
                && std::fs::symlink_metadata(&target)
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            {
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

impl Drop for StagedCapture {
    fn drop(&mut self) {
        let Some(mut custody) = self.custody.take() else {
            return;
        };
        if self.disposition.get() == WriterDisposition::ExternalUnconfirmed {
            // Preserve the complete original storage aggregate. This leak is
            // not recoverability or evidence of external/native writer exit.
            std::mem::forget(custody);
            return;
        }
        // Publication moved the inode. Never let TempDir remove a later reuse
        // of its old pathname, even when publication itself succeeded.
        if self.published {
            if let Some(owner) = custody.owner.take() {
                let _ = owner.keep();
            }
            let target = custody.store.dir_for(&self.id);
            if custody
                .record
                .matches(&custody.store, &target, &custody.lease)
                .is_err()
            {
                std::mem::forget(custody);
            }
            return;
        }
        if custody.matches(&self.dir).is_err() {
            std::mem::forget(custody);
            return;
        }
        if let Some(owner) = custody.owner.take() {
            let _ = owner.keep();
        }
        if remove_original_directory(
            &self.dir,
            CleanupBinding {
                record: &custody.record,
                store: &custody.store,
                lease: &custody.lease,
                // Owner authority is independently known pre-effect or
                // synchronous completion, not a GC disposition inference.
                gc_disposition: None,
            },
        )
        .is_err()
        {
            // Keep the root deletion guard and actual lease too: dropping a
            // last store owner could otherwise delete the quarantined claim.
            std::mem::forget(custody);
        }
    }
}

/// Refuse an id that would land outside the store root, or collide with the
/// staging directory.
/// Admit the staging area a capture writes plaintext into: a real directory,
/// not a link to one, readable by this user alone. Created private when it
/// does not exist yet and narrowed when it was left wider.
pub(super) fn admit_private_staging(store: &CheckpointStore) -> Result<PathBuf> {
    let staging_root = store.root().join(STAGING_DIR);
    mvm_core::config::create_private_dir(&staging_root)
        .with_context(|| format!("creating {}", staging_root.display()))?;
    let metadata = std::fs::symlink_metadata(&staging_root)
        .with_context(|| format!("reading {}", staging_root.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "checkpoint staging {} is not a directory",
        staging_root.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        anyhow::ensure!(
            metadata.mode() & 0o077 == 0,
            "checkpoint staging {} is readable by other users",
            staging_root.display()
        );
        let store_owner = std::fs::metadata(store.root())
            .with_context(|| format!("reading {}", store.root().display()))?
            .uid();
        anyhow::ensure!(
            metadata.uid() == store_owner,
            "checkpoint staging {} belongs to another user than the store",
            staging_root.display()
        );
    }
    Ok(staging_root)
}

fn create_private_dir_new(dir: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

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

/// Diagnostic name parsing, never writer-lifetime or reclaimability evidence.
#[cfg(test)]
fn staging_owner(name: &str) -> Option<i32> {
    name.split_once('-')?.0.parse().ok()
}

pub(super) struct StagingReclamation {
    pub(super) removed: usize,
    pub(super) retained: bool,
}

/// Dry-run and mutation share the same positive claim and real lease rule.
pub(super) fn reclaim_abandoned(store: &CheckpointStore, dry_run: bool) -> StagingReclamation {
    let scanned = scan(store);
    let mut result = StagingReclamation {
        removed: 0,
        retained: scanned.retained,
    };
    for claim in scanned.reclaimable {
        if dry_run || claim.remove().is_ok() {
            result.removed += 1;
        } else {
            // Failed/replaced reclaim claims may still root pool objects.
            result.retained = true;
        }
    }
    result
}

fn sweep_abandoned(store: &CheckpointStore) -> usize {
    reclaim_abandoned(store, false).removed
}

/// Prefix of the private directory under the store root a `vm_full` restore
/// opens its blobs into. It lives only as long as the restore call.
pub(super) const RESTORE_MATERIALIZATION_PREFIX: &str = ".restore-";

/// Remove restore materializations under `store_root` whose owning process
/// died before removing them. Returns how many it removed.
pub(super) fn reclaim_abandoned_restores(store_root: &Path) -> usize {
    crate::private_staging::reclaim_abandoned(store_root, RESTORE_MATERIALIZATION_PREFIX).len()
}

/// The restore materializations [`reclaim_abandoned_restores`] would remove.
pub(super) fn abandoned_restores(store_root: &Path) -> usize {
    crate::private_staging::abandoned(store_root, RESTORE_MATERIALIZATION_PREFIX).len()
}

/// Every regular file and nested directory under `dir`. Directories are
/// deepest-first so every entry is durable before the directory that names it.
fn content_tree_entries(dir: &Path) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut files = Vec::new();
    let mut directories = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in
            std::fs::read_dir(&current).with_context(|| format!("reading {}", current.display()))?
        {
            let entry = entry.with_context(|| format!("reading {}", current.display()))?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                directories.push(entry.path());
                pending.push(entry.path());
            } else if file_type.is_file() {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    directories.sort_by(|a, b| {
        b.components()
            .count()
            .cmp(&a.components().count())
            .then_with(|| a.cmp(b))
    });
    Ok((files, directories))
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
            Vec::new(),
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
    fn a_chunk_tree_syncs_files_then_directories_from_the_leaves_up() {
        let tmp = tempfile::tempdir().unwrap();
        let content = tmp.path().join("content");
        let shard = content.join(".chunks/ab");
        std::fs::create_dir_all(&shard).unwrap();
        std::fs::write(content.join("memory.bin.chunks.json"), b"index").unwrap();
        std::fs::write(shard.join("abcdef"), b"chunk").unwrap();

        let (files, directories) = content_tree_entries(&content).unwrap();

        assert_eq!(
            files,
            vec![shard.join("abcdef"), content.join("memory.bin.chunks.json")]
        );
        assert_eq!(directories, vec![shard, content.join(".chunks")]);
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

    #[test]
    fn the_sweep_reclaims_only_unleased_positive_local_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let external = StagedCapture::begin(&store, &CheckpointId::new("external")).unwrap();
        external.arm_writer().unwrap();
        let external = external.release_lease_for_gc_fixture();
        let live = StagedCapture::begin(&store, &CheckpointId::new("live")).unwrap();
        let local = StagedCapture::begin(&store, &CheckpointId::new("local"))
            .unwrap()
            .release_lease_for_gc_fixture();
        let unknown = store.root().join(STAGING_DIR).join("999999999-unknown");
        std::fs::create_dir(&unknown).unwrap();
        assert_eq!(scan(&store).reclaimable.len(), 1);
        let dry = reclaim_abandoned(&store, true);
        assert_eq!(dry.removed, 1);
        assert!(dry.retained && local.exists());
        let actual = reclaim_abandoned(&store, false);
        assert_eq!(actual.removed, 1);
        assert!(actual.retained && !local.exists());
        assert!(external.exists() && live.dir.exists() && unknown.exists());
        // The external fixture closed its REAL lease. No process exit or
        // native writer was simulated, and lease loss did not clear the hold.
    }

    #[test]
    fn malformed_missing_and_replaced_dispositions_are_never_repaired() {
        use std::os::unix::fs::symlink;
        for fault in 0..7 {
            let tmp = tempfile::tempdir().unwrap();
            let store = CheckpointStore::at(tmp.path().join("store"));
            let path = StagedCapture::begin(&store, &CheckpointId::new("local"))
                .unwrap()
                .release_lease_for_gc_fixture();
            let record = path.join(DISPOSITION_FILE);
            match fault {
                0 => std::fs::remove_file(&record).unwrap(),
                1 => std::fs::write(&record, b"{").unwrap(),
                2 => {
                    std::fs::rename(path.join(LEASE_FILE), tmp.path().join("old-lease")).unwrap();
                    std::fs::write(path.join(LEASE_FILE), b"replacement").unwrap();
                }
                3 => {
                    std::fs::remove_file(&record).unwrap();
                    symlink(tmp.path().join("missing"), &record).unwrap();
                }
                4 => {
                    let mut value: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
                    value["version"] = 99.into();
                    std::fs::write(&record, serde_json::to_vec(&value).unwrap()).unwrap();
                }
                5 => std::fs::write(&record, vec![b'x'; 4097]).unwrap(),
                6 => {
                    std::fs::rename(&path, tmp.path().join("original")).unwrap();
                    std::fs::create_dir(&path).unwrap();
                    std::fs::write(path.join("replacement"), b"keep").unwrap();
                }
                _ => unreachable!(),
            }
            let report = reclaim_abandoned(&store, false);
            assert_eq!(report.removed, 0);
            assert!(report.retained && path.exists());
        }
    }

    #[test]
    fn deletion_claim_retains_a_replacement_installed_after_inspection() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let path = StagedCapture::begin(&store, &CheckpointId::new("local"))
            .unwrap()
            .release_lease_for_gc_fixture();
        assert!(
            reclaim_after_inspection(&store, &path, || {
                std::fs::rename(&path, tmp.path().join("original")).unwrap();
                std::fs::create_dir(&path).unwrap();
                std::fs::write(path.join("replacement"), b"keep").unwrap();
            })
            .is_err()
        );
        let claim = std::fs::read_dir(store.root().join(STAGING_DIR))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|entry| entry.join("entry/replacement").exists())
            .expect("mismatched reclaim claim retained");
        assert_eq!(
            std::fs::read(claim.join("entry/replacement")).unwrap(),
            b"keep"
        );
        assert!(scan(&store).retained);
    }

    #[test]
    fn owner_drop_and_published_tempdir_never_remove_reused_names() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let staged = StagedCapture::begin(&store, &CheckpointId::new("unpublished")).unwrap();
        let path = staged.dir.clone();
        std::fs::rename(&path, tmp.path().join("original")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("replacement"), b"keep").unwrap();
        drop(staged);
        assert_eq!(std::fs::read(path.join("replacement")).unwrap(), b"keep");
        let mut published = StagedCapture::begin(&store, &CheckpointId::new("published")).unwrap();
        let old_name = published.dir.clone();
        published.publish().unwrap();
        std::fs::create_dir(&old_name).unwrap();
        std::fs::write(old_name.join("replacement"), b"keep").unwrap();
        drop(published);
        assert_eq!(
            std::fs::read(old_name.join("replacement")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn moved_stage_cannot_authorize_collection_in_a_replacement_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let path = StagedCapture::begin(&store, &CheckpointId::new("local"))
            .unwrap()
            .release_lease_for_gc_fixture();
        let name = path.file_name().unwrap();
        let old_root = tmp.path().join("old-store");
        std::fs::rename(store.root(), &old_root).unwrap();
        std::fs::create_dir_all(store.root().join(STAGING_DIR)).unwrap();
        std::fs::rename(old_root.join(STAGING_DIR).join(name), &path).unwrap();
        let report = reclaim_abandoned(&store, false);
        assert!(report.retained);
        assert_eq!(report.removed, 0);
        assert!(path.exists());
    }

    #[test]
    fn drop_replaced_step_retains_a_substituted_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let id = CheckpointId::new("shared");
        let mut old = StagedCapture::begin(&store, &id).unwrap();
        old.publish().unwrap();
        drop(old);
        let mut new = StagedCapture::begin(&store, &id).unwrap();
        new.move_replaced_aside().unwrap();
        let (aside, _) = new.replaced.as_ref().unwrap();
        let aside = aside.clone();
        std::fs::rename(&aside, tmp.path().join("original")).unwrap();
        std::fs::create_dir(&aside).unwrap();
        std::fs::write(aside.join("replacement"), b"keep").unwrap();
        let meta =
            CheckpointMeta::builder(id, mvm_core::checkpoint::CheckpointClass::FsQuick, "vm")
                .build();
        new.run(&CommitStep::DropReplaced, &meta).unwrap();
        assert_eq!(std::fs::read(aside.join("replacement")).unwrap(), b"keep");
    }
}
