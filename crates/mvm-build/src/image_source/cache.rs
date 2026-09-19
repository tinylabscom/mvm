//! The local image cache: where images built from a selected checkout are kept
//! so an unchanged pair of checkouts is not built twice.
//!
//! An entry is a directory holding one locally built set — its manifest and
//! every artifact the manifest names — plus a record of the key it was
//! published under. It lives at `<mvm cache>/local-images/v1/<key digest>`.
//! Nothing else is written under `local-images/`, and nothing under it is ever
//! read as anything but `local-dev`.
//!
//! Entries are addressed by the digest of their key rather than of their
//! bytes. A lookup has to find an entry before anything is built, so its name
//! can only come from the inputs; the bytes are pinned inside the entry
//! instead, by the manifest's per-artifact digests, which every read checks.
//!
//! Publishing is atomic. A build writes into a fresh staging directory beside
//! the entries, the staged set is verified as a whole, and one `rename` makes
//! it visible. A crash leaves at most an unnamed staging directory, which a
//! later publish reaps once it is old enough; a reader can never see a partial
//! entry. When two builds publish the same key, the first rename wins and the
//! second discards its copy — `rename` does not replace a non-empty directory.
//!
//! Entries are immutable once published. A read re-verifies the entry against
//! its manifest and against the checkouts as they are now; an entry that fails
//! is evicted and reported, never served.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use mvm_core::image_set::{
    ImageSetRole, ImageTrustTier, LOCAL_SET_MANIFEST_NAME, LocalCheckouts, LocalImageSet,
};
use mvm_core::packs::Sha256Hex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::local_set::open_mvm_checkout;
use super::{ImageSourceError, LocalImageCheckout, LocalSetError, LocalSetRequest};

mod key;

pub use key::{
    FlakeAttr, FlakeLockDigest, ImageBuildRole, ImageBuildTarget, KeyInputs, LocalImageCacheKey,
    ToolchainPins,
};

/// The directory under the mvm cache root that holds local image entries.
pub const LOCAL_IMAGE_CACHE_DIR: &str = "local-images";

/// The layout version, a directory of its own so a future layout never reads
/// an entry written under this one.
const LAYOUT: &str = "v1";

/// The record written into every entry, naming the key it was published under.
pub const ENTRY_RECORD_NAME: &str = "cache-entry.json";

const ENTRY_RECORD_SCHEMA: u32 = 1;
const STAGING_DIR: &str = ".staging";
const EVICTED_DIR: &str = ".evicted";

/// Staging directories are named `<stem>.tmp.<pid>.<seq>`, the convention
/// [`crate::cache_install`] reaps by.
const STAGING_STEM: &str = "entry";

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Why the local image cache refused.
#[derive(Debug, Error)]
pub enum LocalImageCacheError {
    #[error(transparent)]
    Selection(#[from] ImageSourceError),
    #[error(transparent)]
    Checkout(#[from] LocalSetError),
    #[error("{}: {detail}", .path.display())]
    Input { path: PathBuf, detail: String },
    #[error(
        "the cache key names checkouts that have changed since it was derived \
         (key: images {}, mvm {}; now: images {}, mvm {}); derive it again",
        .key.images, .key.mvm, .now.images, .now.mvm
    )]
    KeyStale {
        key: Box<LocalCheckouts>,
        now: Box<LocalCheckouts>,
    },
    #[error("staged entry {}: {detail}", .path.display())]
    StagedEntryRefused { path: PathBuf, detail: String },
    #[error("staged entry {}: {source}", .path.display())]
    StagedSetRefused {
        path: PathBuf,
        source: Box<LocalSetError>,
    },
    #[error("{op} {}: {source}", .path.display())]
    Io {
        op: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

fn io_error(op: &'static str, path: &Path) -> impl FnOnce(io::Error) -> LocalImageCacheError {
    let path = path.to_path_buf();
    move |source| LocalImageCacheError::Io { op, path, source }
}

/// What reading or publishing an entry needs besides its key: the checkouts to
/// hold it against, and the roles the caller is about to use.
#[derive(Debug, Clone, Copy)]
pub struct EntryContext<'a> {
    pub images: &'a LocalImageCheckout,
    pub mvm_checkout: &'a Path,
    pub roles: &'a [ImageSetRole],
}

/// A verified entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedImageSet {
    pub dir: PathBuf,
    pub key: LocalImageCacheKey,
    pub set: LocalImageSet,
}

impl CachedImageSet {
    /// Always [`ImageTrustTier::LocalDev`]: nothing in the cache can say
    /// otherwise, and an entry recording any other tier is evicted.
    #[must_use]
    pub fn tier(&self) -> ImageTrustTier {
        self.set.tier()
    }
}

/// The result of a lookup.
#[derive(Debug)]
pub enum CacheLookup {
    Hit(Box<CachedImageSet>),
    Miss,
    /// An entry was present under the key but did not verify. It has been
    /// removed; the caller builds as on a miss.
    Evicted {
        reason: String,
    },
}

/// The result of a publish. Either way the entry now in the cache was verified
/// after it became visible.
#[derive(Debug)]
pub enum PublishOutcome {
    /// This publish's staged set became the entry.
    Published(CachedImageSet),
    /// Another publish of the same key won; this one's staged copy was
    /// discarded.
    AlreadyPresent(CachedImageSet),
}

impl PublishOutcome {
    #[must_use]
    pub fn entry(&self) -> &CachedImageSet {
        match self {
            Self::Published(entry) | Self::AlreadyPresent(entry) => entry,
        }
    }
}

/// A staging directory for one key, removed on drop unless published.
#[derive(Debug)]
pub struct StagedEntry {
    dir: PathBuf,
    key: LocalImageCacheKey,
}

impl StagedEntry {
    /// The directory the build writes the set into. It exists and is empty.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    #[must_use]
    pub fn key(&self) -> &LocalImageCacheKey {
        &self.key
    }
}

impl Drop for StagedEntry {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The record inside an entry.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryRecord {
    schema: u32,
    tier: ImageTrustTier,
    key_digest: Sha256Hex,
    key: LocalImageCacheKey,
    manifest_sha256: Sha256Hex,
}

/// A local image cache rooted at one directory.
#[derive(Debug, Clone)]
pub struct LocalImageCache {
    root: PathBuf,
}

impl LocalImageCache {
    /// The cache under this process's mvm cache root.
    #[must_use]
    pub fn open_default() -> Self {
        Self::at(Path::new(&mvm_core::config::mvm_cache_dir()).join(LOCAL_IMAGE_CACHE_DIR))
    }

    /// The cache rooted at `root`.
    #[must_use]
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where the entry for `key` is, whether or not it exists.
    #[must_use]
    pub fn entry_dir(&self, key: &LocalImageCacheKey) -> PathBuf {
        self.layout_dir().join(key.digest().as_str())
    }

    fn layout_dir(&self) -> PathBuf {
        self.root.join(LAYOUT)
    }

    fn staging_dir(&self) -> PathBuf {
        self.layout_dir().join(STAGING_DIR)
    }

    fn evicted_dir(&self) -> PathBuf {
        self.layout_dir().join(EVICTED_DIR)
    }

    /// Read the entry for `key`, verified against its manifest and against
    /// the checkouts as they are now.
    ///
    /// A key derived from checkouts that have since changed is an error, not a
    /// miss: it would look up the wrong entry.
    pub fn lookup(
        &self,
        key: &LocalImageCacheKey,
        ctx: &EntryContext<'_>,
    ) -> Result<CacheLookup, LocalImageCacheError> {
        require_current(key, ctx)?;
        let dir = self.entry_dir(key);
        if std::fs::symlink_metadata(&dir).is_err() {
            return Ok(CacheLookup::Miss);
        }
        match read_entry(&dir, key, ctx) {
            Ok(entry) => Ok(CacheLookup::Hit(Box::new(entry))),
            Err(EntryFault::Caller(err)) => Err(err),
            Err(EntryFault::Corrupt(reason)) => {
                self.evict(&dir);
                Ok(CacheLookup::Evicted { reason })
            }
        }
    }

    /// A fresh, empty staging directory for `key`, on the same filesystem as
    /// the entries so publishing it is one `rename`.
    pub fn stage(&self, key: &LocalImageCacheKey) -> Result<StagedEntry, LocalImageCacheError> {
        let staging = self.staging_dir();
        create_private_dir_all(&staging)?;
        crate::cache_install::reap_stale_staging(&staging, STAGING_STEM);
        let name = format!(
            "{STAGING_STEM}.tmp.{}.{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let dir = staging.join(name);
        create_private_dir(&dir)?;
        Ok(StagedEntry {
            dir,
            key: key.clone(),
        })
    }

    /// Verify the set in `staged` and make it the entry for its key.
    ///
    /// Refused unless the staged directory holds exactly one set — its
    /// manifest and the regular files it names, nothing else — built from the
    /// checkouts the key names, which must still be the checkouts on disk.
    pub fn publish(
        &self,
        staged: StagedEntry,
        ctx: &EntryContext<'_>,
    ) -> Result<PublishOutcome, LocalImageCacheError> {
        let key = staged.key.clone();
        require_current(&key, ctx)?;
        let set = verify_staged(&staged, ctx)?;
        write_record(staged.dir(), &key, &set.manifest_sha256)?;
        seal(staged.dir())?;
        let target = self.entry_dir(&key);
        // Two attempts: an entry already present that fails verification is
        // evicted, and the rename is tried once more.
        for _ in 0..2 {
            match std::fs::rename(staged.dir(), &target) {
                Ok(()) => {
                    sync_dir(&self.layout_dir())?;
                    let entry = self.read_published(&target, &key, ctx)?;
                    return Ok(PublishOutcome::Published(entry));
                }
                Err(err) if target_occupied(&err) => match self.lookup(&key, ctx)? {
                    CacheLookup::Hit(entry) => return Ok(PublishOutcome::AlreadyPresent(*entry)),
                    CacheLookup::Miss | CacheLookup::Evicted { .. } => continue,
                },
                Err(err) => return Err(io_error("publishing", &target)(err)),
            }
        }
        Err(LocalImageCacheError::StagedEntryRefused {
            path: staged.dir().to_path_buf(),
            detail: format!(
                "{} is occupied by an entry that keeps failing verification",
                target.display()
            ),
        })
    }

    /// Read back an entry this process just renamed into place. A failure
    /// here is not a corrupt stranger's entry, so it is reported rather than
    /// quietly evicted.
    fn read_published(
        &self,
        dir: &Path,
        key: &LocalImageCacheKey,
        ctx: &EntryContext<'_>,
    ) -> Result<CachedImageSet, LocalImageCacheError> {
        read_entry(dir, key, ctx).map_err(|fault| match fault {
            EntryFault::Caller(err) => err,
            EntryFault::Corrupt(detail) => {
                self.evict(dir);
                LocalImageCacheError::StagedEntryRefused {
                    path: dir.to_path_buf(),
                    detail,
                }
            }
        })
    }

    /// Move a failed entry out of the namespace in one rename, then delete it.
    /// Best-effort past the rename: an undeleted evicted copy is litter, never
    /// an entry, and the next eviction clears it.
    fn evict(&self, dir: &Path) {
        let evicted = self.evicted_dir();
        if create_private_dir_all(&evicted).is_err() {
            let _ = std::fs::remove_dir_all(dir);
            return;
        }
        clear_dir(&evicted);
        let name = format!(
            "{}.{}.{}",
            dir.file_name().and_then(|n| n.to_str()).unwrap_or("entry"),
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let aside = evicted.join(name);
        if std::fs::rename(dir, &aside).is_ok() {
            let _ = std::fs::remove_dir_all(&aside);
        }
    }
}

/// Why an entry could not be read: the caller's fault, which is reported, or
/// the entry's, which evicts it.
enum EntryFault {
    Caller(LocalImageCacheError),
    Corrupt(String),
}

/// The key must name the checkouts as they are now.
fn require_current(
    key: &LocalImageCacheKey,
    ctx: &EntryContext<'_>,
) -> Result<(), LocalImageCacheError> {
    ctx.images.reverify()?;
    let (_, mvm) = open_mvm_checkout(ctx.mvm_checkout)?;
    let now = LocalCheckouts {
        images: ctx.images.identity().clone(),
        mvm,
    };
    if now != key.checkouts {
        return Err(LocalImageCacheError::KeyStale {
            key: Box::new(key.checkouts.clone()),
            now: Box::new(now),
        });
    }
    Ok(())
}

fn read_entry(
    dir: &Path,
    key: &LocalImageCacheKey,
    ctx: &EntryContext<'_>,
) -> Result<CachedImageSet, EntryFault> {
    let meta = std::fs::symlink_metadata(dir).map_err(|e| EntryFault::Corrupt(e.to_string()))?;
    if !meta.file_type().is_dir() {
        return Err(EntryFault::Corrupt("not a directory".to_string()));
    }
    let names = regular_file_names(dir).map_err(EntryFault::Corrupt)?;
    let record = read_record(dir).map_err(EntryFault::Corrupt)?;
    check_record(&record, key).map_err(EntryFault::Corrupt)?;
    let set = read_set(dir, key, ctx).map_err(|err| match err {
        LocalSetError::Selection(_) | LocalSetError::MvmCheckout { .. } => {
            EntryFault::Caller(err.into())
        }
        other => EntryFault::Corrupt(other.to_string()),
    })?;
    if set.manifest_sha256 != record.manifest_sha256 {
        return Err(EntryFault::Corrupt(
            "the manifest is not the one the entry was published with".to_string(),
        ));
    }
    let mut expected = set_file_names(&set);
    expected.insert(ENTRY_RECORD_NAME.to_string());
    check_exact_contents(&names, &expected).map_err(EntryFault::Corrupt)?;
    Ok(CachedImageSet {
        dir: dir.to_path_buf(),
        key: key.clone(),
        set,
    })
}

fn check_record(record: &EntryRecord, key: &LocalImageCacheKey) -> Result<(), String> {
    if record.schema != ENTRY_RECORD_SCHEMA {
        return Err(format!("unknown entry schema {}", record.schema));
    }
    if record.tier != ImageTrustTier::LocalDev {
        return Err(format!(
            "the entry records the {} tier; a local cache entry is only ever {}",
            record.tier,
            ImageTrustTier::LocalDev
        ));
    }
    if &record.key != key || record.key_digest != key.digest() {
        return Err("the entry was published under a different key".to_string());
    }
    Ok(())
}

fn read_set(
    dir: &Path,
    key: &LocalImageCacheKey,
    ctx: &EntryContext<'_>,
) -> Result<LocalImageSet, LocalSetError> {
    ctx.images.read_local_image_set(&LocalSetRequest {
        mvm_checkout: ctx.mvm_checkout,
        set_dir: dir,
        arch: key.arch,
        roles: ctx.roles,
    })
}

fn verify_staged(
    staged: &StagedEntry,
    ctx: &EntryContext<'_>,
) -> Result<LocalImageSet, LocalImageCacheError> {
    let refused = |detail: String| LocalImageCacheError::StagedEntryRefused {
        path: staged.dir().to_path_buf(),
        detail,
    };
    let names = regular_file_names(staged.dir()).map_err(refused)?;
    if names.contains(ENTRY_RECORD_NAME) {
        return Err(refused(format!(
            "{ENTRY_RECORD_NAME} is written by the cache, not by a build"
        )));
    }
    let set = read_set(staged.dir(), &staged.key, ctx).map_err(|err| match err {
        LocalSetError::Selection(_) | LocalSetError::MvmCheckout { .. } => {
            LocalImageCacheError::Checkout(err)
        }
        other => LocalImageCacheError::StagedSetRefused {
            path: staged.dir().to_path_buf(),
            source: Box::new(other),
        },
    })?;
    if set.checkouts != staged.key.checkouts {
        return Err(refused(
            "the set records different checkouts from the key it is published under".to_string(),
        ));
    }
    check_exact_contents(&names, &set_file_names(&set)).map_err(refused)?;
    Ok(set)
}

/// The files a set consists of: its manifest and every artifact it names.
fn set_file_names(set: &LocalImageSet) -> BTreeSet<String> {
    set.artifacts
        .iter()
        .map(|artifact| artifact.name.as_str().to_string())
        .chain([LOCAL_SET_MANIFEST_NAME.to_string()])
        .collect()
}

fn check_exact_contents(
    present: &BTreeSet<String>,
    expected: &BTreeSet<String>,
) -> Result<(), String> {
    if let Some(extra) = present.difference(expected).next() {
        return Err(format!("{extra} is not part of the set"));
    }
    if let Some(missing) = expected.difference(present).next() {
        return Err(format!("{missing} is missing"));
    }
    Ok(())
}

/// The names of everything directly inside `dir`, each of which must be a
/// regular file: an entry has no subdirectories, and a link would make the
/// bytes checked here some other file's.
fn regular_file_names(dir: &Path) -> Result<BTreeSet<String>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("listing: {e}"))?;
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("listing: {e}"))?;
        let raw = entry.file_name();
        let name = raw
            .to_str()
            .ok_or_else(|| format!("{} is not a UTF-8 name", raw.to_string_lossy()))?;
        let kind = entry
            .file_type()
            .map_err(|e| format!("reading {name}: {e}"))?;
        if kind.is_symlink() {
            return Err(format!("{name} is a symlink"));
        }
        if !kind.is_file() {
            return Err(format!("{name} is not a regular file"));
        }
        names.insert(name.to_string());
    }
    Ok(names)
}

fn read_record(dir: &Path) -> Result<EntryRecord, String> {
    let bytes = std::fs::read(dir.join(ENTRY_RECORD_NAME))
        .map_err(|e| format!("reading {ENTRY_RECORD_NAME}: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parsing {ENTRY_RECORD_NAME}: {e}"))
}

fn write_record(
    dir: &Path,
    key: &LocalImageCacheKey,
    manifest_sha256: &Sha256Hex,
) -> Result<(), LocalImageCacheError> {
    let record = EntryRecord {
        schema: ENTRY_RECORD_SCHEMA,
        tier: ImageTrustTier::LocalDev,
        key_digest: key.digest(),
        key: key.clone(),
        manifest_sha256: manifest_sha256.clone(),
    };
    let path = dir.join(ENTRY_RECORD_NAME);
    let body = serde_json::to_vec_pretty(&record).expect("an entry record always serializes");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(io_error("writing", &path))?;
    io::Write::write_all(&mut file, &body).map_err(io_error("writing", &path))
}

/// Make every file read-only and durable, then the directory itself, so the
/// rename publishes bytes that are already on disk.
fn seal(dir: &Path) -> Result<(), LocalImageCacheError> {
    let entries = std::fs::read_dir(dir).map_err(io_error("listing", dir))?;
    for entry in entries {
        let path = entry.map_err(io_error("listing", dir))?.path();
        set_read_only(&path)?;
        std::fs::File::open(&path)
            .and_then(|file| file.sync_all())
            .map_err(io_error("syncing", &path))?;
    }
    sync_dir(dir)
}

#[cfg(unix)]
fn set_read_only(path: &Path) -> Result<(), LocalImageCacheError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
        .map_err(io_error("sealing", path))
}

#[cfg(not(unix))]
fn set_read_only(path: &Path) -> Result<(), LocalImageCacheError> {
    let mut perms = std::fs::metadata(path)
        .map_err(io_error("sealing", path))?
        .permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(path, perms).map_err(io_error("sealing", path))
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), LocalImageCacheError> {
    std::fs::File::open(dir)
        .and_then(|file| file.sync_all())
        .map_err(io_error("syncing", dir))
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> Result<(), LocalImageCacheError> {
    Ok(())
}

/// `rename` onto a non-empty directory fails, which is how a second publisher
/// learns it lost. Linux reports `ENOTEMPTY` or `EEXIST`; both are the same
/// answer here.
fn target_occupied(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::AlreadyExists | io::ErrorKind::DirectoryNotEmpty
    )
}

/// Every directory the cache creates is private to its owner, like the rest of
/// the mvm home.
fn create_private_dir_all(dir: &Path) -> Result<(), LocalImageCacheError> {
    private_dir_builder(true)
        .create(dir)
        .map_err(io_error("creating", dir))
}

fn create_private_dir(dir: &Path) -> Result<(), LocalImageCacheError> {
    private_dir_builder(false)
        .create(dir)
        .map_err(io_error("creating", dir))
}

fn private_dir_builder(recursive: bool) -> std::fs::DirBuilder {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
}

fn clear_dir(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let _ = std::fs::remove_dir_all(entry.path());
    }
}
