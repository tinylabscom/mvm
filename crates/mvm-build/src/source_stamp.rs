//! Cross-process reuse of answers derived from the guest source tree and the
//! guest-runtime object store, keyed on the exact filesystem state they were
//! derived from.
//!
//! A source-checkout launch asks two expensive questions: what the guest
//! sources fingerprint to (a read and hash of every guest input), and whether
//! the cached guest-runtime object is intact (a hash of the archive plus every
//! extracted member). Within one `mvmctl` the process memos answer them once.
//! Every launch is a new process, though, so each one paid both in full.
//!
//! Here an answer is recorded beside a *stamp*: a digest of the identity and
//! timestamps of every file and directory the answer could depend on, plus the
//! identity of the running executable. A later process re-derives the stamp —
//! a `stat` per entry, no reads — and reuses the answer only when it matches
//! exactly.
//!
//! Any write to an input changes its change time (and usually its inode,
//! size or modification time); adding, removing or renaming an entry changes
//! the set of paths stamped. Change times are not settable without privilege,
//! so an edit cannot be disguised as the old file. File timestamps do advance
//! on a coarse clock, though, so a stamp is only produced when every entry was
//! already settled [`SETTLE`] before it was taken — an edit made in the same
//! tick as a recorded stamp could otherwise leave it unchanged. An unsettled
//! tree is simply answered in full, every time, until it settles.
//!
//! The records live in the user's cache directory, which is already the trust
//! root for everything they summarize: whoever can write a record there can
//! equally replace a cached object and the pointer naming it. A missing,
//! unreadable or malformed record is a miss, never an error.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// How long every stamped timestamp must have been still before a stamp may
/// vouch for a reuse. Comfortably above any filesystem's timestamp
/// granularity.
pub(crate) const SETTLE: Duration = Duration::from_secs(2);

/// One filesystem entry's identity and timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EntryStamp {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    pub(crate) mode: u32,
    pub(crate) len: u64,
    pub(crate) mtime: (i64, i64),
    pub(crate) ctime: (i64, i64),
}

impl EntryStamp {
    #[cfg(unix)]
    pub(crate) fn of(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            len: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }

    /// Fold this entry into `hasher`, field by field at fixed width.
    pub(crate) fn fold(&self, hasher: &mut Sha256) {
        hasher.update(self.dev.to_le_bytes());
        hasher.update(self.ino.to_le_bytes());
        hasher.update(self.mode.to_le_bytes());
        hasher.update(self.len.to_le_bytes());
        for (secs, nanos) in [self.mtime, self.ctime] {
            hasher.update(secs.to_le_bytes());
            hasher.update(nanos.to_le_bytes());
        }
    }

    /// Whether both timestamps are strictly older than `horizon`.
    pub(crate) fn settled_before(&self, horizon: (i64, i64)) -> bool {
        self.mtime < horizon && self.ctime < horizon
    }
}

/// `now - SETTLE` as `(seconds, nanoseconds)` since the epoch, the shape the
/// stamps compare in.
pub(crate) fn settle_horizon(now: SystemTime) -> Option<(i64, i64)> {
    let horizon = now.checked_sub(SETTLE)?.duration_since(UNIX_EPOCH).ok()?;
    Some((
        i64::try_from(horizon.as_secs()).ok()?,
        i64::from(horizon.subsec_nanos()),
    ))
}

/// Identity of the running executable, so a record written by one build of
/// `mvmctl` is never answered to another: a rebuilt binary may derive the
/// answer differently.
#[cfg(unix)]
pub(crate) fn executable_stamp() -> Option<EntryStamp> {
    let exe = std::env::current_exe().ok()?;
    Some(EntryStamp::of(&std::fs::metadata(exe).ok()?))
}

/// The stamp of `roots` under `workspace_root`, or `None` when it cannot vouch
/// for a reuse: a root is missing or unreadable, or any entry changed within
/// [`SETTLE`] of `now`.
///
/// Every entry under a directory root is stamped, including ones the answer
/// itself ignores. Stamping a superset of the inputs can only cost a spurious
/// miss; stamping a subset could serve a stale answer.
#[cfg(unix)]
pub(crate) fn tree_stamp(workspace_root: &Path, roots: &[&str], now: SystemTime) -> Option<String> {
    let horizon = settle_horizon(now)?;
    let mut hasher = Sha256::new();
    hasher.update(b"mvm-source-tree-stamp-v1\0");
    let exe = executable_stamp()?;
    exe.fold(&mut hasher);
    hasher.update(workspace_root.as_os_str().as_encoded_bytes());
    hasher.update(b"\0");
    let mut roots: Vec<&str> = roots.to_vec();
    roots.sort_unstable();
    roots.dedup();
    for root in roots {
        let path = workspace_root.join(root);
        // A root is read the way the fingerprint reads it: through a link.
        let metadata = std::fs::metadata(&path).ok()?;
        stamp_entry(&mut hasher, root, &metadata, horizon)?;
        if metadata.is_dir() {
            stamp_dir(&mut hasher, root, &path, horizon)?;
        }
    }
    Some(hex::encode(hasher.finalize()))
}

#[cfg(not(unix))]
pub(crate) fn tree_stamp(
    _workspace_root: &Path,
    _roots: &[&str],
    _now: SystemTime,
) -> Option<String> {
    None
}

#[cfg(unix)]
fn stamp_entry(
    hasher: &mut Sha256,
    relative: &str,
    metadata: &std::fs::Metadata,
    horizon: (i64, i64),
) -> Option<()> {
    let entry = EntryStamp::of(metadata);
    if !entry.settled_before(horizon) {
        return None;
    }
    hasher.update(relative.as_bytes());
    hasher.update(b"\0");
    entry.fold(hasher);
    Some(())
}

#[cfg(unix)]
fn stamp_dir(hasher: &mut Sha256, prefix: &str, dir: &Path, horizon: (i64, i64)) -> Option<()> {
    let mut entries = std::fs::read_dir(dir)
        .ok()?
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        let relative = format!("{prefix}/{}", name.to_str()?);
        let metadata = std::fs::symlink_metadata(entry.path()).ok()?;
        stamp_entry(hasher, &relative, &metadata, horizon)?;
        if metadata.is_dir() {
            stamp_dir(hasher, &relative, &entry.path(), horizon)?;
        }
    }
    Some(())
}

/// Where one answer recorded under `stamp` lives.
fn record_path(dir: &Path, kind: &str, stamp: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(b"mvm-stamped-answer-v1\0");
    hasher.update(kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(stamp.as_bytes());
    dir.join(hex::encode(hasher.finalize()))
}

/// The answer recorded for `(kind, stamp)`, when there is a well-formed one.
pub(crate) fn read_record(dir: &Path, kind: &str, stamp: &str) -> Option<String> {
    let value = std::fs::read_to_string(record_path(dir, kind, stamp)).ok()?;
    let value = value.trim();
    is_sha256_hex(value).then(|| value.to_string())
}

/// Record `value` for `(kind, stamp)`. Best effort: a record that cannot be
/// written only costs a later process the full answer. Not synced — a torn
/// record fails [`read_record`]'s shape check and reads as a miss.
pub(crate) fn write_record(dir: &Path, kind: &str, stamp: &str, value: &str) {
    if !is_sha256_hex(value) || std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let path = record_path(dir, kind, stamp);
    let Ok(staged) = tempfile::NamedTempFile::new_in(dir) else {
        return;
    };
    if std::fs::write(staged.path(), value).is_ok() {
        let _ = staged.persist(path);
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Where fingerprint records are kept: the user's cache, or `None` to keep
/// none.
///
/// Unit tests keep none unless one opts in, so a test walking a scratch tree
/// never writes into the developer's real cache.
fn fingerprint_record_dir() -> Option<PathBuf> {
    if cfg!(test) {
        return FINGERPRINT_RECORD_DIR.with(|dir| dir.borrow().clone());
    }
    Some(crate::cache_install::default_cache_root().join("source-fingerprints"))
}

thread_local! {
    /// The record directory a unit test opted into. Never set outside tests.
    static FINGERPRINT_RECORD_DIR: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Point this thread's fingerprint records at `dir` for the rest of a test.
#[cfg(test)]
pub(crate) fn record_fingerprints_in(dir: Option<PathBuf>) {
    FINGERPRINT_RECORD_DIR.with(|slot| *slot.borrow_mut() = dir);
}

/// The roots of every list in `lists`, in order, once each.
pub(crate) fn roots_of(lists: &[&[&'static str]]) -> Vec<&'static str> {
    let mut roots: Vec<&'static str> = lists.iter().flat_map(|list| list.iter().copied()).collect();
    roots.sort_unstable();
    roots.dedup();
    roots
}

/// Every workspace input any guest-runtime source fingerprint reads.
///
/// Built from the same lists the fingerprints hash, so a new input is stamped
/// the moment it is fingerprinted.
pub(crate) fn guest_fingerprint_roots() -> Vec<&'static str> {
    roots_of(&[
        crate::guest_agent_build::GUEST_SOURCE_INPUTS,
        crate::guest_agent_build::SDK_CDYLIB_SOURCE_INPUTS,
        crate::guest_bins::extras::EXTRAS_SOURCE_INPUTS,
        crate::guest_runtime::RUNTIME_SOURCE_FILES,
        &[crate::guest_bins::python_sdk::PYTHON_SDK_SOURCE_DIR],
    ])
}

/// One fingerprint whose answer may be reused across processes: the name of
/// the question, and every workspace input its answer reads.
///
/// `roots` must cover everything the fingerprint reads, including the inputs
/// of any fingerprint it folds in; a root it does not read only costs a
/// spurious miss when that root changes. A root that does not exist stamps
/// nothing, so the answer is then computed every time.
pub(crate) struct Fingerprint<'a> {
    pub(crate) kind: &'a str,
    pub(crate) roots: &'a [&'a str],
}

/// `compute()`, or the answer an earlier process recorded for exactly this
/// state of the guest inputs.
///
/// The fingerprint's `kind` names the question, including anything besides the
/// tree it depends on (a version, an architecture). An answer is recorded only when the tree
/// was settled and stamped identically before and after computing it, so an
/// edit racing the computation is never recorded against either state.
pub(crate) fn stamped_fingerprint<E>(
    fingerprint: &Fingerprint<'_>,
    workspace_root: &Path,
    compute: impl FnOnce() -> Result<String, E>,
) -> Result<String, E> {
    let Some(dir) = fingerprint_record_dir() else {
        return compute();
    };
    stamped_answer(
        &StampedQuestion {
            kind: fingerprint.kind,
            workspace_root,
            roots: fingerprint.roots,
            record_dir: &dir,
        },
        SystemTime::now,
        compute,
    )
}

/// One question whose answer is reused across processes.
pub(crate) struct StampedQuestion<'a> {
    pub(crate) kind: &'a str,
    pub(crate) workspace_root: &'a Path,
    pub(crate) roots: &'a [&'a str],
    pub(crate) record_dir: &'a Path,
}

/// [`stamped_fingerprint`] with its inputs explicit, and the clock injectable
/// so a test can look at a tree "later" without waiting for it to settle.
pub(crate) fn stamped_answer<E>(
    question: &StampedQuestion<'_>,
    now: impl Fn() -> SystemTime,
    compute: impl FnOnce() -> Result<String, E>,
) -> Result<String, E> {
    let before = tree_stamp(question.workspace_root, question.roots, now());
    if let Some(stamp) = &before
        && let Some(answer) = read_record(question.record_dir, question.kind, stamp)
    {
        return Ok(answer);
    }
    let answer = compute()?;
    if let Some(stamp) = before
        && tree_stamp(question.workspace_root, question.roots, now()).as_deref()
            == Some(stamp.as_str())
    {
        write_record(question.record_dir, question.kind, &stamp, &answer);
    }
    Ok(answer)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::cell::Cell;

    const ROOTS: &[&str] = &["Cargo.lock", "crates/guest/src"];

    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("Cargo.lock"), b"lock").unwrap();
        let src = temp.path().join("crates/guest/src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("lib.rs"), b"fn a() {}").unwrap();
        temp
    }

    fn later() -> SystemTime {
        SystemTime::now() + Duration::from_secs(3600)
    }

    /// Digest the tree's actual bytes, standing in for the real fingerprint.
    fn content_digest(root: &Path) -> String {
        let mut hasher = Sha256::new();
        hasher.update(std::fs::read(root.join("Cargo.lock")).unwrap());
        hasher.update(std::fs::read(root.join("crates/guest/src/lib.rs")).unwrap());
        if let Ok(extra) = std::fs::read(root.join("crates/guest/src/new.rs")) {
            hasher.update(extra);
        }
        hex::encode(hasher.finalize())
    }

    /// Answer the question as a fresh process would, counting computations.
    fn ask(root: &Path, records: &Path, now: SystemTime, computed: &Cell<usize>) -> String {
        stamped_answer::<std::convert::Infallible>(
            &StampedQuestion {
                kind: "test",
                workspace_root: root,
                roots: ROOTS,
                record_dir: records,
            },
            || now,
            || {
                computed.set(computed.get() + 1);
                Ok(content_digest(root))
            },
        )
        .unwrap()
    }

    #[test]
    fn a_settled_tree_is_answered_from_its_record_in_a_later_process() {
        let tree = fixture();
        let records = tempfile::tempdir().unwrap();
        let computed = Cell::new(0);
        let first = ask(tree.path(), records.path(), later(), &computed);
        let second = ask(tree.path(), records.path(), later(), &computed);
        assert_eq!(first, second);
        assert_eq!(computed.get(), 1, "the second process reuses the record");
    }

    #[test]
    fn an_edit_of_the_same_length_is_detected_before_reuse() {
        let tree = fixture();
        let records = tempfile::tempdir().unwrap();
        let computed = Cell::new(0);
        let before = ask(tree.path(), records.path(), later(), &computed);
        // Same size, so only the timestamps and content differ.
        std::fs::write(tree.path().join("crates/guest/src/lib.rs"), b"fn b() {}").unwrap();
        let after = ask(tree.path(), records.path(), later(), &computed);
        assert_ne!(before, after, "the edit must reach the answer");
        assert_eq!(after, content_digest(tree.path()));
        assert_eq!(computed.get(), 2);
    }

    #[test]
    fn an_edit_that_restores_the_old_modification_time_is_still_detected() {
        let tree = fixture();
        let records = tempfile::tempdir().unwrap();
        let computed = Cell::new(0);
        let file = tree.path().join("crates/guest/src/lib.rs");
        let mtime = std::fs::metadata(&file).unwrap().modified().unwrap();
        let before = ask(tree.path(), records.path(), later(), &computed);
        std::fs::write(&file, b"fn c() {}").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        let after = ask(tree.path(), records.path(), later(), &computed);
        assert_ne!(before, after, "the change time still moves");
        assert_eq!(computed.get(), 2);
    }

    #[test]
    fn an_added_or_removed_file_is_detected_before_reuse() {
        let tree = fixture();
        let records = tempfile::tempdir().unwrap();
        let computed = Cell::new(0);
        let original = ask(tree.path(), records.path(), later(), &computed);
        let added = tree.path().join("crates/guest/src/new.rs");
        std::fs::write(&added, b"x").unwrap();
        let with_file = ask(tree.path(), records.path(), later(), &computed);
        assert_ne!(original, with_file);
        std::fs::remove_file(&added).unwrap();
        let without = ask(tree.path(), records.path(), later(), &computed);
        assert_eq!(without, original);
        assert_eq!(computed.get(), 3, "neither change may reuse a record");
    }

    #[test]
    fn an_unsettled_tree_is_answered_in_full_and_never_recorded() {
        let tree = fixture();
        let records = tempfile::tempdir().unwrap();
        let computed = Cell::new(0);
        let now = SystemTime::now();
        ask(tree.path(), records.path(), now, &computed);
        ask(tree.path(), records.path(), now, &computed);
        assert_eq!(computed.get(), 2);
        assert_eq!(std::fs::read_dir(records.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_missing_root_records_nothing_and_a_malformed_record_is_a_miss() {
        let tree = fixture();
        let records = tempfile::tempdir().unwrap();
        assert!(tree_stamp(tree.path(), &["absent"], later()).is_none());

        let stamp = tree_stamp(tree.path(), ROOTS, later()).unwrap();
        std::fs::write(record_path(records.path(), "test", &stamp), b"not a digest").unwrap();
        let computed = Cell::new(0);
        ask(tree.path(), records.path(), later(), &computed);
        assert_eq!(computed.get(), 1);
    }

    #[test]
    fn answers_to_different_questions_do_not_share_a_record() {
        let tree = fixture();
        let records = tempfile::tempdir().unwrap();
        let stamp = tree_stamp(tree.path(), ROOTS, later()).unwrap();
        write_record(records.path(), "one", &stamp, &"a".repeat(64));
        assert_eq!(
            read_record(records.path(), "one", &stamp),
            Some("a".repeat(64))
        );
        assert_eq!(read_record(records.path(), "two", &stamp), None);
    }

    #[test]
    fn every_guest_fingerprint_root_exists_in_this_checkout_and_stamps() {
        let workspace =
            crate::guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        let roots = guest_fingerprint_roots();
        for root in &roots {
            assert!(
                workspace.join(root).exists(),
                "{root} is not in the checkout"
            );
        }
        assert!(tree_stamp(&workspace, &roots, later()).is_some());
    }
}
