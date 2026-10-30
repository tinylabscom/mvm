//! Digests this process has resolved, bound to the identity of the artifact.
//! Resolution hashes the artifact or verifies its sealed digest sidecar.
//!
//! A launch checks the same artifact at several layers (the image-set proof, the
//! retained runtime generation, the checkpoint binding, the VMM's own observed
//! configuration). Each check is a separate decision and each used to re-read the
//! whole file. This registry lets a later check reuse a digest an earlier one
//! resolved, without trusting a path or a timestamp alone.
//!
//! An entry is keyed by device and inode and holds the file's size, mtime, ctime,
//! mode and owner. A replacement is a new inode, and a content write or `chmod`
//! moves ctime, so a change normally invalidates the entry and the file is read
//! again. Two rules close the gaps in that:
//!
//! - **Racy timestamps.** Filesystems stamp files with a coarse clock, so a
//!   rewrite shortly after the previous change can carry the *same* ctime and
//!   mtime. An entry is therefore recorded only for a file whose newest timestamp
//!   is older than [`RACY_WINDOW`] when resolution starts, the rule git uses
//!   for its index. An unsettled file is never remembered by this registry.
//!   There is deliberately no exemption for read-only or private
//!   files: a `chmod`, write and `chmod` inside one clock tick leaves them
//!   unchanged too.
//! - **Resolution must see one file.** The identity is taken before and after
//!   resolution, and a file that changed in between is not recorded.
//!
//! The registry lives in this process only. It is not a trust root: it never
//! outlives the process and nothing reads it back from disk.

use std::io;
use std::path::Path;
use std::time::Duration;

/// A file whose newest timestamp is younger than this when resolution starts is
/// never recorded. It must exceed the filesystem's timestamp granularity (a
/// coarse tick of at most 10 ms on a local Linux filesystem) with room for the
/// clock to be read on either side; it is not meant for network filesystems,
/// whose granularity can be seconds.
pub const RACY_WINDOW: Duration = Duration::from_millis(250);

/// Where a [`sha256_file_verified`] digest came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedSource {
    /// A digest previously resolved for this exact, settled file in this process;
    /// the artifact was not read on this call.
    Remembered,
    /// A verified sealed sidecar supplied the digest; the artifact was not read.
    Sidecar,
    /// The file was read.
    Hashed,
}

/// SHA-256 of `path`, reusing a remembered digest or verified sealed sidecar
/// when available, and otherwise hashing the artifact.
pub fn sha256_file_verified(path: &Path) -> io::Result<String> {
    sha256_file_verified_report_source(path).map(|(hex, _)| hex)
}

/// [`sha256_file_verified`], reporting whether the file was read.
///
/// Returned so a hit is directly assertable: the cost this avoids is linear in
/// artifact size and invisible in a digest that is correct either way.
pub fn sha256_file_verified_report_source(path: &Path) -> io::Result<(String, VerifiedSource)> {
    imp::digest(path, RACY_WINDOW)
}

/// SHA-256 of an already-open file, reading it only when this process has not
/// already resolved a digest for this exact file.
///
/// For a caller that opens a file once, checks its type, mode and owner on the
/// handle, and hashes that same handle so a name cannot be satisfied by one file
/// and handed another. The identity comes from the handle, never from `path`.
pub fn sha256_open_file_verified(file: &std::fs::File) -> io::Result<String> {
    imp::digest_open(file, RACY_WINDOW).map(|(hex, _)| hex)
}

#[cfg(unix)]
mod imp {
    use super::VerifiedSource;
    use crate::crypto::image_verify::{
        DigestSource, sha256_file, sha256_file_cached_report_source, sha256_reader,
    };
    use std::collections::HashMap;
    use std::fs::{File, Metadata};
    use std::io::{self, Seek, SeekFrom};
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;
    use std::sync::{LazyLock, Mutex};
    use std::time::{Duration, SystemTime};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Identity {
        dev: u64,
        ino: u64,
        size: u64,
        mtime: (i64, i64),
        ctime: (i64, i64),
        mode: u32,
        uid: u32,
    }

    /// Keyed by device and inode; each entry holds the identity it was read
    /// under and the resolved digest.
    type Registry = HashMap<(u64, u64), (Identity, String)>;

    /// Bounds a long-lived process, which sees a new inode per launch.
    const MAX_ENTRIES: usize = 4096;

    static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(HashMap::new()));

    fn identity_of(meta: &Metadata) -> Option<Identity> {
        meta.file_type().is_file().then(|| Identity {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.len(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
            mode: meta.mode(),
            uid: meta.uid(),
        })
    }

    /// Whether the newest of mtime and ctime is at least `window` older than now.
    /// A ctime on a whole second means a filesystem too coarse for `window` to
    /// outlast its tick (the cost of a false positive is one more read).
    fn settled(identity: &Identity, window: Duration) -> bool {
        if identity.ctime.1 == 0 {
            return false;
        }
        let stamp = |(secs, nanos): (i64, i64)| {
            Duration::new(
                u64::try_from(secs).unwrap_or(u64::MAX),
                u32::try_from(nanos).unwrap_or(0),
            )
        };
        let newest = stamp(identity.mtime).max(stamp(identity.ctime));
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|now| now.checked_sub(newest))
            .is_some_and(|age| age >= window)
    }

    fn lookup(identity: &Identity) -> Option<String> {
        let registry = REGISTRY.lock().ok()?;
        let (known, digest) = registry.get(&(identity.dev, identity.ino))?;
        (known == identity).then(|| digest.clone())
    }

    fn insert(identity: Identity, digest: &str) {
        if let Ok(mut registry) = REGISTRY.lock() {
            remember(&mut registry, identity, digest);
        }
    }

    fn remember(registry: &mut Registry, identity: Identity, digest: &str) {
        // Entries only save a re-read, so dropping them all is always safe.
        if registry.len() >= MAX_ENTRIES {
            registry.clear();
        }
        registry.insert((identity.dev, identity.ino), (identity, digest.to_owned()));
    }

    /// The shared decision. `read` returns the digest and source; `identity_now` re-reads its
    /// identity afterwards so a file that changed mid-read is not recorded.
    fn decide(
        before: Identity,
        window: Duration,
        read: impl FnOnce() -> io::Result<(String, VerifiedSource)>,
        identity_now: impl FnOnce() -> Option<Identity>,
    ) -> io::Result<(String, VerifiedSource)> {
        let settled_before = settled(&before, window);
        if settled_before && let Some(known) = lookup(&before) {
            return Ok((known, VerifiedSource::Remembered));
        }
        let (digest, source) = read()?;
        if settled_before
            && let Some(after) = identity_now()
            && after == before
        {
            insert(after, &digest);
        }
        Ok((digest, source))
    }

    pub(super) fn digest(path: &Path, window: Duration) -> io::Result<(String, VerifiedSource)> {
        let before = std::fs::symlink_metadata(path)
            .ok()
            .and_then(|meta| identity_of(&meta));
        let Some(before) = before else {
            // Not a regular file (a symlink, a directory, absent): never recorded.
            return Ok((sha256_file(path)?, VerifiedSource::Hashed));
        };
        decide(
            before,
            window,
            // A registry miss still asks the sealed sidecar before reading the
            // file, so a digest an earlier process recorded is reused.
            || {
                sha256_file_cached_report_source(path).map(|(digest, source)| {
                    let source = match source {
                        DigestSource::Sidecar => VerifiedSource::Sidecar,
                        DigestSource::Hashed(_) => VerifiedSource::Hashed,
                    };
                    (digest, source)
                })
            },
            || {
                std::fs::symlink_metadata(path)
                    .ok()
                    .and_then(|meta| identity_of(&meta))
            },
        )
    }

    pub(super) fn digest_open(
        file: &File,
        window: Duration,
    ) -> io::Result<(String, VerifiedSource)> {
        let before = file.metadata().ok().and_then(|meta| identity_of(&meta));
        let Some(before) = before else {
            return Ok((sha256_reader(file)?, VerifiedSource::Hashed));
        };
        decide(
            before,
            window,
            || {
                // The registry's digest is of the whole file, whatever offset
                // the caller's handle is at.
                let mut handle = file;
                handle.seek(SeekFrom::Start(0))?;
                sha256_reader(handle).map(|digest| (digest, VerifiedSource::Hashed))
            },
            || file.metadata().ok().and_then(|meta| identity_of(&meta)),
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn identity(ino: u64, ctime_nanos: i64) -> Identity {
            Identity {
                dev: u64::MAX,
                ino,
                size: 0,
                mtime: (1, 1),
                ctime: (1, ctime_nanos),
                mode: 0o400,
                uid: 0,
            }
        }

        #[test]
        fn a_whole_second_ctime_is_never_settled() {
            assert!(!settled(&identity(0, 0), Duration::ZERO));
            assert!(settled(&identity(0, 5), Duration::ZERO));
        }

        #[test]
        fn the_registry_is_bounded() {
            let mut registry = Registry::new();
            for ino in 0..(MAX_ENTRIES as u64 * 2) {
                remember(&mut registry, identity(ino, 5), "d");
            }
            assert!(registry.len() <= MAX_ENTRIES);
        }
    }
}

/// Without Unix identity there is nothing to bind a digest to, so every call
/// reads the file.
#[cfg(not(unix))]
mod imp {
    use super::VerifiedSource;
    use crate::crypto::image_verify::{sha256_file, sha256_reader};
    use std::fs::File;
    use std::io;
    use std::path::Path;
    use std::time::Duration;

    pub(super) fn digest(path: &Path, _window: Duration) -> io::Result<(String, VerifiedSource)> {
        Ok((sha256_file(path)?, VerifiedSource::Hashed))
    }

    pub(super) fn digest_open(
        file: &File,
        _window: Duration,
    ) -> io::Result<(String, VerifiedSource)> {
        Ok((sha256_reader(file)?, VerifiedSource::Hashed))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::crypto::image_verify::sha256_file;
    use std::os::unix::fs::PermissionsExt as _;

    /// A window short enough to wait out, long enough to exceed the clock tick.
    const TEST_WINDOW: Duration = Duration::from_millis(60);

    fn settle() {
        std::thread::sleep(TEST_WINDOW + Duration::from_millis(60));
    }

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn read_only_file(dir: &Path, name: &str, body: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        path
    }

    /// Rewrite a read-only file in place the way someone with the owner's rights
    /// would: make it writable, change it, make it read-only again.
    fn tamper_in_place(path: &Path, body: &[u8]) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
    }

    fn report(path: &Path, window: Duration) -> (String, VerifiedSource) {
        imp::digest(path, window).unwrap()
    }

    #[test]
    fn a_verified_sidecar_is_not_reported_as_an_artifact_read() {
        use crate::crypto::image_verify::{
            DigestSource, seal_digest_if_matches, sha256_file_cached_report_source,
        };

        let dir = private_dir();
        let path = read_only_file(dir.path(), "sealed", b"accepted bytes");
        let accepted = sha256_file(&path).unwrap();
        std::thread::sleep(RACY_WINDOW + Duration::from_millis(60));
        assert!(seal_digest_if_matches(&path, &accepted).unwrap());
        assert_eq!(
            sha256_file_cached_report_source(&path).unwrap(),
            (accepted.clone(), DigestSource::Sidecar)
        );
        let (digest, source) = sha256_file_verified_report_source(&path).unwrap();
        assert_eq!(digest, accepted);
        assert_eq!(source, VerifiedSource::Sidecar);
        assert_eq!(
            sha256_file_verified_report_source(&path).unwrap(),
            (accepted.clone(), VerifiedSource::Remembered)
        );

        tamper_in_place(&path, b"tampered bytes");
        let (changed, source) = sha256_file_verified_report_source(&path).unwrap();
        assert_eq!(source, VerifiedSource::Hashed);
        assert_ne!(changed, accepted);
        assert_eq!(changed, sha256_file(&path).unwrap());
        assert!(!seal_digest_if_matches(&path, &accepted).unwrap());
    }

    #[test]
    fn an_invalid_sidecar_reports_the_fallback_artifact_read() {
        let dir = private_dir();
        let path = read_only_file(dir.path(), "invalid", b"actual artifact");
        std::fs::write(
            crate::crypto::image_verify::sha256_cache_path(&path),
            "untrusted digest and seal",
        )
        .unwrap();
        let (digest, source) = sha256_file_verified_report_source(&path).unwrap();
        assert_eq!(source, VerifiedSource::Hashed);
        assert_eq!(digest, sha256_file(&path).unwrap());
    }

    #[test]
    fn a_settled_file_is_read_once() {
        let dir = private_dir();
        let path = read_only_file(dir.path(), "a", b"first contents");
        settle();
        let (first, source) = report(&path, TEST_WINDOW);
        assert_eq!(source, VerifiedSource::Hashed);
        assert_eq!(first, sha256_file(&path).unwrap());
        let (second, source) = report(&path, TEST_WINDOW);
        assert_eq!(source, VerifiedSource::Remembered);
        assert_eq!(second, first);
    }

    #[test]
    fn a_file_still_inside_the_window_is_never_remembered() {
        let dir = private_dir();
        let path = read_only_file(dir.path(), "a", b"just written");
        // The window is far longer than the test runs, so the file never settles.
        let window = Duration::from_secs(3600);
        assert_eq!(report(&path, window).1, VerifiedSource::Hashed);
        assert_eq!(report(&path, window).1, VerifiedSource::Hashed);
    }

    /// The case the window exists for: a rewrite inside one clock tick of the
    /// previous change leaves size, mtime, ctime and mode as they were.
    #[test]
    fn a_rewrite_inside_the_window_is_not_served_a_stale_digest() {
        let dir = private_dir();
        let path = read_only_file(dir.path(), "a", b"AAAAAAAA");
        let window = Duration::from_secs(3600);
        let (before, _) = report(&path, window);
        tamper_in_place(&path, b"BBBBBBBB");
        let (after, source) = report(&path, window);
        assert_eq!(source, VerifiedSource::Hashed);
        assert_ne!(after, before);
        assert_eq!(after, sha256_file(&path).unwrap());
    }

    #[test]
    fn a_settled_file_rewritten_in_place_is_read_again() {
        let dir = private_dir();
        let path = read_only_file(dir.path(), "a", b"AAAAAAAA");
        settle();
        let (before, _) = report(&path, TEST_WINDOW);
        assert_eq!(report(&path, TEST_WINDOW).1, VerifiedSource::Remembered);
        // Same length, so size cannot tell the two apart; ctime must.
        tamper_in_place(&path, b"BBBBBBBB");
        let (after, source) = report(&path, TEST_WINDOW);
        assert_eq!(source, VerifiedSource::Hashed);
        assert_ne!(after, before);
        assert_eq!(after, sha256_file(&path).unwrap());
    }

    #[test]
    fn a_settled_file_that_is_replaced_is_read_again() {
        let dir = private_dir();
        let path = read_only_file(dir.path(), "a", b"AAAAAAAA");
        settle();
        let (before, _) = report(&path, TEST_WINDOW);
        let other = read_only_file(dir.path(), "b", b"BBBBBBBB");
        std::fs::rename(&other, &path).unwrap();
        settle();
        let (after, source) = report(&path, TEST_WINDOW);
        assert_eq!(source, VerifiedSource::Hashed);
        assert_ne!(after, before);
    }

    #[test]
    fn a_settled_file_that_only_changes_mode_is_read_again() {
        let dir = private_dir();
        let path = read_only_file(dir.path(), "a", b"unchanged bytes");
        settle();
        report(&path, TEST_WINDOW);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(report(&path, TEST_WINDOW).1, VerifiedSource::Hashed);
    }

    #[test]
    fn an_open_file_shares_the_registry_with_its_path() {
        let dir = private_dir();
        let path = read_only_file(dir.path(), "a", b"through a handle");
        settle();
        let (by_path, _) = report(&path, TEST_WINDOW);
        let file = std::fs::File::open(&path).unwrap();
        let (by_handle, source) = imp::digest_open(&file, TEST_WINDOW).unwrap();
        assert_eq!(source, VerifiedSource::Remembered);
        assert_eq!(by_handle, by_path);
    }

    #[test]
    fn an_open_file_that_changed_is_read_again() {
        let dir = private_dir();
        let path = read_only_file(dir.path(), "a", b"AAAAAAAA");
        settle();
        let file = std::fs::File::open(&path).unwrap();
        let (before, _) = imp::digest_open(&file, TEST_WINDOW).unwrap();
        tamper_in_place(&path, b"BBBBBBBB");
        let reopened = std::fs::File::open(&path).unwrap();
        let (after, source) = imp::digest_open(&reopened, TEST_WINDOW).unwrap();
        assert_eq!(source, VerifiedSource::Hashed);
        assert_ne!(after, before);
    }

    #[test]
    fn a_symlink_is_hashed_and_never_remembered() {
        let dir = private_dir();
        let target = read_only_file(dir.path(), "target", b"through a link");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        settle();
        let (a, first) = report(&link, TEST_WINDOW);
        let (b, second) = report(&link, TEST_WINDOW);
        assert_eq!(a, b);
        assert_eq!(
            (first, second),
            (VerifiedSource::Hashed, VerifiedSource::Hashed)
        );
    }

    #[test]
    fn the_public_entry_points_agree_with_the_plain_hash() {
        let dir = private_dir();
        let path = read_only_file(dir.path(), "a", b"agreement");
        assert_eq!(
            sha256_file_verified(&path).unwrap(),
            sha256_file(&path).unwrap()
        );
        let file = std::fs::File::open(&path).unwrap();
        assert_eq!(
            sha256_open_file_verified(&file).unwrap(),
            sha256_file(&path).unwrap()
        );
    }

    #[test]
    fn a_missing_file_is_an_error() {
        let dir = private_dir();
        assert!(sha256_file_verified(&dir.path().join("absent")).is_err());
    }
}
