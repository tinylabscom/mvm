//! Locating and verifying the Firecracker binary a launch execs.
//!
//! A release ships the Firecracker named by `firecracker.lock` beside `mvmctl`,
//! in a `firecracker/` directory (and, for a package install, in
//! `../lib/mvmctl/firecracker/`). A launch execs that binary by absolute path,
//! after checking it against the lock, so what boots a guest is what the signed
//! release vouched for and not whatever `firecracker` a `PATH` happens to name.
//!
//! The file is opened once and its type, mode, owner, size and SHA-256 are all
//! read from that one handle, so a path cannot be satisfied by one file and
//! then hand back another. A shipped binary that is present but wrong is an
//! error, never a reason to fall through to the next location: a tampered file
//! must not be skipped past.
//!
//! The one way to run a different Firecracker is to name it: set
//! `MVM_FIRECRACKER_BIN` to an absolute path. That binary is the operator's own
//! and is not checked against the lock.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::host::file_memo::{FileStamp, file_stamp_of, now_ns, stamp_is_settled};
use mvm_core::arch::GuestArch;
use mvm_core::crypto::verified_digest::sha256_open_file_verified;
use mvm_core::firecracker_lock::{FirecrackerArchPin, firecracker_lock};

/// The environment variable that names a Firecracker to run instead of the
/// shipped one.
pub const OVERRIDE_ENV: &str = "MVM_FIRECRACKER_BIN";

/// The directory, and the file inside it, a release stages.
const SHIPPED_DIR: &str = "firecracker";
const SHIPPED_FILE: &str = "firecracker";

/// Where a resolved binary came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirecrackerOrigin {
    /// The binary this release ships, checked against `firecracker.lock`.
    Shipped,
    /// A binary the operator named; not checked against the lock.
    Override,
}

/// A Firecracker binary a launch may exec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFirecracker {
    /// Absolute path to exec.
    pub path: PathBuf,
    pub origin: FirecrackerOrigin,
}

/// Why no Firecracker could be resolved.
#[derive(Debug)]
pub enum ResolveError {
    /// No shipped Firecracker exists in any location.
    NotFound {
        searched: Vec<PathBuf>,
    },
    /// A binary exists and is not acceptable: wrong type, mode, owner or size.
    Refused {
        path: PathBuf,
        reason: String,
    },
    /// A shipped binary exists and is not the bytes the lock pins.
    DigestMismatch {
        path: PathBuf,
        expected: String,
        found: String,
    },
    /// `MVM_FIRECRACKER_BIN` does not name an absolute executable file.
    BadOverride {
        value: PathBuf,
        reason: &'static str,
    },
    Io {
        path: PathBuf,
        source: io::Error,
    },
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { searched } => {
                let searched: Vec<String> = searched
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect();
                write!(
                    f,
                    "no Firecracker ships with this mvmctl (looked in {}); install a release, or \
                     set {OVERRIDE_ENV} to the absolute path of your own",
                    searched.join(", ")
                )
            }
            Self::Refused { path, reason } => {
                write!(
                    f,
                    "refusing the Firecracker at {}: it {reason}",
                    path.display()
                )
            }
            Self::DigestMismatch {
                path,
                expected,
                found,
            } => write!(
                f,
                "the Firecracker at {} is {found}, but this release pins {expected}; it was \
                 changed after install, so it was not run",
                path.display()
            ),
            Self::BadOverride { value, reason } => {
                write!(f, "{OVERRIDE_ENV} is {}, which {reason}", value.display())
            }
            Self::Io { path, source } => write!(f, "reading {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for ResolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// The directories a release puts the pinned Firecracker in, relative to the
/// running executable: beside it (an archive install, where the release
/// directory holds `mvmctl` and `firecracker/`), then `../lib/mvmctl/` (a
/// package install, where `mvmctl` is in `/usr/bin`).
pub fn shipped_locations(executable: &Path) -> Vec<PathBuf> {
    let Some(dir) = executable.parent() else {
        return Vec::new();
    };
    let mut locations = vec![dir.join(SHIPPED_DIR)];
    if let Some(prefix) = dir.parent() {
        locations.push(prefix.join("lib").join("mvmctl").join(SHIPPED_DIR));
    }
    locations
}

/// Open `path` without following a final symlink, so the name cannot be
/// redirected to another file after it was looked at.
fn open_no_follow(path: &Path) -> Result<File, ResolveError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| {
            if source.raw_os_error() == Some(libc::ELOOP) {
                ResolveError::Refused {
                    path: path.to_path_buf(),
                    reason: "is a symbolic link".to_string(),
                }
            } else {
                ResolveError::Io {
                    path: path.to_path_buf(),
                    source,
                }
            }
        })
}

/// A remembered successful digest check of the shipped Firecracker, so an
/// unchanged binary is not re-hashed by every process (the in-memory digest
/// registry does not outlive one).
///
/// This is a trusted-host compatibility cache, never authorization: the pin
/// decides what may run, and the memo only lets a launch skip re-reading bytes
/// that already matched it. Like the helper probe memo it assumes trusted host
/// storage, not a writer forging the memo. File timestamps and the clock must
/// be the same clock: a network filesystem whose server clock lags more than
/// the racy margin brings the same-tick rewrite race back.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct BinaryMemo {
    memo_version: u32,
    path: PathBuf,
    stamp: FileStamp,
    sha256: String,
    /// Nanoseconds since the Unix epoch, read before the stamp and the hash.
    recorded_ns: i64,
}

const BINARY_MEMO_VERSION: u32 = 1;
const BINARY_MEMO_FILE: &str = "firecracker-binary.json";

/// Whether the memo proves `path` still holds the pinned bytes. Any doubt
/// (unreadable, unparseable, another file, another stamp, another digest, a
/// memo from the future, a stamp too recent to trust) answers no.
fn memo_accepts(
    memo_file: &Path,
    path: &Path,
    stamp: &FileStamp,
    pin: &FirecrackerArchPin,
    observed_ns: i64,
) -> bool {
    // A symlinked memo is refused rather than followed.
    let Ok(mut handle) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(memo_file)
    else {
        return false;
    };
    let mut bytes = Vec::new();
    if io::Read::read_to_end(&mut handle, &mut bytes).is_err() {
        return false;
    }
    let Ok(memo) = serde_json::from_slice::<BinaryMemo>(&bytes) else {
        return false;
    };
    memo.memo_version == BINARY_MEMO_VERSION
        && memo.path == path
        && memo.stamp == *stamp
        && memo.sha256 == pin.binary_sha256.as_str()
        && stamp_is_settled(stamp, memo.recorded_ns, observed_ns)
}

/// Remember a digest that just matched the pin. Best effort: a failed write
/// only means the next launch hashes again.
fn record_memo(
    memo_dir: &Path,
    path: &Path,
    stamp: FileStamp,
    pin: &FirecrackerArchPin,
    recorded_ns: i64,
) {
    let memo = BinaryMemo {
        memo_version: BINARY_MEMO_VERSION,
        path: path.to_path_buf(),
        stamp,
        sha256: pin.binary_sha256.as_str().to_string(),
        recorded_ns,
    };
    let Ok(bytes) = serde_json::to_vec(&memo) else {
        return;
    };
    if std::fs::create_dir_all(memo_dir).is_ok() {
        let _ =
            mvm_core::atomic_io::write_private_ephemeral(&memo_dir.join(BINARY_MEMO_FILE), &bytes);
    }
}

/// Check `path` against `pin`, reading everything from one open handle.
fn verify(
    path: &Path,
    pin: &FirecrackerArchPin,
    euid: u32,
    memo_dir: Option<&Path>,
) -> Result<(), ResolveError> {
    verify_at(path, pin, euid, memo_dir, now_ns()).map(|_hashed| ())
}

/// [`verify`] with the clock reading supplied, answering whether the bytes had
/// to be hashed. The reading is taken before the handle's stamp, so a memo
/// recorded from it never claims to be younger than the bytes it describes.
fn verify_at(
    path: &Path,
    pin: &FirecrackerArchPin,
    euid: u32,
    memo_dir: Option<&Path>,
    observed_ns: i64,
) -> Result<bool, ResolveError> {
    let refuse = |reason: String| ResolveError::Refused {
        path: path.to_path_buf(),
        reason,
    };
    let file = open_no_follow(path)?;
    let meta = file.metadata().map_err(|source| ResolveError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !meta.is_file() {
        return Err(refuse("is not a regular file".to_string()));
    }
    if meta.len() != pin.binary_size {
        return Err(refuse(format!(
            "is {} bytes, but this release pins {}",
            meta.len(),
            pin.binary_size
        )));
    }
    let mode = meta.mode();
    if mode & 0o111 == 0 {
        return Err(refuse("is not executable".to_string()));
    }
    if mode & 0o022 != 0 {
        return Err(refuse("is writable by its group or by others".to_string()));
    }
    if meta.uid() != euid && meta.uid() != 0 {
        return Err(refuse(format!(
            "is owned by uid {}, not by uid {euid} or root",
            meta.uid()
        )));
    }
    let stamp = file_stamp_of(&meta);
    if let (Some(dir), Some(stamp)) = (memo_dir, &stamp)
        && memo_accepts(&dir.join(BINARY_MEMO_FILE), path, stamp, pin, observed_ns)
    {
        return Ok(false);
    }
    let found = sha256_open_file_verified(&file).map_err(|source| ResolveError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if found != pin.binary_sha256.as_str() {
        return Err(ResolveError::DigestMismatch {
            path: path.to_path_buf(),
            expected: pin.binary_sha256.as_str().to_string(),
            found,
        });
    }
    if let (Some(dir), Some(stamp)) = (memo_dir, stamp) {
        record_memo(dir, path, stamp, pin, observed_ns);
    }
    Ok(true)
}

/// A named Firecracker must be an absolute path to an executable file.
fn check_override(path: &Path) -> Result<ResolvedFirecracker, ResolveError> {
    let bad = |reason: &'static str| ResolveError::BadOverride {
        value: path.to_path_buf(),
        reason,
    };
    if !path.is_absolute() {
        return Err(bad("is not an absolute path"));
    }
    let meta = std::fs::metadata(path).map_err(|_| bad("does not exist"))?;
    if !meta.is_file() {
        return Err(bad("is not a file"));
    }
    if meta.mode() & 0o111 == 0 {
        return Err(bad("is not executable"));
    }
    Ok(ResolvedFirecracker {
        path: path.to_path_buf(),
        origin: FirecrackerOrigin::Override,
    })
}

/// Resolve the Firecracker to exec: the named one if there is one, otherwise the
/// first shipped location that holds a binary, which must match `pin`.
pub fn resolve_with(
    locations: &[PathBuf],
    pin: &FirecrackerArchPin,
    override_bin: Option<&Path>,
    euid: u32,
    memo_dir: Option<&Path>,
) -> Result<ResolvedFirecracker, ResolveError> {
    if let Some(path) = override_bin {
        return check_override(path);
    }
    for directory in locations {
        let candidate = directory.join(SHIPPED_FILE);
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => {
                verify(&candidate, pin, euid, memo_dir)?;
                return Ok(ResolvedFirecracker {
                    path: candidate,
                    origin: FirecrackerOrigin::Shipped,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ResolveError::Io {
                    path: candidate,
                    source,
                });
            }
        }
    }
    Err(ResolveError::NotFound {
        searched: locations.to_vec(),
    })
}

/// Resolve the Firecracker this host's `mvmctl` should exec.
pub fn resolve_for_host() -> Result<ResolvedFirecracker, ResolveError> {
    let executable = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|source| ResolveError::Io {
            path: PathBuf::from("the running mvmctl"),
            source,
        })?;
    let override_bin = std::env::var_os(OVERRIDE_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let mut locations = shipped_locations(&executable);
    locations.push(super::fetch::cache_dir());
    resolve_with(
        &locations,
        firecracker_lock().pin(GuestArch::host()),
        override_bin.as_deref(),
        super::daemon::effective_user_id(),
        Some(&PathBuf::from(mvm_core::config::mvm_cache_dir()).join("firecracker-verify")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::packs::Sha256Hex;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    const BINARY: &[u8] = b"\x7fELF a stand-in for the pinned firecracker\n";

    fn pin_for(bytes: &[u8]) -> FirecrackerArchPin {
        FirecrackerArchPin {
            tarball: "unused.tgz".to_string(),
            tarball_sha256: Sha256Hex::from_bytes(b"tarball"),
            binary: "unused".to_string(),
            binary_sha256: Sha256Hex::from_bytes(bytes),
            binary_size: bytes.len() as u64,
        }
    }

    fn my_uid() -> u32 {
        crate::fc::daemon::effective_user_id()
    }

    /// A directory holding a `firecracker` file with `bytes` and mode `mode`.
    fn shipped(bytes: &[u8], mode: u32) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("firecracker");
        std::fs::write(&file, bytes).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        dir
    }

    fn locations(dirs: &[&tempfile::TempDir]) -> Vec<PathBuf> {
        dirs.iter().map(|dir| dir.path().to_path_buf()).collect()
    }

    fn resolve(
        dirs: &[&tempfile::TempDir],
        bytes: &[u8],
    ) -> Result<ResolvedFirecracker, ResolveError> {
        resolve_with(&locations(dirs), &pin_for(bytes), None, my_uid(), None)
    }

    #[test]
    fn a_shipped_binary_matching_the_pin_resolves_to_its_absolute_path() {
        let dir = shipped(BINARY, 0o755);
        let resolved = resolve(&[&dir], BINARY).unwrap();
        assert_eq!(resolved.origin, FirecrackerOrigin::Shipped);
        assert_eq!(resolved.path, dir.path().join("firecracker"));
        assert!(resolved.path.is_absolute());
    }

    #[test]
    fn the_first_location_that_holds_a_binary_wins() {
        let first = shipped(BINARY, 0o755);
        let second = shipped(BINARY, 0o755);
        let resolved = resolve(&[&first, &second], BINARY).unwrap();
        assert_eq!(resolved.path, first.path().join("firecracker"));
    }

    #[test]
    fn a_later_location_is_used_when_the_earlier_one_holds_nothing() {
        let empty = tempfile::tempdir().unwrap();
        let packaged = shipped(BINARY, 0o755);
        let resolved = resolve(&[&empty, &packaged], BINARY).unwrap();
        assert_eq!(resolved.path, packaged.path().join("firecracker"));
    }

    #[test]
    fn a_tampered_binary_is_refused_and_never_skipped_past() {
        // The same size as the pin, so only the digest can catch it.
        let mut same_size = vec![0u8; BINARY.len()];
        same_size[..4].copy_from_slice(b"\x7fELF");
        let tampered = shipped(&same_size, 0o755);
        let good = shipped(BINARY, 0o755);
        let pin = pin_for(BINARY);
        let outcome = resolve_with(&locations(&[&tampered, &good]), &pin, None, my_uid(), None);
        assert!(
            matches!(outcome, Err(ResolveError::DigestMismatch { .. })),
            "a present-but-wrong binary must stop the search, got {outcome:?}"
        );
    }

    #[test]
    fn a_binary_of_another_size_is_refused_before_it_is_hashed() {
        let dir = shipped(b"\x7fELF short", 0o755);
        assert!(matches!(
            resolve(&[&dir], BINARY),
            Err(ResolveError::Refused { .. })
        ));
    }

    #[test]
    fn a_binary_that_is_not_executable_is_refused() {
        let dir = shipped(BINARY, 0o644);
        let error = resolve(&[&dir], BINARY).unwrap_err();
        assert!(error.to_string().contains("not executable"), "{error}");
    }

    #[test]
    fn a_binary_writable_by_others_is_refused() {
        for mode in [0o775, 0o757, 0o777] {
            let dir = shipped(BINARY, mode);
            let error = resolve(&[&dir], BINARY).unwrap_err();
            assert!(error.to_string().contains("writable"), "{mode:o}: {error}");
        }
    }

    #[test]
    fn a_binary_owned_by_someone_else_is_refused() {
        let dir = shipped(BINARY, 0o755);
        let owner = std::fs::metadata(dir.path().join("firecracker"))
            .unwrap()
            .uid();
        if owner == 0 {
            return; // root owns it, and root-owned files are always accepted
        }
        let outcome = resolve_with(&locations(&[&dir]), &pin_for(BINARY), None, owner + 1, None);
        assert!(
            matches!(outcome, Err(ResolveError::Refused { .. })),
            "{outcome:?}"
        );
    }

    #[test]
    fn a_symlink_is_refused_rather_than_followed() {
        let real = shipped(BINARY, 0o755);
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            real.path().join("firecracker"),
            dir.path().join("firecracker"),
        )
        .unwrap();
        let error = resolve(&[&dir], BINARY).unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
    }

    #[test]
    fn a_directory_named_firecracker_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("firecracker")).unwrap();
        assert!(resolve(&[&dir], BINARY).is_err());
    }

    #[test]
    fn nothing_shipped_names_every_place_it_looked() {
        let empty = tempfile::tempdir().unwrap();
        let error = resolve(&[&empty], BINARY).unwrap_err();
        let text = error.to_string();
        assert!(matches!(error, ResolveError::NotFound { .. }));
        assert!(text.contains(&empty.path().display().to_string()), "{text}");
        assert!(text.contains(OVERRIDE_ENV), "{text}");
    }

    #[test]
    fn a_named_firecracker_is_used_without_checking_the_lock() {
        let dir = shipped(b"\x7fELF the operator's own build\n", 0o755);
        let named = dir.path().join("firecracker");
        let resolved = resolve_with(&[], &pin_for(BINARY), Some(&named), my_uid(), None).unwrap();
        assert_eq!(resolved.origin, FirecrackerOrigin::Override);
        assert_eq!(resolved.path, named);
    }

    #[test]
    fn a_named_firecracker_replaces_a_shipped_one() {
        let shipped_dir = shipped(BINARY, 0o755);
        let own = shipped(b"\x7fELF own\n", 0o755);
        let named = own.path().join("firecracker");
        let resolved = resolve_with(
            &locations(&[&shipped_dir]),
            &pin_for(BINARY),
            Some(&named),
            my_uid(),
            None,
        )
        .unwrap();
        assert_eq!(resolved.path, named);
    }

    #[test]
    fn a_named_firecracker_must_be_an_absolute_executable_file() {
        let dir = shipped(BINARY, 0o644);
        let not_executable = dir.path().join("firecracker");
        for (value, reason) in [
            (PathBuf::from("firecracker"), "not an absolute path"),
            (dir.path().join("missing"), "does not exist"),
            (dir.path().to_path_buf(), "not a file"),
            (not_executable, "not executable"),
        ] {
            let error =
                resolve_with(&[], &pin_for(BINARY), Some(&value), my_uid(), None).unwrap_err();
            assert!(
                matches!(error, ResolveError::BadOverride { .. })
                    && error.to_string().contains(reason),
                "{value:?}: {error}"
            );
        }
    }

    #[test]
    fn locations_are_beside_the_executable_then_the_package_prefix() {
        assert_eq!(
            shipped_locations(Path::new("/usr/bin/mvmctl")),
            vec![
                PathBuf::from("/usr/bin/firecracker"),
                PathBuf::from("/usr/lib/mvmctl/firecracker"),
            ]
        );
        assert_eq!(
            shipped_locations(Path::new("/home/u/.local/lib/mvm/1-v1.2.3/mvmctl")),
            vec![
                PathBuf::from("/home/u/.local/lib/mvm/1-v1.2.3/firecracker"),
                PathBuf::from("/home/u/.local/lib/mvm/lib/mvmctl/firecracker"),
            ]
        );
        assert!(shipped_locations(Path::new("mvmctl")).len() <= 2);
    }

    /// A verify against a memo directory at a chosen clock reading, answering
    /// whether the bytes were hashed.
    fn verify_memoed(
        dir: &tempfile::TempDir,
        memo: &tempfile::TempDir,
        bytes: &[u8],
        observed_ns: i64,
    ) -> Result<bool, ResolveError> {
        verify_at(
            &dir.path().join("firecracker"),
            &pin_for(bytes),
            my_uid(),
            Some(memo.path()),
            observed_ns,
        )
    }

    const SEC: i64 = 1_000_000_000;

    /// A memo whose clock is past the racy margin of the file's fresh
    /// timestamps, so the next check may trust it.
    fn settled_memo(dir: &tempfile::TempDir, memo: &tempfile::TempDir) -> i64 {
        let _ = std::fs::remove_file(memo.path().join(BINARY_MEMO_FILE));
        let base = now_ns();
        assert!(verify_memoed(dir, memo, BINARY, base + 3 * SEC).unwrap());
        base
    }

    /// Rewrites the binary and moves its mtime a second on, so the stamp
    /// differs even where the filesystem's timestamps are coarser than the
    /// time between two writes.
    fn rewrite(dir: &tempfile::TempDir, bytes: &[u8]) {
        let path = dir.path().join("firecracker");
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::fs::write(&path, bytes).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(before + std::time::Duration::from_secs(1))
            .unwrap();
    }

    fn memo_bytes(memo: &tempfile::TempDir) -> Vec<u8> {
        std::fs::read(memo.path().join(BINARY_MEMO_FILE)).unwrap()
    }

    fn edit_memo(memo: &tempfile::TempDir, edit: impl FnOnce(&mut serde_json::Value)) {
        let file = memo.path().join(BINARY_MEMO_FILE);
        let mut value: serde_json::Value = serde_json::from_slice(&memo_bytes(memo)).unwrap();
        edit(&mut value);
        std::fs::write(file, serde_json::to_vec(&value).unwrap()).unwrap();
    }

    #[test]
    fn a_settled_unchanged_binary_is_accepted_without_hashing() {
        let dir = shipped(BINARY, 0o755);
        let memo = tempfile::tempdir().unwrap();
        let base = settled_memo(&dir, &memo);
        assert!(!verify_memoed(&dir, &memo, BINARY, base + 10 * SEC).unwrap());
    }

    #[test]
    fn a_memo_within_the_racy_margin_of_the_file_is_not_trusted() {
        let dir = shipped(BINARY, 0o755);
        let memo = tempfile::tempdir().unwrap();
        let base = now_ns();
        assert!(verify_memoed(&dir, &memo, BINARY, base).unwrap());
        assert!(verify_memoed(&dir, &memo, BINARY, base + SEC).unwrap());
    }

    #[test]
    fn a_memo_older_than_the_file_is_not_trusted() {
        let dir = shipped(BINARY, 0o755);
        let memo = tempfile::tempdir().unwrap();
        let base = settled_memo(&dir, &memo);
        edit_memo(&memo, |value| value["recorded_ns"] = 0.into());
        assert!(verify_memoed(&dir, &memo, BINARY, base + 10 * SEC).unwrap());
    }

    #[test]
    fn a_changed_binary_is_refused_and_the_memo_is_not_renewed() {
        let dir = shipped(BINARY, 0o755);
        let memo = tempfile::tempdir().unwrap();
        let base = settled_memo(&dir, &memo);
        let before = memo_bytes(&memo);
        let mut tampered = vec![0u8; BINARY.len()];
        tampered[..4].copy_from_slice(b"\x7fELF");
        rewrite(&dir, &tampered);
        let outcome = verify_memoed(&dir, &memo, BINARY, base + 10 * SEC);
        assert!(
            matches!(outcome, Err(ResolveError::DigestMismatch { .. })),
            "{outcome:?}"
        );
        assert_eq!(memo_bytes(&memo), before);
    }

    #[test]
    fn a_memo_that_is_corrupt_future_dated_or_missing_a_field_is_hashed() {
        let dir = shipped(BINARY, 0o755);
        let memo = tempfile::tempdir().unwrap();
        let base = settled_memo(&dir, &memo);
        let observed = base + 10 * SEC;
        edit_memo(&memo, |value| value["recorded_ns"] = (observed + 1).into());
        assert!(verify_memoed(&dir, &memo, BINARY, observed).unwrap());
        // The hash renewed the memo; break it three other ways.
        let base = settled_memo(&dir, &memo);
        edit_memo(&memo, |value| {
            value.as_object_mut().unwrap().remove("recorded_ns");
        });
        assert!(verify_memoed(&dir, &memo, BINARY, base + 10 * SEC).unwrap());
        let base = settled_memo(&dir, &memo);
        edit_memo(&memo, |value| value["sha256"] = "00".into());
        assert!(verify_memoed(&dir, &memo, BINARY, base + 10 * SEC).unwrap());
        std::fs::write(memo.path().join(BINARY_MEMO_FILE), b"{not json").unwrap();
        assert!(verify_memoed(&dir, &memo, BINARY, base + 10 * SEC).unwrap());
    }

    fn current_stamp(dir: &tempfile::TempDir) -> (FileStamp, i64) {
        let meta = std::fs::metadata(dir.path().join("firecracker")).unwrap();
        let ctime = meta.ctime() * SEC + meta.ctime_nsec();
        let mtime = meta.mtime() * SEC + meta.mtime_nsec();
        (file_stamp_of(&meta).unwrap(), ctime.max(mtime))
    }

    /// Writes a memo for the file as it stands, recorded at `recorded_ns`.
    fn memo_recorded_at(dir: &tempfile::TempDir, memo: &tempfile::TempDir, recorded_ns: i64) {
        let (stamp, _) = current_stamp(dir);
        let path = dir.path().join("firecracker");
        record_memo(memo.path(), &path, stamp, &pin_for(BINARY), recorded_ns);
    }

    #[test]
    fn the_racy_margin_boundary_is_exact() {
        use crate::host::file_memo::RACY_MARGIN_NS;
        let dir = shipped(BINARY, 0o755);
        let memo = tempfile::tempdir().unwrap();
        let (_, newest) = current_stamp(&dir);
        memo_recorded_at(&dir, &memo, newest + RACY_MARGIN_NS - 1);
        let observed = newest + RACY_MARGIN_NS + 10 * SEC;
        assert!(verify_memoed(&dir, &memo, BINARY, observed).unwrap());
        memo_recorded_at(&dir, &memo, newest + RACY_MARGIN_NS);
        assert!(!verify_memoed(&dir, &memo, BINARY, observed).unwrap());
    }

    #[test]
    fn a_memo_for_another_path_or_stamp_or_version_is_hashed() {
        let dir = shipped(BINARY, 0o755);
        let memo = tempfile::tempdir().unwrap();
        let base = settled_memo(&dir, &memo);
        let observed = base + 10 * SEC;
        edit_memo(&memo, |value| {
            value["path"] = "/elsewhere/firecracker".into()
        });
        assert!(verify_memoed(&dir, &memo, BINARY, observed).unwrap());
        let base = settled_memo(&dir, &memo);
        edit_memo(&memo, |value| value["memo_version"] = 99.into());
        assert!(verify_memoed(&dir, &memo, BINARY, base + 10 * SEC).unwrap());
        // Same bytes, new timestamps: the stamp no longer matches.
        let base = settled_memo(&dir, &memo);
        rewrite(&dir, BINARY);
        assert!(verify_memoed(&dir, &memo, BINARY, base + 10 * SEC).unwrap());
    }

    #[test]
    fn without_a_usable_memo_dir_verification_still_hashes_and_succeeds() {
        let dir = shipped(BINARY, 0o755);
        let file = dir.path().join("firecracker");
        let hashed = |memo_dir: Option<&Path>| {
            verify_at(&file, &pin_for(BINARY), my_uid(), memo_dir, now_ns()).unwrap()
        };
        assert!(hashed(None));
        let blocker = tempfile::NamedTempFile::new().unwrap();
        // A regular file where the directory should be: creating it fails.
        assert!(hashed(Some(&blocker.path().join("sub"))));
        assert!(hashed(Some(&dir.path().join("missing").join("deeper"))));
    }

    #[test]
    fn a_symlinked_memo_is_refused_and_hashed() {
        let dir = shipped(BINARY, 0o755);
        let memo = tempfile::tempdir().unwrap();
        let base = settled_memo(&dir, &memo);
        let real = memo.path().join("real.json");
        let link = memo.path().join(BINARY_MEMO_FILE);
        std::fs::rename(&link, &real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(verify_memoed(&dir, &memo, BINARY, base + 10 * SEC).unwrap());
    }

    /// The launch budget is absolute, so the check has to stay cheap at the
    /// pinned binary's size. The bound is far above what hardware SHA costs and
    /// well below anything that would matter against the budget; it exists to
    /// catch an accidental order-of-magnitude regression, such as hashing twice.
    #[test]
    fn verifying_a_binary_of_the_pinned_size_is_cheap() {
        let mut bytes = vec![0xab_u8; 3_700_000];
        bytes[..4].copy_from_slice(b"\x7fELF");
        let dir = shipped(&bytes, 0o755);
        let started = Instant::now();
        let resolved = resolve(&[&dir], &bytes).unwrap();
        let elapsed = started.elapsed();
        assert_eq!(resolved.origin, FirecrackerOrigin::Shipped);
        assert!(
            elapsed < Duration::from_millis(500),
            "verifying 3.7 MB took {elapsed:?}"
        );
    }
}
