//! Handing a saved machine state to the VMM that maps it, verified.
//!
//! A restored guest's RAM is mapped copy-on-write from a file rather than
//! copied into fresh memory. A private mapping reads through to the file for
//! every page the guest has not written, so what the digest check approved has
//! to be what the mapping serves — not just at the moment of the check, but for
//! as long as the guest runs.
//!
//! Hashing the checkpoint file and then mapping it by name would not give that:
//! between the hash and the `mmap` the file could be replaced or rewritten.
//! Whether a later write to a file shows through a private mapping of it is
//! unspecified. On macOS it has not been observed to — but that is
//! undocumented kernel behaviour, and nothing here relies on it. Three steps
//! close the gap without a second copy of the RAM:
//!
//! 1. **Clone, then drop the name.** The source is opened without following a
//!    symlink and cloned (a copy-on-write filesystem clone, or a byte copy where
//!    the filesystem has none) into an owner-only directory on a local
//!    filesystem, narrowed to mode `0600`, opened read-only, and unlinked
//!    before a byte of it is hashed. A clone is a separate file, so later edits
//!    to the checkpoint do not reach it.
//! 2. **Verify the clone, not the source.** The digest is computed over the
//!    descriptor that will be mapped, after the unlink, so the bytes checked and
//!    the bytes mapped are the same bytes of the same file.
//! 3. **Pass the descriptor, not a path.** The per-VM supervisor inherits the
//!    descriptor and maps it; it never reopens anything by name, and it refuses
//!    a descriptor that still has a name or was opened for writing.
//!
//! # What this guarantees, and against whom
//!
//! The bytes a restore maps are the bytes it verified, as against **other
//! users** and against **later edits or replacement of the checkpoint**. It is
//! not a guarantee against a process running as **this** user.
//!
//! Between the clone appearing under its temporary name and the unlink, any
//! same-user process can open that name for writing and keep the descriptor.
//! The window is a few system calls with a copy-on-write clone, and the whole
//! byte copy on a filesystem that cannot clone — and a process that watches the
//! directory in a loop wins it often. Closing it would not change the boundary:
//! the per-VM supervisor runs as the user, unsandboxed, and is handed the path
//! of the host signing key it signs audit entries with, so a same-user process —
//! including a compromised supervisor of another VM — can already rewrite a
//! checkpoint before it is verified or forge the chain entry that vouches for
//! it. Same-user isolation is out of scope
//! until supervisors are sandboxed.
//!
//! # Sharing
//!
//! Each restore gets its own clone, and each clone is its own file with its own
//! page cache, so restored guests share no memory pages at all — within one
//! tenant or across tenants (pages shared across tenants leak access timing). A
//! clone shares disk blocks with its source, not memory.
//!
//! Sharing clean pages between siblings would need them all to map one file
//! kept alive for as long as any of them runs. That trades a per-restore clone
//! for a long-lived shared object whose owner, lifetime and cleanup the
//! checkpoint store does not manage today, and a single timing side channel
//! between every guest restored from it; nothing here needs it. It would rest on
//! the same same-user trust as the clone window above, not on a stronger one.
//! Separately, the checkpoint layer refuses to load one tenant's saved memory
//! for another.

use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// Leading bytes of a chunk-encrypted snapshot artifact.
///
/// Mapped as guest RAM, ciphertext would boot a guest into noise; decrypted to
/// a file first, the plaintext RAM would sit on disk and undo the point of
/// encrypting it. Neither is acceptable, so an encrypted image is refused.
const ENCRYPTED_MAGIC: &[u8; 4] = mvm_core::crypto::snapshot_encryption::MAGIC;

/// Why a saved-state file could not be handed to a restore.
#[derive(Debug)]
pub enum RestoreImageError {
    /// An I/O step failed.
    Io {
        step: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    /// The source is not a regular file (a symlink, directory or device).
    NotRegular(PathBuf),
    /// The directory the clone is created in could be written by someone else.
    UntrustedDirectory(PathBuf),
    /// The directory the clone is created in is not on a local filesystem, so
    /// the file's bytes are served by another machine that can change them.
    NotLocal(PathBuf),
    /// The file carries encrypted content, which cannot be mapped as RAM.
    Encrypted(PathBuf),
    /// The cloned bytes do not match the digest recorded for them.
    DigestMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    /// An inherited descriptor was not the unlinked, read-only private file
    /// expected.
    NotPrivate(RawFd),
}

impl fmt::Display for RestoreImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { step, path, source } => {
                write!(f, "{step} {}: {source}", path.display())
            }
            Self::NotRegular(path) => write!(
                f,
                "saved machine state {} is not a regular file; refusing to follow it",
                path.display()
            ),
            Self::UntrustedDirectory(path) => write!(
                f,
                "restore directory {} is not private to this user: it must be owned by this \
                 user, carry no group or other permissions, and have no ACL granting access",
                path.display()
            ),
            Self::NotLocal(path) => write!(
                f,
                "restore directory {} is not on a local filesystem; a restore maps its saved \
                 memory only from local storage",
                path.display()
            ),
            Self::Encrypted(path) => write!(
                f,
                "saved machine state {} is encrypted; an encrypted RAM image cannot be \
                 mapped, and decrypting it to disk would defeat the encryption",
                path.display()
            ),
            Self::DigestMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "saved machine state {} failed integrity (sha256): expected {expected}, got {actual}",
                path.display()
            ),
            Self::NotPrivate(fd) => write!(
                f,
                "inherited restore descriptor {fd} is not an unlinked, read-only regular file"
            ),
        }
    }
}

impl std::error::Error for RestoreImageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// How the private copy was produced. Reported so a slow restore can be told
/// apart from a fast one without timing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateCopy {
    /// A copy-on-write filesystem clone: constant time, no bytes written.
    Cloned,
    /// A byte copy, on a filesystem that cannot clone. It writes the whole
    /// saved image — guest RAM included — to disk again on every restore, and
    /// the copy carries its temporary name for the whole of that write, so the
    /// same-user window described in the module docs lasts as long as the copy.
    Copied,
}

/// A verified, unlinked, read-only private copy of one saved-state file.
#[derive(Debug)]
pub struct VerifiedRestoreFile {
    file: File,
    len: u64,
    copy: PrivateCopy,
}

impl VerifiedRestoreFile {
    /// Clone `source` into `private_dir`, verify the clone against
    /// `expected_sha256`, and return it with no name left on disk.
    pub fn prepare(
        source: &Path,
        private_dir: &Path,
        expected_sha256: &str,
    ) -> Result<Self, RestoreImageError> {
        let src = open_regular_nofollow(source)?;
        let dir = open_trusted_dir(private_dir)?;
        let (file, copy) = private_unlinked_copy(&src, source, &dir, private_dir)?;
        let len = file
            .metadata()
            .map_err(|source_err| io_err("stat private copy of", source, source_err))?
            .len();
        refuse_encrypted(&file, source)?;
        let actual = sha256_of(&file, source)?;
        if !actual.eq_ignore_ascii_case(expected_sha256) {
            return Err(RestoreImageError::DigestMismatch {
                path: source.to_path_buf(),
                expected: expected_sha256.to_ascii_lowercase(),
                actual,
            });
        }
        Ok(Self { file, len, copy })
    }

    /// The verified private copy.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Take the verified private copy.
    pub fn into_file(self) -> File {
        self.file
    }

    /// Length of the verified bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the verified file is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How the private copy was produced.
    pub fn copy(&self) -> PrivateCopy {
        self.copy
    }
}

/// Let `cmd`'s child inherit `fds` under the same numbers.
///
/// Every descriptor this process opens is close-on-exec, which is what keeps a
/// restore image from leaking into unrelated spawns. The flag is cleared only in
/// the forked child, immediately before `exec`, so no other process started from
/// this one — concurrently or later — ever holds these descriptors. The child
/// sets the flag again when it adopts them ([`adopt_inherited`]); anything it
/// spawns before that point inherits read-only handles, which can read the
/// verified bytes but never change them.
pub fn inherit_descriptors(cmd: &mut Command, fds: Vec<RawFd>) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure runs in the forked child between `fork` and `exec`,
    // where only async-signal-safe calls are allowed. It calls `fcntl` alone,
    // which is async-signal-safe, and reads a `Vec` that was allocated before
    // the fork and is not mutated or freed inside the closure.
    unsafe {
        cmd.pre_exec(move || {
            for fd in &fds {
                if libc::fcntl(*fd, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

/// Take ownership of a restore descriptor inherited from the launching process.
///
/// Refuses anything that is not an open, unlinked, read-only regular file
/// above the standard streams, so a stale or mistyped descriptor number cannot
/// map whatever happens to occupy that slot, and the supervisor never holds a
/// handle that could write the bytes it maps.
pub fn adopt_inherited(fd: RawFd) -> Result<File, RestoreImageError> {
    if fd <= libc::STDERR_FILENO {
        return Err(RestoreImageError::NotPrivate(fd));
    }
    // SAFETY: `stat` is plain old data and `fstat` fully initializes it on
    // success; on failure the value is never read.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fstat` only reads the descriptor number and writes into `st`,
    // which is a valid exclusive out-pointer for the duration of the call.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(RestoreImageError::NotPrivate(fd));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG || st.st_nlink != 0 {
        return Err(RestoreImageError::NotPrivate(fd));
    }
    // SAFETY: `fcntl(F_GETFL)` on a descriptor fstat just confirmed is open.
    let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if status == -1 || (status & libc::O_ACCMODE) != libc::O_RDONLY {
        return Err(RestoreImageError::NotPrivate(fd));
    }
    // Close-on-exec again, so nothing this process spawns inherits it in turn.
    // SAFETY: `fcntl` on a descriptor fstat just confirmed is open.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        return Err(RestoreImageError::NotPrivate(fd));
    }
    // SAFETY: the descriptor is open (fstat succeeded) and was inherited from
    // the launching process for this purpose alone; nothing else in this
    // process opened it, so the returned `File` becomes its only owner.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn io_err(step: &'static str, path: &Path, source: io::Error) -> RestoreImageError {
    RestoreImageError::Io {
        step,
        path: path.to_path_buf(),
        source,
    }
}

fn open_regular_nofollow(path: &Path) -> Result<File, RestoreImageError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                RestoreImageError::NotRegular(path.to_path_buf())
            } else {
                io_err("open", path, e)
            }
        })?;
    let meta = file.metadata().map_err(|e| io_err("stat", path, e))?;
    if !meta.file_type().is_file() {
        return Err(RestoreImageError::NotRegular(path.to_path_buf()));
    }
    Ok(file)
}

fn open_trusted_dir(path: &Path) -> Result<File, RestoreImageError> {
    open_trusted_dir_with(path, &host_dir_facts)
}

/// What the host reports about a restore directory beyond its owner and mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirFacts {
    /// The directory is on a filesystem this host serves itself.
    local: bool,
    /// An access-control list on the directory grants some access, on top of
    /// what the mode bits say.
    acl_grants_access: bool,
}

/// [`open_trusted_dir`] with the host probe injected, so each refusal is
/// testable on any machine.
///
/// The directory must be private in every sense that lets another user reach
/// a file inside it: owned by this user, no group or other permission bits at
/// all (not even search, which is enough to open a file by name), no ACL entry
/// that grants access, and on a local filesystem. A clone is created in it
/// under a temporary name, so anyone who can reach that name can open it.
fn open_trusted_dir_with(
    path: &Path,
    probe: &dyn Fn(&File) -> io::Result<DirFacts>,
) -> Result<File, RestoreImageError> {
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(|e| io_err("open directory", path, e))?;
    let meta = dir
        .metadata()
        .map_err(|e| io_err("stat directory", path, e))?;
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid || meta.mode() & 0o077 != 0 {
        return Err(RestoreImageError::UntrustedDirectory(path.to_path_buf()));
    }
    let facts = probe(&dir).map_err(|e| io_err("inspect directory", path, e))?;
    if facts.acl_grants_access {
        return Err(RestoreImageError::UntrustedDirectory(path.to_path_buf()));
    }
    if !facts.local {
        return Err(RestoreImageError::NotLocal(path.to_path_buf()));
    }
    Ok(dir)
}

/// The host's answer for [`DirFacts`].
///
/// On a network filesystem the server can change a file's bytes after they
/// were hashed, and a private mapping may read them back for any page the
/// guest has not written, so neither the clone nor its digest would mean much.
#[cfg(target_os = "macos")]
fn host_dir_facts(dir: &File) -> io::Result<DirFacts> {
    // SAFETY: `statfs` is plain old data, fully initialised by a successful
    // `fstatfs`, and not read on failure.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `dir` is an open descriptor and `st` a valid out-pointer.
    if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(DirFacts {
        local: st.f_flags & libc::MNT_LOCAL as u32 != 0,
        acl_grants_access: macos_acl::grants_access(dir)?,
    })
}

/// HVF restores run only on macOS; this branch exists so the module's checks
/// are exercised on Linux too, and it fails closed. The filesystem type must
/// be one of a short list of local filesystems — anything else, including
/// every network and cluster filesystem, is refused — and any POSIX access
/// ACL on the directory counts as granting access.
#[cfg(not(target_os = "macos"))]
fn host_dir_facts(dir: &File) -> io::Result<DirFacts> {
    // SAFETY: `statfs` is plain old data, fully initialised by a successful
    // `fstatfs`, and not read on failure.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `dir` is an open descriptor and `st` a valid out-pointer.
    if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // `f_type` is a signed long on glibc and unsigned on musl; every magic
    // number in the list is positive either way.
    let local = linux_fs_is_local(st.f_type as u64);
    const ACL_XATTR: &[u8] = b"system.posix_acl_access\0";
    // SAFETY: `dir` is an open descriptor, the name is NUL-terminated, and a
    // zero-sized query writes nothing.
    let size = unsafe {
        libc::fgetxattr(
            dir.as_raw_fd(),
            ACL_XATTR.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    let acl_grants_access = if size >= 0 {
        true
    } else {
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ENODATA) | Some(libc::ENOTSUP) => false,
            _ => return Err(error),
        }
    };
    Ok(DirFacts {
        local,
        acl_grants_access,
    })
}

/// Whether a Linux `statfs` magic number names a filesystem this host serves
/// itself. An allowlist, so an unrecognised filesystem is treated as remote.
#[cfg(any(test, not(target_os = "macos")))]
fn linux_fs_is_local(magic: u64) -> bool {
    const LOCAL: &[u64] = &[
        0xef53,      // ext2/3/4
        0x5846_5342, // XFS
        0x9123_683e, // Btrfs
        0x0102_1994, // tmpfs
        0x794c_7630, // overlayfs
        0xf2f5_2010, // F2FS
        0x2fc1_2fc1, // ZFS
    ];
    LOCAL.contains(&magic)
}

/// Extended ACLs on macOS, through the platform's `acl(3)` API, which the
/// `libc` crate does not bind.
#[cfg(target_os = "macos")]
mod macos_acl {
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;
    const ACL_NEXT_ENTRY: libc::c_int = -1;
    const ACL_EXTENDED_DENY: libc::c_int = 2;

    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
        fn acl_get_entry(
            acl: *mut c_void,
            entry_id: libc::c_int,
            entry: *mut *mut c_void,
        ) -> libc::c_int;
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut libc::c_int) -> libc::c_int;
        fn acl_free(obj: *mut c_void) -> libc::c_int;
    }

    /// Whether `file` carries an ACL with any entry other than a deny.
    ///
    /// A deny entry can only take access away, so an ACL made only of those
    /// (the kind macOS puts on a home directory) is harmless; any other entry
    /// may grant access the mode bits do not show.
    pub(super) fn grants_access(file: &File) -> io::Result<bool> {
        // SAFETY: `file` is an open descriptor; a null result means no ACL
        // (errno ENOENT) or a failure.
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOENT) => Ok(false),
                _ => Err(error),
            };
        }
        let mut grants = false;
        let mut which = ACL_FIRST_ENTRY;
        loop {
            let mut entry: *mut c_void = std::ptr::null_mut();
            // SAFETY: `acl` is a live ACL from `acl_get_fd_np` and `entry` a
            // valid out-pointer.
            if unsafe { acl_get_entry(acl, which, &mut entry) } != 0 {
                break;
            }
            which = ACL_NEXT_ENTRY;
            let mut tag: libc::c_int = 0;
            // SAFETY: `entry` was just returned for this live ACL, and `tag`
            // is a valid out-pointer.
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 || tag != ACL_EXTENDED_DENY {
                grants = true;
                break;
            }
        }
        // SAFETY: `acl` came from `acl_get_fd_np` and is freed exactly once.
        unsafe { acl_free(acl) };
        Ok(grants)
    }
}

/// A name no concurrent restore in this or any other process will pick.
fn private_name() -> io::Result<CString> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let name = format!(
        ".restore-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn private_unlinked_copy(
    src: &File,
    source: &Path,
    dir: &File,
    dir_path: &Path,
) -> Result<(File, PrivateCopy), RestoreImageError> {
    private_unlinked_copy_with(src, source, dir, dir_path, &openat_readonly)
}

/// [`private_unlinked_copy`] with the read-only open injected, so the path
/// where the copy exists but cannot be opened is testable.
fn private_unlinked_copy_with(
    src: &File,
    source: &Path,
    dir: &File,
    dir_path: &Path,
    open: &dyn Fn(&File, &CString) -> io::Result<File>,
) -> Result<(File, PrivateCopy), RestoreImageError> {
    let name = private_name().map_err(|e| io_err("name private copy in", dir_path, e))?;
    let copy = match clone_into(src, dir, &name) {
        Ok(()) => PrivateCopy::Cloned,
        Err(e) if clone_unsupported(&e) => {
            copy_into(src, source, dir, &name, dir_path)?;
            PrivateCopy::Copied
        }
        Err(e) => return Err(io_err("clone", source, e)),
    };
    // From here the copy has a name. The guard removes it on every path out
    // of this function, and a removal that fails is reported, not ignored.
    let named = NamedCopy { dir, name: &name };
    // A clone keeps its source's mode. Narrow it before anything else, so
    // even a source left readable or writable by others yields a copy only
    // this user can open; the directory being owner-only already keeps other
    // users from reaching the name.
    if let Err(e) = restrict_to_owner(dir, &name) {
        return Err(named.remove_after(io_err("restrict private copy in", dir_path, e), dir_path));
    }
    let opened = open(dir, &name);
    named
        .unlink()
        .map_err(|e| io_err("unlink private copy in", dir_path, e))?;
    let file = opened.map_err(|e| io_err("open private copy in", dir_path, e))?;
    Ok((file, copy))
}

/// Set `name` in `dir` to mode `0600` without following a symlink.
fn restrict_to_owner(dir: &File, name: &CString) -> io::Result<()> {
    // SAFETY: `dir` is an open directory descriptor and `name` a
    // NUL-terminated single component that lives across the call.
    let rc = unsafe {
        libc::fchmodat(
            dir.as_raw_fd(),
            name.as_ptr(),
            0o600,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// A private copy that still has its temporary name.
///
/// [`NamedCopy::unlink`] removes the name and returns any failure to remove
/// it; dropping the guard without calling it removes the name best-effort.
/// Either way no path out of [`private_unlinked_copy`] leaves a named copy
/// behind silently: a name that could not be removed is an error the caller
/// sees, naming the directory it is in.
struct NamedCopy<'a> {
    dir: &'a File,
    name: &'a CString,
}

impl NamedCopy<'_> {
    /// Remove the name, reporting failure. A failed removal is tried once
    /// more when the guard drops.
    fn unlink(self) -> io::Result<()> {
        let result = unlink_name(self.dir, self.name);
        if result.is_ok() {
            std::mem::forget(self);
        }
        result
    }

    /// Remove the name after `error` ended the copy, and report the removal
    /// failing too rather than dropping it.
    fn remove_after(self, error: RestoreImageError, dir_path: &Path) -> RestoreImageError {
        match self.unlink() {
            Ok(()) => error,
            Err(unlink) => RestoreImageError::Io {
                step: "unlink private copy (after an earlier failure) in",
                path: dir_path.to_path_buf(),
                source: io::Error::new(unlink.kind(), format!("{unlink}; earlier: {error}")),
            },
        }
    }
}

impl Drop for NamedCopy<'_> {
    fn drop(&mut self) {
        let _ = unlink_name(self.dir, self.name);
    }
}

/// Remove `name` from `dir`, retrying an interrupted call.
fn unlink_name(dir: &File, name: &CString) -> io::Result<()> {
    loop {
        // SAFETY: `dir` is an open directory descriptor and `name` a
        // NUL-terminated single path component that lives across the call.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(target_os = "macos")]
fn clone_into(src: &File, dir: &File, name: &CString) -> io::Result<()> {
    // SAFETY: both descriptors are open for the duration of the call and `name`
    // is a NUL-terminated single component. Flags 0: the source is a descriptor,
    // so there is no path to follow.
    let rc = unsafe { libc::fclonefileat(src.as_raw_fd(), dir.as_raw_fd(), name.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "macos"))]
fn clone_into(_src: &File, _dir: &File, _name: &CString) -> io::Result<()> {
    Err(io::Error::from_raw_os_error(libc::ENOTSUP))
}

fn clone_unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENOTSUP) | Some(libc::EXDEV) | Some(libc::EINVAL)
    )
}

fn copy_into(
    src: &File,
    source: &Path,
    dir: &File,
    name: &CString,
    dir_path: &Path,
) -> Result<(), RestoreImageError> {
    // SAFETY: `dir` is an open directory descriptor, `name` a NUL-terminated
    // single component; `O_EXCL | O_NOFOLLOW` refuses anything already there.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io_err(
            "create private copy in",
            dir_path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: `openat` just returned this descriptor and nothing else owns it.
    let mut dst = unsafe { File::from_raw_fd(fd) };
    let mut reader = src;
    let copied = io::copy(&mut reader, &mut dst).map_err(|e| io_err("copy", source, e));
    if copied.is_err() {
        let _ = unlink_name(dir, name);
    }
    copied.map(|_| ())
}

fn openat_readonly(dir: &File, name: &CString) -> io::Result<File> {
    // SAFETY: `dir` is an open directory descriptor and `name` a NUL-terminated
    // single component that outlives the call.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` just returned this descriptor and nothing else owns it.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn refuse_encrypted(file: &File, source: &Path) -> Result<(), RestoreImageError> {
    let mut magic = [0_u8; 4];
    match file.read_exact_at(&mut magic, 0) {
        Ok(()) if &magic == ENCRYPTED_MAGIC => {
            Err(RestoreImageError::Encrypted(source.to_path_buf()))
        }
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        Err(e) => Err(io_err("read", source, e)),
    }
}

fn sha256_of(file: &File, source: &Path) -> Result<String, RestoreImageError> {
    struct Positional<'a> {
        file: &'a File,
        offset: u64,
    }
    impl Read for Positional<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.file.read_at(buf, self.offset)?;
            self.offset += n as u64;
            Ok(n)
        }
    }
    mvm_core::crypto::image_verify::sha256_reader(Positional { file, offset: 0 })
        .map_err(|e| io_err("hash", source, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn sha256_hex(bytes: &[u8]) -> String {
        mvm_core::crypto::image_verify::sha256_reader(bytes).unwrap()
    }

    /// A private directory and a saved-state file inside a second directory,
    /// the shape a restore sees: the checkpoint copy in the state dir, the
    /// clone created beside it.
    fn fixture(bytes: &[u8]) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("state");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = private.join("memory.bin");
        std::fs::write(&source, bytes).unwrap();
        (root, private, source)
    }

    fn read_all(file: &File) -> Vec<u8> {
        let mut out = vec![0_u8; file.metadata().unwrap().len() as usize];
        file.read_exact_at(&mut out, 0).unwrap();
        out
    }

    fn leftover_names(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".restore-"))
            .collect()
    }

    #[test]
    fn a_verified_copy_carries_the_source_bytes_and_leaves_no_name_behind() {
        let bytes = b"saved guest memory".repeat(1000);
        let (_root, private, source) = fixture(&bytes);

        let verified =
            VerifiedRestoreFile::prepare(&source, &private, &sha256_hex(&bytes)).unwrap();

        assert_eq!(read_all(verified.file()), bytes);
        assert_eq!(verified.len(), bytes.len() as u64);
        assert_eq!(verified.file().metadata().unwrap().nlink(), 0, "unlinked");
        assert!(leftover_names(&private).is_empty());
    }

    /// The property the whole module exists for: once verified, the bytes a
    /// restore maps do not change when the checkpoint they came from is edited
    /// or replaced.
    #[test]
    fn editing_the_source_after_preparation_does_not_change_the_verified_copy() {
        let bytes = vec![0x5a_u8; 64 * 1024];
        let (_root, private, source) = fixture(&bytes);
        let verified =
            VerifiedRestoreFile::prepare(&source, &private, &sha256_hex(&bytes)).unwrap();

        std::fs::OpenOptions::new()
            .write(true)
            .open(&source)
            .unwrap()
            .write_all_at(b"tampered", 0)
            .unwrap();
        std::fs::write(&source, b"replaced").unwrap();

        assert_eq!(read_all(verified.file()), bytes);
    }

    #[test]
    fn a_digest_mismatch_is_refused_and_leaves_no_copy() {
        let (_root, private, source) = fixture(b"saved guest memory");
        let error = VerifiedRestoreFile::prepare(&source, &private, &sha256_hex(b"something else"))
            .unwrap_err();
        assert!(
            matches!(error, RestoreImageError::DigestMismatch { .. }),
            "{error}"
        );
        assert!(leftover_names(&private).is_empty());
    }

    #[test]
    fn a_symlinked_source_is_refused_rather_than_followed() {
        let (root, private, _source) = fixture(b"saved guest memory");
        let elsewhere = root.path().join("elsewhere.bin");
        std::fs::write(&elsewhere, b"saved guest memory").unwrap();
        let link = private.join("linked.bin");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();

        let error =
            VerifiedRestoreFile::prepare(&link, &private, &sha256_hex(b"saved guest memory"))
                .unwrap_err();
        assert!(matches!(error, RestoreImageError::NotRegular(_)), "{error}");
    }

    /// The restore directory's filesystem is checked; the temporary directory
    /// tests run in is local, and the refusal names the directory.
    #[test]
    fn the_restore_directory_must_be_on_a_local_filesystem() {
        let (_root, private, _source) = fixture(b"saved guest memory");
        assert!(
            open_trusted_dir(&private).is_ok(),
            "a local tempdir is accepted"
        );
        let remote = |_: &File| {
            Ok(DirFacts {
                local: false,
                acl_grants_access: false,
            })
        };
        let error = open_trusted_dir_with(&private, &remote).unwrap_err();
        assert!(matches!(error, RestoreImageError::NotLocal(_)), "{error}");
        let refusal = error.to_string();
        assert!(refusal.contains("not on a local filesystem"), "{refusal}");
        assert!(refusal.contains(&private.display().to_string()));
    }

    /// An ACL that grants access is refused even when the mode bits are
    /// owner-only, because the ACL is what another user would open through.
    #[test]
    fn a_directory_whose_acl_grants_access_is_refused() {
        let (_root, private, _source) = fixture(b"saved guest memory");
        let shared = |_: &File| {
            Ok(DirFacts {
                local: true,
                acl_grants_access: true,
            })
        };
        let error = open_trusted_dir_with(&private, &shared).unwrap_err();
        assert!(
            matches!(error, RestoreImageError::UntrustedDirectory(_)),
            "{error}"
        );
    }

    /// The real ACL probe: an allow entry is refused, a deny-only ACL (the
    /// kind macOS puts on home directories) is accepted.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_host_acl_probe_refuses_an_allow_entry_and_accepts_deny_only() {
        let (_root, private, _source) = fixture(b"saved guest memory");
        let chmod = |args: &[&str]| {
            let status = Command::new("/bin/chmod")
                .args(args)
                .arg(&private)
                .status()
                .unwrap();
            assert!(status.success(), "chmod {args:?}");
        };

        chmod(&["+a", "everyone deny delete"]);
        assert!(
            open_trusted_dir(&private).is_ok(),
            "deny-only ACL grants nothing"
        );

        chmod(&["+a", "everyone allow read,write,execute"]);
        let error = open_trusted_dir(&private).unwrap_err();
        assert!(
            matches!(error, RestoreImageError::UntrustedDirectory(_)),
            "{error}"
        );
        chmod(&["-N"]);
        assert!(open_trusted_dir(&private).is_ok());
    }

    #[test]
    fn only_known_local_linux_filesystems_count_as_local() {
        assert!(linux_fs_is_local(0xef53), "ext4");
        assert!(linux_fs_is_local(0x0102_1994), "tmpfs");
        for remote in [
            0x6969_u64,  // NFS
            0xff53_4d42, // CIFS
            0x00c3_6400, // Ceph
            0x5346_414f, // AFS
            0x0bd0_0bd0, // Lustre
            0x0116_1970, // GFS2
            0x7461_636f, // OCFS2
            0x7375_6245, // Coda
            0x564c,      // NCP
            0x6573_5546, // FUSE
        ] {
            assert!(!linux_fs_is_local(remote), "{remote:#x} is refused");
        }
    }

    /// A source left open to everyone still yields a copy only this user can
    /// open: the clone keeps its source's mode until it is narrowed.
    #[test]
    fn a_world_writable_source_still_yields_an_owner_only_copy() {
        let bytes = b"saved guest memory".to_vec();
        let (_root, private, source) = fixture(&bytes);
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o666)).unwrap();
        let verified =
            VerifiedRestoreFile::prepare(&source, &private, &sha256_hex(&bytes)).unwrap();
        assert_eq!(verified.file().metadata().unwrap().mode() & 0o777, 0o600);
    }

    /// The copy exists but cannot be opened: the error is the open's, and the
    /// name is gone.
    #[test]
    fn a_copy_that_cannot_be_opened_is_refused_and_leaves_no_name() {
        let (_root, private, source) = fixture(b"saved guest memory");
        let src = open_regular_nofollow(&source).unwrap();
        let dir = open_trusted_dir(&private).unwrap();
        let fail = |_: &File, _: &CString| -> io::Result<File> {
            Err(io::Error::from_raw_os_error(libc::EACCES))
        };
        let error = private_unlinked_copy_with(&src, &source, &dir, &private, &fail).unwrap_err();
        assert!(error.to_string().contains("open private copy"), "{error}");
        assert!(leftover_names(&private).is_empty());
    }

    /// A name that cannot be removed is reported, not swallowed.
    #[test]
    fn a_copy_whose_name_cannot_be_removed_is_reported() {
        let (_root, private, source) = fixture(b"saved guest memory");
        let src = open_regular_nofollow(&source).unwrap();
        let dir = open_trusted_dir(&private).unwrap();
        // Opens the copy and then removes its name behind the guard's back,
        // so the guard's own removal fails.
        let open_then_unlink = |dir: &File, name: &CString| -> io::Result<File> {
            let file = openat_readonly(dir, name)?;
            unlink_name(dir, name)?;
            Ok(file)
        };
        let error = private_unlinked_copy_with(&src, &source, &dir, &private, &open_then_unlink)
            .unwrap_err();
        assert!(error.to_string().contains("unlink private copy"), "{error}");
    }

    /// A copy that still has its temporary name loses it on every way out,
    /// not only the successful one.
    #[test]
    fn a_named_copy_is_removed_when_its_guard_is_dropped() {
        let (_root, private, source) = fixture(b"saved guest memory");
        let dir = open_trusted_dir(&private).unwrap();
        let name = private_name().unwrap();
        let src = open_regular_nofollow(&source).unwrap();
        copy_into(&src, &source, &dir, &name, &private).unwrap();
        assert_eq!(leftover_names(&private).len(), 1);

        drop(NamedCopy {
            dir: &dir,
            name: &name,
        });
        assert!(
            leftover_names(&private).is_empty(),
            "the name did not survive"
        );

        copy_into(&src, &source, &dir, &name, &private).unwrap();
        NamedCopy {
            dir: &dir,
            name: &name,
        }
        .unlink()
        .unwrap();
        assert!(leftover_names(&private).is_empty());
        let again = NamedCopy {
            dir: &dir,
            name: &name,
        }
        .unlink()
        .unwrap_err();
        assert_eq!(
            again.kind(),
            io::ErrorKind::NotFound,
            "a failed unlink is reported"
        );
    }

    /// Search permission alone is enough to open a file by name, so a
    /// directory others can only list and enter is refused too.
    #[test]
    fn a_directory_others_can_enter_is_refused() {
        let (_root, private, source) = fixture(b"saved guest memory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error =
            VerifiedRestoreFile::prepare(&source, &private, &sha256_hex(b"saved guest memory"))
                .unwrap_err();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            matches!(error, RestoreImageError::UntrustedDirectory(_)),
            "{error}"
        );
        assert!(leftover_names(&private).is_empty());
    }

    #[test]
    fn a_directory_others_can_write_is_refused() {
        let (_root, private, source) = fixture(b"saved guest memory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o777)).unwrap();
        let error =
            VerifiedRestoreFile::prepare(&source, &private, &sha256_hex(b"saved guest memory"))
                .unwrap_err();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            matches!(error, RestoreImageError::UntrustedDirectory(_)),
            "{error}"
        );
    }

    /// An encrypted image is refused by name, even when the recorded digest was
    /// taken over the ciphertext and would match: mapping ciphertext as RAM
    /// would boot noise, and decrypting to a file would put plaintext guest
    /// memory on disk.
    #[test]
    fn an_encrypted_image_is_refused_even_when_its_digest_matches() {
        let (_root, private, source) = fixture(&vec![0x11_u8; 4096]);
        mvm_core::crypto::snapshot_encryption::encrypt_file_in_place(&source, &[7_u8; 32]).unwrap();
        let ciphertext = std::fs::read(&source).unwrap();

        let error =
            VerifiedRestoreFile::prepare(&source, &private, &sha256_hex(&ciphertext)).unwrap_err();
        assert!(matches!(error, RestoreImageError::Encrypted(_)), "{error}");
        assert!(error.to_string().contains("decrypting it to disk"));
        assert!(leftover_names(&private).is_empty());
    }

    #[test]
    fn the_byte_copy_fallback_gives_the_same_guarantees() {
        let bytes = b"saved guest memory".repeat(100);
        let (_root, private, source) = fixture(&bytes);
        let src = open_regular_nofollow(&source).unwrap();
        let dir = open_trusted_dir(&private).unwrap();
        let name = private_name().unwrap();

        copy_into(&src, &source, &dir, &name, &private).unwrap();
        let copy = openat_readonly(&dir, &name).unwrap();
        // SAFETY: test-only; `dir` and `name` are valid for the call.
        assert_eq!(
            unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) },
            0
        );
        std::fs::write(&source, b"replaced").unwrap();

        assert_eq!(read_all(&copy), bytes);
        assert_eq!(copy.metadata().unwrap().nlink(), 0);
    }

    #[test]
    fn adopting_refuses_standard_streams_and_named_files() {
        assert!(matches!(
            adopt_inherited(libc::STDIN_FILENO),
            Err(RestoreImageError::NotPrivate(_))
        ));
        let dir = tempfile::tempdir().unwrap();
        let named = File::create(dir.path().join("named")).unwrap();
        let fd = named.as_raw_fd();
        assert!(matches!(
            adopt_inherited(fd),
            Err(RestoreImageError::NotPrivate(_))
        ));
    }

    /// A descriptor that could write the bytes it maps is refused even when it
    /// has no name: the supervisor must never hold a writer of its own RAM
    /// image.
    #[test]
    fn adopting_refuses_a_descriptor_open_for_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("writable");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        // SAFETY: `dup` of a descriptor this test owns.
        let fd = unsafe { libc::dup(file.as_raw_fd()) };
        assert!(matches!(
            adopt_inherited(fd),
            Err(RestoreImageError::NotPrivate(_))
        ));
        // SAFETY: the refused descriptor is still this test's to close.
        unsafe { libc::close(fd) };
    }

    #[test]
    fn a_verified_copy_is_held_read_only() {
        let bytes = b"saved guest memory".to_vec();
        let (_root, private, source) = fixture(&bytes);
        let verified =
            VerifiedRestoreFile::prepare(&source, &private, &sha256_hex(&bytes)).unwrap();
        // SAFETY: `fcntl(F_GETFL)` on a descriptor `verified` owns.
        let status = unsafe { libc::fcntl(verified.file().as_raw_fd(), libc::F_GETFL) };
        assert_eq!(status & libc::O_ACCMODE, libc::O_RDONLY);
        // The temporary directory is on APFS, which clones in constant time.
        #[cfg(target_os = "macos")]
        assert_eq!(verified.copy(), PrivateCopy::Cloned);
    }

    #[test]
    fn adopting_takes_an_unlinked_copy_and_marks_it_close_on_exec() {
        let bytes = b"saved guest memory".to_vec();
        let (_root, private, source) = fixture(&bytes);
        let verified =
            VerifiedRestoreFile::prepare(&source, &private, &sha256_hex(&bytes)).unwrap();
        // Hand the descriptor over the way the supervisor receives it.
        // SAFETY: `dup` of a descriptor this test owns.
        let fd = unsafe { libc::dup(verified.file().as_raw_fd()) };
        assert!(fd > libc::STDERR_FILENO);

        let adopted = adopt_inherited(fd).unwrap();
        assert_eq!(read_all(&adopted), bytes);
        // SAFETY: `fcntl` on a descriptor `adopted` owns.
        let flags = unsafe { libc::fcntl(adopted.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
    }

    #[test]
    fn inherited_descriptors_reach_the_child_and_no_one_else() {
        let bytes = b"saved guest memory".to_vec();
        let (_root, private, source) = fixture(&bytes);
        let verified =
            VerifiedRestoreFile::prepare(&source, &private, &sha256_hex(&bytes)).unwrap();
        let fd = verified.file().as_raw_fd();
        let probe = format!("test -e /dev/fd/{fd}");

        let mut with = Command::new("/bin/sh");
        with.args(["-c", &probe]);
        inherit_descriptors(&mut with, vec![fd]);
        assert!(with.status().unwrap().success(), "the child inherits it");

        let without = Command::new("/bin/sh")
            .args(["-c", &probe])
            .status()
            .unwrap();
        assert!(!without.success(), "an unrelated spawn does not");
    }
}
