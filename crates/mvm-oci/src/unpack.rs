//! Layer-to-tree unpacker.
//!
//! Materializes an OCI layer tarball (already digest-verified + cached
//! by [`crate::layer`]) into a directory tree on the host filesystem,
//! with explicit per-entry safety policies that close the
//! CVE-2019-14271-class category of attacks (path traversal, symlink
//! escape, hardlink-to-host, device-node planting, setuid surprise,
//! xattr-based privilege carry).
//!
//! ## Scope
//!
//! The unpacker handles four tar entry kinds and two OCI-specific
//! filename markers that ride inside regular-file tar entries:
//!
//! - **Regular files** — bytes streamed to a freshly-opened file at
//!   `output_root/<entry-path>`. Mode is preserved from the tar
//!   header, with setuid/setgid bits governed by
//!   [`UnpackOptions::setid_policy`]. Sticky bits are still stripped;
//!   they are not needed for rootfs executables and keeping the
//!   preserved high-bit surface narrow makes audit review simpler.
//! - **Directories** — created with `0o755`, regardless of the tar
//!   header's mode bits. A non-canonical mode is recorded in the
//!   [`UnpackReport`] for downstream auditing but does not change
//!   the on-disk result; mode-rewriting is out of scope for the
//!   base unpacker.
//! - **Symbolic links** — written via [`std::os::unix::fs::symlink`].
//!   The link target is preserved **verbatim**; we deliberately do
//!   *not* canonicalize it at unpack time, because the resolution
//!   happens later inside the booted guest where the layer hierarchy
//!   means something different than it does on the host. The safety
//!   policy enforced at *unpack* time is that the link's location
//!   (the path the symlink *file itself* occupies) is under
//!   `output_root`; targets that point outside are not unpack-time
//!   errors.
//! - **OCI whiteouts** — regular-file tar entries (typeflag
//!   `'0'`) whose *leaf filename* carries the OCI v1.1 whiteout
//!   semantic. `.wh.<name>` removes the sibling `<name>` from the
//!   assembled tree; `.wh..wh..opq` clears the parent directory's
//!   prior-layer contents but preserves the directory itself. The
//!   marker files themselves are **not** materialized, and markers
//!   apply only to prior/lower-layer state, never to entries from
//!   the same layer. Both shapes
//!   pass through every path safety check on the marker's path
//!   before the whiteout helper runs — including
//!   [`RefusalReason::SymlinkInParent`], so a `.wh.passwd` under a
//!   symlinked `etc/` refuses the same way a regular-file write
//!   would. Targets that don't exist are no-ops (the OCI spec is
//!   declarative; single-layer apply is idempotent).
//! - **Hardlinks** — tar `LINK` entries are accepted only
//!   when their link target resolves to an existing regular file
//!   under `output_root`. If the target was written earlier in the
//!   same layer, the entry is materialized as a real hardlink. If
//!   the target exists only from lower/prior layer state, the entry
//!   is materialized as a full copy so the current layer never
//!   creates a new inode alias back into mutable lower-layer
//!   pre-image state. A missing target refuses with
//!   [`RefusalReason::HardlinkTargetMissing`] (CVE-2019-14271
//!   mitigation).
//! - **Extended attributes** — `SCHILY.xattr.*` pax records
//!   are filtered through [`UnpackOptions::xattr_policy`]. The
//!   production default preserves only `user.*`, `security.capability`,
//!   and `security.selinux`; all other xattrs are dropped and reported
//!   in [`UnpackReport::xattr_warnings`]. The tar crate's implicit
//!   xattr unpacking remains disabled so every attribute passes through
//!   this allow-list before touching the host filesystem.
//! - **Device nodes** — tar character-device entries are
//!   materialized only when they are exactly `dev/null`, `dev/zero`,
//!   `dev/random`, or `dev/urandom` with the Linux standard major/minor
//!   numbers. Every other character or block device is refused with
//!   [`RefusalReason::DeviceNodeRefused`].
//! - **Setuid/setgid bits** — regular-file mode bits `0o4000`
//!   and `0o2000` are preserved by default with an audit annotation
//!   in [`UnpackReport::setid_entries`]. Production callers that have
//!   not verified the image with cosign set
//!   [`SetidPolicy::RefuseUnsigned`], which refuses the file with
//!   [`RefusalReason::SetuidUnsigned`]. Production callers with a valid
//!   cosign verification set [`SetidPolicy::PreserveVerified`] so the
//!   audit annotation records the signed-image posture.
//!
//! Every other entry kind — FIFOs, named sockets, sparse files, GNU
//! long-name continuations — is
//! **refused** with [`RefusalReason::UnsupportedEntryType`].
//!
//! ## Safety properties
//!
//! 1. **No path escapes `output_root`.** Three checks layer on top of
//!    each other for defense in depth:
//!    - Refuse absolute paths (`/etc/passwd`).
//!    - Refuse any path containing a literal `..` segment
//!      (segment-by-segment; never substring match — `..foo` is a
//!      valid filename).
//!    - After computing the would-be target as
//!      `output_root.join(rel)`, verify with `.starts_with(output_root)`
//!      that the resolved path is still under root. Catches edge
//!      cases the prior two checks miss (NUL-byte paths, platform-
//!      quirky separators, etc.).
//! 2. **Writes resolve atomically inside the root (Linux).** Every
//!    file / dir / symlink / hardlink / device-node materializes by
//!    resolving the entry's parent directory through
//!    `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS)` and issuing the
//!    leaf creation with `*at` calls against the returned directory
//!    handle — never against a re-derived host path. Resolution and
//!    write therefore share one kernel-checked handle, so a parent
//!    component swapped to a symlink *after* a check can no longer
//!    redirect the write outside the root: the kernel refuses to
//!    traverse the symlink (`ELOOP`) or to escape the root (`EXDEV`).
//!    This closes the check-then-use window that a bare
//!    `symlink_metadata` walk followed by a later `open(2)` leaves
//!    open. [`parent_chain_has_symlink`] is retained as a cheap,
//!    cross-platform fail-fast pre-filter (and as the guard for the
//!    still-path-based whiteout-removal walk); on Linux the `openat2`
//!    handle is the load-bearing authority for writes. On non-Linux
//!    targets (test/dev builds only — the unpacker runs only in the
//!    Linux builder VM in production) writes fall back to path-based
//!    creation with `O_NOFOLLOW` on the leaf.
//! 3. **Leaf opens use `O_NOFOLLOW` + `O_EXCL`** so a symlink or a
//!    pre-existing file planted *at the leaf* is refused (`ELOOP` /
//!    `EEXIST`) rather than followed or overwritten.
//! 4. **Timestamps zeroed by default.** OCI layer tarballs are
//!    notoriously timestamp-dependent; the same image pulled twice
//!    can produce non-byte-identical rootfs trees if mtime is
//!    preserved. [`UnpackOptions::strip_timestamps`] (default `true`)
//!    forces every unpacked entry's mtime/atime to `0` so two unpacks
//!    of the same layer produce byte-identical trees modulo
//!    filesystem-allocated inode numbers.
//!
//! ## Async / sync
//!
//! Tar parsing and filesystem syscalls are CPU- and syscall-bound;
//! exposing them as `async` would require either a Tokio file-I/O
//! shim that just farms out to `spawn_blocking` anyway, or porting
//! the `tar` crate to async (no off-the-shelf async-tar implementation
//! covers OCI semantics). We expose a synchronous `unpack_layer` and
//! expect async callers to wrap with `tokio::task::spawn_blocking`.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// OCI v1.1 whiteout marker prefix. A regular-file tar entry whose
/// **leaf filename** starts with this byte sequence is interpreted as
/// a whiteout instruction, not a file to materialize.
const WHITEOUT_PREFIX: &[u8] = b".wh.";

/// OCI v1.1 opaque-directory whiteout marker — the full leaf
/// filename (not a prefix). Distinct from `.wh.<name>` because it
/// directs the unpacker to clear the **parent** directory's
/// prior-layer contents rather than removing a sibling.
const WHITEOUT_OPAQUE: &[u8] = b".wh..wh..opq";

/// Pax key prefix used by OCI layer producers for extended
/// attributes. The suffix after this prefix is the filesystem xattr
/// name, e.g. `SCHILY.xattr.user.foo` -> `user.foo`.
const PAX_XATTR_PREFIX: &[u8] = b"SCHILY.xattr.";

/// Tar mode bits for setuid and setgid. Sticky (`0o1000`) remains
/// stripped because only setuid/setgid passthrough is granted.
const SETID_MODE_BITS: u32 = 0o6000;

/// Character-device allow-list, expressed as tar-relative paths plus
/// Linux major/minor pairs.
const ALLOWED_DEVICE_NODES: &[AllowedDeviceNode] = &[
    AllowedDeviceNode::new(b"dev/null", 1, 3),
    AllowedDeviceNode::new(b"dev/zero", 1, 5),
    AllowedDeviceNode::new(b"dev/random", 1, 8),
    AllowedDeviceNode::new(b"dev/urandom", 1, 9),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AllowedDeviceNode {
    path: &'static [u8],
    major: u32,
    minor: u32,
}

impl AllowedDeviceNode {
    const fn new(path: &'static [u8], major: u32, minor: u32) -> Self {
        Self { path, major, minor }
    }
}

/// How [`unpack_layer`] handles xattrs carried in pax headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrPolicy {
    /// Preserve the allow-list and drop everything else with
    /// a warning in [`UnpackReport::xattr_warnings`].
    PreserveAllowlisted,
    /// Drop every xattr with a warning. Useful for host filesystems
    /// that cannot represent OCI xattrs safely.
    DropAll,
}

/// How [`unpack_layer`] handles regular files whose tar mode contains
/// setuid (`0o4000`) or setgid (`0o2000`) bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetidPolicy {
    /// Preserve setuid/setgid bits and record each preserved entry as
    /// a development-profile audit annotation.
    PreserveDev,
    /// Refuse setuid/setgid files because the caller is enforcing a
    /// production profile without a verified cosign signature.
    RefuseUnsigned,
    /// Preserve setuid/setgid bits and record each preserved entry as
    /// a cosign-verified production audit annotation.
    PreserveVerified,
}

/// Caller-controlled knobs for [`unpack_layer`].
///
/// Defaults match the local/dev unpack posture; production
/// callers tighten individual fields (notably `setid_policy`) without
/// rebuilding the whole struct.
#[derive(Debug, Clone)]
pub struct UnpackOptions {
    /// Refuse any tar entry whose path length (in bytes, post-
    /// UTF-8-lossy normalisation) exceeds this value. The default
    /// (4096) is Linux's `PATH_MAX` and the longest plausible
    /// real-world image path; anything beyond is either a probe for
    /// path-handling bugs or a malformed tarball.
    pub max_path_len: usize,

    /// When `true` (the default), every unpacked entry's mtime and
    /// atime are forced to the Unix epoch (`0`). When `false`,
    /// the tar header's `mtime` field is preserved. **Set to
    /// `false` only for debugging** — production unpacks
    /// uniformly strip timestamps so two pulls of the same layer
    /// produce byte-identical trees.
    pub strip_timestamps: bool,

    /// Extended-attribute policy for `SCHILY.xattr.*` pax records.
    /// Defaults to [`XattrPolicy::PreserveAllowlisted`], which keeps
    /// only `user.*`, `security.capability`, and `security.selinux`.
    pub xattr_policy: XattrPolicy,

    /// Setuid/setgid policy for regular-file tar mode bits. Defaults
    /// to [`SetidPolicy::PreserveDev`]. Production callers that have
    /// not verified the image with cosign must override this to
    /// [`SetidPolicy::RefuseUnsigned`]; production callers with a
    /// valid cosign result use [`SetidPolicy::PreserveVerified`].
    pub setid_policy: SetidPolicy,
}

impl Default for UnpackOptions {
    fn default() -> Self {
        Self {
            max_path_len: 4096,
            strip_timestamps: true,
            xattr_policy: XattrPolicy::PreserveAllowlisted,
            setid_policy: SetidPolicy::PreserveDev,
        }
    }
}

/// Summary of what [`unpack_layer`] did with a layer. Returned even
/// on the happy path; callers that need a strict "everything
/// accepted or bust" gate inspect `refused.is_empty()`.
#[derive(Debug, Clone, Default)]
pub struct UnpackReport {
    /// Regular files materialized.
    pub files_written: u64,
    /// Directories created (counts only newly-created dirs; entries
    /// for already-existing dirs are silently coalesced).
    pub dirs_created: u64,
    /// Symlinks written.
    pub symlinks_written: u64,
    /// Hardlinks materialized as real hardlinks because the target
    /// was written earlier in this same layer.
    pub hardlinks_written: u64,
    /// Hardlink entries materialized as full file copies because
    /// the target existed only in lower/prior layer state. This is
    /// intentionally separate from `files_written` so callers can
    /// audit hardlink semantics without conflating them with normal
    /// file entries.
    pub hardlink_copies_written: u64,
    /// OCI `.wh.<name>` whiteout markers applied. A successful apply
    /// removes the sibling target if it exists; if the target is
    /// absent the apply is still counted because the marker was
    /// consumed (single-layer apply is declarative — OCI v1.1
    /// §"Layer Filesystem Changeset").
    pub whiteouts_applied: u64,
    /// OCI `.wh..wh..opq` opaque-directory markers applied. A
    /// successful apply clears the parent directory's prior-layer
    /// contents (the directory itself is preserved). Counted even
    /// when the parent is absent or empty, for the same declarative
    /// reason as `whiteouts_applied`.
    pub opaque_markers_applied: u64,
    /// Allow-listed pax xattrs successfully written to the
    /// materialized filesystem entry.
    pub xattrs_written: u64,
    /// Allow-listed character device nodes materialized.
    pub device_nodes_written: u64,
    /// Regular files whose setuid/setgid bits were preserved.
    pub setid_entries_preserved: u64,
    /// Pax xattrs intentionally dropped by policy or because the
    /// host filesystem rejected the write. Each drop also gets a
    /// corresponding [`XattrWarning`] in `xattr_warnings`.
    pub xattrs_dropped: u64,
    /// Non-fatal xattr warnings, in stream order. Xattr drops do not
    /// refuse the tar entry itself; the file/dir/link can still be
    /// materialized while the unsafe or unsupported attribute is
    /// omitted.
    pub xattr_warnings: Vec<XattrWarning>,
    /// Setuid/setgid regular-file entries preserved by policy, in
    /// stream order. This is the setuid/setgid audit annotation surface:
    /// each record carries the raw path, preserved mode, and whether
    /// the caller represented the image as cosign-verified.
    pub setid_entries: Vec<SetidEntry>,
    /// Tar entries refused by policy, in the order they appeared in
    /// the stream. Each carries a [`RefusalReason`] so a downstream
    /// audit / debugging surface can render them.
    pub refused: Vec<RefusedEntry>,
}

/// One regular file whose setuid or setgid mode bit was preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetidEntry {
    /// Path bytes from the tar header, verbatim.
    pub raw_path: Vec<u8>,
    /// Preserved mode bits after sticky-bit stripping. Includes the
    /// normal `0o0777` permissions plus any preserved `0o6000` bits.
    pub mode: u32,
    /// `true` when preserved under [`SetidPolicy::PreserveVerified`].
    /// `false` means the default development policy preserved it.
    pub cosign_verified: bool,
}

/// One xattr that was not preserved. Recorded as a warning instead
/// of a refused entry because denied xattrs are treated as
/// non-fatal metadata drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XattrWarning {
    /// Path bytes from the tar header, verbatim.
    pub raw_path: Vec<u8>,
    /// Xattr name bytes, without the `SCHILY.xattr.` pax prefix.
    pub name: Vec<u8>,
    /// Why this xattr was dropped.
    pub reason: XattrWarningReason,
}

/// Why an xattr was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrWarningReason {
    /// [`XattrPolicy::DropAll`] is active.
    PolicyDropAll,
    /// The xattr name is outside the allow-list.
    NotAllowlisted,
    /// The pax key did not contain a usable xattr name.
    MalformedName,
    /// The xattr passed policy but the host filesystem rejected it.
    ApplyFailed,
}

/// One refused tar entry. The path is recorded as raw bytes (not as
/// a `String`) because the tar header can carry non-UTF-8 paths and
/// we don't want to mask that with lossy decoding before the audit
/// gets a chance to see it.
#[derive(Debug, Clone)]
pub struct RefusedEntry {
    /// Path bytes from the tar header, verbatim. Render via
    /// `String::from_utf8_lossy` for human-readable output;
    /// preserve as-is for audit logging.
    pub raw_path: Vec<u8>,
    /// Which policy rejected the entry.
    pub reason: RefusalReason,
}

/// Why a tar entry was rejected. Each variant maps to one of the
/// safety properties documented at module level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// Path starts with `/`. Tar entries must be relative.
    AbsolutePath,
    /// Path contains a `..` segment (parent-directory reference).
    TraversalSegment,
    /// Path length exceeded [`UnpackOptions::max_path_len`].
    PathTooLong,
    /// Joined-against-root path resolved outside `output_root`. This
    /// is a defense-in-depth check; the prior absolute-path and
    /// traversal-segment refusals should catch every real-world
    /// case before reaching this branch, but the check stays so a
    /// future platform-specific path quirk can't silently bypass.
    JoinedPathEscape,
    /// A parent directory along the target's path is a symlink. We
    /// refuse to write under symlink-prefixed paths so a malicious
    /// layer can't write `bin -> /tmp` in one entry and then
    /// materialize `bin/x` in a later entry that would `open(2)`
    /// `/tmp/x` instead of `<root>/bin/x`.
    SymlinkInParent,
    /// Tar entry type is not supported (FIFOs, named sockets, sparse
    /// files, GNU long-name continuations). The supported kinds are
    /// regular files, directories, in-root symlinks, hardlinks, the
    /// allow-listed device nodes, and the OCI whiteout markers.
    UnsupportedEntryType,
    /// A tar hardlink entry referenced a target that does not exist
    /// in the already-assembled tree. Refusing missing targets is
    /// the CVE-2019-14271 guard: the unpacker never lets a later path
    /// retroactively define what an earlier hardlink points at.
    HardlinkTargetMissing,
    /// A character or block special file did not match the
    /// device-node allow-list. Only `dev/null`, `dev/zero`, `dev/random`, and
    /// `dev/urandom` with their Linux standard major/minor pairs are
    /// materialized; everything else is refused closed.
    DeviceNodeRefused,
    /// A regular file carried setuid or setgid bits while the caller
    /// was enforcing production-without-cosign policy. Equivalent
    /// operator-facing error code: `E_OCI_SETUID_UNSIGNED`.
    SetuidUnsigned,
    /// Tar header was malformed (unreadable path bytes, etc.). We
    /// refuse the entry rather than failing the whole unpack — a
    /// single bad entry shouldn't poison a multi-thousand-entry
    /// layer if the rest is valid.
    MalformedHeader,
}

impl RefusalReason {
    /// Stable wire string for audit logging — never localised, never
    /// rewritten without bumping the wire contract. Pairs with
    /// [`RefusedEntry::raw_path`] to form the audit-entry tuple.
    pub fn audit_tag(self) -> &'static str {
        match self {
            Self::AbsolutePath => "absolute_path",
            Self::TraversalSegment => "traversal_segment",
            Self::PathTooLong => "path_too_long",
            Self::JoinedPathEscape => "joined_path_escape",
            Self::SymlinkInParent => "symlink_in_parent",
            Self::UnsupportedEntryType => "unsupported_entry_type",
            Self::HardlinkTargetMissing => "hardlink_target_missing",
            Self::DeviceNodeRefused => "device_node_refused",
            Self::SetuidUnsigned => "E_OCI_SETUID_UNSIGNED",
            Self::MalformedHeader => "malformed_header",
        }
    }
}

/// Hard-error path for [`unpack_layer`]. Distinguishes
/// "caller-supplied output_root is invalid" (configuration error,
/// surfaces to the operator) from "this specific tar entry is bad"
/// (data error, surfaces in [`UnpackReport::refused`]).
#[derive(Debug, thiserror::Error)]
pub enum UnpackError {
    /// I/O failure reading the tar stream itself (network short-read,
    /// disk EIO, etc.). Distinct from per-entry malformed-header
    /// refusals, which the unpacker continues past.
    #[error("reading layer tar stream: {0}")]
    TarRead(#[from] std::io::Error),

    /// Caller passed a relative path as `output_root`. We require an
    /// absolute path so the "does this resolve under root" check
    /// has well-defined semantics independent of the process's
    /// `cwd`.
    #[error("output_root must be an absolute path; got {0:?}")]
    NonAbsoluteOutputRoot(PathBuf),

    /// `output_root` does not exist or is not a directory. The
    /// directory must exist before unpacking — callers
    /// `create_dir_all` it as part of their pull pipeline before
    /// invoking the unpacker. We refuse to silently create it to
    /// keep the unpacker's filesystem write surface a strict
    /// subset of `output_root`'s subtree.
    #[error("output_root must exist as a directory; got {0:?}")]
    OutputRootNotADir(PathBuf),
}

/// Root-confined materialization surface, created once per
/// [`unpack_layer`] call.
///
/// On Linux every file/dir/symlink/hardlink/device-node is written by
/// resolving the entry's parent directory through
/// `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS)` and issuing the
/// leaf `*at` call against the returned directory handle — never
/// against a re-derived host path. Resolution and write share one
/// kernel-checked handle, so a parent component swapped to a symlink
/// after the up-front [`parent_chain_has_symlink`] fail-fast scan can
/// no longer redirect the write outside the root: the kernel refuses
/// to traverse the symlink (`ELOOP`) or to escape the root (`EXDEV`).
///
/// On non-Linux targets (test/dev builds only — the unpacker runs only
/// in the Linux builder VM in production) the methods fall back to the
/// path-based writers with `O_NOFOLLOW` on the leaf.
struct Rooted<'a> {
    root: &'a Path,
    #[cfg(target_os = "linux")]
    root_fd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl<'a> Rooted<'a> {
    fn open(root: &'a Path) -> std::io::Result<Self> {
        use rustix::fs::{Mode, OFlags};
        // The root is caller-supplied and trusted; allow it to itself
        // be a symlink-to-dir (mirrors the `is_dir()` precheck) by not
        // setting `NOFOLLOW` on this open only.
        let root_fd = rustix::fs::open(root, OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())?;
        Ok(Self { root, root_fd })
    }

    /// Open the parent directory of `rel` relative to the root handle,
    /// refusing any symlinked component atomically. When `create` is
    /// set the intermediate directories are created with `mkdirat` as
    /// the walk descends. Returns the parent directory handle and the
    /// leaf name. Errors are returned as the raw `Errno` so callers can
    /// distinguish a missing component (hardlink source) from a symlink
    /// trap.
    fn open_parent(
        &self,
        rel: &Path,
        create: bool,
    ) -> Result<(std::os::fd::OwnedFd, std::ffi::OsString), rustix::io::Errno> {
        use rustix::fs::{Mode, OFlags, ResolveFlags, mkdirat, openat2};
        use rustix::io::Errno;
        use std::os::fd::AsFd;

        let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS;
        let dir_oflags = OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;

        let mut names: Vec<&OsStr> = Vec::new();
        for comp in rel.components() {
            // `..`/`/`/`.` are refused or stripped upstream; only the
            // Normal segments name real path components.
            if let Component::Normal(seg) = comp {
                names.push(seg);
            }
        }
        let leaf = names.pop().ok_or(Errno::NOENT)?.to_os_string();

        let mut cur: Option<std::os::fd::OwnedFd> = None;
        for name in names {
            let dir = cur.as_ref().map_or(self.root_fd.as_fd(), |f| f.as_fd());
            if create {
                if let Err(e) = mkdirat(dir, name, Mode::from_raw_mode(0o755)) {
                    if e != Errno::EXIST {
                        return Err(e);
                    }
                }
            }
            cur = Some(openat2(dir, name, dir_oflags, Mode::empty(), resolve)?);
        }

        let parent = match cur {
            Some(fd) => fd,
            // Leaf sits directly under the root.
            None => openat2(
                self.root_fd.as_fd(),
                ".",
                OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                resolve,
            )?,
        };
        Ok((parent, leaf))
    }

    fn write_regular_file<R: Read>(
        &self,
        rel: &Path,
        entry: &mut tar::Entry<R>,
        raw_path: &[u8],
        options: &UnpackOptions,
        report: &mut UnpackReport,
    ) -> Result<(), RefusalReason> {
        use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
        use std::io::Write;
        use std::os::fd::AsFd;
        use std::os::unix::fs::PermissionsExt;
        use std::time::SystemTime;

        let mode = classify_regular_file_mode(entry.header().mode().unwrap_or(0o644), options)?;
        let (parent, leaf) = self.open_parent(rel, true).map_err(map_resolve_errno)?;
        let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS;
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = openat2(
            parent.as_fd(),
            &leaf,
            flags,
            Mode::from_raw_mode(mode),
            resolve,
        )
        .map_err(map_resolve_errno)?;
        let mut file = std::fs::File::from(fd);

        if std::io::copy(entry, &mut file).is_err() {
            return Err(RefusalReason::MalformedHeader);
        }
        if file.flush().is_err() {
            return Err(RefusalReason::MalformedHeader);
        }
        // `open(2)` honors umask and may clear setid bits on write, so
        // reassert the policy-classified mode through the fd.
        if file
            .set_permissions(std::fs::Permissions::from_mode(mode))
            .is_err()
        {
            return Err(RefusalReason::MalformedHeader);
        }
        record_setid_entry(report, raw_path, mode, options.setid_policy);
        if options.strip_timestamps {
            let _ = file.set_modified(SystemTime::UNIX_EPOCH);
        }
        Ok(())
    }

    fn create_directory(&self, rel: &Path) -> Result<bool, RefusalReason> {
        use rustix::fs::{Mode, mkdirat};
        use rustix::io::Errno;
        use std::os::fd::AsFd;

        let (parent, leaf) = self.open_parent(rel, true).map_err(map_resolve_errno)?;
        match mkdirat(parent.as_fd(), &leaf, Mode::from_raw_mode(0o755)) {
            Ok(()) => Ok(true),
            Err(e) if e == Errno::EXIST => Ok(false),
            Err(e) => Err(map_resolve_errno(e)),
        }
    }

    fn write_symlink(
        &self,
        rel: &Path,
        link_target_bytes: Option<&[u8]>,
    ) -> Result<(), RefusalReason> {
        use rustix::fs::symlinkat;
        use std::os::fd::AsFd;

        let link_target = match link_target_bytes {
            Some(b) if !b.is_empty() && !b.contains(&0) => b,
            _ => return Err(RefusalReason::MalformedHeader),
        };
        let (parent, leaf) = self.open_parent(rel, true).map_err(map_resolve_errno)?;
        symlinkat(OsStr::from_bytes(link_target), parent.as_fd(), &leaf)
            .map_err(|_| RefusalReason::MalformedHeader)
    }

    fn materialize_device_node<R: Read>(
        &self,
        entry: &tar::Entry<R>,
        rel: &Path,
        raw_path: &[u8],
    ) -> Result<(), RefusalReason> {
        use rustix::fs::{FileType, Mode, makedev, mknodat};
        use std::os::fd::AsFd;

        let major = entry
            .header()
            .device_major()
            .map_err(|_| RefusalReason::MalformedHeader)?;
        let minor = entry
            .header()
            .device_minor()
            .map_err(|_| RefusalReason::MalformedHeader)?;
        let allowed = classify_device_node(entry.header().entry_type(), raw_path, major, minor)?;

        let (parent, leaf) = self.open_parent(rel, true).map_err(map_resolve_errno)?;
        mknodat(
            parent.as_fd(),
            &leaf,
            FileType::CharacterDevice,
            Mode::from_raw_mode(0o666),
            makedev(allowed.major, allowed.minor),
        )
        .map_err(|_| RefusalReason::MalformedHeader)
    }

    fn materialize_hardlink(
        &self,
        link_target_bytes: Option<&[u8]>,
        target_rel: &Path,
        options: &UnpackOptions,
        current_layer_paths: &HashSet<PathBuf>,
    ) -> Result<HardlinkAction, RefusalReason> {
        use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags, linkat, openat2, statat};
        use rustix::io::Errno;
        use std::io::Write;
        use std::os::fd::AsFd;
        use std::os::unix::fs::PermissionsExt;

        let src_rel = validate_hardlink_target(link_target_bytes, self.root, options)?;
        let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS;

        // The source's parent must already exist; a missing component
        // is the CVE-2019-14271 guard, not a symlink trap.
        let (src_parent, src_leaf) = self.open_parent(&src_rel, false).map_err(|e| {
            if e == Errno::NOENT {
                RefusalReason::HardlinkTargetMissing
            } else {
                map_resolve_errno(e)
            }
        })?;

        // Source must be an existing regular file; never dereference a
        // symlink target (mirrors the lstat-based check on non-Linux).
        let st = statat(src_parent.as_fd(), &src_leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| {
            if e == Errno::NOENT {
                RefusalReason::HardlinkTargetMissing
            } else {
                RefusalReason::MalformedHeader
            }
        })?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
            return Err(RefusalReason::MalformedHeader);
        }

        let (dst_parent, dst_leaf) = self
            .open_parent(target_rel, true)
            .map_err(map_resolve_errno)?;

        if current_layer_paths.contains(&src_rel) {
            linkat(
                src_parent.as_fd(),
                &src_leaf,
                dst_parent.as_fd(),
                &dst_leaf,
                AtFlags::empty(),
            )
            .map_err(|_| RefusalReason::MalformedHeader)?;
            return Ok(HardlinkAction::Linked);
        }

        // Cross-layer: copy so the current layer never aliases mutable
        // lower-layer inode state.
        let src_fd = openat2(
            src_parent.as_fd(),
            &src_leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            resolve,
        )
        .map_err(map_resolve_errno)?;
        let mut src = std::fs::File::from(src_fd);
        let mode = src
            .metadata()
            .map_err(|_| RefusalReason::MalformedHeader)?
            .permissions()
            .mode()
            & 0o777;
        let dst_fd = openat2(
            dst_parent.as_fd(),
            &dst_leaf,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(mode),
            resolve,
        )
        .map_err(map_resolve_errno)?;
        let mut dst = std::fs::File::from(dst_fd);
        std::io::copy(&mut src, &mut dst).map_err(|_| RefusalReason::MalformedHeader)?;
        dst.flush().map_err(|_| RefusalReason::MalformedHeader)?;
        if options.strip_timestamps {
            let _ = dst.set_modified(std::time::SystemTime::UNIX_EPOCH);
        }
        Ok(HardlinkAction::Copied)
    }
}

/// Map an `openat2`/`*at` failure to the unpacker's refusal taxonomy.
/// `ELOOP` is a `RESOLVE_NO_SYMLINKS` hit on a symlinked component;
/// `EXDEV` is a `RESOLVE_IN_ROOT` boundary escape. Everything else is
/// an opaque per-entry failure.
#[cfg(target_os = "linux")]
fn map_resolve_errno(e: rustix::io::Errno) -> RefusalReason {
    use rustix::io::Errno;
    if e == Errno::LOOP {
        RefusalReason::SymlinkInParent
    } else if e == Errno::XDEV {
        RefusalReason::JoinedPathEscape
    } else {
        RefusalReason::MalformedHeader
    }
}

#[cfg(not(target_os = "linux"))]
impl<'a> Rooted<'a> {
    fn open(root: &'a Path) -> std::io::Result<Self> {
        Ok(Self { root })
    }

    fn write_regular_file<R: Read>(
        &self,
        rel: &Path,
        entry: &mut tar::Entry<R>,
        raw_path: &[u8],
        options: &UnpackOptions,
        report: &mut UnpackReport,
    ) -> Result<(), RefusalReason> {
        write_regular_file(entry, &self.root.join(rel), raw_path, options, report)
    }

    fn create_directory(&self, rel: &Path) -> Result<bool, RefusalReason> {
        create_directory(&self.root.join(rel))
    }

    fn write_symlink(
        &self,
        rel: &Path,
        link_target_bytes: Option<&[u8]>,
    ) -> Result<(), RefusalReason> {
        write_symlink(link_target_bytes, &self.root.join(rel))
    }

    fn materialize_device_node<R: Read>(
        &self,
        entry: &tar::Entry<R>,
        rel: &Path,
        raw_path: &[u8],
    ) -> Result<(), RefusalReason> {
        materialize_device_node(entry, &self.root.join(rel), raw_path)
    }

    fn materialize_hardlink(
        &self,
        link_target_bytes: Option<&[u8]>,
        target_rel: &Path,
        options: &UnpackOptions,
        current_layer_paths: &HashSet<PathBuf>,
    ) -> Result<HardlinkAction, RefusalReason> {
        materialize_hardlink(
            link_target_bytes,
            &self.root.join(target_rel),
            self.root,
            options,
            current_layer_paths,
        )
    }
}

/// Unpack a single layer tarball under `output_root`, applying the
/// safety policies described at module level.
///
/// Caller's responsibilities:
///
/// - Pre-create `output_root` (we refuse to silently `mkdir` it).
/// - Decompress the layer **before** calling, if the layer
///   `mediaType` is `tar+gzip` / `tar+zstd`. The unpacker
///   reads a *plain* tar stream; the decompression wrapping is
///   the integration layer's problem (and the integration layer
///   already knows the `mediaType` from the manifest descriptor).
///
/// Returns an [`UnpackReport`] enumerating the writes and the
/// refused entries. Refusals are **not** errors — callers that want
/// "all-or-nothing" inspect `report.refused.is_empty()`.
pub fn unpack_layer<R: Read>(
    mut layer_tar: R,
    output_root: &Path,
    options: &UnpackOptions,
) -> Result<UnpackReport, UnpackError> {
    if !output_root.is_absolute() {
        return Err(UnpackError::NonAbsoluteOutputRoot(
            output_root.to_path_buf(),
        ));
    }
    if !output_root.is_dir() {
        return Err(UnpackError::OutputRootNotADir(output_root.to_path_buf()));
    }

    // Open the root once. On Linux every materialization resolves and
    // writes through this handle via `openat2(RESOLVE_IN_ROOT |
    // RESOLVE_NO_SYMLINKS)`, so the resolve-then-write is atomic
    // against a concurrently-planted symlink parent.
    let rooted = Rooted::open(output_root)
        .map_err(|_| UnpackError::OutputRootNotADir(output_root.to_path_buf()))?;

    // We feed the raw reader to `tar::Archive`; the crate handles
    // sub-entry framing. The `set_*` knobs below disable the tar
    // crate's built-in unpacking conveniences — every safety
    // decision passes through our own match.
    let mut archive = tar::Archive::new(&mut layer_tar);
    archive.set_preserve_permissions(false);
    archive.set_preserve_mtime(false);
    archive.set_unpack_xattrs(false);

    let mut report = UnpackReport::default();
    let mut current_layer_paths = HashSet::new();

    for entry_result in archive.entries()? {
        let mut entry = match entry_result {
            Ok(e) => e,
            Err(_) => {
                // A malformed header at the stream level (tar crate's
                // own validation) — record as a malformed-header
                // refusal with empty path and keep going. We can't
                // know the "intended" path of an entry whose header
                // didn't parse.
                report.refused.push(RefusedEntry {
                    raw_path: Vec::new(),
                    reason: RefusalReason::MalformedHeader,
                });
                continue;
            }
        };

        let raw_path = entry.path_bytes().to_vec();

        if raw_path.is_empty() {
            report.refused.push(RefusedEntry {
                raw_path,
                reason: RefusalReason::MalformedHeader,
            });
            continue;
        }

        // Safety check 1 — absolute paths.
        if raw_path.first() == Some(&b'/') {
            report.refused.push(RefusedEntry {
                raw_path,
                reason: RefusalReason::AbsolutePath,
            });
            continue;
        }

        // Safety check 2 — traversal segments. Segment-by-segment
        // (never substring): `..foo` is a valid name; `../foo` is
        // not. Tar paths are slash-separated regardless of host OS.
        let traversal = raw_path.split(|b| *b == b'/').any(|seg| seg == b"..");
        if traversal {
            report.refused.push(RefusedEntry {
                raw_path,
                reason: RefusalReason::TraversalSegment,
            });
            continue;
        }

        // Safety check 3 — max length.
        if raw_path.len() > options.max_path_len {
            report.refused.push(RefusedEntry {
                raw_path,
                reason: RefusalReason::PathTooLong,
            });
            continue;
        }

        let rel_path = PathBuf::from(OsStr::from_bytes(&raw_path));
        let target = output_root.join(&rel_path);

        // Safety check 4 — joined path stays under root. The prior
        // checks should make this unreachable in practice, but
        // platform-specific quirks (NUL bytes, Windows-ish
        // separators in tar entries from cross-platform builds, etc.)
        // could in theory slip through; the explicit
        // `starts_with(output_root)` is the catch-all.
        if !target.starts_with(output_root) {
            report.refused.push(RefusedEntry {
                raw_path,
                reason: RefusalReason::JoinedPathEscape,
            });
            continue;
        }

        // Safety check 5 — fail-fast scan for an already-present
        // symlink in any parent of the target. Walks each existing
        // prefix; if any component is a symlink we refuse this entry.
        // On Linux this is a cheap pre-filter only: the openat2 write
        // path (`Rooted`) is the load-bearing authority that closes
        // the check-then-use race. It still guards the path-based
        // whiteout-removal walk on every platform.
        if parent_chain_has_symlink(output_root, &rel_path) {
            report.refused.push(RefusedEntry {
                raw_path,
                reason: RefusalReason::SymlinkInParent,
            });
            continue;
        }

        // Dispatch: regular files and directories and symlinks
        // materialize; regular-file entries whose **leaf filename**
        // matches the OCI whiteout pattern dispatch to the whiteout
        // helpers instead of `write_regular_file`. Hardlinks and
        // allow-listed device nodes materialize too; everything else
        // refuses.
        let entry_xattrs = match collect_entry_xattrs(&mut entry, &raw_path, options, &mut report) {
            Ok(attrs) => attrs,
            Err(refuse) => {
                report.refused.push(RefusedEntry {
                    raw_path,
                    reason: refuse,
                });
                continue;
            }
        };
        let entry_type = entry.header().entry_type();
        match entry_type {
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                match classify_whiteout(&raw_path) {
                    WhiteoutKind::None => match rooted.write_regular_file(
                        &rel_path,
                        &mut entry,
                        &raw_path,
                        options,
                        &mut report,
                    ) {
                        Ok(()) => {
                            report.files_written += 1;
                            apply_collected_xattrs(&target, &raw_path, entry_xattrs, &mut report);
                            current_layer_paths.insert(rel_path.clone());
                        }
                        Err(refuse) => report.refused.push(RefusedEntry {
                            raw_path: raw_path.clone(),
                            reason: refuse,
                        }),
                    },
                    WhiteoutKind::Opaque => {
                        // Parent-of-marker is the directory we're
                        // clearing. `target` already points at the
                        // marker file, so we strip the marker leaf
                        // to get the parent dir.
                        let parent = target.parent().unwrap_or(output_root);
                        let parent_rel = rel_path.parent().unwrap_or_else(|| Path::new(""));
                        match apply_opaque_whiteout(
                            parent,
                            parent_rel,
                            output_root,
                            &current_layer_paths,
                        ) {
                            Ok(()) => report.opaque_markers_applied += 1,
                            Err(refuse) => report.refused.push(RefusedEntry {
                                raw_path: raw_path.clone(),
                                reason: refuse,
                            }),
                        }
                    }
                    WhiteoutKind::Regular(name_suffix) => {
                        // Sibling target = `<parent_of_marker>/<name_suffix>`.
                        let parent = target.parent().unwrap_or(output_root);
                        let parent_rel = rel_path.parent().unwrap_or_else(|| Path::new(""));
                        let sibling_rel = parent_rel.join(OsStr::from_bytes(name_suffix));
                        let sibling = parent.join(OsStr::from_bytes(name_suffix));
                        match apply_regular_whiteout(
                            &sibling,
                            &sibling_rel,
                            output_root,
                            &current_layer_paths,
                        ) {
                            Ok(()) => report.whiteouts_applied += 1,
                            Err(refuse) => report.refused.push(RefusedEntry {
                                raw_path: raw_path.clone(),
                                reason: refuse,
                            }),
                        }
                    }
                    WhiteoutKind::Malformed => {
                        report.refused.push(RefusedEntry {
                            raw_path: raw_path.clone(),
                            reason: RefusalReason::MalformedHeader,
                        });
                    }
                }
            }
            tar::EntryType::Directory => match rooted.create_directory(&rel_path) {
                Ok(created) => {
                    if created {
                        report.dirs_created += 1;
                    }
                    apply_collected_xattrs(&target, &raw_path, entry_xattrs, &mut report);
                    current_layer_paths.insert(rel_path.clone());
                }
                Err(refuse) => report.refused.push(RefusedEntry {
                    raw_path: raw_path.clone(),
                    reason: refuse,
                }),
            },
            tar::EntryType::Symlink => {
                let link_target = entry.link_name_bytes().map(|b| b.into_owned());
                match rooted.write_symlink(&rel_path, link_target.as_deref()) {
                    Ok(()) => {
                        report.symlinks_written += 1;
                        apply_collected_xattrs(&target, &raw_path, entry_xattrs, &mut report);
                        current_layer_paths.insert(rel_path.clone());
                    }
                    Err(refuse) => report.refused.push(RefusedEntry {
                        raw_path: raw_path.clone(),
                        reason: refuse,
                    }),
                }
            }
            tar::EntryType::Link => {
                let link_target = entry.link_name_bytes().map(|b| b.into_owned());
                match rooted.materialize_hardlink(
                    link_target.as_deref(),
                    &rel_path,
                    options,
                    &current_layer_paths,
                ) {
                    Ok(HardlinkAction::Linked) => {
                        report.hardlinks_written += 1;
                        apply_collected_xattrs(&target, &raw_path, entry_xattrs, &mut report);
                        current_layer_paths.insert(rel_path.clone());
                    }
                    Ok(HardlinkAction::Copied) => {
                        report.hardlink_copies_written += 1;
                        apply_collected_xattrs(&target, &raw_path, entry_xattrs, &mut report);
                        current_layer_paths.insert(rel_path.clone());
                    }
                    Err(refuse) => report.refused.push(RefusedEntry {
                        raw_path: raw_path.clone(),
                        reason: refuse,
                    }),
                }
            }
            tar::EntryType::Char | tar::EntryType::Block => {
                match rooted.materialize_device_node(&entry, &rel_path, &raw_path) {
                    Ok(()) => {
                        report.device_nodes_written += 1;
                        apply_collected_xattrs(&target, &raw_path, entry_xattrs, &mut report);
                        current_layer_paths.insert(rel_path.clone());
                    }
                    Err(refuse) => report.refused.push(RefusedEntry {
                        raw_path: raw_path.clone(),
                        reason: refuse,
                    }),
                }
            }
            _ => {
                report.refused.push(RefusedEntry {
                    raw_path,
                    reason: RefusalReason::UnsupportedEntryType,
                });
            }
        }
    }

    Ok(report)
}

#[derive(Debug)]
struct PendingXattr {
    name: Vec<u8>,
    value: Vec<u8>,
}

fn collect_entry_xattrs<R: Read>(
    entry: &mut tar::Entry<R>,
    raw_path: &[u8],
    options: &UnpackOptions,
    report: &mut UnpackReport,
) -> Result<Vec<PendingXattr>, RefusalReason> {
    let Some(pax_extensions) = entry
        .pax_extensions()
        .map_err(|_| RefusalReason::MalformedHeader)?
    else {
        return Ok(Vec::new());
    };

    let mut attrs = Vec::new();
    for extension in pax_extensions {
        let extension = extension.map_err(|_| RefusalReason::MalformedHeader)?;
        let key = extension.key_bytes();
        let Some(name) = key.strip_prefix(PAX_XATTR_PREFIX) else {
            continue;
        };

        match classify_xattr_name(options.xattr_policy, name) {
            Ok(()) => attrs.push(PendingXattr {
                name: name.to_vec(),
                value: extension.value_bytes().to_vec(),
            }),
            Err(reason) => record_xattr_warning(report, raw_path, name, reason),
        }
    }

    Ok(attrs)
}

fn classify_xattr_name(policy: XattrPolicy, name: &[u8]) -> Result<(), XattrWarningReason> {
    if name.is_empty() || name.contains(&0) {
        return Err(XattrWarningReason::MalformedName);
    }
    if policy == XattrPolicy::DropAll {
        return Err(XattrWarningReason::PolicyDropAll);
    }
    if is_allowlisted_xattr(name) {
        Ok(())
    } else {
        Err(XattrWarningReason::NotAllowlisted)
    }
}

#[cfg(not(target_os = "linux"))]
fn materialize_device_node<R: Read>(
    entry: &tar::Entry<R>,
    target: &Path,
    raw_path: &[u8],
) -> Result<(), RefusalReason> {
    let major = entry
        .header()
        .device_major()
        .map_err(|_| RefusalReason::MalformedHeader)?;
    let minor = entry
        .header()
        .device_minor()
        .map_err(|_| RefusalReason::MalformedHeader)?;
    let allowed = classify_device_node(entry.header().entry_type(), raw_path, major, minor)?;

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|_| RefusalReason::MalformedHeader)?;
    }

    create_allowed_device_node(target, allowed)
}

fn classify_device_node(
    entry_type: tar::EntryType,
    raw_path: &[u8],
    major: Option<u32>,
    minor: Option<u32>,
) -> Result<AllowedDeviceNode, RefusalReason> {
    if entry_type != tar::EntryType::Char {
        return Err(RefusalReason::DeviceNodeRefused);
    }

    let (Some(major), Some(minor)) = (major, minor) else {
        return Err(RefusalReason::DeviceNodeRefused);
    };

    ALLOWED_DEVICE_NODES
        .iter()
        .copied()
        .find(|allowed| {
            allowed.path == raw_path && allowed.major == major && allowed.minor == minor
        })
        .ok_or(RefusalReason::DeviceNodeRefused)
}

/// Non-Linux fallback only — Linux device nodes are created via
/// [`Rooted::materialize_device_node`] (openat2-resolved `mknodat`).
#[cfg(not(target_os = "linux"))]
fn create_allowed_device_node(
    _target: &Path,
    _allowed: AllowedDeviceNode,
) -> Result<(), RefusalReason> {
    Err(RefusalReason::DeviceNodeRefused)
}

fn is_allowlisted_xattr(name: &[u8]) -> bool {
    name.starts_with(b"user.") || name == b"security.capability" || name == b"security.selinux"
}

fn apply_collected_xattrs(
    target: &Path,
    raw_path: &[u8],
    attrs: Vec<PendingXattr>,
    report: &mut UnpackReport,
) {
    for attr in attrs {
        let name = OsStr::from_bytes(&attr.name);
        match xattr::set(target, name, &attr.value) {
            Ok(()) => report.xattrs_written += 1,
            Err(_) => {
                record_xattr_warning(
                    report,
                    raw_path,
                    &attr.name,
                    XattrWarningReason::ApplyFailed,
                );
            }
        }
    }
}

fn record_xattr_warning(
    report: &mut UnpackReport,
    raw_path: &[u8],
    name: &[u8],
    reason: XattrWarningReason,
) {
    report.xattrs_dropped += 1;
    report.xattr_warnings.push(XattrWarning {
        raw_path: raw_path.to_vec(),
        name: name.to_vec(),
        reason,
    });
}

/// Walk each existing prefix of `output_root.join(rel)` and return
/// `true` if any component is a symlink. We use `symlink_metadata`
/// (which does **not** dereference) so the existence check itself
/// can't be defeated by a symlink loop.
fn parent_chain_has_symlink(output_root: &Path, rel: &Path) -> bool {
    let mut cursor = output_root.to_path_buf();
    let components: Vec<_> = rel.components().collect();
    // Walk parent components only — not the leaf. A symlink AT the
    // target itself is fine (we either refuse, overwrite, or
    // O_NOFOLLOW it depending on entry kind); what's dangerous is a
    // symlink in a parent that lets us write under a different
    // subtree.
    let parent_count = components.len().saturating_sub(1);
    for comp in components.iter().take(parent_count) {
        // Skip non-Normal components defensively. `..`/`/` are
        // already refused upstream; any oddity that survived
        // doesn't expand the cursor.
        if let Component::Normal(seg) = comp {
            cursor.push(seg);
            match std::fs::symlink_metadata(&cursor) {
                Ok(meta) if meta.file_type().is_symlink() => return true,
                _ => {
                    // Non-existent or non-symlink — keep walking.
                    // The non-existent case means later
                    // create_dir_all_under_root() will mkdir the
                    // remaining chain; a not-yet-existing path
                    // can't be a symlink trap.
                }
            }
        }
    }
    false
}

/// Write a regular file from `entry` to `target`, with O_NOFOLLOW,
/// zeroed timestamps (when `options.strip_timestamps`), and setuid /
/// setgid mode bits governed by [`UnpackOptions::setid_policy`].
///
/// Returns `Ok(())` on success, or a [`RefusalReason`] for caller-
/// recorded per-entry failures. Hard I/O errors propagate via
/// `Err(RefusalReason::MalformedHeader)` for now — a future
/// sub-phase may grow a distinct `IoError` variant if the
/// granularity matters for audit, but A.1's caller treats all
/// per-entry failures equivalently.
///
/// Non-Linux fallback only — on Linux writes route through
/// [`Rooted::write_regular_file`] (openat2-resolved).
#[cfg(not(target_os = "linux"))]
fn write_regular_file<R: Read>(
    entry: &mut tar::Entry<R>,
    target: &Path,
    raw_path: &[u8],
    options: &UnpackOptions,
    report: &mut UnpackReport,
) -> Result<(), RefusalReason> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    // Ensure parent directories exist. We've already verified no
    // existing parent is a symlink (safety check 5 in
    // `unpack_layer`), so `create_dir_all` here can't escape the
    // root via a planted symlink — only previously-existing host
    // directories could, and we trust the caller to give us a
    // clean `output_root`.
    if let Some(parent) = target.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return Err(RefusalReason::MalformedHeader);
        }
    }

    let mode_from_header =
        classify_regular_file_mode(entry.header().mode().unwrap_or(0o644), options)?;

    let mut opts = OpenOptions::new();
    opts.write(true)
        .create_new(true) // O_CREAT | O_EXCL — refuse to overwrite
        .mode(mode_from_header)
        .custom_flags(libc::O_NOFOLLOW);

    let mut file = match opts.open(target) {
        Ok(f) => f,
        Err(_) => return Err(RefusalReason::MalformedHeader),
    };

    if let Err(_e) = std::io::copy(entry, &mut file) {
        // The partial file is left on disk; the caller's pull
        // pipeline GCs the whole `output_root` on failure. A
        // tighter cleanup is possible but Phase A.1 keeps the
        // happy path simple.
        return Err(RefusalReason::MalformedHeader);
    }

    if let Err(_e) = file.flush() {
        return Err(RefusalReason::MalformedHeader);
    }

    // `open(2)` honors umask, and some kernels clear setuid/setgid
    // when file contents are modified. Apply the policy-classified
    // permissions after all writes through the file descriptor so the
    // on-disk result matches the tar mode without following paths.
    if file
        .set_permissions(std::fs::Permissions::from_mode(mode_from_header))
        .is_err()
    {
        return Err(RefusalReason::MalformedHeader);
    }
    record_setid_entry(report, raw_path, mode_from_header, options.setid_policy);

    if options.strip_timestamps {
        // `utimensat(AT_FDCWD, target, {0, 0})` via the `filetime`
        // crate's std-only equivalent. We use `set_file_mtime` /
        // `set_file_atime` from std-unstable / `filetime`... but
        // `filetime` isn't in our deps yet. Standard library has
        // no stable timestamp setter as of edition 2024; the
        // closest is `std::fs::File::set_modified` (stable in
        // 1.75), which takes `SystemTime`.
        use std::time::SystemTime;
        let _ = file.set_modified(SystemTime::UNIX_EPOCH);
    }

    Ok(())
}

fn classify_regular_file_mode(
    raw_mode: u32,
    options: &UnpackOptions,
) -> Result<u32, RefusalReason> {
    let low_mode = raw_mode & 0o0777;
    let setid_bits = raw_mode & SETID_MODE_BITS;
    if setid_bits == 0 {
        return Ok(low_mode);
    }

    match options.setid_policy {
        SetidPolicy::PreserveDev | SetidPolicy::PreserveVerified => Ok(low_mode | setid_bits),
        SetidPolicy::RefuseUnsigned => Err(RefusalReason::SetuidUnsigned),
    }
}

fn record_setid_entry(report: &mut UnpackReport, raw_path: &[u8], mode: u32, policy: SetidPolicy) {
    if mode & SETID_MODE_BITS == 0 {
        return;
    }

    report.setid_entries_preserved += 1;
    report.setid_entries.push(SetidEntry {
        raw_path: raw_path.to_vec(),
        mode,
        cosign_verified: policy == SetidPolicy::PreserveVerified,
    });
}

/// Create a directory at `target`. Returns `Ok(true)` if a new
/// directory was created, `Ok(false)` if it already existed. Tar
/// archives commonly list a directory entry both before its
/// children and as part of every parent chain, so coalescing
/// is correct and not a refusal.
///
/// Non-Linux fallback only — on Linux this routes through
/// [`Rooted::create_directory`] (openat2-resolved).
#[cfg(not(target_os = "linux"))]
fn create_directory(target: &Path) -> Result<bool, RefusalReason> {
    match std::fs::create_dir(target) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Parent doesn't exist — create the chain.
            if std::fs::create_dir_all(target).is_ok() {
                Ok(true)
            } else {
                Err(RefusalReason::MalformedHeader)
            }
        }
        Err(_) => Err(RefusalReason::MalformedHeader),
    }
}

/// Write a symlink whose location is `target` and whose link-text is
/// `link_target_bytes`. The link target is preserved verbatim — we
/// do not interpret it at unpack time. Refusal conditions:
///
/// - Link target bytes empty.
/// - Link target bytes contain a NUL.
/// - `symlink(2)` returns `EEXIST` (we don't overwrite).
///
/// Non-Linux fallback only — on Linux this routes through
/// [`Rooted::write_symlink`] (openat2-resolved `symlinkat`).
#[cfg(not(target_os = "linux"))]
fn write_symlink(link_target_bytes: Option<&[u8]>, target: &Path) -> Result<(), RefusalReason> {
    use std::os::unix::fs::symlink;

    let link_target = match link_target_bytes {
        Some(b) if !b.is_empty() && !b.contains(&0) => b,
        _ => return Err(RefusalReason::MalformedHeader),
    };

    if let Some(parent) = target.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return Err(RefusalReason::MalformedHeader);
        }
    }

    let link_os = OsStr::from_bytes(link_target);
    match symlink(link_os, target) {
        Ok(()) => Ok(()),
        Err(_) => Err(RefusalReason::MalformedHeader),
    }
}

enum HardlinkAction {
    Linked,
    Copied,
}

/// Materialize a tar hardlink entry at `target`.
///
/// Deliberately distinguishes same-layer and cross-layer
/// hardlinks. Same-layer targets become true hardlinks
/// because both paths belong to the layer currently being applied.
/// Lower-layer targets become full copies because aliasing a new
/// current-layer path to prior-layer inode state would make later
/// whiteout / mutation reasoning depend on host filesystem identity.
///
/// Non-Linux fallback only — on Linux this routes through
/// [`Rooted::materialize_hardlink`] (openat2-resolved `linkat`).
#[cfg(not(target_os = "linux"))]
fn materialize_hardlink(
    link_target_bytes: Option<&[u8]>,
    target: &Path,
    output_root: &Path,
    options: &UnpackOptions,
    current_layer_paths: &HashSet<PathBuf>,
) -> Result<HardlinkAction, RefusalReason> {
    let target_rel = validate_hardlink_target(link_target_bytes, output_root, options)?;
    let source = output_root.join(&target_rel);

    if parent_chain_has_symlink(output_root, &target_rel) {
        return Err(RefusalReason::SymlinkInParent);
    }
    if !source.starts_with(output_root) {
        return Err(RefusalReason::JoinedPathEscape);
    }

    let source_meta = match std::fs::symlink_metadata(&source) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(RefusalReason::HardlinkTargetMissing);
        }
        Err(_) => return Err(RefusalReason::MalformedHeader),
    };
    if !source_meta.file_type().is_file() {
        return Err(RefusalReason::MalformedHeader);
    }

    if let Some(parent) = target.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return Err(RefusalReason::MalformedHeader);
        }
    }

    if current_layer_paths.contains(&target_rel) {
        std::fs::hard_link(&source, target).map_err(|_| RefusalReason::MalformedHeader)?;
        Ok(HardlinkAction::Linked)
    } else {
        copy_existing_regular_file(&source, target, options).map(|()| HardlinkAction::Copied)
    }
}

fn validate_hardlink_target(
    link_target_bytes: Option<&[u8]>,
    output_root: &Path,
    options: &UnpackOptions,
) -> Result<PathBuf, RefusalReason> {
    let raw = match link_target_bytes {
        Some(b) if !b.is_empty() && !b.contains(&0) => b,
        _ => return Err(RefusalReason::MalformedHeader),
    };

    if raw.first() == Some(&b'/') {
        return Err(RefusalReason::AbsolutePath);
    }
    if raw.split(|b| *b == b'/').any(|seg| seg == b"..") {
        return Err(RefusalReason::TraversalSegment);
    }
    if raw.len() > options.max_path_len {
        return Err(RefusalReason::PathTooLong);
    }

    let rel = PathBuf::from(OsStr::from_bytes(raw));
    let joined = output_root.join(&rel);
    if !joined.starts_with(output_root) {
        return Err(RefusalReason::JoinedPathEscape);
    }
    Ok(rel)
}

#[cfg(not(target_os = "linux"))]
fn copy_existing_regular_file(
    source: &Path,
    target: &Path,
    options: &UnpackOptions,
) -> Result<(), RefusalReason> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let source_mode = std::fs::symlink_metadata(source)
        .map_err(|_| RefusalReason::MalformedHeader)?
        .mode()
        & 0o0777;

    let mut source_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)
        .map_err(|_| RefusalReason::MalformedHeader)?;

    let mut target_opts = OpenOptions::new();
    target_opts
        .write(true)
        .create_new(true)
        .mode(source_mode)
        .custom_flags(libc::O_NOFOLLOW);
    let mut target_file = target_opts
        .open(target)
        .map_err(|_| RefusalReason::MalformedHeader)?;

    std::io::copy(&mut source_file, &mut target_file)
        .map_err(|_| RefusalReason::MalformedHeader)?;
    target_file
        .flush()
        .map_err(|_| RefusalReason::MalformedHeader)?;

    if options.strip_timestamps {
        use std::time::SystemTime;
        let _ = target_file.set_modified(SystemTime::UNIX_EPOCH);
    }

    Ok(())
}

/// Tells the dispatch loop whether a regular-file tar entry is
/// actually an OCI whiteout marker and, if so, which kind.
///
/// Decided strictly from the **leaf filename**. The path's parent
/// chain is irrelevant for classification (a directory named `.wh.X`
/// is legitimate as an intermediate component); only the last
/// segment carries the marker semantic.
enum WhiteoutKind<'a> {
    /// Not a whiteout — treat as a regular file write.
    None,
    /// `.wh..wh..opq` — clear parent dir's prior contents.
    Opaque,
    /// `.wh.<name>` — remove sibling. Inner slice is `<name>` (the
    /// suffix after the four-byte `.wh.` prefix).
    Regular(&'a [u8]),
    /// `.wh.` exactly (empty suffix) — wire-format violation, refused.
    Malformed,
}

fn classify_whiteout(raw_path: &[u8]) -> WhiteoutKind<'_> {
    // Leaf filename = bytes after the last `/`. For root-level paths
    // with no `/`, the whole path is the filename.
    let leaf = match raw_path.iter().rposition(|b| *b == b'/') {
        Some(idx) => &raw_path[idx + 1..],
        None => raw_path,
    };

    if leaf == WHITEOUT_OPAQUE {
        return WhiteoutKind::Opaque;
    }
    if !leaf.starts_with(WHITEOUT_PREFIX) {
        return WhiteoutKind::None;
    }
    let suffix = &leaf[WHITEOUT_PREFIX.len()..];
    if suffix.is_empty() {
        return WhiteoutKind::Malformed;
    }
    WhiteoutKind::Regular(suffix)
}

/// Apply a `.wh.<name>` whiteout: remove the sibling file or
/// directory tree at `target` if it exists, except for paths written
/// by the layer currently being applied. OCI whiteouts apply to
/// lower/parent layers only; same-layer entries survive regardless
/// of marker ordering in the tar stream.
///
/// `output_root` is passed so the caller's safety envelope continues
/// to apply — we re-assert `target` lives under it before any
/// filesystem mutation. The check is defense-in-depth: the entry's
/// path already passed every A.1 safety check, and the sibling
/// shares the same parent chain, so this branch should be
/// unreachable for any non-malicious caller wiring.
fn apply_regular_whiteout(
    target: &Path,
    target_rel: &Path,
    output_root: &Path,
    current_layer_paths: &HashSet<PathBuf>,
) -> Result<(), RefusalReason> {
    if !target.starts_with(output_root) {
        return Err(RefusalReason::JoinedPathEscape);
    }

    // `symlink_metadata` doesn't follow symlinks — important so a
    // sibling symlink-to-elsewhere gets removed as a symlink rather
    // than the unpacker dereferencing it and acting on whatever it
    // points at. The corresponding `remove_file` call deletes the
    // symlink, not its target.
    match std::fs::symlink_metadata(target) {
        Ok(meta) if meta.file_type().is_dir() => {
            remove_tree_except_current_layer(target, target_rel, current_layer_paths)
        }
        Ok(_) if current_layer_paths.contains(target_rel) => Ok(()),
        Ok(_) => match std::fs::remove_file(target) {
            Ok(()) => Ok(()),
            Err(_) => Err(RefusalReason::MalformedHeader),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RefusalReason::MalformedHeader),
    }
}

/// Apply a `.wh..wh..opq` opaque whiteout: clear `target_dir`'s
/// lower-layer contents, preserving the directory itself and any
/// same-layer entries below it. OCI says opaque markers are applied
/// before sibling entries regardless of archive ordering; preserving
/// same-layer paths gives that result without buffering the whole
/// layer.
///
/// Same `output_root` defense-in-depth check as the regular
/// whiteout: re-assert the target dir lives under root.
fn apply_opaque_whiteout(
    target_dir: &Path,
    target_rel: &Path,
    output_root: &Path,
    current_layer_paths: &HashSet<PathBuf>,
) -> Result<(), RefusalReason> {
    if !target_dir.starts_with(output_root) {
        return Err(RefusalReason::JoinedPathEscape);
    }

    remove_children_except_current_layer(target_dir, target_rel, current_layer_paths)
}

fn remove_tree_except_current_layer(
    target: &Path,
    target_rel: &Path,
    current_layer_paths: &HashSet<PathBuf>,
) -> Result<(), RefusalReason> {
    if !has_current_layer_path_at_or_below(target_rel, current_layer_paths) {
        return std::fs::remove_dir_all(target).map_err(|_| RefusalReason::MalformedHeader);
    }

    remove_children_except_current_layer(target, target_rel, current_layer_paths)
}

fn remove_children_except_current_layer(
    target_dir: &Path,
    target_rel: &Path,
    current_layer_paths: &HashSet<PathBuf>,
) -> Result<(), RefusalReason> {
    let read_dir = match std::fs::read_dir(target_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(RefusalReason::MalformedHeader),
    };

    for child in read_dir {
        let child = match child {
            Ok(c) => c,
            Err(_) => return Err(RefusalReason::MalformedHeader),
        };
        let child_path = child.path();
        let child_rel = target_rel.join(child.file_name());
        let file_type = match child.file_type() {
            Ok(ft) => ft,
            Err(_) => return Err(RefusalReason::MalformedHeader),
        };
        if current_layer_paths.contains(&child_rel) {
            if file_type.is_dir() {
                remove_children_except_current_layer(&child_path, &child_rel, current_layer_paths)?;
            }
            continue;
        }
        if file_type.is_dir() && has_current_layer_path_below(&child_rel, current_layer_paths) {
            remove_children_except_current_layer(&child_path, &child_rel, current_layer_paths)?;
            continue;
        }
        let removed = if file_type.is_dir() {
            std::fs::remove_dir_all(&child_path)
        } else {
            std::fs::remove_file(&child_path)
        };
        if removed.is_err() {
            return Err(RefusalReason::MalformedHeader);
        }
    }
    Ok(())
}

fn has_current_layer_path_at_or_below(rel: &Path, current_layer_paths: &HashSet<PathBuf>) -> bool {
    current_layer_paths
        .iter()
        .any(|written| written == rel || written.starts_with(rel))
}

fn has_current_layer_path_below(rel: &Path, current_layer_paths: &HashSet<PathBuf>) -> bool {
    current_layer_paths
        .iter()
        .any(|written| written != rel && written.starts_with(rel))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

    /// Helper — build a tar archive in memory from a list of
    /// `(header_setup, body)` closures. Returns the archive bytes.
    fn build_tar(setup: impl FnOnce(&mut tar::Builder<Cursor<Vec<u8>>>)) -> Vec<u8> {
        let buf = Cursor::new(Vec::new());
        let mut builder = tar::Builder::new(buf);
        setup(&mut builder);
        builder.into_inner().unwrap().into_inner()
    }

    /// Add a regular file with the given content + relative path.
    fn add_file(builder: &mut tar::Builder<Cursor<Vec<u8>>>, path: &str, body: &[u8]) {
        add_file_with_mode(builder, path, body, 0o644);
    }

    /// Add a regular file with an explicit tar mode.
    fn add_file_with_mode(
        builder: &mut tar::Builder<Cursor<Vec<u8>>>,
        path: &str,
        body: &[u8],
        mode: u32,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_size(body.len() as u64);
        header.set_mode(mode);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append(&header, body).unwrap();
    }

    /// Add a regular file preceded by pax xattr records.
    fn add_file_with_pax_xattrs(
        builder: &mut tar::Builder<Cursor<Vec<u8>>>,
        path: &str,
        body: &[u8],
        xattrs: &[(&str, &[u8])],
    ) {
        builder
            .append_pax_extensions(xattrs.iter().copied())
            .unwrap();
        add_file(builder, path, body);
    }

    /// Add a directory entry.
    fn add_dir(builder: &mut tar::Builder<Cursor<Vec<u8>>>, path: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder.append(&header, std::io::empty()).unwrap();
    }

    /// Add a symlink.
    fn add_symlink(builder: &mut tar::Builder<Cursor<Vec<u8>>>, path: &str, link_target: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_size(0);
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name(link_target).unwrap();
        header.set_cksum();
        builder.append(&header, std::io::empty()).unwrap();
    }

    /// Add a hardlink entry.
    fn add_hardlink(builder: &mut tar::Builder<Cursor<Vec<u8>>>, path: &str, link_target: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name(link_target).unwrap();
        header.set_cksum();
        builder.append(&header, std::io::empty()).unwrap();
    }

    /// Add a character or block device entry.
    fn add_device_node(
        builder: &mut tar::Builder<Cursor<Vec<u8>>>,
        path: &str,
        entry_type: tar::EntryType,
        major: u32,
        minor: u32,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_size(0);
        header.set_mode(0o666);
        header.set_entry_type(entry_type);
        header.set_device_major(major).unwrap();
        header.set_device_minor(minor).unwrap();
        header.set_cksum();
        builder.append(&header, std::io::empty()).unwrap();
    }

    #[test]
    fn happy_path_writes_files_dirs_symlinks() {
        let tar_bytes = build_tar(|b| {
            add_dir(b, "etc/");
            add_file(b, "etc/hostname", b"alpine\n");
            add_dir(b, "bin/");
            add_file(b, "bin/sh", b"#!fake busybox\n");
            add_symlink(b, "bin/busybox", "sh");
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack happy path");

        assert_eq!(report.files_written, 2, "etc/hostname + bin/sh");
        // Directories: etc/, bin/, plus implicit parents for files
        // we may or may not have created via create_dir_all. We
        // assert ≥ 2 (the two explicit Directory entries).
        assert!(report.dirs_created >= 2, "got {}", report.dirs_created);
        assert_eq!(report.symlinks_written, 1);
        assert!(report.refused.is_empty(), "{:?}", report.refused);

        // Verify files actually exist on disk.
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("etc/hostname")).unwrap(),
            "alpine\n"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("bin/sh")).unwrap(),
            "#!fake busybox\n"
        );
        // Symlink resolves textually to "sh"; the link itself is at
        // bin/busybox.
        let link = std::fs::read_link(tmp.path().join("bin/busybox")).unwrap();
        assert_eq!(link.to_str().unwrap(), "sh");
    }

    /// Build a single-entry tar archive with a hand-rolled USTAR
    /// header whose path field carries `path_bytes` verbatim. This
    /// bypasses `tar::Header::set_path`'s built-in refusals (leading
    /// `/`, `..` segments, length > 100) so we can produce
    /// adversarial inputs that the unpacker is supposed to reject.
    /// Returns the archive bytes (header + 1024 bytes of EOF zero
    /// blocks).
    fn handrolled_tar_with_path(path_bytes: &[u8], entry_type: u8) -> Vec<u8> {
        // The USTAR `name` field is 100 bytes (offset 0..100) plus
        // an optional 155-byte `prefix` field (offset 345..500). For
        // paths up to 100 bytes we fill `name`; longer paths split
        // at any `/`, with the prefix going into `prefix` and the
        // remainder into `name`. For the adversarial-fixture path
        // we test, the *whole* path is short enough to fit in
        // `name` even when it includes `..` segments.
        //
        // For paths > 100 bytes the cleanest way to bypass
        // `set_path`'s refusal is to use the GNU long-name extension
        // (entry typeflag `L`, name = `././@LongLink`, body = the
        // real path, followed by a normal-typeflag entry whose own
        // header carries the *truncated* path). We don't go there —
        // tests that exercise > 100 byte paths use the GNU writer
        // path via `tar::Builder` (which IS happy to emit GNU
        // long-name records) or simply set
        // `UnpackOptions::max_path_len` low enough that a 100-byte
        // path is already over the cap.
        assert!(
            path_bytes.len() <= 100,
            "handrolled_tar_with_path only handles USTAR name-field paths (≤100 bytes); got {}",
            path_bytes.len()
        );

        let mut header = [0u8; 512];
        header[..path_bytes.len()].copy_from_slice(path_bytes);
        // mode 0644
        header[100..108].copy_from_slice(b"0000644\0");
        // uid 0
        header[108..116].copy_from_slice(b"0000000\0");
        // gid 0
        header[116..124].copy_from_slice(b"0000000\0");
        // size = 0
        header[124..136].copy_from_slice(b"00000000000\0");
        // mtime = 0
        header[136..148].copy_from_slice(b"00000000000\0");
        // typeflag
        header[156] = entry_type;
        // USTAR magic + version
        header[257..265].copy_from_slice(b"ustar  \0");
        // Checksum: sum of every byte in the header with the
        // checksum field itself treated as 8 spaces.
        header[148..156].copy_from_slice(b"        ");
        let cksum: u32 = header.iter().map(|&b| b as u32).sum();
        let s = format!("{:06o}\0 ", cksum);
        header[148..156].copy_from_slice(s.as_bytes());

        let mut tar_bytes = header.to_vec();
        // Two 512-byte zero blocks = end-of-archive.
        tar_bytes.extend_from_slice(&[0u8; 1024]);
        tar_bytes
    }

    #[test]
    fn refuses_absolute_path() {
        // `tar::Header::set_path` strips a leading `/`, so we
        // hand-craft a USTAR header to put the literal absolute-path
        // bytes on the wire. Mirrors the path bytes a malicious
        // remote image could ship.
        let tar_bytes = handrolled_tar_with_path(b"/etc/passwd", b'0');
        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack should succeed with refusals, not error");

        assert_eq!(report.files_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::AbsolutePath);
        assert!(
            !tmp.path().join("etc/passwd").exists(),
            "absolute-path entry must not write outside output_root"
        );
    }

    #[test]
    fn refuses_traversal_segment() {
        // `tar::Header::set_path` refuses `..` segments at construction
        // time ("paths in archives must not have `..`"), so we
        // hand-roll a USTAR header to test the unpacker's own
        // segment-by-segment refusal.
        let tar_bytes = handrolled_tar_with_path(b"foo/../escape", b'0');
        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::TraversalSegment);
        // Sister test: `..foo` (no trailing slash) is *not* a
        // traversal; it's a single segment with a valid filename
        // that happens to begin with two dots. Confirm the
        // segment-by-segment check doesn't false-positive on it.
        let tar_bytes2 = handrolled_tar_with_path(b"..foo", b'0');
        let tmp2 = TempDir::new().unwrap();
        let report2 = unpack_layer(
            Cursor::new(tar_bytes2),
            tmp2.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");
        // `..foo` is a valid filename — accepted as a regular file.
        assert_eq!(report2.files_written, 1, "{:?}", report2.refused);
        assert!(report2.refused.is_empty());
    }

    #[test]
    fn refuses_path_too_long() {
        // Use a single-segment 64-byte name + a low max_path_len
        // so the cap fires without needing GNU long-name extensions.
        let path = b"x".repeat(64);
        let tar_bytes = handrolled_tar_with_path(&path, b'0');
        let tmp = TempDir::new().unwrap();
        let opts = UnpackOptions {
            max_path_len: 32,
            ..UnpackOptions::default()
        };
        let report = unpack_layer(Cursor::new(tar_bytes), tmp.path(), &opts).expect("unpack ok");

        assert_eq!(report.files_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::PathTooLong);
    }

    #[test]
    fn hardlink_to_same_layer_target_materializes_as_hardlink() {
        let tar_bytes = build_tar(|b| {
            add_file(b, "real", b"data");
            add_hardlink(b, "alias", "real");
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.hardlinks_written, 1);
        assert_eq!(report.hardlink_copies_written, 0);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("alias")).unwrap(),
            "data"
        );

        use std::os::unix::fs::MetadataExt;
        let real = std::fs::metadata(tmp.path().join("real")).unwrap();
        let alias = std::fs::metadata(tmp.path().join("alias")).unwrap();
        assert_eq!(real.dev(), alias.dev());
        assert_eq!(real.ino(), alias.ino());
    }

    #[test]
    fn refuses_write_under_symlinked_parent() {
        // Layer entries (in order):
        //   1. symlink `bin -> /tmp`  — itself an in-root location
        //   2. regular file `bin/escape` — would land in /tmp/escape
        //      without the parent-chain-symlink check.
        // Expected: entry 1 writes (in-root location); entry 2 is
        // refused with SymlinkInParent.
        let tar_bytes = build_tar(|b| {
            add_symlink(b, "bin", "/tmp");
            add_file(b, "bin/escape", b"do not write");
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.symlinks_written, 1);
        assert_eq!(report.files_written, 0);
        assert_eq!(report.refused.len(), 1);
        assert_eq!(report.refused[0].reason, RefusalReason::SymlinkInParent);
        // Confirm we didn't actually write through the symlink.
        assert!(!std::path::Path::new("/tmp/escape").exists());
    }

    #[test]
    fn rejects_relative_output_root() {
        let err = unpack_layer(
            Cursor::new(Vec::new()),
            Path::new("relative/path"),
            &UnpackOptions::default(),
        )
        .expect_err("relative output_root must be rejected");

        assert!(matches!(err, UnpackError::NonAbsoluteOutputRoot(_)));
    }

    #[test]
    fn rejects_nonexistent_output_root() {
        let err = unpack_layer(
            Cursor::new(Vec::new()),
            Path::new("/nonexistent/path/under/root"),
            &UnpackOptions::default(),
        )
        .expect_err("missing output_root must be rejected");

        assert!(matches!(err, UnpackError::OutputRootNotADir(_)));
    }

    #[test]
    fn reproducibility_two_unpacks_match_modulo_inode() {
        // Same layer, two clean output_roots — every regular file
        // should have mtime 0 in both. We can't compare inode-level
        // equality across two trees, but mtime stripping is the
        // load-bearing property for the upstream `mkfs.ext4` step
        // to produce byte-identical ext4 images.
        let tar_bytes = build_tar(|b| {
            add_file(b, "a", b"x");
            add_file(b, "b", b"y");
        });
        let tmp1 = TempDir::new().unwrap();
        let tmp2 = TempDir::new().unwrap();
        unpack_layer(
            Cursor::new(tar_bytes.clone()),
            tmp1.path(),
            &UnpackOptions::default(),
        )
        .unwrap();
        unpack_layer(
            Cursor::new(tar_bytes),
            tmp2.path(),
            &UnpackOptions::default(),
        )
        .unwrap();

        let m1 = std::fs::metadata(tmp1.path().join("a")).unwrap();
        let m2 = std::fs::metadata(tmp2.path().join("a")).unwrap();
        assert_eq!(m1.modified().unwrap(), std::time::SystemTime::UNIX_EPOCH);
        assert_eq!(m2.modified().unwrap(), std::time::SystemTime::UNIX_EPOCH);
        assert_eq!(m1.modified().unwrap(), m2.modified().unwrap());
    }

    #[test]
    fn refusal_audit_tags_are_stable_and_safe() {
        // Pin the wire format of `audit_tag` — these strings end
        // up in audit chain entries (claim 10), so they must never
        // contain spaces, equals signs, commas, or
        // newlines (which would confuse the existing audit-emit
        // `key=value` parser).
        let all = [
            RefusalReason::AbsolutePath,
            RefusalReason::TraversalSegment,
            RefusalReason::PathTooLong,
            RefusalReason::JoinedPathEscape,
            RefusalReason::SymlinkInParent,
            RefusalReason::HardlinkTargetMissing,
            RefusalReason::DeviceNodeRefused,
            RefusalReason::SetuidUnsigned,
            RefusalReason::UnsupportedEntryType,
            RefusalReason::MalformedHeader,
        ];
        for r in all {
            let t = r.audit_tag();
            assert!(!t.is_empty(), "{r:?}");
            assert!(!t.contains(' '), "{r:?} -> {t:?}");
            assert!(!t.contains('='), "{r:?} -> {t:?}");
            assert!(!t.contains(','), "{r:?} -> {t:?}");
            assert!(!t.contains('\n'), "{r:?} -> {t:?}");
        }
    }

    // ── policy-controlled setuid/setgid bits ───────────

    #[test]
    fn default_setid_policy_preserves_setuid_file_with_audit_annotation() {
        use std::os::unix::fs::MetadataExt;

        let tar_bytes = build_tar(|b| {
            add_file_with_mode(b, "usr/bin/helper", b"#!/bin/sh\n", 0o4755);
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.setid_entries_preserved, 1);
        assert_eq!(report.setid_entries.len(), 1);
        assert_eq!(report.setid_entries[0].raw_path, b"usr/bin/helper");
        assert_eq!(report.setid_entries[0].mode, 0o4755);
        assert!(!report.setid_entries[0].cosign_verified);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert_eq!(
            std::fs::symlink_metadata(tmp.path().join("usr/bin/helper"))
                .unwrap()
                .mode()
                & 0o7777,
            0o4755
        );
    }

    #[test]
    fn unsigned_production_setid_policy_refuses_setuid_file() {
        let tar_bytes = build_tar(|b| {
            add_file_with_mode(b, "usr/bin/helper", b"#!/bin/sh\n", 0o4755);
        });

        let tmp = TempDir::new().unwrap();
        let opts = UnpackOptions {
            setid_policy: SetidPolicy::RefuseUnsigned,
            ..UnpackOptions::default()
        };
        let report = unpack_layer(Cursor::new(tar_bytes), tmp.path(), &opts).expect("unpack ok");

        assert_eq!(report.files_written, 0);
        assert_eq!(report.setid_entries_preserved, 0);
        assert!(report.setid_entries.is_empty());
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].raw_path, b"usr/bin/helper");
        assert_eq!(report.refused[0].reason, RefusalReason::SetuidUnsigned);
        assert_eq!(
            report.refused[0].reason.audit_tag(),
            "E_OCI_SETUID_UNSIGNED"
        );
        assert!(!tmp.path().join("usr/bin/helper").exists());
    }

    #[test]
    fn unsigned_production_setid_policy_refuses_setgid_file() {
        let tar_bytes = build_tar(|b| {
            add_file_with_mode(b, "usr/bin/group-helper", b"#!/bin/sh\n", 0o2755);
        });

        let tmp = TempDir::new().unwrap();
        let opts = UnpackOptions {
            setid_policy: SetidPolicy::RefuseUnsigned,
            ..UnpackOptions::default()
        };
        let report = unpack_layer(Cursor::new(tar_bytes), tmp.path(), &opts).expect("unpack ok");

        assert_eq!(report.files_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::SetuidUnsigned);
        assert!(!tmp.path().join("usr/bin/group-helper").exists());
    }

    #[test]
    fn verified_setid_policy_preserves_setgid_file_with_verified_annotation() {
        use std::os::unix::fs::MetadataExt;

        let tar_bytes = build_tar(|b| {
            add_file_with_mode(b, "usr/bin/group-helper", b"#!/bin/sh\n", 0o2755);
        });

        let tmp = TempDir::new().unwrap();
        let opts = UnpackOptions {
            setid_policy: SetidPolicy::PreserveVerified,
            ..UnpackOptions::default()
        };
        let report = unpack_layer(Cursor::new(tar_bytes), tmp.path(), &opts).expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.setid_entries_preserved, 1);
        assert_eq!(report.setid_entries[0].raw_path, b"usr/bin/group-helper");
        assert_eq!(report.setid_entries[0].mode, 0o2755);
        assert!(report.setid_entries[0].cosign_verified);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert_eq!(
            std::fs::symlink_metadata(tmp.path().join("usr/bin/group-helper"))
                .unwrap()
                .mode()
                & 0o7777,
            0o2755
        );
    }

    #[test]
    fn unsigned_production_setid_policy_allows_regular_file_without_setid_bits() {
        let tar_bytes = build_tar(|b| {
            add_file_with_mode(b, "usr/bin/tool", b"#!/bin/sh\n", 0o755);
        });

        let tmp = TempDir::new().unwrap();
        let opts = UnpackOptions {
            setid_policy: SetidPolicy::RefuseUnsigned,
            ..UnpackOptions::default()
        };
        let report = unpack_layer(Cursor::new(tar_bytes), tmp.path(), &opts).expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.setid_entries_preserved, 0);
        assert!(report.setid_entries.is_empty());
        assert!(report.refused.is_empty(), "{:?}", report.refused);
    }

    // ── allow-listed pax xattrs ───────────────────────

    #[test]
    fn xattr_policy_allowlist_accepts_only_plan85_names() {
        assert_eq!(
            classify_xattr_name(XattrPolicy::PreserveAllowlisted, b"user.mvm.test"),
            Ok(())
        );
        assert_eq!(
            classify_xattr_name(XattrPolicy::PreserveAllowlisted, b"security.capability"),
            Ok(())
        );
        assert_eq!(
            classify_xattr_name(XattrPolicy::PreserveAllowlisted, b"security.selinux"),
            Ok(())
        );
        assert_eq!(
            classify_xattr_name(XattrPolicy::PreserveAllowlisted, b"trusted.overlay.opaque"),
            Err(XattrWarningReason::NotAllowlisted)
        );
        assert_eq!(
            classify_xattr_name(XattrPolicy::DropAll, b"user.mvm.test"),
            Err(XattrWarningReason::PolicyDropAll)
        );
        assert_eq!(
            classify_xattr_name(XattrPolicy::PreserveAllowlisted, b""),
            Err(XattrWarningReason::MalformedName)
        );
    }

    #[test]
    fn allowed_user_xattr_is_preserved_when_host_supports_xattrs() {
        let probe = TempDir::new().unwrap();
        let probe_file = probe.path().join("probe");
        std::fs::write(&probe_file, b"probe").unwrap();
        if xattr::set(&probe_file, "user.mvm.probe", b"1").is_err() {
            eprintln!(
                "skipping xattr preservation assertion: host filesystem rejected user.* xattrs"
            );
            return;
        }

        let tar_bytes = build_tar(|b| {
            add_file_with_pax_xattrs(
                b,
                "bin/tool",
                b"run\n",
                &[("SCHILY.xattr.user.mvm.test", b"ok".as_slice())],
            );
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.xattrs_written, 1);
        assert_eq!(report.xattrs_dropped, 0);
        assert!(
            report.xattr_warnings.is_empty(),
            "{:?}",
            report.xattr_warnings
        );
        assert_eq!(
            xattr::get(tmp.path().join("bin/tool"), "user.mvm.test").unwrap(),
            Some(b"ok".to_vec())
        );
    }

    #[test]
    fn denied_xattr_is_dropped_with_warning() {
        let tar_bytes = build_tar(|b| {
            add_file_with_pax_xattrs(
                b,
                "bin/tool",
                b"run\n",
                &[("SCHILY.xattr.trusted.overlay.opaque", b"y".as_slice())],
            );
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.xattrs_written, 0);
        assert_eq!(report.xattrs_dropped, 1);
        assert_eq!(report.xattr_warnings.len(), 1);
        assert_eq!(report.xattr_warnings[0].raw_path, b"bin/tool");
        assert_eq!(report.xattr_warnings[0].name, b"trusted.overlay.opaque");
        assert_eq!(
            report.xattr_warnings[0].reason,
            XattrWarningReason::NotAllowlisted
        );
        assert!(report.refused.is_empty(), "{:?}", report.refused);
    }

    #[test]
    fn drop_all_xattr_policy_drops_allowlisted_xattr() {
        let tar_bytes = build_tar(|b| {
            add_file_with_pax_xattrs(
                b,
                "bin/tool",
                b"run\n",
                &[("SCHILY.xattr.user.mvm.test", b"ok".as_slice())],
            );
        });

        let tmp = TempDir::new().unwrap();
        let opts = UnpackOptions {
            xattr_policy: XattrPolicy::DropAll,
            ..UnpackOptions::default()
        };
        let report = unpack_layer(Cursor::new(tar_bytes), tmp.path(), &opts).expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.xattrs_written, 0);
        assert_eq!(report.xattrs_dropped, 1);
        assert_eq!(
            report.xattr_warnings[0].reason,
            XattrWarningReason::PolicyDropAll
        );
    }

    // ── allow-listed device nodes ───────────────────────

    #[test]
    fn device_node_allowlist_accepts_only_expected_char_devices() {
        for allowed in ALLOWED_DEVICE_NODES {
            assert_eq!(
                classify_device_node(
                    tar::EntryType::Char,
                    allowed.path,
                    Some(allowed.major),
                    Some(allowed.minor),
                ),
                Ok(*allowed)
            );
        }

        assert_eq!(
            classify_device_node(tar::EntryType::Block, b"dev/null", Some(1), Some(3)),
            Err(RefusalReason::DeviceNodeRefused)
        );
        assert_eq!(
            classify_device_node(tar::EntryType::Char, b"dev/tty", Some(5), Some(0)),
            Err(RefusalReason::DeviceNodeRefused)
        );
        assert_eq!(
            classify_device_node(tar::EntryType::Char, b"dev/null", Some(1), Some(5)),
            Err(RefusalReason::DeviceNodeRefused)
        );
        assert_eq!(
            classify_device_node(tar::EntryType::Char, b"./dev/null", Some(1), Some(3)),
            Err(RefusalReason::DeviceNodeRefused)
        );
        assert_eq!(
            classify_device_node(tar::EntryType::Char, b"dev/null", None, Some(3)),
            Err(RefusalReason::DeviceNodeRefused)
        );
    }

    #[test]
    fn disallowed_character_device_is_refused() {
        let tar_bytes = build_tar(|b| {
            add_device_node(b, "dev/tty", tar::EntryType::Char, 5, 0);
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.device_nodes_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::DeviceNodeRefused);
        assert!(!tmp.path().join("dev/tty").exists());
    }

    #[test]
    fn block_device_is_refused_even_when_path_matches_allowlist() {
        let tar_bytes = build_tar(|b| {
            add_device_node(b, "dev/null", tar::EntryType::Block, 1, 3);
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.device_nodes_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::DeviceNodeRefused);
        assert!(!tmp.path().join("dev/null").exists());
    }

    #[test]
    fn allowed_device_node_under_symlinked_parent_refuses() {
        let tar_bytes = build_tar(|b| {
            add_symlink(b, "dev", "/tmp");
            add_device_node(b, "dev/null", tar::EntryType::Char, 1, 3);
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.symlinks_written, 1);
        assert_eq!(report.device_nodes_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::SymlinkInParent);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn allowed_device_node_materializes_when_host_permits_mknod() {
        use rustix::fs::{CWD, FileType, Mode, makedev, mknodat};
        use std::os::unix::fs::FileTypeExt;

        let tmp = TempDir::new().unwrap();
        let probe = tmp.path().join("probe-null");
        let mode = Mode::from_raw_mode(0o600);
        let dev = makedev(1, 3);
        if mknodat(CWD, &probe, FileType::CharacterDevice, mode, dev).is_err() {
            eprintln!("skipping device-node materialization assertion: mknod not permitted");
            return;
        }
        std::fs::remove_file(&probe).unwrap();

        let tar_bytes = build_tar(|b| {
            add_device_node(b, "dev/null", tar::EntryType::Char, 1, 3);
        });
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.device_nodes_written, 1);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        let meta = std::fs::symlink_metadata(tmp.path().join("dev/null")).unwrap();
        assert!(meta.file_type().is_char_device());
    }

    // ── OCI whiteout + opaque marker semantics ────────

    #[test]
    fn whiteout_removes_prior_layer_sibling_file() {
        // The output tree can already contain lower-layer state
        // before this layer is applied. A sibling `.wh.<name>` marker
        // removes that prior file. The marker itself is not
        // materialized.
        let tar_bytes = build_tar(|b| {
            add_dir(b, "etc/");
            add_file(b, "etc/.wh.passwd", b"");
        });

        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("etc")).unwrap();
        std::fs::write(
            tmp.path().join("etc/passwd"),
            b"root:x:0:0::/root:/bin/sh\n",
        )
        .unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 0);
        assert_eq!(report.whiteouts_applied, 1);
        assert_eq!(report.opaque_markers_applied, 0);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert!(
            !tmp.path().join("etc/passwd").exists(),
            "whiteout should have removed etc/passwd"
        );
        assert!(
            !tmp.path().join("etc/.wh.passwd").exists(),
            "whiteout marker itself must not be materialized in the output tree"
        );
    }

    #[test]
    fn whiteout_does_not_hide_same_layer_file_when_marker_appears_later() {
        // OCI whiteouts hide only lower-layer entries. Same-layer
        // entries survive even if a tar stream places the whiteout
        // marker after the file.
        let tar_bytes = build_tar(|b| {
            add_dir(b, "etc/");
            add_file(b, "etc/passwd", b"new\n");
            add_file(b, "etc/.wh.passwd", b"");
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.whiteouts_applied, 1);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("etc/passwd")).unwrap(),
            "new\n"
        );
        assert!(!tmp.path().join("etc/.wh.passwd").exists());
    }

    #[test]
    fn whiteout_with_absent_target_is_idempotent_noop() {
        // OCI single-layer apply is declarative — a `.wh.<name>`
        // whose target doesn't exist is still a successful apply
        // (the marker has been consumed). Counter still increments.
        let tar_bytes = build_tar(|b| {
            add_dir(b, "etc/");
            add_file(b, "etc/.wh.ghost", b"");
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.whiteouts_applied, 1);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert!(!tmp.path().join("etc/.wh.ghost").exists());
        assert!(!tmp.path().join("etc/ghost").exists());
    }

    #[test]
    fn whiteout_removes_sibling_directory_recursively() {
        // A whiteout on a lower-layer directory takes that whole
        // subtree out. remove_dir_all is the right primitive — we
        // use symlink_metadata first so we don't accidentally walk a
        // symlink-to-elsewhere as a directory.
        let tar_bytes = build_tar(|b| {
            add_dir(b, "etc/");
            add_file(b, "etc/.wh.sub", b"");
        });

        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("etc/sub")).unwrap();
        std::fs::write(tmp.path().join("etc/sub/a"), b"one").unwrap();
        std::fs::write(tmp.path().join("etc/sub/b"), b"two").unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.whiteouts_applied, 1);
        assert!(!tmp.path().join("etc/sub").exists());
        assert!(!tmp.path().join("etc/sub/a").exists());
        assert!(!tmp.path().join("etc/sub/b").exists());
        assert!(tmp.path().join("etc").is_dir(), "parent etc/ must remain");
    }

    #[test]
    fn opaque_whiteout_clears_parent_contents_preserving_directory() {
        // `.wh..wh..opq` clears the parent dir's prior-layer
        // contents but keeps the dir itself. Entries from the
        // current layer survive even when the marker appears later
        // in the tar stream.
        let tar_bytes = build_tar(|b| {
            add_dir(b, "etc/");
            add_file(b, "etc/a", b"alpha");
            add_dir(b, "etc/sub/");
            add_file(b, "etc/sub/c", b"gamma");
            add_file(b, "etc/.wh..wh..opq", b"");
        });

        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("etc/sub")).unwrap();
        std::fs::write(tmp.path().join("etc/old"), b"old").unwrap();
        std::fs::write(tmp.path().join("etc/sub/old"), b"old").unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.opaque_markers_applied, 1);
        assert_eq!(report.whiteouts_applied, 0);
        assert!(report.refused.is_empty(), "{:?}", report.refused);

        // The parent dir survives; prior contents are gone, while
        // current-layer entries remain.
        assert!(tmp.path().join("etc").is_dir(), "etc/ must remain");
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("etc/a")).unwrap(),
            "alpha"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("etc/sub/c")).unwrap(),
            "gamma"
        );
        assert!(!tmp.path().join("etc/old").exists());
        assert!(!tmp.path().join("etc/sub/old").exists());
        // The opaque marker itself is not materialized.
        assert!(!tmp.path().join("etc/.wh..wh..opq").exists());
    }

    #[test]
    fn whiteout_under_symlinked_parent_refuses_like_a_regular_write() {
        // CVE-class guard: a `.wh.passwd` under a symlinked `etc/`
        // must refuse with SymlinkInParent, same as a regular-file
        // write would. Otherwise a malicious layer could write
        // `etc -> /tmp` then `etc/.wh.passwd` and trick the
        // unpacker into removing `/tmp/passwd`.
        let tar_bytes = build_tar(|b| {
            add_symlink(b, "etc", "/tmp");
            add_file(b, "etc/.wh.passwd", b"");
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.symlinks_written, 1);
        assert_eq!(report.whiteouts_applied, 0);
        assert_eq!(report.refused.len(), 1);
        assert_eq!(report.refused[0].reason, RefusalReason::SymlinkInParent);
    }

    #[test]
    fn whiteout_with_traversal_in_path_refuses() {
        // `.wh.foo` is a fine filename; `foo/../.wh.bar` is not — the
        // traversal segment in the parent chain must refuse before
        // the whiteout dispatch even runs.
        let tar_bytes = handrolled_tar_with_path(b"foo/../.wh.bar", b'0');
        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::TraversalSegment);
        assert_eq!(report.whiteouts_applied, 0);
    }

    #[test]
    fn malformed_whiteout_marker_with_empty_suffix_refused() {
        // `.wh.` exactly (no suffix) is a wire-format violation per
        // OCI v1.1 §"Layer Filesystem Changeset" — every whiteout
        // either names a sibling (`.wh.<name>`) or is the magic
        // opaque marker (`.wh..wh..opq`). The bare prefix is neither.
        // Refused as MalformedHeader (not a security boundary; just
        // an unrenderable marker).
        let tar_bytes = build_tar(|b| {
            add_dir(b, "etc/");
            add_file(b, "etc/.wh.", b"");
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.whiteouts_applied, 0);
        assert_eq!(report.opaque_markers_applied, 0);
        assert_eq!(report.refused.len(), 1);
        assert_eq!(report.refused[0].reason, RefusalReason::MalformedHeader);
    }

    #[test]
    fn filename_with_wh_substring_but_not_prefix_is_a_regular_file() {
        // `foo.wh.bar` is a regular filename, not a whiteout. The
        // classifier matches on the *leaf prefix*, not on a
        // substring anywhere in the leaf — otherwise legitimate
        // filenames would be silently dropped.
        let tar_bytes = build_tar(|b| {
            add_file(b, "foo.wh.bar", b"contents");
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.whiteouts_applied, 0);
        assert!(tmp.path().join("foo.wh.bar").is_file());
    }

    #[test]
    fn intermediate_directory_named_wh_passes_through() {
        // A *directory* component named `.wh.something` is not a
        // marker — only the **leaf** filename of a regular-file
        // entry carries the semantic. So `a/.wh.x/y` writes a real
        // file at `a/.wh.x/y` with `.wh.x` materialized as a
        // directory by `create_dir_all`.
        let tar_bytes = build_tar(|b| {
            add_file(b, "a/.wh.x/y", b"data");
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.whiteouts_applied, 0);
        assert!(tmp.path().join("a/.wh.x/y").is_file());
    }

    // ── hardlink semantics ────────────────────────────

    #[test]
    fn hardlink_to_lower_layer_target_materializes_as_copy() {
        let tar_bytes = build_tar(|b| {
            add_hardlink(b, "alias", "lower/real");
        });

        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("lower")).unwrap();
        std::fs::write(tmp.path().join("lower/real"), b"lower-data").unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 0);
        assert_eq!(report.hardlinks_written, 0);
        assert_eq!(report.hardlink_copies_written, 1);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("alias")).unwrap(),
            "lower-data"
        );

        use std::os::unix::fs::MetadataExt;
        let real = std::fs::metadata(tmp.path().join("lower/real")).unwrap();
        let alias = std::fs::metadata(tmp.path().join("alias")).unwrap();
        assert_ne!(
            real.ino(),
            alias.ino(),
            "cross-layer hardlink must be copied, not aliased"
        );
    }

    #[test]
    fn hardlink_to_absent_target_is_refused() {
        let tar_bytes = build_tar(|b| {
            add_hardlink(b, "alias", "missing");
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.hardlinks_written, 0);
        assert_eq!(report.hardlink_copies_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(
            report.refused[0].reason,
            RefusalReason::HardlinkTargetMissing
        );
        assert!(!tmp.path().join("alias").exists());
    }

    #[test]
    fn hardlink_target_traversal_is_refused() {
        let tar_bytes = build_tar(|b| {
            add_file(b, "real", b"data");
            add_hardlink(b, "alias", "../real");
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::TraversalSegment);
        assert!(!tmp.path().join("alias").exists());
    }

    #[test]
    fn hardlink_under_symlinked_parent_refuses() {
        let tar_bytes = build_tar(|b| {
            add_file(b, "real", b"data");
            add_symlink(b, "out", "/tmp");
            add_hardlink(b, "out/alias", "real");
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.symlinks_written, 1);
        assert_eq!(report.hardlinks_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::SymlinkInParent);
    }

    #[test]
    fn hardlink_to_symlink_target_is_refused() {
        let tar_bytes = build_tar(|b| {
            add_symlink(b, "link", "real");
            add_hardlink(b, "alias", "link");
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.symlinks_written, 1);
        assert_eq!(report.hardlinks_written, 0);
        assert_eq!(report.hardlink_copies_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::MalformedHeader);
    }

    // ── path-escape corpus ────────────────────────────

    #[test]
    fn escape_corpus_entries_are_refused_and_write_nothing() {
        // Deterministic single-entry adversarial paths. Each must be
        // refused with the expected reason and leave the output tree
        // untouched. These guard the cheap string fail-fast checks
        // that front the openat2 resolution authority.
        let cases: &[(&[u8], RefusalReason)] = &[
            (b"/etc/passwd", RefusalReason::AbsolutePath),
            (b"/", RefusalReason::AbsolutePath),
            (b"a/../b", RefusalReason::TraversalSegment),
            (b"../escape", RefusalReason::TraversalSegment),
            (b"a/b/../../../escape", RefusalReason::TraversalSegment),
            (b"a/../../escape", RefusalReason::TraversalSegment),
        ];

        for (path, expected) in cases {
            let tar_bytes = handrolled_tar_with_path(path, b'0');
            let tmp = TempDir::new().unwrap();
            let report = unpack_layer(
                Cursor::new(tar_bytes),
                tmp.path(),
                &UnpackOptions::default(),
            )
            .expect("unpack should refuse, not error");

            let rendered = String::from_utf8_lossy(path).into_owned();
            assert_eq!(report.files_written, 0, "{rendered:?} wrote a file");
            assert_eq!(
                report.refused.len(),
                1,
                "{rendered:?}: {:?}",
                report.refused
            );
            assert_eq!(
                report.refused[0].reason, *expected,
                "{rendered:?} mapped to the wrong refusal",
            );
            // Nothing landed under the (empty) root.
            assert_eq!(
                std::fs::read_dir(tmp.path()).unwrap().count(),
                0,
                "{rendered:?} mutated the output tree",
            );
        }
    }

    #[test]
    fn escape_corpus_symlinked_parent_is_refused() {
        // The already-present symlinked-parent case: `bin -> /tmp`
        // then a write under `bin/`. Refused with SymlinkInParent and
        // nothing is written through the symlink.
        let tar_bytes = build_tar(|b| {
            add_symlink(b, "bin", "/tmp");
            add_file(b, "bin/escape", b"do not write");
        });

        let tmp = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.symlinks_written, 1);
        assert_eq!(report.files_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::SymlinkInParent);
        assert!(!std::path::Path::new("/tmp/escape").exists());
    }

    /// TOCTTOU witness (Linux): a parent component swapped to a symlink
    /// in the check→write window must never let a write escape the
    /// root. This fails against the pre-openat2 check-then-use code
    /// (where `create_dir_all` follows the swapped symlink and the
    /// leaf `O_NOFOLLOW` only guards the final component) and passes
    /// once writes resolve through `openat2(RESOLVE_NO_SYMLINKS)`.
    ///
    /// The assertion only inspects the out-of-root escape target, so
    /// the racing swapper can never make it flaky post-fix: an escape
    /// is simply impossible, churn or not.
    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_symlink_swap_in_parent_never_escapes_root() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let root = TempDir::new().unwrap();
        let escape = TempDir::new().unwrap();
        let root_path = root.path().to_path_buf();
        let escape_path = escape.path().to_path_buf();
        let q = root_path.join("p/q");
        let escape_secret = escape_path.join("secret");

        let stop = Arc::new(AtomicBool::new(false));

        let swapper = {
            let stop = stop.clone();
            let q = q.clone();
            let escape_path = escape_path.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = std::fs::remove_dir_all(&q);
                    let _ = std::fs::remove_file(&q);
                    let _ = std::os::unix::fs::symlink(&escape_path, &q);
                    let _ = std::fs::remove_file(&q);
                    let _ = std::fs::create_dir_all(&q);
                }
            })
        };

        // The unpacker writes `p/q/secret`. If a write lands while
        // `p/q` is the attacker symlink, the bytes escape to
        // `<escape>/secret`.
        let tar = build_tar(|b| {
            add_file(b, "p/q/secret", b"leaked");
        });

        let mut escaped = false;
        for _ in 0..6000 {
            let _ = std::fs::create_dir_all(root_path.join("p"));
            let _ = unpack_layer(
                Cursor::new(tar.clone()),
                &root_path,
                &UnpackOptions::default(),
            );
            if escape_secret.exists() {
                escaped = true;
                let _ = std::fs::remove_file(&escape_secret);
            }
            // Reset the in-root subtree for the next iteration;
            // best-effort, since the swapper is racing it too.
            let _ = std::fs::remove_dir_all(root_path.join("p"));
        }

        stop.store(true, Ordering::Relaxed);
        swapper.join().unwrap();

        assert!(
            !escaped,
            "a regular-file write escaped output_root through a parent component swapped \
             to a symlink — openat2(RESOLVE_NO_SYMLINKS) must refuse it atomically",
        );
    }
}
