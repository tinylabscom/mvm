//! Layer-to-tree unpacker.
//!
//! Materializes an OCI layer tarball (already digest-verified + cached
//! by [`crate::oci::layer`]) into a directory tree on the host filesystem,
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
//!   accepted only when they are standard pseudo-devices that the
//!   runtime already expects (`dev/console`, `dev/null`, `dev/zero`,
//!   `dev/random`, `dev/urandom`) with their Linux standard
//!   major/minor numbers. On Linux they are materialized exactly; on
//!   non-Linux hosts they are skipped because the later ext4/rootfs
//!   pipeline drops device nodes and the guest mounts devtmpfs anyway.
//!   Every other character or block device is refused with
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
//! 2. **Filesystem mutations resolve atomically inside the root
//!    (Linux).** Every file / dir / symlink / hardlink / device-node
//!    materialization *and* every whiteout removal resolves the entry's
//!    parent directory through `openat2(RESOLVE_IN_ROOT |
//!    RESOLVE_NO_SYMLINKS)` and issues the leaf operation with `*at`
//!    calls (`openat2`/`mkdirat`/`symlinkat`/`linkat`/`mknodat`/
//!    `unlinkat`) against the returned directory handle — never against
//!    a re-derived host path. Resolution and mutation therefore share
//!    one kernel-checked handle, so a parent component swapped to a
//!    symlink *after* a check can no longer redirect the operation
//!    outside the root: the kernel refuses to traverse the symlink
//!    (`ELOOP`) or to escape the root (`EXDEV`). This closes the
//!    check-then-use window that a bare `symlink_metadata` walk
//!    followed by a later `open(2)` / `remove_*` leaves open.
//!    `parent_chain_has_symlink` is retained as a cheap,
//!    cross-platform fail-fast pre-filter; on Linux the `openat2`
//!    handle is the load-bearing authority. On non-Linux targets
//!    (test/dev builds only — the unpacker runs only in the Linux
//!    builder VM in production) the operations fall back to path-based
//!    creation/removal with `O_NOFOLLOW` on the leaf.
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
//!
//! ## Module layout
//!
//! This module is a thin orchestrator over sibling modules that each
//! own one entry kind's materialization: [`entries`] dispatches by tar
//! `EntryType`; [`fs_ops`] holds the root-confined [`fs_ops::Rooted`]
//! writer plus directory/symlink/hardlink primitives; [`regular_file`],
//! [`device_nodes`], and [`whiteout`] each add their own `impl Rooted`
//! fragment and free-standing helpers for their entry kind; [`xattr`]
//! collects and applies pax extended attributes.

mod device_nodes;
mod entries;
mod fs_ops;
mod regular_file;
mod whiteout;
mod xattr;

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use entries::{
    EntryCtx, unpack_device_entry, unpack_directory_entry, unpack_hardlink_entry,
    unpack_regular_entry, unpack_symlink_entry,
};
use fs_ops::{Rooted, parent_chain_has_symlink};
use xattr::{XattrWarningReason, collect_entry_xattrs};

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
    /// Paths written by this layer (regular files, directories,
    /// symlinks, hardlinks, device nodes). Callers applying multiple
    /// layers to the same root accumulate this set and pass it as
    /// `prior_layer_paths` to the next layer so that later layers can
    /// replace paths known to originate from earlier layers.
    pub paths_written: HashSet<PathBuf>,
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
    /// Allow-listed pseudo-device nodes accepted but intentionally
    /// skipped on hosts that cannot or should not materialize them.
    pub device_nodes_skipped: u64,
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

/// Unpack a single layer tarball under `output_root`, applying the
/// safety policies described at module level.
///
/// This is the backward-compatible entry point for single-layer
/// callers and tests. Multi-layer callers should use
/// [`unpack_layer_with_prior_paths`] and accumulate the
/// [`UnpackReport::paths_written`] set across layers.
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
    layer_tar: R,
    output_root: &Path,
    options: &UnpackOptions,
) -> Result<UnpackReport, UnpackError> {
    unpack_layer_with_prior_paths(layer_tar, output_root, options, &HashSet::new())
}

/// Unpack a single layer tarball under `output_root`, with knowledge
/// of paths written by earlier layers.
///
/// When `prior_layer_paths` contains the relative path of an entry
/// being unpacked, the unpacker removes the existing leaf first
/// (file, symlink, or directory tree) and then re-creates it with
/// the new entry's type. This lets later OCI layers replace files
/// from earlier layers without giving up the `O_EXCL` / `O_NOFOLLOW`
/// first-creation safety for paths that are genuinely new. Same-layer
/// duplicates remain refused.
pub fn unpack_layer_with_prior_paths<R: Read>(
    mut layer_tar: R,
    output_root: &Path,
    options: &UnpackOptions,
    prior_layer_paths: &HashSet<PathBuf>,
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
        let ctx = EntryCtx {
            rooted: &rooted,
            rel_path: &rel_path,
            raw_path: &raw_path,
            target: &target,
            prior_layer_paths,
        };
        match entry_type {
            tar::EntryType::Regular | tar::EntryType::Continuous => unpack_regular_entry(
                &mut entry,
                &ctx,
                entry_xattrs,
                options,
                &mut current_layer_paths,
                &mut report,
            ),
            tar::EntryType::Directory => {
                unpack_directory_entry(&ctx, entry_xattrs, &mut current_layer_paths, &mut report)
            }
            tar::EntryType::Symlink => unpack_symlink_entry(
                &entry,
                &ctx,
                entry_xattrs,
                &mut current_layer_paths,
                &mut report,
            ),
            tar::EntryType::Link => unpack_hardlink_entry(
                &entry,
                &ctx,
                options,
                entry_xattrs,
                &mut current_layer_paths,
                &mut report,
            ),
            tar::EntryType::Char | tar::EntryType::Block => unpack_device_entry(
                &entry,
                &ctx,
                entry_xattrs,
                &mut current_layer_paths,
                &mut report,
            ),
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

/// Shared `#[cfg(test)]` tar-fixture builders used by every submodule's
/// test block, so each can exercise [`unpack_layer`] end-to-end without
/// duplicating the fixture-construction helpers.
#[cfg(test)]
mod test_support {
    use std::io::Cursor;

    /// Helper — build a tar archive in memory from a list of
    /// `(header_setup, body)` closures. Returns the archive bytes.
    pub(super) fn build_tar(setup: impl FnOnce(&mut tar::Builder<Cursor<Vec<u8>>>)) -> Vec<u8> {
        let buf = Cursor::new(Vec::new());
        let mut builder = tar::Builder::new(buf);
        setup(&mut builder);
        builder.into_inner().unwrap().into_inner()
    }

    /// Add a regular file with the given content + relative path.
    pub(super) fn add_file(builder: &mut tar::Builder<Cursor<Vec<u8>>>, path: &str, body: &[u8]) {
        add_file_with_mode(builder, path, body, 0o644);
    }

    /// Add a regular file with an explicit tar mode.
    pub(super) fn add_file_with_mode(
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
    pub(super) fn add_file_with_pax_xattrs(
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
    pub(super) fn add_dir(builder: &mut tar::Builder<Cursor<Vec<u8>>>, path: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder.append(&header, std::io::empty()).unwrap();
    }

    /// Add a symlink.
    pub(super) fn add_symlink(
        builder: &mut tar::Builder<Cursor<Vec<u8>>>,
        path: &str,
        link_target: &str,
    ) {
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
    pub(super) fn add_hardlink(
        builder: &mut tar::Builder<Cursor<Vec<u8>>>,
        path: &str,
        link_target: &str,
    ) {
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
    pub(super) fn add_device_node(
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

    /// Build a single-entry tar archive with a hand-rolled USTAR
    /// header whose path field carries `path_bytes` verbatim. This
    /// bypasses `tar::Header::set_path`'s built-in refusals (leading
    /// `/`, `..` segments, length > 100) so we can produce
    /// adversarial inputs that the unpacker is supposed to reject.
    /// Returns the archive bytes (header + 1024 bytes of EOF zero
    /// blocks).
    pub(super) fn handrolled_tar_with_path(path_bytes: &[u8], entry_type: u8) -> Vec<u8> {
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
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

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
}
