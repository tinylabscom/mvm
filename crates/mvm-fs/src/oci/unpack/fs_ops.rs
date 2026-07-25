//! Root-confined materialization surface: [`Rooted`] resolves and
//! writes every entry under `output_root` on Linux via
//! `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS)`, with a
//! path-based non-Linux fallback. This module owns the directory /
//! symlink / hardlink operations directly; the sibling
//! [`super::regular_file`], [`super::device_nodes`], and
//! [`super::whiteout`] modules each add their own `impl Rooted`
//! fragment for their entry kind.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

#[cfg(not(target_os = "linux"))]
use super::regular_file::copy_existing_regular_file;
use super::{RefusalReason, UnpackOptions};

/// Root-confined materialization surface, created once per
/// [`super::unpack_layer`] call.
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
pub(super) struct Rooted<'a> {
    pub(super) root: &'a Path,
    #[cfg(target_os = "linux")]
    pub(super) root_fd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl<'a> Rooted<'a> {
    pub(super) fn open(root: &'a Path) -> std::io::Result<Self> {
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
    pub(super) fn open_parent(
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

    pub(super) fn create_directory(
        &self,
        rel: &Path,
        prior_layer_paths: &HashSet<PathBuf>,
    ) -> Result<bool, RefusalReason> {
        use rustix::fs::{AtFlags, Mode, mkdirat, unlinkat};
        use rustix::io::Errno;
        use std::os::fd::AsFd;

        let (parent, leaf) = self.open_parent(rel, true).map_err(map_resolve_errno)?;
        if prior_layer_paths.contains(rel) {
            // A prior-layer file or symlink occupying this directory
            // path must be removed before we can create the directory.
            // If the prior entry is itself a directory, `mkdirat` will
            // return EEXIST and we coalesce below.
            if let Err(e) = unlinkat(parent.as_fd(), &leaf, AtFlags::empty()) {
                if e != Errno::NOENT && e != Errno::ISDIR {
                    return Err(RefusalReason::MalformedHeader);
                }
            }
        }
        match mkdirat(parent.as_fd(), &leaf, Mode::from_raw_mode(0o755)) {
            Ok(()) => Ok(true),
            Err(e) if e == Errno::EXIST => Ok(false),
            Err(e) => Err(map_resolve_errno(e)),
        }
    }

    pub(super) fn write_symlink(
        &self,
        rel: &Path,
        link_target_bytes: Option<&[u8]>,
        prior_layer_paths: &HashSet<PathBuf>,
    ) -> Result<(), RefusalReason> {
        use rustix::fs::symlinkat;
        use std::os::fd::AsFd;

        let link_target = match link_target_bytes {
            Some(b) if !b.is_empty() && !b.contains(&0) => b,
            _ => return Err(RefusalReason::MalformedHeader),
        };
        let (parent, leaf) = self.open_parent(rel, true).map_err(map_resolve_errno)?;
        if prior_layer_paths.contains(rel) {
            remove_prior_layer_path(self, rel)?;
        }
        symlinkat(OsStr::from_bytes(link_target), parent.as_fd(), &leaf)
            .map_err(|_| RefusalReason::MalformedHeader)
    }

    pub(super) fn materialize_hardlink(
        &self,
        link_target_bytes: Option<&[u8]>,
        target_rel: &Path,
        options: &UnpackOptions,
        current_layer_paths: &HashSet<PathBuf>,
        prior_layer_paths: &HashSet<PathBuf>,
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

        if prior_layer_paths.contains(target_rel) {
            remove_prior_layer_path(self, target_rel)?;
        }

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

    /// `openat2`-walk to the directory named by `rel` (every component
    /// resolved with `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS`). Raw
    /// `Errno` so callers can treat `ENOENT` as "nothing to remove".
    pub(super) fn open_dir(&self, rel: &Path) -> Result<std::os::fd::OwnedFd, rustix::io::Errno> {
        use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
        use std::os::fd::AsFd;
        let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS;
        let (parent, leaf) = self.open_parent(rel, false)?;
        openat2(
            parent.as_fd(),
            &leaf,
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            resolve,
        )
    }
}

/// Remove a path known to originate from a prior layer so the current
/// layer can recreate it with a different entry type. Directories are
/// removed recursively; files and symlinks are unlinked without
/// dereferencing. Operations resolve through `openat2(RESOLVE_NO_SYMLINKS)`
/// so a swapped symlink parent cannot redirect the removal.
#[cfg(target_os = "linux")]
pub(super) fn remove_prior_layer_path(rooted: &Rooted, rel: &Path) -> Result<(), RefusalReason> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags, openat2, statat, unlinkat};
    use rustix::io::Errno;
    use std::os::fd::AsFd;

    let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS;
    let (parent, leaf) = match rooted.open_parent(rel, false) {
        Ok(v) => v,
        Err(e) if e == Errno::NOENT => return Ok(()),
        Err(e) => return Err(map_resolve_errno(e)),
    };

    let st = match statat(parent.as_fd(), &leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(s) => s,
        Err(e) if e == Errno::NOENT => return Ok(()),
        Err(_) => return Err(RefusalReason::MalformedHeader),
    };

    if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
        let dir_fd = openat2(
            parent.as_fd(),
            &leaf,
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            resolve,
        )
        .map_err(map_resolve_errno)?;
        remove_all_children_in_dir(&dir_fd)?;
        unlinkat(parent.as_fd(), &leaf, AtFlags::REMOVEDIR)
            .map_err(|_| RefusalReason::MalformedHeader)
    } else {
        unlinkat(parent.as_fd(), &leaf, AtFlags::empty())
            .map_err(|_| RefusalReason::MalformedHeader)
    }
}

/// Recursively remove every child of `dir_fd`, descending through
/// directory handles so the walk cannot be redirected by a symlink swap.
#[cfg(target_os = "linux")]
fn remove_all_children_in_dir(dir_fd: &std::os::fd::OwnedFd) -> Result<(), RefusalReason> {
    use rustix::fs::{
        AtFlags, Dir, FileType, Mode, OFlags, ResolveFlags, openat2, statat, unlinkat,
    };
    use std::os::fd::AsFd;

    let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS;
    let child_dir_oflags = OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;

    let mut children: Vec<(std::ffi::OsString, bool)> = Vec::new();
    let dir = Dir::read_from(dir_fd.as_fd()).map_err(|_| RefusalReason::MalformedHeader)?;
    for entry in dir {
        let entry = entry.map_err(|_| RefusalReason::MalformedHeader)?;
        let name_bytes = entry.file_name().to_bytes();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        let name = OsStr::from_bytes(name_bytes).to_os_string();
        let is_dir = match entry.file_type() {
            FileType::Directory => true,
            FileType::Unknown => match statat(dir_fd.as_fd(), &name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => FileType::from_raw_mode(st.st_mode) == FileType::Directory,
                Err(_) => false,
            },
            _ => false,
        };
        children.push((name, is_dir));
    }

    for (name, is_dir) in children {
        if is_dir {
            let child_fd = openat2(
                dir_fd.as_fd(),
                &name,
                child_dir_oflags,
                Mode::empty(),
                resolve,
            )
            .map_err(map_resolve_errno)?;
            remove_all_children_in_dir(&child_fd)?;
            unlinkat(dir_fd.as_fd(), &name, AtFlags::REMOVEDIR)
                .map_err(|_| RefusalReason::MalformedHeader)?;
        } else {
            unlinkat(dir_fd.as_fd(), &name, AtFlags::empty())
                .map_err(|_| RefusalReason::MalformedHeader)?;
        }
    }
    Ok(())
}

/// Map an `openat2`/`*at` failure to the unpacker's refusal taxonomy.
/// `ELOOP` is a `RESOLVE_NO_SYMLINKS` hit on a symlinked component;
/// `EXDEV` is a `RESOLVE_IN_ROOT` boundary escape. Everything else is
/// an opaque per-entry failure.
#[cfg(target_os = "linux")]
pub(super) fn map_resolve_errno(e: rustix::io::Errno) -> RefusalReason {
    use rustix::io::Errno;
    if e == Errno::LOOP {
        RefusalReason::SymlinkInParent
    } else if e == Errno::XDEV {
        RefusalReason::JoinedPathEscape
    } else {
        RefusalReason::MalformedHeader
    }
}

/// Remove a path known to originate from a prior layer so the current
/// layer can recreate it. Non-Linux fallback only.
#[cfg(not(target_os = "linux"))]
pub(super) fn remove_prior_layer_path(root: &Path, rel: &Path) -> Result<(), RefusalReason> {
    let target = root.join(rel);
    if !target.starts_with(root) {
        return Err(RefusalReason::JoinedPathEscape);
    }
    match std::fs::symlink_metadata(&target) {
        Ok(meta) if meta.file_type().is_dir() => {
            std::fs::remove_dir_all(&target).map_err(|_| RefusalReason::MalformedHeader)
        }
        Ok(_) => std::fs::remove_file(&target).map_err(|_| RefusalReason::MalformedHeader),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RefusalReason::MalformedHeader),
    }
}

#[cfg(not(target_os = "linux"))]
impl<'a> Rooted<'a> {
    pub(super) fn open(root: &'a Path) -> std::io::Result<Self> {
        Ok(Self { root })
    }

    pub(super) fn create_directory(
        &self,
        rel: &Path,
        prior_layer_paths: &HashSet<PathBuf>,
    ) -> Result<bool, RefusalReason> {
        if prior_layer_paths.contains(rel) {
            remove_prior_layer_path(self.root, rel)?;
        }
        create_directory(&self.root.join(rel))
    }

    pub(super) fn write_symlink(
        &self,
        rel: &Path,
        link_target_bytes: Option<&[u8]>,
        prior_layer_paths: &HashSet<PathBuf>,
    ) -> Result<(), RefusalReason> {
        if prior_layer_paths.contains(rel) {
            remove_prior_layer_path(self.root, rel)?;
        }
        write_symlink(link_target_bytes, &self.root.join(rel))
    }

    pub(super) fn materialize_hardlink(
        &self,
        link_target_bytes: Option<&[u8]>,
        target_rel: &Path,
        options: &UnpackOptions,
        current_layer_paths: &HashSet<PathBuf>,
        prior_layer_paths: &HashSet<PathBuf>,
    ) -> Result<HardlinkAction, RefusalReason> {
        materialize_hardlink(
            link_target_bytes,
            &self.root.join(target_rel),
            self.root,
            options,
            current_layer_paths,
            prior_layer_paths,
        )
    }
}

/// Walk each existing prefix of `output_root.join(rel)` and return
/// `true` if any component is a symlink. We use `symlink_metadata`
/// (which does **not** dereference) so the existence check itself
/// can't be defeated by a symlink loop.
pub(super) fn parent_chain_has_symlink(output_root: &Path, rel: &Path) -> bool {
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

pub(super) enum HardlinkAction {
    Linked,
    Copied,
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
    prior_layer_paths: &HashSet<PathBuf>,
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

    if prior_layer_paths.contains(&target_rel) {
        remove_prior_layer_path(output_root, &target_rel)?;
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

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

    #[test]
    fn hardlink_to_same_layer_target_materializes_as_hardlink() {
        let tar_bytes = build_tar(|b| {
            add_file(b, "real", b"data");
            add_hardlink(b, "alias", "real");
        });

        let tmp = TempDir::new().unwrap();
        let report = super::super::unpack_layer(
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

    // ── hardlink semantics ────────────────────────────

    #[test]
    fn hardlink_to_lower_layer_target_materializes_as_copy() {
        let tar_bytes = build_tar(|b| {
            add_hardlink(b, "alias", "lower/real");
        });

        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("lower")).unwrap();
        std::fs::write(tmp.path().join("lower/real"), b"lower-data").unwrap();
        let report = super::super::unpack_layer(
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
        let report = super::super::unpack_layer(
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
        let report = super::super::unpack_layer(
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
        let report = super::super::unpack_layer(
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
        let report = super::super::unpack_layer(
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

        // Race for a bounded wall-clock budget, stopping early the
        // instant an escape is observed. Time-bounded (not a fixed
        // iteration count) so heavy swapper contention can't blow up CI
        // wall-clock; thousands of attempts still run on a fast host.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
        let mut escaped = false;
        while !escaped && std::time::Instant::now() < deadline {
            let _ = std::fs::create_dir_all(root_path.join("p"));
            let _ = super::super::unpack_layer(
                Cursor::new(tar.clone()),
                &root_path,
                &UnpackOptions::default(),
            );
            if escape_secret.exists() {
                escaped = true;
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
