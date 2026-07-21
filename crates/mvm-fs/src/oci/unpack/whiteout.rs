//! OCI whiteout semantics: classifying a regular-file tar entry's leaf
//! filename as a `.wh.<name>` sibling removal or a `.wh..wh..opq`
//! opaque-directory clear, and applying either against the
//! already-assembled tree while preserving same-layer entries
//! regardless of marker ordering in the tar stream.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;

use super::RefusalReason;
use super::fs_ops::Rooted;
#[cfg(target_os = "linux")]
use super::fs_ops::map_resolve_errno;

/// OCI v1.1 whiteout marker prefix. A regular-file tar entry whose
/// **leaf filename** starts with this byte sequence is interpreted as
/// a whiteout instruction, not a file to materialize.
const WHITEOUT_PREFIX: &[u8] = b".wh.";

/// OCI v1.1 opaque-directory whiteout marker — the full leaf
/// filename (not a prefix). Distinct from `.wh.<name>` because it
/// directs the unpacker to clear the **parent** directory's
/// prior-layer contents rather than removing a sibling.
const WHITEOUT_OPAQUE: &[u8] = b".wh..wh..opq";

/// Tells the dispatch loop whether a regular-file tar entry is
/// actually an OCI whiteout marker and, if so, which kind.
///
/// Decided strictly from the **leaf filename**. The path's parent
/// chain is irrelevant for classification (a directory named `.wh.X`
/// is legitimate as an intermediate component); only the last
/// segment carries the marker semantic.
pub(super) enum WhiteoutKind<'a> {
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

pub(super) fn classify_whiteout(raw_path: &[u8]) -> WhiteoutKind<'_> {
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

#[cfg(target_os = "linux")]
impl<'a> Rooted<'a> {
    /// Apply a `.wh.<name>` whiteout by resolving the sibling's parent
    /// through `openat2` and removing the sibling via `*at` calls — so a
    /// parent component swapped to a symlink after the fail-fast scan
    /// can't redirect the removal outside the root.
    pub(super) fn apply_regular_whiteout(
        &self,
        target_rel: &Path,
        current_layer_paths: &HashSet<PathBuf>,
    ) -> Result<(), RefusalReason> {
        use rustix::fs::{
            AtFlags, FileType, Mode, OFlags, ResolveFlags, openat2, statat, unlinkat,
        };
        use rustix::io::Errno;
        use std::os::fd::AsFd;

        let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS;
        // A missing parent means the sibling can't exist — a whiteout of
        // an absent target is an idempotent no-op (OCI is declarative).
        let (parent, leaf) = match self.open_parent(target_rel, false) {
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
            remove_children_in_dir(&dir_fd, target_rel, current_layer_paths)?;
            // Remove the now-cleared directory itself unless the current
            // layer wrote something at or below it.
            if !has_current_layer_path_at_or_below(target_rel, current_layer_paths) {
                unlinkat(parent.as_fd(), &leaf, AtFlags::REMOVEDIR)
                    .map_err(|_| RefusalReason::MalformedHeader)?;
            }
            Ok(())
        } else {
            // File or symlink: same-layer entries survive regardless of
            // marker ordering.
            if current_layer_paths.contains(target_rel) {
                return Ok(());
            }
            unlinkat(parent.as_fd(), &leaf, AtFlags::empty())
                .map_err(|_| RefusalReason::MalformedHeader)
        }
    }

    /// Apply a `.wh..wh..opq` opaque whiteout: clear the directory's
    /// lower-layer contents (preserving same-layer entries and the
    /// directory itself), resolved through `openat2`.
    pub(super) fn apply_opaque_whiteout(
        &self,
        target_dir_rel: &Path,
        current_layer_paths: &HashSet<PathBuf>,
    ) -> Result<(), RefusalReason> {
        use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
        use rustix::io::Errno;
        use std::os::fd::AsFd;

        let dir_fd = if target_dir_rel.as_os_str().is_empty() {
            let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS;
            openat2(
                self.root_fd.as_fd(),
                ".",
                OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                resolve,
            )
            .map_err(map_resolve_errno)?
        } else {
            match self.open_dir(target_dir_rel) {
                Ok(fd) => fd,
                Err(e) if e == Errno::NOENT => return Ok(()),
                Err(e) => return Err(map_resolve_errno(e)),
            }
        };
        remove_children_in_dir(&dir_fd, target_dir_rel, current_layer_paths)
    }
}

/// Recursively remove the children of `dir_fd` that are *not* part of
/// the current layer, descending through directory handles (never a
/// re-derived host path) so the walk can't be redirected by a symlink
/// swap. Mirrors `remove_children_except_current_layer` over `*at`
/// calls. `dir_rel` is the path of `dir_fd` relative to the root, used
/// only to test current-layer membership.
#[cfg(target_os = "linux")]
fn remove_children_in_dir(
    dir_fd: &std::os::fd::OwnedFd,
    dir_rel: &Path,
    current_layer_paths: &HashSet<PathBuf>,
) -> Result<(), RefusalReason> {
    use rustix::fs::{
        AtFlags, Dir, FileType, Mode, OFlags, ResolveFlags, openat2, statat, unlinkat,
    };
    use std::os::fd::AsFd;

    let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS;
    let child_dir_oflags = OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;

    // Snapshot entries before mutating: removing during readdir can
    // skip or repeat directory entries.
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
            // `d_type` not populated by this filesystem — lstat to
            // classify (a symlink stays a symlink, removed as a file).
            FileType::Unknown => match statat(dir_fd.as_fd(), &name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => FileType::from_raw_mode(st.st_mode) == FileType::Directory,
                Err(_) => false,
            },
            _ => false,
        };
        children.push((name, is_dir));
    }

    for (name, is_dir) in children {
        let child_rel = dir_rel.join(&name);

        // Same-layer entry: keep it. If it's a directory, still descend
        // to clear any lower-layer children beneath it.
        if current_layer_paths.contains(&child_rel) {
            if is_dir {
                let child_fd = openat2(
                    dir_fd.as_fd(),
                    &name,
                    child_dir_oflags,
                    Mode::empty(),
                    resolve,
                )
                .map_err(map_resolve_errno)?;
                remove_children_in_dir(&child_fd, &child_rel, current_layer_paths)?;
            }
            continue;
        }

        // Lower-layer directory that still holds a same-layer descendant:
        // keep the directory, clear the rest beneath it.
        if is_dir && has_current_layer_path_below(&child_rel, current_layer_paths) {
            let child_fd = openat2(
                dir_fd.as_fd(),
                &name,
                child_dir_oflags,
                Mode::empty(),
                resolve,
            )
            .map_err(map_resolve_errno)?;
            remove_children_in_dir(&child_fd, &child_rel, current_layer_paths)?;
            continue;
        }

        // Otherwise remove it outright.
        if is_dir {
            let child_fd = openat2(
                dir_fd.as_fd(),
                &name,
                child_dir_oflags,
                Mode::empty(),
                resolve,
            )
            .map_err(map_resolve_errno)?;
            remove_children_in_dir(&child_fd, &child_rel, current_layer_paths)?;
            unlinkat(dir_fd.as_fd(), &name, AtFlags::REMOVEDIR)
                .map_err(|_| RefusalReason::MalformedHeader)?;
        } else {
            unlinkat(dir_fd.as_fd(), &name, AtFlags::empty())
                .map_err(|_| RefusalReason::MalformedHeader)?;
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
impl<'a> Rooted<'a> {
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
    pub(super) fn apply_regular_whiteout(
        &self,
        target_rel: &Path,
        current_layer_paths: &HashSet<PathBuf>,
    ) -> Result<(), RefusalReason> {
        apply_regular_whiteout(
            &self.root.join(target_rel),
            target_rel,
            self.root,
            current_layer_paths,
        )
    }

    /// Apply a `.wh..wh..opq` opaque whiteout: clear `target_dir`'s
    /// lower-layer contents, preserving the directory itself and any
    /// same-layer entries below it. OCI says opaque markers are applied
    /// before sibling entries regardless of archive ordering; preserving
    /// same-layer paths gives that result without buffering the whole
    /// layer.
    pub(super) fn apply_opaque_whiteout(
        &self,
        target_dir_rel: &Path,
        current_layer_paths: &HashSet<PathBuf>,
    ) -> Result<(), RefusalReason> {
        let dir = if target_dir_rel.as_os_str().is_empty() {
            self.root.to_path_buf()
        } else {
            self.root.join(target_dir_rel)
        };
        apply_opaque_whiteout(&dir, target_dir_rel, self.root, current_layer_paths)
    }
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
#[cfg(not(target_os = "linux"))]
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
#[cfg(not(target_os = "linux"))]
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

#[cfg(not(target_os = "linux"))]
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

#[cfg(not(target_os = "linux"))]
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
    use super::super::UnpackOptions;
    use super::super::test_support::*;
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

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
        let report = super::super::unpack_layer(
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
        let report = super::super::unpack_layer(
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
        let report = super::super::unpack_layer(
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
        let report = super::super::unpack_layer(
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
        let report = super::super::unpack_layer(
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
        let report = super::super::unpack_layer(
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
        let report = super::super::unpack_layer(
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
        let report = super::super::unpack_layer(
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
        let report = super::super::unpack_layer(
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
        let report = super::super::unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.whiteouts_applied, 0);
        assert!(tmp.path().join("a/.wh.x/y").is_file());
    }

    /// TOCTTOU witness (Linux) for the **removal** path: a parent
    /// component of a whiteout target swapped to an out-of-root symlink
    /// in the check→remove window must never let the removal delete a
    /// file outside the root. Fails against the pre-openat2 removal
    /// (where `symlink_metadata` + `remove_file` follow the swapped
    /// parent) and passes once removal resolves through openat2.
    ///
    /// Like the write witness, it inspects only the out-of-root victim,
    /// so the racing swapper can't make it flaky post-fix.
    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_symlink_swap_during_whiteout_removal_never_escapes_root() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let root = TempDir::new().unwrap();
        let escape = TempDir::new().unwrap();
        let root_path = root.path().to_path_buf();
        let escape_path = escape.path().to_path_buf();
        let d = root_path.join("d");
        let victim = escape_path.join("victim");

        let stop = Arc::new(AtomicBool::new(false));
        let swapper = {
            let stop = stop.clone();
            let d = d.clone();
            let escape_path = escape_path.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = std::fs::remove_dir_all(&d);
                    let _ = std::fs::remove_file(&d);
                    let _ = std::os::unix::fs::symlink(&escape_path, &d);
                    let _ = std::fs::remove_file(&d);
                    let _ = std::fs::create_dir_all(&d);
                }
            })
        };

        // A `.wh.victim` whiteout removes the sibling `d/victim`. If a
        // write lands while `d` is the attacker symlink, the removal
        // deletes `<escape>/victim`.
        let tar = build_tar(|b| {
            add_file(b, "d/.wh.victim", b"");
        });

        // Bounded wall-clock race, stopping early on the first escape
        // (see the write witness for the rationale).
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
        let mut escaped = false;
        while !escaped && std::time::Instant::now() < deadline {
            // The out-of-root victim must exist for the removal to have
            // something to (wrongly) delete; recreate it each round.
            std::fs::create_dir_all(&escape_path).unwrap();
            let _ = std::fs::write(&victim, b"keep");
            let _ = std::fs::create_dir_all(&d);
            let _ = super::super::unpack_layer(
                Cursor::new(tar.clone()),
                &root_path,
                &UnpackOptions::default(),
            );
            if !victim.exists() {
                escaped = true;
            }
            let _ = std::fs::remove_dir_all(&d);
        }

        stop.store(true, Ordering::Relaxed);
        swapper.join().unwrap();

        assert!(
            !escaped,
            "a whiteout removal escaped output_root through a parent component swapped \
             to a symlink and deleted an out-of-root file — openat2 must refuse it",
        );
    }
}
