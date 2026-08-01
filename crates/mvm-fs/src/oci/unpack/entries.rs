//! Per-`EntryType` dispatch handlers invoked from
//! [`super::unpack_layer`]'s tar-iteration loop, once every
//! path-safety check has passed for the current entry.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::ext4::Node;

use super::device_nodes::DeviceNodeAction;
use super::fs_ops::{HardlinkAction, Rooted};
use super::regular_file::{classify_regular_file_mode, record_setid_entry};
use super::whiteout::{WhiteoutKind, classify_whiteout};
use super::xattr::{PendingXattr, apply_collected_xattrs, into_ext4_xattrs};
use super::{RefusalReason, RefusedEntry, UnpackOptions, UnpackReport};

/// Per-entry inputs threaded from `unpack_layer`'s tar-iteration loop
/// into each entry-type handler below — the values every handler needs
/// to materialize its entry through `rooted` and to record the outcome
/// against the shared `raw_path`/`target` pair. `options`, `report`, and
/// `current_layer_paths` travel alongside `ctx` as separate arguments
/// rather than folded in here, since each handler borrows them with
/// different mutability (or, for `options`, not every handler needs it).
pub(super) struct EntryCtx<'a> {
    pub(super) rooted: &'a Rooted<'a>,
    pub(super) rel_path: &'a Path,
    pub(super) raw_path: &'a [u8],
    pub(super) target: &'a Path,
    pub(super) prior_layer_paths: &'a HashSet<PathBuf>,
}

/// Carry an entry the host tree cannot hold into the image instead of
/// writing it.
///
/// Reached when the entry's path collides, under the host filesystem's
/// case folding, with a path this same unpack already materialized —
/// `usr/share/man/man7/pam.7.gz` arriving after
/// `usr/share/man/man7/PAM.7.gz` on a default macOS APFS volume. Writing
/// it would clobber the occupant, so the entry is captured as an ext4
/// [`Node`] in [`UnpackReport::deferred_nodes`] and merged by the image
/// writer, leaving both paths present in the rootfs that actually boots.
///
/// Only the kinds the [`Node`] enum can express are deferrable. A
/// colliding hardlink or device node refuses with
/// [`RefusalReason::HostPathCollision`] — an honest refusal beats an
/// image that silently lost an inode alias.
pub(super) fn defer_colliding_entry<R: Read>(
    entry: &mut tar::Entry<R>,
    entry_type: tar::EntryType,
    ctx: &EntryCtx,
    entry_xattrs: Vec<PendingXattr>,
    options: &UnpackOptions,
    report: &mut UnpackReport,
) {
    let path = guest_path_of(ctx.rel_path);
    let node = match entry_type {
        tar::EntryType::Regular | tar::EntryType::Continuous => {
            let mode =
                match classify_regular_file_mode(entry.header().mode().unwrap_or(0o644), options) {
                    Ok(mode) => mode,
                    Err(refuse) => {
                        report.refused.push(RefusedEntry {
                            raw_path: ctx.raw_path.to_vec(),
                            reason: refuse,
                        });
                        return;
                    }
                };
            let mut data = Vec::new();
            if entry.read_to_end(&mut data).is_err() {
                report.refused.push(RefusedEntry {
                    raw_path: ctx.raw_path.to_vec(),
                    reason: RefusalReason::MalformedHeader,
                });
                return;
            }
            record_setid_entry(report, ctx.raw_path, mode, options.setid_policy);
            Node::File {
                path,
                mode: mode as u16,
                data,
                xattrs: into_ext4_xattrs(entry_xattrs),
            }
        }
        tar::EntryType::Symlink => {
            let target = match entry.link_name_bytes() {
                Some(bytes) if !bytes.is_empty() && !bytes.contains(&0) => {
                    String::from_utf8_lossy(&bytes).into_owned()
                }
                _ => {
                    report.refused.push(RefusedEntry {
                        raw_path: ctx.raw_path.to_vec(),
                        reason: RefusalReason::MalformedHeader,
                    });
                    return;
                }
            };
            Node::Symlink { path, target }
        }
        // Directories are created 0o755 regardless of header mode on the
        // host path too, so the deferred node matches what the tree would
        // otherwise have held.
        tar::EntryType::Directory => Node::Dir {
            path,
            mode: 0o755,
            xattrs: into_ext4_xattrs(entry_xattrs),
        },
        _ => {
            report.refused.push(RefusedEntry {
                raw_path: ctx.raw_path.to_vec(),
                reason: RefusalReason::HostPathCollision,
            });
            return;
        }
    };

    report.deferred_nodes.push(node);
}

/// Guest-absolute path string for the ext4 [`Node`] list, matching the
/// shape [`crate::rootfs::collect_nodes`] produces when it walks the
/// host tree, so deferred nodes and walked nodes are interchangeable.
fn guest_path_of(rel: &Path) -> String {
    format!("/{}", rel.to_string_lossy())
}

/// Materialize a `Regular`/`Continuous` tar entry: either write the
/// file, or — when the leaf filename carries the OCI whiteout marker —
/// apply the corresponding whiteout instead of writing a file.
pub(super) fn unpack_regular_entry<R: Read>(
    entry: &mut tar::Entry<R>,
    ctx: &EntryCtx,
    entry_xattrs: Vec<PendingXattr>,
    options: &UnpackOptions,
    current_layer_paths: &mut HashSet<PathBuf>,
    report: &mut UnpackReport,
) {
    match classify_whiteout(ctx.raw_path) {
        WhiteoutKind::None => {
            match ctx.rooted.write_regular_file(
                ctx.rel_path,
                entry,
                ctx.raw_path,
                options,
                ctx.prior_layer_paths,
                report,
            ) {
                Ok(()) => {
                    report.files_written += 1;
                    apply_collected_xattrs(ctx.target, ctx.raw_path, entry_xattrs, report);
                    current_layer_paths.insert(ctx.rel_path.to_path_buf());
                    report.paths_written.insert(ctx.rel_path.to_path_buf());
                }
                Err(refuse) => report.refused.push(RefusedEntry {
                    raw_path: ctx.raw_path.to_vec(),
                    reason: refuse,
                }),
            }
        }
        WhiteoutKind::Opaque => {
            // Parent-of-marker is the directory we're clearing.
            let parent_rel = ctx.rel_path.parent().unwrap_or_else(|| Path::new(""));
            match ctx
                .rooted
                .apply_opaque_whiteout(parent_rel, current_layer_paths)
            {
                Ok(()) => report.opaque_markers_applied += 1,
                Err(refuse) => report.refused.push(RefusedEntry {
                    raw_path: ctx.raw_path.to_vec(),
                    reason: refuse,
                }),
            }
        }
        WhiteoutKind::Regular(name_suffix) => {
            // Sibling target = `<parent_of_marker>/<name_suffix>`.
            let parent_rel = ctx.rel_path.parent().unwrap_or_else(|| Path::new(""));
            let sibling_rel = parent_rel.join(OsStr::from_bytes(name_suffix));
            match ctx
                .rooted
                .apply_regular_whiteout(&sibling_rel, current_layer_paths)
            {
                Ok(()) => report.whiteouts_applied += 1,
                Err(refuse) => report.refused.push(RefusedEntry {
                    raw_path: ctx.raw_path.to_vec(),
                    reason: refuse,
                }),
            }
        }
        WhiteoutKind::Malformed => {
            report.refused.push(RefusedEntry {
                raw_path: ctx.raw_path.to_vec(),
                reason: RefusalReason::MalformedHeader,
            });
        }
    }
}

/// Materialize a `Directory` tar entry.
pub(super) fn unpack_directory_entry(
    ctx: &EntryCtx,
    entry_xattrs: Vec<PendingXattr>,
    current_layer_paths: &mut HashSet<PathBuf>,
    report: &mut UnpackReport,
) {
    match ctx
        .rooted
        .create_directory(ctx.rel_path, ctx.prior_layer_paths)
    {
        Ok(created) => {
            if created {
                report.dirs_created += 1;
            }
            apply_collected_xattrs(ctx.target, ctx.raw_path, entry_xattrs, report);
            current_layer_paths.insert(ctx.rel_path.to_path_buf());
            report.paths_written.insert(ctx.rel_path.to_path_buf());
        }
        Err(refuse) => report.refused.push(RefusedEntry {
            raw_path: ctx.raw_path.to_vec(),
            reason: refuse,
        }),
    }
}

/// Materialize a `Symlink` tar entry.
pub(super) fn unpack_symlink_entry<R: Read>(
    entry: &tar::Entry<R>,
    ctx: &EntryCtx,
    entry_xattrs: Vec<PendingXattr>,
    current_layer_paths: &mut HashSet<PathBuf>,
    report: &mut UnpackReport,
) {
    let link_target = entry.link_name_bytes().map(|b| b.into_owned());
    match ctx
        .rooted
        .write_symlink(ctx.rel_path, link_target.as_deref(), ctx.prior_layer_paths)
    {
        Ok(()) => {
            report.symlinks_written += 1;
            apply_collected_xattrs(ctx.target, ctx.raw_path, entry_xattrs, report);
            current_layer_paths.insert(ctx.rel_path.to_path_buf());
            report.paths_written.insert(ctx.rel_path.to_path_buf());
        }
        Err(refuse) => report.refused.push(RefusedEntry {
            raw_path: ctx.raw_path.to_vec(),
            reason: refuse,
        }),
    }
}

/// Materialize a `Link` (hardlink) tar entry.
pub(super) fn unpack_hardlink_entry<R: Read>(
    entry: &tar::Entry<R>,
    ctx: &EntryCtx,
    options: &UnpackOptions,
    entry_xattrs: Vec<PendingXattr>,
    current_layer_paths: &mut HashSet<PathBuf>,
    report: &mut UnpackReport,
) {
    let link_target = entry.link_name_bytes().map(|b| b.into_owned());
    match ctx.rooted.materialize_hardlink(
        link_target.as_deref(),
        ctx.rel_path,
        options,
        current_layer_paths,
        ctx.prior_layer_paths,
    ) {
        Ok(HardlinkAction::Linked) => {
            report.hardlinks_written += 1;
            apply_collected_xattrs(ctx.target, ctx.raw_path, entry_xattrs, report);
            current_layer_paths.insert(ctx.rel_path.to_path_buf());
            report.paths_written.insert(ctx.rel_path.to_path_buf());
        }
        Ok(HardlinkAction::Copied) => {
            report.hardlink_copies_written += 1;
            apply_collected_xattrs(ctx.target, ctx.raw_path, entry_xattrs, report);
            current_layer_paths.insert(ctx.rel_path.to_path_buf());
            report.paths_written.insert(ctx.rel_path.to_path_buf());
        }
        Err(refuse) => report.refused.push(RefusedEntry {
            raw_path: ctx.raw_path.to_vec(),
            reason: refuse,
        }),
    }
}

/// Materialize a `Char`/`Block` device-node tar entry. Only the
/// allow-listed pseudo-devices land, and only on Linux — see
/// [`super::fs_ops::Rooted::materialize_device_node`].
#[cfg(target_os = "linux")]
pub(super) fn unpack_device_entry<R: Read>(
    entry: &tar::Entry<R>,
    ctx: &EntryCtx,
    entry_xattrs: Vec<PendingXattr>,
    current_layer_paths: &mut HashSet<PathBuf>,
    report: &mut UnpackReport,
) {
    match ctx.rooted.materialize_device_node(
        entry,
        ctx.rel_path,
        ctx.raw_path,
        ctx.prior_layer_paths,
    ) {
        Ok(DeviceNodeAction::Materialized) => {
            report.device_nodes_written += 1;
            apply_collected_xattrs(ctx.target, ctx.raw_path, entry_xattrs, report);
            current_layer_paths.insert(ctx.rel_path.to_path_buf());
            report.paths_written.insert(ctx.rel_path.to_path_buf());
        }
        Err(refuse) => report.refused.push(RefusedEntry {
            raw_path: ctx.raw_path.to_vec(),
            reason: refuse,
        }),
    }
}

/// Non-Linux fallback: allow-listed device nodes are skipped outright
/// (the later ext4/rootfs pipeline drops device nodes and the guest
/// mounts devtmpfs anyway), so neither the xattrs nor the current-layer
/// path set need updating — see
/// [`super::fs_ops::Rooted::materialize_device_node`].
#[cfg(not(target_os = "linux"))]
pub(super) fn unpack_device_entry<R: Read>(
    entry: &tar::Entry<R>,
    ctx: &EntryCtx,
    _entry_xattrs: Vec<PendingXattr>,
    _current_layer_paths: &mut HashSet<PathBuf>,
    report: &mut UnpackReport,
) {
    match ctx.rooted.materialize_device_node(
        entry,
        ctx.rel_path,
        ctx.raw_path,
        ctx.prior_layer_paths,
    ) {
        Ok(DeviceNodeAction::Skipped) => {
            report.device_nodes_skipped += 1;
        }
        Err(refuse) => report.refused.push(RefusedEntry {
            raw_path: ctx.raw_path.to_vec(),
            reason: refuse,
        }),
    }
}
