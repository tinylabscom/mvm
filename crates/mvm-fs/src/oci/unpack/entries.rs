//! Per-`EntryType` dispatch handlers invoked from
//! [`super::unpack_layer`]'s tar-iteration loop, once every
//! path-safety check has passed for the current entry.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::device_nodes::DeviceNodeAction;
use super::fs_ops::{HardlinkAction, Rooted};
use super::whiteout::{WhiteoutKind, classify_whiteout};
use super::xattr::{PendingXattr, apply_collected_xattrs};
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
