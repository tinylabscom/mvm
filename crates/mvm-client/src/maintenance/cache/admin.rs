//! Host administration, not a host-ABI/SDK deletion surface.
//!
//! These requests select only the configured host home and named policies.
//! They never accept deletion paths or execute a caller-supplied preview.
//! Staging uses the existing Stage 0 lock. Repair retains the established
//! probe/force semantics: the probe is not a lease, and deleting builder-vm
//! also removes its lock inode. Neither it nor the persistent builder record
//! guard excludes all store users. Temp/deep sweeps likewise are maintenance
//! on a quiescent host, not globally serialized with launches.
//! Preview never signals, deletes artifacts, or emits mutation audits. Existing
//! subsystem probes may create their advisory-lock anchor files; "preview"
//! does not claim a byte-for-byte unchanged directory tree.

use super::{CacheEntry, FlowRetentionRequest, RetiredPruneRequest, footprint, retention, standby};
use anyhow::Result;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct CachePruneRequest {
    /// Explicit destructive intent. The library defaults to preview; the CLI
    /// maps its established apply-by-default command to this field.
    pub apply: bool,
    pub orphan_builds: bool,
    pub no_reap_orphans: bool,
    pub orphan_dirs: bool,
    pub deep: bool,
    pub stage0_store: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RepairScope {
    #[default]
    BuilderStore,
    StoreImage,
}

#[derive(Debug, Clone, Default)]
pub struct RepairRequest {
    pub apply: bool,
    pub force: bool,
    pub scope: RepairScope,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CachePruneSummary {
    pub removed: u64,
    pub freed_bytes: u64,
    pub missing: bool,
}

/// Ordered observations, including partial progress before a fatal error.
/// The callback renders observations only; it does not perform maintenance.
pub enum CachePruneEvent {
    Helpers {
        killed: u64,
        removed_dirs: u64,
        freed_bytes: u64,
    },
    OrphanBuilds(usize),
    Missing,
    StagingSkipped,
    StagingPreview(CacheEntry),
    RetiredHvfPreview {
        path: PathBuf,
        entries: u64,
    },
    FlowPreview,
    Standbys {
        inspected: usize,
        removed: usize,
    },
    Checkpoints(retention::CheckpointRetentionReport),
    Content(retention::ContentPruneReport),
    ExpiredPacks(usize),
    PackVersions(usize),
    TempPreview(CacheEntry),
    Retired {
        report: super::PruneReport,
        reclaim: bool,
    },
    DeepEmpty,
    Deep {
        entry: CacheEntry,
        label: &'static str,
        error: Option<String>,
    },
    Stage0Store(mvm_build::builder_vm::BuilderStoreRepair),
    Stage0StoreSkipped,
    Warning(String),
    Summary(CachePruneSummary),
    StoreFootprint(footprint::Stage0Footprint),
}

pub fn repair(request: &RepairRequest) -> Result<mvm_build::builder_vm::BuilderStoreRepair> {
    let cache = configured_cache()?;
    super::directory(&cache.join("builder-vm"))?;
    if !request.force && super::staging::in_flight() {
        anyhow::bail!(
            "a Stage 0 builder bootstrap appears to be in progress (lock held at \
             {}/builder-vm/stage0.lock). Refusing to clear the builder store from under \
             a live build. Wait for it to finish, or pass --force if you are certain the \
             lock is stale (e.g. after a crash).",
            cache.display()
        );
    }
    let report = match request.scope {
        RepairScope::StoreImage => mvm_build::builder_vm::clear_builder_store_image(!request.apply)
            .map_err(|e| anyhow::anyhow!("clearing builder store image: {e}"))?,
        RepairScope::BuilderStore => mvm_build::builder_vm::clear_builder_store(!request.apply)
            .map_err(|e| anyhow::anyhow!("clearing builder store: {e}"))?,
    };
    if request.apply && report.existed {
        mvm_core::audit_emit!(
            CachePrune,
            "op=builder_store_repair freed_bytes={} cache_dir={}",
            report.bytes_freed,
            report.path
        );
    }
    Ok(report)
}

fn configured_cache() -> Result<PathBuf> {
    super::directory(Path::new(&mvm_core::config::mvm_home()))?;
    let cache = PathBuf::from(mvm_core::config::mvm_cache_dir());
    super::directory(&cache)?;
    Ok(cache)
}

pub fn prune(
    request: &CachePruneRequest,
    mut emit: impl FnMut(CachePruneEvent),
) -> Result<CachePruneSummary> {
    let path = configured_cache()?;
    super::directory(&path.join("builder-vm"))?;
    // Pack pruning persists its index under this root. Reject directory
    // redirection before any sweep runs. The provider uses an exclusive
    // temporary file, so a pre-existing index.json.tmp is never opened.
    super::directory(&path.join("packs"))?;
    let dry_run = !request.apply;
    let orphan_dirs = request.orphan_dirs || request.deep;
    let action = stage0_store_reclaim_action(
        request.stage0_store,
        request.deep,
        super::staging::in_flight(),
    );
    if action == Stage0StoreReclaim::Refuse {
        anyhow::bail!(
            "a Stage 0 bootstrap appears to be in progress (lock held at \
             {}/builder-vm/stage0.lock). Refusing to remove the Stage 0 store from \
             under it; run this again once the bootstrap finishes.",
            path.display()
        );
    }
    if !request.no_reap_orphans {
        match super::helpers::reap(dry_run) {
            Ok(o) => emit(CachePruneEvent::Helpers {
                killed: o.killed,
                removed_dirs: o.removed_dirs,
                freed_bytes: o.freed_bytes,
            }),
            Err(e) => emit(CachePruneEvent::Warning(format!(
                "Orphan-helper reap failed: {e:#}"
            ))),
        }
    }
    if request.orphan_builds {
        match crate::manifest::prune(&crate::manifest::PruneRequest {
            orphans: true,
            dry_run,
        }) {
            Ok(report) => emit(CachePruneEvent::OrphanBuilds(if dry_run {
                report.candidates.len()
            } else {
                report.removed_count
            })),
            Err(e) => emit(CachePruneEvent::Warning(format!(
                "Orphan-build prune failed: {e}"
            ))),
        }
    }
    let mut summary = CachePruneSummary::default();
    if !path.exists() {
        summary.missing = true;
        emit(CachePruneEvent::Missing);
        if request.apply {
            mvm_core::audit_emit!(CachePrune, "removed=0 freed_bytes=0 cache_dir=missing");
        }
        return Ok(summary);
    }
    match super::staging::sweep(dry_run, |path, bytes| {
        emit(CachePruneEvent::StagingPreview(CacheEntry { path, bytes }));
    }) {
        Ok(super::staging::Stage0SweepOutcome::Swept {
            removed,
            freed_bytes,
        }) => {
            summary.removed += removed;
            summary.freed_bytes += freed_bytes;
        }
        Ok(super::staging::Stage0SweepOutcome::SkippedLockHeld) => {
            emit(CachePruneEvent::StagingSkipped)
        }
        Err(e) => emit(CachePruneEvent::Warning(format!(
            "Stage 0 staging sweep failed: {e:#}"
        ))),
    }
    let retired = path.join("builder-vm").join(RETIRED_HVF_IMAGE_DIR);
    match sweep_retired_hvf_builder_images(&retired, dry_run, &mut emit) {
        Ok((removed, bytes)) => {
            summary.removed += removed;
            summary.freed_bytes += bytes;
        }
        Err(e) => emit(CachePruneEvent::Warning(format!(
            "removing retired HVF builder images under {}: {e}",
            retired.display()
        ))),
    }
    match super::prune_flow_bytes(&FlowRetentionRequest {
        apply: request.apply,
    }) {
        Ok(report) if dry_run && !report.candidates.is_empty() => {
            emit(CachePruneEvent::FlowPreview)
        }
        Ok(report) => summary.removed += report.removed.len() as u64,
        Err(e) => emit(CachePruneEvent::Warning(format!(
            "flow-byte-log sweep failed: {e}"
        ))),
    }
    match standby::prune(&standby::StandbyPruneRequest {
        apply: request.apply,
    }) {
        Ok(report) => {
            summary.removed += report.removed as u64;
            emit(CachePruneEvent::Standbys {
                inspected: report.inspected,
                removed: report.removed,
            });
        }
        Err(_) if dry_run => {}
        Err(e) => emit(CachePruneEvent::Warning(format!(
            "standby pool reap failed: {e}"
        ))),
    }
    let checkpoints = retention::prune(&retention::CheckpointRetentionRequest {
        apply: request.apply,
    });
    if request.apply {
        summary.removed += checkpoints.removed.len() as u64;
    }
    emit(CachePruneEvent::Checkpoints(checkpoints));
    match retention::prune_content(&retention::ContentPruneRequest {
        apply: request.apply,
    }) {
        Ok(report) => {
            summary.removed += report.entries();
            summary.freed_bytes += report.bytes();
            emit(CachePruneEvent::Content(report));
        }
        Err(e) => emit(CachePruneEvent::Warning(format!(
            "checkpoint content sweep failed: {e:#}"
        ))),
    }
    match mvm_core::pack_cache::prune_expired_packs(chrono::Utc::now(), dry_run) {
        Ok(expired) => {
            if request.apply && !expired.is_empty() {
                mvm_core::audit_emit!(
                    CachePrune,
                    "source=pack_cache_prune count={}",
                    expired.len()
                );
            }
            summary.removed += expired.len() as u64;
            emit(CachePruneEvent::ExpiredPacks(expired.len()));
        }
        Err(e) => emit(CachePruneEvent::Warning(format!(
            "expired-pack sweep failed: {e}"
        ))),
    }
    match mvm_core::pack_cache::prune_versions(PACK_VERSION_KEEP_RECENT, dry_run) {
        Ok(pruned) => {
            if request.apply && !pruned.is_empty() {
                mvm_core::audit_emit!(
                    CachePrune,
                    "source=pack_version_prune count={}",
                    pruned.len()
                );
            }
            summary.removed += pruned.len() as u64;
            emit(CachePruneEvent::PackVersions(pruned.len()));
        }
        Err(e) => emit(CachePruneEvent::Warning(format!(
            "pack version prune failed: {e}"
        ))),
    }
    for entry in walkdir(&path)? {
        let entry_path = entry.path();
        if let Some(name) = entry_path.file_name().and_then(|n| n.to_str())
            && (name.starts_with("mvm-lima-") || name.ends_with(".tmp"))
        {
            let size = dir_size(&entry_path);
            if dry_run {
                emit(CachePruneEvent::TempPreview(CacheEntry {
                    path: entry_path,
                    bytes: size,
                }));
            } else {
                let _ = remove_cache_path(&entry_path);
            }
            // Historical temp cleanup is best effort and counts attempts.
            summary.removed += 1;
            summary.freed_bytes += size;
        }
    }
    let report = super::prune_retired(&RetiredPruneRequest {
        apply: orphan_dirs && request.apply,
    })?;
    if orphan_dirs {
        let entries = if dry_run {
            &report.candidates
        } else {
            &report.removed
        };
        summary.removed += entries.len() as u64;
        summary.freed_bytes += entries.iter().map(|e| e.bytes).sum::<u64>();
    }
    emit(CachePruneEvent::Retired {
        report,
        reclaim: orphan_dirs,
    });
    if request.deep {
        let targets = regenerable_cache_targets(&path);
        if targets.is_empty() {
            emit(CachePruneEvent::DeepEmpty);
        }
        for (entry, label) in targets {
            let error = if dry_run {
                None
            } else {
                remove_cache_path(&entry.path).err().map(|e| e.to_string())
            };
            if error.is_none() {
                summary.removed += 1;
                summary.freed_bytes += entry.bytes;
            }
            emit(CachePruneEvent::Deep {
                entry,
                label,
                error,
            });
        }
    }
    match action {
        Stage0StoreReclaim::Clear => {
            let report = mvm_build::builder_vm::clear_stage0_store_image(dry_run)
                .map_err(|e| anyhow::anyhow!("removing the Stage 0 store image: {e}"))?;
            if report.existed {
                summary.removed += 1;
                summary.freed_bytes += report.bytes_freed;
            }
            emit(CachePruneEvent::Stage0Store(report));
        }
        Stage0StoreReclaim::SkipInFlight => emit(CachePruneEvent::Stage0StoreSkipped),
        Stage0StoreReclaim::Keep | Stage0StoreReclaim::Refuse => {}
    }
    emit(CachePruneEvent::Summary(summary));
    emit(CachePruneEvent::StoreFootprint(footprint::stage0_at(
        &path,
        &path,
        &[],
    )));
    if request.apply {
        let removed = summary.removed;
        let freed = summary.freed_bytes;
        mvm_core::audit_emit!(CachePrune, "removed={removed} freed_bytes={freed}");
    }
    Ok(summary)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage0StoreReclaim {
    Keep,
    Clear,
    Refuse,
    SkipInFlight,
}

fn stage0_store_reclaim_action(
    requested: bool,
    deep: bool,
    bootstrap_in_flight: bool,
) -> Stage0StoreReclaim {
    match (requested, deep, bootstrap_in_flight) {
        (false, false, _) => Stage0StoreReclaim::Keep,
        (_, _, false) => Stage0StoreReclaim::Clear,
        (true, _, true) => Stage0StoreReclaim::Refuse,
        (false, true, true) => Stage0StoreReclaim::SkipInFlight,
    }
}

const PACK_VERSION_KEEP_RECENT: usize = 2;
const RETIRED_HVF_IMAGE_DIR: &str = "hvf";
const REGENERABLE_CACHE_ENTRIES: &[(&str, &str)] = &[
    (
        "stage0",
        "Stage 0 vendored blobs (re-fetched on next cold bootstrap)",
    ),
    (
        "default-microvm",
        "prebuilt default microVM image (rebuilt on next default-image use)",
    ),
    ("oci", "pulled OCI layers (re-pulled on next image pull)"),
    (
        "mount-images",
        "content-addressed mount images (rebuilt on next mount use)",
    ),
];

fn regenerable_cache_targets(cache_root: &Path) -> Vec<(CacheEntry, &'static str)> {
    REGENERABLE_CACHE_ENTRIES
        .iter()
        .filter_map(|(name, label)| {
            let path = cache_root.join(name);
            path.is_dir().then(|| {
                (
                    CacheEntry {
                        bytes: dir_size(&path),
                        path,
                    },
                    *label,
                )
            })
        })
        .collect()
}

fn sweep_retired_hvf_builder_images(
    root: &Path,
    dry_run: bool,
    emit: &mut impl FnMut(CachePruneEvent),
) -> std::io::Result<(u64, u64)> {
    if !root.is_dir() {
        return Ok((0, 0));
    }
    let mut entries = 0;
    for entry in std::fs::read_dir(root)? {
        if entry?.path().is_dir() {
            entries += 1;
        }
    }
    let bytes = dir_size(root);
    if dry_run {
        emit(CachePruneEvent::RetiredHvfPreview {
            path: root.to_owned(),
            entries,
        });
        return Ok((0, 0));
    }
    remove_cache_path(root)?;
    Ok((entries, bytes))
}

fn dir_size(path: &Path) -> u64 {
    mvm_core::disk_usage::tree_bytes(path)
}

/// Never descend through a link. Parent replacement between scan and unlink
/// remains the existing race; this is not an openat-based deletion sandbox.
fn walkdir(path: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries = Vec::new();
    if !path.is_dir() {
        return Ok(entries);
    }
    let mut pending = vec![path.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                pending.push(entry.path());
            }
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn remove_cache_path(path: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

#[cfg(test)]
mod tests;
