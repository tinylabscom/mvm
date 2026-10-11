//! Narrow cache reclamation policies. Live cache names are never inferred from
//! the absence of an allow-list, and callers cannot supply arbitrary delete paths.

use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

mod admin;
pub mod footprint;
pub(crate) mod helpers;
pub mod retention;
pub(crate) mod staging;
pub mod standby;
mod status;

pub use admin::{
    CachePruneEvent, CachePruneRequest, CachePruneSummary, RepairRequest, RepairScope, prune,
    repair,
};
#[cfg(feature = "manifest-verify")]
pub use status::RuntimePackTrustInputs;
pub use status::{CacheStatusEntry, CacheStatusReport, status};
pub use status::{not_instant_reason, runtime_pack_diagnosis};

pub use helpers::{
    ReapOutcome, reap_orphaned_vm_helpers, sweep_orphaned_vm_helpers_before_spawn,
    sweep_orphaned_vm_helpers_on_startup,
};
pub use staging::{
    Stage0SweepOutcome, stage0_active_in_process, stage0_bootstrap_in_flight,
    sweep_orphaned_stage0_staging_dirs,
};

/// Only subsystems that no longer have any readers or writers belong here.
pub const RETIRED_CACHE_ENTRIES: &[&str] = &["docker-nix-store", "builder-nix-store"];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RetiredPruneRequest {
    #[serde(default)]
    pub apply: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct FlowRetentionRequest {
    #[serde(default)]
    pub apply: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CacheEntry {
    pub path: PathBuf,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PruneReport {
    pub candidates: Vec<CacheEntry>,
    pub removed: Vec<CacheEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("cache maintenance refused an unsafe path: {0:?}")]
    UnsafePath(PathBuf),
    #[error("cache maintenance could not access {path:?}: {kind}")]
    Io {
        path: PathBuf,
        kind: std::io::ErrorKind,
    },
}

fn io_error(path: &Path, error: std::io::Error) -> CacheError {
    CacheError::Io {
        path: path.to_owned(),
        kind: error.kind(),
    }
}

fn metadata(path: &Path) -> Result<Option<std::fs::Metadata>, CacheError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(path, error)),
    }
}

fn directory(path: &Path) -> Result<bool, CacheError> {
    if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
        return Err(CacheError::UnsafePath(path.to_owned()));
    }
    match metadata(path)? {
        Some(metadata) if metadata.is_dir() => Ok(true),
        Some(_) => Err(CacheError::UnsafePath(path.to_owned())),
        None => Ok(false),
    }
}

/// Read-only classification, also useful for cache-info frontends.
pub fn retired_entries_at(root: &Path) -> Result<Vec<CacheEntry>, CacheError> {
    if !directory(root)? {
        return Ok(Vec::new());
    }
    let mut candidates = Vec::new();
    for name in RETIRED_CACHE_ENTRIES {
        let path = root.join(name);
        if metadata(&path)?.is_some() {
            candidates.push(CacheEntry {
                bytes: checked_tree_bytes(&path)?,
                path,
            });
        }
    }
    candidates.sort_by_key(|entry| std::cmp::Reverse(entry.bytes));
    Ok(candidates)
}

/// Reclassifies the configured cache at apply time; never consumes a preview's
/// paths. Unknown and live names are retained even when they resemble temp files.
pub fn prune_retired(request: &RetiredPruneRequest) -> Result<PruneReport, CacheError> {
    let home = PathBuf::from(mvm_core::config::mvm_home());
    directory(&home)?;
    prune_retired_with(
        Path::new(&mvm_core::config::mvm_cache_dir()),
        request,
        &mut audit_removed,
    )
}

fn prune_retired_with(
    root: &Path,
    request: &RetiredPruneRequest,
    on_removed: &mut dyn FnMut(&CacheEntry),
) -> Result<PruneReport, CacheError> {
    let mut report = PruneReport {
        candidates: retired_entries_at(root)?,
        removed: Vec::new(),
    };
    if request.apply {
        for candidate in &report.candidates {
            // Re-stat after classification. A replaced symlink is unlinked,
            // never followed into its destination.
            directory(root)?;
            if let Some(current) = metadata(&candidate.path)? {
                let removal = if current.is_dir() {
                    std::fs::remove_dir_all(&candidate.path)
                } else {
                    std::fs::remove_file(&candidate.path)
                };
                removal.map_err(|error| io_error(&candidate.path, error))?;
                on_removed(candidate);
                report.removed.push(candidate.clone());
            }
        }
    }
    Ok(report)
}

/// Apply the conservative seven-day retention window to encrypted flow-byte
/// records. No payload or key is opened, decrypted, or included in the report.
pub fn prune_flow_bytes(request: &FlowRetentionRequest) -> Result<PruneReport, CacheError> {
    let home = PathBuf::from(mvm_core::config::mvm_home());
    directory(&home)?;
    let audit = mvm_core::config::mvm_audit_dir();
    directory(&audit)?;
    prune_flow_bytes_with(
        &audit.join("flow-bytes"),
        request,
        SystemTime::now(),
        &mut audit_removed,
    )
}

fn prune_flow_bytes_with(
    root: &Path,
    request: &FlowRetentionRequest,
    now: SystemTime,
    on_removed: &mut dyn FnMut(&CacheEntry),
) -> Result<PruneReport, CacheError> {
    let mut report = PruneReport::default();
    if !directory(root)? {
        return Ok(report);
    }
    let cutoff = now
        .checked_sub(Duration::from_secs(7 * 86_400))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    for tenant in std::fs::read_dir(root).map_err(|error| io_error(root, error))? {
        let tenant = tenant.map_err(|error| io_error(root, error))?.path();
        // Tenant symlinks must not redirect retention outside the audit tree.
        if !directory(&tenant)? {
            continue;
        }
        for entry in std::fs::read_dir(&tenant).map_err(|error| io_error(&tenant, error))? {
            let path = entry.map_err(|error| io_error(&tenant, error))?.path();
            let Some(meta) = metadata(&path)? else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            if meta.modified().map_err(|error| io_error(&path, error))? < cutoff {
                report.candidates.push(CacheEntry {
                    bytes: allocated_bytes(&meta),
                    path,
                });
            }
        }
    }
    report.candidates.sort_by(|a, b| a.path.cmp(&b.path));
    if request.apply {
        for candidate in &report.candidates {
            directory(root)?;
            if let Some(parent) = candidate.path.parent() {
                directory(parent)?;
            }
            // A writer may have refreshed the record since the scan. Retain
            // that record rather than executing stale preview decisions.
            let Some(meta) = metadata(&candidate.path)? else {
                continue;
            };
            if meta.is_file()
                && meta
                    .modified()
                    .map_err(|error| io_error(&candidate.path, error))?
                    < cutoff
            {
                std::fs::remove_file(&candidate.path)
                    .map_err(|error| io_error(&candidate.path, error))?;
                on_removed(candidate);
                report.removed.push(candidate.clone());
            }
        }
    }
    Ok(report)
}

fn audit_removed(entry: &CacheEntry) {
    // Record each completed deletion, even if a later entry fails. Payloads,
    // tenant names and secret-bearing paths never enter the audit message.
    mvm_core::audit_emit!(
        CachePrune,
        "source=host_cache_maintenance removed=1 freed_bytes={}",
        entry.bytes
    );
}

fn allocated_bytes(metadata: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.blocks().saturating_mul(512)
    }
    #[cfg(not(unix))]
    {
        metadata.len()
    }
}

fn checked_tree_bytes(path: &Path) -> Result<u64, CacheError> {
    let Some(meta) = metadata(path)? else {
        return Ok(0);
    };
    if !meta.is_dir() {
        return Ok(allocated_bytes(&meta));
    }
    let mut bytes = 0u64;
    for entry in std::fs::read_dir(path).map_err(|error| io_error(path, error))? {
        let entry = entry.map_err(|error| io_error(path, error))?;
        bytes = bytes.saturating_add(checked_tree_bytes(&entry.path())?);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prune_retired_at(
        root: &Path,
        request: &RetiredPruneRequest,
    ) -> Result<PruneReport, CacheError> {
        prune_retired_with(root, request, &mut |_| {})
    }

    fn prune_flow_bytes_at(
        root: &Path,
        request: &FlowRetentionRequest,
        now: SystemTime,
    ) -> Result<PruneReport, CacheError> {
        prune_flow_bytes_with(root, request, now, &mut |_| {})
    }

    #[test]
    fn retired_preview_apply_and_repeat_preserve_live_and_unknown_names() {
        let root = tempfile::tempdir().unwrap();
        for name in ["builder-nix-store", "builder-vm", "stage0", "new-cache.tmp"] {
            std::fs::create_dir(root.path().join(name)).unwrap();
            std::fs::write(root.path().join(name).join("payload"), b"data").unwrap();
        }
        let request: RetiredPruneRequest = serde_json::from_str("{}").unwrap();
        assert!(!request.apply);
        let preview = prune_retired_at(root.path(), &request).unwrap();
        assert_eq!(preview.candidates.len(), 1);
        assert!(preview.removed.is_empty());
        assert!(root.path().join("builder-nix-store").exists());
        let report = prune_retired_at(root.path(), &RetiredPruneRequest { apply: true }).unwrap();
        assert_eq!(report.removed.len(), 1);
        assert!(
            prune_retired_at(root.path(), &RetiredPruneRequest { apply: true })
                .unwrap()
                .removed
                .is_empty()
        );
        for name in ["builder-vm", "stage0", "new-cache.tmp"] {
            assert!(root.path().join(name).join("payload").exists());
        }
        let decoded: PruneReport =
            serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert_eq!(decoded, report);
    }

    #[test]
    fn retention_is_nonmutating_in_preview_and_reclassifies_refreshed_records() {
        let root = tempfile::tempdir().unwrap();
        let tenant = root.path().join("tenant");
        std::fs::create_dir(&tenant).unwrap();
        let path = tenant.join("record.bin");
        std::fs::write(&path, b"opaque encrypted bytes").unwrap();
        let now = SystemTime::now() + Duration::from_secs(8 * 86_400);
        let preview =
            prune_flow_bytes_at(root.path(), &FlowRetentionRequest::default(), now).unwrap();
        assert_eq!(preview.candidates.len(), 1);
        assert!(path.exists());
        let request = FlowRetentionRequest { apply: true };
        let current = prune_flow_bytes_at(root.path(), &request, SystemTime::now()).unwrap();
        assert!(current.removed.is_empty());
        assert_eq!(
            prune_flow_bytes_at(root.path(), &request, now)
                .unwrap()
                .removed
                .len(),
            1
        );
        assert!(
            prune_flow_bytes_at(root.path(), &request, now)
                .unwrap()
                .removed
                .is_empty()
        );
    }

    #[test]
    #[cfg(unix)]
    fn symlinks_never_escape_the_cache_or_audit_tree() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("keep"), b"keep").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("builder-nix-store")).unwrap();
        prune_retired_at(root.path(), &RetiredPruneRequest { apply: true }).unwrap();
        assert!(outside.path().join("keep").exists());
        std::os::unix::fs::symlink(outside.path(), root.path().join("tenant")).unwrap();
        assert!(matches!(
            prune_flow_bytes_at(
                root.path(),
                &FlowRetentionRequest { apply: true },
                SystemTime::now()
            ),
            Err(CacheError::UnsafePath(_))
        ));
        assert!(outside.path().join("keep").exists());
        assert!(retired_entries_at(Path::new("/tmp/../escape")).is_err());
    }

    #[test]
    fn malformed_roots_fail_closed_and_errors_do_not_contain_payloads() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"SECRET-CONTENT").unwrap();
        let error = retired_entries_at(file.path()).unwrap_err();
        assert!(!error.to_string().contains("SECRET-CONTENT"));
        assert!(retired_entries_at(Path::new("relative")).is_err());
        assert!(serde_json::from_str::<RetiredPruneRequest>(r#"{"paths":["/"]}"#).is_err());
    }

    #[test]
    fn seven_day_boundary_and_mutation_notifications_are_exact() {
        let root = tempfile::tempdir().unwrap();
        let tenant = root.path().join("tenant");
        std::fs::create_dir(&tenant).unwrap();
        let path = tenant.join("record.bin");
        std::fs::write(&path, b"opaque").unwrap();
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        let boundary = modified + Duration::from_secs(7 * 86_400);
        let mut notifications = 0;
        let mut notify = |_: &CacheEntry| notifications += 1;
        let request = FlowRetentionRequest { apply: true };
        let report = prune_flow_bytes_with(root.path(), &request, boundary, &mut notify).unwrap();
        assert!(report.candidates.is_empty());
        assert!(path.exists());
        let expired = boundary + Duration::from_secs(1);
        let report = prune_flow_bytes_with(root.path(), &request, expired, &mut notify).unwrap();
        assert_eq!(report.removed.len(), 1);
        assert_eq!(notifications, 1);
    }

    #[test]
    #[cfg(unix)]
    fn inaccessible_metadata_is_not_treated_as_an_empty_cache() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("record"), b"secret-value").unwrap();
        std::os::unix::fs::symlink("loop", root.path().join("loop")).unwrap();
        let error = retired_entries_at(&root.path().join("loop/cache")).unwrap_err();
        assert!(matches!(error, CacheError::Io { .. }));
        assert!(!error.to_string().contains("secret-value"));
        assert!(root.path().join("record").exists());
    }
}
