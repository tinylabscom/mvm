//! Read-only cache inventory. Sparse images report both allocated and logical
//! bytes; unreadable entries retain the CLI's best-effort reporting behavior.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheFootprint {
    pub path: PathBuf,
    pub exists: bool,
    pub bytes: Option<u64>,
    pub entries: Vec<EntryFootprint>,
    pub stage0: Stage0Footprint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryFootprint {
    pub name: String,
    pub bytes: u64,
    pub retired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileFootprint {
    pub name: String,
    pub allocated_bytes: u64,
    pub logical_bytes: u64,
    pub age_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobFootprint {
    pub name: String,
    pub file: Option<FileFootprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactFootprint {
    pub arch: String,
    pub rootfs: Option<FileFootprint>,
    pub source_fingerprint_prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage0Footprint {
    pub blobs: Vec<BlobFootprint>,
    pub builder_path: PathBuf,
    pub builder_bytes: Option<u64>,
    pub stores: Vec<FileFootprint>,
    pub artifacts: Vec<ArtifactFootprint>,
    pub auto_gc_cap_gib: u64,
    pub auto_gc_override: String,
}

pub fn inspect() -> CacheFootprint {
    let root = PathBuf::from(mvm_core::config::mvm_cache_dir());
    let stage0 = mvm_build::stage0::stage0_cache_dir();
    let assets = mvm_build::stage0::assets_for_host_arch();
    let filenames: Vec<_> = assets.iter().map(|asset| asset.cache_filename).collect();
    inspect_at(&root, &stage0, &filenames)
}

/// Read-only path injection supports hosts inspecting an offline cache. This
/// report is never accepted as a deletion request.
pub fn inspect_at(root: &Path, stage0: &Path, filenames: &[&str]) -> CacheFootprint {
    CacheFootprint {
        path: root.to_owned(),
        exists: root.exists(),
        bytes: root
            .exists()
            .then(|| mvm_core::disk_usage::tree_bytes(root)),
        entries: entries_at(root),
        stage0: stage0_at(root, stage0, filenames),
    }
}

pub fn entries_at(root: &Path) -> Vec<EntryFootprint> {
    let mut entries: Vec<_> = paths(root)
        .into_iter()
        .map(|path| {
            let name = filename(&path);
            EntryFootprint {
                retired: super::RETIRED_CACHE_ENTRIES.contains(&name.as_str()),
                bytes: mvm_core::disk_usage::tree_bytes(&path),
                name,
            }
        })
        .collect();
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.bytes));
    entries
}

pub fn stage0_at(root: &Path, stage0: &Path, filenames: &[&str]) -> Stage0Footprint {
    let now = SystemTime::now();
    let builder = root.join("builder-vm");
    let mut report = Stage0Footprint {
        blobs: filenames
            .iter()
            .map(|name| BlobFootprint {
                name: (*name).to_owned(),
                file: file(&stage0.join(name), now),
            })
            .collect(),
        builder_bytes: builder
            .is_dir()
            .then(|| mvm_core::disk_usage::tree_bytes(&builder)),
        builder_path: builder.clone(),
        stores: Vec::new(),
        artifacts: Vec::new(),
        auto_gc_cap_gib: mvm_build::builder_vm_runtime::builder_store_gc_cap_kib() / 1024 / 1024,
        auto_gc_override: mvm_build::builder_vm_runtime::MVM_BUILDER_STORE_GC_GIB_ENV.to_owned(),
    };
    for path in paths(&builder) {
        let name = filename(&path);
        if path.is_file() && name.starts_with("nix-store-") && name.ends_with(".img") {
            if let Some(store) = file(&path, now) {
                report.stores.push(store);
            }
        } else if path.is_dir() && name != "vms" && !name.starts_with('.') {
            report.artifacts.push(ArtifactFootprint {
                arch: name,
                rootfs: file(&path.join("rootfs.ext4"), now),
                source_fingerprint_prefix: std::fs::read_to_string(path.join(".mvm-source.sha256"))
                    .ok()
                    .map(|value| value.trim().chars().take(8).collect()),
            });
        }
    }
    report
}

fn paths(root: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .collect();
    paths.sort();
    paths
}

fn filename(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn file(path: &Path, now: SystemTime) -> Option<FileFootprint> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(FileFootprint {
        name: filename(path),
        allocated_bytes: super::allocated_bytes(&metadata),
        logical_bytes: metadata.len(),
        age_secs: metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .map(|age| age.as_secs()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_reports_missing_blobs_and_retired_names_without_mutating() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("cache");
        let absent = inspect_at(&root, &root.join("stage0"), &["seed"]);
        assert!(!absent.exists);
        assert!(!root.exists());
        assert!(absent.stage0.blobs[0].file.is_none());
        std::fs::create_dir_all(root.join("builder-nix-store")).unwrap();
        std::fs::create_dir_all(root.join("builder-vm/aarch64")).unwrap();
        std::fs::write(
            root.join("builder-vm/aarch64/.mvm-source.sha256"),
            "1234567890\n",
        )
        .unwrap();
        let report = inspect_at(&root, &root.join("stage0"), &[]);
        assert!(report.entries.iter().any(|entry| entry.retired));
        assert_eq!(
            report.stage0.artifacts[0]
                .source_fingerprint_prefix
                .as_deref(),
            Some("12345678")
        );
        let json = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serde_json::from_str::<CacheFootprint>(&json).unwrap(),
            report
        );
    }

    #[cfg(unix)]
    #[test]
    fn sparse_store_reports_allocated_bytes_and_skips_live_vm_artifacts() {
        let home = tempfile::tempdir().unwrap();
        let builder = home.path().join("builder-vm");
        std::fs::create_dir_all(builder.join("vms")).unwrap();
        let image = std::fs::File::create(builder.join("nix-store-test.img")).unwrap();
        image.set_len(1 << 30).unwrap();
        let report = stage0_at(home.path(), home.path(), &[]);
        assert_eq!(report.stores.len(), 1);
        assert_eq!(report.stores[0].logical_bytes, 1 << 30);
        assert!(report.stores[0].allocated_bytes < report.stores[0].logical_bytes);
        assert!(report.artifacts.is_empty());
    }
}
