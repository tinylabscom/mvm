//! Thin volume types — name + device path + stats.

use super::backend::BackendVolumeStats;
use std::path::PathBuf;

/// A volume name within a pool. Validated to match
/// `[a-zA-Z][a-zA-Z0-9_-]*` so it's safe to pass to `dmsetup` (no
/// shell-meta, no leading dot).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VolumeId(String);

impl VolumeId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for VolumeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A live thin volume. Carries the device path so callers (e.g.
/// Firecracker drive setup) know where to point.
#[derive(Debug, Clone)]
pub struct ThinVolume {
    id: VolumeId,
    device_path: PathBuf,
}

impl ThinVolume {
    pub fn new(id: VolumeId, device_path: PathBuf) -> Self {
        Self { id, device_path }
    }

    pub fn id(&self) -> &VolumeId {
        &self.id
    }

    pub fn device_path(&self) -> &PathBuf {
        &self.device_path
    }
}

/// Per-volume stats surfaced to `mvmctl storage info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VolumeStats {
    pub used_bytes: u64,
    pub virtual_size_bytes: u64,
}

impl From<BackendVolumeStats> for VolumeStats {
    fn from(b: BackendVolumeStats) -> Self {
        Self {
            used_bytes: b.used_bytes,
            virtual_size_bytes: b.virtual_size_bytes,
        }
    }
}
