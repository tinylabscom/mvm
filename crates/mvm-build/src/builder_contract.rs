//! Platform-neutral inputs and version contract for a builder shell job.

use std::path::PathBuf;

/// Minimum builder image cache contract this host reads.
pub const BUILDER_VM_CACHE_CONTRACT_VERSION: u32 = 5;

/// An extra disk following the builder's persistent Nix-store disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderExtraDisk {
    pub id: String,
    pub path: PathBuf,
    pub read_only: bool,
}

/// A staged shell job, independent of the runtime that executes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderShellJob {
    pub work_dir: PathBuf,
    pub artifact_out: PathBuf,
    pub script: String,
    pub extra_disks: Vec<BuilderExtraDisk>,
}
