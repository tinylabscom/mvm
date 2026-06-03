//! Build output types.
//!
//! These are the typed results of a build run. They are distinct from the
//! mkGuest runtime sidecar (`GuestSidecar` / `mvm-meta.json`), which carries
//! runtime-gate metadata (overlay-aware, accessible, sealed).

use std::path::PathBuf;

use mvm_core::arch::GuestArch;
use mvm_core::kernel_format::KernelFormat;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::compat::{MicrovmBackend, RootfsFormat};

/// A built or verified kernel image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelArtifact {
    pub path: PathBuf,
    pub format: KernelFormat,
    /// SHA-256 hex digest of the file at `path`.
    pub hash: String,
    /// Kernel version string extracted from the image, if available.
    pub version: Option<String>,
}

/// A built or verified rootfs image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootfsArtifact {
    pub path: PathBuf,
    pub format: RootfsFormat,
    /// SHA-256 hex digest of the file at `path`.
    pub hash: String,
    /// Size of the image file in bytes.
    pub size_bytes: u64,
    /// Whether the drive must be opened read-only by the backend.
    ///
    /// Verified-boot / prod path sets `true` (ADR-002 W3 — dm-verity requires
    /// the rootfs is opened RO so the Merkle check holds). Dev/sandbox mode
    /// may set `false` to allow in-guest writes.
    pub read_only: bool,
}

/// A complete set of artifacts that can boot a microVM.
///
/// Carries the kernel and rootfs together with the resolved arch/backend so
/// downstream consumers don't have to re-infer them. `config_path` points to
/// the backend-specific config file (e.g. `firecracker.json`) when one has
/// been written by a `BackendConfigWriter`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicrovmArtifact {
    /// Stable UUID v4 for this artifact set. Matches `ArtifactManifest.artifact_id`.
    pub id: Uuid,
    pub arch: GuestArch,
    pub backend: MicrovmBackend,
    pub kernel: KernelArtifact,
    pub rootfs: RootfsArtifact,
    /// Full kernel cmdline (required_boot_args + any extras from the spec).
    pub boot_args: Vec<String>,
    /// Path to the backend config file, if already written.
    pub config_path: Option<PathBuf>,
}

/// The backend-specific config file written for a `MicrovmArtifact`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendConfigArtifact {
    pub backend: MicrovmBackend,
    pub path: PathBuf,
}

/// Result of running `ArtifactValidator::validate`.
///
/// Stored inside `ArtifactManifest` so validation results travel with the
/// artifact directory without requiring a separate validate pass at boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    /// `true` iff every check passed.
    pub ok: bool,
    pub checks: Vec<ValidationCheck>,
}

/// A single named check inside a `ValidationReport`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCheck {
    pub name: String,
    pub ok: bool,
    /// Human-readable detail — empty string when ok, failure reason when not.
    pub detail: String,
}
