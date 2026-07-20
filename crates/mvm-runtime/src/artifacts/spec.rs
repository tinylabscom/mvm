//! Input specifications describing what to build.
//!
//! `KernelSpec` / `RootfsSpec` / `MicrovmBuildSpec` capture the caller's
//! requirements before any build runs. Implementations of the builder traits
//! consume these and produce the corresponding `*Artifact` types.

use std::path::PathBuf;

use mvm_core::arch::GuestArch;
use mvm_core::kernel_format::KernelFormat;
use serde::{Deserialize, Serialize};

use crate::compat::{MicrovmBackend, RootfsFormat};

/// Where the kernel comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelSource {
    /// Build from a Nix flake output at the given path/URL.
    Flake { flake_ref: String, attr: String },
    /// Use a pre-built kernel at the given local path.
    LocalPath(PathBuf),
    /// Use the builder VM's bundled kernel (libkrun embedded kernel).
    Bundled,
}

/// Where the rootfs comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootfsSource {
    /// Build from a Nix flake output at the given path/URL.
    Flake { flake_ref: String, attr: String },
    /// Use a pre-built rootfs image at the given local path.
    LocalPath(PathBuf),
    /// Import from an OCI image reference (pulled by the builder VM).
    Oci { image_ref: String },
}

/// What kernel to produce (or consume).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelSpec {
    pub arch: GuestArch,
    pub format: KernelFormat,
    pub source: KernelSource,
    /// Minimum version string (informational; not enforced at build time).
    pub min_version: Option<String>,
}

/// What rootfs to produce (or consume).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootfsSpec {
    pub arch: GuestArch,
    pub format: RootfsFormat,
    pub source: RootfsSource,
    /// Path inside the rootfs where the init binary must exist.
    /// Defaults to `/sbin/init` when `None`.
    pub init_path: Option<String>,
}

/// Full specification for building a `MicrovmArtifact`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicrovmBuildSpec {
    pub arch: GuestArch,
    pub backend: MicrovmBackend,
    pub kernel: KernelSpec,
    pub rootfs: RootfsSpec,
    /// Additional kernel cmdline tokens appended to the backend's
    /// `required_boot_args`. Must not contradict them.
    pub extra_boot_args: Vec<String>,
    /// Build ID from the calling pipeline (e.g. a git revision + timestamp).
    pub build_id: String,
    /// Optional tenant scope for the resulting manifest.
    pub tenant_id: Option<String>,
}
