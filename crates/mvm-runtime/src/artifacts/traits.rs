//! Trait surface for the artifact build/write/validate pipeline.
//!
//! Five thin traits; slice-1 implements `MicrovmArtifactBuilder` (via
//! `NixMicrovmBuilder`), `FirecrackerConfigWriter`, and `ArtifactValidator`.
//! The others exist now so callers can be wired without waiting for deferred
//! implementations.

use mvm_core::arch::GuestArch;
use mvm_core::kernel_format::KernelFormat;

use crate::compat::MicrovmBackend;

use super::artifact::{
    BackendConfigArtifact, KernelArtifact, MicrovmArtifact, RootfsArtifact, ValidationReport,
};
use super::spec::{KernelSpec, MicrovmBuildSpec, RootfsSpec};

// ── error ─────────────────────────────────────────────────────────────────────

/// Typed errors for the artifact pipeline.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// The requested kernel format is not accepted by this backend + arch
    /// combination. Message mirrors the spec wording exactly.
    #[error(
        "Cannot build {backend:?} artifact for arch={arch}: \
         kernel format {got:?} not accepted; expected one of {expected:?}"
    )]
    IncompatibleKernelFormat {
        backend: MicrovmBackend,
        arch: GuestArch,
        /// Kernel format that was supplied.
        got: KernelFormat,
        /// Formats this backend accepts for this arch.
        expected: Vec<KernelFormat>,
    },

    /// I/O failure (file read/write, directory creation, etc.).
    #[error("artifact I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// SHA-256 digest of the file on disk doesn't match the manifest.
    #[error("hash mismatch for {path}: expected {expected}, got {actual}")]
    HashMismatch {
        path: std::path::PathBuf,
        expected: String,
        actual: String,
    },

    /// The operation is not implemented for this backend yet.
    #[error("not implemented for backend {backend:?}")]
    NotImplemented { backend: MicrovmBackend },
}

// ── traits ────────────────────────────────────────────────────────────────────

/// Build a kernel image from a `KernelSpec`.
pub trait KernelBuilder {
    fn build_kernel(&self, spec: &KernelSpec) -> Result<KernelArtifact, ArtifactError>;
}

/// Build a rootfs image from a `RootfsSpec`.
pub trait RootfsBuilder {
    fn build_rootfs(&self, spec: &RootfsSpec) -> Result<RootfsArtifact, ArtifactError>;
}

/// Build a complete `MicrovmArtifact` from a `MicrovmBuildSpec`.
///
/// Implementations typically delegate to a `KernelBuilder` + `RootfsBuilder`,
/// then assemble and validate the result.
pub trait MicrovmArtifactBuilder {
    fn build_microvm(&self, spec: &MicrovmBuildSpec) -> Result<MicrovmArtifact, ArtifactError>;
}

/// Write a backend-specific config file (e.g. `firecracker.json`) from a
/// `MicrovmArtifact`.
pub trait BackendConfigWriter {
    fn write_config(
        &self,
        artifact: &MicrovmArtifact,
    ) -> Result<BackendConfigArtifact, ArtifactError>;
}

/// Validate a `MicrovmArtifact` against the compat matrix and the filesystem.
///
/// Returns a `ValidationReport` accumulating every check result. The report's
/// `ok` field is `true` only when all checks pass.
pub trait ArtifactValidator {
    fn validate(&self, artifact: &MicrovmArtifact) -> Result<ValidationReport, ArtifactError>;
}
