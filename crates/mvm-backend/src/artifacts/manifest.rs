//! Build-level artifact manifest (`manifest.json`).
//!
//! Written next to the kernel + rootfs by every build path that produces a
//! `MicrovmArtifact`. This is the *build* manifest — distinct from the mkGuest
//! runtime sidecar (`GuestSidecar` / `mvm-meta.json`), which carries
//! overlay-aware/accessible/sealed gates checked at admission time.
//!
//! ## File layout
//!
//! ```text
//! <artifact-dir>/
//!   vmlinux          (or Image, etc.)
//!   rootfs.ext4
//!   firecracker.json (if a BackendConfigWriter ran)
//!   manifest.json    ← this struct
//! ```

use std::io;
use std::path::{Path, PathBuf};

use mvm_core::arch::GuestArch;
use mvm_core::kernel_format::KernelFormat;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::compat::{MicrovmBackend, RootfsFormat};

use super::artifact::ValidationReport;

pub const MANIFEST_FILENAME: &str = "manifest.json";

// ── embedded sub-structs ──────────────────────────────────────────────────────

/// Flake-derived provenance embedded in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Flake reference used for the build (e.g. `git+file:///path#attr`).
    pub flake_ref: Option<String>,
    /// `nix flake lock` hash from the build's lock file.
    pub lock_hash: Option<String>,
}

/// Kernel fields inlined into the manifest (mirrors `KernelArtifact` minus
/// the heavyweight `PathBuf` — paths are relative to the manifest directory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestKernel {
    pub path: PathBuf,
    pub format: KernelFormat,
    /// SHA-256 hex digest.
    pub hash: String,
    pub version: Option<String>,
}

/// Rootfs fields inlined into the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestRootfs {
    pub path: PathBuf,
    pub format: RootfsFormat,
    /// SHA-256 hex digest.
    pub hash: String,
    pub size: u64,
}

// ── manifest ──────────────────────────────────────────────────────────────────

/// Build-level manifest written as `manifest.json` in the artifact directory.
///
/// `timestamp_unix` is caller-supplied; do not call `SystemTime::now()` here —
/// the build pipeline passes the timestamp so it stays deterministic in tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactManifest {
    /// Stable UUID v4 for this artifact set.
    pub artifact_id: Uuid,
    /// Opaque build identifier from the calling pipeline.
    pub build_id: String,
    /// Tenant scope, if set.
    pub tenant_id: Option<String>,
    pub arch: GuestArch,
    pub backend: MicrovmBackend,
    pub kernel: ManifestKernel,
    pub rootfs: ManifestRootfs,
    /// Path to the backend-specific config file (e.g. `firecracker.json`),
    /// if a `BackendConfigWriter` has run.
    pub config_path: Option<PathBuf>,
    /// Flake + lock provenance, when the artifact came from a Nix build.
    pub provenance: Option<Provenance>,
    /// Semver string of the mvmctl/mvm-backend crate that wrote this manifest.
    pub builder_version: String,
    /// Unix epoch seconds at the time the build completed. Caller-supplied.
    pub timestamp_unix: u64,
    /// Validation result, if `ArtifactValidator::validate` has been run.
    pub validation: Option<ValidationReport>,
}

impl ArtifactManifest {
    /// Canonical path for a manifest inside `dir`.
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(MANIFEST_FILENAME)
    }

    /// Write the manifest to `dir/manifest.json`.
    ///
    /// Creates the directory if it doesn't exist. Returns the path written.
    pub fn write_to_dir(&self, dir: &Path) -> io::Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        let path = Self::path_in(dir);
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, format!("{body}\n"))?;
        Ok(path)
    }

    /// Read a manifest from `dir/manifest.json`.
    ///
    /// Returns `Ok(None)` when the file doesn't exist (pre-manifest artifact
    /// dir). Errors on malformed JSON.
    pub fn read_from_dir(dir: &Path) -> anyhow::Result<Option<Self>> {
        let path = Self::path_in(dir);
        let body = match std::fs::read_to_string(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(anyhow::Error::new(e)),
        };
        let m: Self = serde_json::from_str(&body)
            .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
        Ok(Some(m))
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::arch::GuestArch;
    use mvm_core::kernel_format::KernelFormat;

    use crate::compat::{MicrovmBackend, RootfsFormat};

    fn fixture_manifest() -> ArtifactManifest {
        ArtifactManifest {
            artifact_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            build_id: "test-build-001".to_string(),
            tenant_id: Some("test-tenant".to_string()),
            arch: GuestArch::Aarch64,
            backend: MicrovmBackend::Firecracker,
            kernel: ManifestKernel {
                path: PathBuf::from("Image"),
                format: KernelFormat::Image,
                hash: "abc123def456".to_string(),
                version: Some("6.1.0".to_string()),
            },
            rootfs: ManifestRootfs {
                path: PathBuf::from("rootfs.ext4"),
                format: RootfsFormat::Ext4,
                hash: "deadbeef1234".to_string(),
                size: 1_073_741_824,
            },
            config_path: Some(PathBuf::from("firecracker.json")),
            provenance: Some(Provenance {
                flake_ref: Some("git+file:///repo#packages.aarch64-linux.default".to_string()),
                lock_hash: Some("sha256-abc".to_string()),
            }),
            builder_version: "0.1.0".to_string(),
            timestamp_unix: 1_748_000_000,
            validation: None,
        }
    }

    #[test]
    fn manifest_roundtrips() {
        let m = fixture_manifest();
        let dir = tempfile::tempdir().unwrap();
        let p = m.write_to_dir(dir.path()).unwrap();
        assert_eq!(p, dir.path().join("manifest.json"));
        assert_eq!(
            ArtifactManifest::read_from_dir(dir.path())
                .unwrap()
                .unwrap(),
            m
        );
    }

    #[test]
    fn missing_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let result = ArtifactManifest::read_from_dir(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn malformed_json_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(MANIFEST_FILENAME), "{not json").unwrap();
        let result = ArtifactManifest::read_from_dir(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn written_file_is_newline_terminated() {
        let m = fixture_manifest();
        let dir = tempfile::tempdir().unwrap();
        m.write_to_dir(dir.path()).unwrap();
        let raw = std::fs::read_to_string(dir.path().join(MANIFEST_FILENAME)).unwrap();
        assert!(raw.ends_with('\n'));
    }

    #[test]
    fn serde_roundtrip_preserves_all_fields() {
        let m = fixture_manifest();
        let json = serde_json::to_string(&m).unwrap();
        let parsed: ArtifactManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, parsed);
    }
}
