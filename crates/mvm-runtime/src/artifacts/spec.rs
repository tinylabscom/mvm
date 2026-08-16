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

/// Scheme prefixes that let a caller state which kind of source a string is,
/// overriding the shape heuristic below.
const PATH_SCHEME: &str = "path:";
const OCI_SCHEME: &str = "oci:";

/// Why a caller-supplied string is not a rootfs source at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootfsSourceParseError {
    #[error("empty rootfs source")]
    Empty,
    #[error("`{scheme}` prefix with no value")]
    EmptyPayload { scheme: &'static str },
}

impl RootfsSource {
    /// True for strings whose *shape* declares a filesystem location: an
    /// absolute path, an explicitly-relative one, or a home-relative one. An
    /// OCI reference can take none of these forms, so the two spaces do not
    /// overlap and the answer needs no filesystem lookup.
    fn is_path_shaped(s: &str) -> bool {
        s.starts_with('/')
            || s.starts_with("./")
            || s.starts_with("../")
            || s == "."
            || s == ".."
            || s.starts_with("~/")
    }
}

impl std::str::FromStr for RootfsSource {
    type Err = RootfsSourceParseError;

    /// Classify a caller-declared rootfs string **without consulting the
    /// filesystem**. What a string means is what the caller declared, not a
    /// function of what happens to exist in their working directory — probing
    /// makes a typo fall through to a different arm, and the arms differ in
    /// how the resulting bytes are verified.
    ///
    /// `Flake` is not reachable from a string: a flake source carries an
    /// attribute alongside the reference and is constructed by the build side.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Command substitution and file reads routinely carry a trailing
        // newline; the surrounding whitespace is never part of the intent.
        let s = s.trim();
        if s.is_empty() {
            return Err(RootfsSourceParseError::Empty);
        }
        if let Some(rest) = s.strip_prefix(PATH_SCHEME) {
            return non_empty(rest, PATH_SCHEME).map(|v| Self::LocalPath(PathBuf::from(v)));
        }
        if let Some(rest) = s.strip_prefix(OCI_SCHEME) {
            return non_empty(rest, OCI_SCHEME).map(|v| Self::Oci {
                image_ref: v.to_string(),
            });
        }
        if Self::is_path_shaped(s) {
            Ok(Self::LocalPath(PathBuf::from(s)))
        } else {
            Ok(Self::Oci {
                image_ref: s.to_string(),
            })
        }
    }
}

fn non_empty<'a>(value: &'a str, scheme: &'static str) -> Result<&'a str, RootfsSourceParseError> {
    if value.is_empty() {
        Err(RootfsSourceParseError::EmptyPayload { scheme })
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod rootfs_source_parse_tests {
    use super::*;

    fn parse(s: &str) -> Result<RootfsSource, RootfsSourceParseError> {
        s.parse()
    }

    fn local(p: &str) -> RootfsSource {
        RootfsSource::LocalPath(PathBuf::from(p))
    }

    fn oci(r: &str) -> RootfsSource {
        RootfsSource::Oci {
            image_ref: r.to_string(),
        }
    }

    #[test]
    fn path_shapes_parse_as_local_paths() {
        assert_eq!(
            parse("/var/lib/rootfs.ext4").unwrap(),
            local("/var/lib/rootfs.ext4")
        );
        assert_eq!(parse("./rootfs.ext4").unwrap(), local("./rootfs.ext4"));
        assert_eq!(
            parse("../out/rootfs.ext4").unwrap(),
            local("../out/rootfs.ext4")
        );
        assert_eq!(
            parse("~/images/rootfs.ext4").unwrap(),
            local("~/images/rootfs.ext4")
        );
        assert_eq!(parse(".").unwrap(), local("."));
    }

    #[test]
    fn registry_shapes_parse_as_oci_references() {
        assert_eq!(parse("alpine:3.20").unwrap(), oci("alpine:3.20"));
        assert_eq!(
            parse("docker.io/library/alpine:3.20").unwrap(),
            oci("docker.io/library/alpine:3.20")
        );
        // A bare name that could name a file in someone's cwd is still a
        // reference — nothing here looks at the filesystem.
        assert_eq!(parse("rootfs.ext4").unwrap(), oci("rootfs.ext4"));
    }

    #[test]
    fn schemes_override_the_shape_heuristic() {
        assert_eq!(parse("path:rootfs.ext4").unwrap(), local("rootfs.ext4"));
        assert_eq!(
            parse("oci:/weird/repo:tag").unwrap(),
            oci("/weird/repo:tag")
        );
    }

    #[test]
    fn empty_and_valueless_schemes_are_errors() {
        assert_eq!(parse("").unwrap_err(), RootfsSourceParseError::Empty);
        assert_eq!(parse("   \n").unwrap_err(), RootfsSourceParseError::Empty);
        assert_eq!(
            parse("path:").unwrap_err(),
            RootfsSourceParseError::EmptyPayload {
                scheme: PATH_SCHEME
            }
        );
        assert_eq!(
            parse("oci:").unwrap_err(),
            RootfsSourceParseError::EmptyPayload { scheme: OCI_SCHEME }
        );
    }

    #[test]
    fn surrounding_whitespace_is_not_part_of_the_declaration() {
        assert_eq!(
            parse("  /var/rootfs.ext4\n").unwrap(),
            local("/var/rootfs.ext4")
        );
    }
}
