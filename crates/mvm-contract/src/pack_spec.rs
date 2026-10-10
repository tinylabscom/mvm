//! Closed, language-neutral authored pack input.
//!
//! This is not Workload IR, a lock, a build result, or release metadata. Future
//! resolution lowers this input into the existing IR/compiler, rather than
//! introducing a second compiler. Deserialization and canonicalization validate
//! the whole document. Direct Rust construction must call [`PackSpec::validate`].

use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

use crate::ir::PythonTool;

/// Authored schema version, independent of bundle and Workload IR versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PackSpecSchema {
    #[serde(rename = "mvm.pack-spec/v1")]
    V1,
}

/// Explicit guest target, never inferred from the author's host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PackTarget {
    #[serde(rename = "x86_64-linux")]
    X86_64Linux,
    #[serde(rename = "aarch64-linux")]
    Aarch64Linux,
}

/// Local input tree, relative to the document directory. No executable source
/// expressions, host paths, OCI pulling, or source discovery in this version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PackSource {
    Local {
        #[cfg_attr(
            feature = "schema",
            schemars(
                length(min = 1, max = 4096),
                regex(pattern = r"^(\.|[^/\\:\x00-\x1f\x7f]+(/[^/\\:\x00-\x1f\x7f]+)*)$")
            )
        )]
        path: String,
    },
}

/// Whether a generic package is needed only while building or in the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PackageScope {
    Build,
    Runtime,
}

/// A generic package request, not a Python requirement or a resolved Nix
/// derivation. An absent version asks the future resolver to select and lock one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PackageRequest {
    #[cfg_attr(
        feature = "schema",
        schemars(
            length(min = 1, max = 128),
            regex(pattern = r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$")
        )
    )]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            length(min = 1, max = 128),
            regex(pattern = r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$")
        )
    )]
    pub version: Option<String>,
    pub scope: PackageScope,
}

/// Dependency file references relative to the source root, not inline packages.
/// No Python environment is implied by an empty dependency list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum DependencyFiles {
    Python {
        tool: PythonTool,
        manifest: String,
        lockfile: String,
    },
}

/// Copy a source-relative file/tree to a guest-absolute destination.
/// Ordering is semantic; materialization must reject symlink escapes later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CopyOperation {
    pub source: String,
    pub destination: String,
}

/// Advisory resource requests, not signed grants or admission authority.
/// Units are CPU cores and binary MiB; rootfs sizing is resolved
/// downstream, so the broader IR Resources shape is deliberately not reused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PackResources {
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 65535)))]
    pub cpu_cores: u16,
    /// Binary MiB: one unit is exactly 1_048_576 bytes. The wire name matches
    /// Workload IR; SDK `memory_mib` lowers here unchanged. Byte consumers must
    /// widen to u64 before multiplying by 1_048_576, never by decimal 1_000_000.
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 4294967295u64)))]
    pub memory_mb: u32,
}

/// Pack identity is separate from the generic package requests it contains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PackIdentity {
    /// Full namespace/name, preserved independently of any Workload IR ID.
    #[cfg_attr(
        feature = "schema",
        schemars(
            length(min = 3, max = 129),
            regex(
                pattern = r"^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?/[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$"
            )
        )
    )]
    pub name: String,
    /// SemVer 2.0 text, at most 128 ASCII bytes; numeric identifiers have no
    /// machine-integer bound. Prerelease and build spelling is preserved.
    #[cfg_attr(
        feature = "schema",
        schemars(
            length(min = 5, max = 128),
            regex(
                pattern = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$"
            )
        )
    )]
    pub version: String,
}

impl PackIdentity {
    /// Check the namespace/name grammar and SemVer 2.0 version text.
    pub fn validate(&self) -> Result<(), PackSpecError> {
        if pack_name(&self.name) && release_version(&self.version) {
            Ok(())
        } else {
            Err(PackSpecError::Identity)
        }
    }
}

/// Neutral authored DTO. All fields except package versions are required;
/// empty lists explicitly mean no packages, dependency files, or copies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PackSpecWire", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PackSpec {
    pub schema: PackSpecSchema,
    pub identity: PackIdentity,
    pub target: PackTarget,
    pub source: PackSource,
    pub packages: Vec<PackageRequest>,
    pub dependencies: Vec<DependencyFiles>,
    pub copy: Vec<CopyOperation>,
    /// Literal argv; no shell splitting, substitution, or evaluation.
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub entrypoint: Vec<String>,
    pub resources: PackResources,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackSpecWire {
    schema: PackSpecSchema,
    identity: PackIdentity,
    target: PackTarget,
    source: PackSource,
    packages: Vec<PackageRequest>,
    dependencies: Vec<DependencyFiles>,
    copy: Vec<CopyOperation>,
    entrypoint: Vec<String>,
    resources: PackResources,
}

impl TryFrom<PackSpecWire> for PackSpec {
    type Error = PackSpecError;

    fn try_from(wire: PackSpecWire) -> Result<Self, Self::Error> {
        let spec = Self {
            schema: wire.schema,
            identity: wire.identity,
            target: wire.target,
            source: wire.source,
            packages: wire.packages,
            dependencies: wire.dependencies,
            copy: wire.copy,
            entrypoint: wire.entrypoint,
            resources: wire.resources,
        };
        spec.validate()?;
        Ok(spec)
    }
}

/// Validation errors contain no file contents or credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PackSpecError {
    #[error("invalid pack identity: expected namespace/name and SemVer 2.0 version")]
    Identity,
    #[error("invalid package name or version token")]
    Package,
    #[error("unsafe path: expected normalized portable path without traversal")]
    Path,
    #[error("entrypoint must have a nonempty executable and no NUL bytes")]
    Entrypoint,
    #[error("CPU cores and memory MiB must be positive")]
    Resources,
    #[error("could not serialize PackSpec")]
    Serialization,
}

impl PackSpec {
    /// Validate both deserialized and directly constructed authored input.
    pub fn validate(&self) -> Result<(), PackSpecError> {
        self.identity.validate()?;
        let PackSource::Local { path } = &self.source;
        relative_path(path, true)?;
        for package in &self.packages {
            if !token(&package.name) || package.version.as_deref().is_some_and(|v| !token(v)) {
                return Err(PackSpecError::Package);
            }
        }
        for dependency in &self.dependencies {
            let DependencyFiles::Python {
                manifest, lockfile, ..
            } = dependency;
            relative_path(manifest, false)?;
            relative_path(lockfile, false)?;
        }
        for copy in &self.copy {
            relative_path(&copy.source, true)?;
            if copy.destination.len() > 4096 {
                return Err(PackSpecError::Path);
            }
            let destination = copy
                .destination
                .strip_prefix('/')
                .ok_or(PackSpecError::Path)?;
            relative_path(destination, false)?;
        }
        if self.entrypoint.first().is_none_or(|v| v.trim().is_empty())
            || self.entrypoint.iter().any(|v| v.contains('\0'))
        {
            return Err(PackSpecError::Entrypoint);
        }
        if self.resources.cpu_cores == 0 || self.resources.memory_mb == 0 {
            return Err(PackSpecError::Resources);
        }
        Ok(())
    }

    /// Compact UTF-8 JSON, sorted object keys, no trailing newline. Explicit
    /// null package versions become omitted. Lists and strings are preserved
    /// byte-for-byte; paths are rejected rather than silently rewritten.
    /// This is authored normalization, NOT a lock digest or signature format.
    pub fn canonical_json(&self) -> Result<Vec<u8>, PackSpecError> {
        self.validate()?;
        // A Value's object map is sorted even when a caller enables serde_json's
        // preserve_order feature elsewhere in the dependency graph.
        let mut value = serde_json::to_value(self).map_err(|_| PackSpecError::Serialization)?;
        value.sort_all_objects();
        serde_json::to_vec(&value).map_err(|_| PackSpecError::Serialization)
    }
}

fn pack_name(value: &str) -> bool {
    value
        .split_once('/')
        .is_some_and(|(namespace, name)| pack_component(namespace) && pack_component(name))
}

/// Registry reference component grammar, without a host/runtime dependency.
fn pack_component(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

pub(crate) fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))
}

fn release_version(value: &str) -> bool {
    if value.len() > 128 {
        return false;
    }
    let (version, build) = value
        .split_once('+')
        .map_or((value, None), |(v, b)| (v, Some(b)));
    if build.is_some_and(|b| !b.split('.').all(version_identifier)) {
        return false;
    }
    let (core, prerelease) = version
        .split_once('-')
        .map_or((version, None), |(v, p)| (v, Some(p)));
    if prerelease.is_some_and(|p| {
        !p.split('.').all(|id| {
            version_identifier(id)
                && (!id.bytes().all(|b| b.is_ascii_digit()) || decimal_identifier(id))
        })
    }) {
        return false;
    }
    let mut parts = core.split('.');
    (0..3).all(|_| parts.next().is_some_and(decimal_identifier)) && parts.next().is_none()
}

fn decimal_identifier(value: &str) -> bool {
    !value.is_empty()
        && (value.len() == 1 || !value.starts_with('0'))
        && value.bytes().all(|b| b.is_ascii_digit())
}

fn version_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn relative_path(value: &str, allow_root: bool) -> Result<(), PackSpecError> {
    if allow_root && value == "." {
        return Ok(());
    }
    if value.is_empty()
        || value.len() > 4096
        || value
            .chars()
            .any(|c| c.is_control() || c == '\\' || c == ':')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(PackSpecError::Path);
    }
    Ok(())
}
