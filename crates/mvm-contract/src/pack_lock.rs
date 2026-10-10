//! Frozen record of one resolved [`PackSpec`](crate::pack_spec::PackSpec).
//!
//! A lock binds the authored spec, the exact source snapshot it was resolved
//! against, the Workload IR it lowered to, and the compiler and mvm flake
//! revision that will render it. A frozen build recomputes every field from its
//! inputs and refuses to build when any differ, so a lock that no longer
//! describes its inputs is stale rather than silently reinterpreted.
//!
//! This is not a build result or release metadata: it carries no artifact
//! hashes, signatures, or publisher identity. Deserialization validates the
//! whole document; direct Rust construction must call [`PackLock::validate`].

use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

use crate::pack_spec::{PackIdentity, PackTarget, token};

/// Lock schema version, independent of the PackSpec and Workload IR versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PackLockSchema {
    #[serde(rename = "mvm.pack-lock/v1")]
    V1,
}

/// The compiler and flake inputs a locked pack is rendered with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct LockedCompiler {
    /// Version of the compiler that lowered and rendered the pack.
    pub toolchain_version: String,
    /// Format version of the rendered artifact directory.
    pub artifact_format_version: String,
    /// Full 40-character lowercase mvm commit. Generated flakes take nixpkgs
    /// from this input, so it pins the package set as well.
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 40, max = 40), regex(pattern = r"^[0-9a-f]{40}$"))
    )]
    pub mvm_revision: String,
}

/// Frozen resolution of one PackSpec. Every digest is lowercase hex SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PackLockWire", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PackLock {
    pub schema: PackLockSchema,
    /// Copied from the spec so a lock is attributable without it.
    pub identity: PackIdentity,
    pub target: PackTarget,
    /// Digest of the spec's canonical JSON.
    pub spec_sha256: String,
    /// Digest of the source snapshot: each regular file's relative path, mode
    /// and content, and each in-tree symlink's target.
    pub source_tree_sha256: String,
    /// RFC 8785 digest of the Workload IR the spec lowered to.
    pub workload_sha256: String,
    pub compiler: LockedCompiler,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackLockWire {
    schema: PackLockSchema,
    identity: PackIdentity,
    target: PackTarget,
    spec_sha256: String,
    source_tree_sha256: String,
    workload_sha256: String,
    compiler: LockedCompiler,
}

impl TryFrom<PackLockWire> for PackLock {
    type Error = PackLockError;

    fn try_from(wire: PackLockWire) -> Result<Self, Self::Error> {
        let lock = Self {
            schema: wire.schema,
            identity: wire.identity,
            target: wire.target,
            spec_sha256: wire.spec_sha256,
            source_tree_sha256: wire.source_tree_sha256,
            workload_sha256: wire.workload_sha256,
            compiler: wire.compiler,
        };
        lock.validate()?;
        Ok(lock)
    }
}

/// Validation errors carry no lock contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PackLockError {
    #[error("invalid pack identity: expected namespace/name and SemVer 2.0 version")]
    Identity,
    #[error("invalid digest: expected 64 lowercase hexadecimal characters")]
    Digest,
    #[error("invalid compiler version token")]
    Compiler,
    #[error("invalid mvm revision: expected a 40-character lowercase commit id")]
    Revision,
    #[error("could not serialize PackLock")]
    Serialization,
}

impl PackLock {
    /// Validate both deserialized and directly constructed locks.
    pub fn validate(&self) -> Result<(), PackLockError> {
        self.identity
            .validate()
            .map_err(|_| PackLockError::Identity)?;
        for digest in [
            &self.spec_sha256,
            &self.source_tree_sha256,
            &self.workload_sha256,
        ] {
            if !lower_hex(digest, 64) {
                return Err(PackLockError::Digest);
            }
        }
        if !token(&self.compiler.toolchain_version)
            || !token(&self.compiler.artifact_format_version)
        {
            return Err(PackLockError::Compiler);
        }
        if !lower_hex(&self.compiler.mvm_revision, 40) {
            return Err(PackLockError::Revision);
        }
        Ok(())
    }

    /// Compact UTF-8 JSON with sorted object keys and no trailing newline, the
    /// form a lock is written to disk in.
    pub fn canonical_json(&self) -> Result<Vec<u8>, PackLockError> {
        self.validate()?;
        let mut value = serde_json::to_value(self).map_err(|_| PackLockError::Serialization)?;
        value.sort_all_objects();
        serde_json::to_vec(&value).map_err(|_| PackLockError::Serialization)
    }
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
