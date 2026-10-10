//! Locked pack compilation through the shared workload compiler.
//!
//! A [`PackSpec`] lowers to a canonical [`Workload`](mvm_contract::ir::Workload)
//! and renders through [`compile_pinned`](crate::compile_pinned); there is no
//! pack-specific renderer. [`lock_pack`] records what a spec resolves to
//! against its current source tree, and [`compile_frozen`] builds only when a
//! recorded [`PackLock`](mvm_contract::pack_lock::PackLock) still matches.
//!
//! Lowering refuses what the IR and Nix factories cannot honor yet: build-scoped
//! packages, exact package versions, language dependency files and copy
//! operations. Package resolution, dependency installation and builder
//! execution happen elsewhere and are not implied by a successful compile.

mod frozen;
mod lock;
mod lower;

pub use frozen::{compile_frozen, lock_pack};
pub use lock::{LockField, spec_sha256, stale_fields};
pub use lower::{PACK_EXTENSION, PACK_ROOTFS_SIZE_MIB, lower};

use crate::mvm_pin::PinnedMvmRevision;
use crate::orchestrator::CompileError;
use crate::source::SourceError;
use mvm_contract::ir::ValidationError;
use mvm_contract::pack_lock::PackLockError;
use mvm_contract::pack_spec::{PackSpec, PackSpecError};
use std::io;
use std::path::{Path, PathBuf};

/// A spec, the directory its relative source path resolves against, and the
/// mvm revision its flake will pin.
#[derive(Debug, Clone, Copy)]
pub struct PackInput<'a> {
    pub spec: &'a PackSpec,
    pub spec_dir: &'a Path,
    pub revision: &'a PinnedMvmRevision,
}

#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("invalid pack spec: {0}")]
    Spec(#[from] PackSpecError),
    #[error("invalid pack lock: {0}")]
    Lock(#[from] PackLockError),
    #[error(
        "package {package:?} is build-scoped; the workload compiler has no build-only package set yet"
    )]
    UnsupportedBuildScope { package: String },
    #[error(
        "package {package:?} requests version {version:?}; exact package versions cannot be resolved yet"
    )]
    UnsupportedPackageVersion { package: String, version: String },
    #[error("language dependency files cannot be installed into a pack yet")]
    UnsupportedDependencies,
    #[error("copy operations cannot be materialized into a pack yet")]
    UnsupportedCopy,
    #[error("lowered workload is invalid: {}", join(.0))]
    InvalidWorkload(Vec<ValidationError>),
    #[error("source path {path:?} resolves outside the spec directory")]
    SourceEscape { path: String },
    #[error("source root {} is unusable: {source}", path.display())]
    SourceRoot { path: PathBuf, source: io::Error },
    #[error("source snapshot failed: {0}")]
    Source(SourceError),
    #[error("could not create snapshot staging: {0}")]
    Staging(#[source] io::Error),
    #[error("could not digest the lowered workload: {0}")]
    Digest(#[source] serde_json::Error),
    #[error("pack lock is stale: {} no longer match", join(.fields))]
    StaleLock { fields: Vec<LockField> },
    #[error("{0}")]
    Compile(CompileError),
}

fn join<T: std::fmt::Display>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::mvm_pin::PinnedMvmRevision;
    use mvm_contract::pack_spec::PackSpec;

    pub fn spec() -> PackSpec {
        serde_json::from_value(serde_json::json!({
            "schema": "mvm.pack-spec/v1",
            "identity": { "name": "acme/hello", "version": "1.0.0" },
            "target": "aarch64-linux",
            "source": { "kind": "local", "path": "." },
            "packages": [
                { "name": "busybox", "scope": "runtime" },
                { "name": "jq", "scope": "runtime" }
            ],
            "dependencies": [],
            "copy": [],
            "entrypoint": ["cat", "/app/hello.txt"],
            "resources": { "cpu_cores": 1, "memory_mb": 128 }
        }))
        .unwrap()
    }

    pub fn revision() -> PinnedMvmRevision {
        PinnedMvmRevision::parse("4e65b221744885e536ec91a3f2948cdc508dcb49").unwrap()
    }
}
