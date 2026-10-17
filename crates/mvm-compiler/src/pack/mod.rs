//! Locked pack compilation through the shared workload compiler.
//!
//! A [`PackSpec`] lowers to a canonical [`Workload`](mvm_contract::ir::Workload)
//! and renders through [`compile_pinned`](crate::compile_pinned); there is no
//! pack-specific renderer. [`lock_pack`] records what a spec resolves to
//! against its current source tree, and [`compile_frozen`] builds only when a
//! recorded [`PackLock`](mvm_contract::pack_lock::PackLock) still matches.
//!
//! Copy operations are materialized into an application tree assembled from
//! the verified source snapshot. An npm lockfile lowers to the IR's Node
//! dependency declaration, installed by the Nix factory at build time. A uv
//! lockfile lowers to the IR's Python declaration and is resolved here, from
//! the snapshot, to one wheel per package for the pack's target; the resolved
//! set is recorded in the workload, so the lock binds every wheel's URL and
//! hash, and the generated flake installs exactly that set at build time.
//!
//! Lowering refuses what the IR and Nix factories cannot honor yet: exact
//! package versions, Python dependency files other than a uv
//! lockfile, non-npm Node lockfiles and copies outside the application tree.
//! Builder execution happens elsewhere and is not implied by a successful
//! compile.

mod app_tree;
mod frozen;
mod lock;
mod lower;
pub mod python;

pub use frozen::{compile_frozen, lock_pack};
pub use lock::{LockField, spec_sha256, stale_fields};
pub use lower::{
    APP_DIR, APP_TREE, NPM_LOCKFILE, NPM_MANIFEST, PACK_EXTENSION, PACK_ROOTFS_SIZE_MIB, lower,
};

use crate::mvm_pin::PinnedMvmRevision;
use crate::orchestrator::CompileError;
use crate::source::SourceError;
use mvm_contract::ir::ValidationError;
use mvm_contract::pack_lock::PackLockError;
use mvm_contract::pack_spec::{PackSpec, PackSpecError};
use std::io;
use std::path::{Path, PathBuf};

/// Conventional lock file name. A file by this name at the source root is the
/// lock itself, so it is left out of the snapshot the lock digests: writing
/// the lock beside a spec whose source is `.` must not stale it.
pub const LOCK_FILE: &str = "pack.lock.json";

/// Build inputs only a pack has, written beside `flake.nix` as canonical JSON
/// when there are any: today the resolved Python environment under `python`,
/// whose wheels the flake installs. Absent means the pack has none.
pub const PACK_BUILD_FILE: &str = "pack-build.json";

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
        "package {package:?} requests version {version:?}; exact package versions cannot be resolved yet"
    )]
    UnsupportedPackageVersion { package: String, version: String },
    #[error("{0}")]
    Python(#[from] python::PythonError),
    #[error("could not read {}: {source}", path.display())]
    ReadLockfile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "Node dependencies must be an npm `package.json` and `package-lock.json` at the source root"
    )]
    UnsupportedNodeDependencies,
    #[error("a pack declares at most one dependency manifest and lockfile")]
    MultipleDependencies,
    #[error("copy destination {destination:?} is not inside the application directory /app")]
    CopyOutsideApp { destination: String },
    #[error("copy source {source_path:?} {reason}")]
    CopySource {
        source_path: String,
        reason: &'static str,
    },
    #[error("copy to {destination:?} conflicts with an earlier copy: {reason}")]
    CopyConflict {
        destination: String,
        reason: &'static str,
    },
    #[error("could not assemble the application tree at {}: {source}", path.display())]
    Assemble {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("dependency lockfile check failed: {0}")]
    Lockfile(crate::deps::DepsError),
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
