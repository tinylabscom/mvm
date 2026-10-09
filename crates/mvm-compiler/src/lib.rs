#![forbid(unsafe_code)]
//! Language-neutral compilation stages shared by the workload SDK and pack
//! authoring surfaces.
//!
//! Owns source and dependency analysis, workload lowering, and deterministic
//! build artifacts. `mvm-sdk::compile` re-exports this crate for compatibility.
//! Compilation does not execute builds, access the network, or sign artifacts.

pub mod archive;
mod data;
pub mod deps;
pub mod deps_audit;
pub mod explain;
pub mod flake;
pub mod func_describe;
pub mod hooks;
pub mod launch;
pub mod mvm_pin;
pub mod orchestrator;
pub mod reachability;
pub mod source;
pub mod strip_framework;

pub use archive::{ArchiveError, archive_dir};
pub use deps::{DepsError, validate_lockfiles};
pub use flake::build_flake_nix;
pub use func_describe::{
    FuncDescribeError, FunctionSignature, describe_function, resolve_module_path,
};
pub use hooks::merge_hooks;
pub use launch::{ARTIFACT_FORMAT_VERSION, FLAKE_ATTRIBUTE, TOOLCHAIN_VERSION, build_launch_json};
pub use mvm_pin::{PinnedMvmRevision, default_mvm_flake_url, resolved_mvm_flake_url};
pub use orchestrator::{
    CompileError, compile, compile_archive, compile_archive_pinned, compile_pinned,
    is_archive_output,
};
pub use reachability::{
    Language, NODE_EXTS, PYTHON_EXTS, ReachabilityError, detect_language, discover_node_reachable,
    discover_python_reachable,
};
pub use source::{SourceError, SourcePlan, copy_source, rehash};
pub use strip_framework::{strip_python, strip_typescript};
