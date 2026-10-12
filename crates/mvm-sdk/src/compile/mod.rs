//! Compatibility facade for the shared workload compiler.
//!
//! All stages and their error types are owned by `mvm-compiler`. Existing
//! `mvm_sdk::compile` paths remain available with the `compiler` feature,
//! without a separate implementation.
//! Workload authoring and language bridges stay in the SDK; build execution
//! and artifact signing are not compiler responsibilities.

pub use mvm_compiler::{
    archive, deps, deps_audit, explain, flake, func_describe, hooks, launch, mvm_pin, orchestrator,
    reachability, source, strip_framework,
};

pub use archive::{ArchiveError, archive_dir};
pub use deps::{DepsError, validate_lockfiles};
pub use flake::build_flake_nix;
pub use func_describe::{FuncDescribeError, describe_function, resolve_module_path};
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
