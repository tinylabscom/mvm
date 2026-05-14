//! Compile pipeline — Workload IR to staged build artifacts.
//!
//! Ported from `mvmforge/src/{archive,source,reachability,deps,
//! func_describe,flake,launch,compile,explain}.rs` per the SDK port plan.
//!
//! Phase 2a (this commit) lands the source-bundling primitives:
//!
//! - [`archive`] — deterministic gzipped-tar of a staging directory.
//!   Sorted entries, mtime = 0, normalized modes, gzip with no
//!   filename header. Output is byte-reproducible across runs.
//! - [`source`] — walks `app.source.path`, applies include/exclude
//!   globs, copies files into `<staging>/src/`, and computes a stable
//!   `tree_hash` over the resulting tree. Symlinks preserved in-tree,
//!   rejected out-of-tree.
//! - [`reachability`] — bundler reachability scoping for
//!   function-entrypoint workloads. Tree-sitter-backed AST walks for
//!   Python and Node/TypeScript prune unreachable files from the
//!   staged source before archiving.
//! - [`data`] — tiny helper for parsing curated word lists (used by
//!   [`reachability`] to load the language-extension lists).
//!
//! Phase 2b adds the orchestration layer:
//!
//! - [`deps`] — host-level dependency-lockfile validation (hash-pin
//!   heuristics for `uv.lock`, `requirements.txt`, `pnpm-lock.yaml`,
//!   `package-lock.json`, `yarn.lock`).
//! - [`func_describe`] — tree-sitter function-presence check for
//!   function-entrypoint workloads.
//! - [`flake`] — renderer for the generated `flake.nix`.
//! - [`launch`] — builder for `launch.json` (a sidecar the generated
//!   flake reads at evaluation time; an inlining rewrite is planned
//!   but deferred).
//! - [`mvm_pin`] — pinned mvm flake input baked into every generated
//!   `flake.nix`. Override via `MVM_FLAKE_URL`.
//! - [`compile`] — top-level orchestrator that ties everything
//!   together.
//! - [`explain`] — diagnostic surface for `mvmctl compile --explain`.
//!
//! Phase 2c wires `mvmctl compile <entry>` as the CLI verb.

pub mod archive;
pub(crate) mod data;
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

pub use archive::{ArchiveError, archive_dir};
pub use deps::{DepsError, validate_lockfiles};
pub use flake::build_flake_nix;
pub use func_describe::{FuncDescribeError, describe_function, resolve_module_path};
pub use hooks::merge_hooks;
pub use launch::{ARTIFACT_FORMAT_VERSION, FLAKE_ATTRIBUTE, TOOLCHAIN_VERSION, build_launch_json};
pub use mvm_pin::{default_mvm_flake_url, resolved_mvm_flake_url};
pub use orchestrator::{CompileError, compile, compile_archive, is_archive_output};
pub use reachability::{
    Language, NODE_EXTS, PYTHON_EXTS, ReachabilityError, detect_language, discover_node_reachable,
    discover_python_reachable,
};
pub use source::{SourceError, SourcePlan, copy_source, rehash};
