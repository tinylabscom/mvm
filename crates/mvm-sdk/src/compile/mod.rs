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
//! Phases 2b–2c add the rest of the pipeline: dep validation, function
//! presence checks, flake renderer, launch.json builder, top-level
//! orchestrator, and the `mvmctl compile` CLI verb.

pub mod archive;
pub(crate) mod data;
pub mod reachability;
pub mod source;

pub use archive::{ArchiveError, archive_dir};
pub use reachability::{
    Language, NODE_EXTS, PYTHON_EXTS, ReachabilityError, detect_language, discover_node_reachable,
    discover_python_reachable,
};
pub use source::{SourceError, SourcePlan, copy_source, rehash};
