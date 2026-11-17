//! Authored workload-policy parsing, source resolution, and composition.
//!
//! The client consumes these rules; the future host admission owner can use
//! the same rules without depending on client launch orchestration. This
//! library does not commit a generation, sign a plan, or grant a running
//! workload any effects.

pub mod allow_host;
pub mod builtin;
pub mod manifest;
pub mod merge;
pub mod model;
pub mod resolve;
pub mod source;

pub use manifest::ResolvedManifest;
pub use merge::{LayerSummary, ResolvedPolicy};
pub use model::{GroupFile, PolicyBody, ProfileFile};
pub use resolve::{
    CapturedSource, MAX_EXTENDS_DEPTH, Platform, PolicySelection, ProjectPolicy, SourceKind,
    resolve, resolve_capturing_sources, resolve_from_captured_sources, select_launch_policy,
};
pub use source::{LayerOrigin, PolicyError, PolicyRef, PolicyStore};
