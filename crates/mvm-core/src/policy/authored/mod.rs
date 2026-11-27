//! Authored workload-policy parsing, source resolution, and composition.
//!
//! `mvm-client` and host admission in `mvm-hostd` share these rules, so the
//! CLI, the host library and the SDKs see one policy semantics. Nothing here
//! commits a generation, signs a plan, or grants a running workload any
//! effect: composition only narrows what the surrounding authority allows.

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
