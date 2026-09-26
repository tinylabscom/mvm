//! Composable policy: groups, profiles, and the resolved manifest.
//!
//! What a workload may do used to be spread across `mvm.toml`, a grants
//! file, workload IR and flags. This module adds three layers on top of them:
//!
//! 1. **Groups** ([`model::GroupFile`]) — named, reusable TOML fragments
//!    covering network, secrets, shares, env, tools and resources. A group
//!    may be `required`.
//! 2. **Profiles** ([`model::ProfileFile`]) — `extends`, `groups.include` /
//!    `groups.exclude`, `[[when]]` platform blocks and `[overrides]`,
//!    resolved by [`resolve::resolve`] and merged by [`merge::merge_layers`]
//!    under rules that only narrow what a deny, a block, or a bound says.
//! 3. **The resolved manifest** ([`manifest::ResolvedManifest`]) — the merged
//!    policy as a document, lowered by [`manifest::fold`] into the launch's
//!    own flags so it reaches the signed `ExecutionPlan` through exactly the
//!    grant resolution, synthesis, signing and admission every launch takes.
//!
//! Profiles and groups are found by [`source::PolicyStore`]: a path, a name
//! in the user's policy directory, or a built-in ([`builtin`]).

pub mod builtin;
pub mod manifest;
pub mod merge;
pub mod model;
pub mod preview;
pub mod resolve;
pub mod source;

pub use manifest::{FoldedLaunch, LaunchFlags, ResolvedManifest, fold};
pub use merge::{LayerSummary, ResolvedPolicy};
pub use model::{GroupFile, PolicyBody, ProfileFile};
pub use resolve::{MAX_EXTENDS_DEPTH, Platform, PolicySelection, resolve};
pub use source::{LayerOrigin, PolicyError, PolicyRef, PolicyStore};

#[cfg(test)]
mod equivalence_tests;
