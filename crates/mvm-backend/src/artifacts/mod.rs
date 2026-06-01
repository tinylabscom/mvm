//! Typed build artifact model for microVMs.
//!
//! Three responsibilities, one module:
//!
//! - **`spec`** — input descriptions (`KernelSpec`, `RootfsSpec`,
//!   `MicrovmBuildSpec`) with sources and target constraints.
//! - **`artifact`** — output types (`KernelArtifact`, `RootfsArtifact`,
//!   `MicrovmArtifact`, `BackendConfigArtifact`, `ValidationReport`).
//! - **`traits`** — the five builder/writer/validator traits + `ArtifactError`.
//! - **`manifest`** — `ArtifactManifest` written as `manifest.json` next to
//!   build outputs; distinct from the mkGuest runtime sidecar (`GuestSidecar`
//!   / `mvm-meta.json`).

pub mod artifact;
pub mod manifest;
pub mod spec;
pub mod traits;
