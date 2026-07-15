//! `MicrovmArtifactBuilder` implementations.
//!
//! Slice 1 ships `NixMicrovmBuilder` — delegates to a `BuilderVm` (libkrun
//! or Vz) and assembles a typed `MicrovmArtifact` from the returned
//! `BuilderArtifacts::Image`. The `BuilderVm` is injected so tests can
//! supply a scripted mock without spawning a real VM.

pub mod nix;

pub use nix::NixMicrovmBuilder;
