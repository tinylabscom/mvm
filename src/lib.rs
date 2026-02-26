//! # mvm — Firecracker microVM development tool
//!
//! Facade crate that re-exports the mvm workspace crates so consumers
//! can depend on a single `mvm` library.
//!
//! ## Crate breakdown
//!
//! | Module | Crate | Purpose |
//! |--------|-------|---------|
//! | [`core`] | mvm-core | Types, IDs, config, protocol, signing, routing |
//! | [`security`] | mvm-security | Command gating, threat classification, rate limiting |
//! | [`runtime`] | mvm-runtime | Shell execution, VM lifecycle |
//! | [`build`] | mvm-build | Nix builder pipeline |
//! | [`guest`] | mvm-guest | Vsock protocol, integration manifest |

pub use mvm_build as build;
pub use mvm_core as core;
pub use mvm_guest as guest;
pub use mvm_runtime as runtime;
pub use mvm_security as security;
