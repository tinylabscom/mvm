//! # mvmctl — Firecracker microVM development tool
//!
//! Facade crate that re-exports all mvm workspace crates so consumers
//! only need to depend on the `mvmctl` library.
//!
//! ## Workspace Crates
//!
//! All workspace crates are re-exported at the root:
//!
//! | Module | Crate | Purpose |
//! |--------|-------|---------|
//! | [`core`] | mvm-core | Types, IDs, config, protocol, signing, routing |
//! | [`security`] | mvm-security | Command gating, threat classification, rate limiting |
//! | [`runtime`] | mvm-runtime | Shell execution, VM lifecycle, template management |
//! | [`build`] | mvm-build | Nix builder pipeline |
//! | [`guest`] | mvm-guest | Vsock protocol, integration manifest, guest agent |
//!
//! ## Usage
//!
//! All public interfaces are available through the root crate:
//!
//! ```rust,ignore
//! // Access workspace crates directly
//! use mvmctl::core::agent::{AgentRequest, AgentResponse};
//! use mvmctl::core::pool::UpdateStrategy;
//! use mvmctl::runtime::vm;
//! use mvmctl::security::command_gate::CommandGate;
//!
//! // Or use the prelude for common types
//! use mvmctl::prelude::*;
//! ```
//!
//! ## Prelude
//!
//! The [`prelude`] module provides convenient access to the most commonly used types:
//!
//! ```rust,ignore
//! use mvmctl::prelude::*;
//!
//! // Now you have access to:
//! // - InstanceState, AgentRequest, AgentResponse, ReconcileReport
//! // - HostdRequest, HostdResponse
//! // - anyhow::{Result, Context}
//! ```

// ============================================================================
// Workspace crate re-exports
// ============================================================================

/// Core types, IDs, config, protocol, signing, and routing.
///
/// See [`mvm_core`] for full documentation.
pub use mvm_core as core;

/// Security posture evaluation, command gating, and threat classification.
///
/// See [`mvm_security`] for full documentation.
pub use mvm_security as security;

/// Shell execution, VM lifecycle, and template management.
///
/// See [`mvm_runtime`] for full documentation.
pub use mvm_runtime as runtime;

/// Nix builder pipeline for creating guest images.
///
/// See [`mvm_build`] for full documentation.
pub use mvm_build as build;

/// Guest-side vsock protocol, integrations, and probes.
///
/// See [`mvm_guest`] for full documentation.
pub use mvm_guest as guest;

// ============================================================================
// Prelude
// ============================================================================

/// Commonly used types for convenience.
///
/// Import this module to get quick access to the most frequently used types:
///
/// ```rust,ignore
/// use mvmctl::prelude::*;
/// ```
pub mod prelude {
    // Protocol types
    pub use mvm_core::agent::{AgentRequest, AgentResponse, ReconcileReport};
    pub use mvm_core::protocol::{HostdRequest, HostdResponse};

    // Instance state
    pub use mvm_core::instance::InstanceState;

    // Common result type
    pub use anyhow::{Context, Result};
}
