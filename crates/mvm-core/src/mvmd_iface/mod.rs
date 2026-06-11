//! Signed control-plane wire types shared with the `mvmd` orchestrator.
//!
//! `mvmd` (fleet orchestration daemon, separate repository) depends on
//! `mvm-core` for the shared types it needs to drive promotions, host
//! inventory, and control-plane key rotation. Keeping these types here
//! avoids a cyclic dependency between the two repos and gives mvmd a
//! single, stable contract surface.
//!
//! ## Scope
//!
//! This module describes the *wire format* exchanged between `mvmd` and
//! `mvm` via signed envelopes (see [`crate::protocol::signing::SignedPayload`]).
//! Behavior — placement, reconciliation, drift repair — lives in `mvmd`.
//! Validation and enforcement live in `mvm`. This module is data-only.
//!
//! Every type here uses `#[serde(deny_unknown_fields)]` so an unexpected
//! field fails closed, matching the discipline on the host↔guest vsock
//! protocol.
//!
//! ## Submodules
//!
//! - [`release`] — `ReleasePromotion` and related types for staged rollouts
//!   driven by `mvmd` and executed by `mvm`'s supervisor.
//! - [`control_key`] — `ControlKey` (kid, role, expiry) used to sign
//!   control-plane envelopes.
//! - [`host_inventory`] — `HostInventory` (registration, capacity, state)
//!   so `mvmd` can place workloads.
//!
//! ## Scaffold status
//!
//! Types here are intentionally minimal — enough to fix the contract
//! shape so `mvmd` can compile against them. Concrete behavior and
//! richer fields land alongside the orchestration features that need
//! them. The architectural invariant is that `mvm` itself never grows
//! a server or daemon to *act* on these types.

pub mod control_key;
pub mod host_inventory;
pub mod release;

pub use control_key::{ControlKey, ControlKeyRole};
pub use host_inventory::{HostCapacity, HostInventory, HostState};
pub use release::{PromotionStrategy, ReleasePromotion};
