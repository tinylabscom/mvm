//! Unified per-VM bridge-sidecar surface (ADR-093 / Plan 209).
//!
//! The shared `mvm-bridge` sidecar reads a single [`parse::BridgeConfigJson`]
//! document on stdin regardless of backend, dispatching on an
//! [`parse::BridgeEndpointKind`] discriminant to build the matching
//! `mvm_hostd::supervisor::gateway_bridge::BridgeEndpoints` variant. This folds
//! the previously per-backend stdin contracts (`mvm-firecracker-bridge`'s
//! `BridgeConfigJson` and `mvm-vz-drainer`'s `DrainerConfig`) into one — the
//! contract the source already described as "identical across all three".
//!
//! The plan-decode (`parse::decode_plan_json`) and passt-hash verify
//! (`parse::verify_passt_hash` / `parse::PasstHashesFile`) helpers are reused
//! verbatim from [`crate::firecracker_bridge::parse`] — there is no parser
//! duplication, and the existing fuzz harness keeps driving the same code.
//!
//! Task 1 of Plan 209 is additive: this module defines the unified contract and
//! its tests; the `mvm-bridge` binary (Task 2) and the per-backend producer
//! rewiring + old-bin deletion (Task 4) land separately.

pub mod parse;
