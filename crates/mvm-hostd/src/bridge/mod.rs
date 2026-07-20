//! Unified per-VM bridge-sidecar surface.
//!
//! The shared `mvm-bridge` sidecar reads a single [`parse::BridgeConfigJson`]
//! document on stdin regardless of backend, dispatching on an
//! [`parse::BridgeEndpointKind`] discriminant to build the matching
//! `crate::supervisor::gateway_bridge::BridgeEndpoints` variant. This folds
//! the previously per-backend stdin contract (`mvm-firecracker-bridge`'s
//! `BridgeConfigJson`) into the shared sidecar — the contract the source
//! already described as "identical across backends".
//!
//! The plan-decode (`parse::decode_plan_json`) and passt-hash verify
//! (`parse::verify_passt_hash` / `parse::PasstHashesFile`) helpers are reused
//! verbatim from [`crate::firecracker_bridge::parse`] — there is no parser
//! duplication, and the existing fuzz harness keeps driving the same code.

pub mod parse;
