// schemars 0.8's `derive(JsonSchema)` unconditionally emits code rooted
// at `std::…` (it has no no_std mode), so a crate that derives it can't
// itself be `#![no_std]`. The `schema` feature exists only for
// `mvm-sdk`'s host-side `emit_schema`/`emit_addon_schema` codegen bins —
// never for the wasm32 target — so this drops `no_std` in that one
// build configuration and keeps it everywhere else, including the
// default build the wasm-clean gate exercises.
#![cfg_attr(not(feature = "schema"), no_std)]
#![forbid(unsafe_code)]
//! no_std + alloc core for mvm: the chain-signed audit-log verifier and
//! the canonical Workload IR; the wire protocol and policy DTOs land
//! here incrementally. Builds on wasm32 so the same logic runs in a
//! browser.

extern crate alloc;

pub mod entrypoint;
pub mod ir;
/// Guest lifecycle markers + snapshot timing (the `mvm-init` ↔ host contract).
pub mod lifecycle;
pub mod plan;
pub mod policy;
pub mod protocol;
pub mod verify;
