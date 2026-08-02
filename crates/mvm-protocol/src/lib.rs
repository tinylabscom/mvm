// schemars 0.8's `derive(JsonSchema)` unconditionally emits code rooted
// at `std::…` (it has no no_std mode), so a crate that derives it can't
// itself be `#![no_std]`. The `schema` feature exists only for
// `mvm-sdk`'s host-side `emit_schema`/`emit_addon_schema` codegen bins —
// never for the wasm32 target — so this drops `no_std` in that one
// build configuration and keeps it everywhere else, including the
// default build the wasm-clean gate exercises.
//
// `not(test)` keeps the crate `std` under `cargo test`: libtest itself
// needs `std` to link, so a `no_std` lib can't host the harness. The
// wasm32-unknown-unknown *library* build (the wasm-clean gate) is never
// built `--test`, so it stays `no_std` regardless of this clause.
#![cfg_attr(all(not(feature = "schema"), not(test)), no_std)]
#![forbid(unsafe_code)]
//! no_std + alloc core for mvm: the chain-signed audit-log verifier and
//! the canonical Workload IR; the wire protocol and policy DTOs land
//! here incrementally. Builds on wasm32 so the same logic runs in a
//! browser.

extern crate alloc;

pub mod entrypoint;
pub mod ir;
/// The L3-over-vsock tunnel protocol: framing, control messages, and
/// bounded IP validation. Shared by the in-guest agent and the host
/// gateway.
pub mod l3;
/// Guest lifecycle markers + snapshot timing (the `mvm-init` ↔ host contract).
pub mod lifecycle;
/// RFC 6962 Merkle transparency-log inclusion proofs over the audit log.
pub mod merkle;
pub mod plan;
pub mod policy;
pub mod protocol;
pub mod verify;
