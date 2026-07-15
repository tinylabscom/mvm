//! Shared bridge config + passt-hash parser surface, reused by the
//! `mvm-bridge` sidecar (folded from the former `mvm-firecracker-bridge`).
//!
//! This module exposes the parser types and the `verify_passt_hash` helper so
//! the cargo-fuzz harness under `crates/mvm-vm-host/fuzz/` can drive
//! adversarial input through the same code the sidecar executes. See `parse`
//! for the shapes and behaviour contract.
//!
//! The bridge-config fuzz lane in `.github/workflows/security.yml` runs
//! `cargo fuzz run` against the `BridgeConfigJson` `serde_json` parser and the
//! `PasstHashesFile` `toml` parser nightly + on release-tag pushes.

pub mod parse;
