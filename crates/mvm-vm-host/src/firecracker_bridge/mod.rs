//! Library surface for the per-VM Firecracker bridge sidecar
//! (Plan 113 §Task 12 / ADR-064).
//!
//! The crate's primary product is the `mvm-firecracker-bridge` binary
//! (`src/main.rs`). This `lib.rs` exists to expose the parser types
//! and the `verify_passt_hash` helper so the cargo-fuzz harness under
//! `crates/mvm-firecracker-bridge/fuzz/` can drive adversarial input
//! through the same code the binary executes. See `parse` for the
//! shapes and behaviour contract.
//!
//! Plan 113 §Task 15 / `firecracker-bridge-fuzz` CI lane —
//! `.github/workflows/security.yml` runs `cargo fuzz run` against the
//! `BridgeConfigJson` `serde_json` parser and the `PasstHashesFile`
//! `toml` parser nightly + on release-tag pushes.

pub mod parse;
