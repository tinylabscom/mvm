//! mvm's Linux binaries embedded in mvmctl.
//!
//! Three submodules:
//!   - `manifest` — compile-time list of embedded binaries,
//!     mirrored in `nix/lib/mvm-host-binaries.nix`.
//!   - `embedded` — `include_bytes!`'d payload + SHA-256 hashes
//!     produced by `build.rs`.
//!   - `extract` — race-safe extraction to
//!     `~/.mvm/cache/host-bins/<content-hash>/` on first use.
//!
//! The pinned cross-compile toolchain that *produces* the payload lives in
//! `mvm_build::embed_toolchain`, low enough that the builder-VM bootstrap can
//! ask whether a build is even possible before starting one.

pub mod embedded;
pub mod extract;
pub mod manifest;
// Shared with `build.rs`, which reaches parts `mvmctl` never does (its rerun
// bookkeeping, restoring into `OUT_DIR`).
#[cfg(test)]
#[allow(dead_code)]
mod payload_build;

#[cfg(test)]
use mvm_build::embed_toolchain;
