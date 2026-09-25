//! mvm's Linux binaries embedded in mvmctl.
//!
//! Submodules:
//!   - `manifest` — compile-time list of embedded binaries,
//!     mirrored in `nix/lib/mvm-host-binaries.nix`.
//!   - `embedded` — `include_bytes!`'d payload + SHA-256 hashes
//!     produced by `build.rs`.
//!   - `source` — where the payload comes from: compiled in, or built from
//!     the source checkout into the content store when it was not.
//!   - `extract` — race-safe extraction to
//!     `~/.mvm/cache/host-bins/<content-hash>/` on first use.
//!
//! The pinned cross-compile toolchain that *produces* the payload lives in
//! `mvm_build::embed_toolchain`, low enough that the builder-VM bootstrap can
//! ask whether a build is even possible before starting one.

pub mod embedded;
pub mod extract;
pub mod manifest;
// Shared with `build.rs` by path. Each includer uses a different part of it —
// the build script its rerun bookkeeping, `mvmctl` its store inspection — so
// neither uses all of it.
#[allow(dead_code)]
mod payload_build;
pub mod source;

// `payload_build` names the toolchain module as `super::embed_toolchain`, which
// the build script declares by path and `mvmctl` takes from `mvm-build`.
use mvm_build::embed_toolchain;
