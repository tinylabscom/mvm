//! mvm's Linux binaries embedded in mvmctl.
//!
//! Three submodules:
//!   - `manifest` — compile-time list of embedded binaries,
//!     mirrored in `nix/lib/mvm-host-binaries.nix`.
//!   - `embedded` — `include_bytes!`'d payload + SHA-256 hashes
//!     produced by `build.rs`.
//!   - `extract` — race-safe extraction to
//!     `~/.cache/mvm/host-bins/<content-hash>/` on first use.

pub mod embedded;
pub mod extract;
pub mod manifest;
