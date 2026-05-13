//! Pinned `mvm` flake input baked into every generated `flake.nix`.
//!
//! Generated flakes set `inputs.mvm.url` to either the build-time
//! default below or the `MVM_FLAKE_URL` env-var override (per-developer
//! escape hatch for local checkouts). `inputs.nixpkgs.follows =
//! "mvm/nixpkgs"` — there is no separate `nixpkgs` pin in generated
//! flakes.
//!
//! Bumping this constant requires an ADR for routine updates and
//! follows `SECURITY.md` for security-driven bumps. The pin is a
//! specific commit so build outputs are byte-reproducible regardless
//! of upstream main branch drift; a release-time `xtask` (TODO) bumps
//! this constant as part of cutting a new mvm version.

pub const MVM_OWNER: &str = "tinylabscom";
pub const MVM_REPO: &str = "mvm";
/// Pinned mvm revision. Placeholder for v1 — points at `main`; bump
/// to a concrete commit hash at first release. Override via
/// `MVM_FLAKE_URL` for local development against an in-tree mvm.
pub const MVM_REV: &str = "main";
/// Subdirectory of the mvm repo where `flake.nix` lives. mvm's flake
/// is a *library* (per `nix/flake.nix`'s header) exposing
/// `lib.<system>.mkGuest`; generated user flakes consume it as
/// `inputs.mvm`.
pub const MVM_SUBDIR: &str = "nix";

/// Default `inputs.mvm.url` value rendered into generated flakes.
pub fn default_mvm_flake_url() -> String {
    format!("github:{MVM_OWNER}/{MVM_REPO}/{MVM_REV}?dir={MVM_SUBDIR}")
}

/// Resolved `inputs.mvm.url` for a `mvmctl compile` invocation.
/// Honors `MVM_FLAKE_URL` if set; otherwise falls back to the pin.
pub fn resolved_mvm_flake_url() -> String {
    std::env::var("MVM_FLAKE_URL").unwrap_or_else(|_| default_mvm_flake_url())
}
