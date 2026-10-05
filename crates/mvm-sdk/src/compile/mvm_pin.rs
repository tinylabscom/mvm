//! `mvm` flake input for SDK-generated `flake.nix` files.
//!
//! Generated flakes set `inputs.mvm.url` to either the build-time
//! default below or the `MVM_FLAKE_URL` env-var override (per-developer
//! escape hatch for local checkouts). `inputs.nixpkgs.follows =
//! "mvm/nixpkgs"` — there is no separate `nixpkgs` pin in generated
//! flakes.
//!
//! The default follows `main` for development. Published images call
//! `compile_pinned` with an exact commit revision and carry a lockfile.

pub const MVM_OWNER: &str = "tinylabscom";
pub const MVM_REPO: &str = "mvm";
/// Development input. Publication uses an explicit `PinnedMvmRevision`.
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

/// A source revision suitable for a reproducible published image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedMvmRevision(String);

impl PinnedMvmRevision {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("mvm revision must be a 40-character hexadecimal commit id");
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn flake_url(&self) -> String {
        format!("github:{MVM_OWNER}/{MVM_REPO}/{}?dir={MVM_SUBDIR}", self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::PinnedMvmRevision;

    #[test]
    fn accepts_only_full_commit_revisions() {
        let revision = PinnedMvmRevision::parse("4e65b221744885e536ec91a3f2948cdc508dcb49")
            .expect("full commit id");
        assert_eq!(
            revision.as_str(),
            "4e65b221744885e536ec91a3f2948cdc508dcb49"
        );
        assert!(revision.flake_url().contains(revision.as_str()));
        for invalid in [
            "main",
            "4e65b221",
            "zzzzb221744885e536ec91a3f2948cdc508dcb49",
        ] {
            assert!(PinnedMvmRevision::parse(invalid).is_err(), "{invalid}");
        }
    }
}
