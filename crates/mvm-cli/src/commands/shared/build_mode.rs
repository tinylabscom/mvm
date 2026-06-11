//! Clap flags that resolve to a [`mvm_build::pipeline::BuildMode`].
//!
//! The architectural rule (auto-memory: "image composition is
//! transparent to the user") makes `BuildMode::Prod` the default
//! for production-shape commands (`mvmctl up`/`run`/`start`/
//! `build`/`template build`). These flags are the documented escape
//! hatches:
//!
//! - `--dev` builds the dev variant (dev guest agent + accessible
//!   image; `mvmctl console`/`exec` work against the resulting VM).
//! - `--prod` builds the prod variant (no dev surface; sealed
//!   image; the console gate refuses). Same as the default;
//!   useful for explicit intent in scripts/CI.
//!
//! The two are mutually exclusive (clap enforces).

use clap::Args as ClapArgs;
use mvm_build::pipeline::BuildMode;

/// Mutually-exclusive build-mode override flags.
///
/// Embed via `#[command(flatten)]` in any command's Args struct
/// that drives `dev_build`.
#[derive(ClapArgs, Debug, Clone, Default)]
pub(in crate::commands) struct BuildModeFlags {
    /// Build a dev-shape image: dev guest agent (with `do_exec`)
    /// and accessible image. Enables `mvmctl console` / `mvmctl
    /// exec` against the resulting VM. Mutually exclusive with
    /// `--prod`.
    #[arg(long, conflicts_with = "prod", help_heading = "Build mode")]
    pub dev: bool,
    /// Build a prod-shape image: prod guest agent (no dev RPCs)
    /// and sealed image. The default; flag is for explicit intent.
    /// Mutually exclusive with `--dev`.
    #[arg(long, conflicts_with = "dev", help_heading = "Build mode")]
    pub prod: bool,
}

impl BuildModeFlags {
    /// Resolve the flags to a `BuildMode`. No flag → `Prod` (the
    /// architectural default per the auto-memory rule). Both flags
    /// → unreachable in practice (clap rejects), defensive code
    /// favors `Prod`.
    pub(in crate::commands) fn resolve(&self) -> BuildMode {
        if self.dev {
            BuildMode::Dev
        } else {
            BuildMode::Prod
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_flag_resolves_to_prod() {
        let flags = BuildModeFlags::default();
        assert_eq!(flags.resolve(), BuildMode::Prod);
    }

    #[test]
    fn dev_flag_resolves_to_dev() {
        let flags = BuildModeFlags {
            dev: true,
            prod: false,
        };
        assert_eq!(flags.resolve(), BuildMode::Dev);
    }

    #[test]
    fn prod_flag_resolves_to_prod() {
        let flags = BuildModeFlags {
            dev: false,
            prod: true,
        };
        assert_eq!(flags.resolve(), BuildMode::Prod);
    }
}
