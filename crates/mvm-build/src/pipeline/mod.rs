//! Build pipeline — Nix-based image builds for pools and dev mode.

pub mod build;
pub mod build_cache;
pub mod dev_build;
pub mod orchestrator;
pub mod vsock_builder;

/// Whether a build should produce a dev-shape or prod-shape image.
///
/// **The command run by the user dictates this**, not the user's
/// flake. `mvmctl up`/`run`/`start` are production-shape commands;
/// they build sealed images with runtime access gates. The builder VM's dev shell runs a separate dev-shell
/// sandbox that doesn't go through this build path. An explicit
/// `--dev` flag on production-shape commands is the documented
/// escape hatch for debugging a microVM-shape image; without it,
/// `BuildMode::Prod` is the default.
///
/// Concretely:
/// - `Dev`: injects `--override-input mvm` for the sibling
///   `nix/dev/` flake and passes `--impure` so the override resolves.
/// - `Prod`: no overrides and no `--impure`; the sealed image's runtime
///   profile and signed grant refuse DevOnly access.
///
/// Mirrors the auto-memory rule "image composition is transparent
/// to the user — mvm picks dev-rich vs prod-slim contents based
/// on invocation context."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildMode {
    /// Dev-shape build: accessible image wiring. Used by dev-shell-adjacent
    /// paths and by `--dev` opt-ins on production-
    /// shape commands.
    Dev,
    /// Prod-shape build: sealed image wiring. The default for
    /// `mvmctl up`/`run`/`start`/`build`/
    /// `template build`.
    Prod,
}

impl BuildMode {
    /// Whether this mode should inject the dev sibling flake
    /// override (`--override-input mvm` → `nix/dev/`).
    pub fn injects_dev_override(self) -> bool {
        matches!(self, BuildMode::Dev)
    }
}
