//! `mvmctl bootstrap` — full environment setup from scratch.

use anyhow::Result;
use clap::Args as ClapArgs;

use crate::bootstrap;
use crate::ui;

use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::setup::run_setup_steps;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Production mode (skip Homebrew, assume Linux with apt)
    #[arg(long)]
    pub production: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    bootstrap_environment(args.production)
}

/// Full environment bootstrap: host-tooling setup **plus** pre-acquiring the
/// builder VM image so the first `mvmctl dev up` is fast (no first-run
/// download/build on the hot path). Shared by the top-level `mvmctl bootstrap`
/// and `mvmctl env bootstrap`.
pub(in crate::commands) fn bootstrap_environment(production: bool) -> Result<()> {
    run_steps(production)?;
    // Pre-fetch the builder VM image. On a release install this downloads the
    // published, SHA-256-verified image; on a source checkout it builds it
    // locally (a source checkout never downloads mvm-release artifacts).
    // Cache-gated, so it is a fast no-op when the image is already present.
    super::dev_vz::bootstrap_builder_vm_image()?;
    // Also pre-acquire the dev-shell image so the first `mvmctl dev up` doesn't
    // pay a download/build on the hot path. Non-fatal + cache-gated, mirroring
    // the builder-image prefetch above.
    if dev_image_prefetch_enabled(std::env::var("MVM_SKIP_DEV_IMAGE_PREFETCH").ok().as_deref()) {
        match super::dev_vz::ensure_dev_image() {
            Ok(_) => ui::success("Dev image ready."),
            Err(e) => ui::warn(&format!(
                "dev-image prefetch failed ({e}); the first 'dev up' will fetch it. Skip with MVM_SKIP_DEV_IMAGE_PREFETCH=1."
            )),
        }
    }
    ui::success("\nBootstrap complete! Run 'mvmctl dev' to enter the development environment.");
    Ok(())
}

/// Run the host-tooling bootstrap steps only (no builder-image prefetch) —
/// exposed so `dev` can re-bootstrap without going through the dispatcher.
pub(super) fn run_steps(production: bool) -> Result<()> {
    ui::info("Bootstrapping full environment...\n");

    if !production {
        bootstrap::check_package_manager()?;
    }

    // Dev mode is libkrun/Apple-Container on Apple Silicon macOS or
    // native Firecracker on Linux KVM. There is no Lima VM to provision
    // here; setup_steps below handles the remaining assets.
    bootstrap::hint_libkrun_if_useful();

    // Default sizing for the builder VM; CLI-level overrides ride the
    // setup path.
    run_setup_steps(false, 8, 16)?;
    Ok(())
}

/// Whether to prefetch the dev-shell image during bootstrap. On by default so
/// the first `dev up` is instant; opt out with `MVM_SKIP_DEV_IMAGE_PREFETCH=1`
/// (bandwidth-limited or headless installs).
fn dev_image_prefetch_enabled(skip_env: Option<&str>) -> bool {
    !matches!(skip_env, Some("1"))
}

#[cfg(test)]
mod tests {
    use super::dev_image_prefetch_enabled;

    #[test]
    fn dev_image_prefetch_on_by_default_off_with_flag() {
        assert!(dev_image_prefetch_enabled(None));
        assert!(dev_image_prefetch_enabled(Some("0")));
        assert!(!dev_image_prefetch_enabled(Some("1")));
    }
}
