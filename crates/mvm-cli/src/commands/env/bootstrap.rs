//! CLI arguments and presentation for explicit environment preparation.
use super::{Cli, setup::run_setup_steps};
use crate::{bootstrap, ui};
use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use mvm_core::user_config::MvmConfig;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Production mode (skip Homebrew, assume Linux with apt).
    #[arg(long)]
    pub production: bool,
    /// Permit building the builder image from the selected local checkout.
    #[arg(long)]
    pub allow_local_builder_build: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    bootstrap_environment(args.production)
}

pub(in crate::commands) fn bootstrap_environment(production: bool) -> Result<()> {
    run_steps(production)?;
    // Warm standbys and paused machines are encrypted at rest; a host that
    // has never held a snapshot key gets one here rather than at its first
    // pause.
    crate::commands::shared::ensure_snapshot_key()?;
    let mode = mvm_client::launch::runtime_overlay::runtime_overlay_acquire_mode();
    // A release binary's guest runtime is the one its release ships, acquired
    // once up front. A source build has its tree; the image set has none.
    let release =
        if publishes_its_guest_runtime(mvm_build::artifact_acquisition::compiled_channel(), mode) {
            Some(
                crate::release_guest_runtime::prepare_for_running_binary()
                    .context("preparing the release guest runtime")?,
            )
        } else {
            None
        };
    let phase = ui::activity::start("Preparing builder and workload artifacts".to_owned());
    let kernel = mvm_client::builder_images::environment::prepare_environment(release.as_ref())?;
    phase.finish();
    ui::success(&format!(
        "\nBootstrap complete. Builder VM, host helpers, workload kernel, runtime overlay, initramfs, and OCI guest shims are ready.\nSDK sidecars for glibc and musl are ready. Future machine runs will reuse prepared artifacts.\nWorkload kernel: {kernel}"
    ));
    Ok(())
}

/// Whether this binary takes its guest runtime from a release: a release
/// binary does, unless it was explicitly asked to build one (which then fails
/// for want of a checkout). A source build always assembles its own tree's.
fn publishes_its_guest_runtime(
    channel: mvm_build::artifact_acquisition::DistributionChannel,
    mode: mvm_client::launch::runtime_overlay::RuntimeOverlayAcquireMode,
) -> bool {
    channel == mvm_build::artifact_acquisition::DistributionChannel::Release
        && mode
            == mvm_client::launch::runtime_overlay::RuntimeOverlayAcquireMode::DownloadPublishedArtifact
}

/// Run the host-tooling bootstrap steps only (no builder-image prefetch) —
/// exposed so `dev` can re-bootstrap without going through the dispatcher.
pub(super) fn run_steps(production: bool) -> Result<()> {
    ui::info("Bootstrapping full environment...\n");

    if !production {
        bootstrap::check_package_manager()?;
    }

    // Dev mode is libkrun/HVF on Apple Silicon macOS or
    // native Firecracker on Linux KVM. There is no Lima VM to provision
    // here; setup_steps below handles the remaining assets.
    bootstrap::hint_libkrun_if_useful();

    // Default sizing for the builder VM; CLI-level overrides ride the
    // setup path.
    run_setup_steps(false, 8, 16)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::publishes_its_guest_runtime;
    use mvm_client::launch::runtime_overlay::RuntimeOverlayAcquireMode;

    /// Only a release binary in its default mode acquires a published guest
    /// runtime. A source build assembles its tree's in either mode — the image
    /// set it used to install from in download mode carries none — and a
    /// release binary asked to build has no tree, which the source arm reports.
    #[test]
    fn only_a_release_binary_takes_a_published_guest_runtime() {
        use mvm_build::artifact_acquisition::DistributionChannel;
        assert!(publishes_its_guest_runtime(
            DistributionChannel::Release,
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact
        ));
        assert!(!publishes_its_guest_runtime(
            DistributionChannel::Release,
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout
        ));
        for mode in [
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact,
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout,
        ] {
            assert!(!publishes_its_guest_runtime(
                DistributionChannel::Source,
                mode
            ));
        }
    }
}
