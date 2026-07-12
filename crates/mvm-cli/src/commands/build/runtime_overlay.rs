//! `mvmctl build runtime-overlay build` — explicitly populate the
//! version-matched read-only runtime-overlay cache without booting a VM.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand, ValueEnum};

use crate::commands::runtime_overlay::{
    RuntimeOverlayAcquireMode, RuntimeOverlayAcquireParams, acquire_runtime_overlay,
    runtime_overlay_acquire_mode, runtime_overlay_source_checkout_root,
};
use crate::ui;
use mvm_core::arch::GuestArch;
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug, Clone)]
enum Cmd {
    /// Populate the local cache with the version-matched runtime overlay.
    Build(BuildArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct BuildArgs {
    /// Where the overlay comes from. `build` assembles it from the source
    /// checkout, `download` fetches the published artifact, and `auto`
    /// follows the same resolver ordinary required-overlay boots use.
    #[arg(long, value_enum, default_value_t = Source::Auto)]
    source: Source,

    /// Target architecture. Defaults to the host architecture.
    #[arg(long, value_parser = ["aarch64", "x86_64"])]
    arch: Option<String>,

    /// Override the expected overlay version. Defaults to this `mvmctl` build's
    /// version, which is what ordinary boots require.
    #[arg(long)]
    version: Option<String>,

    /// Rebuild or re-download even when the matching cache entry already exists.
    #[arg(long)]
    force: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Auto,
    Build,
    Download,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.cmd {
        Cmd::Build(build) => run_build(build),
    }
}

fn run_build(args: BuildArgs) -> Result<()> {
    let version = args
        .version
        .clone()
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    let arch = match args.arch.as_deref() {
        Some(raw) => raw.parse::<GuestArch>().context("parse --arch")?,
        None => GuestArch::host(),
    };
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let mode = requested_acquire_mode(args.source);
    let resolver = mvm_build::runtime_overlay::RuntimeOverlayResolver::new(
        cache_root.clone(),
        version.clone(),
    );
    if !args.force {
        match mode {
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout => {
                let artifact = mvm_build::runtime_overlay::resolve_or_build_local_runtime_overlay(
                    &cache_root,
                    &version,
                    arch,
                )?;
                announce_built_overlay(&artifact, false);
                return Ok(());
            }
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact => {
                if let Ok(artifact) = resolver.resolve(arch) {
                    announce_cached_overlay(&artifact);
                    return Ok(());
                }
            }
        }
    }

    let source_checkout_root = match mode {
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout => Some(
            runtime_overlay_source_checkout_root().ok_or_else(|| {
                anyhow::anyhow!(
                    "--source build requires a source checkout with nix/images/runtime-overlay/flake.nix"
                )
            })?,
        ),
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact => None,
    };

    match mode {
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout => {
            ui::info("Building the version-matched runtime overlay from the source checkout...");
        }
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact => {
            ui::info("Downloading the version-matched runtime overlay into the local cache...");
        }
    }

    let artifact = acquire_runtime_overlay(&RuntimeOverlayAcquireParams {
        cache_root: &cache_root,
        expected_version: &version,
        arch,
        source_checkout_root: source_checkout_root.as_deref(),
    })?;
    announce_built_overlay(&artifact, args.force);
    Ok(())
}

fn requested_acquire_mode(source: Source) -> RuntimeOverlayAcquireMode {
    match source {
        Source::Auto => runtime_overlay_acquire_mode(),
        Source::Build => RuntimeOverlayAcquireMode::BuildFromSourceCheckout,
        Source::Download => RuntimeOverlayAcquireMode::DownloadPublishedArtifact,
    }
}

fn announce_cached_overlay(artifact: &mvm_build::runtime_overlay::RuntimeOverlayArtifact) {
    ui::success(&format!(
        "Runtime overlay {} for {} already cached at {}",
        artifact.version,
        artifact.arch,
        artifact.overlay_ext4.display()
    ));
}

fn announce_built_overlay(
    artifact: &mvm_build::runtime_overlay::RuntimeOverlayArtifact,
    forced: bool,
) {
    let action = if forced { "refreshed" } else { "cached" };
    ui::success(&format!(
        "Runtime overlay {} for {} {action}: ext4={}, verity={}",
        artifact.version,
        artifact.arch,
        artifact.overlay_ext4.display(),
        artifact.sidecar.display()
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{Cli, Commands, build::group as build_group};
    use clap::Parser;

    #[test]
    fn runtime_overlay_build_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "mvmctl",
            "build",
            "runtime-overlay",
            "build",
            "--source",
            "download",
            "--arch",
            "aarch64",
            "--version",
            "1.2.3",
            "--force",
        ])
        .expect("parse");
        let Commands::Build(group) = cli.command else {
            panic!("expected build group");
        };
        match group.action {
            build_group::BuildCmd::RuntimeOverlay(_) => {}
            other => panic!("expected runtime-overlay command, got {other:?}"),
        }
    }

    #[test]
    fn requested_acquire_mode_honors_explicit_source() {
        assert_eq!(
            requested_acquire_mode(Source::Build),
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout
        );
        assert_eq!(
            requested_acquire_mode(Source::Download),
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact
        );
    }
}
