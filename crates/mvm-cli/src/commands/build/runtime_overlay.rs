//! `mvmctl dev runtime-overlay build` — explicitly populate the read-only
//! runtime-overlay cache without booting a VM: assembled on the host from a
//! guest runtime — this checkout's, or the published one of this CLI's
//! version. The image set carries no overlay, and a selected image checkout
//! has no say: the overlay is guest runtime, not a Linux-layer image.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand, ValueEnum};

use crate::ui;
use mvm_client::launch::runtime_overlay::{
    RuntimeOverlayAcquireMode, RuntimeOverlayAcquireParams, acquire_runtime_overlay,
    runtime_overlay_source_checkout_root,
};
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
    /// Populate the local cache with the runtime overlay this host boots.
    Build(BuildArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct BuildArgs {
    /// Which guest runtime the overlay is assembled from. `build` assembles
    /// it from the source checkout; `auto` does the same in a source checkout
    /// and otherwise assembles it from the published guest runtime of this
    /// version — on a release binary, the one its own release ships.
    #[arg(long, value_enum, default_value_t = Source::Auto)]
    source: Source,

    /// Target architecture. Defaults to the host architecture.
    #[arg(long, value_parser = ["aarch64", "x86_64"])]
    arch: Option<String>,

    /// Override the expected overlay version of a source build. Defaults to
    /// this `mvmctl` build's version, which is what ordinary source-built
    /// boots require. A published guest runtime is locked to this version.
    #[arg(long)]
    version: Option<String>,

    /// Reassemble even when the matching cache entry already exists.
    #[arg(long)]
    force: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Auto,
    Build,
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
    match requested_acquire_mode(
        args.source,
        runtime_overlay_source_checkout_root().is_some(),
    ) {
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact => {
            assemble_from_published(&cache_root, &version, arch, args.force)
        }
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout => {
            assemble_from_source(&cache_root, &version, arch, args.force)
        }
    }
}

/// Assemble the overlay from this checkout's guest runtime.
fn assemble_from_source(
    cache_root: &std::path::Path,
    version: &str,
    arch: GuestArch,
    force: bool,
) -> Result<()> {
    if !force {
        let artifact = mvm_build::runtime_overlay::resolve_or_build_local_runtime_overlay(
            cache_root, version, arch,
        )?;
        announce_built_overlay(&artifact, false);
        return Ok(());
    }
    mvm_build::runtime_pieces::discard_local_piece(
        cache_root,
        version,
        arch,
        mvm_build::runtime_pieces::RuntimePiece::RuntimeOverlay,
    )
    .context("discarding the cached runtime overlay")?;
    let source_checkout_root = runtime_overlay_source_checkout_root().ok_or_else(|| {
        anyhow::anyhow!(
            "--source build assembles the overlay from guest binaries cargo builds in an mvm \
             source checkout, and this binary has none; run it from a contributor build or set \
             {} to an mvm checkout",
            mvm_build::image_source::GUEST_RUNTIME_SOURCE_ROOT_ENV,
        )
    })?;
    ui::info(
        "Assembling the version-matched runtime overlay from this checkout's guest runtime...",
    );
    let artifact = acquire_runtime_overlay(&RuntimeOverlayAcquireParams {
        cache_root,
        expected_version: version,
        arch,
        source_checkout_root: &source_checkout_root,
    })?;
    announce_built_overlay(&artifact, force);
    Ok(())
}

/// Assemble the overlay from the published guest runtime of this CLI's
/// version — on a release binary, the one its own release ships. The runtime
/// is version-locked to the binary, so another `--version` is refused.
fn assemble_from_published(
    cache_root: &std::path::Path,
    version: &str,
    arch: GuestArch,
    force: bool,
) -> Result<()> {
    let own = env!("CARGO_PKG_VERSION");
    anyhow::ensure!(
        version == own,
        "the published guest runtime this binary uses is mvmctl {own}'s; it cannot assemble a \
         runtime overlay for {version}"
    );
    let runtime = crate::release_guest_runtime::installed_for_running_binary(cache_root, arch)?;
    if force {
        mvm_build::runtime_pieces::discard_local_piece(
            cache_root,
            version,
            arch,
            mvm_build::runtime_pieces::RuntimePiece::RuntimeOverlay,
        )
        .context("discarding the cached runtime overlay")?;
    }
    ui::info("Assembling the runtime overlay from the published guest runtime...");
    let artifact = mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
        cache_root, version, arch, &runtime,
    )
    .context("assembling the runtime overlay from the published guest runtime")?;
    announce_built_overlay(&artifact, force);
    Ok(())
}

/// `auto` assembles from a checkout when there is one, as bootstrap does for
/// a source build, and from the published guest runtime otherwise.
fn requested_acquire_mode(source: Source, checkout: bool) -> RuntimeOverlayAcquireMode {
    match (source, checkout) {
        (Source::Build, _) | (Source::Auto, true) => {
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout
        }
        (Source::Auto, false) => RuntimeOverlayAcquireMode::DownloadPublishedArtifact,
    }
}

fn announce_built_overlay(artifact: &mvm_fs::overlay::RuntimeOverlayArtifact, forced: bool) {
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
            "dev",
            "runtime-overlay",
            "build",
            "--source",
            "build",
            "--arch",
            "aarch64",
            "--version",
            "1.2.3",
            "--force",
        ])
        .expect("parse");
        let Commands::Dev(group) = cli.command else {
            panic!("expected build group");
        };
        match group.action {
            build_group::BuildCmd::RuntimeOverlay(_) => {}
            other => panic!("expected runtime-overlay command, got {other:?}"),
        }
    }

    /// The image set carries no overlay, so there is nothing to download.
    #[test]
    fn source_download_is_no_longer_accepted() {
        let err = Cli::try_parse_from([
            "mvmctl",
            "dev",
            "runtime-overlay",
            "build",
            "--source",
            "download",
        ])
        .expect_err("--source download names a retired image-set member");
        assert!(err.to_string().contains("download"), "{err}");
    }

    #[test]
    fn a_published_runtime_refuses_an_overlay_for_another_version() {
        let cache = tempfile::tempdir().unwrap();
        let error = assemble_from_published(cache.path(), "0.0.0-other", GuestArch::host(), false)
            .expect_err("the published runtime is version-locked");
        assert!(error.to_string().contains("0.0.0-other"), "{error}");
    }

    #[test]
    fn requested_acquire_mode_honors_explicit_source_and_the_checkout() {
        for checkout in [true, false] {
            assert_eq!(
                requested_acquire_mode(Source::Build, checkout),
                RuntimeOverlayAcquireMode::BuildFromSourceCheckout
            );
        }
        assert_eq!(
            requested_acquire_mode(Source::Auto, true),
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout
        );
        assert_eq!(
            requested_acquire_mode(Source::Auto, false),
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact
        );
    }
}
