//! `mvmctl build runtime-overlay build` — explicitly populate the read-only
//! runtime-overlay cache without booting a VM: assembled on the host from this
//! checkout's guest-runtime archive at this CLI's version, or the member of
//! the image set this build pins. A selected image checkout has no say: the
//! overlay is guest runtime, not a Linux-layer image.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand, ValueEnum};

use crate::ui;
use mvm_client::launch::runtime_overlay::{
    RuntimeOverlayAcquireMode, RuntimeOverlayAcquireParams, acquire_runtime_overlay,
    runtime_overlay_acquire_mode, runtime_overlay_source_checkout_root,
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
    /// Where the overlay comes from. `build` assembles it from the source
    /// checkout, `download` fetches the published artifact, and `auto`
    /// follows the same resolver ordinary required-overlay boots use; on a
    /// release binary that is its own release's guest runtime.
    #[arg(long, value_enum, default_value_t = Source::Auto)]
    source: Source,

    /// Target architecture. Defaults to the host architecture.
    #[arg(long, value_parser = ["aarch64", "x86_64"])]
    arch: Option<String>,

    /// Override the expected overlay version of a source build. Defaults to
    /// this `mvmctl` build's version, which is what ordinary source-built
    /// boots require. A download installs the pinned image set's member,
    /// whose version is the member's own.
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
    if assembles_from_release(
        args.source,
        mvm_build::artifact_acquisition::compiled_channel(),
    ) {
        return assemble_from_release(&cache_root, &version, arch, args.force);
    }
    let mode = requested_acquire_mode(args.source);
    let resolver =
        mvm_fs::overlay::RuntimeOverlayResolver::new(cache_root.clone(), version.clone());
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
                if let Ok(artifact) =
                    mvm_build::runtime_overlay::resolve_cached_runtime_overlay(&resolver, arch)
                {
                    announce_cached_overlay(&artifact);
                    return Ok(());
                }
            }
        }
    }

    if args.force && mode == RuntimeOverlayAcquireMode::BuildFromSourceCheckout {
        mvm_build::runtime_pieces::discard_local_piece(
            &cache_root,
            &version,
            arch,
            mvm_build::runtime_pieces::RuntimePiece::RuntimeOverlay,
        )
        .context("discarding the cached runtime overlay")?;
    }
    let source_checkout_root = match mode {
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout => {
            Some(runtime_overlay_source_checkout_root().ok_or_else(|| {
                anyhow::anyhow!(
                    "--source build assembles the overlay from guest binaries cargo builds in an \
                     mvm source checkout, and this binary has none; run it from a contributor \
                     build, set {} to an mvm checkout, or use --source download",
                    mvm_build::image_source::GUEST_RUNTIME_SOURCE_ROOT_ENV,
                )
            })?)
        }
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact => None,
    };

    match mode {
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout => {
            ui::info(
                "Assembling the version-matched runtime overlay from this checkout's guest runtime...",
            );
        }
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact => {
            ui::info(
                "Downloading the runtime overlay from the pinned image set into the local cache...",
            );
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

/// `auto` on a release binary assembles from the guest runtime its own
/// release ships, as bootstrap does; `download` still names the image set.
fn assembles_from_release(
    source: Source,
    channel: mvm_build::artifact_acquisition::DistributionChannel,
) -> bool {
    source == Source::Auto
        && channel == mvm_build::artifact_acquisition::DistributionChannel::Release
}

/// Assemble the overlay from this release binary's own guest runtime. The
/// runtime is version-locked to the binary, so another `--version` is refused.
fn assemble_from_release(
    cache_root: &std::path::Path,
    version: &str,
    arch: GuestArch,
    force: bool,
) -> Result<()> {
    let own = env!("CARGO_PKG_VERSION");
    anyhow::ensure!(
        version == own,
        "this release binary's guest runtime is mvmctl {own}'s; it cannot assemble a runtime \
         overlay for {version}"
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
    ui::info("Assembling the runtime overlay from this release's guest runtime...");
    let artifact = mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
        cache_root, version, arch, &runtime,
    )
    .context("assembling the runtime overlay from the release guest runtime")?;
    announce_built_overlay(&artifact, force);
    Ok(())
}

fn requested_acquire_mode(source: Source) -> RuntimeOverlayAcquireMode {
    match source {
        Source::Auto => runtime_overlay_acquire_mode(),
        Source::Build => RuntimeOverlayAcquireMode::BuildFromSourceCheckout,
        Source::Download => RuntimeOverlayAcquireMode::DownloadPublishedArtifact,
    }
}

fn announce_cached_overlay(artifact: &mvm_fs::overlay::RuntimeOverlayArtifact) {
    ui::success(&format!(
        "Runtime overlay {} for {} already cached at {}",
        artifact.version,
        artifact.arch,
        artifact.overlay_ext4.display()
    ));
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
    fn auto_on_a_release_binary_assembles_from_its_own_guest_runtime() {
        use mvm_build::artifact_acquisition::DistributionChannel;
        assert!(assembles_from_release(
            Source::Auto,
            DistributionChannel::Release
        ));
        for source in [Source::Build, Source::Download] {
            assert!(!assembles_from_release(
                source,
                DistributionChannel::Release
            ));
        }
        for source in [Source::Auto, Source::Build, Source::Download] {
            assert!(!assembles_from_release(source, DistributionChannel::Source));
        }
    }

    #[test]
    fn a_release_binary_refuses_an_overlay_for_another_version() {
        let cache = tempfile::tempdir().unwrap();
        let error = assemble_from_release(cache.path(), "0.0.0-other", GuestArch::host(), false)
            .expect_err("the release runtime is version-locked");
        assert!(error.to_string().contains("0.0.0-other"), "{error}");
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
