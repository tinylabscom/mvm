//! `mvmctl build sdk-sidecar build` — explicitly build and cache the
//! checkout's guest-facing host-services cdylib through the Stage 0 builder VM.

#[cfg(feature = "builder-vm")]
use anyhow::Context;
use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use crate::commands::runtime_overlay::runtime_overlay_source_checkout_root;
use crate::ui;
use mvm_contract::guest_libc::GuestLibc;
use mvm_core::arch::GuestArch;
use mvm_core::user_config::MvmConfig;
use mvm_fs::sdk_sidecar::SdkSidecarResolver;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug, Clone)]
enum Cmd {
    /// Build from this checkout and populate the version-matched cache.
    Build(BuildArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct BuildArgs {
    /// Rebuild even when the cache already matches this checkout.
    #[arg(long)]
    force: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.cmd {
        Cmd::Build(build) => run_build(build),
    }
}

fn run_build(args: BuildArgs) -> Result<()> {
    let workspace_root = runtime_overlay_source_checkout_root().ok_or_else(|| {
        anyhow::anyhow!(
            "SDK sidecar source build requires a source checkout with nix/images/runtime-overlay/flake.nix"
        )
    })?;
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = GuestArch::host();

    // Both variants, every time. Which one a workload needs is a property of
    // the image it boots, not of this command, and a host that caches only one
    // silently makes `--host-service` unusable for every guest carrying the
    // other libc — the failure landing inside the guest at `dlopen` rather than
    // here. The second build shares the first's closure, so it is far cheaper
    // than the first.
    for libc in SIDECAR_LIBC_VARIANTS {
        build_one_variant(
            &workspace_root,
            &cache_root,
            version,
            arch,
            libc,
            args.force,
        )?;
    }
    Ok(())
}

/// The sidecar variants a source build populates.
const SIDECAR_LIBC_VARIANTS: [GuestLibc; 2] = [GuestLibc::Glibc, GuestLibc::Musl];

fn build_one_variant(
    workspace_root: &std::path::Path,
    cache_root: &std::path::Path,
    version: &str,
    arch: GuestArch,
    libc: GuestLibc,
    force: bool,
) -> Result<()> {
    if !force {
        let resolver = SdkSidecarResolver::new(cache_root.to_path_buf(), version.to_string());
        if let Ok(artifact) = resolver.resolve(&arch.to_string(), libc)
            && mvm_build::sdk_sidecar::cached_sidecar_provenance(
                cache_root,
                version,
                arch,
                libc,
                workspace_root,
            )? == mvm_build::sdk_sidecar::SidecarProvenance::MatchesSource
        {
            announce_cached_sidecar(&artifact);
            return Ok(());
        }
    }

    #[cfg(feature = "builder-vm")]
    {
        let artifact = crate::commands::env::builder_vm::build_sdk_sidecar_from_checkout(
            workspace_root,
            cache_root,
            version,
            arch,
            libc,
            mvm_runtime::ui::is_verbose(),
        )
        .with_context(|| {
            format!(
                "building {libc} SDK sidecar {version} for {arch} from {}",
                workspace_root.display()
            )
        })?;
        ui::success(&format!(
            "SDK sidecar {} ({}) for {} cached at {}",
            artifact.version,
            artifact.libc,
            artifact.arch,
            artifact.image.display()
        ));
        Ok(())
    }

    #[cfg(not(feature = "builder-vm"))]
    anyhow::bail!(
        "SDK sidecar source build requires the `builder-vm` feature; rebuild the binary with that feature enabled"
    )
}

fn announce_cached_sidecar(artifact: &mvm_fs::sdk_sidecar::SdkSidecarArtifact) {
    ui::success(&format!(
        "SDK sidecar {} for {} already matches this checkout at {}",
        artifact.version,
        artifact.arch,
        artifact.image.display()
    ));
}
