//! `mvmctl build sdk-sidecar build` — explicitly populate the SDK sidecar
//! cache for both guest libcs: packed on the host from this checkout's
//! guest-runtime archive, or installed from the pinned image set.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand, ValueEnum};

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
    /// Populate the version-matched cache with both libc variants.
    Build(BuildArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct BuildArgs {
    /// Where the sidecars come from. `build` packs them from this checkout's
    /// guest-runtime archive, building the archive first if it is not cached;
    /// `download` installs the pinned image set's members; `auto` builds in a
    /// source checkout and downloads otherwise.
    #[arg(long, value_enum, default_value_t = Source::Auto)]
    source: Source,

    /// Repack or re-download even when a matching sidecar is already cached.
    #[arg(long)]
    force: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Auto,
    Build,
    Download,
}

/// The acquisition a request resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    /// Pack from the guest-runtime archive of the checkout at this root.
    Archive(std::path::PathBuf),
    /// Install the pinned image set's members.
    ImageSet,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.cmd {
        Cmd::Build(build) => run_build(build),
    }
}

fn run_build(args: BuildArgs) -> Result<()> {
    if adopted_from_pinned_set()? {
        return Ok(());
    }
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = GuestArch::host();
    match route(
        args.source,
        mvm_client::launch::runtime_overlay::runtime_overlay_source_checkout_root(),
    )? {
        Route::Archive(workspace_root) => {
            pack_from_archive(&cache_root, version, arch, &workspace_root, args.force)
        }
        Route::ImageSet => install_from_image_set(&cache_root, arch, args.force),
    }
}

/// `auto` builds wherever there is a checkout to build from. An explicit
/// `build` without one is refused with the way out named.
fn route(source: Source, checkout: Option<std::path::PathBuf>) -> Result<Route> {
    match (source, checkout) {
        (Source::Download, _) | (Source::Auto, None) => Ok(Route::ImageSet),
        (Source::Build | Source::Auto, Some(root)) => Ok(Route::Archive(root)),
        (Source::Build, None) => anyhow::bail!(
            "--source build packs the sidecars from the guest runtime cargo builds in an mvm \
             source checkout, and this binary has none; run it from a contributor build, set {} \
             to an mvm checkout, or use --source download",
            mvm_build::image_source::GUEST_RUNTIME_SOURCE_ROOT_ENV,
        ),
    }
}

/// Pack both variants from the checkout's guest-runtime archive: the same
/// archive, and the same packing, that bootstrap and the launch path use.
fn pack_from_archive(
    cache_root: &std::path::Path,
    version: &str,
    arch: GuestArch,
    workspace_root: &std::path::Path,
    force: bool,
) -> Result<()> {
    use mvm_build::runtime_pieces::{
        RuntimePiece, SDK_SIDECAR_LIBCS, discard_local_piece, pack_sdk_sidecars, short_digest,
    };

    let phase = crate::ui::activity::start(format!(
        "Resolving the guest runtime for {arch} from {}",
        workspace_root.display()
    ));
    let runtime = mvm_build::guest_runtime::resolve_or_build_source_guest_runtime(
        cache_root,
        version,
        arch,
        workspace_root,
    )
    .context("resolving the shared guest runtime")?;
    phase.finish();
    if force {
        for libc in SDK_SIDECAR_LIBCS {
            discard_local_piece(cache_root, version, arch, RuntimePiece::SdkSidecar(libc))
                .with_context(|| format!("discarding the cached {libc} SDK sidecar"))?;
        }
    }
    for artifact in pack_sdk_sidecars(cache_root, version, arch, &runtime)? {
        ui::success(&format!(
            "SDK sidecar ({}) for {arch} cached from guest runtime archive {}: {}",
            artifact.libc,
            short_digest(&runtime.digest),
            artifact.image.display()
        ));
    }
    Ok(())
}

/// Install both variants from the pinned image set, skipping one already
/// installed from it unless `force`.
fn install_from_image_set(
    cache_root: &std::path::Path,
    arch: GuestArch,
    force: bool,
) -> Result<()> {
    let set = mvm_build::published_image_set::SetMemberCache::locked();
    let tag = &mvm_core::image_set::image_train_lock()
        .image_set
        .release_tag;
    for libc in mvm_build::runtime_pieces::SDK_SIDECAR_LIBCS {
        let cached =
            mvm_build::sdk_sidecar::image_set_sidecar_resolver(cache_root, &set, arch, libc)
                .ok()
                .and_then(|resolver| resolver.resolve(&arch.to_string(), libc).ok());
        let artifact = match cached {
            Some(artifact) if !force => artifact,
            _ => mvm_build::sdk_sidecar::download_sdk_sidecar(arch, libc, cache_root)?,
        };
        ui::success(&format!(
            "SDK sidecar ({libc}) for {arch} installed from image set {tag}: {}",
            artifact.image.display()
        ));
    }
    Ok(())
}

/// When the caller set `MVM_FETCH_UNCHANGED_IMAGES`, adopt the pinned set's
/// verified sidecar members instead of packing: under `1` only when they were
/// built from exactly this tree's sources, under `pinned` whatever they were
/// built from. Returns whether they were adopted. A refused adoption is final:
/// the verified bytes were asked for, which must not silently fall back to a
/// local pack.
fn adopted_from_pinned_set() -> Result<bool> {
    use mvm_build::fetch_unchanged::{self as fetch, ArmRequest, FetchMode, PinnedMembers};
    let request = ArmRequest::for_host(PinnedMembers::SdkSidecars);
    if request.mode == FetchMode::Off {
        return Ok(false);
    }
    // Said at notice level whichever arm runs: the documented-surface e2e
    // records which one did, and an unannounced fall-through is
    // indistinguishable from the knob doing nothing.
    let arm = fetch::resolve_arm(request)?;
    ui::notice(&arm.report(request));
    let fetch::Arm::Adopt { set, .. } = arm else {
        return Ok(false);
    };
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    fetch::fetch_sidecars_from_set(&set, request.arch, &cache_root).map_err(|e| {
        anyhow::anyhow!(
            "adopting the SDK sidecars of the pinned image set {} failed: {e}",
            set.release_tag()
        )
    })?;
    ui::success(&format!(
        "SDK sidecars (glibc, musl) installed from the pinned image set {}; no build run.",
        set.release_tag()
    ));
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{Cli, Commands, build::group as build_group};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn the_build_verb_parses_its_source_and_force() {
        for argv in [
            vec!["mvmctl", "build", "sdk-sidecar", "build"],
            vec![
                "mvmctl",
                "build",
                "sdk-sidecar",
                "build",
                "--source",
                "download",
                "--force",
            ],
        ] {
            let cli = Cli::try_parse_from(&argv).expect("parse");
            let Commands::Build(group) = cli.command else {
                panic!("expected build group");
            };
            assert!(matches!(group.action, build_group::BuildCmd::SdkSidecar(_)));
        }
    }

    #[test]
    fn a_source_checkout_packs_from_the_archive_by_default() {
        let root = PathBuf::from("/checkout");
        assert_eq!(
            route(Source::Auto, Some(root.clone())).unwrap(),
            Route::Archive(root.clone())
        );
        assert_eq!(
            route(Source::Build, Some(root.clone())).unwrap(),
            Route::Archive(root)
        );
    }

    #[test]
    fn without_a_checkout_auto_installs_the_image_set_members() {
        assert_eq!(route(Source::Auto, None).unwrap(), Route::ImageSet);
    }

    #[test]
    fn download_installs_the_image_set_members_even_in_a_checkout() {
        assert_eq!(
            route(Source::Download, Some(PathBuf::from("/checkout"))).unwrap(),
            Route::ImageSet
        );
    }

    /// The sidecar no longer comes from an image checkout or the builder VM, so
    /// an explicit build without a source checkout names what is missing and
    /// the download alternative, not an image-checkout variable.
    #[test]
    fn an_explicit_build_without_a_checkout_names_the_way_out() {
        let error = route(Source::Build, None).unwrap_err().to_string();
        assert!(error.contains("--source download"), "{error}");
        assert!(
            error.contains(mvm_build::image_source::GUEST_RUNTIME_SOURCE_ROOT_ENV),
            "{error}"
        );
        assert!(
            !error.contains(mvm_build::image_source::MVM_IMAGES_DIR_ENV),
            "{error}"
        );
    }
}
