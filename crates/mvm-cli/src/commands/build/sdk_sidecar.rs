//! `mvmctl dev sdk-sidecar build` — explicitly populate the SDK sidecar
//! cache for both guest libcs, packed on the host from a guest runtime: this
//! checkout's archive, or the published one of this CLI's version. The image
//! set carries no sidecar.

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
    /// Which guest runtime the sidecars are packed from. `build` packs them
    /// from this checkout's guest-runtime archive, building the archive first
    /// if it is not cached; `auto` does the same in a source checkout and
    /// otherwise packs from the published guest runtime of this version — on
    /// a release binary, the one its own release ships.
    #[arg(long, value_enum, default_value_t = Source::Auto)]
    source: Source,

    /// Repack even when a matching sidecar is already cached.
    #[arg(long)]
    force: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Auto,
    Build,
}

/// The acquisition a request resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    /// Pack from the guest-runtime archive of the checkout at this root.
    Archive(std::path::PathBuf),
    /// Pack from the published guest runtime of this CLI's version.
    ReleaseArchive,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.cmd {
        Cmd::Build(build) => run_build(build),
    }
}

fn run_build(args: BuildArgs) -> Result<()> {
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
        Route::ReleaseArchive => {
            let runtime =
                crate::release_guest_runtime::installed_for_running_binary(&cache_root, arch)?;
            pack_from_runtime(&cache_root, version, arch, &runtime, args.force)
        }
    }
}

/// `auto` builds wherever there is a checkout to build from, and otherwise
/// packs from the published guest runtime of this version — a release
/// binary's own. An explicit `build` without a checkout is refused with the
/// way out named.
fn route(source: Source, checkout: Option<std::path::PathBuf>) -> Result<Route> {
    match (source, checkout) {
        (Source::Build | Source::Auto, Some(root)) => Ok(Route::Archive(root)),
        (Source::Auto, None) => Ok(Route::ReleaseArchive),
        (Source::Build, None) => anyhow::bail!(
            "--source build packs the sidecars from the guest runtime cargo builds in an mvm \
             source checkout, and this binary has none; run it from a contributor build, set {} \
             to an mvm checkout, or use --source auto to pack them from the published guest \
             runtime of this version",
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
    pack_from_runtime(cache_root, version, arch, &runtime, force)
}

/// Pack both variants from `runtime`, repacking when `force`.
fn pack_from_runtime(
    cache_root: &std::path::Path,
    version: &str,
    arch: GuestArch,
    runtime: &mvm_build::guest_runtime::GuestRuntime,
    force: bool,
) -> Result<()> {
    use mvm_build::runtime_pieces::{
        RuntimePiece, SDK_SIDECAR_LIBCS, discard_local_piece, pack_sdk_sidecars, short_digest,
    };

    if force {
        for libc in SDK_SIDECAR_LIBCS {
            discard_local_piece(cache_root, version, arch, RuntimePiece::SdkSidecar(libc))
                .with_context(|| format!("discarding the cached {libc} SDK sidecar"))?;
        }
    }
    for artifact in pack_sdk_sidecars(cache_root, version, arch, runtime)? {
        ui::success(&format!(
            "SDK sidecar ({}) for {arch} cached from guest runtime archive {}: {}",
            artifact.libc,
            short_digest(&runtime.digest),
            artifact.image.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{Cli, Commands, build::group as build_group};
    use clap::Parser;
    use std::path::PathBuf;

    /// Without a checkout there is nothing to build from, so `auto` packs
    /// from the published guest runtime of this version — never the image
    /// set, which carries no sidecar.
    #[test]
    fn without_a_checkout_auto_packs_from_the_published_guest_runtime() {
        assert_eq!(route(Source::Auto, None).unwrap(), Route::ReleaseArchive);
    }

    #[test]
    fn the_build_verb_parses_its_source_and_force() {
        for argv in [
            vec!["mvmctl", "dev", "sdk-sidecar", "build"],
            vec![
                "mvmctl",
                "dev",
                "sdk-sidecar",
                "build",
                "--source",
                "build",
                "--force",
            ],
        ] {
            let cli = Cli::try_parse_from(&argv).expect("parse");
            let Commands::Dev(group) = cli.command else {
                panic!("expected build group");
            };
            assert!(matches!(group.action, build_group::BuildCmd::SdkSidecar(_)));
        }
    }

    /// The image set carries no sidecar, so there is nothing to download.
    #[test]
    fn source_download_is_no_longer_accepted() {
        Cli::try_parse_from([
            "mvmctl",
            "dev",
            "sdk-sidecar",
            "build",
            "--source",
            "download",
        ])
        .expect_err("--source download names a retired image-set member");
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

    /// The sidecar no longer comes from an image checkout or the builder VM, so
    /// an explicit build without a source checkout names what is missing and
    /// the published alternative, not an image-checkout variable.
    #[test]
    fn an_explicit_build_without_a_checkout_names_the_way_out() {
        let error = route(Source::Build, None).unwrap_err().to_string();
        assert!(error.contains("--source auto"), "{error}");
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
