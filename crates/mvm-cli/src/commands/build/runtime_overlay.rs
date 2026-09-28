//! `mvmctl build runtime-overlay build` — explicitly populate the read-only
//! runtime-overlay cache without booting a VM: a source build at this CLI's
//! version, or the member of the image set this build pins.

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
    /// follows the same resolver ordinary required-overlay boots use.
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
    // A selected checkout is the overlay's source; fetching the published
    // artifact under one is refused, with the way out named. `--force` is a
    // source-build concept: the pair answers from its content-addressed
    // cache, so an unchanged pair has nothing to force.
    #[cfg(feature = "builder-vm")]
    if let Some(checkout) = crate::commands::env::builder_vm::selected_local_checkout()? {
        if args.source == Source::Download {
            anyhow::bail!(
                "--source download asks for the published overlay while {} names a local image                  checkout; unset it for this run to compare against a signed release",
                mvm_build::image_source::MVM_IMAGES_DIR_ENV,
            );
        }
        return build_pair_overlay(&checkout, &cache_root, &version, arch);
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
            ui::info("Building the version-matched runtime overlay from the source checkout...");
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

/// Build the overlay from the pair's `runtime-overlay.default` target and
/// install it into the version-matched cache, stamped with the pair identity
/// so launches under this pair trust it.
#[cfg(feature = "builder-vm")]
fn build_pair_overlay(
    checkout: &mvm_build::image_source::LocalImageCheckout,
    cache_root: &std::path::Path,
    version: &str,
    arch: GuestArch,
) -> Result<()> {
    use mvm_build::image_source::ImageBuildRole;
    let target = mvm_build::image_source::ImageBuildTarget {
        role: ImageBuildRole::RuntimeOverlay,
        attr: mvm_build::image_source::FlakeAttr::new("default")
            .expect("default is a valid flake attribute"),
    };
    ui::info("Building the runtime overlay from the selected image checkout...");
    let build = crate::commands::env::builder_vm::ensure_pair_built(checkout, target)?;
    let staged = crate::commands::env::builder_vm::staged_contract_files(
        &build.entry,
        &[
            ("runtime_overlay", "overlay.ext4"),
            ("runtime_overlay", "overlay.verity"),
            ("runtime_overlay", "overlay.roothash"),
            ("runtime_overlay", "VERSION"),
        ],
    )?;
    let artifact =
        mvm_fs::overlay::read_overlay_artifact_from_dir(staged.path(), &arch.to_string())?;
    if artifact.version != version {
        anyhow::bail!(
            "the selected checkout's runtime overlay is version {}, but version {version} is required",
            artifact.version,
        );
    }
    let fingerprint = build.key.digest().as_str().to_string();
    let artifact = mvm_build::runtime_overlay::install_overlay_into_cache(
        &artifact,
        cache_root,
        &mvm_build::runtime_overlay::InstallOptions { overwrite: true },
    )?;
    mvm_client::launch::runtime_source::record_overlay_install_pair_fingerprint(
        cache_root,
        version,
        &arch.to_string(),
        &fingerprint,
    )?;
    announce_built_overlay(&artifact, false);
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

#[cfg(all(test, feature = "builder-vm"))]
mod pair_routing_tests {
    use super::*;
    use crate::commands::env::builder_vm::test_pair::{Pair, TestArtifact};
    use mvm_core::util::test_env::TestEnv;

    fn selector_env(pair: &Pair) -> TestEnv {
        let mut env = TestEnv::new();
        env.set(
            mvm_build::image_source::MVM_IMAGES_DIR_ENV,
            pair.images.root(),
        );
        env
    }

    /// Publish a pair `runtime-overlay.default` target whose overlay carries
    /// `version` in its `VERSION` file.
    fn publish_pair_overlay(pair: &Pair, version: &str) {
        pair.publish(
            mvm_build::image_source::ImageBuildRole::RuntimeOverlay,
            "default",
            &[(
                mvm_core::image_set::ImageSetRole::RuntimeOverlay,
                None,
                vec![
                    TestArtifact {
                        name: "overlay.ext4",
                        // A real ext4: the attach-time validator reads the
                        // superblock's feature bits, not just the magic.
                        bytes: mvm_fs::ext4::build_image(
                            mvm_fs::overlay::REQUIRED_OVERLAY_GUEST_PATHS
                                .iter()
                                .map(|path| mvm_fs::ext4::Node::File {
                                    path: path.to_string(),
                                    mode: 0o755,
                                    data: b"overlay guest binary\n".to_vec(),
                                    xattrs: Vec::new(),
                                    owner: mvm_fs::ext4::Owner::ROOT,
                                })
                                .collect(),
                            &Default::default(),
                        )
                        .expect("build the overlay ext4 fixture"),
                        format: "ext4",
                    },
                    TestArtifact {
                        name: "overlay.verity",
                        bytes: b"verity tree\n".to_vec(),
                        format: "verity_hash_tree",
                    },
                    TestArtifact {
                        name: "overlay.roothash",
                        bytes: format!("{}\n", "ab".repeat(32)).into_bytes(),
                        format: "verity_root_hash",
                    },
                    TestArtifact {
                        name: "VERSION",
                        bytes: format!("{version}\n").into_bytes(),
                        format: "text",
                    },
                ],
                &["virtio_blk", "dm_verity"],
            )],
        );
    }

    #[test]
    fn download_is_refused_while_a_checkout_is_selected() {
        let pair = Pair::new();
        let mut env = selector_env(&pair);
        let home = pair.tmp.path().join("home");
        env.isolate_mvm_home(&home);
        std::fs::create_dir_all(&home).unwrap();
        let err = run_build(BuildArgs {
            source: Source::Download,
            arch: None,
            version: None,
            force: false,
        })
        .expect_err("fetching the published overlay under a selected checkout must refuse");
        assert!(
            err.to_string()
                .contains(mvm_build::image_source::MVM_IMAGES_DIR_ENV),
            "{err:#}"
        );
    }

    #[test]
    fn the_pair_overlay_installs_into_the_cache_with_its_identity_stamped() {
        let pair = Pair::new();
        let mut env = selector_env(&pair);
        let home = pair.tmp.path().join("home");
        env.isolate_mvm_home(&home);
        std::fs::create_dir_all(&home).unwrap();
        publish_pair_overlay(&pair, env!("CARGO_PKG_VERSION"));

        run_build(BuildArgs {
            source: Source::Auto,
            arch: None,
            version: None,
            force: false,
        })
        .expect("the pair overlay builds from the warm cache and installs");

        let arch = mvm_core::arch::GuestArch::host().to_string();
        let installed = home
            .join("cache/runtime-overlay")
            .join(env!("CARGO_PKG_VERSION"))
            .join(&arch);
        for name in [
            "overlay.ext4",
            "overlay.verity",
            "overlay.roothash",
            "VERSION",
        ] {
            assert!(
                installed.join(name).is_file(),
                "installed overlay must carry {name}"
            );
        }
        let stamp = std::fs::read_to_string(installed.with_extension("pair"))
            .expect("the install records the pair identity")
            .trim()
            .to_string();
        let key = crate::commands::env::builder_vm::derive_pair_key(
            &pair.images,
            &mvm_build::image_source::ImageBuildTarget {
                role: mvm_build::image_source::ImageBuildRole::RuntimeOverlay,
                attr: mvm_build::image_source::FlakeAttr::new("default").unwrap(),
            },
        )
        .unwrap();
        assert_eq!(
            stamp,
            key.digest().as_str(),
            "the stamp is the pair's cache-key digest, so a changed pair reinstalls"
        );

        // The launch path under the same pair must now answer from the
        // install without another build.
        let mut sc = mvm_core::vm_backend::VmStartConfig::default();
        crate::commands::env::builder_vm::with_pair_artifact_source(|pair_source| {
            mvm_client::launch::runtime_source::attach_runtime_overlay_if_cached_version(
                &mut sc,
                "firecracker",
                None,
                pair_source,
            )
        })
        .expect("launch resolves the stamped pair install");
        assert!(sc.runtime_overlay_path.is_some(), "overlay attached");
    }

    /// A pair build keeps exact equality with this CLI's version: an overlay
    /// the selected checkout built at another version is refused, not
    /// installed.
    #[test]
    fn a_pair_overlay_at_another_version_is_refused() {
        let pair = Pair::new();
        let mut env = selector_env(&pair);
        let home = pair.tmp.path().join("home");
        env.isolate_mvm_home(&home);
        std::fs::create_dir_all(&home).unwrap();
        let other = "0.0.1-member";
        assert_ne!(other, env!("CARGO_PKG_VERSION"));
        publish_pair_overlay(&pair, other);

        let err = run_build(BuildArgs {
            source: Source::Auto,
            arch: None,
            version: None,
            force: false,
        })
        .expect_err("a pair overlay at another version must be refused");
        assert!(
            err.to_string().contains("but version"),
            "the refusal must name the version mismatch: {err:#}"
        );
        assert!(
            !home.join("cache/runtime-overlay").join(other).exists(),
            "nothing may be installed under the pair's version"
        );
    }
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
