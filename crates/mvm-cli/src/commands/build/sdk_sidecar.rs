//! `mvmctl build sdk-sidecar build` — explicitly build and cache the
//! guest-facing host-services sidecar images from the selected `mvm-images`
//! checkout.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

#[cfg(feature = "builder-vm")]
use crate::ui;
#[cfg(feature = "builder-vm")]
use mvm_contract::guest_libc::GuestLibc;
#[cfg(feature = "builder-vm")]
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
    /// Build both libc variants from the selected mvm-images checkout and
    /// populate the version-matched cache.
    Build,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.cmd {
        Cmd::Build => run_build(),
    }
}

/// Build both libc variants from the pair's `runtime-overlay` sidecar targets
/// and install them into the version-matched cache, stamped with the pair
/// identity so launches under this pair trust them.
#[cfg(feature = "builder-vm")]
fn build_pair_sidecars(checkout: &mvm_build::image_source::LocalImageCheckout) -> Result<()> {
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = GuestArch::host();
    for (libc, attr) in [
        (GuestLibc::Glibc, "sdk-sidecar-image"),
        (GuestLibc::Musl, "sdk-sidecar-image-musl"),
    ] {
        let target = mvm_build::image_source::ImageBuildTarget {
            role: mvm_build::image_source::ImageBuildRole::RuntimeOverlay,
            attr: mvm_build::image_source::FlakeAttr::new(attr)
                .expect("a literal attribute is valid"),
        };
        let build = crate::commands::env::builder_vm::ensure_pair_built(checkout, target)?;
        install_pair_sidecar(&build, &cache_root, version, arch, libc)?;
        ui::success(&format!(
            "SDK sidecar ({libc}) built from the selected image checkout and cached."
        ));
    }
    Ok(())
}

/// Install one libc variant from a pair-built sidecar entry, stamped with the
/// pair identity. The entry's files carry the producer's manifest names, so
/// this goes through the same staging install the launch path uses rather
/// than handing the entry directory to the fixed-layout installer.
#[cfg(feature = "builder-vm")]
fn install_pair_sidecar(
    build: &mvm_build::image_source::PairBuild,
    cache_root: &std::path::Path,
    version: &str,
    arch: GuestArch,
    libc: GuestLibc,
) -> Result<()> {
    let fingerprint = build.key.digest().as_str().to_string();
    mvm_client::launch::pair_stage::install_pair_sidecar(
        &build.entry,
        &fingerprint,
        cache_root,
        version,
        arch,
        libc,
    )?;
    Ok(())
}

fn run_build() -> Result<()> {
    #[cfg(feature = "builder-vm")]
    return build_from(crate::commands::env::builder_vm::selected_local_checkout()?.as_ref());

    #[cfg(not(feature = "builder-vm"))]
    {
        if mvm_build::image_source::configured_images_dir().is_some() {
            anyhow::bail!(
                "{} names an image checkout, but building the SDK sidecar from it requires \
                 the `builder-vm` feature; rebuild the binary with that feature enabled",
                mvm_build::image_source::MVM_IMAGES_DIR_ENV,
            );
        }
        Err(sidecar_needs_a_checkout())
    }
}

/// Build both libc variants from the selected checkout — or, when the caller
/// set `MVM_FETCH_UNCHANGED_IMAGES`, adopt the pinned set's verified sidecar
/// members instead: under `1` only when they were built from exactly this
/// tree's sources, under `pinned` whatever they were built from. Without
/// either there is nothing to build from: the sidecars are image-set members,
/// and image construction lives in `mvm-images`.
#[cfg(feature = "builder-vm")]
fn build_from(checkout: Option<&mvm_build::image_source::LocalImageCheckout>) -> Result<()> {
    use mvm_build::fetch_unchanged::{self as fetch, ArmRequest, FetchMode, PinnedMembers};
    let request = ArmRequest::for_host(PinnedMembers::SdkSidecars);
    if request.mode != FetchMode::Off {
        // Said at notice level whichever arm runs: the documented-surface e2e
        // records which one did, and an unannounced fall-through is
        // indistinguishable from the knob doing nothing.
        let arm = fetch::resolve_arm(request)?;
        ui::notice(&arm.report(request));
        if let fetch::Arm::Adopt { set, .. } = arm {
            return adopt_sidecars(&set, request.arch);
        }
    }
    match checkout {
        Some(checkout) => build_pair_sidecars(checkout),
        None => Err(sidecar_needs_a_checkout()),
    }
}

/// Install both libc variants from the verified set. A failure is final: the
/// verified bytes were asked for and refused, which must not silently fall
/// back to a local build.
#[cfg(feature = "builder-vm")]
fn adopt_sidecars(
    set: &mvm_build::published_image_set::PublishedImageSet,
    arch: GuestArch,
) -> Result<()> {
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    mvm_build::fetch_unchanged::fetch_sidecars_from_set(set, arch, &cache_root).map_err(|e| {
        anyhow::anyhow!(
            "adopting the SDK sidecars of the pinned image set {} failed: {e}",
            set.release_tag()
        )
    })?;
    ui::success(&format!(
        "SDK sidecars (glibc, musl) installed from the pinned image set {}; no build run.",
        set.release_tag()
    ));
    Ok(())
}

fn sidecar_needs_a_checkout() -> anyhow::Error {
    mvm_build::image_source::ImageConstructionRefused::new("the SDK sidecar").into()
}

#[cfg(all(test, feature = "builder-vm"))]
mod tests {
    use super::*;

    #[test]
    fn a_sidecar_build_without_an_image_checkout_is_refused() {
        let err = build_from(None).expect_err("nothing can build the sidecar");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("the SDK sidecar is built from an mvm-images checkout"),
            "{rendered}"
        );
        assert!(
            rendered.contains("image construction lives in mvm-images"),
            "{rendered}"
        );
    }

    /// A pair-built sidecar entry names its files the way the image
    /// repository's manifest emitter does (`sdk-sidecar-<libc>-<arch>-sdk.ext4`
    /// and so on), not by the canonical names the sidecar installer reads. The
    /// explicit `build sdk-sidecar build` verb must install from such an entry
    /// for both libc variants, the same as the launch path does.
    #[test]
    fn a_pair_built_sidecar_entry_installs_both_libc_variants() {
        use crate::commands::env::builder_vm::test_pair::{Pair, TestArtifact};
        use mvm_build::image_source::{ImageBuildRole, PairBuild};
        use mvm_core::image_set::ImageSetRole;
        use mvm_core::packs::Sha256Hex;
        use mvm_core::util::test_env::TestEnv;

        let mut env = TestEnv::new();
        let pair = Pair::new();
        let home = pair.tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        env.set("MVM_HOME", &home);
        let version = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());

        for (libc, attr) in [
            (GuestLibc::Glibc, "sdk-sidecar-image"),
            (GuestLibc::Musl, "sdk-sidecar-image-musl"),
        ] {
            let image = sidecar_ext4_bytes(libc);
            let version_file = format!("{version}\n");
            let checksums = format!(
                "{}  sdk.ext4\n{}  VERSION\n",
                Sha256Hex::from_bytes(&image).as_str(),
                Sha256Hex::from_bytes(version_file.as_bytes()).as_str(),
            );
            let entry = pair.publish(
                ImageBuildRole::RuntimeOverlay,
                attr,
                &[(
                    ImageSetRole::SdkSidecar(libc),
                    None,
                    vec![
                        TestArtifact {
                            name: "sdk.ext4",
                            bytes: image,
                            format: "ext4",
                        },
                        TestArtifact {
                            name: "VERSION",
                            bytes: version_file.into_bytes(),
                            format: "text",
                        },
                        TestArtifact {
                            name: "checksums-sha256.txt",
                            bytes: checksums.into_bytes(),
                            format: "text",
                        },
                    ],
                    &["virtio_blk"],
                )],
            );
            let build = PairBuild {
                key: entry.key.clone(),
                entry,
                built: true,
            };

            install_pair_sidecar(&build, &cache_root, version, arch, libc)
                .unwrap_or_else(|error| panic!("installing the {libc} sidecar: {error:#}"));

            let resolved =
                mvm_fs::sdk_sidecar::SdkSidecarResolver::new(cache_root.clone(), version.into())
                    .resolve(&arch.to_string(), libc)
                    .unwrap_or_else(|error| panic!("the {libc} sidecar resolves: {error:#}"));
            assert_eq!(resolved.version, version);
        }
    }

    /// A minimal sidecar ext4 whose cdylib names `libc`, the one property the
    /// resolver proves about the payload.
    fn sidecar_ext4_bytes(libc: GuestLibc) -> Vec<u8> {
        use mvm_fs::ext4::{Node, Owner};
        let nodes = vec![
            Node::Dir {
                path: "/lib".into(),
                mode: 0o555,
                xattrs: Vec::new(),
                owner: Owner::ROOT,
            },
            Node::File {
                path: "/lib/libmvm_host_services.so".into(),
                mode: 0o555,
                data: mvm_fs::elf::test_fixture::shared_object(&[
                    "libgcc_s.so.1",
                    libc.libc_soname().expect("a fixture names a real libc"),
                ]),
                xattrs: Vec::new(),
                owner: Owner::ROOT,
            },
        ];
        mvm_fs::ext4::build_image(nodes, &Default::default()).expect("build sidecar ext4 fixture")
    }
}
