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
        let fingerprint = build.key.digest().as_str().to_string();
        mvm_build::sdk_sidecar::install_source_built_sidecar(
            &build.entry.dir,
            &cache_root,
            version,
            arch,
            libc,
            &fingerprint,
        )?;
        ui::success(&format!(
            "SDK sidecar ({libc}) built from the selected image checkout and cached."
        ));
    }
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

/// Build both libc variants from the selected checkout. Without one there is
/// nothing to build from: the sidecars are image-set members, and image
/// construction lives in `mvm-images`.
#[cfg(feature = "builder-vm")]
fn build_from(checkout: Option<&mvm_build::image_source::LocalImageCheckout>) -> Result<()> {
    match checkout {
        Some(checkout) => build_pair_sidecars(checkout),
        None => Err(sidecar_needs_a_checkout()),
    }
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
}
