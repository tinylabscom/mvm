//! `mvmctl image dev ensure` — ensure the writable dev default-tenant image
//! is installed in the local cache, adopting the pinned set's dev members
//! when they were built from this tree (fetch-when-unchanged), and
//! pair-building from the selected `mvm-images` checkout otherwise.

use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum DevAction {
    /// Ensure the dev default-tenant image is installed: adopt the pinned
    /// set's dev members when fetch-when-unchanged matches this tree,
    /// pair-build from the selected image checkout otherwise
    Ensure,
}

pub(in crate::commands) fn run(action: DevAction) -> Result<()> {
    match action {
        DevAction::Ensure => run_ensure(),
    }
}

/// Ensure the dev default image is installed — fetch the pinned set's dev
/// members when the caller opted into fetch-when-unchanged and the set was
/// built from exactly this tree's sources; otherwise answer from the pair
/// build / cache path `mvmctl run` uses, which pair-builds from the selected
/// checkout or answers a complete cache.
#[cfg(feature = "builder-vm")]
fn run_ensure() -> Result<()> {
    ensure_from(crate::commands::env::builder_vm::selected_local_checkout()?.as_ref())
}

#[cfg(not(feature = "builder-vm"))]
fn run_ensure() -> Result<()> {
    if mvm_build::image_source::configured_images_dir().is_some() {
        anyhow::bail!(
            "{} names an image checkout, but building the dev default image from it requires \
             the `builder-vm` feature; rebuild the binary with that feature enabled",
            mvm_build::image_source::MVM_IMAGES_DIR_ENV,
        );
    }
    anyhow::bail!(
        "ensuring the dev default image requires the `builder-vm` feature; use a release binary"
    )
}

#[cfg(feature = "builder-vm")]
fn ensure_from(checkout: Option<&mvm_build::image_source::LocalImageCheckout>) -> Result<()> {
    if mvm_build::fetch_unchanged::fetch_unchanged_enabled()
        && let Some(result) = try_fetch_unchanged_dev()
    {
        return result;
    }
    let (_, rootfs) = crate::commands::env::builder_vm::default_microvm::dev_image_from(
        checkout.cloned(),
        &crate::commands::env::builder_vm::default_microvm::dev_default_image_cache_dir()
            .display()
            .to_string(),
    )?;
    crate::commands::env::builder_vm::report_recorded_boot_tier(
        "Default image",
        std::path::Path::new(&rootfs),
    );
    Ok(())
}

/// The fetch-when-unchanged arm for `image dev ensure`. `None` means "use the
/// local path instead" — the knob is off, there is no source workspace to
/// fingerprint, the set cannot be acquired, or the set's dev members were
/// built from different sources (or predate them). A fetch failure is
/// `Some(Err(..))`: the verified bytes were asked for and refused, which must
/// not silently fall back to a pair build.
#[cfg(feature = "builder-vm")]
fn try_fetch_unchanged_dev() -> Option<Result<()>> {
    use mvm_build::fetch_unchanged as fetch;
    let workspace = mvm_build::guest_agent_build::detect_source_workspace()?;
    let fingerprint = fetch::tree_sdk_fingerprint(&workspace)
        .map_err(|e| anyhow::anyhow!("fingerprint the tree's cdylib sources: {e}"))
        .ok()?;
    let set = mvm_build::published_image_set::PublishedImageSet::acquire().ok()?;
    let arch = mvm_core::arch::GuestArch::host();
    if !fetch::set_dev_members_match_tree(&set, arch, &fingerprint) {
        crate::ui::info(
            "fetch-when-unchanged: the pinned set's dev default image was built from              different sources; pair-building",
        );
        return None;
    }
    let cache_dir =
        crate::commands::env::builder_vm::default_microvm::dev_default_image_cache_dir();
    Some(
        set.fetch_dev_workload(arch, &cache_dir)
            .and_then(|()| {
                super::boot::cache::stamp_provenance(
                    &cache_dir,
                    &super::boot::cache::AcquiredProvenance::fetched(
                        &set.release_tag().to_string(),
                    ),
                )
            })
            .map(|()| {
                crate::commands::env::builder_vm::report_recorded_boot_tier(
                    "Default image",
                    &cache_dir,
                );
                crate::ui::info(
                    "fetch-when-unchanged: adopted the pinned set's dev default image                (source fingerprint matched; no build run)",
                );
            })
            .map_err(|e| {
                anyhow::anyhow!(
                    "fetch-when-unchanged: adopting the pinned set's dev default image failed: {e}"
                )
            }),
    )
}

#[cfg(all(test, feature = "builder-vm"))]
mod tests {
    use super::*;

    /// With the knob off (the default) and no checkout there is nothing to
    /// build the dev image from: the refusal names the dev default image and
    /// points at mvm-images, it does not surface a missing-flake mystery.
    /// The home is a bare temporary one so a warm cache on the machine
    /// running the test cannot answer in place of the refusal.
    #[test]
    fn dev_ensure_without_a_checkout_is_refused() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("a bare temporary mvm home");
        env.set("MVM_HOME", home.path());

        let err = ensure_from(None).expect_err("nothing can build the dev image");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("the dev default image is built from an mvm-images checkout"),
            "{rendered}"
        );
        assert!(
            rendered.contains("image construction lives in mvm-images"),
            "{rendered}"
        );
    }
}
