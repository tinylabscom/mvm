//! `mvmctl image dev ensure` — ensure the writable dev default-tenant image
//! is installed in the local cache: pair-built from the selected `mvm-images`
//! checkout, or, with none selected, installed from the dev members of the
//! image set this build pins. The dev image is a Linux-layer member, so it is
//! fetched like any other; nothing is adopted in place of a build on the
//! strength of a source fingerprint.

use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum DevAction {
    /// Ensure the dev default-tenant image is installed: pair-build from the
    /// selected image checkout, or install the pinned image set's dev members
    Ensure,
}

pub(in crate::commands) fn run(action: DevAction) -> Result<()> {
    match action {
        DevAction::Ensure => run_ensure(),
    }
}

fn run_ensure() -> Result<()> {
    match crate::commands::env::builder_vm::selected_local_checkout()? {
        Some(checkout) => ensure_from_checkout(&checkout),
        None => {
            let set = crate::commands::env::artifact_verify::acquire_image_set()?;
            install_dev_image(&set, mvm_core::arch::GuestArch::host())
        }
    }
}

/// Answer from the pair build / cache path `mvmctl run` uses.
fn ensure_from_checkout(checkout: &mvm_build::image_source::LocalImageCheckout) -> Result<()> {
    let (_, rootfs) = crate::commands::env::builder_vm::default_microvm::dev_image_from(
        Some(checkout.clone()),
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

/// Install the set's dev members as the dev slot and stamp them as fetched
/// under the set's tag.
fn install_dev_image(
    set: &mvm_build::published_image_set::PublishedImageSet,
    arch: mvm_core::arch::GuestArch,
) -> Result<()> {
    let cache_dir =
        crate::commands::env::builder_vm::default_microvm::dev_default_image_cache_dir();
    set.fetch_dev_workload(arch, &cache_dir)
        .and_then(|()| {
            super::boot::cache::stamp_provenance(
                &cache_dir,
                &super::boot::cache::AcquiredProvenance::fetched(&set.release_tag().to_string()),
            )
        })
        .map_err(|e| {
            anyhow::anyhow!(
                "installing the dev default image of the pinned image set {} failed: {e:#}",
                set.release_tag()
            )
        })?;
    crate::ui::notice(&format!(
        "Default image: dev members of the pinned image set {}",
        set.release_tag()
    ));
    crate::commands::env::builder_vm::report_recorded_boot_tier("Default image", &cache_dir);
    Ok(())
}
