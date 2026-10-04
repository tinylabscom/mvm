//! `mvmctl image dev ensure` — ensure the writable dev default-tenant image
//! is installed in the local cache: adopt the pinned set's dev members when
//! `MVM_FETCH_UNCHANGED_IMAGES` asks for them (`1`: only when they were built
//! from this tree; `pinned`: whatever they were built from), and pair-build
//! from the selected `mvm-images` checkout otherwise.

use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum DevAction {
    /// Ensure the dev default-tenant image is installed: adopt the pinned
    /// set's dev members when MVM_FETCH_UNCHANGED_IMAGES asks for them,
    /// pair-build from the selected image checkout otherwise
    Ensure,
}

pub(in crate::commands) fn run(action: DevAction) -> Result<()> {
    match action {
        DevAction::Ensure => run_ensure(),
    }
}

/// Ensure the dev default image is installed — fetch the pinned set's dev
/// members when `MVM_FETCH_UNCHANGED_IMAGES` asks for them; otherwise answer
/// from the pair build / cache path `mvmctl run` uses, which pair-builds from
/// the selected checkout or answers a complete cache.
fn run_ensure() -> Result<()> {
    ensure_from(crate::commands::env::builder_vm::selected_local_checkout()?.as_ref())
}

fn ensure_from(checkout: Option<&mvm_build::image_source::LocalImageCheckout>) -> Result<()> {
    use mvm_build::fetch_unchanged::{self as fetch, ArmRequest, FetchMode, PinnedMembers};
    let request = ArmRequest::for_host(PinnedMembers::DevDefaultImage);
    if request.mode != FetchMode::Off {
        // Said at notice level whichever arm runs, so the e2e log records it.
        let arm = fetch::resolve_arm(request)?;
        crate::ui::notice(&arm.report(request));
        if let fetch::Arm::Adopt { set, .. } = arm {
            return adopt_dev_image(&set, request.arch);
        }
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

/// Install the set's dev members as the dev slot and stamp them as fetched
/// under the set's tag. A failure is final: the verified bytes were asked for
/// and refused, which must not silently fall back to a pair build.
fn adopt_dev_image(
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
                "adopting the dev default image of the pinned image set {} failed: {e:#}",
                set.release_tag()
            )
        })?;
    crate::commands::env::builder_vm::report_recorded_boot_tier("Default image", &cache_dir);
    Ok(())
}

#[cfg(test)]
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
