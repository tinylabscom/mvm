//! `mvmctl image pull` — fetch + verify an OCI image into the cache.

use std::path::Path;

use anyhow::{Result, bail};

use crate::ui;

/// What a pull that succeeded established about the image it cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PullVerification {
    /// Content digests (and, under `--prod`, signatures) were checked.
    Verified,
    /// A rootfs directory: there is no digest or signature to check.
    Unverified,
}

pub(super) fn run(cache_root: &Path, reference: String, prod: bool) -> Result<PullVerification> {
    use mvm_client::cli_image::{self as image_cache, ImageSource};
    let source = ImageSource::classify(&reference)?;
    let verification = if matches!(source, ImageSource::RootfsDir(_)) {
        PullVerification::Unverified
    } else {
        PullVerification::Verified
    };
    image_cache::validate_preparation(&reference, prod)?;
    crate::release_guest_runtime::ensure_release_pieces_prepared()?;
    if matches!(source, ImageSource::Registry(_)) {
        crate::commands::env::builder_vm::sweep_orphaned_vm_helpers_on_startup();
    }
    let image = image_cache::pull(
        cache_root,
        &reference,
        prod,
        &super::pull_core::acquisition_hooks(),
    )?;
    let provenance = &image.provenance;
    let auth_source = image.auth_source.as_deref().unwrap_or("local");
    mvm_core::audit_emit!(
        ImageFetch,
        "source=image_pull reference={} digest={} prod={} layers={} trust_policy={} verification_status={} auth_source={}",
        image.reference,
        image.resolved_digest,
        prod,
        provenance.layer_digests.len(),
        provenance.trust_policy,
        provenance.verification_status,
        auth_source
    );
    let verb = if image.pulled { "Pulled" } else { "Prepared" };
    ui::success(&format!(
        "{verb} {} -> {}",
        image.reference, image.resolved_digest
    ));
    ui::info(&format!("Rootfs: {}", image.rootfs_path.display()));
    Ok(verification)
}

/// Run `warm` once for `reference` when `--warm` was passed and the pull both
/// succeeded and verified what it cached. A failed pull is returned as it was;
/// an unverified one is refused, because `--warm` promises a standby of a
/// verified image and a rootfs directory has nothing to verify.
pub(super) fn warm_after_pull(
    pulled: Result<PullVerification>,
    reference: &str,
    warm_requested: bool,
    warm: impl FnOnce(&str) -> Result<()>,
) -> Result<()> {
    let verification = pulled?;
    if !warm_requested {
        return Ok(());
    }
    if verification == PullVerification::Unverified {
        bail!(
            "{reference} was prepared but not warmed: a rootfs directory carries no digest or \
             signature for --warm to verify. Warm it explicitly with \
             `mvmctl pool warm --image {reference}` if that is intended."
        );
    }
    warm(reference)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn counting_warm(calls: &Cell<u32>) -> impl FnOnce(&str) -> Result<()> + '_ {
        move |_| {
            calls.set(calls.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn warm_runs_once_after_a_verified_pull() {
        let calls = Cell::new(0);
        warm_after_pull(
            Ok(PullVerification::Verified),
            "alpine",
            true,
            counting_warm(&calls),
        )
        .unwrap();
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn warm_never_runs_after_a_failed_pull() {
        let calls = Cell::new(0);
        let err = warm_after_pull(
            Err(anyhow::anyhow!("manifest digest mismatch")),
            "alpine",
            true,
            counting_warm(&calls),
        )
        .unwrap_err();
        assert_eq!(calls.get(), 0);
        assert_eq!(err.to_string(), "manifest digest mismatch");
    }

    #[test]
    fn warm_never_runs_after_an_unverified_pull() {
        let calls = Cell::new(0);
        let err = warm_after_pull(
            Ok(PullVerification::Unverified),
            "./rootfs",
            true,
            counting_warm(&calls),
        )
        .unwrap_err();
        assert_eq!(calls.get(), 0);
        assert!(err.to_string().contains("not warmed"), "{err}");
    }

    #[test]
    fn warm_never_runs_without_the_flag() {
        let calls = Cell::new(0);
        warm_after_pull(
            Ok(PullVerification::Verified),
            "alpine",
            false,
            counting_warm(&calls),
        )
        .unwrap();
        assert_eq!(calls.get(), 0);
    }
}
