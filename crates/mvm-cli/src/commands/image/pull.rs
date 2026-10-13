//! `mvmctl image pull`: explicit acquisition through the image service.

use std::path::Path;

use anyhow::{Result, bail};
use mvm_client::image_admin::{
    PreparationVerification, PrepareImageRequest, TransferProgress, prepare_image,
};

use crate::ui;

pub(super) fn run(
    cache_root: &Path,
    reference: String,
    prod: bool,
) -> Result<PreparationVerification> {
    let phase = ui::activity::start(format!("Preparing {reference}"));
    let progress = TransferProgress::default();
    let tracked = progress.clone();
    phase.track(move || {
        let (received, total) = tracked.snapshot();
        if total == 0 {
            "verifying and preparing image artifacts".to_owned()
        } else {
            pull_progress_detail(received, total)
        }
    });
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let report = prepare_image(
        &PrepareImageRequest {
            cache_root: cache_root.to_owned(),
            reference,
            prod,
        },
        Some(&mut input),
        &progress,
    )?;
    phase.finish();
    ui::success(&format!(
        "{} {} -> {}",
        if report.local { "Prepared" } else { "Pulled" },
        report.reference,
        report.resolved_digest
    ));
    ui::info(&format!("Rootfs: {}", report.rootfs_path.display()));
    Ok(report.verification)
}

/// Run `warm` once for `reference` when `--warm` was passed and the pull both
/// succeeded and verified what it cached. A failed pull is returned as it was;
/// an unverified one is refused, because `--warm` promises a standby of a
/// verified image and a rootfs directory has nothing to verify.
pub(super) fn warm_after_pull(
    pulled: Result<PreparationVerification>,
    reference: &str,
    warm_requested: bool,
    warm: impl FnOnce(&str) -> Result<()>,
) -> Result<()> {
    let verification = pulled?;
    if !warm_requested {
        return Ok(());
    }
    if verification == PreparationVerification::Unverified {
        bail!(
            "{reference} was prepared but not warmed: a rootfs directory carries no digest or \
             signature for --warm to verify. Warm it explicitly with \
             `mvmctl pool warm --image {reference}` if that is intended."
        );
    }
    warm(reference)
}

/// `12.3 MiB of 45.6 MiB (27%)` — the pull line's detail while layers stream.
fn pull_progress_detail(received: u64, total: u64) -> String {
    use mvm_core::domain::pool::format_bytes;
    if total == 0 {
        return format_bytes(received);
    }
    let received = received.min(total);
    let percent = received.saturating_mul(100) / total;
    format!(
        "{} of {} ({percent}%)",
        format_bytes(received),
        format_bytes(total)
    )
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
            Ok(PreparationVerification::Verified),
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
            Ok(PreparationVerification::Unverified),
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
            Ok(PreparationVerification::Verified),
            "alpine",
            false,
            counting_warm(&calls),
        )
        .unwrap();
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn pull_progress_reads_as_bytes_of_total_with_a_percentage() {
        assert_eq!(
            pull_progress_detail(12 * 1024 * 1024, 48 * 1024 * 1024),
            "12.0 MiB of 48.0 MiB (25%)"
        );
        // A retry or a cache-hit catch-up can overshoot; never show >100%.
        assert_eq!(
            pull_progress_detail(50 * 1024 * 1024, 48 * 1024 * 1024),
            "48.0 MiB of 48.0 MiB (100%)"
        );
        // A manifest that declared no sizes still shows what arrived.
        assert_eq!(pull_progress_detail(2048, 0), "2.0 KiB");
    }
}
