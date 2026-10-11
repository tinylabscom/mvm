//! `mvmctl image pull`: explicit acquisition through the image service.

use std::path::Path;

use anyhow::Result;
use mvm_client::image_admin::{PrepareImageRequest, TransferProgress, prepare_image_with_progress};

use crate::ui;

pub(super) fn run(cache_root: &Path, reference: String, prod: bool) -> Result<()> {
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
    let report = prepare_image_with_progress(
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
    Ok(())
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
