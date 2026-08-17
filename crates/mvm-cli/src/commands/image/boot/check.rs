//! `mvmctl image boot check` — is the cached image behind the published line?
//!
//! Read-only, and nonzero-on-behind so a script can gate on the exit code
//! rather than parse the output.

use anyhow::{Result, bail};
use serde_json::json;

use super::cache;
use crate::update::{BootImageVersion, fetch_latest_boot_image_tag};

/// Every answer the comparison can give, including the two that are neither
/// "behind" nor "current". Collapsing either of those into one of the other
/// arms is how a fresh checkout ends up reported as out of date.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CheckVerdict {
    /// The release line has published nothing yet. Not a failure.
    NoPublishedLine,
    /// Nothing cached, or nothing cached that records which line it came from.
    NoCachedTag {
        latest: String,
    },
    UpToDate {
        cached: String,
    },
    Behind {
        cached: String,
        latest: String,
    },
    /// Cached tag is newer than anything published — a local build of an
    /// unreleased line. Not behind, so not a failure.
    Ahead {
        cached: String,
        latest: String,
    },
}

impl CheckVerdict {
    fn label(&self) -> &'static str {
        match self {
            CheckVerdict::NoPublishedLine => "no-published-line",
            CheckVerdict::NoCachedTag { .. } => "no-cached-tag",
            CheckVerdict::UpToDate { .. } => "up-to-date",
            CheckVerdict::Behind { .. } => "behind",
            CheckVerdict::Ahead { .. } => "ahead",
        }
    }

    fn message(&self) -> String {
        match self {
            CheckVerdict::NoPublishedLine => format!(
                "No published boot image release yet (no tag matching {}*). \
                 Nothing to compare against.",
                crate::update::BOOT_IMAGE_TAG_PREFIX
            ),
            CheckVerdict::NoCachedTag { latest } => format!(
                "Latest published boot image is {latest}; the cache records no image tag, \
                 so there is nothing to compare. A locally built image records none."
            ),
            CheckVerdict::UpToDate { cached } => {
                format!("Cached boot image {cached} is the latest published.")
            }
            CheckVerdict::Behind { cached, latest } => {
                format!("Cached boot image {cached} is behind {latest}.")
            }
            CheckVerdict::Ahead { cached, latest } => {
                format!("Cached boot image {cached} is newer than the latest published {latest}.")
            }
        }
    }
}

/// Compare a cached tag against the latest published one.
///
/// Pure, so every arm is testable without a releases API.
pub(super) fn verdict(cached: Option<&str>, latest: Option<&str>) -> CheckVerdict {
    let Some(latest) = latest else {
        return CheckVerdict::NoPublishedLine;
    };
    let Some(cached) = cached else {
        return CheckVerdict::NoCachedTag {
            latest: latest.to_string(),
        };
    };
    // An unparseable cached tag cannot be ordered. Reporting it as behind
    // would be a guess; reporting it as current would hide a real update.
    let (Some(cached_v), Some(latest_v)) = (
        BootImageVersion::from_tag(cached),
        BootImageVersion::from_tag(latest),
    ) else {
        return CheckVerdict::NoCachedTag {
            latest: latest.to_string(),
        };
    };
    let (cached, latest) = (cached.to_string(), latest.to_string());
    match cached_v.cmp(&latest_v) {
        std::cmp::Ordering::Less => CheckVerdict::Behind { cached, latest },
        std::cmp::Ordering::Equal => CheckVerdict::UpToDate { cached },
        std::cmp::Ordering::Greater => CheckVerdict::Ahead { cached, latest },
    }
}

/// The tag the cache claims: the highest one any variant records.
pub(super) fn cached_tag() -> Option<String> {
    crate::update::highest_boot_image_tag(
        cache::survey()
            .iter()
            .filter_map(|e| e.image_tag())
            .collect::<Vec<_>>()
            .into_iter(),
    )
}

pub(super) fn run(json_output: bool) -> Result<()> {
    let latest = fetch_latest_boot_image_tag()?;
    let cached = cached_tag();
    let verdict = verdict(cached.as_deref(), latest.as_deref());

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": verdict.label(),
                "cached_tag": cached,
                "latest_tag": latest,
                "message": verdict.message(),
            }))?
        );
    } else {
        // The verdict is the command's whole output; the chatter channel is
        // suppressed by default and would swallow it.
        println!("{}", verdict.message());
    }

    // Only "behind" is actionable, and the exit code is the whole interface for
    // a script. Every other arm — including no published line at all — exits
    // clean so a fresh install does not fail a pipeline.
    if let CheckVerdict::Behind { cached, latest } = &verdict {
        bail!("boot image {cached} is behind {latest}; run `mvmctl image boot update`");
    }
    Ok(())
}
