//! On-demand refresh of the built-in official revocation feed.
//!
//! Fetching adds no authority: the bytes go through the same verifier as
//! `mvmctl pack registry revocations update --official`, which pins the release
//! identity, the issuer, the validity window and the rollback checkpoint.
//! The network is touched only when the cached feed is absent, expired or near
//! expiry, and only from `pull` and the front of `run`, never from launch
//! admission. A failed refresh never widens trust: the caller proceeds on a
//! still-valid cache, and otherwise the revocation check itself refuses.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};

const FEED_BASE: &str =
    "https://github.com/tinylabscom/mvm-packs/releases/download/registry-pack-revocations";
const MAX_ASSET_BYTES: u64 = 1024 * 1024;
/// The feed is published every 12 h with 36 h validity.
const REFRESH_WITHIN_HOURS: i64 = 12;

/// Transport seam; the production fetcher is the bounded downloader.
pub(crate) trait FeedFetcher {
    fn fetch(&self, url: &str, limit: u64) -> Result<Vec<u8>>;
}

struct BoundedDownloader;

impl FeedFetcher for BoundedDownloader {
    fn fetch(&self, url: &str, limit: u64) -> Result<Vec<u8>> {
        let dir = tempfile::tempdir().context("creating a staging directory")?;
        let file = dir.path().join("asset");
        crate::http::download_file_bounded(url, &file, limit)?;
        let bytes = std::fs::read(&file).context("reading the downloaded feed asset")?;
        anyhow::ensure!(
            bytes.len() as u64 <= limit,
            "feed asset exceeds its byte budget"
        );
        Ok(bytes)
    }
}

fn needs_refresh(valid_until: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    valid_until.is_none_or(|end| end - now < Duration::hours(REFRESH_WITHIN_HOURS))
}

fn refresh_with(
    fetcher: &dyn FeedFetcher,
    valid_until: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    mut update: impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<bool> {
    if !needs_refresh(valid_until, now) {
        return Ok(false);
    }
    // The two assets are replaced separately, so a mismatched pair is retried once.
    let mut attempt = || -> Result<()> {
        let document = fetcher.fetch(&format!("{FEED_BASE}/revocations.json"), MAX_ASSET_BYTES)?;
        let bundle = fetcher.fetch(
            &format!("{FEED_BASE}/revocations.sigstore.json"),
            MAX_ASSET_BYTES,
        )?;
        update(&document, &bundle)
    };
    attempt().or_else(|_| attempt()).map(|()| true)
}

/// Refresh the official feed when it is due. A failure is reported and
/// otherwise ignored: the revocation check that follows fails closed on its own.
pub(crate) fn ensure_official_feed_fresh() {
    let now = Utc::now();
    let valid_until =
        mvm_core::registry_pack_store::official_registry_pack_revocation_valid_until();
    let result = refresh_with(&BoundedDownloader, valid_until, now, |document, bundle| {
        mvm_core::registry_pack_store::update_official_registry_pack_revocations(document, bundle)
            .map(|_| ())
            .map_err(Into::into)
    });
    if let Err(error) = result {
        let note = if valid_until.is_some_and(|end| end > now) {
            "continuing on the cached feed"
        } else {
            "import one with `mvmctl pack registry revocations update --official --document FILE --bundle FILE`"
        };
        crate::ui::warn(&format!(
            "could not refresh the official revocation feed ({error:#}); {note}"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Fake {
        fail: bool,
        calls: RefCell<Vec<String>>,
    }

    impl FeedFetcher for Fake {
        fn fetch(&self, url: &str, _: u64) -> Result<Vec<u8>> {
            self.calls.borrow_mut().push(url.to_string());
            anyhow::ensure!(!self.fail, "offline");
            Ok(url.as_bytes().to_vec())
        }
    }

    fn fake(fail: bool) -> Fake {
        Fake {
            fail,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn at(hours: i64) -> Option<DateTime<Utc>> {
        Some(Utc::now() + Duration::hours(hours))
    }

    #[test]
    fn a_feed_with_plenty_of_validity_left_touches_no_network() {
        for hours in [13, 30] {
            let fetcher = fake(false);
            assert!(
                !refresh_with(&fetcher, at(hours), Utc::now(), |_, _| panic!("no update")).unwrap()
            );
            assert!(fetcher.calls.borrow().is_empty());
        }
    }

    #[test]
    fn absent_expired_and_near_expiry_caches_refresh() {
        for valid_until in [None, at(-1), at(11)] {
            let fetcher = fake(false);
            let mut updated = 0;
            assert!(
                refresh_with(&fetcher, valid_until, Utc::now(), |document, bundle| {
                    assert!(String::from_utf8_lossy(document).ends_with("/revocations.json"));
                    assert!(
                        String::from_utf8_lossy(bundle).ends_with("/revocations.sigstore.json")
                    );
                    updated += 1;
                    Ok(())
                })
                .unwrap()
            );
            assert_eq!(updated, 1);
        }
    }

    #[test]
    fn a_failed_fetch_is_an_error_for_the_caller_to_downgrade() {
        assert!(refresh_with(&fake(true), None, Utc::now(), |_, _| Ok(())).is_err());
    }

    #[test]
    fn a_mismatched_pair_is_retried_once_and_a_bad_feed_is_refused() {
        let mut attempts = 0;
        assert!(
            refresh_with(&fake(false), None, Utc::now(), |_, _| {
                attempts += 1;
                anyhow::ensure!(attempts > 1, "signature mismatch");
                Ok(())
            })
            .unwrap()
        );
        let error = refresh_with(&fake(false), None, Utc::now(), |_, _| {
            anyhow::bail!("wrong identity")
        })
        .unwrap_err();
        assert!(error.to_string().contains("wrong identity"));
    }
}
