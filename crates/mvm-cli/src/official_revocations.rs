//! On-demand refresh of the built-in official revocation feed.
//!
//! Fetching adds no authority: the bytes go through the same verifier as
//! `mvmctl pack registry revocations update --official`, which pins the release
//! identity, the issuer, the validity window and the rollback checkpoint.
//! The network is touched only when the cached feed is absent, expired or near
//! expiry, and only from `pull` and the front of `run`, never from launch
//! admission. A failed refresh never widens trust: the caller proceeds on a
//! still-valid cache, and otherwise the revocation check itself refuses.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use mvm_core::registry_pack_revocation::RegistryPackRevocationError;
use mvm_core::registry_pack_revocation_store::RegistryPackRevocationStoreError;
use mvm_core::registry_pack_store::RegistryPackStoreError;

const FEED_BASE: &str =
    "https://github.com/tinylabscom/mvm-packs/releases/download/registry-pack-revocations";
const MAX_ASSET_BYTES: u64 = 1024 * 1024;
/// The feed is published every 12 h with 36 h validity.
const REFRESH_WITHIN_HOURS: i64 = 12;
/// Total budget for both assets, every hop and body included, so an
/// unreachable host cannot stall `pull` or `run` for long.
const REFRESH_DEADLINE: Duration = Duration::from_secs(12);

/// Transport seam; the production fetcher is the bounded downloader. `within`
/// is the time left of the one shared deadline.
pub(crate) trait FeedFetcher {
    fn fetch(&self, url: &str, limit: u64, within: Duration) -> Result<Vec<u8>>;
}

struct BoundedDownloader;

impl FeedFetcher for BoundedDownloader {
    fn fetch(&self, url: &str, limit: u64, within: Duration) -> Result<Vec<u8>> {
        let dir = tempfile::tempdir().context("creating a staging directory")?;
        let file = dir.path().join("asset");
        crate::http::download_file_bounded_within(url, &file, limit, within)?;
        let bytes = std::fs::read(&file).context("reading the downloaded feed asset")?;
        anyhow::ensure!(
            bytes.len() as u64 <= limit,
            "feed asset exceeds its byte budget"
        );
        Ok(bytes)
    }
}

/// Why an update was refused; only a signature mismatch can be a half-replaced pair.
pub(crate) struct UpdateRefused {
    pub(crate) error: anyhow::Error,
    pub(crate) pair_mismatch: bool,
}

impl From<RegistryPackStoreError> for UpdateRefused {
    fn from(error: RegistryPackStoreError) -> Self {
        let pair_mismatch = matches!(
            error,
            RegistryPackStoreError::RevocationStore(
                RegistryPackRevocationStoreError::Verification(
                    RegistryPackRevocationError::SignatureInvalid(_)
                )
            )
        );
        Self {
            error: error.into(),
            pair_mismatch,
        }
    }
}

fn needs_refresh(valid_until: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    valid_until.is_none_or(|end| end - chrono::Duration::hours(REFRESH_WITHIN_HOURS) < now)
}

fn fetch_pair(fetcher: &dyn FeedFetcher, total: Duration) -> Result<(Vec<u8>, Vec<u8>)> {
    let start = Instant::now();
    let get = |name: &str| {
        let within = total
            .checked_sub(start.elapsed())
            .filter(|left| !left.is_zero())
            .context("the feed refresh deadline passed")?;
        fetcher.fetch(&format!("{FEED_BASE}/{name}"), MAX_ASSET_BYTES, within)
    };
    Ok((get("revocations.json")?, get("revocations.sigstore.json")?))
}

fn refresh_with(
    fetcher: &dyn FeedFetcher,
    valid_until: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    total: Duration,
    mut update: impl FnMut(&[u8], &[u8]) -> Result<(), UpdateRefused>,
) -> Result<bool> {
    if !needs_refresh(valid_until, now) {
        return Ok(false);
    }
    // The two assets are replaced separately, so a signature mismatch is the
    // one failure worth a second download. Network errors are not retried.
    for attempt in 0..2 {
        let (document, bundle) = fetch_pair(fetcher, total)?;
        match update(&document, &bundle) {
            Ok(()) => return Ok(true),
            Err(refused) if refused.pair_mismatch && attempt == 0 => {}
            Err(refused) => return Err(refused.error),
        }
    }
    unreachable!("the second attempt returns")
}

fn ensure_with(
    fetcher: &dyn FeedFetcher,
    builtin_policy: bool,
    valid_until: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    total: Duration,
    update: impl FnMut(&[u8], &[u8]) -> Result<(), UpdateRefused>,
) -> Result<bool> {
    // An operator publisher policy replaces built-in trust: no network, no cache.
    if !builtin_policy {
        return Ok(false);
    }
    refresh_with(fetcher, valid_until, now, total, update)
}

/// Refresh the official feed when it is due. A failure is reported and
/// otherwise ignored: the revocation check that follows fails closed on its own.
pub(crate) fn ensure_official_feed_fresh() {
    let now = Utc::now();
    let valid_until =
        mvm_core::registry_pack_store::official_registry_pack_revocation_valid_until();
    let builtin_policy = mvm_core::registry_pack_store::load_publisher_policy_or_official_default(
        &mvm_core::config::registry_pack_publisher_policy_path(),
    )
    .is_ok_and(|loaded| loaded.is_official_default());
    let result = ensure_with(
        &BoundedDownloader,
        builtin_policy,
        valid_until,
        now,
        REFRESH_DEADLINE,
        |document, bundle| {
            mvm_core::registry_pack_store::update_official_registry_pack_revocations(
                document, bundle,
            )
            .map(|_| ())
            .map_err(UpdateRefused::from)
        },
    );
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
    use std::cell::{Cell, RefCell};

    const TOTAL: Duration = Duration::from_millis(200);

    struct Fake {
        fail: bool,
        stall: Duration,
        calls: RefCell<Vec<(String, Duration)>>,
    }

    impl FeedFetcher for Fake {
        fn fetch(&self, url: &str, _: u64, within: Duration) -> Result<Vec<u8>> {
            self.calls.borrow_mut().push((url.to_string(), within));
            std::thread::sleep(self.stall);
            anyhow::ensure!(!self.fail, "offline");
            Ok(url.as_bytes().to_vec())
        }
    }

    fn fake(fail: bool) -> Fake {
        Fake {
            fail,
            stall: Duration::ZERO,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn at(hours: i64) -> Option<DateTime<Utc>> {
        Some(Utc::now() + chrono::Duration::hours(hours))
    }

    fn ok(_: &[u8], _: &[u8]) -> Result<(), UpdateRefused> {
        Ok(())
    }

    fn refused(pair_mismatch: bool) -> UpdateRefused {
        UpdateRefused {
            error: anyhow::anyhow!("refused"),
            pair_mismatch,
        }
    }

    #[test]
    fn a_feed_with_plenty_of_validity_left_touches_no_network() {
        for hours in [13, 30] {
            let fetcher = fake(false);
            assert!(!refresh_with(&fetcher, at(hours), Utc::now(), TOTAL, ok).unwrap());
            assert!(fetcher.calls.borrow().is_empty());
        }
    }

    #[test]
    fn absent_expired_and_near_expiry_caches_refresh() {
        for valid_until in [None, at(-1), at(11)] {
            let fetcher = fake(false);
            let updated = Cell::new(0);
            assert!(
                refresh_with(
                    &fetcher,
                    valid_until,
                    Utc::now(),
                    TOTAL,
                    |document, bundle| {
                        assert!(String::from_utf8_lossy(document).ends_with("/revocations.json"));
                        assert!(
                            String::from_utf8_lossy(bundle).ends_with("/revocations.sigstore.json")
                        );
                        updated.set(updated.get() + 1);
                        Ok(())
                    }
                )
                .unwrap()
            );
            assert_eq!(updated.get(), 1);
        }
    }

    #[test]
    fn a_network_error_is_not_retried() {
        let fetcher = fake(true);
        assert!(refresh_with(&fetcher, None, Utc::now(), TOTAL, ok).is_err());
        assert_eq!(fetcher.calls.borrow().len(), 1);
    }

    #[test]
    fn only_a_pair_mismatch_is_retried_and_only_once() {
        let attempts = Cell::new(0);
        assert!(
            refresh_with(&fake(false), None, Utc::now(), TOTAL, |_, _| {
                attempts.set(attempts.get() + 1);
                if attempts.get() == 1 {
                    Err(refused(true))
                } else {
                    Ok(())
                }
            })
            .unwrap()
        );
        assert_eq!(attempts.get(), 2);
        let attempts = Cell::new(0);
        assert!(
            refresh_with(&fake(false), None, Utc::now(), TOTAL, |_, _| {
                attempts.set(attempts.get() + 1);
                Err(refused(true))
            })
            .is_err()
        );
        assert_eq!(attempts.get(), 2);
        // Any other refusal (wrong identity, rollback, expiry) is final.
        let attempts = Cell::new(0);
        let error = refresh_with(&fake(false), None, Utc::now(), TOTAL, |_, _| {
            attempts.set(attempts.get() + 1);
            Err(refused(false))
        })
        .unwrap_err();
        assert_eq!(attempts.get(), 1);
        assert!(error.to_string().contains("refused"));
    }

    #[test]
    fn a_slow_host_is_cut_off_by_the_one_shared_deadline() {
        // The first asset eats the whole budget, so the second is never requested
        // and the fetcher is handed only the time that remains.
        let fetcher = Fake {
            fail: false,
            stall: Duration::from_millis(250),
            calls: RefCell::new(Vec::new()),
        };
        let started = Instant::now();
        let error = refresh_with(&fetcher, None, Utc::now(), TOTAL, ok).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(error.to_string().contains("deadline"));
        let calls = fetcher.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].1 <= TOTAL);
    }

    #[test]
    fn an_operator_publisher_policy_makes_no_network_attempt() {
        let fetcher = fake(false);
        assert!(!ensure_with(&fetcher, false, None, Utc::now(), TOTAL, ok).unwrap());
        assert!(fetcher.calls.borrow().is_empty());
        assert!(ensure_with(&fetcher, true, None, Utc::now(), TOTAL, ok).unwrap());
        assert_eq!(fetcher.calls.borrow().len(), 2);
    }

    #[test]
    fn an_older_feed_is_refused_without_a_retry_and_the_error_reaches_the_caller() {
        use mvm_core::registry_pack_revocation::RegistryPackRevocationError as E;
        let attempts = Cell::new(0);
        let error = ensure_with(&fake(false), true, at(-1), Utc::now(), TOTAL, |_, _| {
            attempts.set(attempts.get() + 1);
            Err(UpdateRefused::from(
                RegistryPackStoreError::RevocationStore(
                    RegistryPackRevocationStoreError::Verification(E::Rollback {
                        previous: 9,
                        received: 3,
                    }),
                ),
            ))
        })
        .unwrap_err();
        assert_eq!(attempts.get(), 1);
        assert!(format!("{error:#}").contains("rolled back"), "{error:#}");
    }

    #[test]
    fn a_signature_failure_is_classified_as_a_pair_mismatch() {
        use mvm_core::registry_pack_revocation::RegistryPackRevocationError as E;
        let refused = UpdateRefused::from(RegistryPackStoreError::RevocationStore(
            RegistryPackRevocationStoreError::Verification(E::SignatureInvalid("x".into())),
        ));
        assert!(refused.pair_mismatch);
    }
}
