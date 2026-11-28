//! Plan-validity checks: time window + nonce de-duplication.
//!
//! Without these checks an old signed plan
//! is replayable indefinitely. The supervisor calls `check_window`
//! at admission and inserts the plan's `nonce` into a `NonceStore`
//! keyed by the signing-key id; the store self-prunes nonces past
//! their `valid_until`.
//!
//! Both checks are deliberately separate from the cryptographic
//! verify in `signing::verify_plan` — the envelope check answers
//! "is this signature valid for this plan", the validity checks
//! answer "should we accept this otherwise-valid plan now".

use std::collections::HashMap;

use mvm_contract::timestamp::{ParseTimestampError, UtcTimestamp};
use thiserror::Error;

use crate::plan::execution_plan::ExecutionPlan;
use crate::plan::types::Nonce;

pub use mvm_contract::plan::validity::FreshnessClaims;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlanValidityError {
    #[error("plan not yet valid (valid_from={valid_from}, now={now})")]
    NotYetValid {
        valid_from: UtcTimestamp,
        now: UtcTimestamp,
    },
    #[error("plan expired (valid_until={valid_until}, now={now})")]
    Expired {
        valid_until: UtcTimestamp,
        now: UtcTimestamp,
    },
    #[error("plan validity window inverted (valid_from={valid_from} >= valid_until={valid_until})")]
    InvertedWindow {
        valid_from: UtcTimestamp,
        valid_until: UtcTimestamp,
    },
    #[error("plan nonce already seen for signer '{signer}'")]
    NonceReplay { signer: String },
    #[error("freshness block missing required field(s)")]
    MissingFreshness,
    #[error("timestamp outside the representable years 0000..=9999")]
    TimestampOutOfRange,
}

impl From<ParseTimestampError> for PlanValidityError {
    fn from(_: ParseTimestampError) -> Self {
        Self::TimestampOutOfRange
    }
}

/// The freshness inputs the window + nonce checks need, decoupled
/// from `ExecutionPlan` so any signed payload — a plan, a signed
/// reconcile request — reuses one replay ledger instead of forking
/// its own.
pub trait Freshness {
    fn nonce(&self) -> &Nonce;
    fn valid_from(&self) -> Result<UtcTimestamp, PlanValidityError>;
    fn valid_until(&self) -> Result<UtcTimestamp, PlanValidityError>;
}

impl Freshness for ExecutionPlan {
    fn nonce(&self) -> &Nonce {
        &self.nonce
    }
    fn valid_from(&self) -> Result<UtcTimestamp, PlanValidityError> {
        Ok(self.valid_from)
    }
    fn valid_until(&self) -> Result<UtcTimestamp, PlanValidityError> {
        Ok(self.valid_until)
    }
}

/// Fail-closed conversion of a wire [`FreshnessClaims`] to a verifiable
/// value: absent freshness is never valid. A free function, not an
/// inherent method — `FreshnessClaims` lives in `mvm-contract`, and
/// `mvm-core` may not add inherent methods to a foreign type.
pub fn checked(claims: &FreshnessClaims) -> Result<CheckedFreshness, PlanValidityError> {
    match (claims.valid_from, claims.valid_until, claims.nonce.clone()) {
        (Some(valid_from), Some(valid_until), Some(nonce)) => Ok(CheckedFreshness {
            valid_from,
            valid_until,
            nonce,
        }),
        _ => Err(PlanValidityError::MissingFreshness),
    }
}

/// A [`FreshnessClaims`] with every field present, ready for
/// [`check_window`] and [`NonceStore::check_and_insert`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedFreshness {
    pub valid_from: UtcTimestamp,
    pub valid_until: UtcTimestamp,
    pub nonce: Nonce,
}

impl Freshness for CheckedFreshness {
    fn nonce(&self) -> &Nonce {
        &self.nonce
    }
    fn valid_from(&self) -> Result<UtcTimestamp, PlanValidityError> {
        Ok(self.valid_from)
    }
    fn valid_until(&self) -> Result<UtcTimestamp, PlanValidityError> {
        Ok(self.valid_until)
    }
}

/// Stateless check: does the item's window cover `now`, and is it
/// well-formed? Inverted windows fail closed.
pub fn check_window<F: Freshness>(item: &F, now: UtcTimestamp) -> Result<(), PlanValidityError> {
    let valid_from = item.valid_from()?;
    let valid_until = item.valid_until()?;
    if valid_from >= valid_until {
        return Err(PlanValidityError::InvertedWindow {
            valid_from,
            valid_until,
        });
    }
    if now < valid_from {
        return Err(PlanValidityError::NotYetValid { valid_from, now });
    }
    if now >= valid_until {
        return Err(PlanValidityError::Expired { valid_until, now });
    }
    Ok(())
}

/// Per-signer nonce ledger. Bounded by `valid_until`: when a stored
/// nonce passes its plan's `valid_until` it can be GC'd safely
/// because `check_window` would reject the plan anyway.
///
/// Replay protection is per-signer keyspace, not global. Two
/// independent signers may use the same nonce; cross-tenant /
/// cross-signer replay isn't the threat — it's a single signer's
/// captured plan being re-submitted.
#[derive(Debug, Default)]
pub struct NonceStore {
    /// Map: signer_id → seen nonces with their plan's `valid_until`.
    seen: HashMap<String, HashMap<Nonce, UtcTimestamp>>,
}

impl NonceStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomic check-and-insert. If the nonce was previously seen for
    /// this signer, returns `Err(NonceReplay)` and does not modify
    /// state.
    pub fn check_and_insert<F: Freshness>(
        &mut self,
        signer: &str,
        item: &F,
    ) -> Result<(), PlanValidityError> {
        let entry = self.seen.entry(signer.to_string()).or_default();
        if entry.contains_key(item.nonce()) {
            return Err(PlanValidityError::NonceReplay {
                signer: signer.to_string(),
            });
        }
        entry.insert(item.nonce().clone(), item.valid_until()?);
        Ok(())
    }

    /// Drop nonces whose `valid_until` is at or before `now`. The
    /// supervisor calls this on a timer; missing a sweep only inflates
    /// memory, never compromises safety.
    pub fn gc(&mut self, now: UtcTimestamp) {
        for nonces in self.seen.values_mut() {
            nonces.retain(|_, valid_until| *valid_until > now);
        }
        self.seen.retain(|_, n| !n.is_empty());
    }

    pub fn len(&self) -> usize {
        self.seen.values().map(HashMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::test_support::PlanFixture;
    use mvm_contract::timestamp::UtcTimestamp;

    const NOW: i64 = 1_784_205_296;

    fn ts(secs: i64) -> UtcTimestamp {
        UtcTimestamp::from_unix(secs, 0).unwrap()
    }

    fn nonce(seed: u8) -> Nonce {
        Nonce::from_bytes([seed; 16])
    }

    fn window(from: i64, until: i64, seed: u8) -> CheckedFreshness {
        checked(&FreshnessClaims::new(ts(from), ts(until), nonce(seed))).unwrap()
    }

    // The reusable freshness primitive rides the same window + nonce
    // ledger the plan path uses — one store, not a fork.
    #[test]
    fn checked_freshness_passes_window_and_records_once() {
        let fresh = window(NOW - 1, NOW + 300, 1);

        check_window(&fresh, ts(NOW)).expect("now is inside the window");

        let mut store = NonceStore::new();
        store
            .check_and_insert("signer-a", &fresh)
            .expect("first use accepted");
        assert_eq!(
            store.check_and_insert("signer-a", &fresh),
            Err(PlanValidityError::NonceReplay {
                signer: "signer-a".into()
            }),
            "replay of the same nonce for the same signer is refused",
        );
    }

    #[test]
    fn absent_freshness_fields_fail_closed() {
        // Wire tolerance: a payload missing the freshness block still
        // deserializes (serde default), but verification rejects it.
        let claims: FreshnessClaims =
            serde_json::from_str("{}").expect("empty object deserializes");
        assert_eq!(checked(&claims), Err(PlanValidityError::MissingFreshness));

        // A partially-populated block is equally invalid.
        let partial = FreshnessClaims {
            valid_from: Some(ts(NOW)),
            valid_until: Some(ts(NOW + 60)),
            nonce: None,
        };
        assert_eq!(checked(&partial), Err(PlanValidityError::MissingFreshness));
    }

    #[test]
    fn checked_freshness_rejects_stale_and_future_windows() {
        let expired = window(NOW - 600, NOW - 300, 2);
        assert!(matches!(
            check_window(&expired, ts(NOW)),
            Err(PlanValidityError::Expired { .. })
        ));

        let not_yet = window(NOW + 300, NOW + 600, 3);
        assert!(matches!(
            check_window(&not_yet, ts(NOW)),
            Err(PlanValidityError::NotYetValid { .. })
        ));
    }

    // The window rule as it stood on chrono, kept here as the oracle: the
    // migrated check must agree at, and one nanosecond either side of, both
    // edges, for whole-second and fractional edges alike.
    #[test]
    fn window_check_matches_the_chrono_rule_at_every_edge() {
        let chrono_rule = |from: UtcTimestamp, until: UtcTimestamp, now: UtcTimestamp| {
            if from >= until {
                "inverted"
            } else if now < from {
                "not_yet"
            } else if now >= until {
                "expired"
            } else {
                "ok"
            }
        };
        let kind = |r: Result<(), PlanValidityError>| match r {
            Ok(()) => "ok",
            Err(PlanValidityError::InvertedWindow { .. }) => "inverted",
            Err(PlanValidityError::NotYetValid { .. }) => "not_yet",
            Err(PlanValidityError::Expired { .. }) => "expired",
            Err(e) => panic!("unexpected {e}"),
        };
        let nano = std::time::Duration::from_nanos(1);
        for frac in [0, 1, 500_000_000, 999_999_999] {
            let from = UtcTimestamp::from_unix(NOW, frac).unwrap();
            for until in [
                from.checked_add_secs(600).unwrap(),
                from,
                from.checked_sub(nano).unwrap(),
            ] {
                let item = CheckedFreshness {
                    valid_from: from,
                    valid_until: until,
                    nonce: nonce(4),
                };
                for edge in [from, until] {
                    for now in [
                        edge.checked_sub(nano).unwrap(),
                        edge,
                        edge.checked_add(nano).unwrap(),
                    ] {
                        assert_eq!(
                            kind(check_window(&item, now)),
                            chrono_rule(from, until, now),
                            "from={from} until={until} now={now}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn gc_drops_at_and_after_valid_until_but_not_one_nanosecond_before() {
        let item = window(NOW, NOW + 60, 5);
        let until = ts(NOW + 60);
        let just_before = UtcTimestamp::from_unix(NOW + 59, 999_999_999).unwrap();
        for (now, kept) in [(just_before, 1), (until, 0)] {
            let mut store = NonceStore::new();
            store.check_and_insert("signer-a", &item).unwrap();
            store.gc(now);
            assert_eq!(store.len(), kept, "{now}");
        }
    }

    // ExecutionPlan must keep working through the generalized helpers —
    // proves the plan admission path is not forked off a second copy.
    #[test]
    fn execution_plan_flows_through_generic_freshness() {
        let now = crate::util::time::utc_timestamp_now();
        let plan = PlanFixture::new()
            .nonce([9u8; 16])
            .validity(
                now.checked_add_secs(-1).unwrap(),
                now.checked_add_secs(300).unwrap(),
            )
            .build();

        check_window(&plan, now).expect("plan window covers now");
        let mut store = NonceStore::new();
        store
            .check_and_insert("host-signer", &plan)
            .expect("first admission");
        assert!(
            store.check_and_insert("host-signer", &plan).is_err(),
            "replayed plan refused"
        );
    }
}
