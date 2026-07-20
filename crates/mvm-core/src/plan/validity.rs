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

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::plan::execution_plan::ExecutionPlan;
use crate::plan::types::Nonce;

pub use mvm_protocol::plan::validity::FreshnessClaims;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlanValidityError {
    #[error("plan not yet valid (valid_from={valid_from}, now={now})")]
    NotYetValid {
        valid_from: DateTime<Utc>,
        now: DateTime<Utc>,
    },
    #[error("plan expired (valid_until={valid_until}, now={now})")]
    Expired {
        valid_until: DateTime<Utc>,
        now: DateTime<Utc>,
    },
    #[error("plan validity window inverted (valid_from={valid_from} >= valid_until={valid_until})")]
    InvertedWindow {
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    },
    #[error("plan nonce already seen for signer '{signer}'")]
    NonceReplay { signer: String },
    #[error("freshness block missing required field(s)")]
    MissingFreshness,
}

/// The freshness inputs the window + nonce checks need, decoupled
/// from `ExecutionPlan` so any signed payload — a plan, a signed
/// reconcile request — reuses one replay ledger instead of forking
/// its own.
pub trait Freshness {
    fn nonce(&self) -> &Nonce;
    fn valid_from(&self) -> DateTime<Utc>;
    fn valid_until(&self) -> DateTime<Utc>;
}

impl Freshness for ExecutionPlan {
    fn nonce(&self) -> &Nonce {
        &self.nonce
    }
    fn valid_from(&self) -> DateTime<Utc> {
        self.valid_from
    }
    fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }
}

/// Fail-closed conversion of a wire [`FreshnessClaims`] to a verifiable
/// value: absent freshness is never valid. A free function, not an
/// inherent method — `FreshnessClaims` lives in `mvm-protocol`, and
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
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub nonce: Nonce,
}

impl Freshness for CheckedFreshness {
    fn nonce(&self) -> &Nonce {
        &self.nonce
    }
    fn valid_from(&self) -> DateTime<Utc> {
        self.valid_from
    }
    fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }
}

/// Stateless check: does the item's window cover `now`, and is it
/// well-formed? Inverted windows fail closed.
pub fn check_window<F: Freshness>(item: &F, now: DateTime<Utc>) -> Result<(), PlanValidityError> {
    let valid_from = item.valid_from();
    let valid_until = item.valid_until();
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
    seen: HashMap<String, HashMap<Nonce, DateTime<Utc>>>,
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
        entry.insert(item.nonce().clone(), item.valid_until());
        Ok(())
    }

    /// Drop nonces whose `valid_until` is at or before `now`. The
    /// supervisor calls this on a timer; missing a sweep only inflates
    /// memory, never compromises safety.
    pub fn gc(&mut self, now: DateTime<Utc>) {
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
    use chrono::Duration;

    fn nonce(seed: u8) -> Nonce {
        Nonce::from_bytes([seed; 16])
    }

    // The reusable freshness primitive rides the same window + nonce
    // ledger the plan path uses — one store, not a fork.
    #[test]
    fn checked_freshness_passes_window_and_records_once() {
        let now = Utc::now();
        let claims = FreshnessClaims::new(
            now - Duration::seconds(1),
            now + Duration::minutes(5),
            nonce(1),
        );
        let fresh = checked(&claims).expect("full claims are valid");

        check_window(&fresh, now).expect("now is inside the window");

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
        let now = Utc::now();
        let partial = FreshnessClaims {
            valid_from: Some(now),
            valid_until: Some(now + Duration::minutes(1)),
            nonce: None,
        };
        assert_eq!(checked(&partial), Err(PlanValidityError::MissingFreshness));
    }

    #[test]
    fn checked_freshness_rejects_stale_and_future_windows() {
        let now = Utc::now();

        let expired = checked(&FreshnessClaims::new(
            now - Duration::minutes(10),
            now - Duration::minutes(5),
            nonce(2),
        ))
        .unwrap();
        assert!(matches!(
            check_window(&expired, now),
            Err(PlanValidityError::Expired { .. })
        ));

        let not_yet = checked(&FreshnessClaims::new(
            now + Duration::minutes(5),
            now + Duration::minutes(10),
            nonce(3),
        ))
        .unwrap();
        assert!(matches!(
            check_window(&not_yet, now),
            Err(PlanValidityError::NotYetValid { .. })
        ));
    }

    // ExecutionPlan must keep working through the generalized helpers —
    // proves the plan admission path is not forked off a second copy.
    #[test]
    fn execution_plan_flows_through_generic_freshness() {
        let now = Utc::now();
        let plan = PlanFixture::new()
            .nonce([9u8; 16])
            .validity(now - Duration::seconds(1), now + Duration::minutes(5))
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
