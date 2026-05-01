//! Plan-validity checks: time window + nonce de-duplication.
//!
//! Closes plan 37 Addendum G4 — without these checks an old signed
//! plan is replayable indefinitely. The supervisor calls
//! `check_validity` at admission and inserts the nonce into a
//! `NonceStore` keyed by signer; the store self-prunes nonces past
//! their `valid_until`.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::plan::ExecutionPlan;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
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
    #[error("nonce already seen for signer '{signer}'")]
    NonceReplay { signer: String },
}

/// Stateless check: does the plan's window cover `now`?
pub fn check_window(plan: &ExecutionPlan, now: DateTime<Utc>) -> Result<(), PlanValidityError> {
    if plan.valid_from >= plan.valid_until {
        return Err(PlanValidityError::InvertedWindow {
            valid_from: plan.valid_from,
            valid_until: plan.valid_until,
        });
    }
    if now < plan.valid_from {
        return Err(PlanValidityError::NotYetValid {
            valid_from: plan.valid_from,
            now,
        });
    }
    if now >= plan.valid_until {
        return Err(PlanValidityError::Expired {
            valid_until: plan.valid_until,
            now,
        });
    }
    Ok(())
}

/// Per-signer nonce ledger. Bounded by `valid_until`: when a stored
/// nonce passes its plan's `valid_until` it can be GC'd safely because
/// the window check would reject the plan anyway.
#[derive(Debug, Default)]
pub struct NonceStore {
    /// Map: signer_id → seen nonces with their plan's valid_until.
    seen: HashMap<String, HashMap<[u8; 16], DateTime<Utc>>>,
}

impl NonceStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomic check-and-insert. If the nonce was previously seen for
    /// this signer, returns `Err(NonceReplay)` and does not modify
    /// state.
    pub fn check_and_insert(
        &mut self,
        signer: &str,
        plan: &ExecutionPlan,
    ) -> Result<(), PlanValidityError> {
        let entry = self.seen.entry(signer.to_string()).or_default();
        if entry.contains_key(&plan.nonce) {
            return Err(PlanValidityError::NonceReplay {
                signer: signer.to_string(),
            });
        }
        entry.insert(plan.nonce, plan.valid_until);
        Ok(())
    }

    /// Drop nonces whose `valid_until` is in the past relative to
    /// `now`. The supervisor calls this on a timer; missing a sweep
    /// only inflates memory, never compromises safety.
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
