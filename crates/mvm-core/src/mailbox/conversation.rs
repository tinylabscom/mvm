//! Pure call/reply bookkeeping for a mailbox caller.
//!
//! No I/O, no clock of its own: every time-dependent method takes a monotonic
//! `now` in milliseconds, so the caller owns the clock and tests need no sleeps.
//!
//! Rules enforced here:
//! - a call is keyed by (principal, epoch, correlation) and that key is unique;
//! - a resolved call leaves a tombstone, so a late or repeated reply is
//!   reported as such and can never satisfy a later call reusing the value;
//! - the pending table is bounded and refuses a registration at the bound;
//!   it never evicts a live call;
//! - dropping an epoch resolves every pending call of it as `Unavailable`.
//!
//! The tombstone ring is bounded too. When it wraps, the oldest tombstone is
//! forgotten: a reply to that forgotten call is then `Unknown`, which never
//! satisfies anything, so the failure is safe. What the ring cannot do after a
//! wrap is refuse reuse of a forgotten correlation; correlation ids are 32
//! bytes and must not be reused, and the ring size bounds how long reuse is
//! detected.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use mvm_contract::protocol::mailbox::{
    CorrelationId, DeliveryOutcome, ExecutionEpoch, PrincipalId,
};

/// Identity of one call: unique per caller principal and execution epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallKey {
    pub principal: PrincipalId,
    pub epoch: ExecutionEpoch,
    pub correlation: CorrelationId,
}

/// How a call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallOutcome {
    Reply,
    TimedOut,
    Cancelled,
    Unavailable,
}

/// What a reply meant to the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyDisposition {
    /// Satisfied a pending call.
    Matched,
    /// The call already timed out, was cancelled or became unavailable.
    Late,
    /// The call was already satisfied by an earlier reply.
    Duplicate,
    /// Nothing is known under this correlation.
    Unknown,
    /// The correlation belongs to a different principal or epoch.
    WrongPrincipalOrEpoch,
}

/// Why a registration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// A live call already holds this key.
    DuplicateCorrelation,
    /// The key was used before and is still remembered.
    ReusedCorrelation,
    /// The pending table is at its bound.
    TableFull,
}

/// Result of a `cast`: the admission level the destination reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CastOutcome {
    pub admission: DeliveryOutcome,
}

/// Bounds for [`PendingCalls`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConversationLimits {
    pub max_pending: usize,
    pub tombstone_ring: usize,
}

/// Pending calls plus a bounded memory of resolved ones.
#[derive(Debug)]
pub struct PendingCalls {
    limits: ConversationLimits,
    /// Key -> monotonic deadline in milliseconds.
    pending: BTreeMap<CallKey, u64>,
    tombstones: VecDeque<(CallKey, CallOutcome)>,
    tombstoned: BTreeSet<CallKey>,
}

impl PendingCalls {
    #[must_use]
    pub fn new(limits: ConversationLimits) -> Self {
        Self {
            limits,
            pending: BTreeMap::new(),
            tombstones: VecDeque::new(),
            tombstoned: BTreeSet::new(),
        }
    }

    pub fn register(&mut self, key: CallKey, deadline: u64) -> Result<(), RegisterError> {
        if self.pending.contains_key(&key) {
            return Err(RegisterError::DuplicateCorrelation);
        }
        if self.tombstoned.contains(&key) {
            return Err(RegisterError::ReusedCorrelation);
        }
        if self.pending.len() >= self.limits.max_pending {
            return Err(RegisterError::TableFull);
        }
        self.pending.insert(key, deadline);
        Ok(())
    }

    pub fn complete(&mut self, key: CallKey) -> ReplyDisposition {
        if self.pending.remove(&key).is_some() {
            self.remember(key, CallOutcome::Reply);
            return ReplyDisposition::Matched;
        }
        if let Some((_, outcome)) = self.tombstones.iter().find(|(k, _)| *k == key) {
            return match outcome {
                CallOutcome::Reply => ReplyDisposition::Duplicate,
                _ => ReplyDisposition::Late,
            };
        }
        let other = |k: &CallKey| k.correlation == key.correlation;
        if self.pending.keys().any(other) || self.tombstones.iter().any(|(k, _)| other(k)) {
            ReplyDisposition::WrongPrincipalOrEpoch
        } else {
            ReplyDisposition::Unknown
        }
    }

    /// Returns whether a live call was cancelled.
    pub fn cancel(&mut self, key: CallKey) -> bool {
        self.resolve(key, CallOutcome::Cancelled)
    }

    /// Resolves every call whose deadline is at or before `now`.
    pub fn expire(&mut self, now: u64) -> Vec<(CallKey, CallOutcome)> {
        let due: Vec<CallKey> = self
            .pending
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(k, _)| *k)
            .collect();
        self.resolve_all(due, CallOutcome::TimedOut)
    }

    /// Resolves every pending call of a principal and epoch as `Unavailable`.
    pub fn drop_epoch(
        &mut self,
        principal: PrincipalId,
        epoch: ExecutionEpoch,
    ) -> Vec<(CallKey, CallOutcome)> {
        let gone: Vec<CallKey> = self
            .pending
            .keys()
            .filter(|k| k.principal == principal && k.epoch == epoch)
            .copied()
            .collect();
        self.resolve_all(gone, CallOutcome::Unavailable)
    }

    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    fn resolve(&mut self, key: CallKey, outcome: CallOutcome) -> bool {
        let live = self.pending.remove(&key).is_some();
        if live {
            self.remember(key, outcome);
        }
        live
    }

    fn resolve_all(
        &mut self,
        keys: Vec<CallKey>,
        outcome: CallOutcome,
    ) -> Vec<(CallKey, CallOutcome)> {
        for key in &keys {
            self.resolve(*key, outcome);
        }
        keys.into_iter().map(|k| (k, outcome)).collect()
    }

    fn remember(&mut self, key: CallKey, outcome: CallOutcome) {
        if self.limits.tombstone_ring == 0 {
            return;
        }
        if self.tombstones.len() >= self.limits.tombstone_ring
            && let Some((old, _)) = self.tombstones.pop_front()
        {
            self.tombstoned.remove(&old);
        }
        self.tombstones.push_back((key, outcome));
        self.tombstoned.insert(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(p: u8, e: u64, c: u8) -> CallKey {
        CallKey {
            principal: PrincipalId::from_bytes([p; 32]),
            epoch: ExecutionEpoch::new(e).expect("epoch"),
            correlation: CorrelationId::from_bytes([c; 32]),
        }
    }

    fn table(max_pending: usize, tombstone_ring: usize) -> PendingCalls {
        PendingCalls::new(ConversationLimits {
            max_pending,
            tombstone_ring,
        })
    }

    #[test]
    fn reply_before_deadline_matches() {
        let mut t = table(4, 4);
        t.register(key(1, 1, 1), 100).unwrap();
        assert!(t.expire(99).is_empty());
        assert_eq!(t.complete(key(1, 1, 1)), ReplyDisposition::Matched);
        assert_eq!(t.pending_len(), 0);
        assert_eq!(t.complete(key(1, 1, 1)), ReplyDisposition::Duplicate);
    }

    #[test]
    fn timeout_then_late_reply_cannot_satisfy_a_reused_correlation() {
        let mut t = table(4, 4);
        t.register(key(1, 1, 1), 100).unwrap();
        assert_eq!(t.expire(100), vec![(key(1, 1, 1), CallOutcome::TimedOut)]);
        assert_eq!(t.complete(key(1, 1, 1)), ReplyDisposition::Late);
        // Reuse of the same value is refused while remembered, so the late
        // reply cannot satisfy a new call.
        assert_eq!(
            t.register(key(1, 1, 1), 200),
            Err(RegisterError::ReusedCorrelation)
        );
        assert_eq!(t.pending_len(), 0);
    }

    #[test]
    fn cancel_then_reply_is_late() {
        let mut t = table(4, 4);
        t.register(key(1, 1, 1), 100).unwrap();
        assert!(t.cancel(key(1, 1, 1)));
        assert!(!t.cancel(key(1, 1, 1)));
        assert_eq!(t.complete(key(1, 1, 1)), ReplyDisposition::Late);
    }

    #[test]
    fn reply_then_cancel_keeps_the_reply() {
        let mut t = table(4, 4);
        t.register(key(1, 1, 1), 100).unwrap();
        assert_eq!(t.complete(key(1, 1, 1)), ReplyDisposition::Matched);
        assert!(!t.cancel(key(1, 1, 1)));
        assert_eq!(t.complete(key(1, 1, 1)), ReplyDisposition::Duplicate);
    }

    #[test]
    fn duplicate_correlation_is_refused() {
        let mut t = table(4, 4);
        t.register(key(1, 1, 1), 100).unwrap();
        assert_eq!(
            t.register(key(1, 1, 1), 100),
            Err(RegisterError::DuplicateCorrelation)
        );
        // Same value under another principal or epoch is a different call.
        t.register(key(2, 1, 1), 100).unwrap();
        t.register(key(1, 2, 1), 100).unwrap();
    }

    #[test]
    fn wrong_principal_or_epoch_is_refused_and_leaves_the_call_pending() {
        let mut t = table(4, 4);
        t.register(key(1, 1, 1), 100).unwrap();
        assert_eq!(
            t.complete(key(2, 1, 1)),
            ReplyDisposition::WrongPrincipalOrEpoch
        );
        assert_eq!(
            t.complete(key(1, 2, 1)),
            ReplyDisposition::WrongPrincipalOrEpoch
        );
        assert_eq!(t.complete(key(1, 1, 9)), ReplyDisposition::Unknown);
        assert_eq!(t.complete(key(1, 1, 1)), ReplyDisposition::Matched);
    }

    #[test]
    fn full_table_refuses_without_evicting() {
        let mut t = table(2, 4);
        t.register(key(1, 1, 1), 100).unwrap();
        t.register(key(1, 1, 2), 100).unwrap();
        assert_eq!(t.register(key(1, 1, 3), 100), Err(RegisterError::TableFull));
        assert_eq!(t.complete(key(1, 1, 1)), ReplyDisposition::Matched);
        assert_eq!(t.complete(key(1, 1, 2)), ReplyDisposition::Matched);
    }

    #[test]
    fn dropping_an_epoch_makes_each_pending_call_unavailable() {
        let mut t = table(8, 8);
        t.register(key(1, 1, 1), 100).unwrap();
        t.register(key(1, 1, 2), 100).unwrap();
        t.register(key(1, 2, 3), 100).unwrap();
        let gone = key(1, 1, 0);
        let mut out = t.drop_epoch(gone.principal, gone.epoch);
        out.sort_by_key(|(k, _)| *k);
        assert_eq!(
            out,
            vec![
                (key(1, 1, 1), CallOutcome::Unavailable),
                (key(1, 1, 2), CallOutcome::Unavailable),
            ]
        );
        assert_eq!(t.pending_len(), 1);
        assert_eq!(t.complete(key(1, 1, 1)), ReplyDisposition::Late);
    }

    #[test]
    fn a_wrapped_ring_forgets_the_oldest_and_never_matches_it() {
        let mut t = table(8, 2);
        for c in 1..=3 {
            t.register(key(1, 1, c), 10).unwrap();
        }
        assert_eq!(t.expire(10).len(), 3);
        // The ring holds the two newest; the oldest is forgotten.
        assert_eq!(t.complete(key(1, 1, 1)), ReplyDisposition::Unknown);
        assert_eq!(t.complete(key(1, 1, 2)), ReplyDisposition::Late);
        assert_eq!(t.complete(key(1, 1, 3)), ReplyDisposition::Late);
        assert_eq!(t.pending_len(), 0);
    }

    #[test]
    fn a_cast_outcome_carries_the_admission_level() {
        let c = CastOutcome {
            admission: DeliveryOutcome::AcceptedLocalDurable,
        };
        assert_eq!(c.admission, DeliveryOutcome::AcceptedLocalDurable);
    }
}
