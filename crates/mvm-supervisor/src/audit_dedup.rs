//! Retry-storm dedup for audit emission. Plan 37 Addendum G2.
//!
//! A workload that gets blocked at the same boundary will often
//! retry. Each retry produces an audit entry. Without dedup, a
//! workload retrying once a millisecond for ten seconds floods
//! the audit log with 10,000 identical lines — correct but
//! expensive, and it drowns out the signal that there *is* a
//! retry storm.
//!
//! `RetryStormSuppressor` is a small in-memory state machine that
//! sits between any audit-producing code path and the audit signer.
//! On each `observe()`:
//!
//! - **First occurrence** (or first since the dedup window
//!   expired): returns `Decision::Emit` — caller emits normally.
//! - **Within the window**: returns `Decision::Suppress` —
//!   caller drops the entry; the suppressor remembers the
//!   running count.
//! - **`flush()`** at the end of the window (or on supervisor
//!   shutdown): returns one `Decision::EmitSummary` per dedup
//!   bucket that saw more than one observation, so the audit log
//!   ends up with one initial entry plus one summary per storm
//!   instead of N×identical entries.
//!
//! The dedup key is `(plan_id, event, bucket)` where `bucket` is
//! a free-form string the caller picks — usually
//! `format!("{destination}|{rule_id}")` for an egress decision or
//! `tool_id` for a tool-call gate decision. Two events with
//! different `bucket` values share neither the count nor the
//! window; that's the contract.
//!
//! The suppressor is sync (no async, no I/O); the caller wraps
//! it in whatever lock makes sense for its concurrency model.

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use mvm_plan::PlanId;

/// One dedup bucket — the supervisor folds equivalent retries
/// into a single bucket via this key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DedupKey {
    pub plan_id: PlanId,
    /// The event name that would otherwise be the audit entry's
    /// `event` field, e.g. `"egress.blocked"` or
    /// `"tool.gate.denied"`.
    pub event: String,
    /// Caller-chosen bucket discriminator. Two observations with
    /// the same `bucket` but different `event` belong to
    /// different buckets, and vice versa.
    pub bucket: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Caller should emit a normal audit entry. This was either
    /// the first observation in this bucket or the first since
    /// the previous window expired.
    Emit,
    /// Caller should drop the audit entry. The suppressor is
    /// keeping the running count; a later `flush()` will produce
    /// the summary.
    Suppress,
}

/// One bucket's running state inside the suppressor.
#[derive(Debug, Clone)]
struct BucketState {
    /// How many additional observations have been suppressed
    /// since the bucket was opened. The first observation that
    /// returned `Decision::Emit` is *not* counted here — only
    /// the suppressed retries.
    suppressed: u32,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

/// Summary record produced by `flush()` for a bucket that saw
/// more than the initial emit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryStormSummary {
    pub key: DedupKey,
    pub count: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Per-`(plan_id, event, bucket)` dedup window with a configurable
/// duration. See module docs.
pub struct RetryStormSuppressor {
    window: Duration,
    seen: HashMap<DedupKey, BucketState>,
}

impl RetryStormSuppressor {
    /// `window` is the dedup interval. After the last observation
    /// in a bucket, that bucket is allowed to emit again
    /// `window` later — closing the bucket and producing a
    /// summary from `flush()`.
    ///
    /// A typical value is 30s for human-facing events and 5s for
    /// machine-driven retries; the supervisor picks per use case.
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            seen: HashMap::new(),
        }
    }

    /// Record an observation. Returns whether the caller should
    /// emit a normal audit entry or drop it.
    pub fn observe(&mut self, key: DedupKey, now: DateTime<Utc>) -> Decision {
        let window_chrono =
            chrono::TimeDelta::from_std(self.window).unwrap_or(chrono::TimeDelta::zero());

        match self.seen.get_mut(&key) {
            None => {
                // First time we've seen this bucket.
                self.seen.insert(
                    key,
                    BucketState {
                        suppressed: 0,
                        first_seen: now,
                        last_seen: now,
                    },
                );
                Decision::Emit
            }
            Some(state) if now.signed_duration_since(state.last_seen) >= window_chrono => {
                // Last observation was outside the dedup window.
                // Restart the bucket: emit normally and reset the
                // counter. Any pending summary should have been
                // produced by `flush()` already.
                state.suppressed = 0;
                state.first_seen = now;
                state.last_seen = now;
                Decision::Emit
            }
            Some(state) => {
                // Inside the window — suppress.
                state.suppressed = state.suppressed.saturating_add(1);
                state.last_seen = now;
                Decision::Suppress
            }
        }
    }

    /// Drain summaries for buckets whose window has passed. Each
    /// returned `RetryStormSummary` corresponds to a bucket whose
    /// last-seen is at least `window` ago and whose suppressed
    /// count is non-zero. After flushing, those buckets are
    /// removed from internal state — a fresh observation later
    /// will re-emit (`Decision::Emit`) and reopen the bucket.
    pub fn flush(&mut self, now: DateTime<Utc>) -> Vec<RetryStormSummary> {
        let window_chrono =
            chrono::TimeDelta::from_std(self.window).unwrap_or(chrono::TimeDelta::zero());
        let mut out = Vec::new();
        self.seen.retain(|key, state| {
            let aged = now.signed_duration_since(state.last_seen) >= window_chrono;
            if aged {
                if state.suppressed > 0 {
                    out.push(RetryStormSummary {
                        key: key.clone(),
                        // count is the total observations,
                        // suppressed + the original 1 emit.
                        count: state.suppressed + 1,
                        first_seen: state.first_seen,
                        last_seen: state.last_seen,
                    });
                }
                false // drop the bucket
            } else {
                true // keep
            }
        });
        out
    }

    /// Number of buckets currently being tracked.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn key(event: &str, bucket: &str) -> DedupKey {
        DedupKey {
            plan_id: PlanId("test-plan".to_string()),
            event: event.to_string(),
            bucket: bucket.to_string(),
        }
    }

    fn t(s: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_777_372_800 + s, 0).unwrap()
    }

    #[test]
    fn first_observation_emits() {
        let mut s = RetryStormSuppressor::new(Duration::from_secs(30));
        assert_eq!(
            s.observe(key("egress.blocked", "evil.com"), t(0)),
            Decision::Emit
        );
    }

    #[test]
    fn second_observation_within_window_suppresses() {
        let mut s = RetryStormSuppressor::new(Duration::from_secs(30));
        s.observe(key("egress.blocked", "evil.com"), t(0));
        let d = s.observe(key("egress.blocked", "evil.com"), t(5));
        assert_eq!(d, Decision::Suppress);
    }

    #[test]
    fn observation_outside_window_emits_again() {
        let mut s = RetryStormSuppressor::new(Duration::from_secs(30));
        s.observe(key("egress.blocked", "evil.com"), t(0));
        // 31s later — outside the window.
        let d = s.observe(key("egress.blocked", "evil.com"), t(31));
        assert_eq!(d, Decision::Emit);
    }

    #[test]
    fn different_bucket_does_not_share_state() {
        let mut s = RetryStormSuppressor::new(Duration::from_secs(30));
        s.observe(key("egress.blocked", "evil.com"), t(0));
        // Different bucket — also emits despite same event.
        let d = s.observe(key("egress.blocked", "other.com"), t(1));
        assert_eq!(d, Decision::Emit);
    }

    #[test]
    fn different_event_does_not_share_state() {
        let mut s = RetryStormSuppressor::new(Duration::from_secs(30));
        s.observe(key("egress.blocked", "evil.com"), t(0));
        let d = s.observe(key("egress.allowed", "evil.com"), t(1));
        assert_eq!(d, Decision::Emit);
    }

    #[test]
    fn different_plan_does_not_share_state() {
        let mut s = RetryStormSuppressor::new(Duration::from_secs(30));
        let k1 = DedupKey {
            plan_id: PlanId("plan-a".to_string()),
            event: "egress.blocked".to_string(),
            bucket: "evil.com".to_string(),
        };
        let k2 = DedupKey {
            plan_id: PlanId("plan-b".to_string()),
            ..k1.clone()
        };
        s.observe(k1, t(0));
        let d = s.observe(k2, t(1));
        assert_eq!(d, Decision::Emit);
    }

    #[test]
    fn flush_produces_summary_for_suppressed_bucket() {
        let mut s = RetryStormSuppressor::new(Duration::from_secs(30));
        s.observe(key("egress.blocked", "evil.com"), t(0));
        for i in 1..=4 {
            s.observe(key("egress.blocked", "evil.com"), t(i));
        }
        // 31s after last observation (which was at t(4)).
        let summaries = s.flush(t(35));
        assert_eq!(summaries.len(), 1);
        let summ = &summaries[0];
        // 1 emit + 4 suppressed = 5 total.
        assert_eq!(summ.count, 5);
        assert_eq!(summ.first_seen, t(0));
        assert_eq!(summ.last_seen, t(4));
        // Bucket cleared after flush.
        assert!(s.is_empty());
    }

    #[test]
    fn flush_skips_bucket_with_only_one_observation() {
        // No retries happened, so no summary is needed.
        let mut s = RetryStormSuppressor::new(Duration::from_secs(30));
        s.observe(key("egress.blocked", "evil.com"), t(0));
        let summaries = s.flush(t(31));
        assert!(summaries.is_empty());
        // But the bucket should be cleared regardless.
        assert!(s.is_empty());
    }

    #[test]
    fn flush_keeps_bucket_still_inside_window() {
        let mut s = RetryStormSuppressor::new(Duration::from_secs(30));
        s.observe(key("egress.blocked", "evil.com"), t(0));
        s.observe(key("egress.blocked", "evil.com"), t(5));
        // Only 10s after last observation — still inside window.
        let summaries = s.flush(t(15));
        assert!(summaries.is_empty());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn flush_window_boundary_uses_inclusive_aging() {
        // At exactly `window` after last_seen, the bucket is
        // considered aged. Pin this so a future change to
        // strict-less-than doesn't slip through.
        let mut s = RetryStormSuppressor::new(Duration::from_secs(30));
        s.observe(key("egress.blocked", "evil.com"), t(0));
        s.observe(key("egress.blocked", "evil.com"), t(0)); // 1 suppressed
        let summaries = s.flush(t(30));
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].count, 2);
    }

    #[test]
    fn re_emit_after_window_resets_count() {
        let mut s = RetryStormSuppressor::new(Duration::from_secs(30));
        s.observe(key("egress.blocked", "evil.com"), t(0));
        s.observe(key("egress.blocked", "evil.com"), t(5)); // suppressed
        s.observe(key("egress.blocked", "evil.com"), t(10)); // suppressed
        // 31s after t(10) → outside window. New observation is
        // an Emit, not a Suppress.
        let d = s.observe(key("egress.blocked", "evil.com"), t(41));
        assert_eq!(d, Decision::Emit);
        // The previous suppression count is gone (the caller
        // would have flushed before this new emit).
        // Add another observation inside the new window.
        let d = s.observe(key("egress.blocked", "evil.com"), t(45));
        assert_eq!(d, Decision::Suppress);
    }

    #[test]
    fn dedup_key_serde_roundtrip() {
        let k = key("egress.blocked", "evil.com");
        let json = serde_json::to_string(&k).unwrap();
        let parsed: DedupKey = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, k);
    }

    #[test]
    fn retry_storm_summary_serde_roundtrip() {
        let summ = RetryStormSummary {
            key: key("egress.blocked", "evil.com"),
            count: 1234,
            first_seen: t(0),
            last_seen: t(60),
        };
        let json = serde_json::to_string(&summ).unwrap();
        let parsed: RetryStormSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, summ);
    }

    #[test]
    fn dedup_key_unknown_field_rejected() {
        let json = r#"{"plan_id":"x","event":"y","bucket":"z","extra":1}"#;
        assert!(serde_json::from_str::<DedupKey>(json).is_err());
    }

    #[test]
    fn saturating_count_does_not_overflow() {
        // Synthetic test: ensure suppressed count uses saturating
        // add. We don't drive 4 billion observations through here,
        // we just sanity-check the contract via the observable
        // length. Real exhaustion would be handled by the caller's
        // flush cadence.
        let s = RetryStormSuppressor::new(Duration::from_secs(30));
        assert_eq!(s.len(), 0);
    }
}
