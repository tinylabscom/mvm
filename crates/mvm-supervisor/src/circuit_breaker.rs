//! Circuit breakers for the inspector chain — Plan 37 Addendum E1.
//!
//! A poorly-tuned PII regex blocking every prompt is a self-inflicted
//! fleet outage. Operators need a fast escape hatch that doesn't
//! require redeploying a new policy bundle: report a few false
//! positives, the breaker flips the noisy detector to **detect-only**,
//! and traffic flows again while the rule gets fixed.
//!
//! ## Failure modes the design closes
//!
//! - **Detect-only, not fully open.** A tripped breaker downgrades a
//!   `Deny` verdict to `Transform { note }` rather than `Allow`. The
//!   audit stream still records the would-have-denied verdict so the
//!   operator can quantify how often the broken detector would have
//!   blocked legitimate traffic before the fix lands. "Open the gate
//!   silently" hides the cost of the misconfiguration; "open with a
//!   loud audit signal" surfaces it.
//! - **Per-inspector, not global.** One bad detector shouldn't trip
//!   the rest of the chain. The breaker keys on
//!   `Inspector::name()` so `pii_redactor` can be open while
//!   `secrets_scanner` stays closed.
//! - **Manual reset, not auto-close.** Default config has
//!   `auto_reset_after = None` because the breaker tripping is the
//!   signal that a human action is required (tune the rule, ship a
//!   policy bundle update, …). Auto-close would mask the underlying
//!   problem. Operators can opt-in to auto-close via
//!   `CircuitBreakerConfig::auto_reset_after` when they prefer the
//!   alternative posture.
//! - **Allow + Transform pass through unmodified.** The breaker only
//!   rewrites `Deny`. A `PiiRedactor` running in detect-only that
//!   produces `Transform { note }` continues to do so — the breaker
//!   layer is invisible to non-deny verdicts.
//!
//! ## Wave-1 scope
//!
//! Ships:
//! 1. `CircuitBreakerConfig` — threshold / window / optional
//!    auto-reset.
//! 2. `InspectorReporter` — thread-safe registry of report counts +
//!    breaker state, keyed by inspector name. Operators call
//!    `report_false_positive(name)` to feed it; consumers query
//!    `is_tripped(name)` and `status(name)`.
//! 3. `CircuitBreaker` — `Inspector` wrapper that consults the
//!    reporter on each `inspect()` and downgrades `Deny` → `Transform`
//!    when the breaker for the wrapped inspector is open.
//! 4. `Clock` trait so tests drive time deterministically (the
//!    window-eviction logic depends on monotonic comparisons against
//!    a wall clock).
//!
//! Deferred:
//! - **CLI surface** (`mvmctl detector report-fp`,
//!   `mvmctl detector status`, `mvmctl detector reset`). Needs the
//!   supervisor's local control-plane API (Plan 37 §25, Wave 5).
//!   Today the reporter is a Rust-API surface only.
//! - **Persistence across supervisor restart.** The reporter is
//!   in-memory; restart clears state. Operators who want stickier
//!   trips can rebuild from the audit stream (every breaker trip
//!   would emit one `EgressInspectorBreakerTripped` entry — Wave 2.7
//!   audit work).
//! - **Audit-on-trip emission.** Wiring the `AuditSigner` into the
//!   reporter means another arg threading through `with_l7_egress`;
//!   we'll fold it into the audit binding rework rather than ship a
//!   half-version now.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::inspector::{Inspector, InspectorVerdict, RequestCtx};

/// Configuration for the false-positive circuit breaker.
#[derive(Clone, Debug)]
pub struct CircuitBreakerConfig {
    /// Reports needed inside `trip_window` to flip the breaker to
    /// `Open`. Default: 5.
    pub trip_threshold: u32,
    /// Window over which `report_false_positive` calls accumulate.
    /// Reports older than this are evicted on every report and on
    /// every `is_tripped` call. Default: 10 minutes.
    pub trip_window: Duration,
    /// `Some(d)` to auto-reset a tripped breaker `d` after the trip
    /// timestamp; `None` to leave it open until manual `reset()`.
    /// Default: `None` — the trip itself is the signal a human
    /// action is required.
    pub auto_reset_after: Option<Duration>,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            trip_threshold: 5,
            trip_window: Duration::from_secs(10 * 60),
            auto_reset_after: None,
        }
    }
}

/// Public projection of an inspector's breaker state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CircuitState {
    /// Forward verdicts unmodified. `recent_reports` is the count of
    /// reports inside the current `trip_window`.
    Closed { recent_reports: u32 },
    /// Downgrade `Deny` → `Transform`. `tripped_at` is the moment the
    /// breaker flipped; `reports_at_trip` records the count at that
    /// moment so an operator dashboard can show "tripped on the 5th
    /// report at 14:32".
    Open {
        tripped_at: DateTime<Utc>,
        reports_at_trip: u32,
    },
}

/// Internal per-inspector state.
struct InspectorEntry {
    /// Recent report timestamps, ordered oldest → newest.
    /// `VecDeque` so window eviction at the front is O(1) amortised.
    reports: VecDeque<DateTime<Utc>>,
    /// `Some(when)` when the breaker is open; `None` when closed.
    tripped_at: Option<DateTime<Utc>>,
    /// Snapshot of `reports.len()` at the moment of tripping.
    reports_at_trip: u32,
}

impl InspectorEntry {
    fn new() -> Self {
        Self {
            reports: VecDeque::new(),
            tripped_at: None,
            reports_at_trip: 0,
        }
    }
}

/// Clock abstraction. Production callers use [`SystemClock`]; tests
/// inject a fixed clock so the trip-window logic is deterministic.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

/// Production clock — wall-clock UTC.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Thread-safe registry of breaker state, keyed by `Inspector::name()`.
///
/// One reporter is shared across every `CircuitBreaker` in the chain
/// (and across any external code that wants to feed it reports —
/// CLI, HTTP API, etc.). The reporter owns no state for a given
/// inspector name until the first report or query for that name.
pub struct InspectorReporter {
    state: Mutex<HashMap<String, InspectorEntry>>,
    config: CircuitBreakerConfig,
    clock: Arc<dyn Clock>,
}

impl InspectorReporter {
    /// Build a reporter with the given config and the system clock.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self::with_clock(config, Arc::new(SystemClock))
    }

    /// Build a reporter with an explicit clock — used by tests.
    pub fn with_clock(config: CircuitBreakerConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            config,
            clock,
        }
    }

    /// Record one false-positive complaint for `name`. Trips the
    /// breaker on the first report at or above `trip_threshold`
    /// inside `trip_window`; subsequent reports while open keep
    /// accumulating in the window but don't re-trip.
    pub fn report_false_positive(&self, name: &str) {
        let now = self.clock.now();
        let cutoff = window_cutoff(now, self.config.trip_window);
        let mut state = self.state.lock().expect("reporter mutex poisoned");
        let entry = state
            .entry(name.to_string())
            .or_insert_with(InspectorEntry::new);
        evict_before(&mut entry.reports, cutoff);
        entry.reports.push_back(now);
        if entry.tripped_at.is_none()
            && u32::try_from(entry.reports.len()).unwrap_or(u32::MAX) >= self.config.trip_threshold
        {
            entry.tripped_at = Some(now);
            entry.reports_at_trip = u32::try_from(entry.reports.len()).unwrap_or(u32::MAX);
        }
    }

    /// Drop all state for `name`: reports cleared, breaker returned
    /// to `Closed`. No-op when the inspector has never been reported.
    pub fn reset(&self, name: &str) {
        let mut state = self.state.lock().expect("reporter mutex poisoned");
        if let Some(entry) = state.get_mut(name) {
            entry.reports.clear();
            entry.tripped_at = None;
            entry.reports_at_trip = 0;
        }
    }

    /// `true` when the breaker for `name` is currently open. Honours
    /// `auto_reset_after`: a breaker whose trip timestamp is older
    /// than the auto-reset interval is treated as closed (and
    /// silently transitioned on the next `report_false_positive`).
    pub fn is_tripped(&self, name: &str) -> bool {
        let state = self.state.lock().expect("reporter mutex poisoned");
        let Some(entry) = state.get(name) else {
            return false;
        };
        let Some(tripped_at) = entry.tripped_at else {
            return false;
        };
        if let Some(auto_reset) = self.config.auto_reset_after
            && auto_reset_elapsed(self.clock.now(), tripped_at) >= auto_reset
        {
            return false;
        }
        true
    }

    /// Public projection of the breaker's state for `name`. Closed
    /// with `recent_reports = 0` when no state exists yet.
    pub fn status(&self, name: &str) -> CircuitState {
        let state = self.state.lock().expect("reporter mutex poisoned");
        state
            .get(name)
            .map_or(CircuitState::Closed { recent_reports: 0 }, entry_to_state)
    }

    /// All inspectors that have any state, sorted by name. Useful
    /// for an operator dashboard / `mvmctl detector status`.
    pub fn statuses(&self) -> Vec<(String, CircuitState)> {
        let state = self.state.lock().expect("reporter mutex poisoned");
        let mut out: Vec<(String, CircuitState)> = state
            .iter()
            .map(|(k, v)| (k.clone(), entry_to_state(v)))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

/// `Inspector` wrapper that consults an `InspectorReporter` and
/// downgrades `Deny` → `Transform` when the wrapped inspector's
/// breaker is open. The wrapper preserves the wrapped inspector's
/// `name()` so audit binding stays intact.
pub struct CircuitBreaker {
    inner: Box<dyn Inspector>,
    reporter: Arc<InspectorReporter>,
}

impl CircuitBreaker {
    pub fn new(inner: Box<dyn Inspector>, reporter: Arc<InspectorReporter>) -> Self {
        Self { inner, reporter }
    }
}

#[async_trait]
impl Inspector for CircuitBreaker {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    async fn inspect(&self, ctx: &mut RequestCtx) -> InspectorVerdict {
        let verdict = self.inner.inspect(ctx).await;
        match verdict {
            InspectorVerdict::Deny { reason } if self.reporter.is_tripped(self.inner.name()) => {
                InspectorVerdict::Transform {
                    note: format!(
                        "{} circuit-breaker tripped (detect-only); would have denied: {}",
                        self.inner.name(),
                        reason
                    ),
                }
            }
            v => v,
        }
    }
}

// ---- private helpers ----

fn entry_to_state(entry: &InspectorEntry) -> CircuitState {
    match entry.tripped_at {
        None => CircuitState::Closed {
            recent_reports: u32::try_from(entry.reports.len()).unwrap_or(u32::MAX),
        },
        Some(when) => CircuitState::Open {
            tripped_at: when,
            reports_at_trip: entry.reports_at_trip,
        },
    }
}

fn window_cutoff(now: DateTime<Utc>, window: Duration) -> DateTime<Utc> {
    chrono::Duration::from_std(window).map_or(now, |d| now - d)
}

fn evict_before(reports: &mut VecDeque<DateTime<Utc>>, cutoff: DateTime<Utc>) {
    while let Some(&front) = reports.front() {
        if front < cutoff {
            reports.pop_front();
        } else {
            break;
        }
    }
}

fn auto_reset_elapsed(now: DateTime<Utc>, tripped_at: DateTime<Utc>) -> Duration {
    (now - tripped_at).to_std().unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Test clock with mutable interior. Each test wires its own.
    struct TestClock(StdMutex<DateTime<Utc>>);

    impl TestClock {
        fn at(t: DateTime<Utc>) -> Self {
            Self(StdMutex::new(t))
        }
        fn advance(&self, d: Duration) {
            let mut t = self.0.lock().expect("test clock poisoned");
            *t += chrono::Duration::from_std(d).expect("chrono duration");
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().expect("test clock poisoned")
        }
    }

    fn t0() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 5, 4, 12, 0, 0).unwrap()
    }

    fn cfg(threshold: u32, window_secs: u64) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            trip_threshold: threshold,
            trip_window: Duration::from_secs(window_secs),
            auto_reset_after: None,
        }
    }

    /// Inspector that always returns the configured verdict. Reused
    /// to drive the wrapper's verdict-rewrite logic without standing
    /// up a real PII/SSRF/etc. inspector.
    struct FixedVerdict {
        name: &'static str,
        verdict: InspectorVerdict,
    }

    #[async_trait]
    impl Inspector for FixedVerdict {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn inspect(&self, _ctx: &mut RequestCtx) -> InspectorVerdict {
            self.verdict.clone()
        }
    }

    fn ctx() -> RequestCtx {
        RequestCtx::new("example.com", 443, "/")
    }

    // ---- InspectorReporter ----

    #[test]
    fn unknown_inspector_status_is_closed_zero() {
        let r = InspectorReporter::with_clock(cfg(3, 60), Arc::new(TestClock::at(t0())));
        assert_eq!(
            r.status("never_reported"),
            CircuitState::Closed { recent_reports: 0 }
        );
        assert!(!r.is_tripped("never_reported"));
        assert!(r.statuses().is_empty());
    }

    #[test]
    fn first_report_records_one_closed() {
        let r = InspectorReporter::with_clock(cfg(3, 60), Arc::new(TestClock::at(t0())));
        r.report_false_positive("pii_redactor");
        assert_eq!(
            r.status("pii_redactor"),
            CircuitState::Closed { recent_reports: 1 }
        );
        assert!(!r.is_tripped("pii_redactor"));
    }

    #[test]
    fn trips_on_threshold_th_report() {
        let clock = Arc::new(TestClock::at(t0()));
        let r = InspectorReporter::with_clock(cfg(3, 60), clock.clone());
        r.report_false_positive("pii_redactor");
        r.report_false_positive("pii_redactor");
        assert!(!r.is_tripped("pii_redactor"));
        // Third report flips the breaker.
        r.report_false_positive("pii_redactor");
        assert!(r.is_tripped("pii_redactor"));
        match r.status("pii_redactor") {
            CircuitState::Open {
                tripped_at,
                reports_at_trip,
            } => {
                assert_eq!(tripped_at, t0());
                assert_eq!(reports_at_trip, 3);
            }
            other => panic!("expected Open, got {other:?}"),
        }
    }

    #[test]
    fn old_reports_outside_window_dont_count() {
        let clock = Arc::new(TestClock::at(t0()));
        let r = InspectorReporter::with_clock(cfg(3, 60), clock.clone());
        r.report_false_positive("pii_redactor");
        r.report_false_positive("pii_redactor");
        clock.advance(Duration::from_secs(120)); // past the 60 s window
        // The next report inside the new window doesn't push us over
        // the threshold because the first two have aged out.
        r.report_false_positive("pii_redactor");
        assert!(!r.is_tripped("pii_redactor"));
        assert_eq!(
            r.status("pii_redactor"),
            CircuitState::Closed { recent_reports: 1 }
        );
    }

    #[test]
    fn manual_reset_returns_to_closed_zero() {
        let clock = Arc::new(TestClock::at(t0()));
        let r = InspectorReporter::with_clock(cfg(2, 60), clock.clone());
        r.report_false_positive("pii_redactor");
        r.report_false_positive("pii_redactor");
        assert!(r.is_tripped("pii_redactor"));
        r.reset("pii_redactor");
        assert!(!r.is_tripped("pii_redactor"));
        assert_eq!(
            r.status("pii_redactor"),
            CircuitState::Closed { recent_reports: 0 }
        );
    }

    #[test]
    fn reset_unknown_inspector_is_noop() {
        let r = InspectorReporter::with_clock(cfg(3, 60), Arc::new(TestClock::at(t0())));
        r.reset("never_reported"); // no panic, no state created
        assert!(r.statuses().is_empty());
    }

    #[test]
    fn breakers_are_per_inspector() {
        let clock = Arc::new(TestClock::at(t0()));
        let r = InspectorReporter::with_clock(cfg(2, 60), clock.clone());
        r.report_false_positive("pii_redactor");
        r.report_false_positive("pii_redactor");
        // pii is open, secrets is untouched.
        assert!(r.is_tripped("pii_redactor"));
        assert!(!r.is_tripped("secrets_scanner"));
        let statuses = r.statuses();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].0, "pii_redactor");
    }

    #[test]
    fn auto_reset_recloses_after_interval() {
        let clock = Arc::new(TestClock::at(t0()));
        let r = InspectorReporter::with_clock(
            CircuitBreakerConfig {
                trip_threshold: 2,
                trip_window: Duration::from_secs(60),
                auto_reset_after: Some(Duration::from_secs(120)),
            },
            clock.clone(),
        );
        r.report_false_positive("pii_redactor");
        r.report_false_positive("pii_redactor");
        assert!(r.is_tripped("pii_redactor"));
        clock.advance(Duration::from_secs(150)); // past auto-reset
        assert!(
            !r.is_tripped("pii_redactor"),
            "auto-reset should re-close after the configured interval"
        );
    }

    #[test]
    fn statuses_are_sorted_by_name() {
        let r = InspectorReporter::with_clock(cfg(3, 60), Arc::new(TestClock::at(t0())));
        for name in ["zeta", "alpha", "mu"] {
            r.report_false_positive(name);
        }
        let statuses = r.statuses();
        let names: Vec<&str> = statuses.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["alpha", "mu", "zeta"]);
    }

    #[test]
    fn already_open_does_not_re_trip_on_more_reports() {
        let clock = Arc::new(TestClock::at(t0()));
        let r = InspectorReporter::with_clock(cfg(2, 60), clock.clone());
        r.report_false_positive("pii_redactor");
        r.report_false_positive("pii_redactor");
        let CircuitState::Open {
            tripped_at: first_trip,
            ..
        } = r.status("pii_redactor")
        else {
            panic!("expected Open after threshold");
        };
        clock.advance(Duration::from_secs(5));
        r.report_false_positive("pii_redactor");
        let CircuitState::Open {
            tripped_at: second_trip,
            reports_at_trip,
        } = r.status("pii_redactor")
        else {
            panic!("expected Open to persist");
        };
        // Trip timestamp is sticky — the trip happened once and
        // shouldn't move on every subsequent report.
        assert_eq!(first_trip, second_trip);
        // reports_at_trip stays at the value it had when the
        // breaker first tripped.
        assert_eq!(reports_at_trip, 2);
    }

    // ---- CircuitBreaker (Inspector wrapper) ----

    #[tokio::test]
    async fn closed_breaker_forwards_deny_unchanged() {
        let r = Arc::new(InspectorReporter::with_clock(
            cfg(3, 60),
            Arc::new(TestClock::at(t0())),
        ));
        let inner = Box::new(FixedVerdict {
            name: "pii_redactor",
            verdict: InspectorVerdict::Deny {
                reason: "ssn detected".to_string(),
            },
        });
        let breaker = CircuitBreaker::new(inner, r);
        let v = breaker.inspect(&mut ctx()).await;
        assert_eq!(
            v,
            InspectorVerdict::Deny {
                reason: "ssn detected".to_string()
            }
        );
    }

    #[tokio::test]
    async fn open_breaker_downgrades_deny_to_transform() {
        let clock = Arc::new(TestClock::at(t0()));
        let r = Arc::new(InspectorReporter::with_clock(cfg(2, 60), clock));
        // Trip the breaker for pii_redactor.
        r.report_false_positive("pii_redactor");
        r.report_false_positive("pii_redactor");
        assert!(r.is_tripped("pii_redactor"));
        let inner = Box::new(FixedVerdict {
            name: "pii_redactor",
            verdict: InspectorVerdict::Deny {
                reason: "ssn detected".to_string(),
            },
        });
        let breaker = CircuitBreaker::new(inner, r);
        let v = breaker.inspect(&mut ctx()).await;
        match v {
            InspectorVerdict::Transform { note } => {
                // Note must surface (a) which inspector tripped and
                // (b) the original deny reason — so audit consumers
                // can answer "what would have been blocked?".
                assert!(note.contains("pii_redactor"));
                assert!(note.contains("circuit-breaker"));
                assert!(note.contains("detect-only"));
                assert!(note.contains("ssn detected"));
            }
            other => panic!("expected Transform, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn breaker_passes_allow_through_unchanged() {
        let clock = Arc::new(TestClock::at(t0()));
        let r = Arc::new(InspectorReporter::with_clock(cfg(2, 60), clock));
        r.report_false_positive("pii_redactor");
        r.report_false_positive("pii_redactor");
        // Tripped — but the inner inspector returns Allow on this
        // request, so the breaker should not synthesize a verdict.
        let inner = Box::new(FixedVerdict {
            name: "pii_redactor",
            verdict: InspectorVerdict::Allow,
        });
        let breaker = CircuitBreaker::new(inner, r);
        assert_eq!(breaker.inspect(&mut ctx()).await, InspectorVerdict::Allow);
    }

    #[tokio::test]
    async fn breaker_passes_transform_through_unchanged() {
        let clock = Arc::new(TestClock::at(t0()));
        let r = Arc::new(InspectorReporter::with_clock(cfg(2, 60), clock));
        r.report_false_positive("pii_redactor");
        r.report_false_positive("pii_redactor");
        // Transform from a detect-only PiiRedactor passes through —
        // the breaker only intervenes on Deny.
        let inner = Box::new(FixedVerdict {
            name: "pii_redactor",
            verdict: InspectorVerdict::Transform {
                note: "redacted [PERSON_1]".to_string(),
            },
        });
        let breaker = CircuitBreaker::new(inner, r);
        assert_eq!(
            breaker.inspect(&mut ctx()).await,
            InspectorVerdict::Transform {
                note: "redacted [PERSON_1]".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn breaker_recloses_after_reset() {
        let clock = Arc::new(TestClock::at(t0()));
        let r = Arc::new(InspectorReporter::with_clock(cfg(2, 60), clock));
        r.report_false_positive("pii_redactor");
        r.report_false_positive("pii_redactor");
        let inner = Box::new(FixedVerdict {
            name: "pii_redactor",
            verdict: InspectorVerdict::Deny {
                reason: "ssn detected".to_string(),
            },
        });
        let breaker = CircuitBreaker::new(inner, r.clone());
        // Open: downgrades.
        assert!(matches!(
            breaker.inspect(&mut ctx()).await,
            InspectorVerdict::Transform { .. }
        ));
        r.reset("pii_redactor");
        // Closed again: forwards Deny.
        assert!(matches!(
            breaker.inspect(&mut ctx()).await,
            InspectorVerdict::Deny { .. }
        ));
    }

    #[tokio::test]
    async fn breaker_for_one_inspector_does_not_affect_another() {
        let clock = Arc::new(TestClock::at(t0()));
        let r = Arc::new(InspectorReporter::with_clock(cfg(2, 60), clock));
        // Trip pii_redactor only.
        r.report_false_positive("pii_redactor");
        r.report_false_positive("pii_redactor");
        let inner_secrets = Box::new(FixedVerdict {
            name: "secrets_scanner",
            verdict: InspectorVerdict::Deny {
                reason: "aws key".to_string(),
            },
        });
        let breaker_secrets = CircuitBreaker::new(inner_secrets, r);
        // secrets_scanner's Deny survives — its breaker is closed.
        match breaker_secrets.inspect(&mut ctx()).await {
            InspectorVerdict::Deny { reason } => assert_eq!(reason, "aws key"),
            other => panic!("expected secrets_scanner Deny intact, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn name_is_inherited_from_wrapped_inspector() {
        let r = Arc::new(InspectorReporter::with_clock(
            cfg(3, 60),
            Arc::new(TestClock::at(t0())),
        ));
        let inner = Box::new(FixedVerdict {
            name: "pii_redactor",
            verdict: InspectorVerdict::Allow,
        });
        let breaker = CircuitBreaker::new(inner, r);
        assert_eq!(breaker.name(), "pii_redactor");
    }
}
