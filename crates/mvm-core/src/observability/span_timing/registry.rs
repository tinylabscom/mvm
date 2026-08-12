//! Process-wide aggregation of span durations, keyed by span identity.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use super::histogram::LogHistogram;

/// Identity of an instrumented call site.
///
/// Both halves come from `tracing`'s `Metadata`, which is `'static`, so the key
/// borrows rather than allocating on every span close.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SpanKey {
    /// The emitting module path (`tracing` target).
    pub target: &'static str,
    /// The span name, which for `#[instrument]` is the function name.
    pub name: &'static str,
}

/// Accumulated timings for one call site.
struct SpanStat {
    calls: u64,
    /// Time the span was entered, including time spent in nested spans.
    busy_ns: u64,
    /// Portion of `busy_ns` attributable to nested instrumented spans.
    child_busy_ns: u64,
    /// Wall-clock from span creation to close, including time not entered.
    wall_ns: u64,
    min_busy_ns: u64,
    max_busy_ns: u64,
    hist: LogHistogram,
}

impl SpanStat {
    fn new() -> Self {
        Self {
            calls: 0,
            busy_ns: 0,
            child_busy_ns: 0,
            wall_ns: 0,
            min_busy_ns: u64::MAX,
            max_busy_ns: 0,
            hist: LogHistogram::new(),
        }
    }

    fn record(&mut self, sample: &SpanSample) {
        self.calls += 1;
        self.busy_ns += sample.busy_ns;
        self.child_busy_ns += sample.child_busy_ns;
        self.wall_ns += sample.wall_ns;
        self.min_busy_ns = self.min_busy_ns.min(sample.busy_ns);
        self.max_busy_ns = self.max_busy_ns.max(sample.busy_ns);
        self.hist.record(sample.busy_ns);
    }
}

/// One completed span observation handed to the registry.
pub struct SpanSample {
    /// Time the span was entered.
    pub busy_ns: u64,
    /// Entered time attributable to nested instrumented spans.
    pub child_busy_ns: u64,
    /// Creation-to-close wall clock.
    pub wall_ns: u64,
}

/// Per-call-site profile emitted in a [`SpanReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanProfile {
    /// Emitting module path.
    pub target: String,
    /// Span name (the function name for `#[instrument]`).
    pub name: String,
    /// Number of completed calls.
    pub calls: u64,
    /// Total entered time, including nested spans.
    pub total_ns: u64,
    /// Total entered time excluding nested instrumented spans. This is the
    /// figure that identifies which function to optimize.
    pub self_ns: u64,
    /// Total creation-to-close wall clock, including time not entered. On async
    /// code the gap against `total_ns` is time awaiting something else.
    pub wall_ns: u64,
    /// Mean entered time per call.
    pub mean_ns: u64,
    /// Fastest observed call.
    pub min_ns: u64,
    /// Slowest observed call.
    pub max_ns: u64,
    /// Median entered time (histogram estimate).
    pub p50_ns: u64,
    /// 95th percentile entered time (histogram estimate).
    pub p95_ns: u64,
    /// 99th percentile entered time (histogram estimate).
    pub p99_ns: u64,
}

/// A full profile snapshot, ordered by descending self time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanReport {
    /// Per-call-site profiles, hottest by self time first.
    pub spans: Vec<SpanProfile>,
}

impl SpanReport {
    /// Sum of self time across every call site.
    pub fn total_self_ns(&self) -> u64 {
        self.spans.iter().map(|s| s.self_ns).sum()
    }

    /// Whether any span was recorded.
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }
}

/// The process-wide span timing registry.
#[derive(Default)]
pub struct SpanTimings {
    stats: Mutex<HashMap<SpanKey, SpanStat>>,
}

static TIMINGS: OnceLock<SpanTimings> = OnceLock::new();

/// The global registry the layer writes into and reporters read from.
pub fn global() -> &'static SpanTimings {
    TIMINGS.get_or_init(SpanTimings::default)
}

impl SpanTimings {
    /// Fold one completed span observation into the registry.
    pub fn record(&self, key: SpanKey, sample: &SpanSample) {
        // A poisoned lock means another thread panicked mid-update; the
        // profile is diagnostic, so recovering beats propagating the panic.
        let mut stats = match self.stats.lock() {
            Ok(stats) => stats,
            Err(poisoned) => poisoned.into_inner(),
        };
        stats
            .entry(key)
            .or_insert_with(SpanStat::new)
            .record(sample);
    }

    /// Snapshot every call site, hottest by self time first.
    pub fn report(&self) -> SpanReport {
        let stats = match self.stats.lock() {
            Ok(stats) => stats,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut spans: Vec<SpanProfile> = stats
            .iter()
            .map(|(key, stat)| {
                let min_ns = if stat.calls == 0 { 0 } else { stat.min_busy_ns };
                // The histogram estimates within ~12%, but min and max are
                // tracked exactly. Clamping to them keeps a percentile from
                // reading outside the observed range -- most visibly a p95
                // below max on a single sample.
                let quantile = |q: f64| {
                    stat.hist
                        .quantile(q)
                        .unwrap_or(0)
                        .clamp(min_ns, stat.max_busy_ns)
                };
                SpanProfile {
                    target: key.target.to_string(),
                    name: key.name.to_string(),
                    calls: stat.calls,
                    total_ns: stat.busy_ns,
                    self_ns: stat.busy_ns.saturating_sub(stat.child_busy_ns),
                    wall_ns: stat.wall_ns,
                    mean_ns: stat.busy_ns.checked_div(stat.calls).unwrap_or(0),
                    min_ns,
                    max_ns: stat.max_busy_ns,
                    p50_ns: quantile(0.50),
                    p95_ns: quantile(0.95),
                    p99_ns: quantile(0.99),
                }
            })
            .collect();
        spans.sort_by(|a, b| {
            b.self_ns
                .cmp(&a.self_ns)
                .then_with(|| b.total_ns.cmp(&a.total_ns))
                .then_with(|| a.target.cmp(&b.target))
                .then_with(|| a.name.cmp(&b.name))
        });
        SpanReport { spans }
    }

    /// Drop every recorded sample. Used by tests and by long-running callers
    /// that report per interval.
    pub fn reset(&self) {
        let mut stats = match self.stats.lock() {
            Ok(stats) => stats,
            Err(poisoned) => poisoned.into_inner(),
        };
        stats.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(busy_ns: u64, child_busy_ns: u64) -> SpanSample {
        SpanSample {
            busy_ns,
            child_busy_ns,
            wall_ns: busy_ns,
        }
    }

    fn key(name: &'static str) -> SpanKey {
        SpanKey {
            target: "mvm_core::test",
            name,
        }
    }

    #[test]
    fn empty_registry_reports_nothing() {
        let t = SpanTimings::default();
        let report = t.report();
        assert!(report.is_empty());
        assert_eq!(report.total_self_ns(), 0);
    }

    #[test]
    fn record_accumulates_calls_and_totals() {
        let t = SpanTimings::default();
        t.record(key("build"), &sample(1_000, 0));
        t.record(key("build"), &sample(3_000, 0));

        let report = t.report();
        assert_eq!(report.spans.len(), 1);
        let profile = &report.spans[0];
        assert_eq!(profile.name, "build");
        assert_eq!(profile.calls, 2);
        assert_eq!(profile.total_ns, 4_000);
        assert_eq!(profile.mean_ns, 2_000);
        assert_eq!(profile.min_ns, 1_000);
        assert_eq!(profile.max_ns, 3_000);
    }

    #[test]
    fn self_time_excludes_nested_child_time() {
        let t = SpanTimings::default();
        // A 10ms call that spent 9ms inside an instrumented child.
        t.record(key("parent"), &sample(10_000_000, 9_000_000));

        let profile = &t.report().spans[0];
        assert_eq!(profile.total_ns, 10_000_000);
        assert_eq!(profile.self_ns, 1_000_000);
    }

    #[test]
    fn report_is_sorted_by_self_time_descending() {
        let t = SpanTimings::default();
        t.record(key("cheap"), &sample(1_000, 0));
        t.record(key("expensive"), &sample(9_000, 0));
        t.record(key("middling"), &sample(5_000, 0));

        let report = t.report();
        let names: Vec<&str> = report.spans.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["expensive", "middling", "cheap"]);
    }

    #[test]
    fn a_hot_parent_ranks_below_the_child_doing_the_work() {
        let t = SpanTimings::default();
        // The classic profiling trap: the parent has the largest total but the
        // child is where the time actually goes.
        t.record(key("orchestrate"), &sample(10_000_000, 9_500_000));
        t.record(key("hash_layer"), &sample(9_500_000, 0));

        let report = t.report();
        assert_eq!(report.spans[0].name, "hash_layer");
        assert_eq!(report.spans[1].name, "orchestrate");
        assert_eq!(report.total_self_ns(), 10_000_000);
    }

    #[test]
    fn distinct_targets_with_the_same_name_stay_separate() {
        let t = SpanTimings::default();
        t.record(
            SpanKey {
                target: "mvm_fs::oci",
                name: "start",
            },
            &sample(1_000, 0),
        );
        t.record(
            SpanKey {
                target: "mvm_runtime::vm",
                name: "start",
            },
            &sample(2_000, 0),
        );

        let report = t.report();
        assert_eq!(report.spans.len(), 2);
    }

    #[test]
    fn reset_clears_recorded_samples() {
        let t = SpanTimings::default();
        t.record(key("build"), &sample(1_000, 0));
        assert!(!t.report().is_empty());
        t.reset();
        assert!(t.report().is_empty());
    }

    #[test]
    fn child_time_exceeding_busy_saturates_to_zero_self_time() {
        // Clock skew across threads must not underflow the subtraction.
        let t = SpanTimings::default();
        t.record(key("odd"), &sample(1_000, 5_000));
        assert_eq!(t.report().spans[0].self_ns, 0);
    }

    #[test]
    fn percentiles_are_populated_from_recorded_samples() {
        let t = SpanTimings::default();
        for ns in 1..=100u64 {
            t.record(key("varied"), &sample(ns * 1_000_000, 0));
        }
        let profile = &t.report().spans[0];
        assert!(profile.p50_ns > 0);
        assert!(profile.p50_ns < profile.p95_ns);
        assert!(profile.p95_ns <= profile.p99_ns);
        assert!(profile.p99_ns <= profile.max_ns);
    }

    #[test]
    fn percentiles_stay_within_the_observed_min_and_max() {
        // The histogram estimates within a bucket; min/max are exact. A p95
        // reading above max (or a p50 below min) is a bucket artifact, not a
        // measurement, and would misread as a real tail.
        let t = SpanTimings::default();
        t.record(key("single"), &sample(696_800_000, 0));

        let profile = &t.report().spans[0];
        assert_eq!(profile.calls, 1);
        for (label, value) in [
            ("p50", profile.p50_ns),
            ("p95", profile.p95_ns),
            ("p99", profile.p99_ns),
        ] {
            assert!(
                value >= profile.min_ns && value <= profile.max_ns,
                "{label} = {value} outside [{}, {}]",
                profile.min_ns,
                profile.max_ns
            );
        }
    }

    #[test]
    fn a_single_sample_reports_identical_percentiles_min_and_max() {
        let t = SpanTimings::default();
        t.record(key("once"), &sample(5_000_000, 0));

        let profile = &t.report().spans[0];
        assert_eq!(profile.min_ns, 5_000_000);
        assert_eq!(profile.max_ns, 5_000_000);
        assert_eq!(profile.p50_ns, 5_000_000);
        assert_eq!(profile.p99_ns, 5_000_000);
    }

    #[test]
    fn report_round_trips_through_json() {
        let t = SpanTimings::default();
        t.record(key("build"), &sample(1_000, 0));
        let report = t.report();
        let json = serde_json::to_string(&report).expect("serialize");
        let back: SpanReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, back);
    }
}
