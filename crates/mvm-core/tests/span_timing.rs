//! End-to-end checks that `#[instrument]` attributes actually produce timings.
//!
//! The regression these guard against is the one that made the attributes
//! already in the tree inert: spans that are never constructed, because no
//! installed layer was interested in them, cannot be measured.

use std::thread::sleep;
use std::time::Duration;

use mvm_core::observability::span_timing::{SpanReport, SpanTimingLayer, SpanTimings};
use tracing::instrument;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

/// The target every fixture span reports under. It must share the `mvm` prefix
/// with real workspace crates so the default timing filter applies.
const TARGET: &str = "mvm_core::span_timing_fixture";

#[instrument(target = "mvm_core::span_timing_fixture")]
fn leaf(millis: u64) {
    sleep(Duration::from_millis(millis));
}

#[instrument(target = "mvm_core::span_timing_fixture")]
fn parent_calling_leaf() {
    sleep(Duration::from_millis(5));
    leaf(20);
}

#[instrument(target = "mvm_core::span_timing_fixture", level = "trace")]
fn trace_level_work() {
    sleep(Duration::from_millis(1));
}

/// A fresh registry per test; integration tests share one process, so a global
/// would let concurrent tests contaminate each other's assertions.
fn fresh_registry() -> &'static SpanTimings {
    Box::leak(Box::new(SpanTimings::default()))
}

/// Run `body` against a subscriber whose *log* filter is `log_filter` and whose
/// *timing* filter is `timing_filter`.
fn profile_with_filters(
    log_filter: &str,
    timing_filter: &str,
    body: impl FnOnce(),
) -> (SpanReport, &'static SpanTimings) {
    let registry = fresh_registry();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(EnvFilter::new(log_filter)))
        .with(SpanTimingLayer::with_registry(registry).with_filter(EnvFilter::new(timing_filter)));

    tracing::subscriber::with_default(subscriber, body);
    (registry.report(), registry)
}

fn profile(body: impl FnOnce()) -> SpanReport {
    profile_with_filters("error", "mvm=trace", body).0
}

fn find<'a>(
    report: &'a SpanReport,
    name: &str,
) -> &'a mvm_core::observability::span_timing::SpanProfile {
    report
        .spans
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| {
            panic!(
                "no span named {name}; recorded: {:?}",
                report.spans.iter().map(|s| &s.name).collect::<Vec<_>>()
            )
        })
}

#[test]
fn instrumented_function_is_timed_despite_a_quiet_log_filter() {
    // This is the CLI's default posture: RUST_LOG unset, no -v, so logs are
    // filtered at `error` while `#[instrument]` spans default to INFO.
    let report = profile(|| leaf(20));

    let leaf = find(&report, "leaf");
    assert_eq!(leaf.calls, 1);
    assert_eq!(leaf.target, TARGET);
    assert!(
        leaf.self_ns >= Duration::from_millis(15).as_nanos() as u64,
        "expected ~20ms, got {}ns",
        leaf.self_ns
    );
}

#[test]
fn a_registry_wide_filter_suppresses_span_construction_and_yields_no_timings() {
    // Documents why the layer stack attaches the log filter to the fmt layer
    // instead of to the registry. With a registry-wide filter the span is never
    // constructed, so no layer -- however wide its own filter -- can time it.
    // This was the arrangement that left the workspace's existing
    // `#[instrument]` attributes producing nothing.
    let registry = fresh_registry();
    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::new("error"))
        .with(SpanTimingLayer::with_registry(registry).with_filter(EnvFilter::new("mvm=trace")));

    tracing::subscriber::with_default(subscriber, || leaf(5));

    assert!(
        registry.report().is_empty(),
        "a registry-wide filter should suppress the span entirely, got {:?}",
        registry.report().spans
    );
}

#[test]
fn a_span_below_the_timing_filter_is_not_recorded() {
    // The timing layer's filter, not the attribute, decides what is measured.
    let report = profile_with_filters("error", "mvm=off", || leaf(5)).0;
    assert!(
        report.is_empty(),
        "expected nothing recorded, got {:?}",
        report.spans
    );
}

#[test]
fn a_non_matching_target_is_not_recorded() {
    let report = profile_with_filters("error", "some_other_crate=trace", || leaf(5)).0;
    assert!(report.is_empty(), "got {:?}", report.spans);
}

#[test]
fn trace_level_spans_are_timed_even_though_logs_stop_at_error() {
    let report = profile(trace_level_work);
    assert_eq!(find(&report, "trace_level_work").calls, 1);
}

#[test]
fn repeated_calls_accumulate_into_one_row() {
    let report = profile(|| {
        for _ in 0..3 {
            leaf(2);
        }
    });

    let leaf = find(&report, "leaf");
    assert_eq!(leaf.calls, 3);
    assert_eq!(report.spans.len(), 1, "calls must fold into a single row");
    assert!(
        leaf.total_ns >= leaf.max_ns,
        "total must cover the slowest call"
    );
    assert!(leaf.min_ns <= leaf.max_ns);
}

#[test]
fn nested_spans_attribute_self_time_to_the_function_doing_the_work() {
    // parent sleeps 5ms itself and calls a leaf that sleeps 20ms.
    let report = profile(parent_calling_leaf);

    let parent = find(&report, "parent_calling_leaf");
    let leaf = find(&report, "leaf");

    // The parent's *total* includes the leaf; its *self* time does not.
    assert!(
        parent.total_ns > leaf.total_ns,
        "parent total {} should exceed leaf total {}",
        parent.total_ns,
        leaf.total_ns
    );
    assert!(
        parent.self_ns < leaf.self_ns,
        "parent self {} should be below leaf self {}",
        parent.self_ns,
        leaf.self_ns
    );

    // Ranking by self time must therefore surface the leaf first.
    assert_eq!(
        report.spans[0].name,
        "leaf",
        "hottest-by-self-time should be the leaf, got {:?}",
        report.spans.iter().map(|s| &s.name).collect::<Vec<_>>()
    );
}

#[test]
fn self_times_sum_to_roughly_the_wall_clock_of_the_root() {
    let report = profile(parent_calling_leaf);
    let total_self = report.total_self_ns();
    let root_total = find(&report, "parent_calling_leaf").total_ns;

    // Self time partitions the root's elapsed time, so the sum should track it
    // closely rather than double-counting the nested call.
    let delta = total_self.abs_diff(root_total);
    assert!(
        delta < Duration::from_millis(10).as_nanos() as u64,
        "self-time sum {total_self} diverged from root total {root_total}"
    );
}

#[test]
fn reset_clears_state_between_profiling_runs() {
    let (report, registry) = profile_with_filters("error", "mvm=trace", || leaf(1));
    assert!(!report.is_empty());
    registry.reset();
    assert!(registry.report().is_empty());
}

#[test]
fn report_serializes_to_json_for_run_over_run_comparison() {
    let report = profile(|| leaf(1));
    let json = serde_json::to_string(&report).expect("serialize");
    assert!(json.contains("\"leaf\""), "{json}");
    let back: SpanReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, report);
}
