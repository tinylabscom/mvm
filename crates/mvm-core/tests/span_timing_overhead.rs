//! Measures what the span-timing layer costs per span, single-threaded and
//! under contention.
//!
//! The registry serialises on one lock at span close. Whether that is
//! acceptable is a question about a number, not a matter of opinion, so the
//! number is measured here rather than asserted in prose. Run with
//! `--nocapture` to read the measurements:
//!
//! ```text
//! cargo test -p mvm-core --test span_timing_overhead -- --nocapture
//! ```
//!
//! The assertions are deliberately loose. They exist to catch a pathological
//! regression — a deadlock, or per-record work that grows with the number of
//! recorded spans — not to pin a performance number on a shared CI box.

use std::thread;
use std::time::Instant;

use mvm_core::observability::span_timing::{SpanTimingLayer, SpanTimings};
use tracing::dispatcher::{self, Dispatch};
use tracing::instrument;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

/// Spans recorded per thread in each measurement.
const SPANS_PER_THREAD: u32 = 20_000;

/// Ceiling per recorded span. Generous by design: a loaded CI box is slow, but
/// nothing healthy is anywhere near this.
const MAX_NS_PER_SPAN: u128 = 100_000;

#[instrument(target = "mvm_core::overhead_fixture")]
fn measured(i: u32) -> u32 {
    i.wrapping_add(1)
}

fn registry() -> &'static SpanTimings {
    Box::leak(Box::new(SpanTimings::default()))
}

fn dispatch_for(registry: &'static SpanTimings) -> Dispatch {
    Dispatch::new(
        tracing_subscriber::registry().with(
            SpanTimingLayer::with_registry(registry).with_filter(EnvFilter::new("mvm=trace")),
        ),
    )
}

/// Drive `SPANS_PER_THREAD * threads` spans and return nanoseconds per span.
fn measure(threads: usize, registry: &'static SpanTimings) -> u128 {
    let dispatch = dispatch_for(registry);
    let start = Instant::now();

    thread::scope(|scope| {
        for _ in 0..threads {
            let dispatch = dispatch.clone();
            scope.spawn(move || {
                dispatcher::with_default(&dispatch, || {
                    for i in 0..SPANS_PER_THREAD {
                        std::hint::black_box(measured(std::hint::black_box(i)));
                    }
                });
            });
        }
    });

    let total = SPANS_PER_THREAD as u128 * threads as u128;
    start.elapsed().as_nanos() / total
}

#[test]
fn single_threaded_overhead_per_span_is_bounded() {
    let registry = registry();
    let ns = measure(1, registry);
    println!("span timing overhead: {ns} ns/span (1 thread)");

    assert_eq!(
        registry.report().spans.len(),
        1,
        "all calls should fold into one call site"
    );
    assert_eq!(registry.report().spans[0].calls, SPANS_PER_THREAD as u64);
    assert!(ns < MAX_NS_PER_SPAN, "{ns} ns/span exceeds the ceiling");
}

#[test]
fn contended_overhead_per_span_is_bounded() {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get().clamp(2, 8))
        .unwrap_or(4);

    let registry = registry();
    let ns = measure(threads, registry);
    println!("span timing overhead: {ns} ns/span ({threads} threads)");

    let report = registry.report();
    assert_eq!(report.spans.len(), 1);
    assert_eq!(
        report.spans[0].calls,
        SPANS_PER_THREAD as u64 * threads as u64,
        "every thread's spans must be recorded exactly once"
    );
    assert!(ns < MAX_NS_PER_SPAN, "{ns} ns/span exceeds the ceiling");
}

#[test]
fn recording_cost_does_not_grow_with_the_number_of_recorded_spans() {
    // The failure this guards is a registry whose per-record work is linear in
    // what it already holds; that would make a long run quadratic and would not
    // show up in a short one.
    let registry = registry();
    let first = measure(1, registry);
    let second = measure(1, registry);
    println!("span timing overhead: first {first} ns/span, second {second} ns/span (1 thread)");

    assert_eq!(
        registry.report().spans[0].calls,
        SPANS_PER_THREAD as u64 * 2
    );
    // Wall-clock noise on a shared box is large, so this only catches growth of
    // a different order, not a few percent of drift.
    assert!(
        second < first.max(1) * 8 + 10_000,
        "second pass {second} ns/span ballooned against first {first} ns/span"
    );
}

#[test]
fn a_disabled_layer_records_nothing_and_stays_cheap() {
    // The off path is what every non-profiling run pays, so it gets its own
    // measurement rather than being assumed free.
    let registry = registry();
    let dispatch = Dispatch::new(
        tracing_subscriber::registry()
            .with(SpanTimingLayer::with_registry(registry).with_filter(EnvFilter::new("mvm=off"))),
    );

    let start = Instant::now();
    dispatcher::with_default(&dispatch, || {
        for i in 0..SPANS_PER_THREAD {
            std::hint::black_box(measured(std::hint::black_box(i)));
        }
    });
    let ns = start.elapsed().as_nanos() / SPANS_PER_THREAD as u128;
    println!("span timing overhead: {ns} ns/span (layer filtered off)");

    assert!(
        registry.report().is_empty(),
        "a filtered-off layer must record nothing"
    );
    assert!(ns < MAX_NS_PER_SPAN, "{ns} ns/span exceeds the ceiling");
}
