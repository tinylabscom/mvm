//! The `tracing` layer that turns `#[instrument]` spans into timing samples.

use std::time::Instant;

use tracing::Subscriber;
use tracing::span::{Attributes, Id};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use mvm_core::observability::span_timing::{SpanKey, SpanSample, SpanTimings};

/// Per-span state held in the registry's span extensions.
struct Timings {
    created: Instant,
    /// Nanoseconds this span has been entered.
    busy_ns: u64,
    /// Nanoseconds attributed upward by nested spans that have closed.
    child_busy_ns: u64,
    /// Set while the span is entered.
    entered_at: Option<Instant>,
}

impl Timings {
    fn new() -> Self {
        Self {
            created: Instant::now(),
            busy_ns: 0,
            child_busy_ns: 0,
            entered_at: None,
        }
    }
}

/// Records the duration of every span it is enabled for.
///
/// Attach it with a per-layer filter so that spans are created even when the
/// log filter would otherwise suppress them — `tracing` skips span
/// construction entirely if no layer is interested, so the filter, not the
/// `#[instrument]` attribute, decides whether a measurement happens at all.
pub struct SpanTimingLayer {
    timings: &'static SpanTimings,
}

impl SpanTimingLayer {
    /// A layer writing into the process-wide registry.
    pub fn new() -> Self {
        Self {
            timings: mvm_core::observability::span_timing::global(),
        }
    }

    /// A layer writing into a caller-supplied registry, for tests.
    pub fn with_registry(timings: &'static SpanTimings) -> Self {
        Self { timings }
    }
}

impl Default for SpanTimingLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for SpanTimingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, _attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        span.extensions_mut().insert(Timings::new());
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        if let Some(timings) = span.extensions_mut().get_mut::<Timings>() {
            timings.entered_at = Some(Instant::now());
        }
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        if let Some(timings) = span.extensions_mut().get_mut::<Timings>()
            && let Some(entered) = timings.entered_at.take()
        {
            timings.busy_ns += entered.elapsed().as_nanos() as u64;
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };

        let (busy_ns, child_busy_ns, wall_ns) = {
            let mut extensions = span.extensions_mut();
            let Some(timings) = extensions.get_mut::<Timings>() else {
                return;
            };
            // A span closed while still entered (an early return inside the
            // guard's scope is not possible, but a leaked guard is) would
            // otherwise lose its final interval.
            if let Some(entered) = timings.entered_at.take() {
                timings.busy_ns += entered.elapsed().as_nanos() as u64;
            }
            (
                timings.busy_ns,
                timings.child_busy_ns,
                timings.created.elapsed().as_nanos() as u64,
            )
        };

        self.timings.record(
            SpanKey {
                target: span.metadata().target(),
                name: span.metadata().name(),
            },
            &SpanSample {
                busy_ns,
                child_busy_ns,
                wall_ns,
            },
        );

        // Attribute this span's time to its parent so the parent can report
        // self time. Done after the child's own extensions borrow is released.
        if let Some(parent) = span.parent()
            && let Some(parent_timings) = parent.extensions_mut().get_mut::<Timings>()
        {
            parent_timings.child_busy_ns += busy_ns;
        }
    }
}
