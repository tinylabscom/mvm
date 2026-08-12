use tracing::Subscriber;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

use super::span_timing::{self, SpanTimingLayer};

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable colored output (for interactive CLI use).
    Human,
    /// Structured JSON output (for daemon/agent mode).
    Json,
}

/// Filter applied when `RUST_LOG` is unset and no caller override is given.
pub const DEFAULT_FILTER: &str = "mvm=info,warn";

/// Build the formatting layer for `format`.
///
/// Boxed so the two output shapes share one layer-stack assembly path instead
/// of duplicating it per format.
fn format_layer<S>(format: LogFormat) -> Box<dyn tracing_subscriber::Layer<S> + Send + Sync>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    match format {
        LogFormat::Human => Box::new(
            fmt::layer()
                .with_target(false)
                .with_thread_ids(false)
                .compact(),
        ),
        LogFormat::Json => Box::new(fmt::layer().json().with_target(true)),
    }
}

/// Resolve the log filter: `RUST_LOG` wins, then `fallback`.
fn log_filter(fallback: &str) -> EnvFilter {
    EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::try_new(fallback).unwrap_or_else(|_| EnvFilter::new("warn")))
}

/// Initialize the global tracing subscriber.
///
/// Call once at program startup. Respects `RUST_LOG` for filtering, falling
/// back to [`DEFAULT_FILTER`].
pub fn init(format: LogFormat) {
    init_with_filter(format, DEFAULT_FILTER);
}

/// Initialize the global tracing subscriber with an explicit fallback filter.
///
/// The log filter is attached to the formatting layer rather than to the
/// registry, so that the span-timing layer can carry its own, wider filter.
/// A registry-wide filter would suppress span *construction*, and an
/// unconstructed span cannot be measured — which is why `#[instrument]` alone
/// yields no timings.
pub fn init_with_filter(format: LogFormat, fallback_filter: &str) {
    let logs = format_layer(format).with_filter(log_filter(fallback_filter));
    let registry = tracing_subscriber::registry().with(logs);

    match span_timing::format_from_env() {
        Some(_) => registry.with(span_timing_layer()).init(),
        None => registry.init(),
    }
}

/// The span-timing layer with its configured target filter.
fn span_timing_layer<S>() -> impl tracing_subscriber::Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let directives = span_timing::filter_from_env();
    let filter = EnvFilter::try_new(&directives).unwrap_or_else(|_| {
        eprintln!(
            "span timings: invalid {} '{directives}', using '{}'",
            span_timing::ENV_FILTER,
            span_timing::DEFAULT_FILTER
        );
        EnvFilter::new(span_timing::DEFAULT_FILTER)
    });
    SpanTimingLayer::new().with_filter(filter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_format_equality() {
        assert_eq!(LogFormat::Human, LogFormat::Human);
        assert_eq!(LogFormat::Json, LogFormat::Json);
        assert_ne!(LogFormat::Human, LogFormat::Json);
    }

    #[test]
    fn log_filter_prefers_the_supplied_fallback_over_a_hardcoded_one() {
        // RUST_LOG is process-global; this asserts the fallback path only,
        // which is the branch callers control.
        let filter = log_filter("mvm=debug");
        assert!(format!("{filter}").contains("debug"));
    }

    #[test]
    fn log_filter_recovers_from_an_unparseable_fallback() {
        // An invalid fallback must not panic the program being logged.
        let filter = log_filter("!!!not a filter!!!");
        assert!(!format!("{filter}").is_empty());
    }

    #[test]
    fn default_filter_keeps_mvm_at_info() {
        assert_eq!(DEFAULT_FILTER, "mvm=info,warn");
    }
}
