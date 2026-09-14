use std::path::Path;

use tracing::Subscriber;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

use mvm_core::observability::span_timing;

use crate::otlp;
use crate::span_timing_layer::SpanTimingLayer;

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

/// Keeps process-lifetime observability resources alive.
///
/// Today that is the OTLP export thread, when one is configured: dropping the
/// guard flushes queued spans, waiting at most the configured export timeout.
/// Bind it in `main` (or the function that returns to it) so the flush runs
/// as the program ends. `std::process::exit` skips destructors, so a path that
/// exits that way loses any spans still queued.
#[must_use = "dropping the guard immediately stops trace export"]
#[derive(Debug, Default)]
pub struct ObservabilityGuard {
    _otlp: Option<otlp::ExportGuard>,
}

/// Initialize the global tracing subscriber.
///
/// Call once at program startup. Respects `RUST_LOG` for filtering, falling
/// back to [`DEFAULT_FILTER`].
pub fn init(format: LogFormat) -> ObservabilityGuard {
    init_with_filter(format, DEFAULT_FILTER)
}

/// Initialize the global tracing subscriber with an explicit fallback filter.
///
/// The log filter is attached to the formatting layer rather than to the
/// registry, so that the span-timing and OTLP layers can carry their own,
/// wider filters. A registry-wide filter would suppress span *construction*,
/// and an unconstructed span can be neither measured nor exported — which is
/// why `#[instrument]` alone yields no timings.
///
/// OTLP export is installed only when an endpoint is configured; see
/// [`otlp::config`]. A configuration that cannot be honoured — cleartext to a
/// remote host, a malformed header — is reported once on stderr and export
/// stays off; it never stops the program.
pub fn init_with_filter(format: LogFormat, fallback_filter: &str) -> ObservabilityGuard {
    let logs = format_layer(format).with_filter(log_filter(fallback_filter));
    let timings = span_timing::format_from_env().map(|_| span_timing_layer());
    let (otlp_layer, otlp_guard) = match otlp_export(&service_name()) {
        Some((layer, guard)) => (Some(layer), Some(guard)),
        None => (None, None),
    };

    tracing_subscriber::registry()
        .with(logs)
        .with(timings)
        .with(otlp_layer)
        .init();

    ObservabilityGuard { _otlp: otlp_guard }
}

/// The default `service.name`: the running executable's file name, so each
/// binary that links this crate reports as itself.
fn service_name() -> String {
    std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(Path::file_stem)
        .and_then(|stem| stem.to_str())
        .map_or_else(|| "mvm".to_string(), str::to_string)
}

/// The OTLP layer with its filter and the guard that flushes it, or `None`
/// when export is not configured or cannot start.
fn otlp_export<S>(
    service_name: &str,
) -> Option<(
    tracing_subscriber::filter::Filtered<otlp::OtlpLayer, EnvFilter, S>,
    otlp::ExportGuard,
)>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let config = match otlp::OtlpConfig::from_env(service_name) {
        Ok(Some(config)) => config,
        Ok(None) => return None,
        Err(error) => {
            eprintln!("otlp: trace export disabled: {error}");
            return None;
        }
    };
    let (layer, guard) = match otlp::spawn_exporter(&config) {
        Ok(started) => started,
        Err(error) => {
            eprintln!("otlp: trace export disabled: {error}");
            return None;
        }
    };
    Some((layer.with_filter(otlp_filter(config.filter())), guard))
}

fn otlp_filter(directives: &str) -> EnvFilter {
    EnvFilter::try_new(directives).unwrap_or_else(|_| {
        eprintln!(
            "otlp: invalid {} '{directives}', using '{}'",
            otlp::config::ENV_FILTER,
            otlp::config::DEFAULT_FILTER
        );
        EnvFilter::new(otlp::config::DEFAULT_FILTER)
    })
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
    fn an_unparseable_otlp_filter_falls_back_to_the_default() {
        let filter = otlp_filter("!!!not a filter!!!");
        assert_eq!(format!("{filter}"), otlp::config::DEFAULT_FILTER);
    }

    #[test]
    fn the_default_service_name_is_the_running_executable() {
        let name = service_name();
        assert!(!name.is_empty());
        assert!(!name.contains('/'), "{name}");
    }

    #[test]
    fn default_filter_keeps_mvm_at_info() {
        assert_eq!(DEFAULT_FILTER, "mvm=info,warn");
    }
}
