//! Span-duration profiling built on `#[instrument]`.
//!
//! `tracing` does not time spans on its own: an `#[instrument]` attribute only
//! declares a span, and unless some layer subscribes to that span's close event
//! nothing measures it. This module supplies that layer, the process-wide
//! aggregation behind it, and the report rendering, so the attributes already
//! scattered through the workspace produce a profile instead of nothing.
//!
//! Profiling is off unless `MVM_SPAN_TIMINGS` is set, and when off the layer is
//! never installed, so the cost is the unchanged cost of a disabled span.
//!
//! # Limits
//!
//! Self time is computed by attributing a closing span's busy time to its
//! immediate parent. A span that the timing filter excludes is not tracked, so
//! an excluded span sitting between two tracked ones breaks the chain and
//! inflates the outer span's self time. The default filter covers every `mvm`
//! target, which keeps the chain intact for workspace code; narrowing
//! [`ENV_FILTER`] trades that guarantee for less measurement overhead.
//!
//! Recording takes a process-wide lock on span close. That is adequate for the
//! coarse, entry-point-level instrumentation this is meant for, and would not
//! be for instrumenting a per-item inner loop.

mod histogram;
mod layer;
mod registry;

use std::fmt::Write as _;

pub use histogram::LogHistogram;
pub use layer::SpanTimingLayer;
pub use registry::{SpanKey, SpanProfile, SpanReport, SpanSample, SpanTimings, global};

/// Environment variable enabling profiling and selecting the report format.
pub const ENV_ENABLE: &str = "MVM_SPAN_TIMINGS";
/// Environment variable choosing a report destination file instead of stderr.
pub const ENV_OUT: &str = "MVM_SPAN_TIMINGS_OUT";
/// Environment variable overriding which targets are timed.
pub const ENV_FILTER: &str = "MVM_SPAN_TIMINGS_FILTER";

/// Targets timed when [`ENV_FILTER`] is unset.
///
/// `trace` rather than `info` so that a span declared at any level is measured;
/// the whole point is to observe spans the log filter would drop.
pub const DEFAULT_FILTER: &str = "mvm=trace";

/// How a profile should be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// Aligned, human-readable table.
    Text,
    /// A single JSON object, for diffing runs or feeding a dashboard.
    Json,
}

/// Parse the value of [`ENV_ENABLE`] into a format, or `None` when disabled.
///
/// Unset, empty, `0`, `off`, `false`, and `no` all disable profiling.
/// `1`, `on`, `true`, `yes`, and `text` select the table; `json` selects JSON.
/// Anything else is treated as enabled-with-table rather than failing, since a
/// typo in a profiling knob should not take down the command being profiled.
pub fn format_from_env_value(value: Option<&str>) -> Option<ReportFormat> {
    let value = value?.trim();
    match value.to_ascii_lowercase().as_str() {
        "" | "0" | "off" | "false" | "no" => None,
        "json" => Some(ReportFormat::Json),
        _ => Some(ReportFormat::Text),
    }
}

/// The configured report format for this process, or `None` when disabled.
pub fn format_from_env() -> Option<ReportFormat> {
    format_from_env_value(std::env::var(ENV_ENABLE).ok().as_deref())
}

/// Whether span profiling is enabled for this process.
pub fn is_enabled() -> bool {
    format_from_env().is_some()
}

/// The target filter to install on the timing layer.
pub fn filter_from_env() -> String {
    std::env::var(ENV_FILTER)
        .ok()
        .filter(|f| !f.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_FILTER.to_string())
}

/// Render a duration in nanoseconds with a human-scaled unit.
pub fn format_ns(ns: u64) -> String {
    const US: u64 = 1_000;
    const MS: u64 = 1_000_000;
    const S: u64 = 1_000_000_000;
    match ns {
        n if n < US => format!("{n}ns"),
        n if n < MS => format!("{:.1}us", n as f64 / US as f64),
        n if n < S => format!("{:.1}ms", n as f64 / MS as f64),
        n => format!("{:.2}s", n as f64 / S as f64),
    }
}

/// Render a report as an aligned table, hottest call site first.
pub fn render_text(report: &SpanReport) -> String {
    if report.is_empty() {
        return "no spans recorded (is the timing layer installed?)\n".to_string();
    }

    let total_self = report.total_self_ns();
    let name_width = report
        .spans
        .iter()
        .map(|s| s.name.len())
        .max()
        .unwrap_or(4)
        .clamp(4, 48);

    let mut out = String::with_capacity(128 * report.spans.len());
    let _ = writeln!(
        out,
        "{:<name_width$}  {:>7}  {:>10}  {:>6}  {:>10}  {:>10}  {:>10}  {:>10}",
        "span", "calls", "self", "self%", "total", "mean", "p95", "max",
    );
    let _ = writeln!(out, "{}", "-".repeat(name_width + 76));

    for span in &report.spans {
        let share = if total_self == 0 {
            0.0
        } else {
            span.self_ns as f64 * 100.0 / total_self as f64
        };
        let name: String = span.name.chars().take(name_width).collect();
        let _ = writeln!(
            out,
            "{:<name_width$}  {:>7}  {:>10}  {:>5.1}%  {:>10}  {:>10}  {:>10}  {:>10}",
            name,
            span.calls,
            format_ns(span.self_ns),
            share,
            format_ns(span.total_ns),
            format_ns(span.mean_ns),
            format_ns(span.p95_ns),
            format_ns(span.max_ns),
        );
    }

    let _ = writeln!(
        out,
        "\n{} span(s), {} total self time. \
         self = time in this function excluding nested instrumented calls.",
        report.spans.len(),
        format_ns(total_self),
    );
    out
}

/// Render a report in the configured format.
pub fn render(report: &SpanReport, format: ReportFormat) -> String {
    match format {
        ReportFormat::Text => render_text(report),
        // A profile that cannot be serialized is a bug worth surfacing, but not
        // one worth aborting the profiled command over.
        ReportFormat::Json => match serde_json::to_string_pretty(report) {
            Ok(json) => format!("{json}\n"),
            Err(err) => format!("{{\"error\":\"failed to serialize span report: {err}\"}}\n"),
        },
    }
}

/// Write the process-wide profile to the configured destination.
///
/// A no-op when profiling is disabled. Called once at the end of a run; safe to
/// call when nothing was recorded. Reporting failures are written to stderr
/// rather than propagated, since the profile is diagnostic output.
pub fn emit_report() {
    let Some(format) = format_from_env() else {
        return;
    };
    let rendered = render(&global().report(), format);
    match std::env::var(ENV_OUT).ok().filter(|p| !p.trim().is_empty()) {
        Some(path) => {
            if let Err(err) = std::fs::write(&path, rendered.as_bytes()) {
                eprintln!("span timings: failed to write {path}: {err}");
            }
        }
        None => eprint!("{rendered}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, calls: u64, self_ns: u64, total_ns: u64) -> SpanProfile {
        SpanProfile {
            target: "mvm_core::test".to_string(),
            name: name.to_string(),
            calls,
            total_ns,
            self_ns,
            wall_ns: total_ns,
            mean_ns: total_ns / calls.max(1),
            min_ns: 1,
            max_ns: total_ns,
            p50_ns: total_ns / calls.max(1),
            p95_ns: total_ns,
            p99_ns: total_ns,
        }
    }

    #[test]
    fn env_value_disables_on_falsey_and_unset() {
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("off"),
            Some("false"),
            Some("no"),
        ] {
            assert_eq!(format_from_env_value(value), None, "value = {value:?}");
        }
    }

    #[test]
    fn env_value_selects_text_or_json() {
        assert_eq!(format_from_env_value(Some("1")), Some(ReportFormat::Text));
        assert_eq!(
            format_from_env_value(Some("text")),
            Some(ReportFormat::Text)
        );
        assert_eq!(
            format_from_env_value(Some("json")),
            Some(ReportFormat::Json)
        );
        assert_eq!(
            format_from_env_value(Some("JSON")),
            Some(ReportFormat::Json)
        );
    }

    #[test]
    fn env_value_is_whitespace_and_case_tolerant() {
        assert_eq!(
            format_from_env_value(Some("  json  ")),
            Some(ReportFormat::Json)
        );
        assert_eq!(format_from_env_value(Some(" OFF ")), None);
    }

    #[test]
    fn unrecognized_env_value_enables_rather_than_failing() {
        assert_eq!(
            format_from_env_value(Some("tabel")),
            Some(ReportFormat::Text)
        );
    }

    #[test]
    fn format_ns_scales_units() {
        assert_eq!(format_ns(999), "999ns");
        assert_eq!(format_ns(1_500), "1.5us");
        assert_eq!(format_ns(2_500_000), "2.5ms");
        assert_eq!(format_ns(3_000_000_000), "3.00s");
    }

    #[test]
    fn render_text_reports_the_empty_case_explicitly() {
        let out = render_text(&SpanReport { spans: vec![] });
        assert!(out.contains("no spans recorded"), "{out}");
    }

    #[test]
    fn render_text_lists_spans_with_share_of_total() {
        let report = SpanReport {
            spans: vec![
                profile("hash_layer", 4, 7_500_000, 7_500_000),
                profile("unpack", 1, 2_500_000, 2_500_000),
            ],
        };
        let out = render_text(&report);
        assert!(out.contains("hash_layer"), "{out}");
        assert!(out.contains("unpack"), "{out}");
        assert!(out.contains("75.0%"), "{out}");
        assert!(out.contains("25.0%"), "{out}");
        assert!(out.contains("2 span(s)"), "{out}");
    }

    #[test]
    fn render_text_survives_a_zero_duration_report() {
        // Guards the percentage divide when every span was too fast to measure.
        let report = SpanReport {
            spans: vec![profile("instant", 1, 0, 0)],
        };
        let out = render_text(&report);
        assert!(out.contains("instant"), "{out}");
        assert!(out.contains("0.0%"), "{out}");
    }

    #[test]
    fn render_text_truncates_an_overlong_span_name() {
        let long = "a".repeat(200);
        let report = SpanReport {
            spans: vec![profile(&long, 1, 1_000, 1_000)],
        };
        let out = render_text(&report);
        // 48-column clamp keeps the table aligned regardless of name length.
        assert!(out.lines().all(|l| l.len() < 160), "{out}");
    }

    #[test]
    fn render_json_emits_a_parseable_report() {
        let report = SpanReport {
            spans: vec![profile("build", 2, 1_000, 2_000)],
        };
        let out = render(&report, ReportFormat::Json);
        let back: SpanReport = serde_json::from_str(&out).expect("valid json");
        assert_eq!(back, report);
    }

    #[test]
    fn filter_default_covers_mvm_targets_at_trace() {
        assert_eq!(DEFAULT_FILTER, "mvm=trace");
        assert!(DEFAULT_FILTER.contains("trace"));
    }
}
