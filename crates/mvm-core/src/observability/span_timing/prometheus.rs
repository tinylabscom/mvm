//! Prometheus text-format rendering for a [`SpanReport`].
//!
//! The counters in [`crate::observability::metrics`] are fixed-name singletons;
//! span timings are per-call-site, so they carry `target` and `span` labels
//! instead of one metric name per function.

use std::fmt::Write as _;

use super::registry::SpanReport;

/// Nanoseconds per second, as a float divisor. Prometheus convention is base
/// units, so durations are exported in seconds rather than the nanoseconds the
/// registry accumulates.
const NANOS_PER_SEC: f64 = 1_000_000_000.0;

/// Escape a Prometheus label value: backslash, double quote, and newline.
///
/// An unescaped span name containing a quote would produce a malformed
/// exposition that breaks the whole scrape, not just the one series.
pub fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Render one metric family across every call site in the report.
fn write_family(
    out: &mut String,
    report: &SpanReport,
    name: &str,
    metric_type: &str,
    help: &str,
    value_of: impl Fn(&super::registry::SpanProfile) -> f64,
) {
    if report.is_empty() {
        return;
    }
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {metric_type}");
    for span in &report.spans {
        let _ = writeln!(
            out,
            "{name}{{target=\"{}\",span=\"{}\"}} {}",
            escape_label_value(&span.target),
            escape_label_value(&span.name),
            value_of(span),
        );
    }
}

/// Render a span profile in Prometheus text exposition format.
///
/// Returns an empty string when nothing was recorded, so a caller can append it
/// unconditionally without emitting a bare `# HELP` block for no series.
pub fn prometheus_exposition(report: &SpanReport) -> String {
    let mut out = String::with_capacity(256 * report.spans.len());

    write_family(
        &mut out,
        report,
        "mvm_span_calls_total",
        "counter",
        "Completed calls of an instrumented function",
        |s| s.calls as f64,
    );
    write_family(
        &mut out,
        report,
        "mvm_span_self_seconds_total",
        "counter",
        "Seconds spent in an instrumented function, excluding nested instrumented calls",
        |s| s.self_ns as f64 / NANOS_PER_SEC,
    );
    write_family(
        &mut out,
        report,
        "mvm_span_total_seconds_total",
        "counter",
        "Seconds spent in an instrumented function, including nested instrumented calls",
        |s| s.total_ns as f64 / NANOS_PER_SEC,
    );
    write_family(
        &mut out,
        report,
        "mvm_span_max_seconds",
        "gauge",
        "Slowest observed call of an instrumented function, in seconds",
        |s| s.max_ns as f64 / NANOS_PER_SEC,
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::span_timing::{SpanProfile, SpanReport};

    fn profile(target: &str, name: &str) -> SpanProfile {
        SpanProfile {
            target: target.to_string(),
            name: name.to_string(),
            calls: 3,
            total_ns: 2_500_000_000,
            self_ns: 1_500_000_000,
            wall_ns: 2_500_000_000,
            mean_ns: 833_333_333,
            min_ns: 1_000_000,
            max_ns: 2_000_000_000,
            p50_ns: 800_000_000,
            p95_ns: 1_900_000_000,
            p99_ns: 2_000_000_000,
        }
    }

    #[test]
    fn empty_report_renders_nothing() {
        let out = prometheus_exposition(&SpanReport { spans: vec![] });
        assert!(out.is_empty(), "{out}");
    }

    #[test]
    fn renders_every_family_with_labels() {
        let report = SpanReport {
            spans: vec![profile("mvm_fs::oci", "unpack_layer")],
        };
        let out = prometheus_exposition(&report);

        for family in [
            "mvm_span_calls_total",
            "mvm_span_self_seconds_total",
            "mvm_span_total_seconds_total",
            "mvm_span_max_seconds",
        ] {
            assert!(out.contains(&format!("# TYPE {family}")), "{family}\n{out}");
        }
        assert!(
            out.contains("mvm_span_calls_total{target=\"mvm_fs::oci\",span=\"unpack_layer\"} 3"),
            "{out}"
        );
    }

    #[test]
    fn durations_are_exported_in_seconds() {
        let report = SpanReport {
            spans: vec![profile("mvm_fs::oci", "unpack_layer")],
        };
        let out = prometheus_exposition(&report);
        // 1_500_000_000 ns == 1.5 s
        assert!(
            out.contains(
                "mvm_span_self_seconds_total{target=\"mvm_fs::oci\",span=\"unpack_layer\"} 1.5"
            ),
            "{out}"
        );
    }

    #[test]
    fn every_span_gets_a_series_in_each_family() {
        let report = SpanReport {
            spans: vec![profile("a::b", "one"), profile("c::d", "two")],
        };
        let out = prometheus_exposition(&report);
        let calls_series = out
            .lines()
            .filter(|l| l.starts_with("mvm_span_calls_total{"))
            .count();
        assert_eq!(calls_series, 2, "{out}");
    }

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape_label_value(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape_label_value(r"a\b"), r"a\\b");
        assert_eq!(escape_label_value("a\nb"), r"a\nb");
        assert_eq!(escape_label_value("plain"), "plain");
    }

    #[test]
    fn a_span_name_with_a_quote_cannot_break_the_exposition() {
        // A malformed line would break the entire scrape, not just this series.
        let mut p = profile("mvm::t", r#"weird"name"#);
        p.calls = 1;
        let out = prometheus_exposition(&SpanReport { spans: vec![p] });
        assert!(out.contains(r#"span="weird\"name""#), "{out}");
        for line in out.lines().filter(|l| !l.starts_with('#')) {
            // Exactly one unescaped quote pair per label, so four in total.
            let unescaped = line.replace("\\\"", "");
            assert_eq!(
                unescaped.matches('"').count(),
                4,
                "unbalanced quoting in {line}"
            );
        }
    }
}
