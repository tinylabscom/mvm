//! Capture and diff span profiles across benchmark runs.
//!
//! The launch harness spawns `mvmctl` as a child process, so a profile is
//! collected by pointing the child at a JSON destination and reading it back.
//! Diffing is pure and lives here so a profile regression is a verdict rather
//! than something a human reads off two tables.
//!
//! The gate compares **per-call** self time, which is robust to two runs that
//! executed a different number of iterations. Call counts are reported
//! alongside, because a function that got called more often is a different
//! defect from one that got slower, and the two need telling apart.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_core::observability::span_timing::{self, SpanProfile, SpanReport};

use super::regression::RegressionVerdict;

/// Environment a child `mvmctl` needs in order to write a JSON profile to
/// `out_path`. Feed these into the launch runner's env list.
pub fn profile_env(out_path: &Path) -> Vec<(String, String)> {
    vec![
        (span_timing::ENV_ENABLE.to_string(), "json".to_string()),
        (
            span_timing::ENV_OUT.to_string(),
            out_path.display().to_string(),
        ),
    ]
}

/// Read a profile a child process wrote.
pub fn read_profile(path: &Path) -> Result<SpanReport> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading span profile {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing span profile {}", path.display()))
}

/// Mean self time per call, or `None` when the span recorded no calls.
fn self_ns_per_call(profile: &SpanProfile) -> Option<f64> {
    (profile.calls > 0).then(|| profile.self_ns as f64 / profile.calls as f64)
}

/// One call site compared across two runs.
#[derive(Debug, Clone, PartialEq)]
pub struct SpanDelta {
    /// Emitting module path.
    pub target: String,
    /// Span name.
    pub name: String,
    /// Baseline calls.
    pub baseline_calls: u64,
    /// Current calls.
    pub current_calls: u64,
    /// Baseline mean self time per call.
    pub baseline_self_ns_per_call: f64,
    /// Current mean self time per call.
    pub current_self_ns_per_call: f64,
    /// Current total self time, for ordering by what actually costs.
    pub current_self_ns: u64,
    /// Verdict over per-call self time.
    pub verdict: RegressionVerdict,
}

impl SpanDelta {
    /// Whether this call site regressed beyond the limit.
    pub fn is_regressed(&self) -> bool {
        matches!(self.verdict, RegressionVerdict::Regressed { .. })
    }

    /// Whether the run called this site a different number of times. A pure
    /// call-count change leaves per-call time flat, so it would otherwise pass
    /// the gate unnoticed.
    pub fn call_count_changed(&self) -> bool {
        self.baseline_calls != self.current_calls
    }
}

/// The full comparison between a baseline profile and a current one.
#[derive(Debug, Clone, PartialEq)]
pub struct SpanComparison {
    /// Call sites present in both runs, hottest by current self time first.
    pub deltas: Vec<SpanDelta>,
    /// `target::name` present only in the current run.
    pub appeared: Vec<String>,
    /// `target::name` present only in the baseline.
    pub disappeared: Vec<String>,
}

impl SpanComparison {
    /// Call sites that regressed beyond the limit.
    pub fn regressions(&self) -> impl Iterator<Item = &SpanDelta> {
        self.deltas.iter().filter(|d| d.is_regressed())
    }

    /// Whether no call site regressed. A newly appeared span is not by itself a
    /// regression — it may just be newly instrumented — so it does not fail
    /// this, but it is reported so the reader can judge.
    pub fn is_clean(&self) -> bool {
        self.regressions().next().is_none()
    }
}

fn qualified(profile: &SpanProfile) -> String {
    format!("{}::{}", profile.target, profile.name)
}

/// Compare per-call self time for every call site present in both reports.
pub fn compare_span_reports(
    baseline: &SpanReport,
    current: &SpanReport,
    max_regression_pct: f64,
) -> SpanComparison {
    let mut deltas = Vec::new();
    let mut appeared = Vec::new();

    for cur in &current.spans {
        let Some(base) = baseline
            .spans
            .iter()
            .find(|b| b.target == cur.target && b.name == cur.name)
        else {
            appeared.push(qualified(cur));
            continue;
        };

        let verdict = match (self_ns_per_call(base), self_ns_per_call(cur)) {
            (Some(b), Some(c)) if b > 0.0 => {
                let delta_pct = (c - b) / b * 100.0;
                if delta_pct > max_regression_pct {
                    RegressionVerdict::Regressed {
                        delta_pct,
                        limit_pct: max_regression_pct,
                    }
                } else {
                    RegressionVerdict::Ok { delta_pct }
                }
            }
            // A zero or absent baseline has no ratio to compare against;
            // reporting it as a pass would be a false green.
            _ => RegressionVerdict::Incomparable {
                reason: format!(
                    "baseline for {} has no positive per-call self time",
                    qualified(cur)
                ),
            },
        };

        deltas.push(SpanDelta {
            target: cur.target.clone(),
            name: cur.name.clone(),
            baseline_calls: base.calls,
            current_calls: cur.calls,
            baseline_self_ns_per_call: self_ns_per_call(base).unwrap_or(0.0),
            current_self_ns_per_call: self_ns_per_call(cur).unwrap_or(0.0),
            current_self_ns: cur.self_ns,
            verdict,
        });
    }

    let disappeared = baseline
        .spans
        .iter()
        .filter(|b| {
            !current
                .spans
                .iter()
                .any(|c| c.target == b.target && c.name == b.name)
        })
        .map(qualified)
        .collect();

    deltas.sort_by(|a, b| {
        b.current_self_ns
            .cmp(&a.current_self_ns)
            .then_with(|| a.name.cmp(&b.name))
    });

    SpanComparison {
        deltas,
        appeared,
        disappeared,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(name: &str, calls: u64, self_ns: u64) -> SpanProfile {
        SpanProfile {
            target: "mvm_cli::bench_fixture".to_string(),
            name: name.to_string(),
            calls,
            total_ns: self_ns,
            self_ns,
            wall_ns: self_ns,
            mean_ns: self_ns / calls.max(1),
            min_ns: 0,
            max_ns: self_ns,
            p50_ns: 0,
            p95_ns: 0,
            p99_ns: 0,
        }
    }

    fn report(spans: Vec<SpanProfile>) -> SpanReport {
        SpanReport { spans }
    }

    #[test]
    fn profile_env_names_the_json_format_and_destination() {
        let env = profile_env(Path::new("/tmp/p.json"));
        assert!(env.contains(&("MVM_SPAN_TIMINGS".to_string(), "json".to_string())));
        assert!(env.contains(&(
            "MVM_SPAN_TIMINGS_OUT".to_string(),
            "/tmp/p.json".to_string()
        )));
    }

    #[test]
    fn an_unchanged_profile_is_clean() {
        let base = report(vec![span("boot", 4, 400)]);
        let cur = report(vec![span("boot", 4, 400)]);

        let cmp = compare_span_reports(&base, &cur, 10.0);
        assert!(cmp.is_clean());
        assert_eq!(cmp.deltas.len(), 1);
        assert!(matches!(
            cmp.deltas[0].verdict,
            RegressionVerdict::Ok { delta_pct } if delta_pct.abs() < f64::EPSILON
        ));
    }

    #[test]
    fn a_slower_call_site_regresses() {
        let base = report(vec![span("boot", 4, 400)]);
        let cur = report(vec![span("boot", 4, 800)]);

        let cmp = compare_span_reports(&base, &cur, 10.0);
        assert!(!cmp.is_clean());
        let regressed: Vec<&SpanDelta> = cmp.regressions().collect();
        assert_eq!(regressed.len(), 1);
        assert_eq!(regressed[0].name, "boot");
        assert!(matches!(
            regressed[0].verdict,
            RegressionVerdict::Regressed { delta_pct, .. } if (delta_pct - 100.0).abs() < 1e-9
        ));
    }

    #[test]
    fn an_improvement_passes_and_reports_a_negative_delta() {
        let base = report(vec![span("boot", 4, 800)]);
        let cur = report(vec![span("boot", 4, 400)]);

        let cmp = compare_span_reports(&base, &cur, 10.0);
        assert!(cmp.is_clean());
        assert!(matches!(
            cmp.deltas[0].verdict,
            RegressionVerdict::Ok { delta_pct } if delta_pct < 0.0
        ));
    }

    #[test]
    fn more_iterations_do_not_read_as_a_regression() {
        // Twice the calls at the same per-call cost is the same code, run more.
        // A total-time gate would flag this; a per-call gate must not.
        let base = report(vec![span("boot", 4, 400)]);
        let cur = report(vec![span("boot", 8, 800)]);

        let cmp = compare_span_reports(&base, &cur, 10.0);
        assert!(cmp.is_clean(), "{:?}", cmp.deltas);
    }

    #[test]
    fn a_changed_call_count_is_surfaced_even_when_per_call_time_is_flat() {
        // Calling a hasher twice per launch instead of once is a real defect
        // that leaves per-call time untouched.
        let base = report(vec![span("sha256_file.uncached", 1, 100)]);
        let cur = report(vec![span("sha256_file.uncached", 2, 200)]);

        let cmp = compare_span_reports(&base, &cur, 10.0);
        assert!(cmp.is_clean(), "per-call time did not change");
        assert!(
            cmp.deltas[0].call_count_changed(),
            "the extra call must still be visible"
        );
        assert_eq!(cmp.deltas[0].baseline_calls, 1);
        assert_eq!(cmp.deltas[0].current_calls, 2);
    }

    #[test]
    fn a_new_span_is_reported_but_does_not_fail_the_gate() {
        let base = report(vec![span("boot", 1, 100)]);
        let cur = report(vec![
            span("boot", 1, 100),
            span("newly_instrumented", 1, 50),
        ]);

        let cmp = compare_span_reports(&base, &cur, 10.0);
        assert!(cmp.is_clean());
        assert_eq!(cmp.appeared.len(), 1);
        assert!(cmp.appeared[0].ends_with("newly_instrumented"));
    }

    #[test]
    fn a_span_that_stopped_being_recorded_is_reported() {
        let base = report(vec![span("boot", 1, 100), span("gone", 1, 50)]);
        let cur = report(vec![span("boot", 1, 100)]);

        let cmp = compare_span_reports(&base, &cur, 10.0);
        assert_eq!(cmp.disappeared.len(), 1);
        assert!(cmp.disappeared[0].ends_with("gone"));
    }

    #[test]
    fn a_zero_baseline_is_incomparable_rather_than_a_false_green() {
        let base = report(vec![span("boot", 1, 0)]);
        let cur = report(vec![span("boot", 1, 500)]);

        let cmp = compare_span_reports(&base, &cur, 10.0);
        assert!(matches!(
            cmp.deltas[0].verdict,
            RegressionVerdict::Incomparable { .. }
        ));
    }

    #[test]
    fn a_baseline_with_no_calls_is_incomparable() {
        let base = report(vec![span("boot", 0, 0)]);
        let cur = report(vec![span("boot", 1, 500)]);

        let cmp = compare_span_reports(&base, &cur, 10.0);
        assert!(matches!(
            cmp.deltas[0].verdict,
            RegressionVerdict::Incomparable { .. }
        ));
    }

    #[test]
    fn deltas_are_ordered_by_current_self_time() {
        let base = report(vec![
            span("cheap", 1, 10),
            span("expensive", 1, 1_000),
            span("middling", 1, 100),
        ]);
        let cur = base.clone();

        let cmp = compare_span_reports(&base, &cur, 10.0);
        let names: Vec<&str> = cmp.deltas.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["expensive", "middling", "cheap"]);
    }

    #[test]
    fn same_name_under_different_targets_stays_separate() {
        let mut base_a = span("start", 1, 100);
        base_a.target = "mvm_fs::oci".to_string();
        let mut base_b = span("start", 1, 100);
        base_b.target = "mvm_runtime::vm".to_string();

        let mut cur_a = base_a.clone();
        cur_a.self_ns = 1_000;
        cur_a.mean_ns = 1_000;

        let cmp = compare_span_reports(
            &report(vec![base_a, base_b.clone()]),
            &report(vec![cur_a, base_b]),
            10.0,
        );
        assert_eq!(cmp.deltas.len(), 2);
        assert_eq!(cmp.regressions().count(), 1);
        assert!(cmp.appeared.is_empty());
        assert!(cmp.disappeared.is_empty());
    }

    #[test]
    fn read_profile_round_trips_a_written_report() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("profile.json");
        let written = report(vec![span("boot", 2, 200)]);
        std::fs::write(&path, serde_json::to_string(&written).expect("serialize")).expect("write");

        let read = read_profile(&path).expect("read");
        assert_eq!(read, written);
    }

    #[test]
    fn read_profile_reports_a_missing_file_rather_than_an_empty_profile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = read_profile(&dir.path().join("absent.json")).expect_err("must fail");
        // An empty profile would read as "nothing was slow", the wrong default.
        assert!(format!("{err}").contains("reading span profile"), "{err}");
    }
}
