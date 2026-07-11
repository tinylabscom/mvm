//! `mvmctl ops bench first-use` — pure measurement substrate.
//!
//! A first-use benchmark answers "how long does it take a brand-new
//! host to go from nothing to a running build?" The one part of that
//! cost this module measures is the in-guest build wall-clock: the
//! builder VM's job harness stamps `job_start_ms`/`job_end_ms` into
//! `boot-timings.json`, and [`build_ms_from_boot_timings`] turns that
//! into a single sample. [`summarize_build_samples`] then folds N
//! samples into the same [`super::bench::PhaseStats`] shape every
//! other bench report already uses, so downstream tooling (report
//! writer, regression gate) doesn't need a second code path.
//!
//! This module is pure and unit-tested end to end. The live probe
//! that actually boots a builder VM and produces `boot-timings.json`
//! samples is wired separately.

use anyhow::{Context, Result};
use serde::Deserialize;

use super::bench::{PhaseStats, summarize};

/// One "run this common flake build in the builder VM" sample: the
/// in-guest build wall-clock, read from the builder VM's
/// `boot-timings.json`.
// Live probe wiring is the first non-test caller.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildSample {
    pub build_ms: u64,
}

/// The two fields of `boot-timings.json` this benchmark cares about.
/// Extra fields in the real file (other job-harness milestones) are
/// ignored; missing fields fail the parse rather than defaulting.
// Live probe wiring is the first non-test caller.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct BootTimings {
    job_start_ms: u64,
    job_end_ms: u64,
}

/// Parse `build_ms = job_end_ms - job_start_ms` from a builder-VM job
/// dir's `boot-timings.json`. Errors — never returns a fabricated
/// `0` — on malformed JSON, missing fields, or `job_end_ms` preceding
/// `job_start_ms` (a clock or measurement anomaly, not a valid
/// sample).
// Live probe wiring is the first non-test caller.
#[allow(dead_code)]
pub fn build_ms_from_boot_timings(boot_timings_json: &str) -> Result<u64> {
    let timings: BootTimings =
        serde_json::from_str(boot_timings_json).context("parsing boot-timings.json")?;
    timings
        .job_end_ms
        .checked_sub(timings.job_start_ms)
        .with_context(|| {
            format!(
                "boot-timings.json: job_end_ms ({}) precedes job_start_ms ({}) — \
             a clock or measurement anomaly, not a valid build sample",
                timings.job_end_ms, timings.job_start_ms
            )
        })
}

/// Aggregate N build samples into the shared [`PhaseStats`] shape by
/// reusing `bench.rs`'s `summarize`/`percentile`.
// Live probe wiring is the first non-test caller.
#[allow(dead_code)]
pub fn summarize_build_samples(samples: &[BuildSample]) -> PhaseStats {
    let ms: Vec<f64> = samples.iter().map(|s| s.build_ms as f64).collect();
    summarize(&ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ms_reads_job_delta() {
        let json = r#"{"job_start_ms": 1000, "job_end_ms": 4200, "other": 1}"#;
        assert_eq!(build_ms_from_boot_timings(json).unwrap(), 3200);
    }

    #[test]
    fn build_ms_errors_on_missing_fields() {
        assert!(build_ms_from_boot_timings(r#"{"job_start_ms": 1000}"#).is_err());
        assert!(build_ms_from_boot_timings("not json").is_err());
    }

    #[test]
    fn build_ms_errors_when_end_before_start() {
        // A clock/measurement anomaly must fail, not underflow to a bogus value.
        assert!(
            build_ms_from_boot_timings(r#"{"job_start_ms": 5000, "job_end_ms": 1000}"#).is_err()
        );
    }

    #[test]
    fn summarize_reports_p50_over_samples() {
        let s = summarize_build_samples(&[
            BuildSample { build_ms: 100 },
            BuildSample { build_ms: 200 },
            BuildSample { build_ms: 300 },
        ]);
        assert_eq!(s.p50, 200.0);
    }
}
