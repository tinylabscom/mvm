//! Live prepared cold-launch baseline.
//!
//! Drives the release-only benchmark entry point against a built `mvmctl` on
//! a host with a prepared artifact cache, then persists the report. `#[ignore]`
//! because it launches real microVMs: it runs when an operator asks for it
//! (`--ignored`), never as part of a stock test run, so the suite can never
//! produce a launch number by accident.
//!
//! Configuration is environment-only, and every knob is required except the
//! counts — a benchmark that guesses what to launch measures the wrong thing:
//!
//! - `MVM_COLD_LAUNCH_MVMCTL` — path to the built (release) binary.
//! - `MVM_COLD_LAUNCH_ARGS` — whitespace-split argv for one launch, e.g.
//!   `machine run --image alpine -- /bin/true`.
//! - `MVM_COLD_LAUNCH_LANE` — lane name; defaults to `prepared_cold`.
//! - `MVM_COLD_LAUNCH_RUNS` / `MVM_COLD_LAUNCH_WARMUP` — default 20 / 2, the
//!   counts the performance contract asks for.

use std::path::PathBuf;

use mvm_cli::bench::cold_launch::LaunchLane;
use mvm_cli::bench::cold_launch_runner::ColdLaunchBench;
use mvm_cli::bench::write_report_with_latest;

/// A required setting, or an error naming the variable that is missing.
fn required(var: &str) -> String {
    match std::env::var(var) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => panic!(
            "{var} must be set to run the cold-launch baseline; \
             see the module docs in tests/cold_launch_bench.rs"
        ),
    }
}

fn count(var: &str, default: u32) -> u32 {
    match std::env::var(var) {
        Ok(value) if !value.trim().is_empty() => value
            .trim()
            .parse()
            .unwrap_or_else(|e| panic!("{var} is not a run count: {e}")),
        _ => default,
    }
}

#[test]
#[ignore = "live: launches real microVMs against a prepared cache; run with --ignored"]
fn prepared_cold_launch_baseline() {
    let mvmctl = PathBuf::from(required("MVM_COLD_LAUNCH_MVMCTL"));
    let argv: Vec<String> = required("MVM_COLD_LAUNCH_ARGS")
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let lane: LaunchLane = std::env::var("MVM_COLD_LAUNCH_LANE")
        .unwrap_or_else(|_| LaunchLane::PreparedCold.as_str().to_string())
        .parse()
        .unwrap_or_else(|e| panic!("{e}"));
    let runs = count("MVM_COLD_LAUNCH_RUNS", 20);
    let warmup = count("MVM_COLD_LAUNCH_WARMUP", 2);

    let report = ColdLaunchBench::builder(&mvmctl, lane)
        .args(argv)
        .runs(runs)
        .warmup(warmup)
        .build()
        .expect("configure the cold-launch benchmark")
        .run()
        .unwrap_or_else(|e| panic!("cold-launch baseline: {e:#}"));

    // Every measured launch is in the report; the runner refuses a sample that
    // does not belong in the lane, so a short report means launches failed
    // rather than that the lane was quietly relaxed.
    assert_eq!(
        report.raw.len(),
        runs as usize,
        "expected {runs} measured samples"
    );
    let dispatch = report.stats.dispatch_window_ms;
    let total = report.stats.total_ms;
    assert_eq!(dispatch.samples, runs, "dispatch window went unmeasured");

    let ms = |value: Option<f64>| value.map_or("n/a".to_string(), |v| format!("{v:.1}ms"));
    eprintln!(
        "[cold-launch] lane={} backend={} arch={} runs={runs} warmup={warmup}",
        report.lane.as_str(),
        report.raw[0].context.backend,
        report.raw[0].context.arch,
    );
    eprintln!(
        "[cold-launch] dispatch_window p50={} p95={} p99={} | total p50={} p95={} p99={}",
        ms(dispatch.p50),
        ms(dispatch.p95),
        ms(dispatch.p99),
        ms(total.p50),
        ms(total.p95),
        ms(total.p99),
    );
    for (name, stats) in &report.stats.sub_phases {
        if stats.samples > 0 {
            eprintln!(
                "[cold-launch]   {name}: n={} p50={} p99={}",
                stats.samples,
                ms(stats.p50),
                ms(stats.p99)
            );
        }
    }

    let path = write_report_with_latest(&report, None, "cold-launch").expect("persist report");
    eprintln!("[cold-launch] report at {}", path.display());
}
