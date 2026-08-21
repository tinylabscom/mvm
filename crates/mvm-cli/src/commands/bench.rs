//! `mvmctl bench` — measure this host's launch latency against the published
//! budgets.
//!
//! The measurement substrate has existed for a while: lanes, percentile
//! statistics, a versioned JSON report, and the budgets the docs publish. What
//! it did not have was a way for a user to run it. Only the CI gate and the
//! conformance suite drove it, so "is this host meeting the contract?" was a
//! question only the project could ask about its own runners, and the numbers
//! in the docs were unfalsifiable by the person they most concerned.
//!
//! This verb drives the same harness the gate does, against the same budgets,
//! and writes the same report shape — deliberately, so a user's report and a
//! CI report are comparable artifacts rather than two formats that happen to
//! carry similar numbers.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::fmt::Write as _;

use crate::bench::cold_launch::{LaunchLane, MIN_MATRIX_SAMPLES, SpanStats};
use crate::bench::cold_launch_runner::ColdLaunchBench;
use crate::ui;

/// Selectable lanes. Mirrors [`LaunchLane`] rather than re-deriving `ValueEnum`
/// on it: the bench module is a library surface and should not grow a clap
/// dependency to be selectable from one verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(in crate::commands) enum LaneArg {
    /// Cached artifacts, no mount image — the headline cold number.
    PreparedCold,
    /// The same launch with an unchanged cached read-only mount image.
    PreparedColdMountHit,
    /// Directory fingerprint plus first mount-image materialization.
    MountMiss,
    /// Image acquisition, unpack, verification, and preparation.
    ArtifactMiss,
    /// A claimed warm standby. Never folded into a cold number.
    WarmClaim,
}

impl From<LaneArg> for LaunchLane {
    fn from(arg: LaneArg) -> Self {
        match arg {
            LaneArg::PreparedCold => LaunchLane::PreparedCold,
            LaneArg::PreparedColdMountHit => LaunchLane::PreparedColdMountHit,
            LaneArg::MountMiss => LaunchLane::MountMiss,
            LaneArg::ArtifactMiss => LaunchLane::ArtifactMiss,
            LaneArg::WarmClaim => LaunchLane::WarmClaim,
        }
    }
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Which launch lane to measure.
    #[arg(long, value_enum, default_value = "prepared-cold")]
    pub lane: LaneArg,
    /// Measured launches. Below 20 the report is not publication-grade.
    #[arg(long, default_value_t = 20)]
    pub runs: u32,
    /// Warm-up launches, discarded before measuring.
    #[arg(long, default_value_t = 2)]
    pub warmup: u32,
    /// Write the report here instead of under `~/.mvm/state/bench/`.
    #[arg(long, value_name = "PATH")]
    pub out: Option<std::path::PathBuf>,
    /// Print the report as JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
    /// Measure even from a debug build, whose numbers mean nothing.
    #[arg(long)]
    pub allow_debug_build: bool,
    /// The launch to measure, after `--`. Defaults to the reproducible
    /// baseline below.
    #[arg(trailing_var_arg = true)]
    pub launch: Vec<String>,
}

/// The launch measured when the caller names none.
///
/// Chosen to be the same on every host rather than to be representative: the
/// bundled default image so nothing is pulled, `--no-detect` so the working
/// directory cannot change which image boots, and a trivial command so the
/// number is the launch rather than the workload. A baseline that varies with
/// where it was run is not a baseline.
const DEFAULT_LAUNCH: [&str; 4] = ["run", "--no-detect", "--", "/bin/true"];

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    // A debug binary is 5-10x slower on the same work, so its percentiles are
    // not this host's latency — they are this build profile's. Publishing or
    // comparing them would be worse than having no number, so refuse by
    // default and say exactly what to do instead.
    if cfg!(debug_assertions) && !args.allow_debug_build {
        anyhow::bail!(
            "refusing to measure from a debug build — its timings are the build profile's, \
             not this host's. Build with `--release` and run that binary, or pass \
             `--allow-debug-build` if you only want the shape of the report."
        );
    }

    let lane: LaunchLane = args.lane.into();

    // The harness shells out to a built `mvmctl`, and the one running this is
    // exactly that — no path to guess and no chance of measuring a different
    // binary than the user invoked.
    let mvmctl = std::env::current_exe().context("resolving this mvmctl binary's path")?;

    if !args.json {
        ui::info(&format!(
            "Measuring lane `{}` ({}) — {} run(s), {} warm-up(s)",
            lane.as_str(),
            lane.description(),
            args.runs,
            args.warmup
        ));
        if args.runs < MIN_MATRIX_SAMPLES {
            ui::warn(&format!(
                "{} runs is below the {MIN_MATRIX_SAMPLES}-sample publication floor; \
                 this report is indicative only",
                args.runs
            ));
        }
    }

    let launch: Vec<String> = if args.launch.is_empty() {
        DEFAULT_LAUNCH.iter().map(|s| s.to_string()).collect()
    } else {
        args.launch.clone()
    };

    if !args.json {
        ui::info(&format!("Launch: mvmctl {}", launch.join(" ")));
        // Every lane but `artifact_miss` assumes the artifacts are already
        // there. On a cold `~/.mvm` the first launch pays a one-time builder
        // bootstrap, and folding that into a launch percentile would overstate
        // this host's latency by orders of magnitude. The runner's lane
        // validation refuses such a sample rather than publishing it, so the
        // failure is loud — but saying so first turns a confusing refusal into
        // one instruction.
        if lane != LaunchLane::ArtifactMiss {
            ui::info(
                "This lane measures launches against a warm cache. Run `mvmctl prepare` first \
                 if this host has not launched before, or the first sample pays a one-time \
                 bootstrap and the runner will refuse it.",
            );
        }
    }

    let bench = ColdLaunchBench::builder(&mvmctl, lane)
        .args(launch)
        .runs(args.runs)
        .warmup(args.warmup)
        .build()?;
    let report = bench.measure().context("running the launch benchmark")?;

    let out_path = crate::bench::write_report_with_latest(&report, args.out.clone(), "bench")
        .context("writing the benchmark report")?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_summary(&report));
        ui::info(&format!("\nReport: {}", out_path.display()));
    }

    // Render and persist the evidence before failing. A breached hard ceiling
    // is the report a user most needs to inspect, not a reason to discard it.
    bench.validate_report(&report)?;
    Ok(())
}

/// Render the benchmark as labelled tables with plain-text verdicts.
///
/// Status is never conveyed by colour alone, phase names are expanded into
/// ordinary language, and the hard maximum is separate from percentiles so a
/// reader cannot mistake p99 for "every boot".
fn render_summary(report: &crate::bench::cold_launch::ColdLaunchReport) -> String {
    let mut out = String::new();
    let budgets = report.lane.budgets();
    let _ = writeln!(out, "\nLaunch timing");
    let _ = writeln!(out, "  Lane:    {}", report.lane.as_str());
    let _ = writeln!(
        out,
        "  Samples: {} measured, {} warm-up",
        report.stats.dispatch_window_ms.samples, report.warmup
    );

    let _ = writeln!(out, "\nHard requirement");
    let _ = writeln!(
        out,
        "  {:<24} {:>12} {:>14}  {:<6}  Remarks",
        "Metric", "Observed", "Requirement", "Status"
    );
    if let Some(requirement) = &report.hard_requirement {
        let observed = format_ms(requirement.observed_max_ms);
        let limit = format!("< {:.1} ms", requirement.limit_ms);
        let status = if requirement.met { "PASS" } else { "FAIL" };
        let _ = writeln!(
            out,
            "  {:<24} {:>12} {:>14}  {:<6}  {}",
            "Boot dispatch maximum", observed, limit, status, requirement.remark
        );
    } else {
        let _ = writeln!(
            out,
            "  {:<24} {:>12} {:>14}  {:<6}  This lane has no hard boot ceiling.",
            "Boot dispatch maximum", "n/a", "n/a", "N/A"
        );
    }

    let _ = writeln!(out, "\nPublished percentile budgets");
    let _ = writeln!(
        out,
        "  {:<11} {:>12} {:>12}  {:<6}",
        "Percentile", "Measured", "Budget", "Status"
    );

    let measured = report.stats.dispatch_window_ms.by_percentile();
    for ((label, value), (_, budget)) in measured.iter().zip(budgets.by_percentile().iter()) {
        let measured_s = format_ms(*value);
        let budget_s = budget.map_or_else(|| "n/a".to_string(), |b| format!("<= {b:.0} ms"));
        let verdict = match (value, budget) {
            (Some(v), Some(b)) if *v <= *b => "PASS",
            (Some(_), Some(_)) => "FAIL",
            _ => "N/A",
        };
        let _ = writeln!(
            out,
            "  {label:<11} {measured_s:>12} {budget_s:>12}  {verdict:<6}"
        );
    }

    let _ = writeln!(out, "\nTiming breakdown");
    let _ = writeln!(
        out,
        "  {:<18} {:>10} {:>10} {:>10} {:>10}  Remarks",
        "Phase", "p50", "p95", "p99", "Max"
    );
    for (phase, stats, remark) in timing_rows(report) {
        let _ = writeln!(
            out,
            "  {phase:<18} {:>10} {:>10} {:>10} {:>10}  {remark}",
            format_ms(stats.p50),
            format_ms(stats.p95),
            format_ms(stats.p99),
            format_ms(stats.max),
        );
    }
    out
}

fn format_ms(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_string(), |ms| format!("{ms:.1} ms"))
}

fn timing_rows(
    report: &crate::bench::cold_launch::ColdLaunchReport,
) -> [(&'static str, SpanStats, &'static str); 10] {
    let stats = &report.stats;
    [
        (
            "Boot dispatch",
            stats.dispatch_window_ms,
            "HARD requirement applies to the maximum, not a percentile.",
        ),
        (
            "  Backend start",
            stats.backend_start_ms,
            "Create the VMM and enter the guest kernel.",
        ),
        (
            "  Agent ready",
            stats.vsock_wait_ms,
            "Reach the authenticated guest agent and dispatch boundary.",
        ),
        (
            "Resolve",
            stats.resolve_ms,
            "Select cached image and runtime artifacts before boot.",
        ),
        (
            "Drives",
            stats.drives_ms,
            "Prepare the guest's immutable and writable drives.",
        ),
        (
            "Admission",
            stats.admit_ms,
            "Validate policy and bind the signed launch plan.",
        ),
        (
            "Command",
            stats.command_ms,
            "Run the benchmark command after boot dispatch.",
        ),
        (
            "Teardown",
            stats.teardown_ms,
            "Stop and reap the transient VM.",
        ),
        (
            "Measured run",
            stats.total_ms,
            "In-process setup, workload, and cleanup through VM teardown.",
        ),
        (
            "Full CLI lifecycle",
            stats.command_lifecycle_ms,
            "Shell-visible time: process spawn through final audit and exit.",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::cold_launch::{
        COLD_LAUNCH_SCHEMA_VERSION, ColdLaunchReport, HardBootRequirement, LaneStats,
        RequirementComparison, TimingMetric,
    };
    use clap::Parser;

    fn parse(argv: &[&str]) -> Result<Args> {
        let mut full = vec!["mvmctl", "bench"];
        full.extend_from_slice(argv);
        let cli = crate::commands::Cli::try_parse_from(full)?;
        match cli.command {
            crate::commands::Commands::Bench(a) => Ok(a),
            _ => panic!("expected Commands::Bench"),
        }
    }

    fn summary_report(max_ms: f64, met: bool) -> ColdLaunchReport {
        let measured = SpanStats {
            samples: 2,
            p50: Some(100.0),
            p95: Some(max_ms),
            p99: Some(max_ms),
            max: Some(max_ms),
        };
        ColdLaunchReport {
            schema_version: COLD_LAUNCH_SCHEMA_VERSION,
            lane: LaunchLane::PreparedCold,
            warmup: 2,
            stats: LaneStats {
                dispatch_window_ms: measured,
                command_lifecycle_ms: SpanStats {
                    p50: Some(180.0),
                    p95: Some(190.0),
                    p99: Some(195.0),
                    max: Some(198.0),
                    ..measured
                },
                total_ms: measured,
                backend_start_ms: measured,
                vsock_wait_ms: measured,
                ..LaneStats::default()
            },
            hard_requirement: Some(HardBootRequirement {
                metric: TimingMetric::DispatchWindowMs,
                comparison: RequirementComparison::LessThan,
                limit_ms: 200.0,
                observed_max_ms: Some(max_ms),
                met,
                remark:
                    "Every prepared boot must reach authenticated command dispatch in under 200 ms."
                        .to_string(),
            }),
            raw: Vec::new(),
        }
    }

    #[test]
    fn the_default_lane_is_the_headline_cold_number() {
        let args = parse(&[]).expect("bare `bench` parses");
        assert_eq!(args.lane, LaneArg::PreparedCold);
        assert_eq!(args.runs, MIN_MATRIX_SAMPLES);
        assert!(!args.json);
        assert!(
            args.launch.is_empty(),
            "the default launch is applied later"
        );
    }

    #[test]
    fn human_summary_names_the_hard_maximum_and_explains_each_phase() {
        let rendered = render_summary(&summary_report(150.0, true));
        assert!(rendered.contains("Hard requirement"), "{rendered}");
        assert!(rendered.contains("Boot dispatch maximum"), "{rendered}");
        assert!(rendered.contains("< 200.0 ms"), "{rendered}");
        assert!(rendered.contains("PASS"), "{rendered}");
        assert!(rendered.contains("Timing breakdown"), "{rendered}");
        assert!(rendered.contains("Full CLI lifecycle"), "{rendered}");
        assert!(rendered.contains("final audit and exit"), "{rendered}");
        assert!(rendered.contains("Remarks"), "{rendered}");
        assert!(
            rendered.contains("Create the VMM and enter the guest kernel."),
            "{rendered}"
        );
        assert!(
            rendered.contains("not a percentile"),
            "the output must distinguish max from p99: {rendered}"
        );
        assert!(
            !rendered.contains("\u{1b}["),
            "status must not require terminal colour: {rendered}"
        );
    }

    #[test]
    fn human_summary_prints_an_explicit_failure_at_the_boundary() {
        let rendered = render_summary(&summary_report(200.0, false));
        let hard_row = rendered
            .lines()
            .find(|line| line.contains("Boot dispatch maximum"))
            .expect("hard-requirement row");
        assert!(hard_row.contains("FAIL"), "{hard_row}");
        assert!(hard_row.contains("200.0 ms"), "{hard_row}");
    }

    /// The default has to be host-independent or the baseline is not one.
    #[test]
    fn the_default_launch_pulls_nothing_and_ignores_the_directory() {
        assert!(
            DEFAULT_LAUNCH.contains(&"--no-detect"),
            "the working directory must not choose the measured image"
        );
        assert!(
            !DEFAULT_LAUNCH.contains(&"--image"),
            "the baseline must not depend on a registry pull"
        );
    }

    #[test]
    fn a_caller_supplied_launch_wins() {
        let args = parse(&["--", "run", "--image", "alpine", "--", "true"]).expect("parses");
        assert_eq!(args.launch.first().map(String::as_str), Some("run"));
        assert!(args.launch.iter().any(|a| a == "alpine"));
    }

    #[test]
    fn every_lane_is_selectable_and_maps_to_its_harness_lane() {
        // A lane the CLI cannot select is a lane a user cannot measure, and
        // the two enums are separate declarations that could drift.
        for lane in LaunchLane::ALL {
            let flag = lane.as_str().replace('_', "-");
            let args = parse(&["--lane", &flag])
                .unwrap_or_else(|e| panic!("lane `{flag}` must be selectable: {e}"));
            assert_eq!(
                LaunchLane::from(args.lane),
                lane,
                "`--lane {flag}` must map to {lane:?}"
            );
        }
    }

    #[test]
    fn a_debug_build_refuses_unless_the_caller_opts_in() {
        // Guarded on the profile this test is compiled in: under `--release`
        // there is nothing to refuse.
        if !cfg!(debug_assertions) {
            return;
        }
        let err = run(parse(&[]).expect("parses")).expect_err("a debug build must refuse");
        assert!(
            err.to_string().contains("debug build"),
            "the refusal must say why: {err}"
        );
    }
}
