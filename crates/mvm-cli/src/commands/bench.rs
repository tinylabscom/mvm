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

use crate::bench::cold_launch::{LaunchLane, MIN_MATRIX_SAMPLES};
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

    let report = ColdLaunchBench::builder(&mvmctl, lane)
        .args(launch)
        .runs(args.runs)
        .warmup(args.warmup)
        .build()?
        .run()
        .context("running the launch benchmark")?;

    let out_path = crate::bench::write_report_with_latest(&report, args.out.clone(), "bench")
        .context("writing the benchmark report")?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    print_summary(&report);
    ui::info(&format!("\nReport: {}", out_path.display()));
    Ok(())
}

/// Print each measured percentile beside the budget it is judged against, so
/// the verdict is visible rather than something the reader has to look up.
fn print_summary(report: &crate::bench::cold_launch::ColdLaunchReport) {
    let budgets = report.lane.budgets();
    println!("\nlane: {}", report.lane.as_str());
    println!("samples: {}", report.stats.dispatch_window_ms.samples);
    println!("\n  percentile   measured     budget   verdict");

    let measured = report.stats.dispatch_window_ms.by_percentile();
    for ((label, value), (_, budget)) in measured.iter().zip(budgets.by_percentile().iter()) {
        let measured_s = value.map_or_else(|| "—".to_string(), |v| format!("{v:.1} ms"));
        let budget_s = budget.map_or_else(|| "—".to_string(), |b| format!("{b:.0} ms"));
        let verdict = match (value, budget) {
            (Some(v), Some(b)) if *v <= *b => "ok",
            (Some(_), Some(_)) => "OVER",
            _ => "",
        };
        println!("  {label:<11}{measured_s:>10}{budget_s:>11}   {verdict}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
