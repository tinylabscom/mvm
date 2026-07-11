//! `mvmctl ops bench first-use` — measurement substrate + live probes.
//!
//! A first-use benchmark answers "how long does it take a brand-new
//! host to go from nothing to a running build?" That question splits
//! into two costs:
//!
//! - **In-guest build wall-clock.** The builder VM's job harness
//!   stamps `job_start_ms`/`job_end_ms` into `boot-timings.json`, and
//!   [`build_ms_from_boot_timings`] turns that into a single sample.
//!   [`summarize_build_samples`] then folds N samples into the same
//!   [`super::bench::PhaseStats`] shape every other bench report
//!   already uses, so downstream tooling (report writer, regression
//!   gate) doesn't need a second code path.
//! - **`mvmctl dev up` wall-clock**, cold (fresh dev-image cache) and
//!   warm (cache hit), measured by spawning the real subcommand.
//!
//! The parse/aggregate/report substrate above is pure and unit-tested
//! end to end, always compiled. The live probes that actually spawn
//! `mvmctl dev up` / `mvmctl machine build` and boot real VMs sit
//! behind the `bench-first-use` feature — mirroring the `libkrun-live`
//! gate on `bench microvm-launch` — so a stock build never touches a
//! hypervisor.

use anyhow::{Context, Result};
use serde::Deserialize;
#[cfg(feature = "bench-first-use")]
use serde::Serialize;

#[cfg(feature = "bench-first-use")]
use super::bench::{BENCH_SCHEMA_VERSION, FirstUseArgs, write_report_with_latest};
use super::bench::{PhaseStats, summarize};

/// One "run this common flake build in the builder VM" sample: the
/// in-guest build wall-clock, read from the builder VM's
/// `boot-timings.json`.
#[cfg_attr(not(feature = "bench-first-use"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildSample {
    pub build_ms: u64,
}

/// The two fields of `boot-timings.json` this benchmark cares about.
/// Extra fields in the real file (other job-harness milestones) are
/// ignored; missing fields fail the parse rather than defaulting.
#[cfg_attr(not(feature = "bench-first-use"), allow(dead_code))]
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
#[cfg_attr(not(feature = "bench-first-use"), allow(dead_code))]
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
#[cfg_attr(not(feature = "bench-first-use"), allow(dead_code))]
pub fn summarize_build_samples(samples: &[BuildSample]) -> PhaseStats {
    let ms: Vec<f64> = samples.iter().map(|s| s.build_ms as f64).collect();
    summarize(&ms)
}

// ──────────────────────────────────────────────────────────────────
// Live probes (bench-first-use only). Boot the real dev VM and drive
// real in-guest builder-VM builds by shelling out to this same
// `mvmctl` binary — never in default/CI builds.
// ──────────────────────────────────────────────────────────────────

/// A full first-use benchmark run: dev-up cold vs warm, and the
/// in-guest build cost for the measured flake.
#[cfg(feature = "bench-first-use")]
#[derive(Debug, Clone, Serialize)]
struct FirstUseReport {
    schema_version: u32,
    runs: u32,
    flake: String,
    dev_up_cold: PhaseStats,
    dev_up_warm: PhaseStats,
    in_guest_build: PhaseStats,
}

/// Resolved inputs for one first-use probe run: the `mvmctl` binary
/// to shell out to, the run count, and the flake to build in-guest.
/// Grouped into a struct (rather than threading three bare arguments
/// through every probe function) per the workspace's no-long-arg-list
/// convention.
#[cfg(feature = "bench-first-use")]
struct FirstUseProbeConfig {
    mvmctl_bin: std::path::PathBuf,
    runs: u32,
    flake: String,
}

/// The canonical fixture flake for the in-guest build probe:
/// `examples/exit_code`, the smallest flake in the repo shaped
/// exactly like the SDK-generated user flake (`inputs.mvm` pinned to
/// GitHub, rewritten to the in-repo `nix/` via the source-checkout
/// `--override-input mvm path:/work/nix` path every `mvmctl build`
/// already applies), so a measured build exercises a genuine
/// nixpkgs eval+build with no network round-trip for `mvm` itself.
/// Resolved by walking up from this crate's manifest dir, mirroring
/// the same walk-up idiom `dev_build.rs::local_mvm_workspace` uses to
/// find the in-repo `nix/flake.nix`.
#[cfg(feature = "bench-first-use")]
fn default_first_use_flake() -> String {
    let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("examples/exit_code");
        if candidate.join("flake.nix").is_file() {
            return candidate.display().to_string();
        }
        if !dir.pop() {
            // Not a source checkout (or the fixture moved) — fall
            // back to a relative path; the caller's cwd may resolve
            // it, and if not, `mvmctl machine build` reports a clear
            // "flake not found" error rather than this function
            // failing silently.
            return "examples/exit_code".to_string();
        }
    }
}

#[cfg(feature = "bench-first-use")]
fn resolve_first_use_probe_config(args: &FirstUseArgs) -> Result<FirstUseProbeConfig> {
    let mvmctl_bin = std::env::current_exe()
        .context("resolving the running mvmctl binary path for the first-use live probe")?;
    let flake = args
        .flake
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(default_first_use_flake);
    Ok(FirstUseProbeConfig {
        mvmctl_bin,
        runs: args.runs,
        flake,
    })
}

/// Time one `mvmctl dev up --json` spawn→exit, in milliseconds.
/// `--json` already implies non-interactive (`--no-shell`).
#[cfg(feature = "bench-first-use")]
fn timed_dev_up(cfg: &FirstUseProbeConfig) -> Result<f64> {
    let start = std::time::Instant::now();
    let status = std::process::Command::new(&cfg.mvmctl_bin)
        .args(["dev", "up", "--json"])
        .status()
        .context("spawning `mvmctl dev up --json`")?;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    if !status.success() {
        anyhow::bail!("`mvmctl dev up --json` exited with {status}");
    }
    Ok(elapsed_ms)
}

/// Tear the dev VM down between iterations so the next `dev up` is a
/// real start, not a no-op against an already-running VM. `reset`
/// also deletes the cached dev image so the following `dev up` is
/// genuinely cold. `mvmctl dev down` is idempotent (a no-op, exit 0,
/// when nothing is running), so this is safe to call unconditionally.
#[cfg(feature = "bench-first-use")]
fn dev_down(cfg: &FirstUseProbeConfig, reset: bool) -> Result<()> {
    let mut command = std::process::Command::new(&cfg.mvmctl_bin);
    command.args(["dev", "down", "--json"]);
    if reset {
        command.arg("--reset");
    }
    let status = command.status().context("spawning `mvmctl dev down`")?;
    if !status.success() {
        anyhow::bail!(
            "`mvmctl dev down{}` exited with {status}",
            if reset { " --reset" } else { "" }
        );
    }
    Ok(())
}

/// Measure `cfg.runs` cold/warm `dev up` pairs. Each cold sample is
/// preceded by `dev down --reset` (deletes the cached dev image, so
/// the following `dev up` resolves the real download/build path);
/// each warm sample immediately follows on the now-cached image (the
/// `ensure_dev_image` cache-hit path). `dev down` (no reset) tears
/// the VM down between every measured boot.
#[cfg(feature = "bench-first-use")]
fn run_dev_up_probe(cfg: &FirstUseProbeConfig) -> Result<(PhaseStats, PhaseStats)> {
    let mut cold = Vec::with_capacity(cfg.runs as usize);
    let mut warm = Vec::with_capacity(cfg.runs as usize);
    for i in 0..cfg.runs {
        dev_down(cfg, true)
            .with_context(|| format!("dev down --reset before cold dev-up run {i}"))?;
        cold.push(timed_dev_up(cfg).with_context(|| format!("cold dev-up run {i}"))?);
        dev_down(cfg, false).with_context(|| format!("dev down after cold dev-up run {i}"))?;

        warm.push(timed_dev_up(cfg).with_context(|| format!("warm dev-up run {i}"))?);
        dev_down(cfg, false).with_context(|| format!("dev down after warm dev-up run {i}"))?;
    }
    Ok((summarize(&cold), summarize(&warm)))
}

/// The builder VM's job dir root: `~/.cache/mvm/builder-vm/jobs/`.
#[cfg(feature = "bench-first-use")]
fn builder_vm_jobs_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_core::config::mvm_cache_dir())
        .join("builder-vm")
        .join("jobs")
}

/// Snapshot the job dir's immediate entry names. A missing dir (no
/// build has ever run) is an empty set, not an error — the very first
/// probe run legitimately starts from nothing.
#[cfg(feature = "bench-first-use")]
fn list_job_dir_names(dir: &std::path::Path) -> Result<std::collections::HashSet<String>> {
    match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .map(|entry| {
                let entry =
                    entry.with_context(|| format!("reading entry under {}", dir.display()))?;
                Ok(entry.file_name().to_string_lossy().into_owned())
            })
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(std::collections::HashSet::new()),
        Err(e) => Err(e).with_context(|| format!("listing {}", dir.display())),
    }
}

/// Run one in-guest build. `--force` bypasses `dev_build`'s host-side
/// build-cache fingerprint short-circuit, which would otherwise skip
/// the builder VM entirely on a repeat build of the same flake and
/// never emit a fresh `boot-timings.json`.
#[cfg(feature = "bench-first-use")]
fn run_machine_build(cfg: &FirstUseProbeConfig) -> Result<()> {
    let status = std::process::Command::new(&cfg.mvmctl_bin)
        .args(["machine", "build", "--flake", &cfg.flake, "--force"])
        .status()
        .context("spawning `mvmctl machine build`")?;
    if !status.success() {
        anyhow::bail!(
            "`mvmctl machine build --flake {} --force` exited with {status}",
            cfg.flake
        );
    }
    Ok(())
}

/// Measure `cfg.runs` in-guest builds of `cfg.flake`: snapshot the
/// job dir, run the build, diff to find the new job, and parse its
/// `boot-timings.json`.
#[cfg(feature = "bench-first-use")]
fn run_in_guest_build_probe(cfg: &FirstUseProbeConfig) -> Result<PhaseStats> {
    let jobs_dir = builder_vm_jobs_dir();
    let mut samples = Vec::with_capacity(cfg.runs as usize);
    for i in 0..cfg.runs {
        let before = list_job_dir_names(&jobs_dir)?;
        run_machine_build(cfg).with_context(|| format!("in-guest build run {i}"))?;
        let after = list_job_dir_names(&jobs_dir)?;
        let mut new_jobs: Vec<&String> = after.difference(&before).collect();
        new_jobs.sort();
        let job_name = match new_jobs.as_slice() {
            [only] => (*only).clone(),
            [] => anyhow::bail!(
                "in-guest build run {i}: no new job dir appeared under {} after \
                 `mvmctl machine build` — the build may have been served from \
                 cache despite --force, or the job dir layout changed",
                jobs_dir.display()
            ),
            _ => anyhow::bail!(
                "in-guest build run {i}: {} new job dirs appeared under {} — \
                 expected exactly one; refusing to guess which one this run \
                 produced",
                new_jobs.len(),
                jobs_dir.display()
            ),
        };
        let boot_timings_path = jobs_dir.join(&job_name).join("boot-timings.json");
        let boot_timings_json = std::fs::read_to_string(&boot_timings_path)
            .with_context(|| format!("reading {}", boot_timings_path.display()))?;
        let build_ms = build_ms_from_boot_timings(&boot_timings_json)
            .with_context(|| format!("in-guest build run {i}"))?;
        samples.push(BuildSample { build_ms });
    }
    Ok(summarize_build_samples(&samples))
}

/// Live entrypoint for `mvmctl ops bench first-use` under
/// `bench-first-use`: run both probes, assemble the report, write it
/// via the shared bench report writer, and print the headline
/// numbers.
#[cfg(feature = "bench-first-use")]
pub(super) fn run_first_use_live(args: FirstUseArgs) -> Result<()> {
    let probe_cfg = resolve_first_use_probe_config(&args)?;
    let (dev_up_cold, dev_up_warm) = run_dev_up_probe(&probe_cfg)?;
    let in_guest_build = run_in_guest_build_probe(&probe_cfg)?;

    let report = FirstUseReport {
        schema_version: BENCH_SCHEMA_VERSION,
        runs: probe_cfg.runs,
        flake: probe_cfg.flake,
        dev_up_cold,
        dev_up_warm,
        in_guest_build,
    };

    let out_path = write_report_with_latest(&report, args.out, "first-use")?;
    eprintln!(
        "[mvm] bench first-use: {} runs, dev-up cold p50={:.2}ms, warm p50={:.2}ms, \
         in-guest build p50={:.2}ms, report at {}",
        report.runs,
        report.dev_up_cold.p50,
        report.dev_up_warm.p50,
        report.in_guest_build.p50,
        out_path.display()
    );
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(())
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
