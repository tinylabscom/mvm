//! `mvmctl bench microvm-launch` — measure cold runtime-microvm launch
//! latency (Plan 93 Phase 2 Lever 0).
//!
//! Everything else in Phase 2 (kernel cmdline trim, handshake
//! pipelining, the warm pool) is judged against this harness — "without
//! measurement we'll optimise the wrong thing." The measurement
//! substrate here — per-iteration host wall-clock timing, N-run
//! statistics, a versioned JSON report, and baseline regression-gating
//! — is pure and fully unit-tested via a mock [`LaunchProbe`].
//!
//! The live libkrun probe (the only part that needs a real backend) is
//! the one piece not exercised by unit tests; it is a tracked follow-up
//! (see `specs/plans/93-fast-secure-dev-path-followups.md`). When wired
//! it MUST drive `admit_plan_for_boot` so the harness measures the real
//! signed-plan boot, never a bypass — otherwise we'd benchmark a
//! configuration that can never ship.
//!
//! Backend scope: v1 measures **libkrun** only. Vz / Firecracker benches
//! are a deferred follow-up (logged, not silently skipped).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};
use serde::{Deserialize, Serialize};

use mvm_core::user_config::MvmConfig;

use super::Cli;

/// Report schema version. Bump on any breaking change to
/// [`BenchReport`]; a baseline with a different version is refused as
/// incomparable rather than mis-compared.
pub const BENCH_SCHEMA_VERSION: u32 = 1;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: BenchAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum BenchAction {
    /// Measure cold runtime-microvm launch latency end-to-end.
    MicrovmLaunch(MicrovmLaunchArgs),
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MicrovmLaunchArgs {
    /// Number of measured iterations.
    #[arg(long, default_value_t = 20)]
    pub runs: u32,
    /// Warmup iterations discarded before measuring (absorb dylib
    /// load / codesign re-exec / page-cache cost on the first boot).
    #[arg(long, default_value_t = 2)]
    pub warmup: u32,
    /// Hypervisor backend to measure. v1 supports `libkrun` only.
    #[arg(long, default_value = "libkrun")]
    pub hypervisor: String,
    /// Write the JSON report here. Default:
    /// `~/.mvm/bench/microvm-launch-<rfc3339>.json` plus a stable
    /// `microvm-launch-latest.json` copy.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Also print the JSON report to stdout.
    #[arg(long)]
    pub json: bool,
    /// Compare the median `total_ready_ms` against this baseline
    /// report and exit non-zero if it regressed past
    /// `--max-regression-pct`.
    #[arg(long)]
    pub baseline: Option<PathBuf>,
    /// Maximum tolerated regression (percent) when `--baseline` is set.
    #[arg(long, default_value_t = 10.0)]
    pub max_regression_pct: f64,
}

// ──────────────────────────────────────────────────────────────────
// Timing + statistics (pure).
// ──────────────────────────────────────────────────────────────────

/// One iteration's per-phase host wall-clock timing, milliseconds.
///
/// All four fields are host-clock spans. Guest-monotonic milestones
/// (first-accept / entrypoint-ready, read from the guest's
/// `BootTimingReport`) are intentionally NOT folded in here — mixing
/// clock domains would double-count. `total_ready_ms` is the headline:
/// host wall-clock from `start()` entry to the control plane reporting
/// `Ready`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct IterationTiming {
    pub start_to_pid_ms: f64,
    pub pid_to_connect_ms: f64,
    pub handshake_ms: f64,
    pub total_ready_ms: f64,
}

/// Four host-monotonic instants captured during one boot. `start` is
/// `LibkrunBackend::start` entry; `pid_seen` is when the supervisor
/// PID file first appears; `connected` is the first successful vsock
/// connect to the guest agent; `ready` is when the guest reports the
/// control plane Ready.
// Task 5 (live probe wiring) will construct BootMarks from the real
// instants captured during the boot sequence.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct BootMarks {
    pub start: std::time::Instant,
    pub pid_seen: std::time::Instant,
    pub connected: std::time::Instant,
    pub ready: std::time::Instant,
}

impl BootMarks {
    /// Collapse the marks into the four reported spans. All arithmetic
    /// is `Instant`-difference so it can never go negative for marks
    /// captured in order. Takes `self` by value (`BootMarks` is `Copy`).
    // Task 5 (live probe wiring) is the first non-test caller.
    #[allow(dead_code)]
    pub fn to_timing(self) -> IterationTiming {
        let ms = |a: std::time::Instant, b: std::time::Instant| {
            b.saturating_duration_since(a).as_secs_f64() * 1000.0
        };
        IterationTiming {
            start_to_pid_ms: ms(self.start, self.pid_seen),
            pid_to_connect_ms: ms(self.pid_seen, self.connected),
            handshake_ms: ms(self.connected, self.ready),
            total_ready_ms: ms(self.start, self.ready),
        }
    }
}

/// Summary statistics for one phase across all measured iterations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct PhaseStats {
    pub min: f64,
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub max: f64,
    pub mean: f64,
    pub stddev: f64,
}

/// Linear-interpolated percentile over an unsorted sample. `p` is in
/// `[0, 100]`. Returns `NaN` for an empty sample (callers summarise
/// only non-empty run sets).
pub fn percentile(samples: &[f64], p: f64) -> f64 {
    if samples.is_empty() {
        return f64::NAN;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (p / 100.0) * ((sorted.len() - 1) as f64);
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        let frac = rank - lo as f64;
        sorted[lo] + (sorted[hi] - sorted[lo]) * frac
    }
}

/// Collapse a phase's samples into [`PhaseStats`]. Panics-free on
/// non-empty input; an empty input yields all-`NaN` (guarded upstream).
pub fn summarize(samples: &[f64]) -> PhaseStats {
    let n = samples.len();
    let mean = if n == 0 {
        f64::NAN
    } else {
        samples.iter().sum::<f64>() / n as f64
    };
    let stddev = if n < 2 {
        0.0
    } else {
        let var = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        var.sqrt()
    };
    PhaseStats {
        min: samples.iter().cloned().fold(f64::INFINITY, f64::min),
        p50: percentile(samples, 50.0),
        p90: percentile(samples, 90.0),
        p99: percentile(samples, 99.0),
        max: samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        mean,
        stddev,
    }
}

// ──────────────────────────────────────────────────────────────────
// Report schema + persistence.
// ──────────────────────────────────────────────────────────────────

/// Host + configuration fingerprint a report was measured under.
/// Two reports are only comparable when these match — a kernel or
/// backend change invalidates the baseline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostDescriptor {
    pub os: String,
    pub arch: String,
    pub hypervisor: String,
    pub libkrun_version: Option<String>,
    pub kernel_sha256: Option<String>,
    pub cmdline: Option<String>,
}

/// A full benchmark run: host fingerprint, run counts, per-phase
/// stats, and the raw per-iteration vector for re-analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    pub schema_version: u32,
    pub host: HostDescriptor,
    pub runs: u32,
    pub warmup: u32,
    pub start_to_pid_ms: PhaseStats,
    pub pid_to_connect_ms: PhaseStats,
    pub handshake_ms: PhaseStats,
    pub total_ready_ms: PhaseStats,
    pub raw: Vec<IterationTiming>,
}

fn build_report(
    host: HostDescriptor,
    runs: u32,
    warmup: u32,
    raw: Vec<IterationTiming>,
) -> BenchReport {
    let col = |f: fn(&IterationTiming) -> f64| summarize(&raw.iter().map(f).collect::<Vec<f64>>());
    BenchReport {
        schema_version: BENCH_SCHEMA_VERSION,
        host,
        runs,
        warmup,
        start_to_pid_ms: col(|i| i.start_to_pid_ms),
        pid_to_connect_ms: col(|i| i.pid_to_connect_ms),
        handshake_ms: col(|i| i.handshake_ms),
        total_ready_ms: col(|i| i.total_ready_ms),
        raw,
    }
}

/// Serialize `report` to `path` (pretty JSON), creating parent dirs.
pub fn write_report(report: &BenchReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating bench report dir {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(report).context("serializing bench report")?;
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Load a [`BenchReport`] from `path` for `--baseline` comparison.
pub fn read_report(path: &Path) -> Result<BenchReport> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading baseline {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing baseline {}", path.display()))
}

// ──────────────────────────────────────────────────────────────────
// Baseline regression gate (pure).
// ──────────────────────────────────────────────────────────────────

/// Outcome of comparing a current run to a baseline.
#[derive(Debug, Clone, PartialEq)]
pub enum RegressionVerdict {
    /// Within tolerance (negative `delta_pct` = improvement).
    Ok { delta_pct: f64 },
    /// Regressed beyond `limit_pct`.
    Regressed { delta_pct: f64, limit_pct: f64 },
    /// The two reports describe different hosts/configs/schema and
    /// must not be compared (avoids false greens after a kernel or
    /// backend change).
    Incomparable { reason: String },
}

/// Compare median `total_ready_ms`. Refuses to compare across a
/// differing host descriptor or schema version — silently comparing
/// a faster kernel's numbers against an older baseline would mask a
/// real regression (or invent a fake one).
pub fn compare_to_baseline(
    baseline: &BenchReport,
    current: &BenchReport,
    max_regression_pct: f64,
) -> RegressionVerdict {
    if baseline.schema_version != current.schema_version {
        return RegressionVerdict::Incomparable {
            reason: format!(
                "schema version differs (baseline {}, current {})",
                baseline.schema_version, current.schema_version
            ),
        };
    }
    if baseline.host != current.host {
        return RegressionVerdict::Incomparable {
            reason: "host descriptor differs (os/arch/hypervisor/kernel/cmdline) — \
                     a baseline from a different host or kernel is not comparable"
                .to_string(),
        };
    }
    let base = baseline.total_ready_ms.p50;
    let cur = current.total_ready_ms.p50;
    if !(base.is_finite() && cur.is_finite()) || base <= 0.0 {
        return RegressionVerdict::Incomparable {
            reason: "non-finite or zero baseline median total_ready_ms".to_string(),
        };
    }
    let delta_pct = (cur - base) / base * 100.0;
    if delta_pct > max_regression_pct {
        RegressionVerdict::Regressed {
            delta_pct,
            limit_pct: max_regression_pct,
        }
    } else {
        RegressionVerdict::Ok { delta_pct }
    }
}

// ──────────────────────────────────────────────────────────────────
// Orchestration (probe-generic, so tests use a mock).
// ──────────────────────────────────────────────────────────────────

/// One cold launch measurement. Implementors boot a guest, time it to
/// readiness, and tear it down before returning. The live impl MUST go
/// through signed-plan admission (claim 8).
pub trait LaunchProbe {
    fn measure_once(&mut self) -> Result<IterationTiming>;
    fn host_descriptor(&self) -> HostDescriptor;
}

/// Run `warmup` discarded iterations, then `runs` measured ones, and
/// summarise. The warmup boots absorb first-run dylib-load / codesign
/// cost so they don't skew the measured set.
pub fn run_benchmark<P: LaunchProbe>(probe: &mut P, runs: u32, warmup: u32) -> Result<BenchReport> {
    if runs == 0 {
        bail!("--runs must be >= 1");
    }
    for i in 0..warmup {
        probe
            .measure_once()
            .with_context(|| format!("warmup iteration {i}"))?;
    }
    let mut raw = Vec::with_capacity(runs as usize);
    for i in 0..runs {
        raw.push(
            probe
                .measure_once()
                .with_context(|| format!("measured iteration {i}"))?,
        );
    }
    Ok(build_report(probe.host_descriptor(), runs, warmup, raw))
}

// ──────────────────────────────────────────────────────────────────
// Live libkrun probe (tracked follow-up — see module docs).
// ──────────────────────────────────────────────────────────────────

struct LibkrunProbe {
    os: String,
    arch: String,
    // Per-iteration counter so each boot gets a unique VM name and the
    // teardown of run N never races the cold start of run N+1. Only
    // read on the `libkrun-live` path.
    #[allow(dead_code)]
    iter: u32,
}

impl LibkrunProbe {
    fn new(_args: &MicrovmLaunchArgs) -> Result<Self> {
        Ok(Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            iter: 0,
        })
    }
}

impl LaunchProbe for LibkrunProbe {
    fn measure_once(&mut self) -> Result<IterationTiming> {
        // Under `libkrun-live`, boot a real guest through the claim-8
        // admission path and convert the captured marks to spans.
        // Without the feature, fail honestly rather than fake a number —
        // a stock binary cannot boot a libkrun guest.
        #[cfg(feature = "libkrun-live")]
        {
            // Unique name per iteration so teardown of run N never races
            // the cold start of run N+1.
            self.iter += 1;
            let name = format!("mvm-bench-{}", self.iter);
            let marks = crate::commands::ops::bench_probe::boot_measure_once(&name)?;
            Ok(marks.to_timing())
        }
        #[cfg(not(feature = "libkrun-live"))]
        {
            bail!(
                "bench microvm-launch: this binary was built without the \
                 `libkrun-live` feature, so it cannot boot a real guest. \
                 Rebuild with `cargo build -p mvm-cli --features libkrun-live` \
                 on a host where libkrun boots (the slp/krun Homebrew trio \
                 installed). The measurement substrate is otherwise complete."
            )
        }
    }

    fn host_descriptor(&self) -> HostDescriptor {
        // Hash the canonical kernel so the regression gate refuses to
        // compare across a kernel swap (a faster/slower kernel must
        // invalidate the baseline, not silently mis-compare). Resolved
        // from the same default-microvm image the probe boots.
        let kernel_sha256 = super::bench_probe::resolve_probe_image()
            .ok()
            .and_then(|img| {
                mvm_security::image_verify::sha256_file(std::path::Path::new(&img.kernel)).ok()
            });
        HostDescriptor {
            os: self.os.clone(),
            arch: self.arch.clone(),
            hypervisor: "libkrun".to_string(),
            libkrun_version: None,
            kernel_sha256,
            // The runtime libkrun cmdline (Apple Silicon HVF / virtio
            // console), matching the backend's supervisor config.
            cmdline: Some("console=hvc0 root=/dev/vda rw init=/init".to_string()),
        }
    }
}

// ──────────────────────────────────────────────────────────────────
// CLI entry.
// ──────────────────────────────────────────────────────────────────

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        BenchAction::MicrovmLaunch(a) => run_microvm_launch(a),
    }
}

fn default_report_path(stamp: &str) -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_state_dir())
        .join("bench")
        .join(format!("microvm-launch-{stamp}.json"))
}

fn run_microvm_launch(args: MicrovmLaunchArgs) -> Result<()> {
    if args.hypervisor != "libkrun" {
        bail!(
            "bench microvm-launch v1 supports --hypervisor libkrun only (got {:?}); \
             Vz / Firecracker benches are a tracked Plan 93 follow-up",
            args.hypervisor
        );
    }

    let mut probe = LibkrunProbe::new(&args)?;
    let report = run_benchmark(&mut probe, args.runs, args.warmup)?;

    // utc_now() is RFC3339 (`2026-05-29T12:34:56+00:00`); sanitise the
    // colons/plus/dot so it's a safe filename component.
    let stamp = mvm_core::time::utc_now().replace([':', '+', '.'], "-");
    let out_path = match args.out {
        Some(p) => p,
        None => default_report_path(&stamp),
    };
    write_report(&report, &out_path)?;
    // Stable "latest" copy alongside the timestamped report so a CI
    // baseline always has a fixed path to read.
    if let Some(parent) = out_path.parent() {
        let latest = parent.join("microvm-launch-latest.json");
        let _ = write_report(&report, &latest);
    }
    eprintln!(
        "[mvm] bench microvm-launch: {} runs, median total_ready_ms={:.2}, report at {}",
        report.runs,
        report.total_ready_ms.p50,
        out_path.display()
    );

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    if let Some(baseline_path) = args.baseline.as_deref() {
        let baseline = read_report(baseline_path)?;
        match compare_to_baseline(&baseline, &report, args.max_regression_pct) {
            RegressionVerdict::Ok { delta_pct } => {
                eprintln!("[mvm] bench: within tolerance ({delta_pct:+.2}% vs baseline)");
            }
            RegressionVerdict::Incomparable { reason } => {
                bail!("bench baseline is incomparable: {reason}");
            }
            RegressionVerdict::Regressed {
                delta_pct,
                limit_pct,
            } => {
                bail!(
                    "bench regression: total_ready_ms median up {delta_pct:+.2}% \
                     vs baseline (limit {limit_pct:.2}%)"
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-9, "expected {b}, got {a}");
    }

    #[test]
    fn percentile_linear_interpolation_on_known_vector() {
        let v = vec![10.0, 20.0, 30.0, 40.0]; // n=4
        approx(percentile(&v, 0.0), 10.0);
        approx(percentile(&v, 100.0), 40.0);
        // p50 = midpoint of the [0..3] index range = rank 1.5 → 25.
        approx(percentile(&v, 50.0), 25.0);
    }

    #[test]
    fn percentile_single_and_empty() {
        approx(percentile(&[7.0], 50.0), 7.0);
        assert!(percentile(&[], 50.0).is_nan());
    }

    #[test]
    fn summarize_known_vector() {
        let v = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let s = summarize(&v);
        approx(s.min, 2.0);
        approx(s.max, 9.0);
        approx(s.mean, 5.0);
        // Population stddev of this classic set is 2.0.
        approx(s.stddev, 2.0);
    }

    fn host(arch: &str) -> HostDescriptor {
        HostDescriptor {
            os: "macos".to_string(),
            arch: arch.to_string(),
            hypervisor: "libkrun".to_string(),
            libkrun_version: Some("1.0".to_string()),
            kernel_sha256: Some("deadbeef".to_string()),
            cmdline: Some("root=/dev/vda rw init=/init".to_string()),
        }
    }

    fn report_with_median(arch: &str, median: f64) -> BenchReport {
        let raw = vec![IterationTiming {
            start_to_pid_ms: 1.0,
            pid_to_connect_ms: 1.0,
            handshake_ms: 1.0,
            total_ready_ms: median,
        }];
        build_report(host(arch), 1, 0, raw)
    }

    #[test]
    fn baseline_flags_regression_and_passes_improvement() {
        let base = report_with_median("aarch64", 100.0);
        let worse = report_with_median("aarch64", 120.0);
        let better = report_with_median("aarch64", 80.0);

        assert!(matches!(
            compare_to_baseline(&base, &worse, 10.0),
            RegressionVerdict::Regressed { .. }
        ));
        assert!(matches!(
            compare_to_baseline(&base, &better, 10.0),
            RegressionVerdict::Ok { .. }
        ));
        // Exactly at the limit is not a regression.
        let at_limit = report_with_median("aarch64", 110.0);
        assert!(matches!(
            compare_to_baseline(&base, &at_limit, 10.0),
            RegressionVerdict::Ok { .. }
        ));
    }

    #[test]
    fn baseline_refuses_cross_host_comparison() {
        let base = report_with_median("aarch64", 100.0);
        let other = report_with_median("x86_64", 100.0);
        assert!(matches!(
            compare_to_baseline(&base, &other, 10.0),
            RegressionVerdict::Incomparable { .. }
        ));
    }

    #[test]
    fn report_json_roundtrips() {
        let r = report_with_median("aarch64", 42.0);
        let json = serde_json::to_string(&r).unwrap();
        let back: BenchReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, BENCH_SCHEMA_VERSION);
        approx(back.total_ready_ms.p50, 42.0);
        assert_eq!(back.raw.len(), 1);
    }

    #[test]
    fn write_then_read_report_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("microvm-launch-test.json");
        let r = report_with_median("aarch64", 55.0);
        write_report(&r, &path).unwrap();
        let back = read_report(&path).unwrap();
        approx(back.total_ready_ms.p50, 55.0);
    }

    /// Deterministic probe so the orchestration loop is testable
    /// without a VM: it yields a fixed timing per call and counts
    /// calls so the test can assert warmup boots are discarded.
    struct MockProbe {
        timing: IterationTiming,
        calls: usize,
    }

    impl LaunchProbe for MockProbe {
        fn measure_once(&mut self) -> Result<IterationTiming> {
            self.calls += 1;
            Ok(self.timing)
        }
        fn host_descriptor(&self) -> HostDescriptor {
            host("aarch64")
        }
    }

    #[test]
    fn run_benchmark_discards_warmup_and_summarises_measured() {
        let mut probe = MockProbe {
            timing: IterationTiming {
                start_to_pid_ms: 5.0,
                pid_to_connect_ms: 3.0,
                handshake_ms: 2.0,
                total_ready_ms: 50.0,
            },
            calls: 0,
        };
        let report = run_benchmark(&mut probe, 4, 2).unwrap();
        // warmup(2) + runs(4) boots total.
        assert_eq!(probe.calls, 6);
        assert_eq!(report.runs, 4);
        assert_eq!(report.warmup, 2);
        // Only the 4 measured iterations are summarised.
        assert_eq!(report.raw.len(), 4);
        approx(report.total_ready_ms.p50, 50.0);
        approx(report.start_to_pid_ms.mean, 5.0);
    }

    #[test]
    fn run_benchmark_rejects_zero_runs() {
        let mut probe = MockProbe {
            timing: IterationTiming {
                start_to_pid_ms: 1.0,
                pid_to_connect_ms: 1.0,
                handshake_ms: 1.0,
                total_ready_ms: 1.0,
            },
            calls: 0,
        };
        assert!(run_benchmark(&mut probe, 0, 0).is_err());
    }

    #[test]
    fn spans_from_marks_are_non_negative_and_ordered() {
        use std::time::Duration;
        let t0 = std::time::Instant::now();
        let marks = BootMarks {
            start: t0,
            pid_seen: t0 + Duration::from_millis(10),
            connected: t0 + Duration::from_millis(25),
            ready: t0 + Duration::from_millis(40),
        };
        let it = marks.to_timing();
        approx(it.start_to_pid_ms, 10.0);
        approx(it.pid_to_connect_ms, 15.0);
        approx(it.handshake_ms, 15.0);
        approx(it.total_ready_ms, 40.0);
        assert!(it.total_ready_ms >= it.start_to_pid_ms);
    }

    /// Live boot of the canonical default-microvm image through the
    /// real admission path. Gated behind `libkrun-live` so stock CI
    /// (no Hypervisor.framework nested virt) skips it; runs on a dev
    /// host / self-hosted macOS runner with the slp/krun trio + an
    /// `mvm-libkrun-supervisor` on the launch path.
    #[cfg(feature = "libkrun-live")]
    #[test]
    fn live_probe_returns_finite_ordered_spans() {
        let mut probe = LibkrunProbe::new(&MicrovmLaunchArgs {
            runs: 1,
            warmup: 0,
            hypervisor: "libkrun".to_string(),
            out: None,
            json: false,
            baseline: None,
            max_regression_pct: 10.0,
        })
        .unwrap();
        let it = probe
            .measure_once()
            .expect("live boot should succeed on a libkrun host");
        for v in [
            it.start_to_pid_ms,
            it.pid_to_connect_ms,
            it.handshake_ms,
            it.total_ready_ms,
        ] {
            assert!(
                v.is_finite() && v >= 0.0,
                "span must be finite and non-negative: {v}"
            );
        }
        assert!(it.total_ready_ms >= it.start_to_pid_ms);
    }

    /// The libkrun probe must stamp the kernel sha into the
    /// `HostDescriptor` so a kernel swap invalidates the baseline (a
    /// `None` kernel sha would let a different kernel mis-compare as a
    /// regression-free run). Needs the cached image present, not a
    /// boot — gated under `libkrun-live` because it touches
    /// `~/.cache/mvm`.
    #[cfg(feature = "libkrun-live")]
    #[test]
    fn host_descriptor_is_populated() {
        let probe = LibkrunProbe::new(&MicrovmLaunchArgs {
            runs: 1,
            warmup: 0,
            hypervisor: "libkrun".to_string(),
            out: None,
            json: false,
            baseline: None,
            max_regression_pct: 10.0,
        })
        .unwrap();
        let h = probe.host_descriptor();
        assert!(
            h.kernel_sha256.is_some(),
            "kernel sha must be set so a kernel swap invalidates the baseline"
        );
    }
}
