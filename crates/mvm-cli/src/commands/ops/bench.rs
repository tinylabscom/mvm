//! `mvmctl bench microvm-launch` / `microvm-density` — measure runtime
//! microVM launch latency and host footprint.
//!
//! Every other launch optimisation (kernel cmdline trim, handshake
//! pipelining, the warm pool) is judged against this harness — without
//! measurement we'd optimise the wrong thing. The measurement
//! substrate here — per-iteration host wall-clock timing, N-run
//! statistics, a versioned JSON report, and baseline regression-gating
//! — is pure and fully unit-tested via a mock [`LaunchProbe`].
//!
//! Live probes MUST drive signed-plan admission so the harness measures
//! a launch shape that can actually ship. libkrun is feature-gated
//! behind `libkrun-live`; Firecracker runs on Linux/KVM hosts.
//! Firecracker v1 reports backend-accepted/PID-observed readiness
//! because the current Linux proof image does not expose the guest
//! control-plane ping endpoint.
//!
//! Backend scope: v1 measures libkrun, Vz, and Firecracker.

use std::path::{Path, PathBuf};
use std::thread;

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
    /// Measure held-live runtime-microvm supervisor/VMM footprint.
    MicrovmDensity(MicrovmDensityArgs),
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
    /// Launch this many instances concurrently as a single wave and
    /// report P50/P95/P99 for that wave. The default keeps the
    /// original serial benchmark semantics.
    #[arg(long, default_value_t = 1)]
    pub concurrency: u32,
    /// Safety cap for `--concurrency` so a typo cannot fork-bomb the host.
    #[arg(long, default_value_t = 64)]
    pub max_concurrency: u32,
    /// Hypervisor backend to measure. v1 supports `libkrun`, macOS `vz`, and
    /// Linux `firecracker`.
    #[arg(long, default_value = "libkrun")]
    pub hypervisor: String,
    /// Warm standby pool target to request for each measured launch.
    ///
    /// Currently supported for Linux Firecracker launch probes; use
    /// `0` for a cold baseline and `1` for the Plan 118 warm-claim
    /// delta proof.
    #[arg(long, default_value_t = 0)]
    pub warm_pool_size: u32,
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

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MicrovmDensityArgs {
    /// Number of admitted instances to boot and hold live while sampling footprint.
    #[arg(long, default_value_t = 4)]
    pub count: u32,
    /// Safety cap for `--count` so a typo cannot exhaust host memory.
    #[arg(long, default_value_t = 16)]
    pub max_count: u32,
    /// Hypervisor backend to measure. v1 supports `libkrun`, macOS `vz`, and
    /// Linux `firecracker`.
    #[arg(long, default_value = "libkrun")]
    pub hypervisor: String,
    /// Write the JSON report here. Default:
    /// `~/.mvm/bench/microvm-density-<rfc3339>.json` plus a stable
    /// `microvm-density-latest.json` copy.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Also print the JSON report to stdout.
    #[arg(long)]
    pub json: bool,
    /// Compare `per_instance_bytes` against this baseline report and
    /// exit non-zero if it regressed past `--max-regression-pct`.
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
// Live probe wiring will construct BootMarks from the real instants
// captured during the boot sequence.
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
    // Live probe wiring is the first non-test caller.
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
    #[serde(default)]
    pub readiness_boundary: Option<String>,
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

/// Footprint sample for one launched instance, in bytes.
///
/// The platform accessor owns how the number is measured (Linux PSS,
/// macOS `phys_footprint`). The report schema keeps it normalized to
/// bytes so density baselines are comparable within the same
/// [`HostDescriptor`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstanceFootprint {
    pub vm_name: String,
    pub pid: u32,
    pub bytes: u64,
}

/// Aggregate density result for a held-live instance set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DensityStats {
    pub instances: u32,
    pub total_bytes: u64,
    pub per_instance_bytes: u64,
    pub min_instance_bytes: u64,
    pub max_instance_bytes: u64,
}

/// Read-only density report. Live orchestration boots `count`
/// admitted instances, samples their supervisor/VMM process
/// footprints, then tears them down; the pure schema is VM-free.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DensityReport {
    pub schema_version: u32,
    pub host: HostDescriptor,
    pub count: u32,
    pub max_count: u32,
    pub stats: DensityStats,
    pub raw: Vec<InstanceFootprint>,
}

/// Tail-latency summary for concurrent launch waves.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct TailLatencyStats {
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
}

/// Launch distribution report for a single concurrency level. This is
/// the concurrent sibling of [`BenchReport`]: each raw timing is one
/// admitted instance launched as part of the same wave.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LaunchDistributionReport {
    pub schema_version: u32,
    pub host: HostDescriptor,
    pub concurrency: u32,
    pub start_to_pid_ms: PhaseStats,
    pub pid_to_connect_ms: PhaseStats,
    pub handshake_ms: PhaseStats,
    pub total_ready_ms: PhaseStats,
    pub total_ready_tail_ms: TailLatencyStats,
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

/// Derive density stats from per-instance footprint samples.
#[cfg(any(
    test,
    feature = "libkrun-live",
    target_os = "linux",
    target_os = "macos"
))]
pub fn summarize_density(samples: &[InstanceFootprint]) -> DensityStats {
    let instances = samples.len() as u32;
    let total_bytes = samples.iter().map(|sample| sample.bytes).sum::<u64>();
    let per_instance_bytes = if instances == 0 {
        0
    } else {
        total_bytes / u64::from(instances)
    };
    DensityStats {
        instances,
        total_bytes,
        per_instance_bytes,
        min_instance_bytes: samples.iter().map(|sample| sample.bytes).min().unwrap_or(0),
        max_instance_bytes: samples.iter().map(|sample| sample.bytes).max().unwrap_or(0),
    }
}

pub fn summarize_tail_latency(samples: &[f64]) -> TailLatencyStats {
    TailLatencyStats {
        p50: percentile(samples, 50.0),
        p95: percentile(samples, 95.0),
        p99: percentile(samples, 99.0),
    }
}

#[cfg(any(
    test,
    feature = "libkrun-live",
    target_os = "linux",
    target_os = "macos"
))]
pub fn build_density_report(
    host: HostDescriptor,
    count: u32,
    max_count: u32,
    raw: Vec<InstanceFootprint>,
) -> DensityReport {
    DensityReport {
        schema_version: BENCH_SCHEMA_VERSION,
        host,
        count,
        max_count,
        stats: summarize_density(&raw),
        raw,
    }
}

pub fn build_launch_distribution_report(
    host: HostDescriptor,
    concurrency: u32,
    raw: Vec<IterationTiming>,
) -> LaunchDistributionReport {
    let col = |f: fn(&IterationTiming) -> f64| summarize(&raw.iter().map(f).collect::<Vec<f64>>());
    let total_ready_samples = raw
        .iter()
        .map(|iteration| iteration.total_ready_ms)
        .collect::<Vec<f64>>();
    LaunchDistributionReport {
        schema_version: BENCH_SCHEMA_VERSION,
        host,
        concurrency,
        start_to_pid_ms: col(|i| i.start_to_pid_ms),
        pid_to_connect_ms: col(|i| i.pid_to_connect_ms),
        handshake_ms: col(|i| i.handshake_ms),
        total_ready_ms: col(|i| i.total_ready_ms),
        total_ready_tail_ms: summarize_tail_latency(&total_ready_samples),
        raw,
    }
}

/// Serialize `report` to `path` (pretty JSON), creating parent dirs.
pub fn write_json_report<T: Serialize>(report: &T, path: &Path) -> Result<()> {
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

pub fn read_launch_distribution_report(path: &Path) -> Result<LaunchDistributionReport> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading baseline {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing baseline {}", path.display()))
}

pub fn read_density_report(path: &Path) -> Result<DensityReport> {
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

pub fn compare_launch_distribution_to_baseline(
    baseline: &LaunchDistributionReport,
    current: &LaunchDistributionReport,
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
    if baseline.concurrency != current.concurrency {
        return RegressionVerdict::Incomparable {
            reason: format!(
                "concurrency differs (baseline {}, current {})",
                baseline.concurrency, current.concurrency
            ),
        };
    }
    compare_metric(
        baseline.total_ready_tail_ms.p95,
        current.total_ready_tail_ms.p95,
        max_regression_pct,
        "non-finite or zero baseline p95 total_ready_ms",
    )
}

pub fn compare_density_to_baseline(
    baseline: &DensityReport,
    current: &DensityReport,
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
    if baseline.count != current.count {
        return RegressionVerdict::Incomparable {
            reason: format!(
                "density count differs (baseline {}, current {})",
                baseline.count, current.count
            ),
        };
    }
    compare_metric(
        baseline.stats.per_instance_bytes as f64,
        current.stats.per_instance_bytes as f64,
        max_regression_pct,
        "zero baseline per_instance_bytes",
    )
}

fn compare_metric(
    baseline: f64,
    current: f64,
    max_regression_pct: f64,
    invalid_reason: &str,
) -> RegressionVerdict {
    if !(baseline.is_finite() && current.is_finite()) || baseline <= 0.0 {
        return RegressionVerdict::Incomparable {
            reason: invalid_reason.to_string(),
        };
    }
    let delta_pct = (current - baseline) / baseline * 100.0;
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

/// Run one concurrent launch wave. Each worker gets its own probe instance so
/// the live path uses distinct VM names, signed plans, nonces, and state dirs.
pub fn run_launch_distribution<F, P>(
    host: HostDescriptor,
    concurrency: u32,
    max_concurrency: u32,
    make_probe: F,
) -> Result<LaunchDistributionReport>
where
    F: Fn(u32) -> Result<P> + Send + Sync,
    P: LaunchProbe + Send + 'static,
{
    if concurrency == 0 {
        bail!("--concurrency must be >= 1");
    }
    if max_concurrency == 0 {
        bail!("--max-concurrency must be >= 1");
    }
    if concurrency > max_concurrency {
        bail!("--concurrency {concurrency} exceeds --max-concurrency {max_concurrency}");
    }

    let make_probe = &make_probe;
    let raw = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(concurrency as usize);
        for index in 0..concurrency {
            handles.push(scope.spawn(move || {
                let mut probe = make_probe(index)?;
                probe
                    .measure_once()
                    .with_context(|| format!("concurrent launch worker {index}"))
            }));
        }

        let mut raw = Vec::with_capacity(concurrency as usize);
        for handle in handles {
            raw.push(
                handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("launch worker panicked"))??,
            );
        }
        Ok::<_, anyhow::Error>(raw)
    })?;

    Ok(build_launch_distribution_report(host, concurrency, raw))
}

/// Linux `/proc/<pid>/smaps_rollup` reports proportional set size in KiB.
#[cfg(any(test, target_os = "linux"))]
pub fn parse_linux_smaps_rollup_pss_bytes(input: &str) -> Result<u64> {
    for line in input.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("Pss:") {
            let mut parts = rest.split_whitespace();
            let kib = parts
                .next()
                .context("Pss line missing numeric value")?
                .parse::<u64>()
                .context("parsing Pss KiB value")?;
            let unit = parts.next().unwrap_or("kB");
            if unit != "kB" {
                bail!("unsupported Pss unit {unit:?}; expected kB");
            }
            return kib
                .checked_mul(1024)
                .context("Pss KiB value overflowed bytes");
        }
    }
    bail!("smaps_rollup did not contain a Pss line")
}

#[cfg(target_os = "linux")]
pub fn read_process_footprint_bytes(pid: u32) -> Result<u64> {
    let path = PathBuf::from("/proc")
        .join(pid.to_string())
        .join("smaps_rollup");
    let body =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    parse_linux_smaps_rollup_pss_bytes(&body)
}

#[cfg(target_os = "macos")]
pub fn read_process_footprint_bytes(pid: u32) -> Result<u64> {
    let mut info = std::mem::MaybeUninit::<libc::rusage_info_v4>::zeroed();
    let rc = unsafe {
        libc::proc_pid_rusage(
            pid as libc::c_int,
            libc::RUSAGE_INFO_V4,
            info.as_mut_ptr().cast(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("proc_pid_rusage(RUSAGE_INFO_V4) for pid {pid}"));
    }
    let info = unsafe { info.assume_init() };
    Ok(info.ri_phys_footprint)
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
pub fn read_process_footprint_bytes(_pid: u32) -> Result<u64> {
    bail!("process footprint sampling is only implemented on Linux and macOS")
}

/// Persist a guest-monotonic boot timing cross-check beside the bench reports.
/// The host-clock report remains the regression metric; this sidecar audits the
/// guest's own phase timing without mixing clock domains.
#[cfg(any(feature = "libkrun-live", target_os = "macos"))]
pub(in crate::commands::ops) fn write_boot_timing_sidecar(
    vm_name: &str,
    boot_millis: &mvm_guest::vsock::BootTimingReport,
) -> Result<()> {
    let path = PathBuf::from(mvm_core::config::mvm_state_dir())
        .join("bench")
        .join(format!("boot-timing-{vm_name}.json"));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating boot timing dir {}", parent.display()))?;
    }
    let json =
        serde_json::to_string_pretty(boot_millis).context("serializing boot timing report")?;
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

// ──────────────────────────────────────────────────────────────────
// Live libkrun probe (tracked follow-up — see module docs).
// ──────────────────────────────────────────────────────────────────

struct LibkrunProbe {
    os: String,
    arch: String,
    #[cfg(feature = "libkrun-live")]
    name_prefix: String,
    // Per-iteration counter so each boot gets a unique VM name and the
    // teardown of run N never races the cold start of run N+1. Only
    // read on the `libkrun-live` path.
    #[allow(dead_code)]
    iter: u32,
}

impl LibkrunProbe {
    fn new(_args: &MicrovmLaunchArgs) -> Result<Self> {
        Self::new_with_prefix("mvm-bench")
    }

    fn new_with_prefix(name_prefix: impl Into<String>) -> Result<Self> {
        let name_prefix = name_prefix.into();
        #[cfg(not(feature = "libkrun-live"))]
        let _ = name_prefix;
        Ok(Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            #[cfg(feature = "libkrun-live")]
            name_prefix,
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
            let name = format!("{}-{}", self.name_prefix, self.iter);
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
                mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(&img.kernel)).ok()
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
            readiness_boundary: Some("guest-agent-ping".to_string()),
        }
    }
}

#[cfg(target_os = "macos")]
struct VzProbe {
    os: String,
    arch: String,
    name_prefix: String,
    iter: u32,
}

#[cfg(target_os = "macos")]
impl VzProbe {
    fn new(_args: &MicrovmLaunchArgs) -> Result<Self> {
        Self::new_with_prefix("mvm-bench-vz")
    }

    fn new_with_prefix(name_prefix: impl Into<String>) -> Result<Self> {
        Ok(Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            name_prefix: name_prefix.into(),
            iter: 0,
        })
    }
}

#[cfg(target_os = "macos")]
impl LaunchProbe for VzProbe {
    fn measure_once(&mut self) -> Result<IterationTiming> {
        self.iter += 1;
        let name = format!("{}-{}", self.name_prefix, self.iter);
        let held = boot_vz_hold_once(&name)?;
        let marks = held.marks;
        drop(held);
        assert_vz_bench_cleanup(&name)?;
        Ok(marks.to_timing())
    }

    fn host_descriptor(&self) -> HostDescriptor {
        let kernel_sha256 = super::bench_probe::resolve_probe_image()
            .ok()
            .and_then(|img| {
                mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(&img.kernel)).ok()
            });
        HostDescriptor {
            os: self.os.clone(),
            arch: self.arch.clone(),
            hypervisor: "vz".to_string(),
            libkrun_version: None,
            kernel_sha256,
            cmdline: Some("console=hvc0 root=/dev/vda rw init=/init".to_string()),
            readiness_boundary: Some("guest-agent-readiness".to_string()),
        }
    }
}

#[cfg(target_os = "macos")]
struct HeldVzVm {
    vm_name: String,
    pid: u32,
    marks: BootMarks,
}

#[cfg(target_os = "macos")]
impl HeldVzVm {
    fn vm_name(&self) -> &str {
        &self.vm_name
    }

    fn pid(&self) -> u32 {
        self.pid
    }
}

#[cfg(target_os = "macos")]
impl Drop for HeldVzVm {
    fn drop(&mut self) {
        use mvm_core::vm_backend::VmId;

        let backend = mvm_backend::backend::AnyBackend::from_hypervisor("vz");
        let _ = backend.stop(&VmId(self.vm_name.clone()));
    }
}

#[cfg(target_os = "macos")]
fn boot_vz_hold_once(vm_name: &str) -> Result<HeldVzVm> {
    use mvm_core::vm_backend::VmStartConfig;
    use std::time::Instant;

    use crate::commands::vm::plan_admission::populate_audit_substrate;

    let img = super::bench_probe::resolve_probe_image()?;
    let admitted = super::bench_probe::admit_probe_plan(
        std::path::Path::new(&img.rootfs),
        vm_name,
        "vz",
        None,
    )?;

    let mut cfg = VmStartConfig {
        name: vm_name.to_string(),
        rootfs_path: img.rootfs.clone(),
        kernel_path: Some(img.kernel.clone()),
        cpus: 2,
        memory_mib: 2048,
        ..Default::default()
    };
    populate_audit_substrate(&mut cfg, &admitted, None)?;

    let backend = mvm_backend::backend::AnyBackend::from_hypervisor("vz");
    let start = Instant::now();
    backend.start(&cfg).context("probe vz backend.start")?;

    let (pid, pid_seen) = wait_for_vz_pid_file(vm_name)?;
    let (connected, ready) = wait_for_guest_readiness_and_record(vm_name)?;

    Ok(HeldVzVm {
        vm_name: vm_name.to_string(),
        pid,
        marks: BootMarks {
            start,
            pid_seen,
            connected,
            ready,
        },
    })
}

#[cfg(target_os = "macos")]
fn wait_for_vz_pid_file(vm_name: &str) -> Result<(u32, std::time::Instant)> {
    use mvm_guest::vsock::adaptive_backoff;

    let pid_path = mvm_core::config::vm_state_dir(vm_name).join("vz.pid");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut attempt = 0u32;
    loop {
        if let Ok(body) = std::fs::read_to_string(&pid_path)
            && let Ok(pid) = body.trim().parse::<u32>()
        {
            return Ok((pid, std::time::Instant::now()));
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "probe: Vz supervisor pid file never appeared or was invalid at {}",
                pid_path.display()
            );
        }
        std::thread::sleep(adaptive_backoff(attempt));
        attempt += 1;
    }
}

#[cfg(target_os = "macos")]
fn wait_for_guest_readiness_and_record(
    vm_name: &str,
) -> Result<(std::time::Instant, std::time::Instant)> {
    use mvm_guest::vsock::adaptive_backoff;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let mut attempt = 0u32;
    loop {
        if let Ok(report) = crate::commands::vm::wait::fetch_readiness(vm_name) {
            let now = std::time::Instant::now();
            write_boot_timing_sidecar(vm_name, &report.boot_millis)?;
            return Ok((now, now));
        }
        if std::time::Instant::now() >= deadline {
            bail!("probe: guest control plane never reached Ready (readiness) for {vm_name}");
        }
        std::thread::sleep(adaptive_backoff(attempt));
        attempt += 1;
    }
}

#[cfg(target_os = "macos")]
fn assert_vz_bench_cleanup(vm_name: &str) -> Result<()> {
    let backend = mvm_backend::backend::AnyBackend::from_hypervisor("vz");
    let list = backend
        .list()
        .with_context(|| format!("listing Vz VMs after bench cleanup for {vm_name}"))?;
    if list.iter().any(|vm| vm.name == vm_name) {
        bail!("bench cleanup leaked Vz VM registry entry for {vm_name}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct FirecrackerProbe {
    os: String,
    arch: String,
    name_prefix: String,
    warm_pool_size: u32,
    iter: u32,
}

#[cfg(target_os = "linux")]
impl FirecrackerProbe {
    fn new(args: &MicrovmLaunchArgs) -> Result<Self> {
        Self::new_with_prefix_and_warm_pool_size("mvm-bench-fc", args.warm_pool_size)
    }

    fn new_with_prefix(name_prefix: impl Into<String>) -> Result<Self> {
        Self::new_with_prefix_and_warm_pool_size(name_prefix, 0)
    }

    fn new_with_prefix_and_warm_pool_size(
        name_prefix: impl Into<String>,
        warm_pool_size: u32,
    ) -> Result<Self> {
        Ok(Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            name_prefix: name_prefix.into(),
            warm_pool_size,
            iter: 0,
        })
    }
}

#[cfg(target_os = "linux")]
impl LaunchProbe for FirecrackerProbe {
    fn measure_once(&mut self) -> Result<IterationTiming> {
        self.iter += 1;
        let name = format!("{}-{}", self.name_prefix, self.iter);
        let held = boot_firecracker_hold_once(&name, self.warm_pool_size)?;
        let marks = held.marks;
        drop(held);
        assert_firecracker_bench_cleanup(&name)?;
        Ok(marks.to_timing())
    }

    fn host_descriptor(&self) -> HostDescriptor {
        let kernel_sha256 = super::bench_probe::resolve_probe_image()
            .ok()
            .and_then(|img| {
                mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(&img.kernel)).ok()
            });
        HostDescriptor {
            os: self.os.clone(),
            arch: self.arch.clone(),
            hypervisor: "firecracker".to_string(),
            libkrun_version: None,
            kernel_sha256,
            cmdline: Some("console=ttyS0 reboot=k panic=1 net.ifnames=0 ip=<per-slot>".to_string()),
            readiness_boundary: Some("firecracker-pid".to_string()),
        }
    }
}

#[cfg(target_os = "linux")]
struct HeldFirecrackerVm {
    vm_name: String,
    pid: u32,
    marks: BootMarks,
}

#[cfg(target_os = "linux")]
impl HeldFirecrackerVm {
    fn vm_name(&self) -> &str {
        &self.vm_name
    }

    fn pid(&self) -> u32 {
        self.pid
    }
}

#[cfg(target_os = "linux")]
impl Drop for HeldFirecrackerVm {
    fn drop(&mut self) {
        use mvm_core::vm_backend::VmId;

        let backend = mvm_backend::backend::AnyBackend::from_hypervisor("firecracker");
        let _ = backend.stop(&VmId(self.vm_name.clone()));
    }
}

#[cfg(target_os = "linux")]
fn boot_firecracker_hold_once(vm_name: &str, warm_pool_size: u32) -> Result<HeldFirecrackerVm> {
    use mvm_core::vm_backend::VmStartConfig;
    use std::time::Instant;

    use crate::commands::vm::plan_admission::populate_audit_substrate;

    let img = super::bench_probe::resolve_probe_image()?;
    let admitted = super::bench_probe::admit_probe_plan(
        std::path::Path::new(&img.rootfs),
        vm_name,
        "firecracker",
        None,
    )?;

    let mut cfg = VmStartConfig {
        name: vm_name.to_string(),
        rootfs_path: img.rootfs.clone(),
        kernel_path: Some(img.kernel.clone()),
        cpus: 2,
        memory_mib: 2048,
        warm_pool_size,
        ..Default::default()
    };
    populate_audit_substrate(&mut cfg, &admitted, None)?;

    let backend = mvm_backend::backend::AnyBackend::from_hypervisor("firecracker");
    let start = Instant::now();
    backend
        .start(&cfg)
        .context("probe firecracker backend.start")?;

    let abs_dir = mvm_backend::microvm::resolve_running_vm_dir(vm_name)?;
    let (pid, pid_seen) = wait_for_firecracker_pid(&abs_dir)?;
    // The current Linux proof image used by the Firecracker host boots
    // successfully but does not expose the mvm guest-agent ping endpoint.
    // Report backend-accepted/PID-observed timing honestly and fingerprint
    // that boundary in HostDescriptor so it cannot be baseline-compared
    // against guest-agent-ready libkrun reports.
    let connected = pid_seen;
    let ready = pid_seen;

    Ok(HeldFirecrackerVm {
        vm_name: vm_name.to_string(),
        pid,
        marks: BootMarks {
            start,
            pid_seen,
            connected,
            ready,
        },
    })
}

#[cfg(target_os = "linux")]
fn assert_firecracker_bench_cleanup(vm_name: &str) -> Result<()> {
    let backend = mvm_backend::backend::AnyBackend::from_hypervisor("firecracker");
    let list = backend
        .list()
        .with_context(|| format!("listing VMs after bench cleanup for {vm_name}"))?;
    if list.iter().any(|vm| vm.name == vm_name) {
        anyhow::bail!("bench cleanup leaked VM registry entry for {vm_name}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wait_for_firecracker_pid(abs_dir: &str) -> Result<(u32, std::time::Instant)> {
    use mvm_guest::vsock::adaptive_backoff;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut attempt = 0u32;
    loop {
        if let Ok(pid) = mvm_backend::microvm::read_firecracker_pid(abs_dir) {
            return Ok((pid, std::time::Instant::now()));
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("probe: Firecracker pid file never appeared under {abs_dir}");
        }
        std::thread::sleep(adaptive_backoff(attempt));
        attempt += 1;
    }
}

// ──────────────────────────────────────────────────────────────────
// CLI entry.
// ──────────────────────────────────────────────────────────────────

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        BenchAction::MicrovmLaunch(a) => run_microvm_launch(a),
        BenchAction::MicrovmDensity(a) => run_microvm_density(a),
    }
}

fn default_report_path(kind: &str, stamp: &str) -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_state_dir())
        .join("bench")
        .join(format!("{kind}-{stamp}.json"))
}

fn timestamp_for_report_path() -> String {
    // utc_now() is RFC3339 (`2026-05-29T12:34:56+00:00`); sanitise the
    // colons/plus/dot so it's a safe filename component.
    mvm_core::time::utc_now().replace([':', '+', '.'], "-")
}

fn write_report_with_latest<T: Serialize>(
    report: &T,
    out: Option<PathBuf>,
    kind: &str,
) -> Result<PathBuf> {
    let stamp = timestamp_for_report_path();
    let out_path = match out {
        Some(p) => p,
        None => default_report_path(kind, &stamp),
    };
    write_json_report(report, &out_path)?;
    if let Some(parent) = out_path.parent() {
        let latest = parent.join(format!("{kind}-latest.json"));
        let _ = write_json_report(report, &latest);
    }
    Ok(out_path)
}

fn run_microvm_launch(args: MicrovmLaunchArgs) -> Result<()> {
    validate_launch_hypervisor(&args.hypervisor)?;
    if args.warm_pool_size > 0 && args.hypervisor != "firecracker" {
        bail!("--warm-pool-size is currently wired for --hypervisor firecracker benchmarks");
    }
    if args.concurrency == 0 {
        bail!("--concurrency must be >= 1");
    }
    if args.max_concurrency == 0 {
        bail!("--max-concurrency must be >= 1");
    }
    if args.concurrency > args.max_concurrency {
        bail!(
            "--concurrency {} exceeds --max-concurrency {}",
            args.concurrency,
            args.max_concurrency
        );
    }

    if args.concurrency > 1 {
        if args.warmup > 0 {
            bail!("--warmup is only supported for serial microvm-launch runs");
        }
        let report = match args.hypervisor.as_str() {
            "libkrun" => {
                let host = LibkrunProbe::new(&args)?.host_descriptor();
                run_launch_distribution(host, args.concurrency, args.max_concurrency, |i| {
                    LibkrunProbe::new_with_prefix(format!("mvm-bench-c{i}"))
                })?
            }
            "firecracker" => run_firecracker_launch_distribution(&args)?,
            "vz" => run_vz_launch_distribution(&args)?,
            _ => unreachable!("validated hypervisor"),
        };
        let out_path = write_report_with_latest(&report, args.out, "microvm-launch-concurrent")?;
        eprintln!(
            "[mvm] bench microvm-launch: concurrency={}, p95 total_ready_ms={:.2}, report at {}",
            report.concurrency,
            report.total_ready_tail_ms.p95,
            out_path.display()
        );
        if args.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        if let Some(baseline_path) = args.baseline.as_deref() {
            let baseline = read_launch_distribution_report(baseline_path)?;
            match compare_launch_distribution_to_baseline(
                &baseline,
                &report,
                args.max_regression_pct,
            ) {
                RegressionVerdict::Ok { delta_pct } => {
                    eprintln!(
                        "[mvm] bench: concurrent p95 within tolerance ({delta_pct:+.2}% vs baseline)"
                    );
                }
                RegressionVerdict::Incomparable { reason } => {
                    bail!("bench baseline is incomparable: {reason}");
                }
                RegressionVerdict::Regressed {
                    delta_pct,
                    limit_pct,
                } => {
                    bail!(
                        "bench regression: concurrent p95 total_ready_ms up {delta_pct:+.2}% \
                         vs baseline (limit {limit_pct:.2}%)"
                    );
                }
            }
        }
        return Ok(());
    }

    let report = match args.hypervisor.as_str() {
        "libkrun" => {
            let mut probe = LibkrunProbe::new(&args)?;
            run_benchmark(&mut probe, args.runs, args.warmup)?
        }
        "firecracker" => {
            let mut probe = new_firecracker_probe(&args)?;
            run_benchmark(&mut probe, args.runs, args.warmup)?
        }
        "vz" => {
            let mut probe = new_vz_probe(&args)?;
            run_benchmark(&mut probe, args.runs, args.warmup)?
        }
        _ => unreachable!("validated hypervisor"),
    };
    let out_path = write_report_with_latest(&report, args.out, "microvm-launch")?;

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

fn run_microvm_density(args: MicrovmDensityArgs) -> Result<()> {
    validate_density_hypervisor(&args.hypervisor)?;
    if args.count == 0 {
        bail!("--count must be >= 1");
    }
    if args.max_count == 0 {
        bail!("--max-count must be >= 1");
    }
    if args.count > args.max_count {
        bail!(
            "--count {} exceeds --max-count {}",
            args.count,
            args.max_count
        );
    }

    let report = match args.hypervisor.as_str() {
        "libkrun" => run_libkrun_density(args.count, args.max_count)?,
        "firecracker" => run_firecracker_density(args.count, args.max_count)?,
        "vz" => run_vz_density(args.count, args.max_count)?,
        _ => unreachable!("validated hypervisor"),
    };
    let out_path = write_report_with_latest(&report, args.out, "microvm-density")?;
    eprintln!(
        "[mvm] bench microvm-density: {} instances, per-instance={} bytes, report at {}",
        report.stats.instances,
        report.stats.per_instance_bytes,
        out_path.display()
    );

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    if let Some(baseline_path) = args.baseline.as_deref() {
        let baseline = read_density_report(baseline_path)?;
        match compare_density_to_baseline(&baseline, &report, args.max_regression_pct) {
            RegressionVerdict::Ok { delta_pct } => {
                eprintln!(
                    "[mvm] bench: density per-instance footprint within tolerance ({delta_pct:+.2}% vs baseline)"
                );
            }
            RegressionVerdict::Incomparable { reason } => {
                bail!("bench baseline is incomparable: {reason}");
            }
            RegressionVerdict::Regressed {
                delta_pct,
                limit_pct,
            } => {
                bail!(
                    "bench regression: density per-instance footprint up {delta_pct:+.2}% \
                     vs baseline (limit {limit_pct:.2}%)"
                );
            }
        }
    }

    Ok(())
}

fn validate_launch_hypervisor(hypervisor: &str) -> Result<()> {
    match hypervisor {
        "libkrun" => Ok(()),
        "firecracker" => {
            if cfg!(target_os = "linux") {
                Ok(())
            } else {
                bail!("bench microvm-launch --hypervisor firecracker requires Linux/KVM")
            }
        }
        "vz" => {
            if cfg!(target_os = "macos") {
                Ok(())
            } else {
                bail!("bench microvm-launch --hypervisor vz requires macOS with Vz")
            }
        }
        other => bail!(
            "bench microvm-launch v1 supports --hypervisor libkrun, macOS vz, and Linux \
             firecracker (got {other:?})"
        ),
    }
}

fn validate_density_hypervisor(hypervisor: &str) -> Result<()> {
    match hypervisor {
        "libkrun" => Ok(()),
        "firecracker" => {
            if cfg!(target_os = "linux") {
                Ok(())
            } else {
                bail!("bench microvm-density --hypervisor firecracker requires Linux/KVM")
            }
        }
        "vz" => {
            if cfg!(target_os = "macos") {
                Ok(())
            } else {
                bail!("bench microvm-density --hypervisor vz requires macOS with Vz")
            }
        }
        other => bail!(
            "bench microvm-density v1 supports --hypervisor libkrun, macOS vz, and Linux \
             firecracker (got {other:?})"
        ),
    }
}

#[cfg(target_os = "linux")]
fn new_firecracker_probe(args: &MicrovmLaunchArgs) -> Result<FirecrackerProbe> {
    FirecrackerProbe::new(args)
}

#[cfg(not(target_os = "linux"))]
fn new_firecracker_probe(_args: &MicrovmLaunchArgs) -> Result<LibkrunProbe> {
    bail!("bench microvm-launch --hypervisor firecracker requires Linux/KVM")
}

#[cfg(target_os = "macos")]
fn new_vz_probe(args: &MicrovmLaunchArgs) -> Result<VzProbe> {
    VzProbe::new(args)
}

#[cfg(not(target_os = "macos"))]
fn new_vz_probe(_args: &MicrovmLaunchArgs) -> Result<LibkrunProbe> {
    bail!("bench microvm-launch --hypervisor vz requires macOS with Vz")
}

#[cfg(target_os = "linux")]
fn run_firecracker_launch_distribution(
    args: &MicrovmLaunchArgs,
) -> Result<LaunchDistributionReport> {
    let host = FirecrackerProbe::new(args)?.host_descriptor();
    run_launch_distribution(host, args.concurrency, args.max_concurrency, |i| {
        FirecrackerProbe::new_with_prefix_and_warm_pool_size(
            format!("mvm-bench-fc-c{i}"),
            args.warm_pool_size,
        )
    })
}

#[cfg(not(target_os = "linux"))]
fn run_firecracker_launch_distribution(
    _args: &MicrovmLaunchArgs,
) -> Result<LaunchDistributionReport> {
    bail!("bench microvm-launch --hypervisor firecracker requires Linux/KVM")
}

#[cfg(target_os = "macos")]
fn run_vz_launch_distribution(args: &MicrovmLaunchArgs) -> Result<LaunchDistributionReport> {
    let host = VzProbe::new(args)?.host_descriptor();
    run_launch_distribution(host, args.concurrency, args.max_concurrency, |i| {
        VzProbe::new_with_prefix(format!("mvm-bench-vz-c{i}"))
    })
}

#[cfg(not(target_os = "macos"))]
fn run_vz_launch_distribution(_args: &MicrovmLaunchArgs) -> Result<LaunchDistributionReport> {
    bail!("bench microvm-launch --hypervisor vz requires macOS with Vz")
}

#[cfg(feature = "libkrun-live")]
fn run_libkrun_density(count: u32, max_count: u32) -> Result<DensityReport> {
    let host = LibkrunProbe::new_with_prefix("mvm-density")?.host_descriptor();
    let mut held = Vec::with_capacity(count as usize);
    for i in 0..count {
        let name = format!("mvm-density-{i}");
        held.push(
            crate::commands::ops::bench_probe::boot_hold_once(&name)
                .with_context(|| format!("density boot {name}"))?,
        );
    }
    let raw = held
        .iter()
        .map(|vm| {
            Ok(InstanceFootprint {
                vm_name: vm.vm_name().to_string(),
                pid: vm.pid(),
                bytes: read_process_footprint_bytes(vm.pid())?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    drop(held);
    Ok(build_density_report(host, count, max_count, raw))
}

#[cfg(not(feature = "libkrun-live"))]
fn run_libkrun_density(_count: u32, _max_count: u32) -> Result<DensityReport> {
    bail!(
        "bench microvm-density: this binary was built without the \
         `libkrun-live` feature, so it cannot boot and hold real guests. \
         Rebuild with `cargo build -p mvm-cli --features libkrun-live` \
         on a host where libkrun boots."
    )
}

#[cfg(target_os = "linux")]
fn run_firecracker_density(count: u32, max_count: u32) -> Result<DensityReport> {
    let host = FirecrackerProbe::new_with_prefix("mvm-density-fc")?.host_descriptor();
    let mut held = Vec::with_capacity(count as usize);
    for i in 0..count {
        let name = format!("mvm-density-fc-{i}");
        held.push(
            boot_firecracker_hold_once(&name, 0).with_context(|| format!("density boot {name}"))?,
        );
    }
    let raw = held
        .iter()
        .map(|vm| {
            Ok(InstanceFootprint {
                vm_name: vm.vm_name().to_string(),
                pid: vm.pid(),
                bytes: read_process_footprint_bytes(vm.pid())?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    drop(held);
    for sample in &raw {
        assert_firecracker_bench_cleanup(&sample.vm_name)?;
    }
    Ok(build_density_report(host, count, max_count, raw))
}

#[cfg(not(target_os = "linux"))]
fn run_firecracker_density(_count: u32, _max_count: u32) -> Result<DensityReport> {
    bail!("bench microvm-density --hypervisor firecracker requires Linux/KVM")
}

#[cfg(target_os = "macos")]
fn run_vz_density(count: u32, max_count: u32) -> Result<DensityReport> {
    let host = VzProbe::new_with_prefix("mvm-density-vz")?.host_descriptor();
    let mut held = Vec::with_capacity(count as usize);
    for i in 0..count {
        let name = format!("mvm-density-vz-{i}");
        held.push(boot_vz_hold_once(&name).with_context(|| format!("density boot {name}"))?);
    }
    let raw = held
        .iter()
        .map(|vm| {
            Ok(InstanceFootprint {
                vm_name: vm.vm_name().to_string(),
                pid: vm.pid(),
                bytes: read_process_footprint_bytes(vm.pid())?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    drop(held);
    for sample in &raw {
        assert_vz_bench_cleanup(&sample.vm_name)?;
    }
    Ok(build_density_report(host, count, max_count, raw))
}

#[cfg(not(target_os = "macos"))]
fn run_vz_density(_count: u32, _max_count: u32) -> Result<DensityReport> {
    bail!("bench microvm-density --hypervisor vz requires macOS with Vz")
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
            readiness_boundary: Some("guest-agent-ping".to_string()),
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

    fn launch_args() -> MicrovmLaunchArgs {
        MicrovmLaunchArgs {
            runs: 1,
            warmup: 0,
            concurrency: 1,
            max_concurrency: 64,
            hypervisor: "libkrun".to_string(),
            warm_pool_size: 0,
            out: None,
            json: false,
            baseline: None,
            max_regression_pct: 10.0,
        }
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
    fn launch_distribution_baseline_compares_concurrency_p95() {
        let base = build_launch_distribution_report(
            host("aarch64"),
            2,
            vec![
                IterationTiming {
                    start_to_pid_ms: 1.0,
                    pid_to_connect_ms: 0.0,
                    handshake_ms: 0.0,
                    total_ready_ms: 100.0,
                },
                IterationTiming {
                    start_to_pid_ms: 1.0,
                    pid_to_connect_ms: 0.0,
                    handshake_ms: 0.0,
                    total_ready_ms: 100.0,
                },
            ],
        );
        let worse = build_launch_distribution_report(
            host("aarch64"),
            2,
            vec![
                IterationTiming {
                    start_to_pid_ms: 1.0,
                    pid_to_connect_ms: 0.0,
                    handshake_ms: 0.0,
                    total_ready_ms: 130.0,
                },
                IterationTiming {
                    start_to_pid_ms: 1.0,
                    pid_to_connect_ms: 0.0,
                    handshake_ms: 0.0,
                    total_ready_ms: 130.0,
                },
            ],
        );
        assert!(matches!(
            compare_launch_distribution_to_baseline(&base, &worse, 10.0),
            RegressionVerdict::Regressed { .. }
        ));
    }

    #[test]
    fn density_baseline_compares_per_instance_bytes() {
        let baseline = build_density_report(
            host("aarch64"),
            2,
            2,
            vec![
                InstanceFootprint {
                    vm_name: "a".to_string(),
                    pid: 1,
                    bytes: 100,
                },
                InstanceFootprint {
                    vm_name: "b".to_string(),
                    pid: 2,
                    bytes: 100,
                },
            ],
        );
        let current = build_density_report(
            host("aarch64"),
            2,
            2,
            vec![
                InstanceFootprint {
                    vm_name: "a".to_string(),
                    pid: 1,
                    bytes: 130,
                },
                InstanceFootprint {
                    vm_name: "b".to_string(),
                    pid: 2,
                    bytes: 130,
                },
            ],
        );

        assert!(matches!(
            compare_density_to_baseline(&baseline, &current, 10.0),
            RegressionVerdict::Regressed { .. }
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
    fn density_summary_derives_per_instance_footprint() {
        let samples = vec![
            InstanceFootprint {
                vm_name: "bench-a".to_string(),
                pid: 101,
                bytes: 10 * 1024 * 1024,
            },
            InstanceFootprint {
                vm_name: "bench-b".to_string(),
                pid: 102,
                bytes: 14 * 1024 * 1024,
            },
            InstanceFootprint {
                vm_name: "bench-c".to_string(),
                pid: 103,
                bytes: 12 * 1024 * 1024,
            },
        ];

        let stats = summarize_density(&samples);

        assert_eq!(stats.instances, 3);
        assert_eq!(stats.total_bytes, 36 * 1024 * 1024);
        assert_eq!(stats.per_instance_bytes, 12 * 1024 * 1024);
        assert_eq!(stats.min_instance_bytes, 10 * 1024 * 1024);
        assert_eq!(stats.max_instance_bytes, 14 * 1024 * 1024);
    }

    #[test]
    fn density_report_roundtrips_and_handles_empty_samples() {
        let report = build_density_report(host("aarch64"), 0, 16, Vec::new());

        assert_eq!(report.schema_version, BENCH_SCHEMA_VERSION);
        assert_eq!(report.count, 0);
        assert_eq!(report.max_count, 16);
        assert_eq!(report.stats.instances, 0);
        assert_eq!(report.stats.total_bytes, 0);
        assert_eq!(report.stats.per_instance_bytes, 0);

        let json = serde_json::to_string(&report).unwrap();
        let back: DensityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn launch_distribution_report_summarises_concurrent_wave() {
        let raw = vec![
            IterationTiming {
                start_to_pid_ms: 10.0,
                pid_to_connect_ms: 20.0,
                handshake_ms: 1.0,
                total_ready_ms: 100.0,
            },
            IterationTiming {
                start_to_pid_ms: 20.0,
                pid_to_connect_ms: 30.0,
                handshake_ms: 1.0,
                total_ready_ms: 200.0,
            },
            IterationTiming {
                start_to_pid_ms: 30.0,
                pid_to_connect_ms: 40.0,
                handshake_ms: 1.0,
                total_ready_ms: 300.0,
            },
            IterationTiming {
                start_to_pid_ms: 40.0,
                pid_to_connect_ms: 50.0,
                handshake_ms: 1.0,
                total_ready_ms: 400.0,
            },
        ];

        let report = build_launch_distribution_report(host("aarch64"), 4, raw);

        assert_eq!(report.schema_version, BENCH_SCHEMA_VERSION);
        assert_eq!(report.concurrency, 4);
        approx(report.total_ready_ms.p50, 250.0);
        approx(report.total_ready_tail_ms.p50, 250.0);
        approx(report.total_ready_tail_ms.p95, 385.0);
        approx(report.total_ready_tail_ms.p99, 397.0);
        approx(report.start_to_pid_ms.p50, 25.0);
    }

    #[test]
    fn smaps_rollup_pss_parser_reads_kib_as_bytes() {
        let fixture = "\
Rss:                1720 kB
Pss:                 384 kB
Pss_Dirty:           128 kB
";
        assert_eq!(
            parse_linux_smaps_rollup_pss_bytes(fixture).unwrap(),
            384 * 1024
        );
    }

    #[test]
    fn smaps_rollup_pss_parser_rejects_missing_pss() {
        let err = parse_linux_smaps_rollup_pss_bytes("Rss: 10 kB\n").unwrap_err();
        assert!(err.to_string().contains("Pss"), "unexpected error: {err:#}");
    }

    #[test]
    fn run_launch_distribution_enforces_concurrency_cap() {
        let err = run_launch_distribution(host("aarch64"), 5, 4, |_i| {
            Ok(MockProbe {
                timing: IterationTiming {
                    start_to_pid_ms: 1.0,
                    pid_to_connect_ms: 1.0,
                    handshake_ms: 1.0,
                    total_ready_ms: 1.0,
                },
                calls: 0,
            })
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn run_launch_distribution_summarises_probe_wave() {
        let report = run_launch_distribution(host("aarch64"), 3, 4, |i| {
            Ok(MockProbe {
                timing: IterationTiming {
                    start_to_pid_ms: f64::from(i + 1),
                    pid_to_connect_ms: 1.0,
                    handshake_ms: 1.0,
                    total_ready_ms: f64::from((i + 1) * 100),
                },
                calls: 0,
            })
        })
        .unwrap();

        assert_eq!(report.concurrency, 3);
        assert_eq!(report.raw.len(), 3);
        approx(report.total_ready_tail_ms.p50, 200.0);
        approx(report.total_ready_tail_ms.p95, 290.0);
    }

    #[test]
    fn write_then_read_report_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("microvm-launch-test.json");
        let r = report_with_median("aarch64", 55.0);
        write_json_report(&r, &path).unwrap();
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
    fn microvm_launch_rejects_concurrency_above_cap_before_boot() {
        let mut args = launch_args();
        args.concurrency = 9;
        args.max_concurrency = 8;
        let err = run_microvm_launch(args).unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn microvm_density_rejects_count_above_cap_before_boot() {
        let err = run_microvm_density(MicrovmDensityArgs {
            count: 17,
            max_count: 16,
            hypervisor: "libkrun".to_string(),
            out: None,
            json: false,
            baseline: None,
            max_regression_pct: 10.0,
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "unexpected error: {err:#}"
        );
    }

    #[cfg(not(feature = "libkrun-live"))]
    #[test]
    fn microvm_density_without_live_feature_fails_honestly() {
        let err = run_microvm_density(MicrovmDensityArgs {
            count: 1,
            max_count: 1,
            hypervisor: "libkrun".to_string(),
            out: None,
            json: false,
            baseline: None,
            max_regression_pct: 10.0,
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("libkrun-live"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn launch_hypervisor_validation_accepts_firecracker_only_on_linux() {
        assert!(validate_launch_hypervisor("libkrun").is_ok());
        let fc = validate_launch_hypervisor("firecracker");
        if cfg!(target_os = "linux") {
            assert!(fc.is_ok());
        } else {
            assert!(fc.unwrap_err().to_string().contains("Linux/KVM"));
        }
        let vz = validate_launch_hypervisor("vz");
        if cfg!(target_os = "macos") {
            assert!(vz.is_ok());
        } else {
            assert!(vz.unwrap_err().to_string().contains("macOS with Vz"));
        }
    }

    #[test]
    fn density_hypervisor_validation_accepts_firecracker_only_on_linux() {
        assert!(validate_density_hypervisor("libkrun").is_ok());
        let fc = validate_density_hypervisor("firecracker");
        if cfg!(target_os = "linux") {
            assert!(fc.is_ok());
        } else {
            assert!(fc.unwrap_err().to_string().contains("Linux/KVM"));
        }
        let vz = validate_density_hypervisor("vz");
        if cfg!(target_os = "macos") {
            assert!(vz.is_ok());
        } else {
            assert!(vz.unwrap_err().to_string().contains("macOS with Vz"));
        }
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
        let args = launch_args();
        let mut probe = LibkrunProbe::new(&args).unwrap();
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
        let args = launch_args();
        let probe = LibkrunProbe::new(&args).unwrap();
        let h = probe.host_descriptor();
        assert!(
            h.kernel_sha256.is_some(),
            "kernel sha must be set so a kernel swap invalidates the baseline"
        );
    }
}
