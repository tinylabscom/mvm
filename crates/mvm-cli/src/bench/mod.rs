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
//! Backend scope: v1 measures libkrun, HVF, and Firecracker.

pub mod harness;
pub mod probe;
pub mod probes;
pub mod regression;
pub mod report;
pub mod stats;

// `BootMarks` and the boot-timing-sidecar writer are the only bench-internal
// items another file (`probe.rs`, under `libkrun-live`) reaches through
// this module's path — everything else submodules need from each other they
// reach directly via `super::<submodule>`.
#[cfg(feature = "libkrun-live")]
pub(crate) use probes::write_boot_timing_sidecar;
#[cfg(feature = "libkrun-live")]
pub use stats::BootMarks;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};
use serde::Serialize;

use mvm_core::user_config::MvmConfig;

use harness::{LaunchProbe, read_process_footprint_bytes, run_benchmark, run_launch_distribution};
use probes::LibkrunProbe;
#[cfg(target_os = "linux")]
use probes::{FirecrackerProbe, assert_firecracker_bench_cleanup, boot_firecracker_hold_once};
#[cfg(target_os = "macos")]
use probes::{HvfProbe, assert_hvf_bench_cleanup, boot_hvf_hold_once};
use regression::{
    RegressionVerdict, compare_density_to_baseline, compare_launch_distribution_to_baseline,
    compare_to_baseline,
};
use report::{
    DensityReport, InstanceFootprint, LaunchDistributionReport, build_density_report,
    read_density_report, read_launch_distribution_report, read_report, write_json_report,
};

#[derive(ClapArgs, Debug, Clone)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub action: BenchAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum BenchAction {
    /// Measure cold runtime-microvm launch latency end-to-end.
    MicrovmLaunch(MicrovmLaunchArgs),
    /// Measure held-live runtime-microvm supervisor/VMM footprint.
    MicrovmDensity(MicrovmDensityArgs),
}

#[derive(ClapArgs, Debug, Clone)]
pub(crate) struct MicrovmLaunchArgs {
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
    /// Hypervisor backend to measure. v1 supports `libkrun`, macOS `hvf`, and
    /// Linux `firecracker`.
    #[arg(long, default_value = "libkrun")]
    pub hypervisor: String,
    /// Warm standby pool target to request for each measured launch.
    ///
    /// Currently supported for Linux Firecracker launch probes; use
    /// `0` for a cold baseline and `1` for a warm-claim delta proof.
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
pub(crate) struct MicrovmDensityArgs {
    /// Number of admitted instances to boot and hold live while sampling footprint.
    #[arg(long, default_value_t = 4)]
    pub count: u32,
    /// Safety cap for `--count` so a typo cannot exhaust host memory.
    #[arg(long, default_value_t = 16)]
    pub max_count: u32,
    /// Hypervisor backend to measure. v1 supports `libkrun`, macOS `hvf`, and
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
// CLI entry.
// ──────────────────────────────────────────────────────────────────

pub(crate) fn run(args: Args, _cfg: &MvmConfig) -> Result<()> {
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

pub fn write_report_with_latest<T: Serialize>(
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
            "hvf" => run_hvf_launch_distribution(&args)?,
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
        "hvf" => {
            let mut probe = new_hvf_probe(&args)?;
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
        "hvf" => run_hvf_density(args.count, args.max_count)?,
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
        "hvf" => {
            if cfg!(target_os = "macos") {
                Ok(())
            } else {
                bail!("bench microvm-launch --hypervisor hvf requires macOS with HVF")
            }
        }
        other => bail!(
            "bench microvm-launch v1 supports --hypervisor libkrun, macOS hvf, and Linux \
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
        "hvf" => {
            if cfg!(target_os = "macos") {
                Ok(())
            } else {
                bail!("bench microvm-density --hypervisor hvf requires macOS with HVF")
            }
        }
        other => bail!(
            "bench microvm-density v1 supports --hypervisor libkrun, macOS hvf, and Linux \
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
fn new_hvf_probe(args: &MicrovmLaunchArgs) -> Result<HvfProbe> {
    HvfProbe::new(args)
}

#[cfg(not(target_os = "macos"))]
fn new_hvf_probe(_args: &MicrovmLaunchArgs) -> Result<LibkrunProbe> {
    bail!("bench microvm-launch --hypervisor hvf requires macOS with HVF")
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
fn run_hvf_launch_distribution(args: &MicrovmLaunchArgs) -> Result<LaunchDistributionReport> {
    let host = HvfProbe::new(args)?.host_descriptor();
    run_launch_distribution(host, args.concurrency, args.max_concurrency, |i| {
        HvfProbe::new_with_prefix(format!("mvm-bench-hvf-c{i}"))
    })
}

#[cfg(not(target_os = "macos"))]
fn run_hvf_launch_distribution(_args: &MicrovmLaunchArgs) -> Result<LaunchDistributionReport> {
    bail!("bench microvm-launch --hypervisor hvf requires macOS with HVF")
}

#[cfg(feature = "libkrun-live")]
fn run_libkrun_density(count: u32, max_count: u32) -> Result<DensityReport> {
    let host = LibkrunProbe::new_with_prefix("mvm-density")?.host_descriptor();
    let mut held = Vec::with_capacity(count as usize);
    for i in 0..count {
        let name = format!("mvm-density-{i}");
        held.push(
            crate::bench::probe::boot_hold_once(&name)
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
fn run_hvf_density(count: u32, max_count: u32) -> Result<DensityReport> {
    let host = HvfProbe::new_with_prefix("mvm-density-hvf")?.host_descriptor();
    let mut held = Vec::with_capacity(count as usize);
    for i in 0..count {
        let name = format!("mvm-density-hvf-{i}");
        held.push(boot_hvf_hold_once(&name).with_context(|| format!("density boot {name}"))?);
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
        assert_hvf_bench_cleanup(&sample.vm_name)?;
    }
    Ok(build_density_report(host, count, max_count, raw))
}

#[cfg(not(target_os = "macos"))]
fn run_hvf_density(_count: u32, _max_count: u32) -> Result<DensityReport> {
    bail!("bench microvm-density --hypervisor hvf requires macOS with HVF")
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let hvf = validate_launch_hypervisor("hvf");
        if cfg!(target_os = "macos") {
            assert!(hvf.is_ok());
        } else {
            assert!(hvf.unwrap_err().to_string().contains("macOS with HVF"));
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
        let hvf = validate_density_hypervisor("hvf");
        if cfg!(target_os = "macos") {
            assert!(hvf.is_ok());
        } else {
            assert!(hvf.unwrap_err().to_string().contains("macOS with HVF"));
        }
    }
}
