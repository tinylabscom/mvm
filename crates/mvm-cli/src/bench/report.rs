//! Report schema + persistence.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::stats::{BENCH_SCHEMA_VERSION, IterationTiming, PhaseStats, percentile, summarize};

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
    /// Guest-agent process RSS queried after the guest reached readiness.
    /// This is a guest-process witness, not the whole VM working set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_agent_rss_bytes: Option<u64>,
}

/// Aggregate guest-agent RSS across the samples that reported it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestRssStats {
    pub instances: u32,
    pub total_bytes: u64,
    pub per_instance_bytes: u64,
    pub min_instance_bytes: u64,
    pub max_instance_bytes: u64,
}

/// Aggregate density result for a held-live instance set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DensityStats {
    pub instances: u32,
    pub total_bytes: u64,
    pub per_instance_bytes: u64,
    pub min_instance_bytes: u64,
    pub max_instance_bytes: u64,
    /// None when the live backend did not return guest-agent RSS.
    #[serde(default)]
    pub guest_agent_rss: Option<GuestRssStats>,
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

pub(super) fn build_report(
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
    let instances = u32::try_from(samples.len()).expect("density sample count fits in u32");
    let total_bytes = samples.iter().map(|sample| sample.bytes).sum::<u64>();
    let per_instance_bytes = if instances == 0 {
        0
    } else {
        total_bytes / u64::from(instances)
    };
    let guest_rss = samples
        .iter()
        .filter_map(|sample| sample.guest_agent_rss_bytes)
        .collect::<Vec<_>>();
    let guest_agent_rss = if guest_rss.is_empty() {
        None
    } else {
        let guest_instances =
            u32::try_from(guest_rss.len()).expect("guest RSS sample count fits in u32");
        let guest_total = guest_rss.iter().sum::<u64>();
        Some(GuestRssStats {
            instances: guest_instances,
            total_bytes: guest_total,
            per_instance_bytes: guest_total / u64::from(guest_instances),
            min_instance_bytes: guest_rss.iter().copied().min().unwrap_or(0),
            max_instance_bytes: guest_rss.iter().copied().max().unwrap_or(0),
        })
    };
    DensityStats {
        instances,
        total_bytes,
        per_instance_bytes,
        min_instance_bytes: samples.iter().map(|sample| sample.bytes).min().unwrap_or(0),
        max_instance_bytes: samples.iter().map(|sample| sample.bytes).max().unwrap_or(0),
        guest_agent_rss,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-9, "expected {b}, got {a}");
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
                guest_agent_rss_bytes: None,
            },
            InstanceFootprint {
                vm_name: "bench-b".to_string(),
                pid: 102,
                bytes: 14 * 1024 * 1024,
                guest_agent_rss_bytes: None,
            },
            InstanceFootprint {
                vm_name: "bench-c".to_string(),
                pid: 103,
                bytes: 12 * 1024 * 1024,
                guest_agent_rss_bytes: None,
            },
        ];

        let stats = summarize_density(&samples);

        assert_eq!(stats.instances, 3);
        assert_eq!(stats.total_bytes, 36 * 1024 * 1024);
        assert_eq!(stats.per_instance_bytes, 12 * 1024 * 1024);
        assert_eq!(stats.min_instance_bytes, 10 * 1024 * 1024);
        assert_eq!(stats.max_instance_bytes, 14 * 1024 * 1024);
        assert_eq!(stats.guest_agent_rss, None);
    }

    #[test]
    fn density_summary_aggregates_available_guest_agent_rss() {
        let samples = vec![
            InstanceFootprint {
                vm_name: "bench-a".to_string(),
                pid: 101,
                bytes: 100,
                guest_agent_rss_bytes: Some(2_000),
            },
            InstanceFootprint {
                vm_name: "bench-b".to_string(),
                pid: 102,
                bytes: 100,
                guest_agent_rss_bytes: None,
            },
            InstanceFootprint {
                vm_name: "bench-c".to_string(),
                pid: 103,
                bytes: 100,
                guest_agent_rss_bytes: Some(4_000),
            },
        ];

        assert_eq!(
            summarize_density(&samples).guest_agent_rss,
            Some(GuestRssStats {
                instances: 2,
                total_bytes: 6_000,
                per_instance_bytes: 3_000,
                min_instance_bytes: 2_000,
                max_instance_bytes: 4_000,
            })
        );
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
    fn write_then_read_report_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("microvm-launch-test.json");
        let r = report_with_median("aarch64", 55.0);
        write_json_report(&r, &path).unwrap();
        let back = read_report(&path).unwrap();
        approx(back.total_ready_ms.p50, 55.0);
    }
}
