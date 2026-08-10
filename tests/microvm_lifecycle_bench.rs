//! Opt-in live benchmark for repeated microVM lifecycle operations.
//!
//! The default run performs 1,000 HVF start/stop operations serially, keeping
//! only one VM resident at a time. Increase `MVM_LIFECYCLE_BENCH_CONCURRENCY`
//! to measure bounded batches of concurrently resident VMs.
//!
//! ```text
//! MVM_LIFECYCLE_BENCH=1 \
//! MVM_LIFECYCLE_BENCH_KERNEL=/path/to/vmlinux \
//! MVM_LIFECYCLE_BENCH_ROOTFS=/path/to/rootfs.ext4 \
//! cargo test --test microvm_lifecycle_bench -- --exact --nocapture
//! ```
//!
//! Use `MVM_LIFECYCLE_BENCH_BACKENDS=all` or a comma-separated list of
//! `firecracker`, `hvf`, `libkrun`, `qemu`, and `apple-container` to compare
//! backends. The benchmark measures the backend lifecycle calls themselves;
//! guest-agent readiness is a separate measurement boundary.

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use mvm_core::vm_backend::{VmId, VmStartConfig};
use mvm_runtime::backend::AnyBackend;

const ENABLE_VAR: &str = "MVM_LIFECYCLE_BENCH";
const BACKENDS_VAR: &str = "MVM_LIFECYCLE_BENCH_BACKENDS";
const KERNEL_VAR: &str = "MVM_LIFECYCLE_BENCH_KERNEL";
const ROOTFS_VAR: &str = "MVM_LIFECYCLE_BENCH_ROOTFS";
const COUNT_VAR: &str = "MVM_LIFECYCLE_BENCH_COUNT";
const CONCURRENCY_VAR: &str = "MVM_LIFECYCLE_BENCH_CONCURRENCY";
const CPUS_VAR: &str = "MVM_LIFECYCLE_BENCH_CPUS";
const MEMORY_MIB_VAR: &str = "MVM_LIFECYCLE_BENCH_MEMORY_MIB";

const DEFAULT_BACKENDS: &str = "hvf";
const DEFAULT_COUNT: usize = 1_000;
const DEFAULT_CONCURRENCY: usize = 1;
const DEFAULT_CPUS: u32 = 1;
const DEFAULT_MEMORY_MIB: u32 = 256;
const ALL_MICROVM_BACKENDS: &[&str] = &["firecracker", "hvf", "libkrun", "qemu", "apple-container"];

#[test]
fn starts_and_stops_1000_microvms() -> Result<()> {
    if std::env::var(ENABLE_VAR).as_deref() != Ok("1") {
        eprintln!("[microvm_lifecycle_bench] skipped; set {ENABLE_VAR}=1 to launch real microVMs");
        return Ok(());
    }

    let spec = BenchSpec::from_env()?;
    for backend in &spec.backends {
        run_backend(&spec, backend)?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct BenchSpec {
    backends: Vec<String>,
    kernel: PathBuf,
    rootfs: PathBuf,
    count: usize,
    concurrency: usize,
    cpus: u32,
    memory_mib: u32,
}

impl BenchSpec {
    fn from_env() -> Result<Self> {
        let backends = parse_backend_selectors(
            &std::env::var(BACKENDS_VAR).unwrap_or_else(|_| DEFAULT_BACKENDS.to_string()),
        )?;
        let count = env_usize(COUNT_VAR, DEFAULT_COUNT)?;
        let concurrency = env_usize(CONCURRENCY_VAR, DEFAULT_CONCURRENCY)?;
        if count == 0 {
            bail!("{COUNT_VAR} must be positive");
        }
        if concurrency == 0 {
            bail!("{CONCURRENCY_VAR} must be positive");
        }
        if concurrency > count {
            bail!("{CONCURRENCY_VAR}={concurrency} cannot exceed {COUNT_VAR}={count}");
        }

        Ok(Self {
            backends,
            kernel: required_file(KERNEL_VAR)?,
            rootfs: required_file(ROOTFS_VAR)?,
            count,
            concurrency,
            cpus: env_u32(CPUS_VAR, DEFAULT_CPUS)?,
            memory_mib: env_u32(MEMORY_MIB_VAR, DEFAULT_MEMORY_MIB)?,
        })
    }

    fn config(&self, backend: &str, index: usize) -> VmStartConfig {
        VmStartConfig {
            name: unique_vm_name(backend, index),
            rootfs_path: self.rootfs.to_string_lossy().into_owned(),
            kernel_path: Some(self.kernel.to_string_lossy().into_owned()),
            cpus: self.cpus,
            memory_mib: self.memory_mib,
            revision_hash: "microvm-lifecycle-bench".to_string(),
            flake_ref: "prebuilt-runtime-image".to_string(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MeasurementSummary {
    p50: Duration,
    p95: Duration,
    p99: Duration,
    max: Duration,
}

#[derive(Debug)]
struct StartedVm {
    id: VmId,
    elapsed: Duration,
}

fn run_backend(spec: &BenchSpec, selector: &str) -> Result<()> {
    let backend = Arc::new(AnyBackend::from_hypervisor(selector));
    let mut start_samples = Vec::with_capacity(spec.count);
    let mut stop_samples = Vec::with_capacity(spec.count);
    let mut start_wall = Duration::ZERO;
    let mut stop_wall = Duration::ZERO;

    for batch_start in (0..spec.count).step_by(spec.concurrency) {
        let batch_end = (batch_start + spec.concurrency).min(spec.count);
        let configs = (batch_start..batch_end)
            .map(|index| spec.config(selector, index))
            .collect::<Vec<_>>();
        let started_at = Instant::now();
        let started = start_batch(Arc::clone(&backend), configs)?;
        start_wall += started_at.elapsed();
        start_samples.extend(started.iter().map(|vm| vm.elapsed));

        let stop_started_at = Instant::now();
        let stopped = stop_batch(Arc::clone(&backend), started)?;
        stop_wall += stop_started_at.elapsed();
        stop_samples.extend(stopped);
    }

    print_report(
        selector,
        spec,
        &start_samples,
        &stop_samples,
        start_wall,
        stop_wall,
    );
    Ok(())
}

fn start_batch(backend: Arc<AnyBackend>, configs: Vec<VmStartConfig>) -> Result<Vec<StartedVm>> {
    let results = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(configs.len());
        for config in configs {
            let backend = Arc::clone(&backend);
            handles.push(scope.spawn(move || {
                let name = config.name.clone();
                let started_at = Instant::now();
                let result = backend
                    .start(&config)
                    .with_context(|| format!("starting benchmark VM {name}"));
                (name, started_at.elapsed(), result)
            }));
        }

        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("lifecycle benchmark start worker panicked"))
            })
            .collect::<Result<Vec<_>>>()
    })?;

    let mut started = Vec::with_capacity(results.len());
    let mut failure = None;
    for (name, elapsed, result) in results {
        match result {
            Ok(id) => started.push(StartedVm { id, elapsed }),
            Err(error) => {
                failure.get_or_insert_with(|| anyhow::anyhow!("{name}: {error:#}"));
            }
        }
    }

    if let Some(error) = failure {
        for vm in &started {
            if let Err(cleanup_error) = backend.stop(&vm.id) {
                eprintln!(
                    "[microvm_lifecycle_bench] cleanup failed for {} after start failure: {cleanup_error:#}",
                    vm.id.0
                );
            }
        }
        return Err(error);
    }

    Ok(started)
}

fn stop_batch(backend: Arc<AnyBackend>, started: Vec<StartedVm>) -> Result<Vec<Duration>> {
    let results = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(started.len());
        for vm in started {
            let backend = Arc::clone(&backend);
            handles.push(scope.spawn(move || {
                let started_at = Instant::now();
                let result = backend.stop(&vm.id);
                (vm.id, started_at.elapsed(), result)
            }));
        }

        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("lifecycle benchmark stop worker panicked"))
            })
            .collect::<Result<Vec<_>>>()
    })?;

    let mut samples = Vec::with_capacity(results.len());
    let mut failures = Vec::new();
    for (id, elapsed, result) in results {
        match result {
            Ok(()) => samples.push(elapsed),
            Err(error) => failures.push((id, error)),
        }
    }

    if failures.is_empty() {
        return Ok(samples);
    }

    for (id, error) in &failures {
        eprintln!(
            "[microvm_lifecycle_bench] stop failed for {}; retrying once: {error:#}",
            id.0
        );
        if let Err(retry_error) = backend.stop(id) {
            eprintln!(
                "[microvm_lifecycle_bench] stop retry failed for {}: {retry_error:#}",
                id.0
            );
        }
    }
    let (id, error) = failures
        .into_iter()
        .next()
        .expect("stop failures are non-empty");
    Err(error).with_context(|| format!("stopping benchmark VM {}", id.0))
}

fn print_report(
    backend: &str,
    spec: &BenchSpec,
    starts: &[Duration],
    stops: &[Duration],
    start_wall: Duration,
    stop_wall: Duration,
) {
    let start = summarize(starts);
    let stop = summarize(stops);
    eprintln!(
        "[microvm_lifecycle_bench] backend={backend} count={} concurrency={} memory_mib={} cpus={}",
        spec.count, spec.concurrency, spec.memory_mib, spec.cpus
    );
    print_phase("start", start, start_wall, starts.len());
    print_phase("stop", stop, stop_wall, stops.len());
    eprintln!(
        "[microvm_lifecycle_bench] lifecycle wall={}ms throughput={:.2} VMs/s",
        millis(start_wall + stop_wall),
        starts.len() as f64 / (start_wall + stop_wall).as_secs_f64()
    );
}

fn print_phase(label: &str, summary: MeasurementSummary, wall: Duration, count: usize) {
    eprintln!(
        "[microvm_lifecycle_bench] {label} n={count} p50={:.2}ms p95={:.2}ms p99={:.2}ms max={:.2}ms wall={:.2}ms throughput={:.2} VMs/s",
        millis(summary.p50),
        millis(summary.p95),
        millis(summary.p99),
        millis(summary.max),
        millis(wall),
        count as f64 / wall.as_secs_f64()
    );
}

fn summarize(samples: &[Duration]) -> MeasurementSummary {
    assert!(!samples.is_empty(), "benchmark must produce samples");
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    MeasurementSummary {
        p50: percentile(&sorted, 50),
        p95: percentile(&sorted, 95),
        p99: percentile(&sorted, 99),
        max: *sorted.last().expect("non-empty samples"),
    }
}

fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    let rank = (sorted.len() * percent).div_ceil(100).saturating_sub(1);
    sorted[rank.min(sorted.len() - 1)]
}

fn parse_backend_selectors(raw: &str) -> Result<Vec<String>> {
    let mut selectors = Vec::new();
    for selector in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if selector == "all" {
            for backend in ALL_MICROVM_BACKENDS {
                if !selectors.iter().any(|known| known == backend) {
                    selectors.push((*backend).to_string());
                }
            }
            continue;
        }
        if !ALL_MICROVM_BACKENDS.contains(&selector) {
            bail!(
                "unknown {BACKENDS_VAR} backend {selector:?}; expected all or one of {}",
                ALL_MICROVM_BACKENDS.join(", ")
            );
        }
        if !selectors.iter().any(|known| known == selector) {
            selectors.push(selector.to_string());
        }
    }
    if selectors.is_empty() {
        bail!("{BACKENDS_VAR} must contain at least one backend");
    }
    Ok(selectors)
}

fn required_file(var: &str) -> Result<PathBuf> {
    let path = std::env::var_os(var)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("{var} is required for the live benchmark"))?;
    if !path.is_file() {
        bail!("{var}={} is not a file", path.display());
    }
    Ok(path)
}

fn env_usize(var: &str, default: usize) -> Result<usize> {
    match std::env::var(var) {
        Ok(raw) => raw
            .parse::<usize>()
            .with_context(|| format!("parsing {var}={raw:?} as a positive integer")),
        Err(_) => Ok(default),
    }
}

fn env_u32(var: &str, default: u32) -> Result<u32> {
    match std::env::var(var) {
        Ok(raw) => raw
            .parse::<u32>()
            .with_context(|| format!("parsing {var}={raw:?} as a positive integer")),
        Err(_) => Ok(default),
    }
}

fn unique_vm_name(backend: &str, index: usize) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let backend = backend.replace('-', "_");
    format!(
        "mvm-lifecycle-bench-{backend}-{}-{nanos}-{index}",
        std::process::id()
    )
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

#[test]
fn backend_selector_defaults_to_hvf_and_expands_all() {
    assert_eq!(
        parse_backend_selectors(DEFAULT_BACKENDS).expect("default selector"),
        vec!["hvf"]
    );
    assert_eq!(
        parse_backend_selectors("all").expect("all selector"),
        ALL_MICROVM_BACKENDS
            .iter()
            .map(|selector| (*selector).to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn backend_selector_rejects_unknown_and_empty_values() {
    assert!(parse_backend_selectors("").is_err());
    assert!(parse_backend_selectors("hvf,unknown").is_err());
    assert_eq!(
        parse_backend_selectors("hvf,all").expect("duplicate selectors are removed"),
        ["hvf", "firecracker", "libkrun", "qemu", "apple-container"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
    );
}

#[test]
fn percentile_summary_reports_tail_values() {
    let summary = summarize(&[
        Duration::from_millis(1),
        Duration::from_millis(2),
        Duration::from_millis(3),
        Duration::from_millis(4),
    ]);
    assert_eq!(summary.p50, Duration::from_millis(2));
    assert_eq!(summary.p95, Duration::from_millis(4));
    assert_eq!(summary.p99, Duration::from_millis(4));
    assert_eq!(summary.max, Duration::from_millis(4));
}
