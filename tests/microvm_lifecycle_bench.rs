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
//! MVM_LIFECYCLE_BENCH_INITRD=/path/to/rootfs.initrd \
//! MVM_LIFECYCLE_BENCH_ROOTFS_VERITY=/path/to/rootfs.verity \
//! MVM_LIFECYCLE_BENCH_ROOTFS_ROOTHASH=<64-lowercase-hex> \
//! MVM_LIFECYCLE_BENCH_RUNTIME_OVERLAY=/path/to/overlay.ext4 \
//! MVM_LIFECYCLE_BENCH_RUNTIME_OVERLAY_VERITY=/path/to/overlay.verity \
//! MVM_LIFECYCLE_BENCH_RUNTIME_OVERLAY_ROOTHASH=<64-lowercase-hex> \
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
use mvm_runtime::workload_runner::StopTiming;
use mvm_vmm::host::hvf_supervisor::HvfShutdownTimingRecord;

const ENABLE_VAR: &str = "MVM_LIFECYCLE_BENCH";
const BACKENDS_VAR: &str = "MVM_LIFECYCLE_BENCH_BACKENDS";
const KERNEL_VAR: &str = "MVM_LIFECYCLE_BENCH_KERNEL";
const ROOTFS_VAR: &str = "MVM_LIFECYCLE_BENCH_ROOTFS";
const INITRD_VAR: &str = "MVM_LIFECYCLE_BENCH_INITRD";
const ROOTFS_VERITY_VAR: &str = "MVM_LIFECYCLE_BENCH_ROOTFS_VERITY";
const ROOTFS_ROOTHASH_VAR: &str = "MVM_LIFECYCLE_BENCH_ROOTFS_ROOTHASH";
const RUNTIME_OVERLAY_VAR: &str = "MVM_LIFECYCLE_BENCH_RUNTIME_OVERLAY";
const RUNTIME_OVERLAY_VERITY_VAR: &str = "MVM_LIFECYCLE_BENCH_RUNTIME_OVERLAY_VERITY";
const RUNTIME_OVERLAY_ROOTHASH_VAR: &str = "MVM_LIFECYCLE_BENCH_RUNTIME_OVERLAY_ROOTHASH";
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
    mvm_hostd::audit::host_keypair::load_or_init()
        .context("initializing the benchmark host signer")?;
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
    rootfs_integrity: Option<RootfsIntegritySpec>,
    runtime_overlay: Option<RuntimeOverlaySpec>,
    count: usize,
    concurrency: usize,
    cpus: u32,
    memory_mib: u32,
}

#[derive(Debug, Clone)]
struct RootfsIntegritySpec {
    initrd: PathBuf,
    verity: PathBuf,
    roothash: String,
}

#[derive(Debug, Clone)]
struct RuntimeOverlaySpec {
    image: PathBuf,
    verity: PathBuf,
    roothash: String,
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
            rootfs_integrity: rootfs_integrity_from_env()?,
            runtime_overlay: runtime_overlay_from_env()?,
            count,
            concurrency,
            cpus: env_u32(CPUS_VAR, DEFAULT_CPUS)?,
            memory_mib: env_u32(MEMORY_MIB_VAR, DEFAULT_MEMORY_MIB)?,
        })
    }

    fn config(&self, backend: &str, index: usize) -> VmStartConfig {
        let mut config = VmStartConfig {
            name: unique_vm_name(backend, index),
            rootfs_path: self.rootfs.to_string_lossy().into_owned(),
            kernel_path: Some(self.kernel.to_string_lossy().into_owned()),
            cpus: self.cpus,
            memory_mib: self.memory_mib,
            revision_hash: "microvm-lifecycle-bench".to_string(),
            flake_ref: "prebuilt-runtime-image".to_string(),
            ..Default::default()
        };
        if let Some(rootfs_integrity) = &self.rootfs_integrity {
            apply_rootfs_integrity(&mut config, rootfs_integrity);
        }
        if let Some(runtime_overlay) = &self.runtime_overlay {
            apply_runtime_overlay(&mut config, runtime_overlay);
        }
        config
    }
}

fn apply_rootfs_integrity(config: &mut VmStartConfig, rootfs_integrity: &RootfsIntegritySpec) {
    config.initrd_path = Some(rootfs_integrity.initrd.to_string_lossy().into_owned());
    config.verity_path = Some(rootfs_integrity.verity.to_string_lossy().into_owned());
    config.roothash = Some(rootfs_integrity.roothash.clone());
}

fn apply_runtime_overlay(config: &mut VmStartConfig, runtime_overlay: &RuntimeOverlaySpec) {
    config.runtime_overlay_path = Some(runtime_overlay.image.to_string_lossy().into_owned());
    config.runtime_overlay_verity_path =
        Some(runtime_overlay.verity.to_string_lossy().into_owned());
    config.runtime_overlay_roothash = Some(runtime_overlay.roothash.clone());
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

#[derive(Debug)]
struct StoppedVm {
    elapsed: Duration,
    timing: Option<StopTiming>,
    hvf_shutdown_timing: Option<HvfShutdownTimingRecord>,
}

fn run_backend(spec: &BenchSpec, selector: &str) -> Result<()> {
    let backend = Arc::new(AnyBackend::from_hypervisor(selector));
    let mut start_samples = Vec::with_capacity(spec.count);
    let mut stop_samples = Vec::with_capacity(spec.count);
    let mut stop_timings = Vec::with_capacity(spec.count);
    let mut hvf_shutdown_timings = Vec::with_capacity(spec.count);
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
        stop_samples.extend(stopped.iter().map(|vm| vm.elapsed));
        stop_timings.extend(stopped.iter().filter_map(|vm| vm.timing));
        hvf_shutdown_timings.extend(stopped.iter().filter_map(|vm| vm.hvf_shutdown_timing));
    }

    print_report(
        LifecycleReport::builder()
            .backend(selector)
            .spec(spec)
            .starts(&start_samples)
            .stops(&stop_samples)
            .stop_timings(&stop_timings)
            .hvf_shutdown_timings(&hvf_shutdown_timings)
            .start_wall(start_wall)
            .stop_wall(stop_wall)
            .build()?,
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

fn stop_batch(backend: Arc<AnyBackend>, started: Vec<StartedVm>) -> Result<Vec<StoppedVm>> {
    let results = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(started.len());
        for vm in started {
            let backend = Arc::clone(&backend);
            handles.push(scope.spawn(move || {
                let started_at = Instant::now();
                let result = backend.stop_with_timing(&vm.id);
                let hvf_shutdown_timing = read_hvf_shutdown_timing(&vm.id);
                (vm.id, started_at.elapsed(), result, hvf_shutdown_timing)
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
    for (id, elapsed, result, hvf_shutdown_timing) in results {
        match result {
            Ok(timing) => samples.push(StoppedVm {
                elapsed,
                timing,
                hvf_shutdown_timing,
            }),
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

fn read_hvf_shutdown_timing(id: &VmId) -> Option<HvfShutdownTimingRecord> {
    let state_dir = mvm_core::config::vm_state_dir(&id.0);
    let path = mvm_vmm::host::hvf_supervisor::shutdown_timing_path(&state_dir);
    let json = std::fs::read(path).ok()?;
    let record = serde_json::from_slice::<HvfShutdownTimingRecord>(&json).ok()?;
    (record.schema_version == 1).then_some(record)
}

struct LifecycleReport<'a> {
    backend: &'a str,
    spec: &'a BenchSpec,
    starts: &'a [Duration],
    stops: &'a [Duration],
    stop_timings: &'a [StopTiming],
    hvf_shutdown_timings: &'a [HvfShutdownTimingRecord],
    start_wall: Duration,
    stop_wall: Duration,
}

impl<'a> LifecycleReport<'a> {
    fn builder() -> LifecycleReportBuilder<'a> {
        LifecycleReportBuilder::default()
    }
}

#[derive(Default)]
struct LifecycleReportBuilder<'a> {
    backend: Option<&'a str>,
    spec: Option<&'a BenchSpec>,
    starts: Option<&'a [Duration]>,
    stops: Option<&'a [Duration]>,
    stop_timings: Option<&'a [StopTiming]>,
    hvf_shutdown_timings: Option<&'a [HvfShutdownTimingRecord]>,
    start_wall: Option<Duration>,
    stop_wall: Option<Duration>,
}

impl<'a> LifecycleReportBuilder<'a> {
    fn backend(mut self, backend: &'a str) -> Self {
        self.backend = Some(backend);
        self
    }

    fn spec(mut self, spec: &'a BenchSpec) -> Self {
        self.spec = Some(spec);
        self
    }

    fn starts(mut self, starts: &'a [Duration]) -> Self {
        self.starts = Some(starts);
        self
    }

    fn stops(mut self, stops: &'a [Duration]) -> Self {
        self.stops = Some(stops);
        self
    }

    fn stop_timings(mut self, stop_timings: &'a [StopTiming]) -> Self {
        self.stop_timings = Some(stop_timings);
        self
    }

    fn hvf_shutdown_timings(mut self, hvf_shutdown_timings: &'a [HvfShutdownTimingRecord]) -> Self {
        self.hvf_shutdown_timings = Some(hvf_shutdown_timings);
        self
    }

    fn start_wall(mut self, start_wall: Duration) -> Self {
        self.start_wall = Some(start_wall);
        self
    }

    fn stop_wall(mut self, stop_wall: Duration) -> Self {
        self.stop_wall = Some(stop_wall);
        self
    }

    fn build(self) -> Result<LifecycleReport<'a>> {
        Ok(LifecycleReport {
            backend: self
                .backend
                .context("lifecycle report backend is required")?,
            spec: self.spec.context("lifecycle report spec is required")?,
            starts: self
                .starts
                .context("lifecycle report starts are required")?,
            stops: self.stops.context("lifecycle report stops are required")?,
            stop_timings: self
                .stop_timings
                .context("lifecycle report stop timings are required")?,
            hvf_shutdown_timings: self
                .hvf_shutdown_timings
                .context("lifecycle report HVF shutdown timings are required")?,
            start_wall: self
                .start_wall
                .context("lifecycle report start wall time is required")?,
            stop_wall: self
                .stop_wall
                .context("lifecycle report stop wall time is required")?,
        })
    }
}

fn print_report(report: LifecycleReport<'_>) {
    let LifecycleReport {
        backend,
        spec,
        starts,
        stops,
        stop_timings,
        hvf_shutdown_timings,
        start_wall,
        stop_wall,
    } = report;
    let start = summarize(starts);
    let stop = summarize(stops);
    eprintln!(
        "[microvm_lifecycle_bench] backend={backend} count={} concurrency={} memory_mib={} cpus={}",
        spec.count, spec.concurrency, spec.memory_mib, spec.cpus
    );
    print_phase("start", start, start_wall, starts.len());
    print_phase("stop", stop, stop_wall, stops.len());
    print_stop_breakdown(stop_timings);
    print_hvf_shutdown_breakdown(hvf_shutdown_timings);
    eprintln!(
        "[microvm_lifecycle_bench] lifecycle wall={}ms throughput={:.2} VMs/s",
        millis(start_wall + stop_wall),
        starts.len() as f64 / (start_wall + stop_wall).as_secs_f64()
    );
}

fn print_hvf_shutdown_breakdown(timings: &[HvfShutdownTimingRecord]) {
    if timings.is_empty() {
        return;
    }
    eprintln!(
        "[microvm_lifecycle_bench] hvf-supervisor-shutdown n={} watchdog_to_vcpu_exit={} watchdog_join={} io_thread_join={} vcpu_destroy={} vm_destroy={} console_write={} workload_exit_write={}",
        timings.len(),
        format_summary(
            timings
                .iter()
                .map(|timing| Duration::from_micros(timing.watchdog_to_vcpu_exit_micros))
        ),
        format_summary(
            timings
                .iter()
                .map(|timing| Duration::from_micros(timing.watchdog_join_micros))
        ),
        format_summary(
            timings
                .iter()
                .map(|timing| Duration::from_micros(timing.io_thread_join_micros))
        ),
        format_summary(
            timings
                .iter()
                .map(|timing| Duration::from_micros(timing.vcpu_destroy_micros))
        ),
        format_summary(
            timings
                .iter()
                .map(|timing| Duration::from_micros(timing.vm_destroy_micros))
        ),
        format_summary(
            timings
                .iter()
                .map(|timing| Duration::from_micros(timing.console_write_micros))
        ),
        format_summary(
            timings
                .iter()
                .map(|timing| Duration::from_micros(timing.workload_exit_write_micros))
        ),
    );
}

fn print_stop_breakdown(timings: &[StopTiming]) {
    if timings.is_empty() {
        return;
    }

    eprintln!(
        "[microvm_lifecycle_bench] stop-breakdown n={} attach={} endpoint_reaping={} driver_kill={} console_cleanup={} total={}",
        timings.len(),
        format_summary(timings.iter().map(|timing| timing.attach)),
        format_summary(timings.iter().map(|timing| timing.endpoint_reaping)),
        format_summary(timings.iter().map(|timing| timing.driver_kill)),
        format_summary(timings.iter().map(|timing| timing.console_cleanup)),
        format_summary(timings.iter().map(|timing| timing.total)),
    );

    let details = timings
        .iter()
        .filter_map(|timing| timing.driver_detail)
        .collect::<Vec<_>>();
    if details.len() == timings.len() {
        eprintln!(
            "[microvm_lifecycle_bench] stop-driver-detail n={} supervisor_signal={} pid_disappearance={} force_kill_wait={} state_cleanup={} force_kill_escalations={}/{}",
            details.len(),
            format_summary(details.iter().map(|detail| detail.supervisor_signal)),
            format_summary(details.iter().map(|detail| detail.pid_disappearance)),
            format_summary(details.iter().map(|detail| detail.force_kill_wait)),
            format_summary(details.iter().map(|detail| detail.state_cleanup)),
            force_kill_escalation_count(timings),
            timings.len(),
        );
    }
}

fn force_kill_escalation_count(timings: &[StopTiming]) -> usize {
    timings
        .iter()
        .filter_map(|timing| timing.driver_detail)
        .filter(|detail| detail.force_kill_wait > Duration::ZERO)
        .count()
}

fn format_summary(samples: impl Iterator<Item = Duration>) -> String {
    let samples = samples.collect::<Vec<_>>();
    let summary = summarize(&samples);
    format!(
        "p50={:.2}ms/p95={:.2}ms/p99={:.2}ms/max={:.2}ms",
        millis(summary.p50),
        millis(summary.p95),
        millis(summary.p99),
        millis(summary.max),
    )
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
    validate_file(var, path)
}

fn validate_file(var: &str, path: PathBuf) -> Result<PathBuf> {
    if !path.is_file() {
        bail!("{var}={} is not a file", path.display());
    }
    Ok(path)
}

fn runtime_overlay_from_env() -> Result<Option<RuntimeOverlaySpec>> {
    runtime_overlay_from_values(
        std::env::var_os(RUNTIME_OVERLAY_VAR).map(PathBuf::from),
        std::env::var_os(RUNTIME_OVERLAY_VERITY_VAR).map(PathBuf::from),
        std::env::var(RUNTIME_OVERLAY_ROOTHASH_VAR).ok(),
    )
}

fn rootfs_integrity_from_env() -> Result<Option<RootfsIntegritySpec>> {
    rootfs_integrity_from_values(
        std::env::var_os(INITRD_VAR).map(PathBuf::from),
        std::env::var_os(ROOTFS_VERITY_VAR).map(PathBuf::from),
        std::env::var(ROOTFS_ROOTHASH_VAR).ok(),
    )
}

fn rootfs_integrity_from_values(
    initrd: Option<PathBuf>,
    verity: Option<PathBuf>,
    roothash: Option<String>,
) -> Result<Option<RootfsIntegritySpec>> {
    match (initrd, verity, roothash) {
        (None, None, None) => Ok(None),
        (Some(initrd), Some(verity), Some(roothash)) => Ok(Some(RootfsIntegritySpec {
            initrd: validate_file(INITRD_VAR, initrd)?,
            verity: validate_file(ROOTFS_VERITY_VAR, verity)?,
            roothash: validate_roothash(ROOTFS_ROOTHASH_VAR, roothash)?,
        })),
        _ => bail!(
            "{INITRD_VAR}, {ROOTFS_VERITY_VAR}, and {ROOTFS_ROOTHASH_VAR} must be set together"
        ),
    }
}

fn runtime_overlay_from_values(
    image: Option<PathBuf>,
    verity: Option<PathBuf>,
    roothash: Option<String>,
) -> Result<Option<RuntimeOverlaySpec>> {
    match (image, verity, roothash) {
        (None, None, None) => Ok(None),
        (Some(image), Some(verity), Some(roothash)) => {
            let image = validate_file(RUNTIME_OVERLAY_VAR, image)?;
            let verity = validate_file(RUNTIME_OVERLAY_VERITY_VAR, verity)?;
            let roothash = validate_roothash(RUNTIME_OVERLAY_ROOTHASH_VAR, roothash)?;
            Ok(Some(RuntimeOverlaySpec {
                image,
                verity,
                roothash,
            }))
        }
        _ => bail!(
            "{RUNTIME_OVERLAY_VAR}, {RUNTIME_OVERLAY_VERITY_VAR}, and \
             {RUNTIME_OVERLAY_ROOTHASH_VAR} must be set together"
        ),
    }
}

fn validate_roothash(var: &str, roothash: String) -> Result<String> {
    if roothash.len() != 64
        || !roothash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{var} must be 64 lowercase hexadecimal bytes");
    }
    Ok(roothash)
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
    let backend = backend.replace('-', "");
    format!(
        "p314-{backend}-{:x}-{nanos:x}-{index:x}",
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
fn benchmark_vm_names_leave_room_for_unix_socket_paths() {
    let name = unique_vm_name("apple-container", usize::MAX);
    assert!(name.len() <= 64, "benchmark VM name is too long: {name}");
    assert!(
        name.chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-'),
        "benchmark VM name contains a path-hostile character: {name}"
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
fn runtime_overlay_is_optional_but_must_be_complete_and_valid() {
    assert!(
        runtime_overlay_from_values(None, None, None)
            .unwrap()
            .is_none()
    );

    let temp = tempfile::tempdir().expect("create runtime-overlay fixture");
    let image = temp.path().join("overlay.ext4");
    let verity = temp.path().join("overlay.verity");
    std::fs::write(&image, b"image").expect("write overlay fixture");
    std::fs::write(&verity, b"verity").expect("write verity fixture");
    let roothash = "ab".repeat(32);
    let parsed = runtime_overlay_from_values(
        Some(image.clone()),
        Some(verity.clone()),
        Some(roothash.clone()),
    )
    .expect("parse complete runtime overlay")
    .expect("complete tuple produces a runtime overlay");
    assert_eq!(parsed.image, image);
    assert_eq!(parsed.verity, verity);
    assert_eq!(parsed.roothash, roothash);

    let mut config = VmStartConfig::default();
    apply_runtime_overlay(&mut config, &parsed);
    assert_eq!(
        config.runtime_overlay_roothash.as_deref(),
        Some(roothash.as_str())
    );

    assert!(runtime_overlay_from_values(Some(parsed.image), None, None).is_err());
    assert!(
        runtime_overlay_from_values(
            Some(parsed.verity.clone()),
            Some(parsed.verity),
            Some("AB".repeat(32)),
        )
        .is_err()
    );
}

#[test]
fn rootfs_integrity_is_optional_but_must_be_complete_and_valid() {
    assert!(
        rootfs_integrity_from_values(None, None, None)
            .unwrap()
            .is_none()
    );

    let temp = tempfile::tempdir().expect("create rootfs-integrity fixture");
    let initrd = temp.path().join("rootfs.initrd");
    let verity = temp.path().join("rootfs.verity");
    std::fs::write(&initrd, b"initrd").expect("write initrd fixture");
    std::fs::write(&verity, b"verity").expect("write verity fixture");
    let roothash = "cd".repeat(32);
    let parsed = rootfs_integrity_from_values(
        Some(initrd.clone()),
        Some(verity.clone()),
        Some(roothash.clone()),
    )
    .expect("parse complete rootfs integrity tuple")
    .expect("complete tuple produces rootfs integrity inputs");
    assert_eq!(parsed.initrd, initrd);
    assert_eq!(parsed.verity, verity);
    assert_eq!(parsed.roothash, roothash);

    let mut config = VmStartConfig::default();
    apply_rootfs_integrity(&mut config, &parsed);
    assert_eq!(config.roothash.as_deref(), Some(roothash.as_str()));
    assert!(rootfs_integrity_from_values(Some(parsed.initrd), None, None).is_err());
    assert!(
        rootfs_integrity_from_values(
            Some(parsed.verity.clone()),
            Some(parsed.verity),
            Some("not-a-hash".to_string()),
        )
        .is_err()
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

#[test]
fn force_kill_escalation_count_only_counts_nonzero_force_waits() {
    let timings = [
        StopTiming {
            driver_detail: Some(mvm_vmm::driver::RunningVmStopTiming::default()),
            ..StopTiming::default()
        },
        StopTiming {
            driver_detail: Some(mvm_vmm::driver::RunningVmStopTiming {
                force_kill_wait: Duration::from_millis(2),
                ..mvm_vmm::driver::RunningVmStopTiming::default()
            }),
            ..StopTiming::default()
        },
        StopTiming::default(),
    ];
    assert_eq!(force_kill_escalation_count(&timings), 1);
}

#[test]
fn lifecycle_report_builder_carries_every_measurement() {
    let spec = BenchSpec {
        backends: vec!["hvf".to_string()],
        kernel: PathBuf::new(),
        rootfs: PathBuf::new(),
        rootfs_integrity: None,
        runtime_overlay: None,
        count: 1,
        concurrency: 1,
        cpus: 1,
        memory_mib: 256,
    };
    let starts = [Duration::from_millis(1)];
    let stops = [Duration::from_millis(2)];
    let stop_timings = [StopTiming::default()];
    let hvf_shutdown_timings = [HvfShutdownTimingRecord {
        schema_version: 1,
        watchdog_to_vcpu_exit_micros: 0,
        watchdog_join_micros: 0,
        io_thread_join_micros: 0,
        vcpu_destroy_micros: 0,
        vm_destroy_micros: 0,
        console_write_micros: 0,
        workload_exit_write_micros: 0,
    }];
    let report = LifecycleReport::builder()
        .backend("hvf")
        .spec(&spec)
        .starts(&starts)
        .stops(&stops)
        .stop_timings(&stop_timings)
        .hvf_shutdown_timings(&hvf_shutdown_timings)
        .start_wall(Duration::from_millis(3))
        .stop_wall(Duration::from_millis(4))
        .build()
        .expect("complete lifecycle report");

    assert_eq!(report.backend, "hvf");
    assert_eq!(report.starts, starts);
    assert_eq!(report.stops, stops);
    assert_eq!(report.start_wall, Duration::from_millis(3));
    assert_eq!(report.stop_wall, Duration::from_millis(4));
}

#[test]
fn lifecycle_report_builder_refuses_missing_measurements() {
    assert!(LifecycleReport::builder().backend("hvf").build().is_err());
}
