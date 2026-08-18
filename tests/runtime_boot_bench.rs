//! Live boot benchmark for already-built runtime images.
//!
//! This deliberately excludes the builder VM and Nix image build path.
//! It measures only backend launch of prebuilt `vmlinux` + `rootfs.ext4`
//! artifacts, with an optional guest-agent readiness check.
//!
//! Run with a config file:
//!
//! ```text
//! MVM_RUNTIME_BOOT_CONFIG=/tmp/mvm-runtime-boot.toml \
//!   cargo test --test runtime_boot_bench prebuilt_runtime_image_boots_within_budget -- --exact --nocapture
//! ```
//!
//! Optional knobs:
//! - `MVM_RUNTIME_BOOT_BENCH=1` to run from environment variables only.
//! - `MVM_RUNTIME_BOOT_CONFIG=/path/to/config.toml` for TOML config.
//! - `MVM_RUNTIME_BOOT_RUNS=10` for serial samples.
//! - `MVM_RUNTIME_BOOT_CONCURRENT=3` for fan-out width.
//! - `MVM_RUNTIME_BOOT_BUDGET_MS=200` for the per-VM max budget.
//! - `MVM_RUNTIME_BOOT_READY=start-return|guest-agent`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use mvm_agentd::vsock::{GuestRequest, GuestResponse};
use mvm_core::vm_backend::RuntimeSourcePolicy;
use mvm_core::vm_backend::VmStartConfig;
use mvm_runtime::backend::AnyBackend;
use mvm_runtime::vsock_transport::VsockTransport as _;
use serde::Deserialize;

const ENABLE_VAR: &str = "MVM_RUNTIME_BOOT_BENCH";
const CONFIG_VAR: &str = "MVM_RUNTIME_BOOT_CONFIG";
const BACKEND_VAR: &str = "MVM_RUNTIME_BOOT_BACKEND";
const KERNEL_VAR: &str = "MVM_RUNTIME_BOOT_KERNEL";
const ROOTFS_VAR: &str = "MVM_RUNTIME_BOOT_ROOTFS";
const RUNS_VAR: &str = "MVM_RUNTIME_BOOT_RUNS";
const CONCURRENT_VAR: &str = "MVM_RUNTIME_BOOT_CONCURRENT";
const BUDGET_VAR: &str = "MVM_RUNTIME_BOOT_BUDGET_MS";
const READY_VAR: &str = "MVM_RUNTIME_BOOT_READY";
const CPUS_VAR: &str = "MVM_RUNTIME_BOOT_CPUS";
const MEMORY_MIB_VAR: &str = "MVM_RUNTIME_BOOT_MEMORY_MIB";
/// The prod guest rootfs carries no baked agent: `/init` resolves it from
/// `/mvm/runtime`, which is the runtime overlay attached as a second
/// virtio-blk drive. Booting one without the overlay panics the guest at
/// `Attempted to kill init!` before the agent can bind vsock, so a harness that
/// cannot attach an overlay cannot boot a prod image at all. All three are
/// required together, matching what the backend demands.
const OVERLAY_VAR: &str = "MVM_RUNTIME_BOOT_OVERLAY";
const OVERLAY_VERITY_VAR: &str = "MVM_RUNTIME_BOOT_OVERLAY_VERITY";
const OVERLAY_ROOTHASH_VAR: &str = "MVM_RUNTIME_BOOT_OVERLAY_ROOTHASH";
/// A sealed (dm-verity) image does not mount its own runtime overlay. Its
/// `/init` never gets the chance: `mvm-verity-init` runs from an initramfs and
/// mounts the overlay at `/mvm/runtime` before `switch_root`. Boot one without
/// the initramfs and the kernel execs the rootfs `/init` directly, which finds
/// no agent and panics with `Attempted to kill init!` — an image fault by
/// appearance and a harness fault in fact.
const VERITY_VAR: &str = "MVM_RUNTIME_BOOT_VERITY";
const ROOTHASH_VAR: &str = "MVM_RUNTIME_BOOT_ROOTHASH";
/// Overrides the initramfs the sealed path would otherwise resolve. Left unset
/// the harness resolves it exactly as production does, through
/// `mvm_build::initramfs::resolve_or_build_local_initramfs`, rather than
/// growing a second acquisition path that could drift from it.
const INITRD_VAR: &str = "MVM_RUNTIME_BOOT_INITRD";

const DEFAULT_BACKEND: &str = "firecracker";
const DEFAULT_RUNS: usize = 5;
const DEFAULT_CONCURRENT: usize = 3;
const DEFAULT_BUDGET_MS: u64 = 200;
const DEFAULT_READY: ReadySignal = ReadySignal::GuestAgent;
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const READY_POLL: Duration = Duration::from_millis(5);

#[test]
fn prebuilt_runtime_image_boots_within_budget() -> Result<()> {
    let Some(spec) = BenchSpec::from_env()? else {
        eprintln!("[runtime_boot_bench] skipped; set {ENABLE_VAR}=1 to run the live benchmark");
        return Ok(());
    };

    let serial = measure_serial(&spec)?;
    let serial_summary = summarize(&serial);
    eprintln!(
        "[runtime_boot_bench] serial backend={} ready={:?} runs={} p50={}ms p95={}ms max={}ms budget={}ms",
        spec.backend,
        spec.ready,
        serial.len(),
        serial_summary.p50.as_millis(),
        serial_summary.p95.as_millis(),
        serial_summary.max.as_millis(),
        spec.budget.as_millis(),
    );
    assert_within_budget("serial max", serial_summary.max, spec.budget);

    let concurrent = measure_concurrent(&spec)?;
    let concurrent_summary = summarize(&concurrent);
    eprintln!(
        "[runtime_boot_bench] concurrent backend={} ready={:?} count={} p50={}ms p95={}ms max={}ms budget={}ms",
        spec.backend,
        spec.ready,
        concurrent.len(),
        concurrent_summary.p50.as_millis(),
        concurrent_summary.p95.as_millis(),
        concurrent_summary.max.as_millis(),
        spec.budget.as_millis(),
    );
    assert_within_budget("concurrent max", concurrent_summary.max, spec.budget);

    Ok(())
}

#[derive(Debug, Clone)]
struct BenchSpec {
    backend: String,
    kernel: PathBuf,
    rootfs: PathBuf,
    runs: usize,
    concurrent: usize,
    budget: Duration,
    ready: ReadySignal,
    cpus: u32,
    memory_mib: u32,
    overlay: Option<OverlaySpec>,
    sealed: Option<SealedSpec>,
}

/// Verity sidecar, roothash and the initramfs that mounts them. All or none,
/// for the same reason the overlay triple is: a partial set boots a shape
/// nothing ships and fails as though the image were broken.
#[derive(Debug, Clone)]
struct SealedSpec {
    verity: PathBuf,
    roothash: String,
    initrd: PathBuf,
}

/// All three or none. The backend attaches the overlay only when the path, the
/// verity sidecar and the roothash are all present, so accepting a partial set
/// here would boot without an overlay and fail as though none was configured.
#[derive(Debug, Clone)]
struct OverlaySpec {
    path: PathBuf,
    verity: PathBuf,
    roothash: String,
}

impl BenchSpec {
    fn from_env() -> Result<Option<Self>> {
        let config = RawBenchConfig::from_env()?;
        if std::env::var(ENABLE_VAR).as_deref() != Ok("1") && config.is_none() {
            return Ok(None);
        }
        let config = config.unwrap_or_default();

        let overlay = overlay_spec(&config)?;
        let sealed = sealed_spec(&config)?;
        let kernel = required_path(KERNEL_VAR, config.kernel)?;
        let rootfs = required_path(ROOTFS_VAR, config.rootfs)?;
        let ready =
            ReadySignal::parse(&env_string_opt(READY_VAR, config.ready).unwrap_or_else(|| {
                default_ready_for_backend(&env_string_opt(BACKEND_VAR, config.backend.clone()))
            }))?;
        Ok(Some(Self {
            backend: env_string_opt(BACKEND_VAR, config.backend)
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string()),
            kernel,
            rootfs,
            runs: env_usize(RUNS_VAR, config.runs, DEFAULT_RUNS)?,
            concurrent: env_usize(CONCURRENT_VAR, config.concurrent, DEFAULT_CONCURRENT)?,
            budget: Duration::from_millis(env_u64(
                BUDGET_VAR,
                config.budget_ms,
                DEFAULT_BUDGET_MS,
            )?),
            ready,
            cpus: env_u32(CPUS_VAR, config.cpus, 1)?,
            memory_mib: env_u32(MEMORY_MIB_VAR, config.memory_mib, 256)?,
            overlay,
            sealed,
        }))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawBenchConfig {
    backend: Option<String>,
    kernel: Option<PathBuf>,
    rootfs: Option<PathBuf>,
    runs: Option<usize>,
    concurrent: Option<usize>,
    #[serde(alias = "budget_ms")]
    budget_ms: Option<u64>,
    ready: Option<String>,
    cpus: Option<u32>,
    #[serde(alias = "memory_mib")]
    memory_mib: Option<u32>,
    overlay: Option<PathBuf>,
    #[serde(alias = "overlay_verity")]
    overlay_verity: Option<PathBuf>,
    #[serde(alias = "overlay_roothash")]
    overlay_roothash: Option<String>,
    verity: Option<PathBuf>,
    roothash: Option<String>,
    initrd: Option<PathBuf>,
}

impl RawBenchConfig {
    fn from_env() -> Result<Option<Self>> {
        let Some(path) = std::env::var_os(CONFIG_VAR).map(PathBuf::from) else {
            return Ok(None);
        };
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {CONFIG_VAR}={}", path.display()))?;
        let config = toml::from_str(&raw)
            .with_context(|| format!("parsing {CONFIG_VAR}={}", path.display()))?;
        Ok(Some(config))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadySignal {
    StartReturn,
    GuestAgent,
}

impl ReadySignal {
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "start-return" | "start_return" | "start" => Ok(Self::StartReturn),
            "guest-agent" | "guest_agent" | "agent" => Ok(Self::GuestAgent),
            other => bail!("unknown {READY_VAR}={other:?}; expected start-return or guest-agent"),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::StartReturn => "start-return",
            Self::GuestAgent => "guest-agent",
        }
    }
}

#[derive(Debug, Clone)]
struct BootMeasurement {
    elapsed: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Summary {
    p50: Duration,
    p95: Duration,
    max: Duration,
}

fn measure_serial(spec: &BenchSpec) -> Result<Vec<BootMeasurement>> {
    let mut measurements = Vec::with_capacity(spec.runs);
    for run in 0..spec.runs {
        let name = unique_vm_name(&format!("serial-{run}"));
        measurements.push(measure_one(spec, name)?);
    }
    Ok(measurements)
}

fn measure_concurrent(spec: &BenchSpec) -> Result<Vec<BootMeasurement>> {
    let barrier = Arc::new(Barrier::new(spec.concurrent));
    let mut handles = Vec::with_capacity(spec.concurrent);

    for idx in 0..spec.concurrent {
        let spec = spec.clone();
        let barrier = Arc::clone(&barrier);
        let name = unique_vm_name(&format!("concurrent-{idx}"));
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            measure_one(&spec, name)
        }));
    }

    let mut measurements = Vec::with_capacity(spec.concurrent);
    for handle in handles {
        measurements.push(
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("concurrent boot worker panicked"))??,
        );
    }
    Ok(measurements)
}

fn measure_one(spec: &BenchSpec, name: String) -> Result<BootMeasurement> {
    let backend = AnyBackend::from_hypervisor(&spec.backend);
    let config = VmStartConfig {
        name: name.clone(),
        rootfs_path: spec.rootfs.to_string_lossy().into_owned(),
        kernel_path: Some(spec.kernel.to_string_lossy().into_owned()),
        cpus: spec.cpus,
        memory_mib: spec.memory_mib,
        revision_hash: "runtime-boot-bench".to_string(),
        flake_ref: "prebuilt-runtime-image".to_string(),
        runtime_overlay_path: spec
            .overlay
            .as_ref()
            .map(|o| o.path.to_string_lossy().into_owned()),
        runtime_overlay_verity_path: spec
            .overlay
            .as_ref()
            .map(|o| o.verity.to_string_lossy().into_owned()),
        runtime_overlay_roothash: spec.overlay.as_ref().map(|o| o.roothash.clone()),
        verity_path: spec
            .sealed
            .as_ref()
            .map(|s| s.verity.to_string_lossy().into_owned()),
        roothash: spec.sealed.as_ref().map(|s| s.roothash.clone()),
        initrd_path: spec
            .sealed
            .as_ref()
            .map(|s| s.initrd.to_string_lossy().into_owned()),
        // A sealed image has no baked agent to fall back to, so a missing
        // overlay must refuse the boot rather than drop into the ladder's
        // rootfs branch and report the absence as a panic.
        runtime_source_policy: if spec.sealed.is_some() {
            RuntimeSourcePolicy::RequiredOverlay
        } else {
            RuntimeSourcePolicy::default()
        },
        ..Default::default()
    };

    let started = Instant::now();
    let id = backend
        .start(&config)
        .with_context(|| format!("starting benchmark VM {name} with backend {}", spec.backend))?;
    let ready_result = wait_until_ready(spec, &name);
    let elapsed = started.elapsed();
    let stop_result = backend.stop(&id);

    if let Err(e) = stop_result {
        eprintln!("[runtime_boot_bench] warning: failed to stop {name}: {e}");
    }
    ready_result?;

    Ok(BootMeasurement { elapsed })
}

fn wait_until_ready(spec: &BenchSpec, name: &str) -> Result<()> {
    match spec.ready {
        ReadySignal::StartReturn => Ok(()),
        ReadySignal::GuestAgent => wait_for_guest_agent(&spec.backend, name),
    }
}

fn wait_for_guest_agent(backend: &str, name: &str) -> Result<()> {
    if backend == "hvf" {
        return wait_for_hvf_guest_agent(name);
    }
    let uds_path = guest_agent_socket_path(backend, name)?;
    let deadline = Instant::now() + READY_TIMEOUT;
    let mut last_err = None;

    while Instant::now() < deadline {
        match ping_guest_agent(&uds_path) {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
        std::thread::sleep(READY_POLL);
    }

    Err(last_err.unwrap_or_else(|| {
        anyhow::anyhow!(
            "guest agent did not become ready at {} within {:?}",
            uds_path.display(),
            READY_TIMEOUT
        )
    }))
}

fn wait_for_hvf_guest_agent(name: &str) -> Result<()> {
    let transport = mvm_runtime::vsock_transport::HvfVsockTransport::for_vm(name);
    let deadline = Instant::now() + READY_TIMEOUT;
    let mut last_err = None;

    while Instant::now() < deadline {
        match transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT) {
            Ok(mut stream) => {
                // ADR-019 / plan 74 W1: hard cutover requires hello
                // before any operational request, so a raw `Ping`
                // probe no longer works. Treat a successful hello
                // negotiation (with the `Ping` capability acknowledged)
                // as the readiness signal.
                match mvm_agentd::vsock::negotiate_protocol(
                    &mut stream,
                    vec![mvm_agentd::vsock::GuestCapability::Ping],
                ) {
                    Ok(negotiated)
                        if negotiated
                            .capabilities
                            .contains(&mvm_agentd::vsock::GuestCapability::Ping) =>
                    {
                        return Ok(());
                    }
                    Ok(_) => {
                        last_err = Some(anyhow::anyhow!(
                            "guest agent did not advertise the Ping capability"
                        ))
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            Err(e) => last_err = Some(e),
        }
        std::thread::sleep(READY_POLL);
    }

    Err(last_err.unwrap_or_else(|| {
        anyhow::anyhow!("Apple Container guest agent did not become ready within {READY_TIMEOUT:?}")
    }))
}

fn guest_agent_socket_path(backend: &str, name: &str) -> Result<PathBuf> {
    match backend {
        "firecracker" => Ok(mvm_core::config::vm_state_dir(name)
            .join("runtime")
            .join("v.sock")),
        "libkrun" | "krun" => Ok(mvm_core::config::vm_state_dir(name).join(format!(
            "vsock-{}.sock",
            mvm_agentd::vsock::GUEST_AGENT_PORT
        ))),
        other => bail!(
            "{READY_VAR}=guest-agent is not wired for backend {other:?}; use {READY_VAR}=start-return"
        ),
    }
}

fn ping_guest_agent(uds_path: &Path) -> Result<()> {
    let mut stream = mvm_agentd::vsock::connect_to(&uds_path.to_string_lossy(), 1)?;
    let negotiated = mvm_agentd::vsock::negotiate_protocol(
        &mut stream,
        vec![mvm_agentd::vsock::GuestCapability::Ping],
    )?;
    if !negotiated
        .capabilities
        .contains(&mvm_agentd::vsock::GuestCapability::Ping)
    {
        bail!("guest agent did not advertise the Ping capability");
    }
    let response = mvm_agentd::vsock::send_request(&mut stream, &GuestRequest::Ping)?;
    match response {
        GuestResponse::Pong => Ok(()),
        other => bail!("unexpected ping response: {other:?}"),
    }
}

fn summarize(measurements: &[BootMeasurement]) -> Summary {
    assert!(
        !measurements.is_empty(),
        "benchmark must have at least one measurement"
    );
    let mut values: Vec<_> = measurements.iter().map(|m| m.elapsed).collect();
    values.sort();
    Summary {
        p50: percentile(&values, 50),
        p95: percentile(&values, 95),
        max: *values.last().expect("non-empty values"),
    }
}

fn percentile(sorted: &[Duration], pct: usize) -> Duration {
    assert!(!sorted.is_empty(), "percentile needs at least one sample");
    let rank = ((sorted.len() * pct).div_ceil(100)).saturating_sub(1);
    sorted[rank.min(sorted.len() - 1)]
}

fn assert_within_budget(label: &str, actual: Duration, budget: Duration) {
    assert!(
        actual <= budget,
        "{label} exceeded runtime boot budget: {actual:?} > {budget:?}"
    );
}

/// Resolve the overlay triple, refusing a partial one. A silently-dropped
/// overlay is indistinguishable at the console from an image with no agent, so
/// name the missing piece here rather than let the guest panic explain it.
fn overlay_spec(config: &RawBenchConfig) -> Result<Option<OverlaySpec>> {
    let path = env_path_opt(OVERLAY_VAR, config.overlay.clone());
    let verity = env_path_opt(OVERLAY_VERITY_VAR, config.overlay_verity.clone());
    let roothash = env_string_opt(OVERLAY_ROOTHASH_VAR, config.overlay_roothash.clone());
    match (path, verity, roothash) {
        (None, None, None) => Ok(None),
        (Some(path), Some(verity), Some(roothash)) => {
            let roothash = roothash.trim().to_string();
            if roothash.is_empty() {
                anyhow::bail!("{OVERLAY_ROOTHASH_VAR} is set but empty");
            }
            Ok(Some(OverlaySpec {
                path,
                verity,
                roothash,
            }))
        }
        (path, verity, roothash) => {
            let mut missing = Vec::new();
            if path.is_none() {
                missing.push(OVERLAY_VAR);
            }
            if verity.is_none() {
                missing.push(OVERLAY_VERITY_VAR);
            }
            if roothash.is_none() {
                missing.push(OVERLAY_ROOTHASH_VAR);
            }
            anyhow::bail!(
                "runtime overlay is half-configured; the backend attaches it only \
                 when all three are set. Missing: {}",
                missing.join(", ")
            )
        }
    }
}

/// Resolve the sealed-boot set, refusing a partial one. The initramfs is
/// resolved through the same function the CLI's boot path uses, so the gate
/// cannot drift from what production actually attaches; an explicit
/// `MVM_RUNTIME_BOOT_INITRD` overrides it for a host that cannot build one.
fn sealed_spec(config: &RawBenchConfig) -> Result<Option<SealedSpec>> {
    let verity = env_path_opt(VERITY_VAR, config.verity.clone());
    let roothash = env_string_opt(ROOTHASH_VAR, config.roothash.clone());
    let (verity, roothash) = match (verity, roothash) {
        (None, None) => return Ok(None),
        (Some(v), Some(h)) => (v, h),
        (v, h) => {
            let mut missing = Vec::new();
            if v.is_none() {
                missing.push(VERITY_VAR);
            }
            if h.is_none() {
                missing.push(ROOTHASH_VAR);
            }
            anyhow::bail!(
                "sealed boot is half-configured; a verity sidecar without its \
                 roothash cannot be attached. Missing: {}",
                missing.join(", ")
            )
        }
    };
    let roothash = roothash.trim().to_string();
    if roothash.is_empty() {
        anyhow::bail!("{ROOTHASH_VAR} is set but empty");
    }
    let initrd = match env_path_opt(INITRD_VAR, config.initrd.clone()) {
        Some(p) => p,
        None => resolve_initramfs()?,
    };
    Ok(Some(SealedSpec {
        verity,
        roothash,
        initrd,
    }))
}

/// The universal initramfs, via the production resolver. On Linux it builds one
/// when the cache is cold; elsewhere it falls back to a published artifact.
fn resolve_initramfs() -> Result<PathBuf> {
    let cache_root = PathBuf::from(mvmctl::core::config::mvm_cache_dir()).join("initramfs");
    let artifact = mvmctl::build::initramfs::resolve_or_build_local_initramfs(
        &mvm_runtime::build_env::RuntimeBuildEnv,
        &cache_root,
        env!("CARGO_PKG_VERSION"),
        mvmctl::core::arch::GuestArch::host(),
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "sealed boot needs the universal initramfs and none could be resolved: {e}. \
             Set {INITRD_VAR} to one built elsewhere."
        )
    })?;
    Ok(artifact.image_path)
}

fn env_path_opt(var: &str, configured: Option<PathBuf>) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or(configured)
}

fn required_path(var: &str, configured: Option<PathBuf>) -> Result<PathBuf> {
    let path = std::env::var_os(var)
        .map(PathBuf::from)
        .or(configured)
        .ok_or_else(|| anyhow::anyhow!("{var} is required, or set it in {CONFIG_VAR}"))?;
    if !path.is_file() {
        bail!("{var}={} is not a file", path.display());
    }
    Ok(path)
}

fn env_string_opt(var: &str, configured: Option<String>) -> Option<String> {
    std::env::var(var).ok().or(configured)
}

fn default_ready_for_backend(backend: &Option<String>) -> String {
    match backend.as_deref() {
        Some("hvf") => ReadySignal::StartReturn.as_str().to_string(),
        _ => DEFAULT_READY.as_str().to_string(),
    }
}

fn env_usize(var: &str, configured: Option<usize>, default: usize) -> Result<usize> {
    let value = env_u64(var, configured.map(|v| v as u64), default as u64)?;
    usize::try_from(value).with_context(|| format!("{var} does not fit in usize: {value}"))
}

fn env_u32(var: &str, configured: Option<u32>, default: u32) -> Result<u32> {
    let value = env_u64(var, configured.map(u64::from), u64::from(default))?;
    u32::try_from(value).with_context(|| format!("{var} does not fit in u32: {value}"))
}

fn env_u64(var: &str, configured: Option<u64>, default: u64) -> Result<u64> {
    match std::env::var(var) {
        Ok(raw) => raw
            .parse::<u64>()
            .with_context(|| format!("parsing {var}={raw:?} as u64")),
        Err(_) => Ok(configured.unwrap_or(default)),
    }
}

fn unique_vm_name(label: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("mvm-boot-bench-{label}-{}-{millis}", std::process::id())
}

#[test]
fn ready_signal_parser_accepts_expected_aliases() {
    assert_eq!(
        ReadySignal::parse("start-return").expect("parse start-return"),
        ReadySignal::StartReturn
    );
    assert_eq!(
        ReadySignal::parse("start").expect("parse start"),
        ReadySignal::StartReturn
    );
    assert_eq!(
        ReadySignal::parse("guest-agent").expect("parse guest-agent"),
        ReadySignal::GuestAgent
    );
    assert_eq!(
        ReadySignal::parse("agent").expect("parse agent"),
        ReadySignal::GuestAgent
    );
}

#[test]
fn summary_reports_percentiles_and_max() {
    let measurements = [
        BootMeasurement {
            elapsed: Duration::from_millis(10),
        },
        BootMeasurement {
            elapsed: Duration::from_millis(20),
        },
        BootMeasurement {
            elapsed: Duration::from_millis(30),
        },
        BootMeasurement {
            elapsed: Duration::from_millis(40),
        },
    ];
    let summary = summarize(&measurements);
    assert_eq!(summary.p50, Duration::from_millis(20));
    assert_eq!(summary.p95, Duration::from_millis(40));
    assert_eq!(summary.max, Duration::from_millis(40));
}

#[test]
fn config_file_shape_accepts_hvf_defaults() {
    let config: RawBenchConfig = toml::from_str(
        r#"
backend = "hvf"
kernel = "/tmp/vmlinux"
rootfs = "/tmp/rootfs.ext4"
runs = 2
concurrent = 3
budget-ms = 200
cpus = 1
memory-mib = 256
"#,
    )
    .expect("parse runtime boot bench config");

    assert_eq!(config.backend.as_deref(), Some("hvf"));
    assert_eq!(config.runs, Some(2));
    assert_eq!(config.concurrent, Some(3));
    assert_eq!(
        default_ready_for_backend(&config.backend),
        ReadySignal::StartReturn.as_str()
    );
}

#[test]
fn live_bench_is_disabled_by_default() -> Result<()> {
    if std::env::var(ENABLE_VAR).is_ok() {
        eprintln!("[runtime_boot_bench] env already set; skipping disabled-by-default assertion");
        return Ok(());
    }
    assert!(BenchSpec::from_env()?.is_none());
    Ok(())
}

/// The overlay is what carries the guest agent for a prod image. A half-set
/// triple used to be indistinguishable from an unset one, and the backend
/// silently declined to attach it — the first visible symptom was a kernel
/// panic that blamed the image.
#[test]
fn overlay_spec_is_absent_when_nothing_is_configured() {
    let config = RawBenchConfig::default();
    assert!(
        overlay_spec(&config)
            .expect("no overlay is valid")
            .is_none()
    );
}

#[test]
fn overlay_spec_accepts_the_complete_triple() {
    let config = RawBenchConfig {
        overlay: Some(PathBuf::from("/tmp/overlay.ext4")),
        overlay_verity: Some(PathBuf::from("/tmp/overlay.verity")),
        overlay_roothash: Some("  deadbeef\n".to_string()),
        ..RawBenchConfig::default()
    };
    let spec = overlay_spec(&config)
        .expect("complete triple is valid")
        .expect("complete triple yields an overlay");
    assert_eq!(spec.path, PathBuf::from("/tmp/overlay.ext4"));
    assert_eq!(spec.verity, PathBuf::from("/tmp/overlay.verity"));
    // Trimmed: the roothash is read from a file that ends in a newline.
    assert_eq!(spec.roothash, "deadbeef");
}

#[test]
fn overlay_spec_refuses_a_half_configured_overlay_and_names_what_is_missing() {
    let config = RawBenchConfig {
        overlay: Some(PathBuf::from("/tmp/overlay.ext4")),
        ..RawBenchConfig::default()
    };
    let err = overlay_spec(&config)
        .expect_err("a partial overlay must not silently boot without one")
        .to_string();
    // Compare the missing list exactly. `contains(OVERLAY_VAR)` would always
    // hold — it is a prefix of the other two names — so a substring check here
    // would pass no matter which variables the message actually named.
    let listed = err
        .split_once("Missing: ")
        .map(|(_, rest)| rest.trim().to_string())
        .unwrap_or_else(|| panic!("error should name what is missing: {err}"));
    assert_eq!(
        listed,
        format!("{OVERLAY_VERITY_VAR}, {OVERLAY_ROOTHASH_VAR}")
    );
}

#[test]
fn overlay_spec_refuses_a_blank_roothash() {
    let config = RawBenchConfig {
        overlay: Some(PathBuf::from("/tmp/overlay.ext4")),
        overlay_verity: Some(PathBuf::from("/tmp/overlay.verity")),
        overlay_roothash: Some("   \n".to_string()),
        ..RawBenchConfig::default()
    };
    let err = overlay_spec(&config)
        .expect_err("a blank roothash is not a roothash")
        .to_string();
    assert!(err.contains(OVERLAY_ROOTHASH_VAR), "{err}");
}

/// An unsealed boot stays unsealed. Resolving an initramfs for an image that
/// does not need one would make every dev-image bench depend on a build.
#[test]
fn sealed_spec_is_absent_when_nothing_is_configured() {
    let config = RawBenchConfig::default();
    assert!(
        sealed_spec(&config)
            .expect("no sealed set is valid")
            .is_none()
    );
}

#[test]
fn sealed_spec_accepts_verity_roothash_and_an_explicit_initrd() {
    let config = RawBenchConfig {
        verity: Some(PathBuf::from("/tmp/rootfs.verity")),
        roothash: Some("  cafebabe\n".to_string()),
        initrd: Some(PathBuf::from("/tmp/initramfs.cpio.gz")),
        ..RawBenchConfig::default()
    };
    let spec = sealed_spec(&config)
        .expect("a complete sealed set is valid")
        .expect("a complete sealed set yields a spec");
    assert_eq!(spec.verity, PathBuf::from("/tmp/rootfs.verity"));
    assert_eq!(spec.initrd, PathBuf::from("/tmp/initramfs.cpio.gz"));
    // Trimmed: the roothash is read from a file that ends in a newline.
    assert_eq!(spec.roothash, "cafebabe");
}

#[test]
fn sealed_spec_refuses_a_verity_sidecar_without_its_roothash() {
    let config = RawBenchConfig {
        verity: Some(PathBuf::from("/tmp/rootfs.verity")),
        initrd: Some(PathBuf::from("/tmp/initramfs.cpio.gz")),
        ..RawBenchConfig::default()
    };
    let err = sealed_spec(&config)
        .expect_err("a sidecar with no roothash cannot be attached")
        .to_string();
    let listed = err
        .split_once("Missing: ")
        .map(|(_, rest)| rest.trim().to_string())
        .unwrap_or_else(|| panic!("error should name what is missing: {err}"));
    assert_eq!(listed, ROOTHASH_VAR);
}

#[test]
fn sealed_spec_refuses_a_blank_roothash() {
    let config = RawBenchConfig {
        verity: Some(PathBuf::from("/tmp/rootfs.verity")),
        roothash: Some("  \n".to_string()),
        initrd: Some(PathBuf::from("/tmp/initramfs.cpio.gz")),
        ..RawBenchConfig::default()
    };
    let err = sealed_spec(&config)
        .expect_err("a blank roothash is not a roothash")
        .to_string();
    assert!(err.contains(ROOTHASH_VAR), "{err}");
}
