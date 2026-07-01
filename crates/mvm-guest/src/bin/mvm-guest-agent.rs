//! Guest vsock agent — runs inside the microVM, listens on
//! `GUEST_AGENT_PORT` (5252).
//!
//! Handles host-to-guest requests (Ping, WorkerStatus, SleepPrep, Wake, etc.)
//! and reports real system metrics via a background monitoring thread.
//!
//! ## Usage
//!
//! ```text
//! mvm-guest-agent [OPTIONS]
//!
//! Options:
//!   --config <path>            JSON config file (default: /etc/mvm/agent.json)
//!   --port <port>              Vsock port to listen on (default: 5252)
//!   --busy-threshold <float>   Load average threshold for busy (default: 0.1)
//!   --sample-interval <secs>   Monitoring sample interval (default: 5)
//!   --help, -h                 Print usage
//! ```

use std::io::{Read, Write};
use std::mem::size_of;
use std::os::fd::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mvm_core::security::AgentProfile;
use mvm_guest::entrypoint::{
    CallCaps, CallOutcome, EntrypointPolicy, PayloadCapStream, ValidatedEntrypoint, execute,
};
use mvm_guest::integrations::{
    self, IntegrationEntry, IntegrationHealthResult, IntegrationStateReport, IntegrationStatus,
};
use mvm_guest::lifecycle_hooks::{self, ReadinessConfig};
use mvm_guest::probes::{self, ProbeEntry, ProbeOutputFormat, ProbeResult};
use mvm_guest::runtime_config::{self, ConcurrencyConfig};
use mvm_guest::vsock::{
    BootTimingReport, ComponentState, EntrypointEvent, FsChange, FsChangeKind, GUEST_AGENT_PORT,
    GuestRequest, GuestResponse, ReadinessReport, RunEntrypointError, enforce_verb_grant,
};
use mvm_guest::worker_pool::{DispatchError, DispatchOutcome, WorkerPool};
use mvm_guest::worker_protocol::WorkerOutcome;
use serde::Deserialize;

// ============================================================================
// Configuration
// ============================================================================

const DEFAULT_CONFIG_PATH: &str = "/etc/mvm/agent.json";
const DEFAULT_BUSY_THRESHOLD: f64 = 0.1;
const DEFAULT_SAMPLE_INTERVAL_SECS: u64 = 5;

// Baked-in lifecycle hook paths. The Nix factory at
// `nix/lib/factories/mkFunctionService.nix` always emits these
// scripts (no-op `:` body when the user declared no commands for
// the phase). The agent only needs to know the canonical path;
// missing-script fall-through is handled inside `lifecycle_hooks`
// defensively.
const AFTER_START_HOOK: &str = "/etc/mvm/hooks/after_start.sh";
const BEFORE_STOP_HOOK: &str = "/etc/mvm/hooks/before_stop.sh";

/// Maximum time to wait for the after_start probe to exit 0 before
/// the agent gives up (30s). On timeout, the pool stays NotReady and
/// dispatch refuses fast.
const READINESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Sleep between readiness probe attempts. 200 ms balances fast
/// ready-detection against shell-fork overhead.
const READINESS_INTERVAL: Duration = Duration::from_millis(200);

/// Maximum time to give the before_stop hook before SIGKILL.
const SHUTDOWN_HOOK_GRACE: Duration = Duration::from_secs(10);

/// Sleep between shutdown-hook completion checks.
const SHUTDOWN_HOOK_POLL: Duration = Duration::from_millis(200);

#[derive(Deserialize)]
struct AgentConfig {
    #[serde(default = "default_port")]
    port: u32,
    #[serde(default = "default_busy_threshold")]
    busy_threshold: f64,
    #[serde(default = "default_sample_interval_secs")]
    sample_interval_secs: u64,
}

fn default_port() -> u32 {
    GUEST_AGENT_PORT
}
fn default_busy_threshold() -> f64 {
    DEFAULT_BUSY_THRESHOLD
}
fn default_sample_interval_secs() -> u64 {
    DEFAULT_SAMPLE_INTERVAL_SECS
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            busy_threshold: default_busy_threshold(),
            sample_interval_secs: default_sample_interval_secs(),
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage: mvm-guest-agent [OPTIONS]\n\
         \n\
         Options:\n\
         \x20 --config <path>            JSON config file (default: {})\n\
         \x20 --port <port>              Vsock port to listen on (default: {})\n\
         \x20 --busy-threshold <float>   Load average threshold for busy (default: {})\n\
         \x20 --sample-interval <secs>   Monitoring sample interval (default: {})\n\
         \x20 --help, -h                 Print this help",
        DEFAULT_CONFIG_PATH, GUEST_AGENT_PORT, DEFAULT_BUSY_THRESHOLD, DEFAULT_SAMPLE_INTERVAL_SECS,
    );
}

fn parse_config() -> AgentConfig {
    let (cfg, resolved_path) = parse_config_with_path();
    // Stash the resolved config path so the SIGHUP handler's
    // `apply_reload` re-reads the same file the operator launched
    // against (handles `--config <path>` overrides).
    let _ = AGENT_CONFIG_PATH.set(resolved_path);
    cfg
}

/// Test seam — returns the resolved path the file was read from
/// (or the default path if nothing was found) alongside the
/// parsed config. Production goes through [`parse_config`].
fn parse_config_with_path() -> (AgentConfig, PathBuf) {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path: Option<String> = None;
    let mut cli_port: Option<u32> = None;
    let mut cli_threshold: Option<f64> = None;
    let mut cli_interval: Option<u64> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--config" => {
                i += 1;
                config_path = args.get(i).cloned();
            }
            "--port" => {
                i += 1;
                cli_port = args.get(i).and_then(|v| {
                    v.parse()
                        .map_err(|e| eprintln!("invalid --port value '{}': {}", v, e))
                        .ok()
                });
            }
            "--busy-threshold" => {
                i += 1;
                cli_threshold = args.get(i).and_then(|v| {
                    v.parse()
                        .map_err(|e| eprintln!("invalid --busy-threshold value '{}': {}", v, e))
                        .ok()
                });
            }
            "--sample-interval" => {
                i += 1;
                cli_interval = args.get(i).and_then(|v| {
                    v.parse()
                        .map_err(|e| eprintln!("invalid --sample-interval value '{}': {}", v, e))
                        .ok()
                });
            }
            other => {
                eprintln!("unknown flag: {}", other);
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // Load config file: explicit path, or default path (silently ignored if missing).
    let mut cfg = match &config_path {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(data) => match serde_json::from_str::<AgentConfig>(&data) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("failed to parse config {}: {}", path, e);
                    std::process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("failed to read config {}: {}", path, e);
                std::process::exit(1);
            }
        },
        None => match std::fs::read_to_string(DEFAULT_CONFIG_PATH) {
            Ok(data) => serde_json::from_str::<AgentConfig>(&data)
                .map_err(|e| {
                    eprintln!(
                        "failed to parse default config {}: {}",
                        DEFAULT_CONFIG_PATH, e
                    )
                })
                .ok()
                .unwrap_or_default(),
            Err(_) => AgentConfig::default(),
        },
    };

    // CLI flags override config file values.
    if let Some(p) = cli_port {
        cfg.port = p;
    }
    if let Some(t) = cli_threshold {
        cfg.busy_threshold = t;
    }
    if let Some(s) = cli_interval {
        cfg.sample_interval_secs = s;
    }

    let resolved = config_path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
    (cfg, resolved)
}

// ============================================================================
// Vsock socket constants and FFI (same as mvm-builder-agent)
// ============================================================================

const AF_VSOCK: i32 = 40;
const SOCK_STREAM: i32 = 1;
const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;
const MAX_FRAME_SIZE: usize = 256 * 1024;

#[repr(C)]
struct SockAddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

unsafe extern "C" {
    fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
    fn bind(sockfd: i32, addr: *const core::ffi::c_void, addrlen: u32) -> i32;
    fn listen(sockfd: i32, backlog: i32) -> i32;
    fn accept(sockfd: i32, addr: *mut core::ffi::c_void, addrlen: *mut u32) -> i32;
    fn close(fd: i32) -> i32;
}

// ============================================================================
// Agent state (shared between monitoring thread and request handlers)
// ============================================================================

struct AgentState {
    status: String,
    last_busy_at: Option<String>,
}

impl AgentState {
    fn new() -> Self {
        Self {
            status: "idle".to_string(),
            last_busy_at: None,
        }
    }
}

// ============================================================================
// Boot readiness state
// ============================================================================

/// Per-subsystem readiness, surfaced through `ReadinessStatus` and
/// also consulted by `RunEntrypoint` so a host that races
/// invocation ahead of warmup gets a typed `NotReady` rather than a
/// permanent failure.
///
/// **State design.** A single `Mutex<BootStateInner>` instead of
/// per-component atomics. Readers (`ReadinessStatus` handlers,
/// `entrypoint_ready()` checks) are rare; writers fire at boot
/// completion events. The lock holds for at most a few struct-field
/// reads so contention is a non-issue. Per-component atomics
/// (`AtomicU8` + side-channel for `Failed { message }`) would be
/// more complex and earn nothing measurable.
///
/// **Why background init is still safe.** Per-handler invariants
/// stay intact:
///   - `RunEntrypoint` consults this state AND the existing
///     `VALIDATED_ENTRYPOINT` `OnceLock` — `NotReady` while
///     `Starting`, `EntrypointInvalid` once `VALIDATED_ENTRYPOINT`
///     is set to `Err`.
///   - Warm-process dispatch in the worker pool keeps its own
///     ready flag (`WorkerPool::wait_for_ready`) — this state is
///     observability, not the gate.
struct AgentBootState {
    inner: Mutex<BootStateInner>,
    profile: AgentProfile,
    boot_at: std::time::Instant,
    /// Pinned agent-verb grant from the admission handshake; `None` means
    /// no grant is pinned — the class gate (`allowed_in`) is the only
    /// verb filter.
    verb_grant: Option<mvm_core::plan::VerbGrant>,
}

#[derive(Default)]
struct BootStateInner {
    control_plane: ComponentState,
    entrypoint: ComponentState,
    warm_pool: ComponentState,
    integrations: ComponentState,
    probes: ComponentState,
    volumes: ComponentState,
    timing: BootTimingReport,
}

impl AgentBootState {
    fn new(profile: AgentProfile, boot_at: std::time::Instant) -> Self {
        Self {
            inner: Mutex::new(BootStateInner {
                // Two components start `Starting` rather than the
                // `Default` `Disabled`: `control_plane` flips to
                // `Ready` immediately after `bind+listen` in `main`
                // (we're not running until then), and `entrypoint`
                // is the boot dependency `RunEntrypoint` gates on.
                // The remaining components keep `Disabled` from
                // `Default` — the background init thread flips them
                // to `Starting` when it sees config that requires
                // them.
                control_plane: ComponentState::Starting,
                entrypoint: ComponentState::Starting,
                ..Default::default()
            }),
            profile,
            boot_at,
            verb_grant: None,
        }
    }

    /// Milliseconds elapsed since `boot_at`. Always fits in `u64`
    /// for any plausible agent lifetime; saturates on the absurd.
    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.boot_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn mark_vsock_bound(&self) {
        if let Ok(mut s) = self.inner.lock() {
            s.control_plane = ComponentState::Ready;
            let ms = self.elapsed_ms();
            s.timing.agent_started_ms.get_or_insert(ms);
            s.timing.vsock_bound_ms.get_or_insert(ms);
        }
    }

    /// Stamp the first-accept timing. Idempotent — only the first
    /// caller wins, subsequent accept loops are no-ops.
    fn mark_first_accept(&self) {
        if let Ok(mut s) = self.inner.lock()
            && s.timing.first_accept_ms.is_none()
        {
            s.timing.first_accept_ms = Some(self.elapsed_ms());
        }
    }

    fn set_entrypoint(&self, state: ComponentState) {
        if let Ok(mut s) = self.inner.lock() {
            // `Disabled` is terminal too — an image that offers no per-call
            // entrypoint resolves immediately (entrypoint starts as
            // `Starting`), same as `set_warm_pool` treats its Disabled.
            let became_terminal = matches!(
                state,
                ComponentState::Ready | ComponentState::Failed { .. } | ComponentState::Disabled
            );
            s.entrypoint = state;
            if became_terminal && s.timing.entrypoint_ready_ms.is_none() {
                s.timing.entrypoint_ready_ms = Some(self.elapsed_ms());
            }
        }
    }

    /// Set the warm-pool component and stamp `warm_pool_ready_ms`
    /// when the state first leaves `Starting` for a terminal value
    /// (`Ready` / `Failed` / `Disabled`). Initial `Disabled` (the
    /// `Default` value, set before any background thread runs) does
    /// not stamp — we only count time once init actually starts.
    fn set_warm_pool(&self, state: ComponentState) {
        if let Ok(mut s) = self.inner.lock() {
            let was_starting = matches!(s.warm_pool, ComponentState::Starting);
            s.warm_pool = state;
            if was_starting && s.timing.warm_pool_ready_ms.is_none() {
                s.timing.warm_pool_ready_ms = Some(self.elapsed_ms());
            }
        }
    }

    /// Set the integrations component. Stamps `integrations_ready_ms`
    /// on the first transition out of `Starting`. See `set_warm_pool`
    /// for the rationale on skipping initial-Disabled stamps.
    fn set_integrations(&self, state: ComponentState) {
        if let Ok(mut s) = self.inner.lock() {
            let was_starting = matches!(s.integrations, ComponentState::Starting);
            s.integrations = state;
            if was_starting && s.timing.integrations_ready_ms.is_none() {
                s.timing.integrations_ready_ms = Some(self.elapsed_ms());
            }
        }
    }

    /// Set the probes component. Stamps `probes_ready_ms` on the
    /// first transition out of `Starting`.
    fn set_probes(&self, state: ComponentState) {
        if let Ok(mut s) = self.inner.lock() {
            let was_starting = matches!(s.probes, ComponentState::Starting);
            s.probes = state;
            if was_starting && s.timing.probes_ready_ms.is_none() {
                s.timing.probes_ready_ms = Some(self.elapsed_ms());
            }
        }
    }

    fn snapshot(&self) -> ReadinessReport {
        let inner = self.inner.lock();
        let (control_plane, entrypoint, warm_pool, integrations, probes, volumes, timing) =
            match inner {
                Ok(s) => (
                    s.control_plane.clone(),
                    s.entrypoint.clone(),
                    s.warm_pool.clone(),
                    s.integrations.clone(),
                    s.probes.clone(),
                    s.volumes.clone(),
                    s.timing.clone(),
                ),
                // Poisoned lock means another thread panicked mid-update;
                // surface that as a generic Failed rather than swallowing.
                Err(_) => {
                    let msg = "boot-state lock poisoned".to_string();
                    (
                        ComponentState::Failed {
                            message: msg.clone(),
                        },
                        ComponentState::Failed {
                            message: msg.clone(),
                        },
                        ComponentState::Failed {
                            message: msg.clone(),
                        },
                        ComponentState::Failed {
                            message: msg.clone(),
                        },
                        ComponentState::Failed {
                            message: msg.clone(),
                        },
                        ComponentState::Failed { message: msg },
                        BootTimingReport::default(),
                    )
                }
            };
        ReadinessReport {
            control_plane,
            entrypoint,
            warm_pool,
            integrations,
            probes,
            volumes,
            profile: self.profile,
            boot_millis: timing,
        }
    }
}

// ============================================================================
// Integration health state (shared between health thread and request handlers)
// ============================================================================

struct IntegrationHealth {
    entry: IntegrationEntry,
    last_result: Option<IntegrationHealthResult>,
}

struct IntegrationState {
    integrations: Vec<IntegrationHealth>,
}

// ============================================================================
// Probe health state (shared between probe thread and request handlers)
// ============================================================================

struct ProbeHealth {
    entry: ProbeEntry,
    last_result: Option<ProbeResult>,
}

struct ProbeState {
    probes: Vec<ProbeHealth>,
}

// ============================================================================
// System monitoring
// ============================================================================

/// Read 1-minute load average from /proc/loadavg.
fn sample_load() -> f64 {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
        })
        .unwrap_or(0.0)
}

/// Format current UTC time as ISO 8601.
fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Convert epoch seconds to UTC date/time components.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    // Days since 1970-01-01 to (year, month, day).
    // Algorithm from Howard Hinnant's chrono-compatible date library.
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hour, minute, second
    )
}

/// Background monitoring loop — samples /proc/loadavg at the configured interval.
///
/// Reads `HOT_BUSY_THRESHOLD_BITS` and `HOT_SAMPLE_INTERVAL_SECS`
/// on every iteration so a SIGHUP-driven reload picks up on the next
/// sample without restarting the loop.
fn monitoring_loop(state: Arc<Mutex<AgentState>>) {
    loop {
        let load = sample_load();
        let busy_threshold = f64::from_bits(HOT_BUSY_THRESHOLD_BITS.load(Ordering::Acquire));
        if let Ok(mut s) = state.lock() {
            if load >= busy_threshold {
                s.status = "busy".to_string();
                s.last_busy_at = Some(utc_now());
            } else {
                s.status = "idle".to_string();
            }
        }
        let interval_secs = HOT_SAMPLE_INTERVAL_SECS.load(Ordering::Acquire).max(1); // never sleep 0 — busy-spin would peg a CPU
        std::thread::sleep(Duration::from_secs(interval_secs));
    }
}

// ============================================================================
// Shell command execution
// ============================================================================

/// Run a shell command with a timeout, returning the captured output.
///
/// Uses `/bin/sh -c` (absolute path — NixOS systemd services may not have
/// `/bin` in PATH, but `/bin/sh` always exists as a symlink to bash).
/// Timeout is enforced natively via `try_wait` polling to avoid depending
/// on the `timeout` binary from coreutils being in PATH.
fn run_shell_with_timeout(cmd: &str, timeout: Duration) -> std::io::Result<std::process::Output> {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Poll until the child exits or the timeout fires.
    let start = Instant::now();
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if start.elapsed() >= timeout => {
                if let Err(e) = child.kill() {
                    eprintln!("failed to kill child process: {e}");
                }
                if let Err(e) = child.wait() {
                    eprintln!("failed to wait child process: {e}");
                }
                return Ok(std::process::Output {
                    status: std::process::ExitStatus::default(),
                    stdout: Vec::new(),
                    stderr: format!("timed out after {}s", timeout.as_secs()).into_bytes(),
                });
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    };

    // Child has exited — read remaining pipe output.
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut r) = child.stdout.take()
        && let Err(e) = r.read_to_end(&mut stdout)
    {
        eprintln!("failed to read child stdout: {e}");
    }
    if let Some(mut r) = child.stderr.take()
        && let Err(e) = r.read_to_end(&mut stderr)
    {
        eprintln!("failed to read child stderr: {e}");
    }
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

// ============================================================================
// Integration health monitoring
// ============================================================================

/// Run a single health check command for an integration.
fn run_health_check(entry: &IntegrationEntry) -> IntegrationHealthResult {
    let Some(ref cmd) = entry.health_cmd else {
        return IntegrationHealthResult {
            healthy: true,
            detail: "no health_cmd configured".to_string(),
            checked_at: utc_now(),
        };
    };

    let timeout = Duration::from_secs(entry.health_timeout_secs);
    match run_shell_with_timeout(cmd, timeout) {
        Ok(out) if out.status.success() => IntegrationHealthResult {
            healthy: true,
            detail: "ok".to_string(),
            checked_at: utc_now(),
        },
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = if stderr.trim().is_empty() {
                format!("exit code {}", out.status.code().unwrap_or(-1))
            } else {
                stderr.trim().to_string()
            };
            IntegrationHealthResult {
                healthy: false,
                detail,
                checked_at: utc_now(),
            }
        }
        Err(e) => IntegrationHealthResult {
            healthy: false,
            detail: format!("failed to execute: {}", e),
            checked_at: utc_now(),
        },
    }
}

/// Background loop that periodically runs health checks for all integrations.
fn integration_health_loop(state: Arc<Mutex<IntegrationState>>) {
    let count = state.lock().map(|s| s.integrations.len()).unwrap_or(0);
    let mut last_checked: Vec<Option<std::time::Instant>> = vec![None; count];
    let boot_time = std::time::Instant::now();

    loop {
        let entries: Vec<(usize, IntegrationEntry)> = {
            let Ok(s) = state.lock() else {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            };
            s.integrations
                .iter()
                .enumerate()
                .map(|(i, ih)| (i, ih.entry.clone()))
                .collect()
        };

        for (idx, entry) in &entries {
            if entry.health_cmd.is_none() {
                continue;
            }
            let interval = Duration::from_secs(entry.health_interval_secs);
            let should_check = match last_checked.get(*idx).copied().flatten() {
                Some(last) => last.elapsed() >= interval,
                None => true,
            };
            if !should_check {
                continue;
            }

            let result = run_health_check(entry);
            // During the startup grace period, still store results (so the host
            // can poll via vsock) but don't log failures to console.
            let in_grace = entry.startup_grace_secs > 0
                && boot_time.elapsed() < Duration::from_secs(entry.startup_grace_secs);
            if !result.healthy && !in_grace {
                eprintln!(
                    "mvm-guest-agent: health check failed for '{}': {}",
                    entry.name, result.detail
                );
            }
            if let Ok(mut s) = state.lock()
                && let Some(ih) = s.integrations.get_mut(*idx)
            {
                ih.last_result = Some(result);
            }
            last_checked[*idx] = Some(std::time::Instant::now());
        }

        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Build an IntegrationStateReport from cached health data.
///
/// `boot_at` is the time the agent started; used to determine whether a
/// service is still within its `startup_grace_secs` window.  During that
/// window, unhealthy or not-yet-checked integrations report `starting`
/// instead of `error` / `pending` so the host knows the VM is still
/// initialising rather than broken.
fn build_integration_reports(
    integration_state: &Arc<Mutex<IntegrationState>>,
    boot_at: std::time::Instant,
) -> Vec<IntegrationStateReport> {
    let Ok(s) = integration_state.lock() else {
        return vec![];
    };
    s.integrations
        .iter()
        .map(|ih| {
            let in_grace = ih.entry.startup_grace_secs > 0
                && boot_at.elapsed() < Duration::from_secs(ih.entry.startup_grace_secs);
            let status = match &ih.last_result {
                Some(r) if r.healthy => IntegrationStatus::Active,
                Some(_) if in_grace => IntegrationStatus::Starting,
                Some(r) => IntegrationStatus::Error(r.detail.clone()),
                None if in_grace => IntegrationStatus::Starting,
                None => IntegrationStatus::Pending,
            };
            IntegrationStateReport {
                name: ih.entry.name.clone(),
                status,
                last_checkpoint_at: None,
                state_size_bytes: 0,
                health: ih.last_result.clone(),
            }
        })
        .collect()
}

// ============================================================================
// Probe health monitoring
// ============================================================================

/// Run a single probe command.
fn run_probe(entry: &ProbeEntry) -> ProbeResult {
    let timeout = Duration::from_secs(entry.timeout_secs);
    let output = run_shell_with_timeout(&entry.cmd, timeout);

    match output {
        Ok(out) if out.status.success() => {
            let json_output = if entry.output_format == ProbeOutputFormat::Json {
                let stdout = String::from_utf8_lossy(&out.stdout);
                serde_json::from_str(stdout.trim()).ok()
            } else {
                None
            };
            ProbeResult {
                name: entry.name.clone(),
                healthy: true,
                detail: "ok".to_string(),
                output: json_output,
                checked_at: utc_now(),
            }
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = if stderr.trim().is_empty() {
                format!("exit code {}", out.status.code().unwrap_or(-1))
            } else {
                stderr.trim().to_string()
            };
            ProbeResult {
                name: entry.name.clone(),
                healthy: false,
                detail,
                output: None,
                checked_at: utc_now(),
            }
        }
        Err(e) => ProbeResult {
            name: entry.name.clone(),
            healthy: false,
            detail: format!("failed to execute: {}", e),
            output: None,
            checked_at: utc_now(),
        },
    }
}

/// Background loop that periodically runs all loaded probes.
fn probe_health_loop(state: Arc<Mutex<ProbeState>>) {
    let count = state.lock().map(|s| s.probes.len()).unwrap_or(0);
    let mut last_checked: Vec<Option<std::time::Instant>> = vec![None; count];

    loop {
        let entries: Vec<(usize, ProbeEntry)> = {
            let Ok(s) = state.lock() else {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            };
            s.probes
                .iter()
                .enumerate()
                .map(|(i, ph)| (i, ph.entry.clone()))
                .collect()
        };

        for (idx, entry) in &entries {
            let interval = Duration::from_secs(entry.interval_secs);
            let should_check = match last_checked.get(*idx).copied().flatten() {
                Some(last) => last.elapsed() >= interval,
                None => true,
            };
            if !should_check {
                continue;
            }

            let result = run_probe(entry);
            if !result.healthy {
                eprintln!(
                    "mvm-guest-agent: probe '{}' failed: {}",
                    entry.name, result.detail
                );
            }
            if let Ok(mut s) = state.lock()
                && let Some(ph) = s.probes.get_mut(*idx)
            {
                ph.last_result = Some(result);
            }
            last_checked[*idx] = Some(std::time::Instant::now());
        }

        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Build probe reports from cached results.
fn build_probe_reports(probe_state: &Arc<Mutex<ProbeState>>) -> Vec<ProbeResult> {
    let Ok(s) = probe_state.lock() else {
        return vec![];
    };
    s.probes
        .iter()
        .filter_map(|ph| ph.last_result.clone())
        .collect()
}

// ============================================================================
// Length-prefixed frame I/O (mirrors vsock.rs protocol)
// ============================================================================

fn read_request(file: &mut std::fs::File) -> Option<GuestRequest> {
    let mut len_buf = [0u8; 4];
    if file.read_exact(&mut len_buf).is_err() {
        return None;
    }
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len > MAX_FRAME_SIZE {
        eprintln!("frame too large: {} bytes", frame_len);
        return None;
    }
    let mut buf = vec![0u8; frame_len];
    if file.read_exact(&mut buf).is_err() {
        return None;
    }
    serde_json::from_slice(&buf).ok()
}

fn write_response(file: &mut std::fs::File, resp: &GuestResponse) {
    let data = match serde_json::to_vec(resp) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("failed to serialize response: {}", e);
            return;
        }
    };
    let len = (data.len() as u32).to_be_bytes();
    if let Err(e) = file.write_all(&len) {
        eprintln!("failed to write vsock response: {e}");
    }
    if let Err(e) = file.write_all(&data) {
        eprintln!("failed to write vsock response: {e}");
    }
    if let Err(e) = file.flush() {
        eprintln!("failed to flush vsock response: {e}");
    }
}

// ============================================================================
// Request handlers
// ============================================================================

/// Sync filesystems and drop page cache.
fn do_sleep_prep() -> (bool, String) {
    // Sync all filesystems.
    let sync_ok = std::process::Command::new("sync")
        .status()
        .is_ok_and(|s| s.success());

    // Drop page cache (requires root, best-effort).
    let drop_ok = std::fs::write("/proc/sys/vm/drop_caches", "3").is_ok();

    if sync_ok && drop_ok {
        (true, "filesystems synced, page cache dropped".to_string())
    } else if sync_ok {
        (
            true,
            "filesystems synced, page cache drop failed (non-root?)".to_string(),
        )
    } else {
        (false, "sync failed".to_string())
    }
}

/// Process registry singleton — shared across all `ProcStart` /
/// `ProcWait` / etc. dispatches inside one agent process. Dev-only
/// (gated alongside `process_rpc`); the symbol is absent from prod
/// builds.
#[cfg(feature = "dev-shell")]
fn proc_registry() -> &'static mvm_guest::process_rpc::Registry {
    use std::sync::OnceLock;
    static REGISTRY: OnceLock<mvm_guest::process_rpc::Registry> = OnceLock::new();
    REGISTRY.get_or_init(mvm_guest::process_rpc::Registry::new)
}

/// `ProcWait` streaming arm — writes intermediate Stdout/Stderr
/// frames to the connection and returns the terminal event for the
/// dispatch loop to write last. Mirrors `handle_run_entrypoint`.
#[cfg(feature = "dev-shell")]
fn handle_proc_wait_streaming(
    file: &mut std::fs::File,
    pid_token: &str,
    timeout_secs: Option<u64>,
) -> mvm_guest::vsock::ProcWaitEvent {
    let caps = mvm_guest::process_rpc::Caps::production();
    let registry = proc_registry();
    mvm_guest::process_rpc::handle_proc_wait(registry, &caps, pid_token, timeout_secs, |ev| {
        write_response(file, &GuestResponse::ProcWaitEvent(ev));
    })
}

/// `Exec` streaming arm — writes intermediate `ExecEvent` Stdout/Stderr
/// frames to the connection and returns the terminal `Exit` or `TimedOut`
/// for the dispatch loop to write last. Mirrors `handle_run_entrypoint` /
/// `handle_proc_wait_streaming`. (dev-shell only)
#[cfg(feature = "dev-shell")]
fn do_exec_streaming(
    file: &mut std::fs::File,
    command: &str,
    stdin_data: Option<&str>,
    timeout_secs: Option<u64>,
) -> GuestResponse {
    let terminal = mvm_guest::exec_stream::stream_exec(command, stdin_data, timeout_secs, |ev| {
        write_response(file, &GuestResponse::ExecEvent(ev));
    });
    GuestResponse::ExecEvent(terminal)
}

/// Write one staged file to disk (creating parents, applying mode) before an
/// `ExecBatch` runs its commands. (dev-shell only)
#[cfg(feature = "dev-shell")]
fn stage_file_to_disk(s: &mvm_guest::vsock::StageFile) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = std::path::Path::new(&s.path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&s.path, &s.content)?;
    std::fs::set_permissions(&s.path, std::fs::Permissions::from_mode(s.mode))
}

/// `getrusage(RUSAGE_CHILDREN).ru_maxrss` (KiB on Linux): the high-water RSS
/// across reaped children — a cumulative peak proxy for the batch. `None` when
/// the call fails or reports nothing. (dev-shell only)
#[cfg(feature = "dev-shell")]
fn read_peak_rss_kib() -> Option<u64> {
    // SAFETY: getrusage only writes the provided rusage struct.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) };
    (rc == 0 && usage.ru_maxrss > 0).then_some(usage.ru_maxrss as u64)
}

/// `ExecBatch` arm (dev-shell only): stage every file, then run each argv
/// command buffered (stop at the first non-zero exit), returning one
/// `ExecOutcomeWire` per command run. One round-trip, no streaming.
#[cfg(feature = "dev-shell")]
fn do_exec_batch(
    stages: &[mvm_guest::vsock::StageFile],
    commands: &[Vec<String>],
    timeout_secs: Option<u64>,
) -> GuestResponse {
    use mvm_guest::vsock::{ExecEvent, ExecOutcomeWire};
    for s in stages {
        if let Err(e) = stage_file_to_disk(s) {
            return GuestResponse::Error {
                message: format!("exec-batch staging {} failed: {e}", s.path),
            };
        }
    }
    let mut outcomes = Vec::new();
    for argv in commands {
        let command = argv
            .iter()
            .map(|a| shell_quote_for_sh(a))
            .collect::<Vec<_>>()
            .join(" ");
        let start = std::time::Instant::now();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let terminal =
            mvm_guest::exec_stream::stream_exec(&command, None, timeout_secs, |ev| match ev {
                ExecEvent::Stdout { chunk } => stdout.extend_from_slice(&chunk),
                ExecEvent::Stderr { chunk } => stderr.extend_from_slice(&chunk),
                _ => {}
            });
        let status = match terminal {
            ExecEvent::Exit { code } => code,
            ExecEvent::TimedOut => 124,
            _ => -1,
        };
        outcomes.push(ExecOutcomeWire {
            status,
            stdout,
            stderr,
            duration_ms: start.elapsed().as_millis() as u64,
            peak_rss_kib: read_peak_rss_kib(),
        });
        if status != 0 {
            break;
        }
    }
    GuestResponse::ExecBatchResult { outcomes }
}

/// Read the wrapper's language from `/etc/mvm/wrapper.json`. Returns
/// `None` if the file is missing, unparseable, or the field is
/// absent — caller treats that as "language unknown, refuse the
/// `RunCode` call rather than guess".
#[cfg(feature = "dev-shell")]
fn read_wrapper_language() -> Option<String> {
    let raw = std::fs::read_to_string("/etc/mvm/wrapper.json").ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get("language")?.as_str().map(str::to_owned)
}

/// Stateless run-code v1: dispatch a fresh interpreter subprocess
/// with the user-supplied source on its `-c` / `-e` arg. Refuses
/// unknown languages with a wire-stable error string. Streams output
/// via `do_exec_streaming`.
///
/// A future v2 will route through the warm-process pool instead,
/// providing stateful eval across calls. Wire shape stays identical —
/// the dispatch flips inside this function.
#[cfg(feature = "dev-shell")]
fn do_run_code(file: &mut std::fs::File, code: &str, timeout_secs: Option<u64>) -> GuestResponse {
    let lang = match read_wrapper_language() {
        Some(l) => l,
        None => {
            write_response(
                file,
                &GuestResponse::ExecEvent(mvm_guest::vsock::ExecEvent::Stderr {
                    chunk: b"run-code refused: /etc/mvm/wrapper.json missing or has no \
                         language field"
                        .to_vec(),
                }),
            );
            return GuestResponse::ExecEvent(mvm_guest::vsock::ExecEvent::Exit { code: -1 });
        }
    };
    let interpreter = match lang.as_str() {
        "python" => "python3",
        "node" => "node",
        other => {
            write_response(
                file,
                &GuestResponse::ExecEvent(mvm_guest::vsock::ExecEvent::Stderr {
                    chunk: format!(
                        "run-code refused: unsupported language {:?} \
                     (supported: python, node)",
                        other
                    )
                    .into_bytes(),
                }),
            );
            return GuestResponse::ExecEvent(mvm_guest::vsock::ExecEvent::Exit { code: -1 });
        }
    };
    // Build the shell command. Single-quote the code so the shell
    // doesn't expand `$VAR` / backticks inside it; embedded single
    // quotes get the close-quote-escape-reopen treatment.
    let interp_flag = if interpreter == "node" { "-e" } else { "-c" };
    let shell_command = format!(
        "{} {} {}",
        interpreter,
        interp_flag,
        shell_quote_for_sh(code)
    );
    do_exec_streaming(file, &shell_command, None, timeout_secs)
}

/// Single-quote `s` for `/bin/sh` consumption: doubles up embedded
/// `'` as `'\''` (close-quote, escaped-quote, re-open). Mirrors
/// `mvm_cli::commands::vm::session::shell_quote` — duplicated here
/// rather than depending on mvm-cli to keep the agent's dependency
/// surface lean.
#[cfg(feature = "dev-shell")]
fn shell_quote_for_sh(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

// ============================================================================
// RunEntrypoint handler.
//
// Boot-time validates `/etc/mvm/entrypoint`, holds the resolved fd open in a
// `OnceLock` for the agent's lifetime, and serializes per-VM concurrency
// through a mutex. Each call gets its own TMPDIR (mode 0700, removed on
// drop) so transient state never leaks between calls.
//
// The handler writes Stdout and Stderr events directly to the vsock stream
// and returns the terminal Exit/Error event for the caller's
// `write_response` to send. Net-effect for v1: three vsock frames per call
// (one Stdout, one Stderr, one terminal). v2 may chunk progressively
// without changing the wire shape — the host already reads frames in a
// loop until `is_terminal()`.
// ============================================================================

/// Validation result captured once at boot. The held `ValidatedEntrypoint`
/// keeps an open file handle to the wrapper binary so spawn-time uses
/// `/proc/self/fd/<n>` (Linux) instead of re-resolving the path, defeating
/// any TOCTOU between validation and spawn.
static VALIDATED_ENTRYPOINT: OnceLock<Result<ValidatedEntrypoint, String>> = OnceLock::new();

/// One in-flight `RunEntrypoint` per VM — applies to the cold
/// path only. When `WARM_POOL.is_some()`, this lock is bypassed; the
/// new invariant is "one in-flight call per worker, ≤ `pool_size`
/// concurrent". Concurrent callers under cold-tier still
/// get `EntrypointEvent::Error { kind: Busy }` immediately; warm-tier
/// callers queue FIFO up to `max_queue_depth` and get `Busy` on
/// overflow.
static RUN_ENTRYPOINT_LOCK: Mutex<()> = Mutex::new(());

/// Warm-process worker pool, populated at boot from
/// `/etc/mvm/runtime.json`. `None` means cold-tier
/// behavior — the existing single-call path. `Some(_)` activates
/// the warm-process branch in `handle_run_entrypoint` and the
/// thread-per-connection accept-loop.
static WARM_POOL: OnceLock<Option<Arc<WorkerPool>>> = OnceLock::new();

// ============================================================================
// Signal handling.
//
// On SIGTERM / SIGINT, the agent flips `SHUTDOWN_REQUESTED` (atomic
// store, async-signal-safe). The accept loop polls the flag at
// each iteration and after every `accept()` return (signals deliver
// `EINTR` to the syscall, which already triggers the loop's
// continue path). Once the flag flips, the loop breaks and
// `shutdown_subsystems` runs:
//   1. Sets the warm-process pool's shutdown atomic so new
//      dispatches refuse fast-fail.
//   2. SIGTERMs/SIGKILLs idle workers via `WorkerPool::shutdown`.
//   3. Sleeps a configurable grace so in-flight calls drain.
//
// A second SIGTERM/SIGINT during drain calls `_exit(128 + signo)`
// directly so a wedged drain doesn't strand operators. `_exit` is
// async-signal-safe; nothing else in the handler needs to be
// (the pool drain happens after the loop, in a normal Rust
// context).
//
// The handler itself does only atomic stores and (on second signal)
// `_exit`. It does not allocate, lock, or call any non-async-
// signal-safe libc routine — see `man 7 signal-safety`.
// ============================================================================

/// Set on first SIGTERM/SIGINT. The accept loop polls this and
/// breaks when it flips.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Process-resident VMGenID reseeder. Seeded with the all-zero baseline so the
/// first non-zero token delivered on a `PostRestore` resume counts as a
/// clone-divergence and reseeds the CSPRNG. The reseeder's state rides the VM
/// memory snapshot, so two clones restored from one snapshot both diverge from
/// the captured value when the host hands each a distinct fresh token.
static GENID_RESEEDER: Mutex<mvm_guest::genid::GenIdReseeder> = Mutex::new(
    mvm_guest::genid::GenIdReseeder::new([0u8; mvm_core::crypto::vmgenid::GENID_BYTES]),
);

/// Dispatch a token delivered on `PostRestore` to the resident reseeder. A
/// poisoned lock degrades to "no rotation" rather than panicking the handler —
/// the remount/restart work still needs to run.
fn reseed_on_post_restore(
    token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
) -> mvm_guest::genid::GenIdAction {
    match GENID_RESEEDER.lock() {
        Ok(mut r) => r.on_post_restore_token(token),
        Err(_) => mvm_guest::genid::GenIdAction::Unchanged,
    }
}

/// Counts shutdown signals delivered. ≥2 means the operator has
/// asked twice — escalate to `_exit` and skip the drain.
static SHUTDOWN_SIGNAL_COUNT: AtomicU8 = AtomicU8::new(0);

/// Set by `on_reload_signal` (SIGHUP). The accept loop polls this
/// between iterations and, when set, re-reads
/// the config file and applies the hot-reloadable subset.
/// Distinct from `SHUTDOWN_REQUESTED` so a reload doesn't terminate
/// the agent.
static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Path of the config file the agent loaded at boot. Captured by
/// `parse_config` so the SIGHUP handler can re-read the same file
/// even when the operator launched with `--config <path>`.
static AGENT_CONFIG_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Current value of the busy threshold (f64 bits) seen by the
/// monitoring loop. Updated atomically by `apply_reload`.
static HOT_BUSY_THRESHOLD_BITS: AtomicU64 = AtomicU64::new(0);

/// Current sample interval in seconds, updated atomically by
/// `apply_reload`. Initialized to a sane default until main() runs.
static HOT_SAMPLE_INTERVAL_SECS: AtomicU64 = AtomicU64::new(DEFAULT_SAMPLE_INTERVAL_SECS);

/// Default grace period for `shutdown_subsystems` to wait between
/// "shut down requested" and forcing exit. Mirrors the cold-path
/// `CallCaps::v1().kill_grace_period * 2 + slack` so a typical
/// in-flight call has time to finish + the worker pool can SIGTERM
/// → grace → SIGKILL idle workers cleanly.
const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// SIGTERM/SIGINT handler. Async-signal-safe — only atomic stores
/// and (on repeat-signal) `_exit`. Never allocates, never locks.
///
/// First signal: flip `SHUTDOWN_REQUESTED`. The accept loop in
/// `main` observes the flag and runs `shutdown_subsystems`.
///
/// Second signal: `_exit(128 + signo)`. POSIX convention for
/// signal-killed processes; matches what bash sees as the process
/// exit code.
unsafe extern "C" fn on_shutdown_signal(sig: libc::c_int) {
    let prior = SHUTDOWN_SIGNAL_COUNT.fetch_add(1, Ordering::AcqRel);
    if prior >= 1 {
        // Operator's second SIGTERM/SIGINT — bail out without
        // waiting for any drain. `_exit` is async-signal-safe.
        // SAFETY: libc call with a valid status integer.
        unsafe {
            libc::_exit(128 + sig);
        }
    }
    SHUTDOWN_REQUESTED.store(true, Ordering::Release);
}

/// SIGHUP handler.
///
/// Flips `RELOAD_REQUESTED`. The accept loop polls it between
/// iterations and, when set, calls `apply_reload` to re-read the
/// config file and update the hot-reloadable atomics. Unlike
/// the shutdown handler, this does NOT escalate on repeat — each
/// SIGHUP triggers a fresh reload.
///
/// Async-signal-safe — only an atomic store.
unsafe extern "C" fn on_reload_signal(_sig: libc::c_int) {
    RELOAD_REQUESTED.store(true, Ordering::Release);
}

/// Install handlers for SIGTERM and SIGINT. Best-effort: if
/// `sigaction` fails for any reason, the agent logs and continues
/// — graceful drain is a nice-to-have, not load-bearing. On a
/// microVM lifecycle the handler usually never fires anyway because
/// the kernel teardown is abrupt; the handler matters when an
/// operator manually `kill -TERM`s the agent or when in-place
/// updates land later.
///
/// `#[inline(never)]` is load-bearing for the symbol-contract
/// gate (`scripts/check-prod-agent-no-exec.sh`) which asserts
/// this symbol is present as positive evidence the handlers are
/// wired in. Mirrors the same pattern on `handle_run_entrypoint`
/// and `dispatch_via_warm_pool`.
#[inline(never)]
fn install_signal_handlers() {
    // SAFETY: zeroed sigaction is the documented "use defaults"
    // sentinel. We populate sa_sigaction (handler), sa_mask (no
    // signals blocked during handler), and leave sa_flags = 0
    // (default disposition: restart syscalls handled by libc, but
    // we deliberately want EINTR on accept).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_shutdown_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        // sa_flags = 0: do NOT set SA_RESTART. The accept syscall
        // returns EINTR when a signal lands, which is exactly how
        // we want the loop to wake up.
        let term_rc = libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        let int_rc = libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        if term_rc != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("mvm-guest-agent: sigaction(SIGTERM) failed: {err}");
        }
        if int_rc != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("mvm-guest-agent: sigaction(SIGINT) failed: {err}");
        }

        // SIGHUP handler. Separate sigaction because the
        // dispositions differ: SIGHUP should NOT escalate on
        // repeat (each delivery triggers a fresh reload).
        let mut sa_hup: libc::sigaction = std::mem::zeroed();
        sa_hup.sa_sigaction = on_reload_signal as *const () as usize;
        libc::sigemptyset(&mut sa_hup.sa_mask);
        let hup_rc = libc::sigaction(libc::SIGHUP, &sa_hup, std::ptr::null_mut());
        if hup_rc != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("mvm-guest-agent: sigaction(SIGHUP) failed: {err}");
        }
    }
}

/// Re-read the agent config file and apply the hot-reloadable
/// subset to live atomics. Called from the accept loop when
/// `RELOAD_REQUESTED` is set (SIGHUP). Never terminates the agent;
/// reload errors log and continue with the
/// prior values.
///
/// ## Reload-safety review
///
/// `AgentConfig` carries three fields. The decisions are:
///
/// - `port: u32` — **NOT reloadable.** Changing it would require
///   re-binding the listening socket, which would terminate every
///   live vsock connection. Operator must restart the agent.
/// - `busy_threshold: f64` — **reloadable.** Read every monitoring
///   loop iteration via `HOT_BUSY_THRESHOLD_BITS`.
/// - `sample_interval_secs: u64` — **reloadable.** Read every
///   monitoring loop iteration via `HOT_SAMPLE_INTERVAL_SECS`.
///
/// A reload that changes `port` logs a warning and leaves the
/// running port in place. Future hot-reloadable fields extend this
/// function; non-reloadable ones inherit the warning pattern.
pub(crate) fn apply_reload() {
    let Some(path) = AGENT_CONFIG_PATH.get() else {
        eprintln!("mvm-guest-agent: reload skipped — config path not captured");
        return;
    };
    let data = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "mvm-guest-agent: reload skipped — failed to read {}: {e}",
                path.display()
            );
            return;
        }
    };
    let new_cfg = match serde_json::from_str::<AgentConfig>(&data) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "mvm-guest-agent: reload skipped — failed to parse {}: {e}",
                path.display()
            );
            return;
        }
    };
    apply_reload_to_atomics(&new_cfg);
}

/// Test seam — applies a parsed config to the hot atomics without
/// touching the filesystem. Production wraps this through
/// [`apply_reload`].
fn apply_reload_to_atomics(new_cfg: &AgentConfig) {
    // Compare to the current values so we log meaningful diffs.
    let cur_thresh = f64::from_bits(HOT_BUSY_THRESHOLD_BITS.load(Ordering::Acquire));
    let cur_interval = HOT_SAMPLE_INTERVAL_SECS.load(Ordering::Acquire);

    if (new_cfg.busy_threshold - cur_thresh).abs() > f64::EPSILON {
        HOT_BUSY_THRESHOLD_BITS.store(new_cfg.busy_threshold.to_bits(), Ordering::Release);
        eprintln!(
            "mvm-guest-agent: reload — busy_threshold {cur_thresh} → {}",
            new_cfg.busy_threshold
        );
    }
    if new_cfg.sample_interval_secs != cur_interval {
        HOT_SAMPLE_INTERVAL_SECS.store(new_cfg.sample_interval_secs, Ordering::Release);
        eprintln!(
            "mvm-guest-agent: reload — sample_interval_secs {cur_interval} → {}",
            new_cfg.sample_interval_secs
        );
    }
    // `port` is not reloadable. The accept socket is already bound;
    // changing it would terminate live connections. Log if it
    // changed so the operator knows a restart is needed.
    //
    // We can't compare against the live port (it isn't stored in a
    // hot atomic — that would imply it's hot-reloadable, which it
    // isn't). Instead the warning fires unconditionally when the
    // file's port differs from the default, on the theory that an
    // operator who edited the config wants to know it didn't take.
    if new_cfg.port != default_port() {
        eprintln!(
            "mvm-guest-agent: reload — port={} on disk; the running agent \
             keeps its boot-time port (restart to apply)",
            new_cfg.port
        );
    }
}

/// Drain all subsystems before exiting. Currently the only one
/// that benefits from a graceful shutdown is the warm-process
/// pool (cold-tier `RunEntrypoint` calls hold no long-lived
/// resources). Adding more drains here is the natural extension
/// point if future additions (snapshot finalization, integration
/// teardown) want orderly exit.
fn shutdown_subsystems(grace: Duration) {
    eprintln!("mvm-guest-agent: shutdown requested; draining for up to {grace:?}");
    // Run the workload's baked `before_stop.sh` hook *before*
    // tearing down the worker
    // pool so the hook can still see live workers (e.g. to flush
    // application state through them). Best-effort: missing script /
    // non-zero exit / grace overrun all log + continue. SIGKILL on
    // the agent itself bypasses this entire path by design.
    run_before_stop_hook();
    if let Some(Some(pool)) = WARM_POOL.get() {
        pool.shutdown(grace);
    }
    eprintln!("mvm-guest-agent: drain complete; exiting");
}

/// Fire the baked `before_stop.sh` hook with the configured grace
/// deadline. Log-only: shutdown continues regardless of outcome. The
/// Nix factory always bakes this script (no-op `:` body when no
/// commands declared), but we treat `ScriptMissing` as success so a
/// half-assembled rootfs doesn't wedge teardown.
fn run_before_stop_hook() {
    match lifecycle_hooks::run_shutdown_hook(
        Path::new(BEFORE_STOP_HOOK),
        SHUTDOWN_HOOK_GRACE,
        SHUTDOWN_HOOK_POLL,
    ) {
        Ok(()) => {
            eprintln!("mvm-guest-agent: before_stop hook completed cleanly");
        }
        Err(lifecycle_hooks::ShutdownError::ScriptMissing { script }) => {
            eprintln!(
                "mvm-guest-agent: before_stop hook `{}` not present; nothing to run",
                script.display()
            );
        }
        Err(e) => {
            eprintln!("mvm-guest-agent: before_stop hook failed (continuing shutdown): {e}");
        }
    }
}

/// Validate `/etc/mvm/entrypoint` at agent boot. The result is stashed in
/// `VALIDATED_ENTRYPOINT`. On failure, log a single line — the agent stays
/// up; only `RunEntrypoint` requests fail with `EntrypointInvalid`.
///
/// Also updates `AgentBootState.entrypoint` so `ReadinessStatus`
/// reports `Ready` (or `Failed { message }`) and stamps
/// `entrypoint_ready_ms` for cold-path timing.
fn init_entrypoint_validation(boot_state: &Arc<AgentBootState>) {
    let result = match EntrypointPolicy::production().validate() {
        Ok(v) => {
            eprintln!(
                "mvm-guest-agent: entrypoint validated at {} (held open for fexecve)",
                v.resolved.display()
            );
            boot_state.set_entrypoint(ComponentState::Ready);
            Ok(v)
        }
        Err(e) if e.is_entrypoint_not_offered() => {
            // Boot-script image: the entrypoint is baked as PID 1's boot
            // command, not a per-call wrapper under /usr/lib/mvm/wrappers/.
            // RunEntrypoint is simply not offered here — a clean state, not a
            // failure (the default/sealed-idle image and every command/shell
            // image today). Reported as `Disabled`, logged calmly.
            eprintln!(
                "mvm-guest-agent: no per-call entrypoint wrapper baked; \
                 RunEntrypoint not offered for this image"
            );
            boot_state.set_entrypoint(ComponentState::Disabled);
            Err("this image does not offer a per-call entrypoint (RunEntrypoint)".to_string())
        }
        Err(e) => {
            let msg = e.to_string();
            eprintln!(
                "mvm-guest-agent: entrypoint validation failed at boot: {msg}; \
                 RunEntrypoint requests will return EntrypointInvalid"
            );
            boot_state.set_entrypoint(ComponentState::Failed {
                message: msg.clone(),
            });
            Err(msg)
        }
    };
    let _ = VALIDATED_ENTRYPOINT.set(result);
}

/// Read `/etc/mvm/runtime.json` and, if it carries `concurrency.kind
/// = "warm_process"`, stand up the worker pool.
///
/// Failure modes are deliberately fail-loud — mvmforge owns
/// `runtime.json`, so a malformed file or rejected `in_process` mode
/// is a build bug, not a runtime fallback. The agent exits non-zero
/// rather than silently dropping to cold tier and confusing
/// observers about which tier is active.
///
/// Missing `runtime.json` or absent `concurrency` → `Ok(None)`, the
/// cold path stays in charge.
///
/// Runs in the boot-time background thread chained after
/// `init_entrypoint_validation`. Updates
/// `AgentBootState.warm_pool` (`Disabled` for cold-tier images,
/// `Starting` → `Ready` for warm-pool, `Failed` on entrypoint
/// dependency failure). Process-exit-on-bad-config is preserved —
/// `runtime.json` is part of the immutable image and a malformed
/// file is a build bug.
fn init_warm_pool(boot_state: &Arc<AgentBootState>) {
    let result: Option<Arc<WorkerPool>> = match runtime_config::load() {
        Ok(None) => {
            boot_state.set_warm_pool(ComponentState::Disabled);
            None
        }
        Ok(Some(rc)) => match rc.concurrency {
            None => {
                boot_state.set_warm_pool(ComponentState::Disabled);
                None
            }
            Some(ConcurrencyConfig::WarmProcess(wp)) => {
                boot_state.set_warm_pool(ComponentState::Starting);
                match VALIDATED_ENTRYPOINT.get() {
                    Some(Ok(entry)) => match entry.try_clone() {
                        Ok(cloned) => match WorkerPool::start(wp, Arc::new(cloned), Vec::new()) {
                            Ok(pool) => {
                                // Run the baked `after_start.sh`
                                // readiness probe before
                                // letting traffic in. Pool starts in
                                // `NotReady`; `wait_for_ready` flips it
                                // on success, leaves it `NotReady` on
                                // timeout/exec error so subsequent
                                // dispatches fast-fail with `NotReady`
                                // (host surface: Busy + "warming up"
                                // message) rather than hitting an
                                // unwarmed wrapper.
                                wait_for_after_start(&pool);
                                boot_state.set_warm_pool(ComponentState::Ready);
                                Some(pool)
                            }
                            Err(e) => {
                                eprintln!(
                                    "mvm-guest-agent: warm-process pool start failed: {e}; refusing to boot"
                                );
                                std::process::exit(1);
                            }
                        },
                        Err(e) => {
                            eprintln!(
                                "mvm-guest-agent: warm-process configured but entrypoint clone failed: {e}; refusing to boot"
                            );
                            std::process::exit(1);
                        }
                    },
                    _ => {
                        // Entrypoint validation failed; surface a
                        // matching warm-pool failure rather than
                        // process-exit. Keep the control plane up so
                        // `ReadinessStatus` can report both failures
                        // together.
                        boot_state.set_warm_pool(ComponentState::Failed {
                            message: "entrypoint validation failed".to_string(),
                        });
                        None
                    }
                }
            }
        },
        Err(e) => {
            eprintln!("mvm-guest-agent: invalid /etc/mvm/runtime.json: {e}; refusing to boot");
            std::process::exit(1);
        }
    };
    let _ = WARM_POOL.set(result);
}

/// Run the baked `after_start.sh` readiness probe and gate the
/// worker pool's traffic spigot on its success.
///
/// - On success (or absent script: workload declared no after_start
///   hook), the pool flips to ready and dispatch starts accepting
///   invokes.
/// - On timeout / exec error, the pool stays `NotReady`. The agent
///   keeps the vsock listener up — operators get a host-visible log
///   line + every dispatch returns `Busy` with a "warming up"
///   message. Better than silently dispatching to an unready
///   workload.
fn wait_for_after_start(pool: &Arc<WorkerPool>) {
    let cfg = ReadinessConfig::new(AFTER_START_HOOK)
        .with_timeout(READINESS_TIMEOUT)
        .with_interval(READINESS_INTERVAL);
    match pool.wait_for_ready(&cfg) {
        Ok(()) => {
            eprintln!(
                "mvm-guest-agent: warm-process pool ready (after_start probe `{AFTER_START_HOOK}` ok)"
            );
        }
        Err(e) => {
            eprintln!(
                "mvm-guest-agent: warm-process pool not ready — after_start probe failed: {e}; \
                 dispatches will surface NotReady until manual intervention"
            );
        }
    }
}

/// Scan `/etc/mvm/integrations.d/*.json`, populate
/// `integration_state` with the discovered entries, and spawn the
/// health-check loop iff at least one integration was loaded. Runs
/// on its own background thread so a slow or malformed drop-in
/// cannot delay the accept loop.
///
/// Transitions in `AgentBootState`:
///   `Starting` → `Ready`    (≥ 1 integration loaded; health loop spawned)
///   `Starting` → `Disabled` (no integrations declared)
///
/// `Failed` is not currently produced — `load_dropin_dir` is
/// best-effort per-file (a malformed JSON file is skipped with a
/// stderr log; the rest still load). That upholds the invariant
/// that a malformed integration drop-in does not kill control-plane
/// readiness.
fn init_integrations(
    boot_state: &Arc<AgentBootState>,
    integration_state: &Arc<Mutex<IntegrationState>>,
) {
    boot_state.set_integrations(ComponentState::Starting);
    let entries = integrations::load_dropin_dir(integrations::INTEGRATIONS_DROPIN_DIR);
    let count = entries.len();
    if let Ok(mut s) = integration_state.lock() {
        s.integrations = entries
            .into_iter()
            .map(|e| IntegrationHealth {
                entry: e,
                last_result: None,
            })
            .collect();
    }
    if count > 0 {
        boot_state.set_integrations(ComponentState::Ready);
        let health_state = Arc::clone(integration_state);
        std::thread::spawn(move || integration_health_loop(health_state));
    } else {
        boot_state.set_integrations(ComponentState::Disabled);
    }
}

/// Scan `/etc/mvm/probes.d/*.json`, populate `probe_state` with the
/// discovered entries, and spawn the probe loop iff at least one
/// probe was loaded. Mirrors `init_integrations`.
fn init_probes(boot_state: &Arc<AgentBootState>, probe_state: &Arc<Mutex<ProbeState>>) {
    boot_state.set_probes(ComponentState::Starting);
    let entries = probes::load_probe_dropin_dir(probes::PROBES_DROPIN_DIR);
    let count = entries.len();
    if let Ok(mut s) = probe_state.lock() {
        s.probes = entries
            .into_iter()
            .map(|e| ProbeHealth {
                entry: e,
                last_result: None,
            })
            .collect();
    }
    if count > 0 {
        boot_state.set_probes(ComponentState::Ready);
        let health_state = Arc::clone(probe_state);
        std::thread::spawn(move || probe_health_loop(health_state));
    } else {
        boot_state.set_probes(ComponentState::Disabled);
    }
}

/// Generate a per-call TMPDIR path under /tmp. The mutex guarantees only
/// one in-flight call per VM, so a name collision is exceedingly unlikely
/// — but use pid + nanos anyway to survive any post-crash leftovers.
fn make_call_tmpdir() -> std::io::Result<CallTmpdir> {
    use std::os::unix::fs::DirBuilderExt;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let path = PathBuf::from(format!("/tmp/mvm-call-{pid}-{nanos:x}"));
    std::fs::DirBuilder::new().mode(0o700).create(&path)?;
    Ok(CallTmpdir { path })
}

/// RAII wrapper that removes the TMPDIR on drop. The cleanup runs from the
/// agent — robust to wrapper crashes, kills, and any panic on the agent's
/// own side.
struct CallTmpdir {
    path: PathBuf,
}

impl CallTmpdir {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CallTmpdir {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.path) {
            eprintln!(
                "mvm-guest-agent: TMPDIR cleanup failed for {}: {e}",
                self.path.display()
            );
        }
    }
}

/// Wrap an `EntrypointEvent` in a `GuestResponse` for vsock framing.
fn evt(e: EntrypointEvent) -> GuestResponse {
    GuestResponse::EntrypointEvent(e)
}

/// Handle a `RunEntrypoint` request. Writes streaming events directly via
/// `write_response` and returns the terminal event for the dispatcher to
/// send through the existing `match` arm pattern.
///
/// `#[inline(never)]` is load-bearing for the symbol-contract gate.
/// LTO inlines functions called from a single site, which would erase
/// the `mvm_guest_agent::handle_run_entrypoint` symbol from `nm`
/// output even though the handler is logically compiled in. The gate
/// (`scripts/check-prod-agent-no-exec.sh`) requires the symbol to be
/// present as positive evidence that the handler is wired up. Without
/// `inline(never)` the gate fails on every prod build. Cost: one
/// extra call boundary in a slow-path RPC handler — imperceptible.
#[inline(never)]
fn handle_run_entrypoint(
    file: &mut std::fs::File,
    stdin: Vec<u8>,
    timeout_secs: u64,
    env: Vec<(String, String)>,
) -> GuestResponse {
    // When a warm-process pool is active, route through it instead
    // of the cold-respawn path. The host wire is identical;
    // the pool's `dispatch` synthesizes the same `EntrypointEvent`
    // stream (Stdout / Stderr / Exit | Error) we'd produce below.
    if let Some(Some(pool)) = WARM_POOL.get() {
        return dispatch_via_warm_pool(file, pool, stdin, timeout_secs, env);
    }

    let _guard = match RUN_ENTRYPOINT_LOCK.try_lock() {
        Ok(g) => g,
        Err(_) => {
            return evt(EntrypointEvent::Error {
                kind: RunEntrypointError::Busy,
                message: "another RunEntrypoint call is in flight".into(),
            });
        }
    };

    let entrypoint = match VALIDATED_ENTRYPOINT.get() {
        Some(Ok(e)) => e,
        Some(Err(msg)) => {
            return evt(EntrypointEvent::Error {
                kind: RunEntrypointError::EntrypointInvalid,
                message: msg.clone(),
            });
        }
        None => {
            return evt(EntrypointEvent::Error {
                kind: RunEntrypointError::EntrypointInvalid,
                message: "entrypoint validation never ran".into(),
            });
        }
    };

    let tmpdir = match make_call_tmpdir() {
        Ok(t) => t,
        Err(e) => {
            return evt(EntrypointEvent::Error {
                kind: RunEntrypointError::InternalError,
                message: format!("create per-call TMPDIR: {e}"),
            });
        }
    };

    let outcome = execute(
        entrypoint,
        tmpdir.path(),
        &stdin,
        Duration::from_secs(timeout_secs),
        CallCaps::v1(),
        env,
    );

    // tmpdir drops at end of scope (or on early-return below) and runs
    // its `Drop` cleanup.
    match outcome {
        CallOutcome::Exited {
            code,
            stdout,
            stderr,
            controls,
        } => {
            write_response(file, &evt(EntrypointEvent::Stdout { chunk: stdout }));
            write_response(file, &evt(EntrypointEvent::Stderr { chunk: stderr }));
            emit_controls(file, controls);
            evt(EntrypointEvent::Exit { code })
        }
        CallOutcome::Timeout {
            stdout,
            stderr,
            controls,
        } => {
            write_response(file, &evt(EntrypointEvent::Stdout { chunk: stdout }));
            write_response(file, &evt(EntrypointEvent::Stderr { chunk: stderr }));
            emit_controls(file, controls);
            evt(EntrypointEvent::Error {
                kind: RunEntrypointError::Timeout,
                message: format!("wrapper exceeded {timeout_secs}s timeout"),
            })
        }
        CallOutcome::PayloadCap {
            stream,
            stdout,
            stderr,
            controls,
        } => {
            write_response(file, &evt(EntrypointEvent::Stdout { chunk: stdout }));
            write_response(file, &evt(EntrypointEvent::Stderr { chunk: stderr }));
            emit_controls(file, controls);
            let stream_name = match stream {
                PayloadCapStream::Stdin => "stdin",
                PayloadCapStream::Stdout => "stdout",
                PayloadCapStream::Stderr => "stderr",
            };
            evt(EntrypointEvent::Error {
                kind: RunEntrypointError::PayloadCap,
                message: format!("{stream_name} exceeded its cap"),
            })
        }
        CallOutcome::SpawnFailed { message } => evt(EntrypointEvent::Error {
            kind: RunEntrypointError::InternalError,
            message,
        }),
        CallOutcome::WrapperCrashed {
            signal,
            stdout,
            stderr,
            controls,
        } => {
            write_response(file, &evt(EntrypointEvent::Stdout { chunk: stdout }));
            write_response(file, &evt(EntrypointEvent::Stderr { chunk: stderr }));
            emit_controls(file, controls);
            evt(EntrypointEvent::Error {
                kind: RunEntrypointError::WrapperCrashed,
                message: format!("wrapper exited via signal {signal}"),
            })
        }
    }
}

/// Emit each fd-3 control record as one `EntrypointEvent::Control`
/// frame on the response stream. The cold-path counterpart to the
/// wrapper's own control emission. v1 emits all records after stdout
/// and stderr; the host already accepts non-terminal events in any
/// order before the terminal `Exit` / `Error`.
fn emit_controls(file: &mut std::fs::File, records: Vec<mvm_guest::entrypoint::ControlRecord>) {
    for r in records {
        write_response(
            file,
            &evt(EntrypointEvent::Control {
                header_json: r.header_json,
                payload: r.payload,
            }),
        );
    }
}

/// Route a `RunEntrypoint` request through the warm-process worker
/// pool. The pool's `dispatch` returns a single
/// `DispatchOutcome` per call (one buffered frame), which we
/// translate back into the existing host-facing `EntrypointEvent`
/// stream — same wire shape as the cold path so `mvmctl invoke` is
/// unaffected.
///
/// `#[inline(never)]` is load-bearing for the symbol-contract gate
/// (mirrors the `handle_run_entrypoint` symbol invariant). The CI
/// gate at `scripts/check-prod-agent-no-exec.sh`
/// requires this symbol to be present on the same binary that
/// ships, as positive evidence the warm-process substrate is
/// wired in. Without `inline(never)` LTO would erase it from the
/// `nm` output.
#[inline(never)]
fn dispatch_via_warm_pool(
    file: &mut std::fs::File,
    pool: &Arc<WorkerPool>,
    stdin: Vec<u8>,
    timeout_secs: u64,
    env: Vec<(String, String)>,
) -> GuestResponse {
    match pool.dispatch(stdin, timeout_secs, env) {
        Ok(DispatchOutcome {
            stdout,
            stderr,
            controls,
            outcome,
        }) => {
            write_response(file, &evt(EntrypointEvent::Stdout { chunk: stdout }));
            write_response(file, &evt(EntrypointEvent::Stderr { chunk: stderr }));
            emit_controls(file, controls);
            match outcome {
                WorkerOutcome::Exit { code } => evt(EntrypointEvent::Exit { code }),
                WorkerOutcome::Error { kind, message } => evt(EntrypointEvent::Error {
                    kind: map_worker_error_kind(&kind),
                    message,
                }),
            }
        }
        Err(DispatchError::QueueFull) => evt(EntrypointEvent::Error {
            kind: RunEntrypointError::Busy,
            message: "warm-process pool queue is full".into(),
        }),
        Err(DispatchError::ShuttingDown) => evt(EntrypointEvent::Error {
            kind: RunEntrypointError::InternalError,
            message: "warm-process pool is shutting down".into(),
        }),
        Err(DispatchError::NoLiveWorkers) => evt(EntrypointEvent::Error {
            kind: RunEntrypointError::InternalError,
            message: "warm-process pool has no live workers".into(),
        }),
        // after_start readiness probe has not yet succeeded —
        // workload is still warming up. Surface as Busy
        // so the host's retry semantics apply (same as queue-full);
        // the message distinguishes the cause for operators.
        Err(DispatchError::NotReady) => evt(EntrypointEvent::Error {
            kind: RunEntrypointError::Busy,
            message: "warm-process pool warming up (after_start probe not yet ready)".into(),
        }),
    }
}

fn map_worker_error_kind(kind: &str) -> RunEntrypointError {
    match kind {
        "wrapper_crash" => RunEntrypointError::WrapperCrashed,
        "timeout" => RunEntrypointError::Timeout,
        _ => RunEntrypointError::InternalError,
    }
}

/// Collect filesystem changes by walking the overlay upper directory.
///
/// When the rootfs is mounted read-only with an overlay (squashfs + tmpfs),
/// all writes go to the upper dir (typically /overlay/upper). Walking it
/// reveals every file created or modified since boot.
///
/// Falls back to an empty list if the overlay dir doesn't exist (non-overlay
/// rootfs or unrestricted mode).
fn collect_fs_diff() -> Vec<FsChange> {
    // Common overlay upper dir paths
    let upper_dirs = ["/overlay/upper", "/run/overlay/upper", "/tmp/overlay/upper"];
    let upper = upper_dirs.iter().find(|p| std::path::Path::new(p).is_dir());

    let Some(upper_dir) = upper else {
        return Vec::new();
    };

    let mut changes = Vec::new();
    walk_dir(std::path::Path::new(upper_dir), upper_dir, &mut changes);
    changes.sort_by(|a, b| a.path.cmp(&b.path));
    changes
}

fn walk_dir(dir: &std::path::Path, strip_prefix: &str, changes: &mut Vec<FsChange>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let rel = path
            .to_str()
            .unwrap_or("")
            .strip_prefix(strip_prefix)
            .unwrap_or("")
            .to_string();

        if rel.is_empty() {
            continue;
        }

        if path.is_dir() {
            walk_dir(&path, strip_prefix, changes);
        } else {
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            // In overlay upper dir, whiteout files (.wh.*) indicate deletion
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if let Some(deleted_name) = filename.strip_prefix(".wh.") {
                let parent = path.parent().unwrap_or(&path);
                let del_rel = parent
                    .to_str()
                    .unwrap_or("")
                    .strip_prefix(strip_prefix)
                    .unwrap_or("");
                changes.push(FsChange {
                    path: format!("{}/{}", del_rel, deleted_name),
                    kind: FsChangeKind::Deleted,
                    size: 0,
                });
            } else {
                // File exists in upper = created or modified
                changes.push(FsChange {
                    path: rel,
                    kind: FsChangeKind::Created, // can't distinguish create vs modify from overlay alone
                    size,
                });
            }
        }
    }
}

fn handle_client(
    fd: RawFd,
    state: &Arc<Mutex<AgentState>>,
    integration_state: &Arc<Mutex<IntegrationState>>,
    probe_state: &Arc<Mutex<ProbeState>>,
    boot_state: &Arc<AgentBootState>,
) {
    // SAFETY: fd comes from accept and is a valid file descriptor owned by this function.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };

    // Hard cutover: every operational request must be preceded by at
    // least one successful protocol_hello in this
    // session. A non-hello first request is treated as a protocol
    // violation and rejected with `ProtocolMismatch`; we do not maintain
    // a soft compatibility shim for pre-hello hosts.
    let mut hello_seen = false;
    let req = loop {
        let Some(req) = read_request(&mut file) else {
            return;
        };

        match req {
            GuestRequest::ProtocolHello {
                host_protocol_version,
                min_supported_version,
                host_version,
                requested_capabilities,
            } => {
                let resp = mvm_guest::vsock::protocol_hello_response(
                    host_protocol_version,
                    min_supported_version,
                    &host_version,
                    &requested_capabilities,
                );
                if matches!(resp, GuestResponse::ProtocolHelloAck { .. }) {
                    hello_seen = true;
                }
                write_response(&mut file, &resp);
            }
            other => {
                if !hello_seen {
                    let resp = GuestResponse::ProtocolMismatch {
                        host_protocol_version: 0,
                        agent_protocol_version: mvm_guest::vsock::PROTOCOL_VERSION,
                        required_action: mvm_guest::vsock::ProtocolUpgradeAction::UpgradeHost,
                        message: "guest agent requires protocol_hello before any other request"
                            .to_string(),
                    };
                    write_response(&mut file, &resp);
                    return;
                }
                break other;
            }
        }
    };

    let active_profile = boot_state.profile;
    let boot_at = boot_state.boot_at;

    // Profile gate. Reject dev-only verbs in sealed-prod *before*
    // the per-variant handler runs. The gate returns a typed
    // `UnsupportedInProfile` response so an SDK can branch on
    // capability without parsing message text — this sits at the
    // protocol layer in addition to the per-handler policy checks
    // (dispatcher allowlists are not enough by themselves) and the
    // `#[cfg(feature = "dev-shell")]` compile-time symbol-absence
    // gate for `do_exec` / `do_run_code` (claim 4).
    if !req.allowed_in(active_profile) {
        let resp = GuestResponse::UnsupportedInProfile {
            profile: active_profile,
            verb: req.verb_name().to_string(),
        };
        write_response(&mut file, &resp);
        return;
    }

    if let Some(resp) = enforce_verb_grant(&req, boot_state.verb_grant.as_ref()) {
        write_response(&mut file, &resp);
        return;
    }

    let resp = match req {
        // The hello-prelude loop above guarantees `req` is not a
        // ProtocolHello, but keep an explicit, loud panic to catch
        // future loop refactors that would silently let a hello fall
        // through. Returning `Error` here would mask the bug.
        GuestRequest::ProtocolHello { .. } => {
            unreachable!("protocol hello reached operational dispatch")
        }

        GuestRequest::Ping => GuestResponse::Pong,

        GuestRequest::WorkerStatus => {
            let (status, last_busy_at) = match state.lock() {
                Ok(s) => (s.status.clone(), s.last_busy_at.clone()),
                Err(_) => ("unknown".to_string(), None),
            };
            GuestResponse::WorkerStatus {
                status,
                last_busy_at,
            }
        }

        GuestRequest::SleepPrep {
            drain_timeout_secs: _,
        } => {
            let (success, detail) = do_sleep_prep();
            GuestResponse::SleepPrepAck {
                success,
                detail: Some(detail),
            }
        }

        GuestRequest::Wake => {
            // Reset monitoring state after wake from snapshot.
            if let Ok(mut s) = state.lock() {
                s.status = "idle".to_string();
                s.last_busy_at = None;
            }
            GuestResponse::WakeAck { success: true }
        }

        GuestRequest::IntegrationStatus => GuestResponse::IntegrationStatusReport {
            integrations: build_integration_reports(integration_state, boot_at),
        },

        GuestRequest::CheckpointIntegrations { integrations: _ } => {
            GuestResponse::CheckpointResult {
                success: true,
                failed: vec![],
                detail: None,
            }
        }

        GuestRequest::ProbeStatus => GuestResponse::ProbeStatusReport {
            probes: build_probe_reports(probe_state),
        },

        GuestRequest::PrimedStatus => GuestResponse::PrimedStatusReport {
            primed: mvm_guest::vsock::workload_is_primed_at(std::path::Path::new(
                mvm_guest::vsock::PRIMED_MARKER_PATH,
            )),
        },

        GuestRequest::PostRestore { token } => {
            // First, rotate the VMGenID: feed the host-minted token to the
            // process-resident reseeder. Its state is captured in the snapshot,
            // so two clones of one snapshot both diverge from the captured
            // value when the host delivers each a distinct fresh token. A
            // zero token (no-rotation restore) is a no-op.
            let reseeded = matches!(
                reseed_on_post_restore(token),
                mvm_guest::genid::GenIdAction::Reseeded
            );
            // Then send SIGUSR1 to PID 1 to trigger drive remount + service restart.
            let result = std::process::Command::new("kill")
                .args(["-USR1", "1"])
                .output();
            match result {
                Ok(out) if out.status.success() => GuestResponse::PostRestoreAck {
                    success: true,
                    detail: Some("post-restore signal sent to init".to_string()),
                    reseeded,
                },
                Ok(out) => GuestResponse::PostRestoreAck {
                    success: false,
                    detail: Some(format!(
                        "kill failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    )),
                    reseeded,
                },
                Err(e) => GuestResponse::PostRestoreAck {
                    success: false,
                    detail: Some(format!("failed to send signal: {}", e)),
                    reseeded,
                },
            }
        }

        #[cfg(feature = "dev-shell")]
        GuestRequest::Exec {
            command,
            stdin,
            timeout_secs,
        } => {
            eprintln!("[audit] exec request: {:?}", command);
            do_exec_streaming(&mut file, &command, stdin.as_deref(), timeout_secs)
        }

        #[cfg(not(feature = "dev-shell"))]
        GuestRequest::Exec { .. } => GuestResponse::Error {
            message: "exec not available: guest agent built without dev-shell feature".to_string(),
        },

        #[cfg(feature = "dev-shell")]
        GuestRequest::ExecBatch {
            stages,
            commands,
            timeout_secs,
        } => {
            eprintln!(
                "[audit] exec-batch request: {} stages, {} commands",
                stages.len(),
                commands.len()
            );
            do_exec_batch(&stages, &commands, timeout_secs)
        }

        #[cfg(not(feature = "dev-shell"))]
        GuestRequest::ExecBatch { .. } => GuestResponse::Error {
            message: "exec-batch not available: guest agent built without dev-shell feature"
                .to_string(),
        },

        #[cfg(feature = "dev-shell")]
        GuestRequest::RunCode { code, timeout_secs } => {
            // Stateless v1: read /etc/mvm/wrapper.json to learn the
            // wrapper's language, then dispatch a fresh interpreter
            // subprocess. A future v2 will route through the
            // warm-process pool's persistent wrapper for stateful
            // eval; wire shape stays identical.
            //
            // Code body is NOT logged (matches `mvmctl session
            // run-code`'s host-side audit posture — argv / code can
            // carry user-typed secrets).
            eprintln!("[audit] run-code request");
            do_run_code(&mut file, &code, timeout_secs)
        }

        #[cfg(not(feature = "dev-shell"))]
        GuestRequest::RunCode { .. } => GuestResponse::Error {
            message: "run-code not available: guest agent built without dev-shell feature"
                .to_string(),
        },

        GuestRequest::RunEntrypoint {
            stdin,
            timeout_secs,
            env,
        } => {
            // Distinguish "validation hasn't completed yet"
            // (Starting → NotReady, transient) from
            // "validation failed" (Failed → EntrypointInvalid,
            // terminal). Snapshot once so the decision is consistent
            // even if a concurrent background-thread update flips
            // state mid-handler.
            if matches!(boot_state.snapshot().entrypoint, ComponentState::Starting) {
                GuestResponse::EntrypointEvent(EntrypointEvent::Error {
                    kind: RunEntrypointError::NotReady,
                    message: "entrypoint validation in progress; poll ReadinessStatus and retry"
                        .to_string(),
                })
            } else {
                handle_run_entrypoint(&mut file, stdin, timeout_secs, env)
            }
        }

        GuestRequest::FsDiff => {
            // Walk the overlay upper dir to find changes since boot.
            // The overlay upper dir is typically at /overlay/upper when
            // the rootfs is mounted read-only with an overlay.
            let changes = collect_fs_diff();
            GuestResponse::FsDiffResult { changes }
        }

        GuestRequest::StartPortForward { guest_port } => {
            let vsock_port = mvm_guest::vsock::PORT_FORWARD_BASE + guest_port as u32;
            eprintln!("port-fwd: starting vsock:{vsock_port} → tcp://localhost:{guest_port}");
            std::thread::spawn(move || {
                run_port_forwarder(vsock_port, guest_port);
            });
            GuestResponse::PortForwardStarted {
                guest_port,
                vsock_port,
            }
        }
        GuestRequest::StartUnixSocketForward {
            guest_path,
            host_vsock_port,
            socket_mode,
        } => match start_unix_socket_forwarder(&guest_path, host_vsock_port, socket_mode) {
            Ok(()) => GuestResponse::UnixSocketForwardStarted {
                guest_path,
                host_vsock_port,
            },
            Err(err) => GuestResponse::Error {
                message: format!("unix socket forward failed: {err}"),
            },
        },

        // PTY-over-vsock console — the single dev-only interactive path. The
        // relay lives behind `#[cfg(feature = "dev-shell")]` so its symbols are
        // absent from a sealed production agent (claim 15; mirrors the
        // `do_exec` gate). The protocol profile gate
        // above already rejects these verbs in sealed-prod, but the compile-time
        // gate is the load-bearing guarantee — no console code is even linked.
        #[cfg(feature = "dev-shell")]
        GuestRequest::ConsoleOpen {
            cols,
            rows,
            env,
            argv,
        } => {
            // Check security policy — console requires access.console = true.
            // When no policy file is provisioned (dev mode), use permissive defaults.
            let policy = mvm_guest::builder_agent::load_security_policy()
                .ok()
                .flatten()
                .unwrap_or_else(mvm_core::security::SecurityPolicy::dev_defaults);
            let console_allowed = policy.access.console;
            if !console_allowed {
                return write_response(
                    &mut file,
                    &GuestResponse::Error {
                        message: "console rejected: access.console not enabled in security policy"
                            .to_string(),
                    },
                );
            }
            match mvm_guest::console::open_session(cols, rows, &env, &argv) {
                Ok(session) => {
                    let session_id = session.session_id;
                    let data_port = session.data_port;
                    eprintln!("console: opened session {session_id}, data port {data_port}");

                    // Run the relay in a background thread
                    std::thread::spawn(move || {
                        let exit_code = mvm_guest::console::run_console_relay(&session);
                        eprintln!("console: session {session_id} ended, exit code {exit_code}");
                    });

                    GuestResponse::ConsoleOpened {
                        session_id,
                        data_port,
                    }
                }
                Err(e) => GuestResponse::Error {
                    message: format!("console open failed: {e}"),
                },
            }
        }

        #[cfg(not(feature = "dev-shell"))]
        GuestRequest::ConsoleOpen { .. } => GuestResponse::Error {
            message: "console not available: guest agent built without dev-shell feature"
                .to_string(),
        },

        #[cfg(feature = "dev-shell")]
        GuestRequest::ConsoleClose { session_id } => {
            // Console sessions end when the shell exits or the host disconnects.
            // Explicit close is a no-op if already closed.
            if mvm_guest::console::is_active() {
                GuestResponse::Error {
                    message: "explicit close not yet supported — disconnect to end session"
                        .to_string(),
                }
            } else if let Some(exit_code) = mvm_guest::console::completed_exit_code(session_id) {
                GuestResponse::ConsoleExited {
                    session_id,
                    exit_code,
                }
            } else {
                GuestResponse::ConsoleExited {
                    session_id,
                    exit_code: 0,
                }
            }
        }

        #[cfg(not(feature = "dev-shell"))]
        GuestRequest::ConsoleClose { .. } => GuestResponse::Error {
            message: "console not available: guest agent built without dev-shell feature"
                .to_string(),
        },

        #[cfg(feature = "dev-shell")]
        GuestRequest::ConsoleResize {
            session_id,
            cols,
            rows,
        } => {
            if mvm_guest::console::resize_active_session(cols, rows) {
                eprintln!("console: resized to {cols}x{rows}");
                GuestResponse::ConsoleResized { session_id }
            } else {
                GuestResponse::Error {
                    message: "no active console session to resize".to_string(),
                }
            }
        }

        #[cfg(not(feature = "dev-shell"))]
        GuestRequest::ConsoleResize { .. } => GuestResponse::Error {
            message: "console not available: guest agent built without dev-shell feature"
                .to_string(),
        },

        // Report whether boot-time entrypoint validation succeeded.
        // Used by `mvmctl doctor` against a
        // running guest. Prod-safe — no inputs, no secrets in the
        // response (just a path + reason string).
        GuestRequest::EntrypointStatus => match VALIDATED_ENTRYPOINT.get() {
            Some(Ok(v)) => GuestResponse::EntrypointStatusReport {
                ok: true,
                path: Some(v.resolved.display().to_string()),
                detail: None,
            },
            Some(Err(msg)) => GuestResponse::EntrypointStatusReport {
                ok: false,
                path: None,
                detail: Some(msg.clone()),
            },
            // With background init, `None` means validation is still
            // running, not "never ran".
            None => GuestResponse::EntrypointStatusReport {
                ok: false,
                path: None,
                detail: Some("entrypoint validation in progress".to_string()),
            },
        },

        // Structured readiness snapshot. Cheap — a single mutex
        // lock + struct copy. Designed to be the
        // verb a host polls during `mvmctl wait <vm> --for ...`
        // without back-pressure on the rest of the agent.
        GuestRequest::ReadinessStatus => {
            GuestResponse::ReadinessStatusReport(boot_state.snapshot())
        }

        // FS RPC verbs. Production-safe surface backed by
        // `mvm_guest::fs_rpc::handle_with_defaults`: every path
        // routes through `mvm_core::crypto::policy::PathPolicy` (deny
        // list + canonicalization), per-call caps gate read/write
        // sizes, and `FsResult::Error` carries a typed `kind` so
        // the host can branch without parsing message text.
        GuestRequest::FsRead {
            path,
            offset,
            length,
            ..
        } => GuestResponse::FsResult(mvm_guest::fs_rpc::handle_with_defaults(
            mvm_guest::fs_rpc::FsRequest::Read {
                path: &path,
                offset,
                length,
            },
        )),
        GuestRequest::FsWrite {
            path,
            content,
            mode,
            create_parents,
            ..
        } => GuestResponse::FsResult(mvm_guest::fs_rpc::handle_with_defaults(
            mvm_guest::fs_rpc::FsRequest::Write {
                path: &path,
                content: &content,
                mode,
                create_parents,
            },
        )),
        GuestRequest::FsList { path, .. } => {
            GuestResponse::FsResult(mvm_guest::fs_rpc::handle_with_defaults(
                mvm_guest::fs_rpc::FsRequest::List { path: &path },
            ))
        }
        GuestRequest::FsStat {
            path,
            follow_symlinks,
        } => GuestResponse::FsResult(mvm_guest::fs_rpc::handle_with_defaults(
            mvm_guest::fs_rpc::FsRequest::Stat {
                path: &path,
                follow_symlinks,
            },
        )),
        GuestRequest::FsMkdir {
            path,
            mode,
            parents,
        } => GuestResponse::FsResult(mvm_guest::fs_rpc::handle_with_defaults(
            mvm_guest::fs_rpc::FsRequest::Mkdir {
                path: &path,
                mode,
                parents,
            },
        )),
        GuestRequest::FsRemove {
            path, recursive, ..
        } => GuestResponse::FsResult(mvm_guest::fs_rpc::handle_with_defaults(
            mvm_guest::fs_rpc::FsRequest::Remove {
                path: &path,
                recursive,
            },
        )),
        GuestRequest::FsMove { from, to, .. } => GuestResponse::FsResult(
            mvm_guest::fs_rpc::handle_with_defaults(mvm_guest::fs_rpc::FsRequest::Move {
                from: &from,
                to: &to,
            }),
        ),

        // Process control verbs. Dev-only — the handler lives behind
        // `#[cfg(feature = "dev-shell")]` so its symbols are stripped
        // from prod builds (the `prod-agent-runentry-contract` CI
        // gate enforces it). Prod builds return a typed
        // `UnsupportedInProduction` error so SDK callers can branch
        // on capability without parsing message text.
        GuestRequest::ProcStart {
            argv,
            env,
            cwd,
            stdin,
            timeout_secs: _, // applied during ProcWait
        } => {
            #[cfg(feature = "dev-shell")]
            {
                let caps = mvm_guest::process_rpc::Caps::production();
                GuestResponse::ProcResult(mvm_guest::process_rpc::handle_proc_start(
                    proc_registry(),
                    &caps,
                    &argv,
                    &env,
                    cwd.as_deref(),
                    &stdin,
                ))
            }
            #[cfg(not(feature = "dev-shell"))]
            {
                let _ = (argv, env, cwd, stdin);
                GuestResponse::ProcResult(mvm_guest::vsock::ProcResult::Error {
                    kind: mvm_guest::vsock::ProcErrorKind::UnsupportedInProduction,
                    message:
                        "process control not available: guest agent built without dev-shell feature"
                            .to_string(),
                })
            }
        }
        GuestRequest::ProcList => {
            #[cfg(feature = "dev-shell")]
            {
                GuestResponse::ProcResult(mvm_guest::process_rpc::handle_proc_list(proc_registry()))
            }
            #[cfg(not(feature = "dev-shell"))]
            {
                GuestResponse::ProcResult(mvm_guest::vsock::ProcResult::Error {
                    kind: mvm_guest::vsock::ProcErrorKind::UnsupportedInProduction,
                    message:
                        "process control not available: guest agent built without dev-shell feature"
                            .to_string(),
                })
            }
        }
        GuestRequest::ProcSignal { pid_token, signum } => {
            #[cfg(feature = "dev-shell")]
            {
                GuestResponse::ProcResult(mvm_guest::process_rpc::handle_proc_signal(
                    proc_registry(),
                    &pid_token,
                    signum,
                ))
            }
            #[cfg(not(feature = "dev-shell"))]
            {
                let _ = (pid_token, signum);
                GuestResponse::ProcResult(mvm_guest::vsock::ProcResult::Error {
                    kind: mvm_guest::vsock::ProcErrorKind::UnsupportedInProduction,
                    message:
                        "process control not available: guest agent built without dev-shell feature"
                            .to_string(),
                })
            }
        }
        GuestRequest::ProcSendInput { pid_token, bytes } => {
            #[cfg(feature = "dev-shell")]
            {
                let caps = mvm_guest::process_rpc::Caps::production();
                GuestResponse::ProcResult(mvm_guest::process_rpc::handle_proc_send_input(
                    proc_registry(),
                    &caps,
                    &pid_token,
                    &bytes,
                ))
            }
            #[cfg(not(feature = "dev-shell"))]
            {
                let _ = (pid_token, bytes);
                GuestResponse::ProcResult(mvm_guest::vsock::ProcResult::Error {
                    kind: mvm_guest::vsock::ProcErrorKind::UnsupportedInProduction,
                    message:
                        "process control not available: guest agent built without dev-shell feature"
                            .to_string(),
                })
            }
        }
        GuestRequest::ProcKill { pid_token } => {
            #[cfg(feature = "dev-shell")]
            {
                GuestResponse::ProcResult(mvm_guest::process_rpc::handle_proc_kill(
                    proc_registry(),
                    &pid_token,
                ))
            }
            #[cfg(not(feature = "dev-shell"))]
            {
                let _ = pid_token;
                GuestResponse::ProcResult(mvm_guest::vsock::ProcResult::Error {
                    kind: mvm_guest::vsock::ProcErrorKind::UnsupportedInProduction,
                    message:
                        "process control not available: guest agent built without dev-shell feature"
                            .to_string(),
                })
            }
        }
        GuestRequest::ProcWait {
            pid_token,
            timeout_secs,
        } => {
            #[cfg(feature = "dev-shell")]
            {
                let terminal = handle_proc_wait_streaming(&mut file, &pid_token, timeout_secs);
                GuestResponse::ProcWaitEvent(terminal)
            }
            #[cfg(not(feature = "dev-shell"))]
            {
                let _ = (pid_token, timeout_secs);
                GuestResponse::ProcWaitEvent(mvm_guest::vsock::ProcWaitEvent::Error {
                    kind: mvm_guest::vsock::ProcErrorKind::UnsupportedInProduction,
                    message:
                        "process control not available: guest agent built without dev-shell feature"
                            .to_string(),
                })
            }
        }

        // virtio-fs volume mount/unmount. Production-safe; every
        // host-supplied path runs through
        // `mvm_core::crypto::policy::MountPathPolicy` before any
        // mount(2) syscall. Real handler lives in `mvm_guest::volume`.
        GuestRequest::MountVolume {
            volume_name,
            guest_path,
            read_only,
        } => GuestResponse::VolumeMountResult(mvm_guest::volume::handle_mount(
            &volume_name,
            &guest_path,
            read_only,
        )),
        GuestRequest::UnmountVolume { guest_path, force } => {
            GuestResponse::VolumeMountResult(mvm_guest::volume::handle_unmount(&guest_path, force))
        }

        // Substrate-side mirror of `mvmctl session set-timeout`. If
        // the warm-process pool is active (tier-2 dispatch), the
        // agent updates its idle-recycle threshold and a recycler
        // thread reaps individual workers idle past the new
        // timeout — keeping the VM up while pruning waste. If no pool
        // is active, the verb is a no-op acknowledged with
        // `applied_secs = 0`; the host-side reaper remains the only
        // enforcement on cold-path-only builds.
        GuestRequest::UpdateIdleTimeout { secs } => match WARM_POOL.get() {
            Some(Some(pool)) => {
                let previous = pool.set_idle_timeout(secs);
                GuestResponse::UpdateIdleTimeoutAck {
                    previous_secs: previous,
                    applied_secs: secs,
                }
            }
            _ => GuestResponse::UpdateIdleTimeoutAck {
                previous_secs: 0,
                applied_secs: 0,
            },
        },
    };

    write_response(&mut file, &resp);
}

// ============================================================================
// Vsock → TCP port forwarders
// ============================================================================

/// Loopback host the port forwarder dials when proxying vsock → TCP.
///
/// Pinning this to `127.0.0.1` is load-bearing: the agent must never
/// accept TCP traffic from outside the guest. The forwarder only
/// originates outbound TCP, but a future "double-ended" forwarder must reuse
/// this constant rather than reach for `0.0.0.0` or a configurable host.
const PORT_FORWARD_TCP_HOST: &str = "127.0.0.1";

/// Bind a vsock listener and forward each connection to a local TCP port.
fn run_port_forwarder(vsock_port: u32, tcp_port: u16) {
    // SAFETY: libc call with constant arguments.
    let fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
    if fd < 0 {
        eprintln!("port-fwd: failed to create vsock socket for port {tcp_port}");
        return;
    }

    let addr = SockAddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: vsock_port,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };

    // SAFETY: valid pointer and size.
    let rc = unsafe {
        bind(
            fd,
            &addr as *const SockAddrVm as *const core::ffi::c_void,
            size_of::<SockAddrVm>() as u32,
        )
    };
    if rc != 0 {
        eprintln!("port-fwd: failed to bind vsock port {vsock_port} for tcp/{tcp_port}");
        // SAFETY: `fd` is the vsock socket created above, not yet wrapped in an
        // owning type; close takes no pointers.
        unsafe {
            close(fd);
        }
        return;
    }

    // SAFETY: fd is valid.
    if unsafe { listen(fd, 8) } != 0 {
        eprintln!("port-fwd: failed to listen on vsock port {vsock_port}");
        unsafe {
            close(fd);
        }
        return;
    }

    eprintln!("port-fwd: vsock:{vsock_port} → tcp://localhost:{tcp_port}");

    loop {
        // SAFETY: null addr pointers are fine when we don't need peer info.
        let cfd = unsafe { accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if cfd < 0 {
            continue;
        }

        std::thread::spawn(move || {
            use std::os::unix::net::UnixStream;
            // SAFETY: cfd is a valid fd from accept(). UnixStream is a
            // thin wrapper around an fd — works fine for vsock sockets.
            let vsock_stream = unsafe { UnixStream::from_raw_fd(cfd as RawFd) };
            let Ok(tcp_stream) = std::net::TcpStream::connect((PORT_FORWARD_TCP_HOST, tcp_port))
            else {
                eprintln!("port-fwd: connect to localhost:{tcp_port} failed");
                return;
            };
            let Ok(mut tcp_read) = tcp_stream.try_clone() else {
                return;
            };
            let Ok(mut vsock_write) = vsock_stream.try_clone() else {
                return;
            };
            let mut vsock_read = vsock_stream;
            let mut tcp_write = tcp_stream;

            let h1 = std::thread::spawn(move || {
                let _ = std::io::copy(&mut vsock_read, &mut tcp_write);
            });
            let h2 = std::thread::spawn(move || {
                let _ = std::io::copy(&mut tcp_read, &mut vsock_write);
            });
            let _ = h1.join();
            let _ = h2.join();
        });
    }
}

fn validate_unix_forward_guest_path(path: &str) -> anyhow::Result<()> {
    let path = std::path::Path::new(path);
    if !path.is_absolute() {
        anyhow::bail!("guest socket path must be absolute");
    }
    if !path.starts_with("/run/mvm/") {
        anyhow::bail!("guest socket path must be under /run/mvm");
    }
    Ok(())
}

fn start_unix_socket_forwarder(
    guest_path: &str,
    host_vsock_port: u32,
    socket_mode: u32,
) -> anyhow::Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

    validate_unix_forward_guest_path(guest_path)?;
    let path = std::path::PathBuf::from(guest_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_socket() => {
            std::fs::remove_file(&path)?;
        }
        Ok(_) => {
            anyhow::bail!("refusing to replace non-socket path {}", path.display());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(socket_mode & 0o777))?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let Ok(upstream) = mvm_guest::vsock::connect_host_vsock(
                    host_vsock_port,
                    mvm_guest::vsock::DEFAULT_TIMEOUT_SECS,
                ) else {
                    eprintln!("unix-fwd: connect_host_vsock({host_vsock_port}) failed");
                    return;
                };
                let Ok(mut guest_read) = stream.try_clone() else {
                    return;
                };
                let Ok(mut host_write) = upstream.try_clone() else {
                    return;
                };
                let mut guest_write = stream;
                let mut host_read = upstream;
                let h1 = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut guest_read, &mut host_write);
                });
                let h2 = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut host_read, &mut guest_write);
                });
                let _ = h1.join();
                let _ = h2.join();
            });
        }
    });
    Ok(())
}

// ============================================================================
// Entry point
// ============================================================================

fn main() {
    let cfg = parse_config();

    // Resolve the active vsock profile from the baked image config.
    // The policy file lives on a dm-verity rootfs for sealed-prod
    // images, so its `profile` field can't be widened at runtime —
    // flipping it would break the
    // verity hash and the kernel panics in `mvm-verity-init` before
    // userspace. Absence of `/etc/mvm/security.json` is treated as an
    // unprovisioned dev image (`SecurityPolicy::dev_defaults`).
    let active_profile = mvm_guest::builder_agent::load_security_policy()
        .ok()
        .flatten()
        .map(|p| p.profile)
        .unwrap_or_else(|| mvm_core::security::SecurityPolicy::dev_defaults().profile);
    eprintln!("mvm-guest-agent: profile={:?}", active_profile);

    eprintln!(
        "mvm-guest-agent: starting on vsock port {} (threshold={}, interval={}s)",
        cfg.port, cfg.busy_threshold, cfg.sample_interval_secs
    );

    // Install signal handlers BEFORE vsock bind + background init.
    // Same handlers fire whether we're mid-warmup
    // or steady-state; better to wire them up before any work that
    // might want clean teardown.
    install_signal_handlers();

    // SAFETY: libc call, arguments are constant values.
    let fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
    if fd < 0 {
        eprintln!("failed to create vsock socket");
        std::process::exit(1);
    }

    let addr = SockAddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: cfg.port,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };

    // SAFETY: pointers are valid for the specified size.
    let bind_rc = unsafe {
        bind(
            fd,
            &addr as *const SockAddrVm as *const core::ffi::c_void,
            size_of::<SockAddrVm>() as u32,
        )
    };
    if bind_rc != 0 {
        eprintln!("failed to bind vsock port {}", cfg.port);
        // SAFETY: `fd` is the vsock socket created above, not yet wrapped in an
        // owning type; close takes no pointers.
        unsafe {
            close(fd);
        }
        std::process::exit(1);
    }

    // SAFETY: fd is valid.
    if unsafe { listen(fd, 16) } != 0 {
        eprintln!("failed to listen on vsock socket");
        unsafe {
            close(fd);
        }
        std::process::exit(1);
    }

    // Record boot time for startup grace period tracking.
    let boot_at = std::time::Instant::now();

    // Shared readiness state. Created AFTER vsock bind+listen so
    // `mark_vsock_bound` stamps an accurate
    // `vsock_bound_ms`. Cloned into every handler thread via
    // `Arc::clone` — the inner Mutex serialises the few writes
    // (`set_entrypoint`, `set_warm_pool`, …) without measurable
    // contention because writes only fire at boot completion events.
    let boot_state = Arc::new(AgentBootState::new(active_profile, boot_at));
    boot_state.mark_vsock_bound();
    eprintln!(
        "mvm-guest-agent: control plane ready ({}ms)",
        boot_state
            .snapshot()
            .boot_millis
            .vsock_bound_ms
            .unwrap_or(0)
    );

    // Defer entrypoint validation + warm-pool startup to a
    // background thread chained in dependency order
    // (warm pool reads `VALIDATED_ENTRYPOINT.get()`, so the sequence
    // must stay serial inside this one thread). The accept loop
    // below begins serving `Ping` / `ReadinessStatus` /
    // `EntrypointStatus` immediately; `RunEntrypoint` returns
    // `NotReady` until the entrypoint flips to `Ready`.
    {
        let bs = Arc::clone(&boot_state);
        std::thread::spawn(move || {
            init_entrypoint_validation(&bs);
            init_warm_pool(&bs);
        });
    }

    // Start background monitoring thread.
    let state = Arc::new(Mutex::new(AgentState::new()));
    let monitor_state = Arc::clone(&state);
    // Seed the hot-reloadable atomics from the boot-time config so
    // monitoring_loop picks up the same values it would have with
    // the prior captured-by-value shape.
    HOT_BUSY_THRESHOLD_BITS.store(cfg.busy_threshold.to_bits(), Ordering::Release);
    HOT_SAMPLE_INTERVAL_SECS.store(cfg.sample_interval_secs, Ordering::Release);
    std::thread::spawn(move || monitoring_loop(monitor_state));

    // Defer integration drop-in scanning + health loop startup to a
    // dedicated background thread. The scan
    // itself is fast (single directory read), but moving it off the
    // bind-to-accept critical path also means a malformed drop-in
    // can't bubble a panic into the boot sequence.
    let integration_state = Arc::new(Mutex::new(IntegrationState {
        integrations: Vec::new(),
    }));
    {
        let bs = Arc::clone(&boot_state);
        let s = Arc::clone(&integration_state);
        std::thread::spawn(move || init_integrations(&bs, &s));
    }

    // Same shape for the probe drop-in scan + loop.
    let probe_state = Arc::new(Mutex::new(ProbeState { probes: Vec::new() }));
    {
        let bs = Arc::clone(&boot_state);
        let s = Arc::clone(&probe_state);
        std::thread::spawn(move || init_probes(&bs, &s));
    }

    // Start the egress forward proxy (loopback FORWARD_PROXY_PORT).
    // The workload's HTTP_PROXY (set by the host invoke path only when the VM
    // has a substitution endpoint) routes secret-bearing requests here; this
    // relays them over vsock to the host endpoint, which substitutes the real
    // credential. Always started (cheap, loopback-only): with no HTTP_PROXY in
    // the workload env it simply sees no connections. Not dev-shell-gated —
    // egress substitution is a production feature.
    std::thread::spawn(|| {
        if let Err(e) = mvm_guest::forward_proxy::start_forward_proxy(30) {
            eprintln!("mvm-guest-agent: forward proxy failed to start: {e}");
        }
    });

    // Port forwarders are started on-demand via StartPortForward requests
    // from the host (works with all backends, no config drive needed).

    eprintln!(
        "mvm-guest-agent: listening on vsock port {} (entrypoint, warm pool, integrations, probes initializing in background)",
        cfg.port
    );

    // When warm-process is active, real concurrency from multiple
    // host invokes lands in parallel — spawn a thread per
    // accepted connection so they reach distinct workers. Cold-tier
    // images keep the single-threaded accept loop unchanged for
    // bit-identical behavior. `handle_client` already takes shared
    // state through `Arc<Mutex<…>>`, so per-connection threading
    // is a safe addition; the new pool itself does its own slot
    // mutex / condvar bookkeeping.
    //
    // Poll `SHUTDOWN_REQUESTED` between accepts and after each
    // `accept()` return (signals deliver `EINTR` so accept
    // returns < 0, which already triggers the bottom-of-loop check).
    // Once the flag flips, break out and drain via
    // `shutdown_subsystems`.
    // `warm_active` is now re-evaluated per
    // iteration. The background init thread populates `WARM_POOL`
    // some time after the accept loop starts, so a one-shot capture
    // at loop entry would mis-classify all subsequent connections
    // as cold-tier. `WARM_POOL.get()` is a relaxed atomic load —
    // cheap enough to do per-accept.
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
            break;
        }
        // Apply pending SIGHUP-driven config reload.
        // Compare-and-swap to false so a concurrent SIGHUP between
        // the load and the apply isn't lost (it'll re-set the flag
        // and we'll pick it up on the next iteration).
        if RELOAD_REQUESTED
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            apply_reload();
        }
        // SAFETY: null addr pointers are allowed for accept when peer addr is not needed.
        let cfd = unsafe { accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if cfd < 0 {
            // Most common reason: EINTR from a signal. Re-check the
            // flag immediately so a SIGTERM that landed mid-accept
            // breaks the loop without waiting for the next accept
            // to start.
            if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
                break;
            }
            // Same fast-path for SIGHUP — apply the reload on the
            // next iteration's compare_exchange.
            continue;
        }
        // Stamp first-accept timing once. Idempotent inside
        // `AgentBootState` — subsequent calls are no-ops.
        boot_state.mark_first_accept();
        let warm_active = matches!(WARM_POOL.get(), Some(Some(_)));
        if warm_active {
            let state = Arc::clone(&state);
            let integration_state = Arc::clone(&integration_state);
            let probe_state = Arc::clone(&probe_state);
            let bs = Arc::clone(&boot_state);
            std::thread::spawn(move || {
                handle_client(cfd, &state, &integration_state, &probe_state, &bs);
            });
        } else {
            handle_client(cfd, &state, &integration_state, &probe_state, &boot_state);
        }
    }

    // Close the listening socket so any in-flight accept on a
    // peer thread (warm-process accept-thread-per-conn mode) wakes.
    // SAFETY: fd was created by socket() and is owned by us.
    unsafe {
        close(fd);
    }
    shutdown_subsystems(DEFAULT_SHUTDOWN_GRACE);
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_guest::integrations::{IntegrationEntry, IntegrationHealthResult, IntegrationStatus};
    use mvm_guest::vsock::{GuestCapability, read_frame, write_frame};
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;

    // ─── signal handling unit tests ───────────────────────────
    //
    // These exercise the handler in isolation by calling the
    // `extern "C"` function directly with a synthetic signo. We
    // deliberately do NOT raise real signals against the test
    // process — Cargo runs tests in a single shared binary and
    // a real SIGTERM would terminate every concurrent test.
    //
    // The tests share global statics with the rest of the binary,
    // so each test resets `SHUTDOWN_REQUESTED` and
    // `SHUTDOWN_SIGNAL_COUNT` at the start. Using a Mutex around
    // the reset+invoke serializes signal-handler tests so they
    // don't observe each other's state mutations.

    static SIGNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_shutdown_state() {
        SHUTDOWN_REQUESTED.store(false, Ordering::Release);
        SHUTDOWN_SIGNAL_COUNT.store(0, Ordering::Release);
    }

    #[test]
    fn signal_handler_flips_shutdown_flag_on_first_signal() {
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        reset_shutdown_state();
        assert!(!SHUTDOWN_REQUESTED.load(Ordering::Acquire));
        // SAFETY: the handler is async-signal-safe and only stores
        // an atomic on first invocation; SIGTERM signo is a valid
        // libc constant.
        unsafe {
            on_shutdown_signal(libc::SIGTERM);
        }
        assert!(SHUTDOWN_REQUESTED.load(Ordering::Acquire));
        assert_eq!(SHUTDOWN_SIGNAL_COUNT.load(Ordering::Acquire), 1);
    }

    #[test]
    fn signal_handler_increments_count_idempotent_first_call() {
        // Calling once must leave count==1, flag==true. Calling
        // again would `_exit` per the second-signal escalation,
        // so we never invoke the handler twice in tests.
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        reset_shutdown_state();
        // SAFETY: the handler only performs async-signal-safe atomic stores;
        // calling it directly (not from a real signal) with a valid signal
        // number is sound, and one call stays below the second-signal `_exit`.
        unsafe {
            on_shutdown_signal(libc::SIGINT);
        }
        assert_eq!(SHUTDOWN_SIGNAL_COUNT.load(Ordering::Acquire), 1);
        assert!(SHUTDOWN_REQUESTED.load(Ordering::Acquire));
    }

    #[test]
    fn install_signal_handlers_does_not_panic() {
        // Installing twice should be safe; sigaction overwrites.
        // We don't assert the prior disposition is preserved
        // because the test runner may have its own handlers.
        install_signal_handlers();
        install_signal_handlers();
    }

    // ─── SIGHUP config reload ──────────────────────────────

    fn reset_reload_state() {
        RELOAD_REQUESTED.store(false, Ordering::Release);
    }

    #[test]
    fn signal_handler_flips_reload_flag_on_sighup() {
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        reset_reload_state();
        assert!(!RELOAD_REQUESTED.load(Ordering::Acquire));
        // SAFETY: handler is async-signal-safe and only stores an
        // atomic; SIGHUP signo is a valid libc constant.
        unsafe {
            on_reload_signal(libc::SIGHUP);
        }
        assert!(RELOAD_REQUESTED.load(Ordering::Acquire));
    }

    #[test]
    fn signal_handler_reload_is_idempotent_on_repeat() {
        // Unlike SIGTERM/SIGINT, SIGHUP must NOT escalate on the
        // second delivery — each one is a fresh reload request.
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        reset_reload_state();
        // SAFETY: the SIGHUP handler only does an atomic store and never
        // escalates; calling it directly with a valid signal number is sound.
        unsafe {
            on_reload_signal(libc::SIGHUP);
            on_reload_signal(libc::SIGHUP);
            on_reload_signal(libc::SIGHUP);
        }
        assert!(RELOAD_REQUESTED.load(Ordering::Acquire));
        // No `_exit` happened or this test wouldn't have returned.
    }

    #[test]
    fn apply_reload_updates_hot_atomics_with_new_values() {
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        // Seed the atomics to known values.
        HOT_BUSY_THRESHOLD_BITS.store(0.1f64.to_bits(), Ordering::Release);
        HOT_SAMPLE_INTERVAL_SECS.store(5, Ordering::Release);

        let new_cfg = AgentConfig {
            port: default_port(),
            busy_threshold: 0.75,
            sample_interval_secs: 30,
        };
        apply_reload_to_atomics(&new_cfg);

        let updated_thresh = f64::from_bits(HOT_BUSY_THRESHOLD_BITS.load(Ordering::Acquire));
        let updated_interval = HOT_SAMPLE_INTERVAL_SECS.load(Ordering::Acquire);
        assert!(
            (updated_thresh - 0.75).abs() < f64::EPSILON,
            "busy_threshold not updated: got {updated_thresh}"
        );
        assert_eq!(updated_interval, 30);
    }

    #[test]
    fn apply_reload_is_noop_when_values_unchanged() {
        // If the on-disk config matches the live state, the
        // reload path runs without changing anything — the
        // monitoring loop sees the same values.
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        HOT_BUSY_THRESHOLD_BITS.store(0.5f64.to_bits(), Ordering::Release);
        HOT_SAMPLE_INTERVAL_SECS.store(10, Ordering::Release);

        let same_cfg = AgentConfig {
            port: default_port(),
            busy_threshold: 0.5,
            sample_interval_secs: 10,
        };
        apply_reload_to_atomics(&same_cfg);

        assert_eq!(
            HOT_BUSY_THRESHOLD_BITS.load(Ordering::Acquire),
            0.5f64.to_bits()
        );
        assert_eq!(HOT_SAMPLE_INTERVAL_SECS.load(Ordering::Acquire), 10);
    }

    #[test]
    fn apply_reload_handles_partial_update() {
        // Only busy_threshold differs; sample_interval_secs stays.
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        HOT_BUSY_THRESHOLD_BITS.store(0.2f64.to_bits(), Ordering::Release);
        HOT_SAMPLE_INTERVAL_SECS.store(7, Ordering::Release);

        let new_cfg = AgentConfig {
            port: default_port(),
            busy_threshold: 0.9,
            sample_interval_secs: 7,
        };
        apply_reload_to_atomics(&new_cfg);

        assert!(
            (f64::from_bits(HOT_BUSY_THRESHOLD_BITS.load(Ordering::Acquire)) - 0.9).abs()
                < f64::EPSILON
        );
        assert_eq!(HOT_SAMPLE_INTERVAL_SECS.load(Ordering::Acquire), 7);
    }

    #[test]
    fn apply_reload_logs_warning_when_port_differs() {
        // The port is not reloadable; a non-default port in the
        // file should log a warning. We can't easily capture
        // stderr in a test, but we can prove the function doesn't
        // panic or update the (non-existent) port atomic.
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        let new_cfg = AgentConfig {
            port: 9999,
            busy_threshold: default_busy_threshold(),
            sample_interval_secs: default_sample_interval_secs(),
        };
        apply_reload_to_atomics(&new_cfg);
        // Pass — no panic. The eprintln warning is by-eye.
    }

    #[test]
    fn shutdown_subsystems_no_pool_runs_quickly() {
        // With no warm pool active (the default for cold-tier
        // tests), shutdown_subsystems should return promptly —
        // it has nothing to drain.
        let start = std::time::Instant::now();
        shutdown_subsystems(Duration::from_millis(50));
        // No warm pool → no drain sleep → must return in well
        // under the grace.
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "shutdown_subsystems with no pool should return quickly"
        );
    }

    #[test]
    fn handle_client_accepts_protocol_hello_before_request() {
        let (mut host, guest) = UnixStream::pair().expect("unix stream pair");
        host.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        host.set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set write timeout");

        let state = Arc::new(Mutex::new(AgentState::new()));
        let integration_state = Arc::new(Mutex::new(IntegrationState {
            integrations: vec![],
        }));
        let probe_state = Arc::new(Mutex::new(ProbeState { probes: vec![] }));
        // handle_client takes `&Arc<AgentBootState>` (carrying
        // profile + boot_at + readiness) instead of a bare
        // boot_at + active_profile.
        let boot_state = Arc::new(AgentBootState::new(
            AgentProfile::Dev,
            std::time::Instant::now(),
        ));
        boot_state.mark_vsock_bound();

        let handle = std::thread::spawn(move || {
            handle_client(
                guest.into_raw_fd(),
                &state,
                &integration_state,
                &probe_state,
                &boot_state,
            );
        });

        write_frame(
            &mut host,
            &GuestRequest::ProtocolHello {
                host_protocol_version: mvm_guest::vsock::PROTOCOL_VERSION,
                min_supported_version: mvm_guest::vsock::MIN_SUPPORTED_PROTOCOL_VERSION,
                host_version: "test-host".to_string(),
                requested_capabilities: vec![GuestCapability::Ping],
            },
        )
        .expect("write protocol hello");

        let ack: GuestResponse = read_frame(&mut host).expect("read protocol ack");
        assert!(matches!(
            ack,
            GuestResponse::ProtocolHelloAck {
                capabilities,
                ..
            } if capabilities == vec![GuestCapability::Ping]
        ));

        write_frame(&mut host, &GuestRequest::Ping).expect("write ping");
        let pong: GuestResponse = read_frame(&mut host).expect("read pong");
        assert!(matches!(pong, GuestResponse::Pong));

        handle.join().expect("handle_client thread");
    }

    /// Hard-cutover regression: an operational request sent as the
    /// *first* request in a session (no prior
    /// `ProtocolHello`) must be rejected with `ProtocolMismatch`
    /// (`required_action: upgrade_host`) and the connection must be
    /// closed without dispatching the underlying operation.
    #[test]
    fn handle_client_rejects_non_hello_first_request() {
        let (mut host, guest) = UnixStream::pair().expect("unix stream pair");
        host.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        host.set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set write timeout");

        let state = Arc::new(Mutex::new(AgentState::new()));
        let integration_state = Arc::new(Mutex::new(IntegrationState {
            integrations: vec![],
        }));
        let probe_state = Arc::new(Mutex::new(ProbeState { probes: vec![] }));
        let boot_state = Arc::new(AgentBootState::new(
            AgentProfile::Dev,
            std::time::Instant::now(),
        ));
        boot_state.mark_vsock_bound();

        let handle = std::thread::spawn(move || {
            handle_client(
                guest.into_raw_fd(),
                &state,
                &integration_state,
                &probe_state,
                &boot_state,
            );
        });

        // Bare `Ping` with no prior hello — the soft-cutover path used
        // to let this through and answer `Pong`. Under hard cutover the
        // agent must respond with `ProtocolMismatch` and close.
        write_frame(&mut host, &GuestRequest::Ping).expect("write ping");
        let resp: GuestResponse = read_frame(&mut host).expect("read mismatch");
        match resp {
            GuestResponse::ProtocolMismatch {
                required_action,
                agent_protocol_version,
                ..
            } => {
                assert_eq!(
                    required_action,
                    mvm_guest::vsock::ProtocolUpgradeAction::UpgradeHost
                );
                assert_eq!(agent_protocol_version, mvm_guest::vsock::PROTOCOL_VERSION);
            }
            other => panic!("expected ProtocolMismatch, got {other:?}"),
        }

        // After the mismatch the agent closed the connection: another
        // read returns either an EOF/read error or no further bytes.
        // We assert the read does not succeed with a fresh response —
        // i.e. there is no second operational dispatch.
        let trailing: anyhow::Result<GuestResponse> = read_frame(&mut host);
        assert!(
            trailing.is_err(),
            "agent must close after ProtocolMismatch; got trailing {trailing:?}"
        );

        handle.join().expect("handle_client thread");
    }

    fn make_state(
        entries: Vec<(IntegrationEntry, Option<IntegrationHealthResult>)>,
    ) -> Arc<Mutex<IntegrationState>> {
        let integrations = entries
            .into_iter()
            .map(|(entry, last_result)| IntegrationHealth { entry, last_result })
            .collect();
        Arc::new(Mutex::new(IntegrationState { integrations }))
    }

    fn entry_with_grace(name: &str, grace_secs: u64) -> IntegrationEntry {
        IntegrationEntry {
            name: name.to_string(),
            checkpoint_cmd: None,
            restore_cmd: None,
            critical: false,
            health_cmd: Some("true".to_string()),
            health_interval_secs: 10,
            health_timeout_secs: 5,
            startup_grace_secs: grace_secs,
        }
    }

    fn unhealthy_result() -> IntegrationHealthResult {
        IntegrationHealthResult {
            healthy: false,
            detail: "connection refused".to_string(),
            checked_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn healthy_result() -> IntegrationHealthResult {
        IntegrationHealthResult {
            healthy: true,
            detail: "ok".to_string(),
            checked_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_grace_period_unhealthy_returns_starting() {
        // Boot happened 5 seconds ago, grace period is 60 seconds
        let boot_at = std::time::Instant::now() - Duration::from_secs(5);
        let state = make_state(vec![(
            entry_with_grace("app", 60),
            Some(unhealthy_result()),
        )]);

        let reports = build_integration_reports(&state, boot_at);
        assert_eq!(reports.len(), 1);
        assert!(
            matches!(reports[0].status, IntegrationStatus::Starting),
            "Expected Starting during grace period, got {:?}",
            reports[0].status
        );
    }

    #[test]
    fn test_grace_period_expired_returns_error() {
        // Boot happened 120 seconds ago, grace period is 60 seconds
        let boot_at = std::time::Instant::now() - Duration::from_secs(120);
        let state = make_state(vec![(
            entry_with_grace("app", 60),
            Some(unhealthy_result()),
        )]);

        let reports = build_integration_reports(&state, boot_at);
        assert_eq!(reports.len(), 1);
        assert!(
            matches!(reports[0].status, IntegrationStatus::Error(_)),
            "Expected Error after grace period, got {:?}",
            reports[0].status
        );
    }

    #[test]
    fn test_grace_period_no_result_returns_starting() {
        // Boot happened 5 seconds ago, no health check result yet
        let boot_at = std::time::Instant::now() - Duration::from_secs(5);
        let state = make_state(vec![(entry_with_grace("app", 60), None)]);

        let reports = build_integration_reports(&state, boot_at);
        assert_eq!(reports.len(), 1);
        assert!(
            matches!(reports[0].status, IntegrationStatus::Starting),
            "Expected Starting for no-result during grace, got {:?}",
            reports[0].status
        );
    }

    #[test]
    fn test_no_grace_period_no_result_returns_pending() {
        let boot_at = std::time::Instant::now() - Duration::from_secs(5);
        let state = make_state(vec![(entry_with_grace("app", 0), None)]);

        let reports = build_integration_reports(&state, boot_at);
        assert_eq!(reports.len(), 1);
        assert!(
            matches!(reports[0].status, IntegrationStatus::Pending),
            "Expected Pending with no grace and no result, got {:?}",
            reports[0].status
        );
    }

    #[test]
    fn test_healthy_returns_active_regardless_of_grace() {
        let boot_at = std::time::Instant::now() - Duration::from_secs(5);
        let state = make_state(vec![(entry_with_grace("app", 60), Some(healthy_result()))]);

        let reports = build_integration_reports(&state, boot_at);
        assert_eq!(reports.len(), 1);
        assert!(
            matches!(reports[0].status, IntegrationStatus::Active),
            "Expected Active for healthy integration, got {:?}",
            reports[0].status
        );
    }

    /// Regression: the port forwarder's TCP connect target must remain
    /// loopback. Anything else would let traffic exit the guest's network
    /// namespace, defeating the "no host network from guest" claim. If you
    /// ever need to make this configurable, update the threat model first.
    #[test]
    fn test_port_forward_target_is_loopback() {
        assert_eq!(PORT_FORWARD_TCP_HOST, "127.0.0.1");
        let parsed: std::net::IpAddr = PORT_FORWARD_TCP_HOST.parse().unwrap();
        assert!(parsed.is_loopback(), "port-forward target must be loopback");
    }

    #[test]
    fn unix_forward_guest_path_is_confined_to_run_mvm() {
        validate_unix_forward_guest_path("/run/mvm/ssh-agent.sock").expect("valid path");
        let relative = validate_unix_forward_guest_path("run/mvm/ssh-agent.sock")
            .expect_err("relative path rejected");
        assert!(relative.to_string().contains("absolute"));
        let outside =
            validate_unix_forward_guest_path("/tmp/ssh-agent.sock").expect_err("outside rejected");
        assert!(outside.to_string().contains("under /run/mvm"));
    }

    // ─── lifecycle-hook wiring tests ──────────────────
    //
    // The production agent points at `/etc/mvm/hooks/{after_start,
    // before_stop}.sh` baked by the Nix factory. The unit tests below
    // exercise the wiring helpers against tempdir-baked scripts via
    // the underlying `mvm_guest::lifecycle_hooks` API — the production
    // wrappers (`wait_for_after_start`, `run_before_stop_hook`) are
    // thin path-resolution + logging shells over that API, so we test
    // the API contract end-to-end through them by parameterizing on
    // the path. Direct calls to `wait_for_after_start` /
    // `run_before_stop_hook` exercise the const-path wrappers and
    // assert they tolerate a missing production hook (the agent's
    // unit-test environment never has `/etc/mvm/hooks/*` baked).

    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path as StdPath;

    fn write_hook_script(dir: &StdPath, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        let mut f = fs::File::create(&p).expect("create hook script");
        f.write_all(body.as_bytes()).expect("write hook body");
        let mut perms = fs::metadata(&p).expect("hook metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&p, perms).expect("chmod hook");
        p
    }

    #[test]
    fn run_before_stop_hook_tolerates_missing_production_path() {
        // The const path `/etc/mvm/hooks/before_stop.sh` does not
        // exist in unit-test environments. The wrapper must not
        // panic, must not exit, must log + continue. We can't easily
        // assert log content here, so the assertion is "this returns
        // without panicking" — the wrapper has no return value.
        run_before_stop_hook();
    }

    #[test]
    fn run_shutdown_hook_via_lifecycle_api_writes_marker() {
        // A workload whose before_stop.sh writes a marker file proves
        // shutdown hooks fired on clean teardown. We can't reach the
        // const path, but we can prove the underlying API the wrapper
        // calls honors the contract.
        let tmp = tempfile::tempdir().expect("tempdir");
        let marker = tmp.path().join("stopped.marker");
        let body = format!(
            "#!/bin/sh\necho fired > {marker}\n",
            marker = marker.display()
        );
        let script = write_hook_script(tmp.path(), "before_stop.sh", &body);
        lifecycle_hooks::run_shutdown_hook(&script, SHUTDOWN_HOOK_GRACE, SHUTDOWN_HOOK_POLL)
            .expect("clean shutdown hook");
        let contents = fs::read_to_string(&marker).expect("marker file present");
        assert_eq!(contents.trim(), "fired");
    }

    #[test]
    fn run_shutdown_hook_via_lifecycle_api_kills_after_grace() {
        // The shutdown wrapper SIGKILLs a runaway hook after the
        // configured grace deadline so a buggy `before_stop.sh`
        // can't wedge teardown.
        let tmp = tempfile::tempdir().expect("tempdir");
        let script = write_hook_script(tmp.path(), "slow.sh", "#!/bin/sh\nsleep 5\n");
        let err = lifecycle_hooks::run_shutdown_hook(
            &script,
            Duration::from_millis(200),
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            lifecycle_hooks::ShutdownError::GraceExceeded { .. }
        ));
    }

    #[test]
    fn readiness_constants_match_plan_73() {
        // Lock in the readiness tunables — guards against an accidental
        // edit that would silently soften the readiness deadline.
        assert_eq!(READINESS_TIMEOUT, Duration::from_secs(30));
        assert_eq!(READINESS_INTERVAL, Duration::from_millis(200));
        assert_eq!(SHUTDOWN_HOOK_GRACE, Duration::from_secs(10));
        assert_eq!(SHUTDOWN_HOOK_POLL, Duration::from_millis(200));
        assert_eq!(AFTER_START_HOOK, "/etc/mvm/hooks/after_start.sh");
        assert_eq!(BEFORE_STOP_HOOK, "/etc/mvm/hooks/before_stop.sh");
    }

    // ─── AgentBootState transitions ────

    fn fresh_boot_state() -> AgentBootState {
        AgentBootState::new(AgentProfile::SealedProd, std::time::Instant::now())
    }

    #[test]
    fn boot_state_starts_with_starting_control_plane_and_entrypoint() {
        let s = fresh_boot_state().snapshot();
        assert_eq!(s.control_plane, ComponentState::Starting);
        assert_eq!(s.entrypoint, ComponentState::Starting);
        // Optional subsystems default to Disabled — they only flip
        // to Starting when their background init thread actually runs.
        assert_eq!(s.warm_pool, ComponentState::Disabled);
        assert_eq!(s.integrations, ComponentState::Disabled);
        assert_eq!(s.probes, ComponentState::Disabled);
        assert_eq!(s.volumes, ComponentState::Disabled);
    }

    #[test]
    fn mark_vsock_bound_flips_control_plane_to_ready_and_stamps_timing() {
        let bs = fresh_boot_state();
        bs.mark_vsock_bound();
        let s = bs.snapshot();
        assert_eq!(s.control_plane, ComponentState::Ready);
        assert!(s.boot_millis.vsock_bound_ms.is_some());
        assert!(s.boot_millis.agent_started_ms.is_some());
    }

    #[test]
    fn set_entrypoint_ready_stamps_entrypoint_ready_ms_once() {
        let bs = fresh_boot_state();
        bs.set_entrypoint(ComponentState::Ready);
        let t1 = bs.snapshot().boot_millis.entrypoint_ready_ms;
        assert!(t1.is_some());
        // A later transition (e.g. PostRestore reset) must not
        // overwrite the original timing — readers polling for
        // cold-path stats want the FIRST ready time, not the most
        // recent.
        std::thread::sleep(std::time::Duration::from_millis(2));
        bs.set_entrypoint(ComponentState::Failed {
            message: "synthetic".to_string(),
        });
        let t2 = bs.snapshot().boot_millis.entrypoint_ready_ms;
        assert_eq!(t1, t2);
    }

    #[test]
    fn set_integrations_starting_then_ready_stamps_timing() {
        let bs = fresh_boot_state();
        // The init helpers go through Starting first; only that path
        // should stamp the timing. A direct Disabled → Disabled
        // transition must NOT stamp.
        bs.set_integrations(ComponentState::Disabled);
        assert!(bs.snapshot().boot_millis.integrations_ready_ms.is_none());

        bs.set_integrations(ComponentState::Starting);
        assert!(bs.snapshot().boot_millis.integrations_ready_ms.is_none());

        bs.set_integrations(ComponentState::Ready);
        assert!(bs.snapshot().boot_millis.integrations_ready_ms.is_some());
    }

    #[test]
    fn set_integrations_starting_then_disabled_also_stamps() {
        // Empty drop-in dir: the background thread enters Starting,
        // scans, finds nothing, and flips to Disabled. That's still
        // a meaningful "scan completed" event — stamp the time so
        // a host can see cold-path latency includes the no-op scan.
        let bs = fresh_boot_state();
        bs.set_integrations(ComponentState::Starting);
        bs.set_integrations(ComponentState::Disabled);
        assert!(bs.snapshot().boot_millis.integrations_ready_ms.is_some());
    }

    #[test]
    fn set_warm_pool_only_stamps_after_first_starting_transition() {
        let bs = fresh_boot_state();
        // Initial Disabled (Default) → Disabled (cold-tier image,
        // no warm-pool config). No Starting in between → no stamp.
        bs.set_warm_pool(ComponentState::Disabled);
        assert!(bs.snapshot().boot_millis.warm_pool_ready_ms.is_none());

        bs.set_warm_pool(ComponentState::Starting);
        bs.set_warm_pool(ComponentState::Ready);
        assert!(bs.snapshot().boot_millis.warm_pool_ready_ms.is_some());
    }
}
