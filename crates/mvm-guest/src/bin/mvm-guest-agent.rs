//! Guest vsock agent — runs inside the microVM, listens on vsock port 52.
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
//!   --port <port>              Vsock port to listen on (default: 52)
//!   --busy-threshold <float>   Load average threshold for busy (default: 0.1)
//!   --sample-interval <secs>   Monitoring sample interval (default: 5)
//!   --help, -h                 Print usage
//! ```

use std::io::{Read, Write};
use std::mem::size_of;
use std::os::fd::{FromRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mvm_guest::integrations::{
    self, IntegrationEntry, IntegrationHealthResult, IntegrationStateReport, IntegrationStatus,
};
use mvm_guest::probes::{self, ProbeEntry, ProbeOutputFormat, ProbeResult};
use mvm_guest::vsock::{FsChange, FsChangeKind, GUEST_AGENT_PORT, GuestRequest, GuestResponse};
use serde::Deserialize;

// ============================================================================
// Configuration
// ============================================================================

const DEFAULT_CONFIG_PATH: &str = "/etc/mvm/agent.json";
const DEFAULT_BUSY_THRESHOLD: f64 = 0.1;
const DEFAULT_SAMPLE_INTERVAL_SECS: u64 = 5;

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

    cfg
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
fn monitoring_loop(state: Arc<Mutex<AgentState>>, busy_threshold: f64, sample_interval: Duration) {
    loop {
        let load = sample_load();
        if let Ok(mut s) = state.lock() {
            if load >= busy_threshold {
                s.status = "busy".to_string();
                s.last_busy_at = Some(utc_now());
            } else {
                s.status = "idle".to_string();
            }
        }
        std::thread::sleep(sample_interval);
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

/// Maximum output size per stream (1 MiB) to prevent OOM from unbounded output.
#[cfg(feature = "dev-shell")]
const MAX_EXEC_OUTPUT: usize = 1024 * 1024;

/// Run a command via `sh -c` and capture output (dev-only, feature-gated).
#[cfg(feature = "dev-shell")]
fn do_exec(command: &str, stdin_data: Option<&str>, _timeout_secs: u64) -> GuestResponse {
    use std::process::{Command, Stdio};

    let mut child = match Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return GuestResponse::ExecResult {
                exit_code: -1,
                stdout: String::new(),
                stderr: format!("failed to spawn: {}", e),
            };
        }
    };

    if let Some(data) = stdin_data {
        if let Some(ref mut pipe) = child.stdin {
            if let Err(e) = pipe.write_all(data.as_bytes()) {
                eprintln!("failed to write to pipe: {e}");
            }
        }
    }
    drop(child.stdin.take());

    match child.wait_with_output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let truncate = |s: &str| -> String {
                if s.len() > MAX_EXEC_OUTPUT {
                    let mut t = s[..MAX_EXEC_OUTPUT].to_string();
                    t.push_str("\n... (truncated)");
                    t
                } else {
                    s.to_string()
                }
            };
            GuestResponse::ExecResult {
                exit_code: out.status.code().unwrap_or(-1),
                stdout: truncate(&stdout),
                stderr: truncate(&stderr),
            }
        }
        Err(e) => GuestResponse::ExecResult {
            exit_code: -1,
            stdout: String::new(),
            stderr: format!("wait failed: {}", e),
        },
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
    boot_at: std::time::Instant,
) {
    // SAFETY: fd comes from accept and is a valid file descriptor owned by this function.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };

    let Some(req) = read_request(&mut file) else {
        return;
    };

    let resp = match req {
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

        GuestRequest::PostRestore => {
            // Send SIGUSR1 to PID 1 to trigger drive remount + service restart.
            let result = std::process::Command::new("kill")
                .args(["-USR1", "1"])
                .output();
            match result {
                Ok(out) if out.status.success() => GuestResponse::PostRestoreAck {
                    success: true,
                    detail: Some("post-restore signal sent to init".to_string()),
                },
                Ok(out) => GuestResponse::PostRestoreAck {
                    success: false,
                    detail: Some(format!(
                        "kill failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    )),
                },
                Err(e) => GuestResponse::PostRestoreAck {
                    success: false,
                    detail: Some(format!("failed to send signal: {}", e)),
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
            let allowed = mvm_guest::builder_agent::load_security_policy()
                .ok()
                .flatten()
                .is_some_and(|p| p.access.debug_exec);
            if !allowed {
                GuestResponse::Error {
                    message: "exec rejected: access.debug_exec not enabled in security policy"
                        .to_string(),
                }
            } else {
                do_exec(&command, stdin.as_deref(), timeout_secs.unwrap_or(30))
            }
        }

        #[cfg(not(feature = "dev-shell"))]
        GuestRequest::Exec { .. } => GuestResponse::Error {
            message: "exec not available: guest agent built without dev-shell feature".to_string(),
        },

        GuestRequest::FsDiff => {
            // Walk the overlay upper dir to find changes since boot.
            // The overlay upper dir is typically at /overlay/upper when
            // the rootfs is mounted read-only with an overlay.
            let changes = collect_fs_diff();
            GuestResponse::FsDiffResult { changes }
        }
    };

    write_response(&mut file, &resp);
}

// ============================================================================
// Entry point
// ============================================================================

fn main() {
    let cfg = parse_config();

    eprintln!(
        "mvm-guest-agent: starting on vsock port {} (threshold={}, interval={}s)",
        cfg.port, cfg.busy_threshold, cfg.sample_interval_secs
    );

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

    // Start background monitoring thread.
    let state = Arc::new(Mutex::new(AgentState::new()));
    let monitor_state = Arc::clone(&state);
    let busy_threshold = cfg.busy_threshold;
    let sample_interval = Duration::from_secs(cfg.sample_interval_secs);
    std::thread::spawn(move || monitoring_loop(monitor_state, busy_threshold, sample_interval));

    // Scan drop-in integrations and start health check thread.
    let entries = integrations::load_dropin_dir(integrations::INTEGRATIONS_DROPIN_DIR);
    let integration_count = entries.len();
    let integration_state = Arc::new(Mutex::new(IntegrationState {
        integrations: entries
            .into_iter()
            .map(|e| IntegrationHealth {
                entry: e,
                last_result: None,
            })
            .collect(),
    }));
    if integration_count > 0 {
        let health_state = Arc::clone(&integration_state);
        std::thread::spawn(move || integration_health_loop(health_state));
    }

    // Scan drop-in probes and start probe execution thread.
    let probe_entries = probes::load_probe_dropin_dir(probes::PROBES_DROPIN_DIR);
    let probe_count = probe_entries.len();
    let probe_state = Arc::new(Mutex::new(ProbeState {
        probes: probe_entries
            .into_iter()
            .map(|e| ProbeHealth {
                entry: e,
                last_result: None,
            })
            .collect(),
    }));
    if probe_count > 0 {
        let health_probe_state = Arc::clone(&probe_state);
        std::thread::spawn(move || probe_health_loop(health_probe_state));
    }

    eprintln!(
        "mvm-guest-agent: listening on vsock port {} ({} integrations, {} probes)",
        cfg.port, integration_count, probe_count
    );

    loop {
        // SAFETY: null addr pointers are allowed for accept when peer addr is not needed.
        let cfd = unsafe { accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if cfd < 0 {
            continue;
        }
        handle_client(cfd, &state, &integration_state, &probe_state, boot_at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_guest::integrations::{IntegrationEntry, IntegrationHealthResult, IntegrationStatus};

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
}
