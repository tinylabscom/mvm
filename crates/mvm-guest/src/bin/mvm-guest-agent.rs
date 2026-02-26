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
use mvm_guest::vsock::{GUEST_AGENT_PORT, GuestRequest, GuestResponse};
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
                cli_port = args.get(i).and_then(|v| v.parse().ok());
            }
            "--busy-threshold" => {
                i += 1;
                cli_threshold = args.get(i).and_then(|v| v.parse().ok());
            }
            "--sample-interval" => {
                i += 1;
                cli_interval = args.get(i).and_then(|v| v.parse().ok());
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
        None => std::fs::read_to_string(DEFAULT_CONFIG_PATH)
            .ok()
            .and_then(|data| serde_json::from_str::<AgentConfig>(&data).ok())
            .unwrap_or_default(),
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

    let timeout = entry.health_timeout_secs;
    let timeout_cmd = format!("timeout {} {}", timeout, cmd);
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&timeout_cmd)
        .output();

    match output {
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
            if !result.healthy {
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
fn build_integration_reports(
    integration_state: &Arc<Mutex<IntegrationState>>,
) -> Vec<IntegrationStateReport> {
    let Ok(s) = integration_state.lock() else {
        return vec![];
    };
    s.integrations
        .iter()
        .map(|ih| {
            let status = match &ih.last_result {
                Some(r) if r.healthy => IntegrationStatus::Active,
                Some(r) => IntegrationStatus::Error(r.detail.clone()),
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
    let _ = file.write_all(&len);
    let _ = file.write_all(&data);
    let _ = file.flush();
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

fn handle_client(
    fd: RawFd,
    state: &Arc<Mutex<AgentState>>,
    integration_state: &Arc<Mutex<IntegrationState>>,
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
            integrations: build_integration_reports(integration_state),
        },

        GuestRequest::CheckpointIntegrations { integrations: _ } => {
            GuestResponse::CheckpointResult {
                success: true,
                failed: vec![],
                detail: None,
            }
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

    eprintln!(
        "mvm-guest-agent: listening on vsock port {} ({} integrations)",
        cfg.port, integration_count
    );

    loop {
        // SAFETY: null addr pointers are allowed for accept when peer addr is not needed.
        let cfd = unsafe { accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if cfd < 0 {
            continue;
        }
        handle_client(cfd, &state, &integration_state);
    }
}
