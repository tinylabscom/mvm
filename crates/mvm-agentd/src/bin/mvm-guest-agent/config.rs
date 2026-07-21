//! Agent CLI/JSON configuration: parsing, defaults, and usage text.

use std::path::PathBuf;

use mvm_agentd::vsock::GUEST_AGENT_PORT;
use serde::Deserialize;

pub(crate) const DEFAULT_CONFIG_PATH: &str = "/etc/mvm/agent.json";
pub(crate) const DEFAULT_BUSY_THRESHOLD: f64 = 0.1;
pub(crate) const DEFAULT_SAMPLE_INTERVAL_SECS: u64 = 5;

#[derive(Deserialize)]
pub(crate) struct AgentConfig {
    #[serde(default = "default_port")]
    pub(crate) port: u32,
    #[serde(default = "default_busy_threshold")]
    pub(crate) busy_threshold: f64,
    #[serde(default = "default_sample_interval_secs")]
    pub(crate) sample_interval_secs: u64,
}

pub(crate) fn default_port() -> u32 {
    GUEST_AGENT_PORT
}
pub(crate) fn default_busy_threshold() -> f64 {
    DEFAULT_BUSY_THRESHOLD
}
pub(crate) fn default_sample_interval_secs() -> u64 {
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

pub(crate) fn print_usage() {
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

pub(crate) fn parse_config() -> AgentConfig {
    let (cfg, resolved_path) = parse_config_with_path();
    // Stash the resolved config path so the SIGHUP handler's
    // `apply_reload` re-reads the same file the operator launched
    // against (handles `--config <path>` overrides).
    let _ = crate::globals::AGENT_CONFIG_PATH.set(resolved_path);
    cfg
}

/// Test seam — returns the resolved path the file was read from
/// (or the default path if nothing was found) alongside the
/// parsed config. Production goes through [`parse_config`].
pub(crate) fn parse_config_with_path() -> (AgentConfig, PathBuf) {
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
