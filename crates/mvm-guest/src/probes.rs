use serde::{Deserialize, Serialize};

// ============================================================================
// Probe model — read-only inspection checks for microVM introspection.
//
// Probes are separate from integrations: integrations have lifecycle hooks
// (checkpoint/restore for sleep/wake), while probes are purely observational.
// Each probe is defined by a JSON drop-in file in /etc/mvm/probes.d/ inside
// the guest rootfs, populated by the Nix flake at build time.
// ============================================================================

/// Directory where probe drop-in files are placed inside the guest.
/// Each `*.json` file declares one probe the guest agent should execute.
pub const PROBES_DROPIN_DIR: &str = "/etc/mvm/probes.d";

/// Output format for a probe command.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutputFormat {
    /// Healthy/unhealthy based on exit code. Stderr captured as detail.
    #[default]
    ExitCode,
    /// Parse stdout as JSON and include in the report.
    Json,
}

/// A probe definition loaded from `/etc/mvm/probes.d/*.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeEntry {
    /// Probe name (e.g. "disk-usage", "gpu-status").
    pub name: String,
    /// Human-readable description of what this probe checks.
    #[serde(default)]
    pub description: Option<String>,
    /// Shell command to execute.
    pub cmd: String,
    /// Interval in seconds between probe executions (default: 30).
    #[serde(default = "default_probe_interval")]
    pub interval_secs: u64,
    /// Timeout in seconds for each probe execution (default: 10).
    #[serde(default = "default_probe_timeout")]
    pub timeout_secs: u64,
    /// Output format (default: exit_code).
    #[serde(default)]
    pub output_format: ProbeOutputFormat,
}

fn default_probe_interval() -> u64 {
    30
}

fn default_probe_timeout() -> u64 {
    10
}

/// Result of running a single probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Probe name.
    pub name: String,
    /// Whether the probe passed (exit code 0).
    pub healthy: bool,
    /// Human-readable detail (stderr for exit_code mode, error message on failure).
    pub detail: String,
    /// Parsed stdout JSON (only for json output_format, None otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    /// ISO 8601 timestamp of when this probe ran.
    pub checked_at: String,
}

/// Load probe entries from a drop-in directory.
///
/// Reads all `*.json` files in `dir`, parsing each as a [`ProbeEntry`].
/// Invalid files are logged to stderr and skipped. Returns an empty vec
/// if the directory does not exist.
pub fn load_probe_dropin_dir(dir: &str) -> Vec<ProbeEntry> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        eprintln!("mvm-guest-agent: probes dir {} not found, no probes", dir);
        return vec![];
    };
    let mut result = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(data) => match serde_json::from_str::<ProbeEntry>(&data) {
                Ok(pe) => {
                    eprintln!("mvm-guest-agent: loaded probe '{}'", pe.name);
                    result.push(pe);
                }
                Err(e) => eprintln!("mvm-guest-agent: failed to parse {:?}: {}", path, e),
            },
            Err(e) => eprintln!("mvm-guest-agent: failed to read {:?}: {}", path, e),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_entry_serde_roundtrip() {
        let entry = ProbeEntry {
            name: "disk-usage".to_string(),
            description: Some("Check disk space".to_string()),
            cmd: "df -h / | awk 'NR==2{print $5}'".to_string(),
            interval_secs: 60,
            timeout_secs: 5,
            output_format: ProbeOutputFormat::Json,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: ProbeEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "disk-usage");
        assert_eq!(parsed.description.as_deref(), Some("Check disk space"));
        assert_eq!(parsed.interval_secs, 60);
        assert_eq!(parsed.timeout_secs, 5);
        assert_eq!(parsed.output_format, ProbeOutputFormat::Json);
    }

    #[test]
    fn test_probe_entry_defaults() {
        let json = r#"{"name":"disk","cmd":"df -h"}"#;
        let parsed: ProbeEntry = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.name, "disk");
        assert_eq!(parsed.cmd, "df -h");
        assert!(parsed.description.is_none());
        assert_eq!(parsed.interval_secs, 30);
        assert_eq!(parsed.timeout_secs, 10);
        assert_eq!(parsed.output_format, ProbeOutputFormat::ExitCode);
    }

    #[test]
    fn test_probe_output_format_serde() {
        let variants = vec![
            (ProbeOutputFormat::ExitCode, "\"exit_code\""),
            (ProbeOutputFormat::Json, "\"json\""),
        ];
        for (fmt, expected) in &variants {
            let json = serde_json::to_string(fmt).unwrap();
            assert_eq!(&json, expected);
            let parsed: ProbeOutputFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, fmt);
        }
    }

    #[test]
    fn test_probe_result_serde_roundtrip() {
        let result = ProbeResult {
            name: "disk-usage".to_string(),
            healthy: true,
            detail: "ok".to_string(),
            output: Some(serde_json::json!({"usage_pct": 42, "free_gb": 18})),
            checked_at: "2026-02-26T12:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ProbeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "disk-usage");
        assert!(parsed.healthy);
        assert!(parsed.output.is_some());
        let output = parsed.output.unwrap();
        assert_eq!(output["usage_pct"], 42);
        assert_eq!(output["free_gb"], 18);
    }

    #[test]
    fn test_probe_result_without_output() {
        let result = ProbeResult {
            name: "check".to_string(),
            healthy: false,
            detail: "exit code 1".to_string(),
            output: None,
            checked_at: "2026-02-26T12:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("output"), "output:None should be skipped");
        let parsed: ProbeResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.output.is_none());
    }

    #[test]
    fn test_probe_dropin_dir_constant() {
        assert_eq!(PROBES_DROPIN_DIR, "/etc/mvm/probes.d");
    }

    #[test]
    fn test_load_probe_dropin_dir_nonexistent() {
        let entries = load_probe_dropin_dir("/tmp/mvm-test-nonexistent-probes-dir");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_load_probe_dropin_dir_with_files() {
        let dir = std::env::temp_dir().join("mvm-test-probes-dropin");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Valid probe file
        std::fs::write(
            dir.join("disk.json"),
            r#"{"name":"disk-usage","cmd":"df -h","interval_secs":15,"output_format":"json"}"#,
        )
        .unwrap();

        // Non-json file should be ignored
        std::fs::write(dir.join("readme.txt"), "ignore me").unwrap();

        // Invalid JSON should be skipped
        std::fs::write(dir.join("bad.json"), "not json").unwrap();

        let entries = load_probe_dropin_dir(dir.to_str().unwrap());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "disk-usage");
        assert_eq!(entries[0].cmd, "df -h");
        assert_eq!(entries[0].interval_secs, 15);
        assert_eq!(entries[0].timeout_secs, 10); // default
        assert_eq!(entries[0].output_format, ProbeOutputFormat::Json);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_probe_entry_backward_compat() {
        // Minimal JSON without optional fields should parse
        let json = r#"{"name":"simple","cmd":"true"}"#;
        let parsed: ProbeEntry = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.name, "simple");
        assert_eq!(parsed.cmd, "true");
        assert!(parsed.description.is_none());
        assert_eq!(parsed.interval_secs, 30);
        assert_eq!(parsed.timeout_secs, 10);
        assert_eq!(parsed.output_format, ProbeOutputFormat::ExitCode);
    }
}
