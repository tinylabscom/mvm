use serde::{Deserialize, Serialize};

// ============================================================================
// Integration state model — structured layout for integration session state
// on the data disk. The guest agent checkpoints integration state before
// sleep and restores it on wake. Any workload can register itself by
// dropping a JSON file into the drop-in directory.
// ============================================================================

/// Base path inside the guest where integration state is stored.
pub const INTEGRATIONS_BASE_PATH: &str = "/data/integrations";

/// Directory where integration drop-in files are placed.
/// Each `*.json` file declares one integration the guest agent should monitor.
pub const INTEGRATIONS_DROPIN_DIR: &str = "/etc/mvm/integrations.d";

/// Manifest listing active integrations for an instance.
/// Written to the config drive so the guest agent knows which
/// integrations to manage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntegrationManifest {
    pub integrations: Vec<IntegrationEntry>,
}

/// An individual integration to manage on this instance.
///
/// Typically declared via a JSON drop-in file in `/etc/mvm/integrations.d/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationEntry {
    /// Integration name (e.g. "openclaw-worker", "my-service").
    /// Used as the directory name under /data/integrations/.
    pub name: String,
    /// Optional command to run before sleep to checkpoint state.
    /// If None, the integration manager only ensures state dirs exist.
    #[serde(default)]
    pub checkpoint_cmd: Option<String>,
    /// Optional command to run after wake to restore state.
    #[serde(default)]
    pub restore_cmd: Option<String>,
    /// If true, sleep is blocked until this integration successfully checkpoints.
    /// If false, checkpoint failure is logged but sleep proceeds.
    #[serde(default)]
    pub critical: bool,
    /// Command to run for health checks. Exit 0 = healthy, non-zero = unhealthy.
    /// Stderr is captured as the error detail on failure.
    #[serde(default)]
    pub health_cmd: Option<String>,
    /// Interval in seconds between health checks (default: 30).
    #[serde(default = "default_health_interval")]
    pub health_interval_secs: u64,
    /// Timeout in seconds for each health check execution (default: 10).
    #[serde(default = "default_health_timeout")]
    pub health_timeout_secs: u64,
    /// Grace period in seconds after boot before logging health failures (default: 0).
    /// During the grace period, health checks still run and results are stored
    /// (so the host can poll), but failures are not logged to console.
    #[serde(default)]
    pub startup_grace_secs: u64,
}

fn default_health_interval() -> u64 {
    30
}

fn default_health_timeout() -> u64 {
    10
}

/// Runtime status of a single integration on a guest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationStatus {
    /// Integration is running and connected.
    Active,
    /// Integration is paused (e.g. during checkpoint).
    Paused,
    /// Integration has an error.
    Error(String),
    /// Integration is not yet initialized.
    #[default]
    Pending,
    /// Integration is within its startup grace period — health checks are
    /// running but failures are suppressed until the grace window expires.
    Starting,
}

/// Result of a single health check execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationHealthResult {
    /// Whether the health check passed (exit code 0).
    pub healthy: bool,
    /// Human-readable detail ("ok" on success, stderr or exit code on failure).
    pub detail: String,
    /// ISO 8601 timestamp of when this check ran.
    pub checked_at: String,
}

/// Full state report for a single integration (returned by guest agent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationStateReport {
    pub name: String,
    pub status: IntegrationStatus,
    /// ISO timestamp of last successful checkpoint.
    #[serde(default)]
    pub last_checkpoint_at: Option<String>,
    /// Bytes of state data on disk.
    #[serde(default)]
    pub state_size_bytes: u64,
    /// Latest health check result, if a health_cmd is configured.
    #[serde(default)]
    pub health: Option<IntegrationHealthResult>,
}

impl IntegrationManifest {
    /// Parse from JSON.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

/// Generate the guest-side state directory path for an integration.
pub fn integration_state_dir(name: &str) -> String {
    format!("{}/{}/state", INTEGRATIONS_BASE_PATH, name)
}

/// Generate the guest-side checkpoint marker path for an integration.
pub fn integration_checkpoint_path(name: &str) -> String {
    format!("{}/{}/checkpoint", INTEGRATIONS_BASE_PATH, name)
}

/// Load integration entries from a drop-in directory.
///
/// Reads all `*.json` files in `dir`, parsing each as an [`IntegrationEntry`].
/// Invalid files are logged to stderr and skipped. Returns an empty vec if the
/// directory does not exist.
pub fn load_dropin_dir(dir: &str) -> Vec<IntegrationEntry> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        eprintln!(
            "mvm-guest-agent: integrations dir {} not found, no integrations",
            dir
        );
        return vec![];
    };
    let mut result = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(data) => match serde_json::from_str::<IntegrationEntry>(&data) {
                Ok(ie) => {
                    eprintln!("mvm-guest-agent: loaded integration '{}'", ie.name);
                    result.push(ie);
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
    fn test_manifest_serde_roundtrip() {
        let manifest = IntegrationManifest {
            integrations: vec![
                IntegrationEntry {
                    name: "whatsapp".to_string(),
                    checkpoint_cmd: Some("/opt/openclaw/bin/whatsapp-checkpoint".to_string()),
                    restore_cmd: Some("/opt/openclaw/bin/whatsapp-restore".to_string()),
                    critical: true,
                    health_cmd: Some("/opt/openclaw/bin/whatsapp-health".to_string()),
                    health_interval_secs: 15,
                    health_timeout_secs: 5,
                    startup_grace_secs: 0,
                },
                IntegrationEntry {
                    name: "slack".to_string(),
                    checkpoint_cmd: None,
                    restore_cmd: None,
                    critical: false,
                    health_cmd: None,
                    health_interval_secs: default_health_interval(),
                    health_timeout_secs: default_health_timeout(),
                    startup_grace_secs: 0,
                },
            ],
        };

        let json = manifest.to_json().unwrap();
        let parsed = IntegrationManifest::from_json(&json).unwrap();
        assert_eq!(parsed.integrations.len(), 2);
        assert_eq!(parsed.integrations[0].name, "whatsapp");
        assert!(parsed.integrations[0].critical);
        assert!(parsed.integrations[0].checkpoint_cmd.is_some());
        assert_eq!(parsed.integrations[0].health_interval_secs, 15);
        assert_eq!(parsed.integrations[1].name, "slack");
        assert!(!parsed.integrations[1].critical);
        assert!(parsed.integrations[1].health_cmd.is_none());
    }

    #[test]
    fn test_empty_manifest() {
        let manifest = IntegrationManifest::default();
        let json = manifest.to_json().unwrap();
        let parsed = IntegrationManifest::from_json(&json).unwrap();
        assert!(parsed.integrations.is_empty());
    }

    #[test]
    fn test_integration_status_serde() {
        let variants = vec![
            (IntegrationStatus::Active, "\"active\""),
            (IntegrationStatus::Paused, "\"paused\""),
            (IntegrationStatus::Pending, "\"pending\""),
            (IntegrationStatus::Starting, "\"starting\""),
            (
                IntegrationStatus::Error("conn lost".to_string()),
                "{\"error\":\"conn lost\"}",
            ),
        ];

        for (status, expected) in &variants {
            let json = serde_json::to_string(status).unwrap();
            assert_eq!(&json, expected);
            let parsed: IntegrationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, status);
        }
    }

    #[test]
    fn test_integration_state_report_roundtrip() {
        let report = IntegrationStateReport {
            name: "telegram".to_string(),
            status: IntegrationStatus::Active,
            last_checkpoint_at: Some("2025-06-01T12:00:00Z".to_string()),
            state_size_bytes: 4096,
            health: Some(IntegrationHealthResult {
                healthy: true,
                detail: "ok".to_string(),
                checked_at: "2025-06-01T12:00:05Z".to_string(),
            }),
        };

        let json = serde_json::to_string(&report).unwrap();
        let parsed: IntegrationStateReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "telegram");
        assert_eq!(parsed.status, IntegrationStatus::Active);
        assert_eq!(parsed.state_size_bytes, 4096);
        assert!(parsed.health.unwrap().healthy);
    }

    #[test]
    fn test_state_dir_paths() {
        assert_eq!(
            integration_state_dir("whatsapp"),
            "/data/integrations/whatsapp/state"
        );
        assert_eq!(
            integration_checkpoint_path("telegram"),
            "/data/integrations/telegram/checkpoint"
        );
    }

    #[test]
    fn test_integration_status_default() {
        assert_eq!(IntegrationStatus::default(), IntegrationStatus::Pending);
    }

    #[test]
    fn test_manifest_backward_compat() {
        // JSON without optional fields (including new health fields) should parse fine
        let json = r#"{"integrations": [{"name": "signal"}]}"#;
        let parsed = IntegrationManifest::from_json(json).unwrap();
        assert_eq!(parsed.integrations.len(), 1);
        assert_eq!(parsed.integrations[0].name, "signal");
        assert!(parsed.integrations[0].checkpoint_cmd.is_none());
        assert!(!parsed.integrations[0].critical);
        // Health fields get defaults
        assert!(parsed.integrations[0].health_cmd.is_none());
        assert_eq!(parsed.integrations[0].health_interval_secs, 30);
        assert_eq!(parsed.integrations[0].health_timeout_secs, 10);
    }

    #[test]
    fn test_integration_entry_health_fields_serde() {
        let entry = IntegrationEntry {
            name: "myapp".to_string(),
            checkpoint_cmd: None,
            restore_cmd: None,
            critical: false,
            health_cmd: Some("systemctl is-active myapp".to_string()),
            health_interval_secs: 15,
            health_timeout_secs: 5,
            startup_grace_secs: 30,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: IntegrationEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.health_cmd.as_deref(),
            Some("systemctl is-active myapp")
        );
        assert_eq!(parsed.health_interval_secs, 15);
        assert_eq!(parsed.health_timeout_secs, 5);
    }

    #[test]
    fn test_integration_health_result_serde() {
        let result = IntegrationHealthResult {
            healthy: false,
            detail: "exit code 1".to_string(),
            checked_at: "2025-06-01T12:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: IntegrationHealthResult = serde_json::from_str(&json).unwrap();
        assert!(!parsed.healthy);
        assert_eq!(parsed.detail, "exit code 1");
        assert_eq!(parsed.checked_at, "2025-06-01T12:00:00Z");
    }

    #[test]
    fn test_state_report_health_none_compat() {
        // State report without health field (backward compat with old agents)
        let json = r#"{"name":"old","status":"active","state_size_bytes":0}"#;
        let parsed: IntegrationStateReport = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.name, "old");
        assert!(parsed.health.is_none());
    }

    #[test]
    fn test_load_dropin_dir_nonexistent() {
        let entries = load_dropin_dir("/tmp/mvm-test-nonexistent-dropin-dir");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_load_dropin_dir_with_files() {
        let dir = std::env::temp_dir().join("mvm-test-dropin");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Valid integration file
        std::fs::write(
            dir.join("myapp.json"),
            r#"{"name":"myapp","health_cmd":"echo ok","health_interval_secs":10}"#,
        )
        .unwrap();

        // Non-json file should be ignored
        std::fs::write(dir.join("readme.txt"), "ignore me").unwrap();

        // Invalid JSON should be skipped
        std::fs::write(dir.join("bad.json"), "not json").unwrap();

        let entries = load_dropin_dir(dir.to_str().unwrap());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "myapp");
        assert_eq!(entries[0].health_cmd.as_deref(), Some("echo ok"));
        assert_eq!(entries[0].health_interval_secs, 10);
        assert_eq!(entries[0].health_timeout_secs, 10); // default

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dropin_dir_constant() {
        assert_eq!(INTEGRATIONS_DROPIN_DIR, "/etc/mvm/integrations.d");
    }
}
