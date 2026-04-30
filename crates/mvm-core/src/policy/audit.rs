use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::security::{GateDecision, ThreatFinding};

// ============================================================================
// Local mvmctl audit log (single-host operations)
// ============================================================================

/// Default path for the local audit log.
///
/// Prefers XDG state directory (`~/.local/state/mvm/log/`). Falls back to
/// legacy `~/.mvm/log/` if an audit log already exists there.
pub fn default_audit_log() -> String {
    // Check legacy location for backward compat
    let legacy = format!("{}/log/audit.jsonl", crate::config::mvm_data_dir());
    if std::path::Path::new(&legacy).exists() {
        return legacy;
    }
    format!("{}/log/audit.jsonl", crate::config::mvm_state_dir())
}

/// Rotate when the audit log exceeds this size.
const ROTATE_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB

/// Categories of local mvmctl operations that are audit-logged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalAuditKind {
    VmStart,
    VmStop,
    KeyLookup,
    VolumeCreate,
    VolumeOpen,
    UpdateInstall,
    Uninstall,
    // --- DX features (Phase 2) ---
    NetworkCreate,
    NetworkRemove,
    ImageFetch,
    TemplateBuild,
    TemplatePush,
    TemplatePull,
    ConfigChange,
    ConsoleSessionStart,
    ConsoleSessionEnd,
    // --- MCP server (plan 32 / Proposal A) ---
    /// `tools/call run` invocation — every LLM-driven code execution
    /// against a microVM is auditable.
    McpToolsCallRun,
    /// `tools/call run` failed before completing (orchestration error,
    /// not a non-zero guest exit code).
    McpToolsCallRunError,
    /// MCP session opened — first call with a previously-unseen
    /// `session=ID` parameter (plan 32 / Proposal A.2).
    McpSessionStarted,
    /// MCP session closed by the client (`close: true`) or reaped
    /// by the server (idle / max-lifetime / shutdown drain).
    McpSessionClosed,
}

/// A single local audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAuditEvent {
    pub timestamp: String,
    pub kind: LocalAuditKind,
    pub vm_name: Option<String>,
    pub detail: Option<String>,
}

impl LocalAuditEvent {
    /// Create an event stamped with the current UTC time.
    pub fn now(kind: LocalAuditKind, vm_name: Option<String>, detail: Option<String>) -> Self {
        let timestamp = chrono::Utc::now().to_rfc3339();
        Self {
            timestamp,
            kind,
            vm_name,
            detail,
        }
    }
}

/// Append-only local audit log writer.
pub struct LocalAuditLog {
    path: PathBuf,
}

impl LocalAuditLog {
    /// Open (or create) a local audit log at `path`.
    ///
    /// Creates parent directories if they don't exist.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create audit log dir: {}", parent.display()))?;
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// Append one JSONL line.  Rotates to `audit.jsonl.1` when the file
    /// exceeds [`ROTATE_THRESHOLD_BYTES`].
    pub fn append(&self, event: &LocalAuditEvent) -> Result<()> {
        self.maybe_rotate()?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("Failed to open audit log: {}", self.path.display()))?;

        let line = serde_json::to_string(event).context("Failed to serialize audit event")?;
        writeln!(file, "{line}").context("Failed to write audit event")?;
        Ok(())
    }

    fn maybe_rotate(&self) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }
        let meta = std::fs::metadata(&self.path)
            .with_context(|| format!("Failed to stat {}", self.path.display()))?;
        if meta.len() >= ROTATE_THRESHOLD_BYTES {
            let rotated = self.path.with_extension("jsonl.1");
            std::fs::rename(&self.path, &rotated)
                .with_context(|| format!("Failed to rotate audit log to {}", rotated.display()))?;
        }
        Ok(())
    }
}

/// Emit a local audit event to the default log path (best-effort).
///
/// Errors are logged via `tracing::warn!` and never propagated — audit
/// failures must not block the operation being logged.
pub fn emit(kind: LocalAuditKind, vm_name: Option<&str>, detail: Option<&str>) {
    let event = LocalAuditEvent::now(kind, vm_name.map(str::to_owned), detail.map(str::to_owned));
    let path = PathBuf::from(default_audit_log());
    match LocalAuditLog::open(&path).and_then(|log| log.append(&event)) {
        Ok(()) => {}
        Err(e) => tracing::warn!("audit log write failed: {e}"),
    }
}

/// Audit event types for per-tenant audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    // -- Instance lifecycle --
    InstanceCreated,
    InstanceStarted,
    InstanceStopped,
    InstanceWarmed,
    InstanceSlept,
    InstanceWoken,
    InstanceDestroyed,
    // -- Pool/Tenant --
    PoolCreated,
    PoolBuilt,
    PoolDestroyed,
    TenantCreated,
    TenantDestroyed,
    // -- Operational --
    QuotaExceeded,
    SecretsRotated,
    SnapshotCreated,
    SnapshotRestored,
    SnapshotDeleted,
    TransitionDeferred,
    MinRuntimeOverridden,
    // -- Vsock security (Phase 8) --
    VsockSessionStarted,
    VsockSessionEnded,
    VsockFrameReceived,
    CommandBlocked,
    CommandApproved,
    CommandDenied,
    ThreatDetected,
    RateLimitExceeded,
    SessionRecycled,
}

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub tenant_id: String,
    pub pool_id: Option<String>,
    pub instance_id: Option<String>,
    pub action: AuditAction,
    pub detail: Option<String>,
    /// Threat findings from the classifier (empty for non-security events).
    #[serde(default)]
    pub threats: Vec<ThreatFinding>,
    /// Gate decision for command-gated events.
    #[serde(default)]
    pub gate_decision: Option<GateDecision>,
    /// Vsock frame sequence number.
    #[serde(default)]
    pub frame_sequence: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            tenant_id: "acme".to_string(),
            pool_id: Some("workers".to_string()),
            instance_id: Some("i-abc123".to_string()),
            action: AuditAction::InstanceStarted,
            detail: Some("pid=12345".to_string()),
            threats: vec![],
            gate_decision: None,
            frame_sequence: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"tenant_id\":\"acme\""));
        assert!(json.contains("\"InstanceStarted\""));
    }

    #[test]
    fn test_audit_entry_no_optionals() {
        let entry = AuditEntry {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            tenant_id: "acme".to_string(),
            pool_id: None,
            instance_id: None,
            action: AuditAction::TenantCreated,
            detail: None,
            threats: vec![],
            gate_decision: None,
            frame_sequence: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"pool_id\":null"));
    }

    #[test]
    fn test_all_audit_actions_serialize() {
        let actions = vec![
            AuditAction::InstanceCreated,
            AuditAction::InstanceStarted,
            AuditAction::InstanceStopped,
            AuditAction::InstanceWarmed,
            AuditAction::InstanceSlept,
            AuditAction::InstanceWoken,
            AuditAction::InstanceDestroyed,
            AuditAction::PoolCreated,
            AuditAction::PoolBuilt,
            AuditAction::PoolDestroyed,
            AuditAction::TenantCreated,
            AuditAction::TenantDestroyed,
            AuditAction::QuotaExceeded,
            AuditAction::SecretsRotated,
            AuditAction::SnapshotCreated,
            AuditAction::SnapshotRestored,
            AuditAction::SnapshotDeleted,
            AuditAction::TransitionDeferred,
            AuditAction::MinRuntimeOverridden,
            AuditAction::VsockSessionStarted,
            AuditAction::VsockSessionEnded,
            AuditAction::VsockFrameReceived,
            AuditAction::CommandBlocked,
            AuditAction::CommandApproved,
            AuditAction::CommandDenied,
            AuditAction::ThreatDetected,
            AuditAction::RateLimitExceeded,
            AuditAction::SessionRecycled,
        ];

        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn test_audit_entry_backward_compat() {
        // Old-format JSON without new fields should still deserialize
        let json = r#"{
            "timestamp": "2025-01-01T00:00:00Z",
            "tenant_id": "acme",
            "pool_id": null,
            "instance_id": null,
            "action": "TenantCreated",
            "detail": null
        }"#;
        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.tenant_id, "acme");
        assert!(entry.threats.is_empty());
        assert!(entry.gate_decision.is_none());
        assert!(entry.frame_sequence.is_none());
    }

    #[test]
    fn test_audit_entry_with_security_fields() {
        use crate::security::{GateDecision, Severity, ThreatCategory, ThreatFinding};

        let entry = AuditEntry {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            tenant_id: "acme".to_string(),
            pool_id: None,
            instance_id: Some("i-001".to_string()),
            action: AuditAction::ThreatDetected,
            detail: Some("classified vsock frame".to_string()),
            threats: vec![ThreatFinding {
                category: ThreatCategory::Destructive,
                pattern_id: "rm_rf_root".to_string(),
                severity: Severity::Critical,
                matched_text: "rm -rf /".to_string(),
                context: "literal match".to_string(),
            }],
            gate_decision: Some(GateDecision::Blocked {
                pattern: "rm -rf /".to_string(),
                reason: "destructive".to_string(),
            }),
            frame_sequence: Some(42),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.threats.len(), 1);
        assert_eq!(parsed.threats[0].category, ThreatCategory::Destructive);
        assert!(parsed.gate_decision.is_some());
        assert_eq!(parsed.frame_sequence, Some(42));
    }

    // -------------------------------------------------------------------------
    // LocalAuditEvent / LocalAuditLog tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_local_audit_event_serializes() {
        let event = LocalAuditEvent::now(
            LocalAuditKind::VmStart,
            Some("my-vm".to_string()),
            Some("flake=.".to_string()),
        );
        let json = serde_json::to_string(&event).unwrap();
        let parsed: LocalAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.kind, LocalAuditKind::VmStart);
        assert_eq!(parsed.vm_name.as_deref(), Some("my-vm"));
        assert_eq!(parsed.detail.as_deref(), Some("flake=."));
        assert!(!parsed.timestamp.is_empty());
    }

    #[test]
    fn test_local_audit_kind_all_variants_serialize() {
        let kinds = [
            LocalAuditKind::VmStart,
            LocalAuditKind::VmStop,
            LocalAuditKind::KeyLookup,
            LocalAuditKind::VolumeCreate,
            LocalAuditKind::VolumeOpen,
            LocalAuditKind::UpdateInstall,
            LocalAuditKind::Uninstall,
            LocalAuditKind::NetworkCreate,
            LocalAuditKind::NetworkRemove,
            LocalAuditKind::ImageFetch,
            LocalAuditKind::TemplateBuild,
            LocalAuditKind::TemplatePush,
            LocalAuditKind::TemplatePull,
            LocalAuditKind::ConfigChange,
            LocalAuditKind::ConsoleSessionStart,
            LocalAuditKind::ConsoleSessionEnd,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn test_local_audit_log_append() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");

        let log = LocalAuditLog::open(&path).unwrap();
        let event = LocalAuditEvent::now(LocalAuditKind::VmStop, Some("vm1".to_string()), None);
        log.append(&event).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("vm_stop"));
        assert!(contents.contains("vm1"));
        // One line per event.
        assert_eq!(contents.lines().count(), 1);

        // Append a second event.
        let event2 = LocalAuditEvent::now(
            LocalAuditKind::UpdateInstall,
            None,
            Some("v1.2.3".to_string()),
        );
        log.append(&event2).unwrap();
        let contents2 = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents2.lines().count(), 2);
    }

    #[test]
    fn test_local_audit_log_rotation() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");

        // Write a file that exceeds the rotation threshold.
        let big_content = "x".repeat(ROTATE_THRESHOLD_BYTES as usize + 1);
        std::fs::write(&path, big_content).unwrap();

        let log = LocalAuditLog::open(&path).unwrap();
        let event = LocalAuditEvent::now(LocalAuditKind::Uninstall, None, None);
        log.append(&event).unwrap();

        // The rotated file should exist.
        let rotated = path.with_extension("jsonl.1");
        assert!(rotated.exists(), "rotation file should be created");

        // The new log file should contain only the new event.
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 1);
        assert!(contents.contains("uninstall"));
    }
}
