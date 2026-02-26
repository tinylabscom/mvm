use serde::{Deserialize, Serialize};

use crate::security::{GateDecision, ThreatFinding};

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
}
