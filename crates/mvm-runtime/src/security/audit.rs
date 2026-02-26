use anyhow::{Context, Result};

pub use mvm_core::audit::{AuditAction, AuditEntry};
use mvm_core::tenant::tenant_audit_log_path;
use mvm_core::time;

use crate::shell;

/// Append an audit event to the tenant's audit log.
///
/// Each event is a single JSON line appended to `tenants/<tenant>/audit.log`.
/// The log is append-only — entries are never modified or deleted.
pub fn log_event(
    tenant_id: &str,
    pool_id: Option<&str>,
    instance_id: Option<&str>,
    action: AuditAction,
    detail: Option<&str>,
) -> Result<()> {
    let entry = AuditEntry {
        timestamp: time::utc_now(),
        tenant_id: tenant_id.to_string(),
        pool_id: pool_id.map(|s| s.to_string()),
        instance_id: instance_id.map(|s| s.to_string()),
        action,
        detail: detail.map(|s| s.to_string()),
        threats: vec![],
        gate_decision: None,
        frame_sequence: None,
    };

    let json_line =
        serde_json::to_string(&entry).with_context(|| "Failed to serialize audit entry")?;

    let log_path = tenant_audit_log_path(tenant_id);

    // Append JSON line atomically (>> is append, single write)
    shell::run_in_vm(&format!(
        "echo '{}' >> {}",
        json_line.replace('\'', "'\\''"),
        log_path,
    ))
    .with_context(|| format!("Failed to write audit log for tenant {}", tenant_id))?;

    Ok(())
}

/// Maximum audit log size before rotation (10 MiB).
const MAX_AUDIT_LOG_BYTES: u64 = 10 * 1024 * 1024;

/// Number of rotated audit log files to keep.
const KEEP_ROTATED: u32 = 3;

/// Rotate an audit log if it exceeds the size limit.
///
/// Rotation scheme: audit.log -> audit.log.1.gz -> audit.log.2.gz -> audit.log.3.gz
/// Keeps the most recent `KEEP_ROTATED` compressed files.
pub fn rotate_audit_log(tenant_id: &str) -> Result<()> {
    let log_path = tenant_audit_log_path(tenant_id);

    // Check file size
    let size_str =
        shell::run_in_vm_stdout(&format!("stat -c%s {} 2>/dev/null || echo 0", log_path))?;
    let size: u64 = size_str.trim().parse().unwrap_or(0);

    if size < MAX_AUDIT_LOG_BYTES {
        return Ok(());
    }

    // Rotate: shift existing numbered files up, drop oldest
    for i in (1..KEEP_ROTATED).rev() {
        let from = format!("{}.{}.gz", log_path, i);
        let to = format!("{}.{}.gz", log_path, i + 1);
        let _ = shell::run_in_vm(&format!("mv {} {} 2>/dev/null || true", from, to));
    }

    // Compress current log to .1.gz and truncate
    shell::run_in_vm(&format!(
        "gzip -c {} > {}.1.gz && truncate -s 0 {}",
        log_path, log_path, log_path
    ))
    .with_context(|| format!("Failed to rotate audit log for tenant {}", tenant_id))?;

    // Remove any file beyond KEEP_ROTATED
    let oldest = format!("{}.{}.gz", log_path, KEEP_ROTATED + 1);
    let _ = shell::run_in_vm(&format!("rm -f {}", oldest));

    Ok(())
}

/// Read the last N audit log entries for a tenant.
pub fn read_audit_log(tenant_id: &str, last_n: usize) -> Result<Vec<AuditEntry>> {
    let log_path = tenant_audit_log_path(tenant_id);

    let output = shell::run_in_vm_stdout(&format!(
        "tail -n {} {} 2>/dev/null || true",
        last_n, log_path
    ))?;

    let mut entries = Vec::new();
    for line in output.lines().filter(|l| !l.is_empty()) {
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(line) {
            entries.push(entry);
        }
    }

    Ok(entries)
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
        assert!(json.contains("pid=12345"));
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
        assert!(json.contains("\"TenantCreated\""));
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
    fn test_rotation_constants() {
        assert_eq!(MAX_AUDIT_LOG_BYTES, 10 * 1024 * 1024);
        assert_eq!(KEEP_ROTATED, 3);
    }

    #[test]
    fn test_rotate_noop_when_small() {
        use crate::shell_mock;

        let tenant_json = shell_mock::tenant_fixture("acme", 3, "10.240.3.0/24", "10.240.3.1");
        let (_guard, _fs) = shell_mock::mock_fs()
            .with_file("/var/lib/mvm/tenants/acme/tenant.json", &tenant_json)
            .install();

        // File doesn't exist or is small — rotation should be a no-op
        let result = rotate_audit_log("acme");
        assert!(result.is_ok());
    }
}
