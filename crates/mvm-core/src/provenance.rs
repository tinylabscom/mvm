//! Audit-log to PROV-O exporter.
//!
//! Reads `mvm`'s existing chain-signed JSONL audit streams and emits
//! W3C PROV-O Turtle via `mvm_contract::provenance`. This is a
//! read-only, additive layer: it does not modify the source log or
//! make authorization decisions.

use std::io::{BufRead, Write};

use anyhow::{Context, Result};

use mvm_contract::policy::audit::{AuditEntry, LocalAuditEvent};
use mvm_contract::provenance::{
    ProvenanceGraph, audit_entry_to_provenance, local_audit_event_to_provenance,
};

/// Read a per-tenant JSONL audit log and write PROV-O Turtle.
///
/// Each line must deserialize as [`AuditEntry`]. Invalid lines are
/// skipped with a warning so that a single corrupted line does not
/// abort export of the rest of the chain.
pub fn export_tenant_audit_log<R: BufRead, W: Write>(reader: R, writer: &mut W) -> Result<()> {
    let mut graph = ProvenanceGraph::new();
    let mut sequence = 0u64;

    for line in reader.lines() {
        let line = line.context("Failed to read audit log line")?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEntry>(&line) {
            Ok(entry) => {
                let entry_graph = audit_entry_to_provenance(&entry, sequence);
                graph.extend(entry_graph);
                sequence += 1;
            }
            Err(e) => {
                tracing::warn!("Skipping malformed audit entry: {e}");
            }
        }
    }

    let turtle = graph.to_turtle();
    writer
        .write_all(turtle.as_bytes())
        .context("Failed to write Turtle output")
}

/// Read the local `audit.jsonl` and write PROV-O Turtle.
///
/// Each line must deserialize as [`LocalAuditEvent`]. Invalid lines
/// are skipped with a warning.
pub fn export_local_audit_log<R: BufRead, W: Write>(reader: R, writer: &mut W) -> Result<()> {
    let mut graph = ProvenanceGraph::new();
    let mut sequence = 0u64;

    for line in reader.lines() {
        let line = line.context("Failed to read audit log line")?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<LocalAuditEvent>(&line) {
            Ok(event) => {
                let event_graph = local_audit_event_to_provenance(&event, sequence);
                graph.extend(event_graph);
                sequence += 1;
            }
            Err(e) => {
                tracing::warn!("Skipping malformed local audit event: {e}");
            }
        }
    }

    let turtle = graph.to_turtle();
    writer
        .write_all(turtle.as_bytes())
        .context("Failed to write Turtle output")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::policy::audit::{AuditAction, AuditEntry, LocalAuditEvent, LocalAuditKind};

    #[test]
    fn test_export_tenant_audit_log() {
        let entry = AuditEntry {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            tenant_id: "acme".to_string(),
            pool_id: None,
            instance_id: Some("i-001".to_string()),
            action: AuditAction::InstanceStarted,
            detail: Some("booted".to_string()),
            threats: vec![],
            gate_decision: None,
            frame_sequence: None,
        };
        let line = serde_json::to_string(&entry).unwrap();
        let input: &[u8] = line.as_bytes();
        let mut output = Vec::new();
        export_tenant_audit_log(input, &mut output).unwrap();
        let turtle = String::from_utf8(output).unwrap();
        assert!(turtle.contains("prov:Activity"));
        assert!(turtle.contains("prov:Agent"));
        assert!(turtle.contains("prov:Entity"));
        assert!(turtle.contains("acme"));
    }

    #[test]
    fn test_export_local_audit_log() {
        let event = LocalAuditEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            kind: LocalAuditKind::VmStart,
            vm_name: Some("my-vm".to_string()),
            detail: Some("template=alpine".to_string()),
        };
        let line = serde_json::to_string(&event).unwrap();
        let input: &[u8] = line.as_bytes();
        let mut output = Vec::new();
        export_local_audit_log(input, &mut output).unwrap();
        let turtle = String::from_utf8(output).unwrap();
        assert!(turtle.contains("prov:Activity"));
        assert!(turtle.contains("mvm:host_operator"));
        assert!(turtle.contains("VmStart"));
    }

    #[test]
    fn test_export_tenant_audit_log_skips_malformed_lines() {
        let input = b"not valid json\n";
        let mut output = Vec::new();
        export_tenant_audit_log(&input[..], &mut output).unwrap();
        let turtle = String::from_utf8(output).unwrap();
        assert!(!turtle.contains("prov:Activity"));
    }
}
