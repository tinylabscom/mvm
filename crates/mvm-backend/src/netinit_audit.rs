//! Plan 74 W2 — host-side audit emission for the guest-side
//! `mvm-guest-netinit` defense layer.
//!
//! `mvm-guest-netinit` runs at boot inside every microVM,
//! installs kernel blackhole routes for the mandatory-deny
//! ranges, and writes a single marker-prefixed JSON line to
//! stdout (captured by the kernel console). This module is the
//! host-side glue that:
//!
//! 1. Reads the console log after the VM is ready.
//! 2. Parses the netinit `Report` via the canonical marker.
//! 3. Emits one or two `LocalAuditKind::NetworkMandatoryDeny`
//!    audit events — a success summary if any rules installed
//!    cleanly, plus a fail-closed-class record if the install
//!    had per-route failures.
//!
//! The detail format follows mvmd ADR 0022 §"Failure semantics":
//! every audit record names `layer=guest_netinit`, the
//! per-event `scope`, and an `effect` for the fail-closed case.
//! That convention lets a future dashboard pivot on:
//!
//! - `scope=install` → "rules in force"
//! - `scope=install_failed` → "one or more rules didn't land"
//! - per-flow events from a future kernel-LOG consumer →
//!   `scope=flow,proto=tcp,dst=...`
//!
//! Same `NetworkMandatoryDeny` variant for all three; consumers
//! branch on the detail keys.

use std::path::Path;

use mvm_guest::netinit::{Report, parse_report_from_console};

/// Read a console log file and emit netinit audit events.
///
/// Returns `Ok(Some(report))` when a report was found and
/// emitted, `Ok(None)` when no marker was present (e.g. the VM
/// pre-dates the netinit-emitting mkGuest build, or netinit
/// itself failed to even produce output), `Err` on I/O failure.
///
/// **Best-effort semantics.** A missing report is not an error
/// — older templates that boot without netinit are still valid
/// in the transition period. The caller (typically the
/// `mvmctl up` start flow) logs the no-marker case at info level
/// and proceeds.
pub fn parse_and_emit_netinit_audit(
    console_log_path: &Path,
    vm_name: &str,
) -> std::io::Result<Option<Report>> {
    let contents = std::fs::read_to_string(console_log_path)?;
    let Some(report) = parse_report_from_console(&contents) else {
        return Ok(None);
    };
    emit_netinit_audit(&report, vm_name);
    Ok(Some(report))
}

/// Resolve `console.log` for a named VM and emit netinit audit.
/// Convenience wrapper that the `mvmctl up` start flow calls
/// once `wait_for_guest_agent` succeeds — by then the kernel
/// console has captured netinit's output line.
///
/// Best-effort: returns `Ok(None)` when the log file doesn't
/// exist yet or doesn't carry the marker. Only `Err` on
/// unexpected I/O failures the caller would want to surface.
pub fn emit_for_vm(vm_name: &str) -> std::io::Result<Option<Report>> {
    let console_log =
        crate::microvm::vm_console_log_path(vm_name).map_err(std::io::Error::other)?;
    if !console_log.exists() {
        // VM is too new (start flow hasn't created the file yet) or
        // backend uses a different log path (libkrun / Apple
        // Container). Both are real cases; not an error.
        return Ok(None);
    }
    parse_and_emit_netinit_audit(&console_log, vm_name)
}

/// Emit `NetworkMandatoryDeny` audit events for a parsed
/// [`Report`]. Public so a future caller that already has the
/// report in hand (e.g. via vsock from the agent) can skip the
/// console-log parse step and audit directly.
pub fn emit_netinit_audit(report: &Report, vm_name: &str) {
    // Success summary — one record per workload, regardless of
    // how many CIDRs were installed. The detail carries the full
    // CIDR list pipe-separated (commas inside CIDRs would break
    // the audit detail's key=value comma framing).
    if !report.installed.is_empty() {
        let cidrs: Vec<String> = report
            .installed
            .iter()
            .map(|r| r.cidr.to_string())
            .collect();
        let categories: Vec<String> = report
            .installed
            .iter()
            .map(|r| r.category.clone())
            .collect();
        // De-dup categories so the audit line carries the
        // distinct set, not one entry per CIDR. `cloud-metadata`
        // and `link-local` are likely to both appear; loopback
        // + cgnat often once each.
        let mut distinct_categories = categories.clone();
        distinct_categories.sort();
        distinct_categories.dedup();
        mvm_core::audit_emit!(
            NetworkMandatoryDeny,
            vm: vm_name,
            "scope=install,layer=guest_netinit,cidrs={cidrs},categories={cats}",
            cidrs = cidrs.join("|"),
            cats = distinct_categories.join("|"),
        );
    }

    // Fail-closed-class summary — emitted when any route
    // failed to install. `effect=continue` documents that
    // `/init` does NOT abort the boot today; the host-side
    // iptables (where it applies) is the primary layer.
    // mvmd ADR 0022 §"Failure semantics" names the keys.
    if report.has_failures() {
        let failed_cidrs: Vec<String> = report.failed.iter().map(|r| r.cidr.to_string()).collect();
        // First-reason is representative; the full list lives
        // in the console log and can be retrieved by an
        // operator inspecting `firecracker.log` or `console.log`.
        let first_reason = report
            .failed
            .first()
            .map(|r| r.reason.as_str())
            .unwrap_or("unknown");
        mvm_core::audit_emit!(
            NetworkMandatoryDeny,
            vm: vm_name,
            "scope=install_failed,layer=guest_netinit,effect=continue,failed_cidrs={cidrs},first_reason={reason}",
            cidrs = failed_cidrs.join("|"),
            reason = first_reason,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_guest::netinit::{REPORT_MARKER, Report, RouteFailed, RouteInstalled};

    fn report_with_one_installed() -> Report {
        Report {
            installed: vec![RouteInstalled {
                cidr: "169.254.169.254/32".parse().unwrap(),
                category: "cloud-metadata".to_string(),
            }],
            failed: vec![],
            skipped_ipv6: vec![],
            skipped_loopback: vec![],
        }
    }

    fn report_with_failure() -> Report {
        Report {
            installed: vec![RouteInstalled {
                cidr: "169.254.169.254/32".parse().unwrap(),
                category: "cloud-metadata".to_string(),
            }],
            failed: vec![RouteFailed {
                cidr: "127.0.0.0/8".parse().unwrap(),
                category: "loopback".to_string(),
                reason: "operation not permitted".to_string(),
            }],
            skipped_ipv6: vec![],
            skipped_loopback: vec![],
        }
    }

    /// The parse path returns `None` when the console log has
    /// no marker (older templates, or a netinit binary that
    /// crashed before emitting anything). Not an error.
    #[test]
    fn parse_returns_none_when_console_missing_marker() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            "[    0.000000] Booting Linux\n[mvm-init] mounted /proc\n",
        )
        .unwrap();
        let out = parse_and_emit_netinit_audit(tmp.path(), "vm-test").unwrap();
        assert!(out.is_none());
    }

    /// End-to-end: a console log with the marker line yields
    /// a parsed report. The audit emission itself writes to the
    /// default audit log so we can't assert its contents in a
    /// unit test without log-pointer plumbing; the function
    /// returning `Ok(Some(report))` is the contract.
    #[test]
    fn parse_returns_report_when_console_has_marker() {
        let report = report_with_one_installed();
        let json = serde_json::to_string(&report).unwrap();
        let log = format!(
            "[    0.000000] Booting Linux\n\
             [mvm-init] mounted /proc\n\
             {REPORT_MARKER} {json}\n\
             [mvm-agent] starting on vsock\n"
        );
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), log).unwrap();
        let out = parse_and_emit_netinit_audit(tmp.path(), "vm-test").unwrap();
        let parsed = out.expect("marker must produce a report");
        assert_eq!(parsed.installed.len(), 1);
        assert_eq!(parsed.installed[0].category, "cloud-metadata");
    }

    /// `parse_and_emit_netinit_audit` propagates I/O errors
    /// when the console log file is absent. The caller (start
    /// flow) treats this as best-effort and proceeds.
    #[test]
    fn parse_returns_io_error_when_path_missing() {
        let result = parse_and_emit_netinit_audit(Path::new("/no/such/file/anywhere"), "vm-test");
        assert!(result.is_err());
    }

    /// Emission for a clean report uses `scope=install` and
    /// includes every CIDR in the detail. We can't directly
    /// observe the LocalAuditEvent without overriding the audit
    /// log path, so this test verifies the helper doesn't panic
    /// on the clean-input path. The detail-format contract is
    /// covered by inspection of the source + the doc comment.
    #[test]
    fn emit_netinit_audit_clean_report_does_not_panic() {
        emit_netinit_audit(&report_with_one_installed(), "vm-test");
    }

    /// Emission for a report with failures emits BOTH the
    /// success summary (for the entries that landed) AND the
    /// fail-closed class record (for the entries that didn't).
    /// Same not-panic contract; detail format covered by
    /// inspection.
    #[test]
    fn emit_netinit_audit_failed_report_does_not_panic() {
        emit_netinit_audit(&report_with_failure(), "vm-test");
    }

    /// Empty report (no installed, no failed, no skipped) is
    /// the "netinit ran but did nothing" case — emit nothing.
    /// Verifies the function short-circuits cleanly.
    #[test]
    fn emit_netinit_audit_empty_report_emits_nothing() {
        let empty = Report::empty();
        emit_netinit_audit(&empty, "vm-test");
        // No assertion possible at this layer; the audit log
        // would just have no new records. The function not
        // panicking is the contract.
    }
}
