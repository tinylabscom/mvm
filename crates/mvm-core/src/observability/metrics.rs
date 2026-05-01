use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

/// Global metrics registry (singleton).
static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Get or initialize the global metrics instance.
pub fn global() -> &'static Metrics {
    METRICS.get_or_init(Metrics::new)
}

/// Application-wide metrics counters.
pub struct Metrics {
    // ── Request counters ────────────────────────────────────────────
    pub requests_total: AtomicU64,
    pub requests_reconcile: AtomicU64,
    pub requests_node_info: AtomicU64,
    pub requests_node_stats: AtomicU64,
    pub requests_tenant_list: AtomicU64,
    pub requests_instance_list: AtomicU64,
    pub requests_wake: AtomicU64,
    pub requests_rate_limited: AtomicU64,
    pub requests_failed: AtomicU64,

    // ── Reconcile counters ──────────────────────────────────────────
    pub reconcile_runs: AtomicU64,
    pub reconcile_errors: AtomicU64,
    pub reconcile_duration_ms: AtomicU64,

    // ── Instance counters ───────────────────────────────────────────
    pub instances_created: AtomicU64,
    pub instances_started: AtomicU64,
    pub instances_stopped: AtomicU64,
    pub instances_slept: AtomicU64,
    pub instances_woken: AtomicU64,
    pub instances_destroyed: AtomicU64,
    pub instances_deferred: AtomicU64,

    // ── Connection counters ─────────────────────────────────────────
    pub connections_accepted: AtomicU64,
    pub connections_rejected: AtomicU64,

    // ── Timing gauges (last observed, milliseconds) ─────────────────
    pub build_image_duration_ms: AtomicU64,
    pub vm_start_duration_ms: AtomicU64,
    pub vsock_handshake_rtt_ms: AtomicU64,

    // ── Dev/builder image verification (plan 36 §Layer 4 step 11) ───
    // One counter per outcome of the cosign-signed manifest +
    // SHA-256 verification pipeline at apple_container.rs::download_dev_image.
    // The duration gauge is the last observed wall-clock from
    // try_fetch_signed_manifest entry through verify_artifact_hash exit.
    // mvmd plan 23 will read these via the prometheus exposition to alert
    // on attack-shaped failure spikes (sig_invalid / digest_mismatch).
    pub dev_image_verify_ok: AtomicU64,
    pub dev_image_verify_sig_invalid: AtomicU64,
    pub dev_image_verify_digest_mismatch: AtomicU64,
    pub dev_image_verify_version_skew: AtomicU64,
    pub dev_image_verify_revoked: AtomicU64,
    pub dev_image_verify_expired: AtomicU64,
    pub dev_image_verify_network: AtomicU64,
    pub dev_image_verify_duration_ms: AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            requests_reconcile: AtomicU64::new(0),
            requests_node_info: AtomicU64::new(0),
            requests_node_stats: AtomicU64::new(0),
            requests_tenant_list: AtomicU64::new(0),
            requests_instance_list: AtomicU64::new(0),
            requests_wake: AtomicU64::new(0),
            requests_rate_limited: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            reconcile_runs: AtomicU64::new(0),
            reconcile_errors: AtomicU64::new(0),
            reconcile_duration_ms: AtomicU64::new(0),
            instances_created: AtomicU64::new(0),
            instances_started: AtomicU64::new(0),
            instances_stopped: AtomicU64::new(0),
            instances_slept: AtomicU64::new(0),
            instances_woken: AtomicU64::new(0),
            instances_destroyed: AtomicU64::new(0),
            instances_deferred: AtomicU64::new(0),
            connections_accepted: AtomicU64::new(0),
            connections_rejected: AtomicU64::new(0),
            build_image_duration_ms: AtomicU64::new(0),
            vm_start_duration_ms: AtomicU64::new(0),
            vsock_handshake_rtt_ms: AtomicU64::new(0),
            dev_image_verify_ok: AtomicU64::new(0),
            dev_image_verify_sig_invalid: AtomicU64::new(0),
            dev_image_verify_digest_mismatch: AtomicU64::new(0),
            dev_image_verify_version_skew: AtomicU64::new(0),
            dev_image_verify_revoked: AtomicU64::new(0),
            dev_image_verify_expired: AtomicU64::new(0),
            dev_image_verify_network: AtomicU64::new(0),
            dev_image_verify_duration_ms: AtomicU64::new(0),
        }
    }

    /// Collect a snapshot of all metrics for serialization.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_reconcile: self.requests_reconcile.load(Ordering::Relaxed),
            requests_node_info: self.requests_node_info.load(Ordering::Relaxed),
            requests_node_stats: self.requests_node_stats.load(Ordering::Relaxed),
            requests_tenant_list: self.requests_tenant_list.load(Ordering::Relaxed),
            requests_instance_list: self.requests_instance_list.load(Ordering::Relaxed),
            requests_wake: self.requests_wake.load(Ordering::Relaxed),
            requests_rate_limited: self.requests_rate_limited.load(Ordering::Relaxed),
            requests_failed: self.requests_failed.load(Ordering::Relaxed),
            reconcile_runs: self.reconcile_runs.load(Ordering::Relaxed),
            reconcile_errors: self.reconcile_errors.load(Ordering::Relaxed),
            reconcile_duration_ms: self.reconcile_duration_ms.load(Ordering::Relaxed),
            instances_created: self.instances_created.load(Ordering::Relaxed),
            instances_started: self.instances_started.load(Ordering::Relaxed),
            instances_stopped: self.instances_stopped.load(Ordering::Relaxed),
            instances_slept: self.instances_slept.load(Ordering::Relaxed),
            instances_woken: self.instances_woken.load(Ordering::Relaxed),
            instances_destroyed: self.instances_destroyed.load(Ordering::Relaxed),
            instances_deferred: self.instances_deferred.load(Ordering::Relaxed),
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            connections_rejected: self.connections_rejected.load(Ordering::Relaxed),
            build_image_duration_ms: self.build_image_duration_ms.load(Ordering::Relaxed),
            vm_start_duration_ms: self.vm_start_duration_ms.load(Ordering::Relaxed),
            vsock_handshake_rtt_ms: self.vsock_handshake_rtt_ms.load(Ordering::Relaxed),
            dev_image_verify_ok: self.dev_image_verify_ok.load(Ordering::Relaxed),
            dev_image_verify_sig_invalid: self.dev_image_verify_sig_invalid.load(Ordering::Relaxed),
            dev_image_verify_digest_mismatch: self
                .dev_image_verify_digest_mismatch
                .load(Ordering::Relaxed),
            dev_image_verify_version_skew: self
                .dev_image_verify_version_skew
                .load(Ordering::Relaxed),
            dev_image_verify_revoked: self.dev_image_verify_revoked.load(Ordering::Relaxed),
            dev_image_verify_expired: self.dev_image_verify_expired.load(Ordering::Relaxed),
            dev_image_verify_network: self.dev_image_verify_network.load(Ordering::Relaxed),
            dev_image_verify_duration_ms: self.dev_image_verify_duration_ms.load(Ordering::Relaxed),
        }
    }

    /// Format metrics in Prometheus exposition format.
    pub fn prometheus_exposition(&self) -> String {
        let s = self.snapshot();
        let mut out = String::with_capacity(2048);

        write_metric(
            &mut out,
            "mvm_requests_total",
            s.requests_total,
            "Total QUIC API requests received",
        );
        write_metric(
            &mut out,
            "mvm_requests_reconcile_total",
            s.requests_reconcile,
            "Reconcile requests",
        );
        write_metric(
            &mut out,
            "mvm_requests_node_info_total",
            s.requests_node_info,
            "NodeInfo requests",
        );
        write_metric(
            &mut out,
            "mvm_requests_node_stats_total",
            s.requests_node_stats,
            "NodeStats requests",
        );
        write_metric(
            &mut out,
            "mvm_requests_tenant_list_total",
            s.requests_tenant_list,
            "TenantList requests",
        );
        write_metric(
            &mut out,
            "mvm_requests_instance_list_total",
            s.requests_instance_list,
            "InstanceList requests",
        );
        write_metric(
            &mut out,
            "mvm_requests_wake_total",
            s.requests_wake,
            "WakeInstance requests",
        );
        write_metric(
            &mut out,
            "mvm_requests_rate_limited_total",
            s.requests_rate_limited,
            "Rate-limited requests",
        );
        write_metric(
            &mut out,
            "mvm_requests_failed_total",
            s.requests_failed,
            "Failed requests",
        );
        write_metric(
            &mut out,
            "mvm_reconcile_runs_total",
            s.reconcile_runs,
            "Reconcile loop executions",
        );
        write_metric(
            &mut out,
            "mvm_reconcile_errors_total",
            s.reconcile_errors,
            "Reconcile errors",
        );
        write_metric(
            &mut out,
            "mvm_reconcile_duration_milliseconds",
            s.reconcile_duration_ms,
            "Last reconcile duration in ms",
        );
        write_metric(
            &mut out,
            "mvm_instances_created_total",
            s.instances_created,
            "Instances created",
        );
        write_metric(
            &mut out,
            "mvm_instances_started_total",
            s.instances_started,
            "Instances started",
        );
        write_metric(
            &mut out,
            "mvm_instances_stopped_total",
            s.instances_stopped,
            "Instances stopped",
        );
        write_metric(
            &mut out,
            "mvm_instances_slept_total",
            s.instances_slept,
            "Instances slept",
        );
        write_metric(
            &mut out,
            "mvm_instances_woken_total",
            s.instances_woken,
            "Instances woken",
        );
        write_metric(
            &mut out,
            "mvm_instances_destroyed_total",
            s.instances_destroyed,
            "Instances destroyed",
        );
        write_metric(
            &mut out,
            "mvm_instances_deferred_total",
            s.instances_deferred,
            "Instances deferred by min-runtime policy",
        );
        write_metric(
            &mut out,
            "mvm_connections_accepted_total",
            s.connections_accepted,
            "Connections accepted",
        );
        write_metric(
            &mut out,
            "mvm_connections_rejected_total",
            s.connections_rejected,
            "Connections rejected",
        );
        write_gauge(
            &mut out,
            "mvm_build_image_duration_milliseconds",
            s.build_image_duration_ms,
            "Last build_image() duration in milliseconds",
        );
        write_gauge(
            &mut out,
            "mvm_vm_start_duration_milliseconds",
            s.vm_start_duration_ms,
            "Last VM start duration in milliseconds",
        );
        write_gauge(
            &mut out,
            "mvm_vsock_handshake_rtt_milliseconds",
            s.vsock_handshake_rtt_ms,
            "Last vsock auth handshake RTT in milliseconds",
        );

        // Plan 36 §Layer 4 step 11: dev/builder image verification
        // outcomes. One counter per outcome lets a Prometheus query
        // alert on attack-shaped failure spikes
        // (sig_invalid / digest_mismatch in particular).
        write_metric(
            &mut out,
            "mvm_dev_image_verify_ok_total",
            s.dev_image_verify_ok,
            "Successful dev/builder image manifest verifications",
        );
        write_metric(
            &mut out,
            "mvm_dev_image_verify_sig_invalid_total",
            s.dev_image_verify_sig_invalid,
            "Cosign signature failures on dev/builder image manifests",
        );
        write_metric(
            &mut out,
            "mvm_dev_image_verify_digest_mismatch_total",
            s.dev_image_verify_digest_mismatch,
            "SHA-256 mismatches on downloaded dev/builder image artifacts",
        );
        write_metric(
            &mut out,
            "mvm_dev_image_verify_version_skew_total",
            s.dev_image_verify_version_skew,
            "Manifest version did not match runtime mvmctl version",
        );
        write_metric(
            &mut out,
            "mvm_dev_image_verify_revoked_total",
            s.dev_image_verify_revoked,
            "Image rejected because its version is on the cosign-signed revocation list",
        );
        write_metric(
            &mut out,
            "mvm_dev_image_verify_expired_total",
            s.dev_image_verify_expired,
            "Image manifest past its not_after window",
        );
        write_metric(
            &mut out,
            "mvm_dev_image_verify_network_total",
            s.dev_image_verify_network,
            "Network failures during dev/builder image manifest fetch or revocation refresh",
        );
        write_gauge(
            &mut out,
            "mvm_dev_image_verify_duration_milliseconds",
            s.dev_image_verify_duration_ms,
            "Last dev/builder image verification wall-clock in milliseconds",
        );

        out
    }
}

fn write_metric(out: &mut String, name: &str, value: u64, help: &str) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {} {}", name, help);
    let _ = writeln!(out, "# TYPE {} counter", name);
    let _ = writeln!(out, "{} {}", name, value);
}

fn write_gauge(out: &mut String, name: &str, value: u64, help: &str) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {} {}", name, help);
    let _ = writeln!(out, "# TYPE {} gauge", name);
    let _ = writeln!(out, "{} {}", name, value);
}

/// Serializable snapshot of all metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_reconcile: u64,
    pub requests_node_info: u64,
    pub requests_node_stats: u64,
    pub requests_tenant_list: u64,
    pub requests_instance_list: u64,
    pub requests_wake: u64,
    pub requests_rate_limited: u64,
    pub requests_failed: u64,
    pub reconcile_runs: u64,
    pub reconcile_errors: u64,
    pub reconcile_duration_ms: u64,
    pub instances_created: u64,
    pub instances_started: u64,
    pub instances_stopped: u64,
    pub instances_slept: u64,
    pub instances_woken: u64,
    pub instances_destroyed: u64,
    pub instances_deferred: u64,
    pub connections_accepted: u64,
    pub connections_rejected: u64,
    pub build_image_duration_ms: u64,
    pub vm_start_duration_ms: u64,
    pub vsock_handshake_rtt_ms: u64,
    #[serde(default)]
    pub dev_image_verify_ok: u64,
    #[serde(default)]
    pub dev_image_verify_sig_invalid: u64,
    #[serde(default)]
    pub dev_image_verify_digest_mismatch: u64,
    #[serde(default)]
    pub dev_image_verify_version_skew: u64,
    #[serde(default)]
    pub dev_image_verify_revoked: u64,
    #[serde(default)]
    pub dev_image_verify_expired: u64,
    #[serde(default)]
    pub dev_image_verify_network: u64,
    #[serde(default)]
    pub dev_image_verify_duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_increment() {
        let m = Metrics::new();
        m.requests_total.fetch_add(1, Ordering::Relaxed);
        m.requests_total.fetch_add(1, Ordering::Relaxed);
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_metrics_snapshot() {
        let m = Metrics::new();
        m.instances_created.fetch_add(5, Ordering::Relaxed);
        m.reconcile_runs.fetch_add(3, Ordering::Relaxed);

        let snap = m.snapshot();
        assert_eq!(snap.instances_created, 5);
        assert_eq!(snap.reconcile_runs, 3);
        assert_eq!(snap.requests_total, 0);
    }

    #[test]
    fn test_metrics_snapshot_roundtrip() {
        let m = Metrics::new();
        m.requests_total.fetch_add(10, Ordering::Relaxed);

        let snap = m.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("\"requests_total\":10"));
    }

    #[test]
    fn test_prometheus_exposition_format() {
        let m = Metrics::new();
        m.requests_total.fetch_add(42, Ordering::Relaxed);
        m.connections_accepted.fetch_add(7, Ordering::Relaxed);

        let prom = m.prometheus_exposition();
        assert!(prom.contains("# HELP mvm_requests_total"));
        assert!(prom.contains("# TYPE mvm_requests_total counter"));
        assert!(prom.contains("mvm_requests_total 42"));
        assert!(prom.contains("mvm_connections_accepted_total 7"));
    }

    #[test]
    fn test_timing_gauges_store_and_snapshot() {
        let m = Metrics::new();
        m.build_image_duration_ms.store(1234, Ordering::Relaxed);
        m.vm_start_duration_ms.store(567, Ordering::Relaxed);
        m.vsock_handshake_rtt_ms.store(89, Ordering::Relaxed);

        let snap = m.snapshot();
        assert_eq!(snap.build_image_duration_ms, 1234);
        assert_eq!(snap.vm_start_duration_ms, 567);
        assert_eq!(snap.vsock_handshake_rtt_ms, 89);
    }

    #[test]
    fn test_timing_gauges_prometheus_type_is_gauge() {
        let m = Metrics::new();
        m.build_image_duration_ms.store(100, Ordering::Relaxed);
        let prom = m.prometheus_exposition();
        assert!(prom.contains("# TYPE mvm_build_image_duration_milliseconds gauge"));
        assert!(prom.contains("# TYPE mvm_vm_start_duration_milliseconds gauge"));
        assert!(prom.contains("# TYPE mvm_vsock_handshake_rtt_milliseconds gauge"));
    }

    #[test]
    fn test_timing_gauges_prometheus_values() {
        let m = Metrics::new();
        m.vm_start_duration_ms.store(42, Ordering::Relaxed);
        let prom = m.prometheus_exposition();
        assert!(prom.contains("mvm_vm_start_duration_milliseconds 42"));
    }
}
