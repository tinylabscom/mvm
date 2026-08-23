//! Per-VM metrics — A3 of the filesystem-volumes plan.
//!
//! Today's `metrics::Metrics` is a single global counter set
//! describing the host process as a whole. Sandbox-runtime SDKs
//! need per-VM cardinality (CPU/mem/disk/net for a single
//! sandbox), labelled by `instance_id`, `tenant`, and `template`,
//! with mvmd able to scrape one VM's slice without touching others.
//!
//! This module is the registry + Prometheus serialiser for that
//! data. Source readers (firecracker metrics socket, /sys TAP byte
//! counters, etc.) live in the supervisor crate alongside the
//! sampling tick — the registry stays pure data.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

/// Labels carried on every per-VM metric.
///
/// Kept as a value type so the registry can hand snapshots out by
/// value; the labels are immutable for the life of the
/// registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceLabels {
    pub instance_id: String,
    pub tenant: String,
    pub template: String,
}

/// One observation of a VM's resource usage. Values are absolute
/// counters / gauges sampled by the supervisor; Prometheus consumers
/// rate-difference the counters themselves.
///
/// Every field is `u64` so the sample-overflow story is "wraps at
/// 2^64 bytes/seconds, which is decades on modern hardware." Where
/// the underlying source returns `None` (e.g. /sys not available on
/// macOS), the supervisor reports zero — explicit absence is
/// callers'-side via `last_sample_unix_secs == 0`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceMetricsValues {
    /// CPU time consumed by the VMM process, microseconds (counter).
    pub cpu_user_us: u64,
    pub cpu_system_us: u64,
    /// Resident memory of the VMM process, bytes (gauge).
    pub mem_resident_bytes: u64,
    /// Cumulative bytes read by the VM's block devices (counter).
    pub disk_read_bytes: u64,
    /// Cumulative bytes written by the VM's block devices (counter).
    pub disk_write_bytes: u64,
    /// Cumulative bytes received on the VM's TAP iface (counter).
    pub net_rx_bytes: u64,
    /// Cumulative bytes transmitted on the VM's TAP iface (counter).
    pub net_tx_bytes: u64,
    /// Cumulative packets received on the TAP iface (counter).
    pub net_rx_packets: u64,
    /// Cumulative packets transmitted on the TAP iface (counter).
    pub net_tx_packets: u64,
    /// Wall-clock seconds since the supervisor first saw this VM
    /// running (gauge).
    pub uptime_secs: u64,
    /// Unix-seconds when the last sample fired. Zero = never.
    pub last_sample_unix_secs: u64,
    /// Cumulative AI API requests made by the VM through the host egress seam.
    pub ai_requests_total: u64,
    /// Cumulative input/prompt tokens reported by AI providers.
    pub ai_tokens_input_total: u64,
    /// Cumulative output/completion tokens reported by AI providers.
    pub ai_tokens_output_total: u64,
    /// Cumulative total tokens reported by AI providers.
    pub ai_tokens_total_total: u64,
}

#[derive(Debug, Clone)]
struct Entry {
    labels: InstanceLabels,
    values: InstanceMetricsValues,
}

/// Process-global per-VM metrics registry.
///
/// `register` claims the slot; `update` mutates the values atomically
/// (whole-snapshot replace, since the supervisor sampler computes
/// the values together); `unregister` drops the slot when the VM
/// goes away. The registry uses `BTreeMap` so the snapshot order is
/// deterministic — the Prometheus exposition output is stable
/// across calls, which simplifies golden tests and consumer
/// caching.
#[derive(Default)]
pub struct InstanceMetricsRegistry {
    entries: Mutex<BTreeMap<String, Entry>>,
}

impl InstanceMetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a VM to the registry. If `instance_id` was already
    /// registered, its labels are replaced and its values are
    /// reset to zero (matches the "fresh boot" intent).
    pub fn register(&self, labels: InstanceLabels) {
        let id = labels.instance_id.clone();
        let mut map = self.entries.lock().expect("instance_metrics mutex");
        map.insert(
            id,
            Entry {
                labels,
                values: InstanceMetricsValues::default(),
            },
        );
    }

    /// Drop a VM. Returns `true` if the instance was registered.
    pub fn unregister(&self, instance_id: &str) -> bool {
        let mut map = self.entries.lock().expect("instance_metrics mutex");
        map.remove(instance_id).is_some()
    }

    /// Replace a VM's values. Returns `false` if the instance is
    /// not registered (caller's update is dropped).
    pub fn update(&self, instance_id: &str, values: InstanceMetricsValues) -> bool {
        let mut map = self.entries.lock().expect("instance_metrics mutex");
        match map.get_mut(instance_id) {
            Some(entry) => {
                entry.values = values;
                true
            }
            None => false,
        }
    }

    /// Atomically update only the AI egress counters on an existing entry.
    ///
    /// This leaves CPU, memory, network, and disk samples untouched, so the
    /// substitution endpoint and the supervisor sampler can both contribute
    /// to the same VM's exposition without racing on the full value snapshot.
    /// Returns `false` if the instance is not registered.
    pub fn update_ai_counters(
        &self,
        instance_id: &str,
        requests: u64,
        input_tokens: u64,
        output_tokens: u64,
        total_tokens: u64,
    ) -> bool {
        let mut map = self.entries.lock().expect("instance_metrics mutex");
        match map.get_mut(instance_id) {
            Some(entry) => {
                entry.values.ai_requests_total = requests;
                entry.values.ai_tokens_input_total = input_tokens;
                entry.values.ai_tokens_output_total = output_tokens;
                entry.values.ai_tokens_total_total = total_tokens;
                true
            }
            None => false,
        }
    }

    /// Look up one VM's labels + most recent sample.
    pub fn get(&self, instance_id: &str) -> Option<(InstanceLabels, InstanceMetricsValues)> {
        let map = self.entries.lock().expect("instance_metrics mutex");
        map.get(instance_id)
            .map(|e| (e.labels.clone(), e.values.clone()))
    }

    /// Snapshot every VM's labels + values in `instance_id` order.
    pub fn snapshot(&self) -> Vec<(InstanceLabels, InstanceMetricsValues)> {
        let map = self.entries.lock().expect("instance_metrics mutex");
        map.values()
            .map(|e| (e.labels.clone(), e.values.clone()))
            .collect()
    }

    /// Number of registered VMs.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("instance_metrics mutex").len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries
            .lock()
            .expect("instance_metrics mutex")
            .is_empty()
    }

    /// Render the per-VM metrics in Prometheus exposition format.
    ///
    /// Every metric carries `{instance_id, tenant, template}`
    /// labels so a single Prometheus instance can scrape multiple
    /// hosts. Empty registries emit just the `# HELP` / `# TYPE`
    /// header lines so consumers see the metric names exist (avoids
    /// "metric not found" alerts during quiet periods).
    pub fn prometheus_exposition(&self) -> String {
        let snapshot = self.snapshot();
        let mut out = String::with_capacity(2048);
        for spec in METRIC_SPECS {
            push_header(&mut out, spec);
            for (labels, values) in &snapshot {
                push_sample(&mut out, spec, labels, (spec.read)(values));
            }
        }
        out
    }
}

/// Return a per-process singleton registry. Convenience for the
/// supervisor sampling tick which needs one shared instance across
/// the supervisor's threads.
pub fn global() -> &'static InstanceMetricsRegistry {
    static REGISTRY: OnceLock<InstanceMetricsRegistry> = OnceLock::new();
    REGISTRY.get_or_init(InstanceMetricsRegistry::new)
}

// ============================================================================
// Prometheus exposition machinery
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetricKind {
    Counter,
    Gauge,
}

struct MetricSpec {
    name: &'static str,
    kind: MetricKind,
    help: &'static str,
    read: fn(&InstanceMetricsValues) -> u64,
}

const METRIC_SPECS: &[MetricSpec] = &[
    MetricSpec {
        name: "mvm_instance_cpu_user_microseconds_total",
        kind: MetricKind::Counter,
        help: "VMM-process user-mode CPU time, microseconds",
        read: |v| v.cpu_user_us,
    },
    MetricSpec {
        name: "mvm_instance_cpu_system_microseconds_total",
        kind: MetricKind::Counter,
        help: "VMM-process kernel-mode CPU time, microseconds",
        read: |v| v.cpu_system_us,
    },
    MetricSpec {
        name: "mvm_instance_memory_resident_bytes",
        kind: MetricKind::Gauge,
        help: "VMM-process resident set size, bytes",
        read: |v| v.mem_resident_bytes,
    },
    MetricSpec {
        name: "mvm_instance_disk_read_bytes_total",
        kind: MetricKind::Counter,
        help: "Cumulative bytes read by the VM block devices",
        read: |v| v.disk_read_bytes,
    },
    MetricSpec {
        name: "mvm_instance_disk_write_bytes_total",
        kind: MetricKind::Counter,
        help: "Cumulative bytes written by the VM block devices",
        read: |v| v.disk_write_bytes,
    },
    MetricSpec {
        name: "mvm_instance_net_rx_bytes_total",
        kind: MetricKind::Counter,
        help: "Cumulative bytes received on the VM TAP interface",
        read: |v| v.net_rx_bytes,
    },
    MetricSpec {
        name: "mvm_instance_net_tx_bytes_total",
        kind: MetricKind::Counter,
        help: "Cumulative bytes transmitted on the VM TAP interface",
        read: |v| v.net_tx_bytes,
    },
    MetricSpec {
        name: "mvm_instance_net_rx_packets_total",
        kind: MetricKind::Counter,
        help: "Cumulative packets received on the VM TAP interface",
        read: |v| v.net_rx_packets,
    },
    MetricSpec {
        name: "mvm_instance_net_tx_packets_total",
        kind: MetricKind::Counter,
        help: "Cumulative packets transmitted on the VM TAP interface",
        read: |v| v.net_tx_packets,
    },
    MetricSpec {
        name: "mvm_instance_uptime_seconds",
        kind: MetricKind::Gauge,
        help: "Wall-clock seconds since the supervisor first saw the VM running",
        read: |v| v.uptime_secs,
    },
    MetricSpec {
        name: "mvm_instance_last_sample_unix_seconds",
        kind: MetricKind::Gauge,
        help: "Unix seconds at the most recent sample for this VM (0 = never sampled)",
        read: |v| v.last_sample_unix_secs,
    },
    MetricSpec {
        name: "mvm_instance_ai_requests_total",
        kind: MetricKind::Counter,
        help: "Cumulative AI API requests made by the VM through the host egress seam",
        read: |v| v.ai_requests_total,
    },
    MetricSpec {
        name: "mvm_instance_ai_tokens_input_total",
        kind: MetricKind::Counter,
        help: "Cumulative input/prompt tokens reported by AI providers",
        read: |v| v.ai_tokens_input_total,
    },
    MetricSpec {
        name: "mvm_instance_ai_tokens_output_total",
        kind: MetricKind::Counter,
        help: "Cumulative output/completion tokens reported by AI providers",
        read: |v| v.ai_tokens_output_total,
    },
    MetricSpec {
        name: "mvm_instance_ai_tokens_total_total",
        kind: MetricKind::Counter,
        help: "Cumulative total tokens reported by AI providers",
        read: |v| v.ai_tokens_total_total,
    },
];

fn push_header(out: &mut String, spec: &MetricSpec) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {} {}", spec.name, spec.help);
    let _ = writeln!(
        out,
        "# TYPE {} {}",
        spec.name,
        match spec.kind {
            MetricKind::Counter => "counter",
            MetricKind::Gauge => "gauge",
        }
    );
}

fn push_sample(out: &mut String, spec: &MetricSpec, labels: &InstanceLabels, value: u64) {
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "{}{{instance_id=\"{}\",tenant=\"{}\",template=\"{}\"}} {}",
        spec.name,
        escape_label(&labels.instance_id),
        escape_label(&labels.tenant),
        escape_label(&labels.template),
        value
    );
}

/// Escape a label value per the Prometheus exposition spec —
/// backslashes, double quotes, and newlines need backslash-escapes.
/// Tenant / template names that legally contain those characters
/// are exotic but possible; do the right thing.
fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(id: &str) -> InstanceLabels {
        InstanceLabels {
            instance_id: id.to_string(),
            tenant: "acme".to_string(),
            template: "python-3.12".to_string(),
        }
    }

    #[test]
    fn registry_starts_empty() {
        let reg = InstanceMetricsRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert_eq!(reg.snapshot().len(), 0);
    }

    #[test]
    fn register_and_get_roundtrip() {
        let reg = InstanceMetricsRegistry::new();
        reg.register(labels("i-1"));
        let (got_labels, got_values) = reg.get("i-1").unwrap();
        assert_eq!(got_labels.instance_id, "i-1");
        assert_eq!(got_values, InstanceMetricsValues::default());
    }

    #[test]
    fn update_returns_false_for_unknown_instance() {
        let reg = InstanceMetricsRegistry::new();
        assert!(!reg.update("no-such-vm", InstanceMetricsValues::default()));
    }

    #[test]
    fn update_replaces_values_atomically() {
        let reg = InstanceMetricsRegistry::new();
        reg.register(labels("i-1"));
        let v = InstanceMetricsValues {
            cpu_user_us: 1_000_000,
            mem_resident_bytes: 256 * 1024 * 1024,
            net_rx_bytes: 12345,
            uptime_secs: 30,
            last_sample_unix_secs: 1_700_000_000,
            ..Default::default()
        };
        assert!(reg.update("i-1", v.clone()));
        let (_, got) = reg.get("i-1").unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn unregister_removes_entry() {
        let reg = InstanceMetricsRegistry::new();
        reg.register(labels("i-1"));
        assert!(reg.unregister("i-1"));
        assert!(reg.get("i-1").is_none());
        assert!(!reg.unregister("i-1"));
    }

    #[test]
    fn re_register_resets_values() {
        let reg = InstanceMetricsRegistry::new();
        reg.register(labels("i-1"));
        reg.update(
            "i-1",
            InstanceMetricsValues {
                cpu_user_us: 999,
                ..Default::default()
            },
        );
        // Same id registered again → fresh-boot semantics.
        reg.register(labels("i-1"));
        let (_, got) = reg.get("i-1").unwrap();
        assert_eq!(got, InstanceMetricsValues::default());
    }

    #[test]
    fn snapshot_is_deterministic_by_instance_id() {
        let reg = InstanceMetricsRegistry::new();
        reg.register(labels("i-z"));
        reg.register(labels("i-a"));
        reg.register(labels("i-m"));
        let ids: Vec<String> = reg
            .snapshot()
            .into_iter()
            .map(|(l, _)| l.instance_id)
            .collect();
        assert_eq!(ids, vec!["i-a", "i-m", "i-z"]);
    }

    #[test]
    fn empty_registry_emits_only_headers() {
        let reg = InstanceMetricsRegistry::new();
        let out = reg.prometheus_exposition();
        // Headers are present so consumers see the metric names
        // exist; no sample lines means no `mvm_instance_cpu_...{...}`
        // value rows.
        assert!(out.contains("# HELP mvm_instance_cpu_user_microseconds_total"));
        assert!(out.contains("# TYPE mvm_instance_cpu_user_microseconds_total counter"));
        for line in out.lines() {
            assert!(
                !line.contains("instance_id="),
                "unexpected sample line on empty registry: {line}"
            );
        }
    }

    #[test]
    fn populated_registry_emits_labelled_samples() {
        let reg = InstanceMetricsRegistry::new();
        reg.register(labels("i-1"));
        reg.update(
            "i-1",
            InstanceMetricsValues {
                cpu_user_us: 42,
                mem_resident_bytes: 1024,
                net_rx_bytes: 99,
                uptime_secs: 5,
                last_sample_unix_secs: 1_700_000_000,
                ..Default::default()
            },
        );
        let out = reg.prometheus_exposition();
        assert!(out.contains(
            "mvm_instance_cpu_user_microseconds_total{instance_id=\"i-1\",tenant=\"acme\",template=\"python-3.12\"} 42"
        ));
        assert!(out.contains(
            "mvm_instance_memory_resident_bytes{instance_id=\"i-1\",tenant=\"acme\",template=\"python-3.12\"} 1024"
        ));
        assert!(out.contains(
            "mvm_instance_net_rx_bytes_total{instance_id=\"i-1\",tenant=\"acme\",template=\"python-3.12\"} 99"
        ));
        assert!(out.contains(
            "mvm_instance_uptime_seconds{instance_id=\"i-1\",tenant=\"acme\",template=\"python-3.12\"} 5"
        ));
    }

    #[test]
    fn label_escaping_handles_quotes_backslash_newline() {
        let reg = InstanceMetricsRegistry::new();
        reg.register(InstanceLabels {
            instance_id: "i-\"quoted\"".to_string(),
            tenant: "back\\slash".to_string(),
            template: "new\nline".to_string(),
        });
        let out = reg.prometheus_exposition();
        // Verify each escape appears in the rendered output.
        assert!(out.contains(r#"instance_id="i-\"quoted\"""#));
        assert!(out.contains(r#"tenant="back\\slash""#));
        assert!(out.contains(r#"template="new\nline""#));
    }

    #[test]
    fn multiple_vms_emit_one_sample_per_vm_per_metric() {
        let reg = InstanceMetricsRegistry::new();
        for id in ["i-1", "i-2", "i-3"] {
            reg.register(labels(id));
        }
        let out = reg.prometheus_exposition();
        // 11 metrics × 3 VMs = 33 sample lines, each beginning with
        // a metric name. Match the cpu_user counter specifically:
        let cpu_user_sample_count = out
            .lines()
            .filter(|l| l.starts_with("mvm_instance_cpu_user_microseconds_total{"))
            .count();
        assert_eq!(cpu_user_sample_count, 3);
    }

    #[test]
    fn global_returns_singleton() {
        // Calling `global()` twice yields the same registry —
        // updates on the first must be visible through the second.
        let labels_one = InstanceLabels {
            instance_id: "global-test-vm".to_string(),
            tenant: "t".to_string(),
            template: "tpl".to_string(),
        };
        global().register(labels_one);
        global().update(
            "global-test-vm",
            InstanceMetricsValues {
                cpu_user_us: 7,
                ..Default::default()
            },
        );
        let (_, got) = global().get("global-test-vm").unwrap();
        assert_eq!(got.cpu_user_us, 7);
        // Clean up so this test doesn't pollute later snapshots.
        global().unregister("global-test-vm");
    }
}
