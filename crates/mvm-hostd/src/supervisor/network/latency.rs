//! Per-observer `on_packet` latency. Exposed as a
//! Prometheus summary (`_sum` + `_count`) per (observer, vm, direction)
//! via a per-VM scrape file the CLI `/metrics` handler concatenates
//! (`~/.mvm/audit/metrics-<vm>-observer-latency.prom`). Mirrors the
//! cross-process surface `flow_count.rs` uses: the supervisor and CLI run
//! as the same user and share `~/.mvm/audit/` (mode 0700), so the
//! filesystem is the boundary — no new socket, no new RPC.

use crate::supervisor::audit::FlowDirection;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// (sum_micros, count) for one (observer, direction) bucket.
type Bucket = (u64, u64);

pub struct ObserverLatency {
    vm: String,
    // Reserved for a future per-tenant label; `vm` is the scrape key today
    // (one guest = one tenant), so we don't emit `tenant` yet.
    #[allow(dead_code)]
    tenant: String,
    buckets: Mutex<BTreeMap<(&'static str, &'static str), Bucket>>,
}

impl ObserverLatency {
    pub fn new(vm: impl Into<String>, tenant: impl Into<String>) -> Self {
        Self {
            vm: vm.into(),
            tenant: tenant.into(),
            buckets: Mutex::new(BTreeMap::new()),
        }
    }

    /// Record one `on_packet` call's wall time in microseconds.
    pub fn record(&self, observer: &'static str, direction: FlowDirection, micros: u64) {
        let mut g = self
            .buckets
            .lock()
            .expect("observer-latency mutex poisoned");
        let e = g.entry((observer, direction.as_str())).or_insert((0, 0));
        e.0 = e.0.saturating_add(micros);
        e.1 = e.1.saturating_add(1);
    }

    pub fn prometheus_format(&self) -> String {
        let g = self
            .buckets
            .lock()
            .expect("observer-latency mutex poisoned");
        let mut out = String::new();
        out.push_str(
            "# HELP mvm_observer_latency_us Per-observer on_packet latency (microseconds)\n\
             # TYPE mvm_observer_latency_us summary\n",
        );
        let vm = &self.vm;
        for ((observer, direction), (sum, count)) in g.iter() {
            out.push_str(&format!(
                "mvm_observer_latency_us_sum{{observer=\"{observer}\",vm=\"{vm}\",direction=\"{direction}\"}} {sum}\n"
            ));
            out.push_str(&format!(
                "mvm_observer_latency_us_count{{observer=\"{observer}\",vm=\"{vm}\",direction=\"{direction}\"}} {count}\n"
            ));
        }
        out
    }

    /// Atomic-ish write (tmp + rename), mirroring
    /// `FlowCountMetrics::write_scrape_file`. Fails closed (no-op) when
    /// `HOME` is unset — never falls back to a world-writable directory.
    pub fn write_scrape_file(&self) {
        let Some(home) = std::env::var_os("HOME") else {
            return;
        };
        let path = std::path::Path::new(&home)
            .join(".mvm/audit")
            .join(format!("metrics-{}-observer-latency.prom", self.vm));
        self.write_scrape_file_to(&path);
    }

    pub fn write_scrape_file_to(&self, path: &std::path::Path) {
        let body = self.prometheus_format();
        let tmp = path.with_extension("prom.tmp");
        if std::fs::write(&tmp, body).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::audit::FlowDirection;

    #[test]
    fn record_accumulates_sum_and_count() {
        let l = ObserverLatency::new("vm-a", "acme");
        l.record("egress-redactor", FlowDirection::Egress, 10);
        l.record("egress-redactor", FlowDirection::Egress, 30);
        let prom = l.prometheus_format();
        assert!(
            prom.contains(
                "mvm_observer_latency_us_count{observer=\"egress-redactor\",vm=\"vm-a\",direction=\"egress\"} 2"
            ),
            "prom was: {prom}"
        );
        assert!(
            prom.contains(
                "mvm_observer_latency_us_sum{observer=\"egress-redactor\",vm=\"vm-a\",direction=\"egress\"} 40"
            ),
            "prom was: {prom}"
        );
    }

    #[test]
    fn separate_directions_bucket_independently() {
        let l = ObserverLatency::new("vm-b", "t");
        l.record("o", FlowDirection::Egress, 5);
        l.record("o", FlowDirection::Ingress, 7);
        let prom = l.prometheus_format();
        assert!(prom.contains("direction=\"egress\"} 1"));
        assert!(prom.contains("direction=\"ingress\"} 1"));
    }

    #[test]
    fn write_scrape_file_to_uses_observer_latency_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".mvm/audit")).unwrap();
        let l = ObserverLatency::new("vm-x", "t");
        l.record("hostname-filter", FlowDirection::Egress, 5);
        let target = dir
            .path()
            .join(".mvm/audit/metrics-vm-x-observer-latency.prom");
        l.write_scrape_file_to(&target);
        let body = std::fs::read_to_string(&target).unwrap();
        assert!(body.contains("mvm_observer_latency_us_count"));
    }
}
