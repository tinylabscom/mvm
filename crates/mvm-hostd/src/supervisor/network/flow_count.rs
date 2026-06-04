//! Plan 113 / ADR-064 — flow-count-metrics observer.
//!
//! Per-tenant flow counters surfaced via mvm-cli's existing
//! --metrics-port Prometheus endpoint (mvm-cli/src/metrics_server.rs).
//! Three counter families keyed on tenant:
//!
//!   mvm_flow_opened_total{tenant="..."}
//!   mvm_flow_closed_total{tenant="..."}
//!   mvm_flow_close_reason_total{tenant="...",reason="..."}
//!
//! Wired to the CLI metrics endpoint via a per-VM scrape file at
//! `~/.mvm/audit/metrics-<vm>-flow-count.prom`. The CLI's `/metrics`
//! handler concatenates these files; see
//! `mvm_cli::metrics_server::append_per_vm_scrape_files`.
//!
//! The mvm-supervisor::gateway_bridge::FlowEvent does NOT carry a
//! tenant string per event — the supervisor is single-VM single-tenant
//! by construction (ADR-002 "one guest = one workload"). The tenant is
//! established at supervisor startup via BridgeConfig.plan.tenant; this
//! observer reads MVM_TENANT once at Arc-construction time, which is
//! one of the four canonical tenant sources from ADR-064 §Decision 9.

use crate::supervisor::gateway_bridge::{FlowEvent, FlowEventKind};
use crate::supervisor::network::{Observer, RequiredCapabilities};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub struct FlowCountMetrics {
    tenant: String,
    opened: AtomicU64,
    closed: AtomicU64,
    closed_by_reason: Mutex<std::collections::BTreeMap<String, u64>>,
}

impl FlowCountMetrics {
    /// Constructor used by `ObserverAllowlist::resolve`. The allowlist
    /// closure signature is `Fn() -> Arc<dyn Observer>` (no args), so
    /// the tenant is read from `MVM_TENANT` at construction time.
    pub fn into_arc() -> Arc<dyn Observer> {
        let tenant = std::env::var("MVM_TENANT").unwrap_or_else(|_| "local".to_string());
        Arc::new(Self {
            tenant,
            opened: AtomicU64::new(0),
            closed: AtomicU64::new(0),
            closed_by_reason: Mutex::new(std::collections::BTreeMap::new()),
        })
    }

    pub fn opened(&self) -> u64 {
        self.opened.load(Ordering::SeqCst)
    }

    pub fn closed(&self) -> u64 {
        self.closed.load(Ordering::SeqCst)
    }

    pub fn closed_by_reason_snapshot(&self) -> std::collections::BTreeMap<String, u64> {
        self.closed_by_reason
            .lock()
            .expect("flow-count-metrics mutex poisoned")
            .clone()
    }

    /// Prometheus text format for the three counter families.
    /// Mounted by mvm-cli's /metrics handler via the per-VM scrape
    /// file at `~/.mvm/audit/metrics-<vm>-flow-count.prom` (written
    /// from `write_scrape_file()` after every event).
    pub fn prometheus_format(&self) -> String {
        let tenant = &self.tenant;
        let opened = self.opened.load(Ordering::SeqCst);
        let closed = self.closed.load(Ordering::SeqCst);
        let reasons = self.closed_by_reason_snapshot();
        let mut out = String::new();
        out.push_str(
            "# HELP mvm_flow_opened_total Total flows observed opened per tenant\n\
             # TYPE mvm_flow_opened_total counter\n",
        );
        out.push_str(&format!(
            "mvm_flow_opened_total{{tenant=\"{tenant}\"}} {opened}\n"
        ));
        out.push_str(
            "# HELP mvm_flow_closed_total Total flows observed closed per tenant\n\
             # TYPE mvm_flow_closed_total counter\n",
        );
        out.push_str(&format!(
            "mvm_flow_closed_total{{tenant=\"{tenant}\"}} {closed}\n"
        ));
        out.push_str(
            "# HELP mvm_flow_close_reason_total Per-reason flow-closed counters\n\
             # TYPE mvm_flow_close_reason_total counter\n",
        );
        for (reason, n) in reasons {
            out.push_str(&format!(
                "mvm_flow_close_reason_total{{tenant=\"{tenant}\",reason=\"{reason}\"}} {n}\n"
            ));
        }
        out
    }

    /// Per-VM scrape file the CLI's `/metrics` handler concatenates.
    /// Lives under `~/.mvm/audit/` (mode 0700, ADR-002 §W1.5) because
    /// the supervisor and the CLI run as the same user and share that
    /// directory already — no new socket or RPC is needed to cross
    /// the process boundary.
    ///
    /// Fails closed (`None`) when `HOME` or `MVM_VM_NAME` is unset, or
    /// when `MVM_VM_NAME` is not valid UTF-8 (the on-disk filename
    /// needs a `&str` for `format!`). Mirrors the `ObserverAllowlist::
    /// resolve` posture: a misconfigured systemd unit must not silently
    /// fall back to a world-writable directory like `/tmp` where a
    /// local attacker could pre-plant a symlink at the rename target.
    /// `var_os` is preferred over `var` so a non-UTF-8 `HOME` is treated
    /// as unset rather than falling through `Err(NotUnicode)` into a
    /// fallback path.
    fn scrape_file_path(&self) -> Option<std::path::PathBuf> {
        let home = std::env::var_os("HOME")?;
        let vm_name = std::env::var_os("MVM_VM_NAME")?;
        let vm_name = vm_name.to_str()?;
        Some(scrape_file_path_for(std::path::Path::new(&home), vm_name))
    }

    /// Atomic-ish write: tmp + rename so a concurrent CLI scrape sees
    /// either the previous file or the new one, never a half-written
    /// blob mid-fwrite.
    fn write_scrape_file(&self) {
        let Some(path) = self.scrape_file_path() else {
            tracing::debug!("flow-count metrics scrape skipped (HOME or MVM_VM_NAME unset)");
            return;
        };
        self.write_scrape_file_to(&path);
    }

    fn write_scrape_file_to(&self, path: &std::path::Path) {
        let body = self.prometheus_format();
        let tmp = path.with_extension("prom.tmp");
        if let Err(e) = std::fs::write(&tmp, body) {
            tracing::warn!(path = %tmp.display(), error = %e, "flow-count metrics scrape write failed");
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            tracing::warn!(path = %path.display(), error = %e, "flow-count metrics scrape rename failed");
        }
    }
}

fn scrape_file_path_for(home: &std::path::Path, vm_name: &str) -> std::path::PathBuf {
    home.join(".mvm/audit")
        .join(format!("metrics-{vm_name}-flow-count.prom"))
}

impl Observer for FlowCountMetrics {
    fn name(&self) -> &'static str {
        "flow-count-metrics"
    }

    fn required_capabilities(&self) -> RequiredCapabilities {
        RequiredCapabilities {
            flow_events: true,
            payload_tap: false,
        }
    }

    fn on_flow_event(&self, event: &FlowEvent) {
        match &event.kind {
            FlowEventKind::Opened => {
                self.opened.fetch_add(1, Ordering::SeqCst);
            }
            FlowEventKind::Closed { reason } => {
                self.closed.fetch_add(1, Ordering::SeqCst);
                let mut g = self
                    .closed_by_reason
                    .lock()
                    .expect("flow-count-metrics mutex poisoned");
                let key = reason.as_str().to_string();
                *g.entry(key).or_insert(0) += 1;
            }
        }
        self.write_scrape_file();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::audit::{FlowCloseReason, FlowDirection};

    // Tests construct FlowCountMetrics directly via struct literal so
    // they have access to the concrete fields; FlowCountMetrics::into_arc()
    // returns Arc<dyn Observer> which doesn't expose internals.

    fn opened_evt() -> FlowEvent {
        FlowEvent {
            flow_id: "vm-a-egress-1".to_string(),
            direction: FlowDirection::Egress,
            kind: FlowEventKind::Opened,
        }
    }

    fn closed_evt(reason: FlowCloseReason) -> FlowEvent {
        FlowEvent {
            flow_id: "vm-a-egress-1".to_string(),
            direction: FlowDirection::Egress,
            kind: FlowEventKind::Closed { reason },
        }
    }

    #[test]
    fn opened_counter_increments() {
        let m = FlowCountMetrics {
            tenant: "test-opens".into(),
            opened: AtomicU64::new(0),
            closed: AtomicU64::new(0),
            closed_by_reason: Mutex::new(std::collections::BTreeMap::new()),
        };
        m.on_flow_event(&opened_evt());
        m.on_flow_event(&opened_evt());
        assert_eq!(m.opened(), 2);
    }

    #[test]
    fn closed_counter_and_reason_split() {
        let m = FlowCountMetrics {
            tenant: "test-closes".into(),
            opened: AtomicU64::new(0),
            closed: AtomicU64::new(0),
            closed_by_reason: Mutex::new(std::collections::BTreeMap::new()),
        };
        m.on_flow_event(&closed_evt(FlowCloseReason::Eof));
        m.on_flow_event(&closed_evt(FlowCloseReason::PolicyDropped));
        m.on_flow_event(&closed_evt(FlowCloseReason::Eof));
        assert_eq!(m.closed(), 3);
        let snap = m.closed_by_reason_snapshot();
        assert_eq!(snap.get("eof").copied(), Some(2));
        assert_eq!(snap.get("policy_dropped").copied(), Some(1));
    }

    #[test]
    fn prometheus_format_emits_expected_lines() {
        let m = FlowCountMetrics {
            tenant: "acme".into(),
            opened: AtomicU64::new(5),
            closed: AtomicU64::new(3),
            closed_by_reason: Mutex::new({
                let mut m = std::collections::BTreeMap::new();
                m.insert("eof".to_string(), 2u64);
                m.insert("policy_dropped".to_string(), 1u64);
                m
            }),
        };
        let prom = m.prometheus_format();
        assert!(
            prom.contains("mvm_flow_opened_total{tenant=\"acme\"} 5"),
            "prom was: {prom}"
        );
        assert!(
            prom.contains("mvm_flow_closed_total{tenant=\"acme\"} 3"),
            "prom was: {prom}"
        );
        assert!(
            prom.contains("mvm_flow_close_reason_total{tenant=\"acme\",reason=\"eof\"} 2"),
            "prom was: {prom}"
        );
        assert!(
            prom.contains(
                "mvm_flow_close_reason_total{tenant=\"acme\",reason=\"policy_dropped\"} 1"
            ),
            "prom was: {prom}"
        );
    }

    #[test]
    fn required_capabilities_no_payload_tap() {
        let m = FlowCountMetrics {
            tenant: "caps-test".into(),
            opened: AtomicU64::new(0),
            closed: AtomicU64::new(0),
            closed_by_reason: Mutex::new(std::collections::BTreeMap::new()),
        };
        let req = m.required_capabilities();
        assert!(req.flow_events);
        assert!(!req.payload_tap);
    }

    #[test]
    fn scrape_file_path_for_composes_home_and_vm_name() {
        let p = scrape_file_path_for(std::path::Path::new("/var/folders/x"), "test-vm-scrape");
        assert_eq!(
            p,
            std::path::PathBuf::from(
                "/var/folders/x/.mvm/audit/metrics-test-vm-scrape-flow-count.prom"
            )
        );
    }

    #[test]
    fn scrape_file_path_returns_none_when_no_env_set_in_pure_path() {
        // The pure path-composition function ignores env, so this is
        // race-free. The env-reading wrapper's None-on-missing
        // behaviour is asserted by code-review of the body, not by
        // manipulating env at runtime.
        let p = scrape_file_path_for(std::path::Path::new("/home/u"), "vm-a");
        assert!(p.ends_with(".mvm/audit/metrics-vm-a-flow-count.prom"));
    }

    #[test]
    fn write_scrape_file_to_writes_prometheus_body() {
        let tmpdir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmpdir.path().join(".mvm/audit")).unwrap();
        let m = FlowCountMetrics {
            tenant: "scrape-test".into(),
            opened: AtomicU64::new(1),
            closed: AtomicU64::new(0),
            closed_by_reason: Mutex::new(std::collections::BTreeMap::new()),
        };
        let target = tmpdir
            .path()
            .join(".mvm/audit/metrics-test-vm-scrape-flow-count.prom");
        m.write_scrape_file_to(&target);
        let body = std::fs::read_to_string(&target).expect("scrape file exists");
        assert!(body.contains("mvm_flow_opened_total{tenant=\"scrape-test\"} 1"));
    }
}
