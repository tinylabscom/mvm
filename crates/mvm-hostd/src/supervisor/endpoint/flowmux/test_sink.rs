//! Explicit fixture adapter preserving real signed-chain assertions.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use mvm_core::audit_sink::{AuditHealth, AuditSink};

use crate::supervisor::audit::audit_recorder::{EventCategory, Recorder};

pub(super) struct RecorderSink {
    recorder: Arc<Recorder>,
    runtime: tokio::runtime::Handle,
    health: Mutex<AuditHealth>,
}

impl RecorderSink {
    pub(super) fn wrap(recorder: Arc<Recorder>) -> Arc<dyn AuditSink> {
        Arc::new(Self {
            recorder,
            runtime: tokio::runtime::Handle::current(),
            health: Mutex::new(AuditHealth::default()),
        })
    }
}

impl AuditSink for RecorderSink {
    fn record(&self, event: &str, labels: BTreeMap<String, String>) -> std::io::Result<()> {
        let category = if event.starts_with("dns.") {
            EventCategory::Dns
        } else if event.starts_with("icmp.") {
            EventCategory::Icmp
        } else {
            EventCategory::Host
        };
        let mut health = self.health.lock().unwrap();
        let result = self
            .runtime
            .block_on(self.recorder.record_unbound(category, event, labels))
            .map_err(std::io::Error::other);
        if result.is_ok() {
            health.record_success();
        } else {
            health.record_failure();
        }
        result
    }

    fn suppress_denial(&self) {
        self.health.lock().unwrap().suppress_denial();
    }

    fn flush_health(&self) -> std::io::Result<()> {
        Ok(())
    }
}
