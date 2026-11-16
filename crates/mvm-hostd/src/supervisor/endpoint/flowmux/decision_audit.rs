//! Synchronous decision writes; failure accounting belongs exclusively to the sink.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Mutex;

use mvm_core::audit_sink::AuditSink;

use super::{FlowMuxError, FlowMuxSession, registry::FlowClass};

pub(super) fn record(
    sink: &dyn AuditSink,
    event: &str,
    labels: BTreeMap<String, String>,
) -> std::io::Result<()> {
    sink.record(event, labels).inspect_err(|error| {
        tracing::warn!(%error, event, "FlowMux audit write failed; epoch marked incomplete");
    })
}

/// Shared by the session and its UDP relay; only successful writes enter the cache.
#[derive(Default)]
pub(super) struct UdpDenials(Mutex<BTreeSet<SocketAddr>>);

impl UdpDenials {
    pub(super) fn record(
        &self,
        sink: &dyn AuditSink,
        stream_id: u32,
        target: SocketAddr,
        reason: &str,
        capacity: usize,
    ) {
        let mut recorded = self.0.lock().expect("UDP denial cache poisoned");
        if recorded.contains(&target) {
            sink.suppress_denial();
            return;
        }
        let mut labels = udp_labels(stream_id, target);
        labels.insert("reason".into(), reason.into());
        if record(sink, "host.flow.denied", labels).is_ok() && recorded.len() < capacity {
            recorded.insert(target);
        }
    }
}

pub(super) fn udp_labels(stream_id: u32, target: SocketAddr) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("stream_id".into(), stream_id.to_string()),
        ("class".into(), "udp".into()),
        ("target".into(), target.to_string()),
    ])
}

impl FlowMuxSession {
    pub(super) fn record_protocol_refusal(&self, stream_id: u32, reason: &str) {
        self.record_denial(
            "host.flow.denied",
            BTreeMap::from([
                ("stream_id".into(), stream_id.to_string()),
                ("class".into(), "session".into()),
                ("reason".into(), reason.into()),
            ]),
        );
    }

    pub(super) fn record_handler_error(
        &self,
        stream_id: u32,
        class: FlowClass,
        error: &FlowMuxError,
    ) {
        if matches!(error, FlowMuxError::Audit(_)) {
            return;
        }
        let event = if class == FlowClass::Icmp {
            "icmp.refused"
        } else {
            "host.flow.denied"
        };
        self.record_denial(
            event,
            BTreeMap::from([
                ("stream_id".into(), stream_id.to_string()),
                ("class".into(), class.to_string()),
                ("reason".into(), "host_refused".into()),
            ]),
        );
    }

    pub(super) fn record_dns_refusal(&self, stream_id: u32, reason: &str) {
        self.record_denial(
            "dns.refused",
            BTreeMap::from([
                ("stream_id".into(), stream_id.to_string()),
                ("reason".into(), reason.into()),
            ]),
        );
    }

    pub(super) fn record_allow(
        &self,
        event: &str,
        labels: BTreeMap<String, String>,
    ) -> std::io::Result<()> {
        record(self.audit_sink.as_ref(), event, labels)
    }

    pub(super) fn record_denial(&self, event: &str, labels: BTreeMap<String, String>) {
        // A failed write has marked the epoch incomplete before returning.
        if record(self.audit_sink.as_ref(), event, labels).is_err() {
            tracing::debug!(event, "FlowMux preserves denial after audit failure");
        }
    }
}
