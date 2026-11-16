//! ICMP decision metadata, written by the shared admission handler before echo.

use std::collections::BTreeMap;

use mvm_core::audit_sink::AuditSink;

use crate::supervisor::audit::icmp_audit::EchoAudit;

use super::{FlowMuxError, FlowMuxSession, Opcode, decision_audit, lock_registry, registry};

impl FlowMuxSession {
    /// Keep parse, admission and rate policy in the transport-independent handler.
    pub(super) fn handle_icmp_echo(
        &mut self,
        stream_id: u32,
        payload_len: u32,
    ) -> Result<(), FlowMuxError> {
        use crate::supervisor::{datapath::icmp_echo, datapath::icmp_handler};

        if !self.check_connection_rate(registry::FlowClass::Icmp) {
            return Err(FlowMuxError::FrameRefused("icmp rate limit".to_string()));
        }
        lock_registry(&self.registry)
            .open_guest(stream_id, registry::FlowClass::Icmp)
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
        let line = String::from_utf8_lossy(self.frame_payload(payload_len)).into_owned();
        let (replies, _) = icmp_handler::serve_request_audited(
            &line,
            &self.gate,
            &self.icmp_rate,
            &icmp_echo::PingSocketEcho,
            |audit| record(self.audit_sink.as_ref(), audit),
        );
        // One echo per flow; the last reply retires it even on refusal.
        let last = replies.len().saturating_sub(1);
        for (index, reply) in replies.into_iter().enumerate() {
            let encoded = serde_json::to_vec(&reply)
                .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
            let opcode = match reply {
                mvm_core::icmp_wire::IcmpEchoReply::Refused { .. } => Opcode::IcmpRefused,
                _ => Opcode::IcmpReply,
            };
            self.write_frame(opcode, stream_id, &encoded)?;
            if index == last {
                self.mark_sent(opcode, stream_id);
            }
        }
        self.remove_stream(stream_id);
        Ok(())
    }
}

pub(super) fn record(sink: &dyn AuditSink, audit: &EchoAudit) -> std::io::Result<()> {
    let (event, labels) = match audit {
        EchoAudit::Admitted { host, ip, count } => (
            "icmp.admitted",
            BTreeMap::from([
                ("host".into(), host.clone()),
                ("ip".into(), ip.clone()),
                ("count".into(), count.to_string()),
                ("verdict".into(), "admitted".into()),
            ]),
        ),
        EchoAudit::Refused { host, reason } => (
            "icmp.refused",
            BTreeMap::from([
                ("host".into(), host.clone()),
                ("reason".into(), reason.clone()),
                ("verdict".into(), "refused".into()),
            ]),
        ),
    };
    decision_audit::record(sink, event, labels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::datapath::{
        egress_rate::EgressRateGuard, icmp_echo::EchoTransport, icmp_handler,
    };
    use crate::supervisor::endpoint::flowmux::{
        audit_tests::CapturingSink, tests::gate_pinning_name,
    };
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    struct NoEcho;

    impl EchoTransport for NoEcho {
        fn echo(
            &self,
            _: std::net::IpAddr,
            _: u16,
            _: u16,
            _: Duration,
        ) -> std::io::Result<Option<Duration>> {
            panic!("a failed allow must not reach the echo transport");
        }
    }

    #[test]
    fn a_failed_icmp_allow_is_recorded_before_any_echo() {
        let gate = gate_pinning_name("echo.test", "93.184.216.34".parse().unwrap(), 443);
        let sink = CapturingSink::default();
        sink.fail.store(true, Ordering::SeqCst);
        let (replies, _) = icmp_handler::serve_request_audited(
            r#"{"host":"echo.test","count":1,"payload_len":8,"timeout_ms":100}"#,
            &gate,
            &EgressRateGuard::default(),
            &NoEcho,
            |audit| record(&sink, audit),
        );
        assert!(matches!(
            replies.as_slice(),
            [mvm_core::icmp_wire::IcmpEchoReply::Refused { .. }]
        ));
        assert!(sink.incomplete.load(Ordering::SeqCst));
        assert_eq!(sink.records.lock().unwrap()[0].0, "icmp.admitted");
    }
}
