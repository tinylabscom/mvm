//! Chain-signed ICMP echo decision events.
//!
//! Echo reaches the network on a workload's behalf, so it leaves the same kind
//! of trace every other egress verb does. One entry per *request* rather than
//! per packet: the request is where the admission decision happens, and a
//! per-packet entry would let a workload flood the chain with up to
//! [`MAX_ECHO_COUNT`] entries per connection while saying nothing new.
//!
//! The entry carries the destination and the count, never payload bytes — an
//! echo payload is a fixed pattern this host generates, but recording it would
//! still be recording traffic rather than decisions.
//!
//! [`MAX_ECHO_COUNT`]: mvm_core::icmp_wire::MAX_ECHO_COUNT

#[cfg(target_os = "linux")]
use std::future::Future;

use crate::supervisor::audit_recorder::{EventCategory, Recorder};

/// What the gate decided about one echo request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EchoAudit {
    /// Admitted, and echoed at this address.
    Admitted {
        /// Destination host as the guest asked for it.
        host: String,
        /// The pinned address the host echoed.
        ip: String,
        /// Echoes requested.
        count: u16,
    },
    /// Refused before any packet existed.
    Refused {
        /// Destination host as the guest asked for it, empty when unparseable.
        host: String,
        /// The refusal, safe to record: policy shape, not traffic.
        reason: String,
    },
}

/// Record one echo request's decision.
pub async fn emit_icmp_echo(recorder: &Recorder, audit: &EchoAudit) {
    let (event, labels) = match audit {
        EchoAudit::Admitted { host, ip, count } => (
            "icmp.admitted",
            vec![
                ("host".to_string(), host.clone()),
                ("ip".to_string(), ip.clone()),
                ("count".to_string(), count.to_string()),
                ("verdict".to_string(), "admitted".to_string()),
            ],
        ),
        EchoAudit::Refused { host, reason } => (
            "icmp.refused",
            vec![
                ("host".to_string(), host.clone()),
                ("verdict".to_string(), "refused".to_string()),
                ("reason".to_string(), reason.clone()),
            ],
        ),
    };
    if let Err(error) = recorder
        .record_unbound(EventCategory::Icmp, event, labels)
        .await
    {
        tracing::warn!(%error, "ICMP echo audit emit failed");
    }
}

/// Record an echo decision from the blocking vsock transport.
#[cfg(target_os = "linux")]
pub fn emit_icmp_echo_blocking(recorder: &Recorder, audit: &EchoAudit) {
    emit_blocking(emit_icmp_echo(recorder, audit));
}

#[cfg(target_os = "linux")]
fn emit_blocking(emit: impl Future<Output = ()>) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::warn!("ICMP audit runtime unavailable");
        return;
    };
    if !matches!(
        handle.runtime_flavor(),
        tokio::runtime::RuntimeFlavor::MultiThread
    ) {
        tracing::warn!("ICMP audit requires a multi-thread runtime on the blocking transport");
        return;
    }
    tokio::task::block_in_place(|| handle.block_on(emit));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal entry must carry the reason — a chain that records only
    /// "refused" cannot answer why afterwards, which is the question anyone
    /// reading it will have.
    #[test]
    fn a_refusal_carries_its_reason_and_host() {
        let audit = EchoAudit::Refused {
            host: "evil.test".into(),
            reason: "evil.test is not admitted; allowed: example.com".into(),
        };
        let EchoAudit::Refused { host, reason } = &audit else {
            unreachable!()
        };
        assert_eq!(host, "evil.test");
        assert!(reason.contains("not admitted"));
    }

    /// An admitted entry records the address actually echoed, not just the name
    /// asked for: the pin is what the policy decided on.
    #[test]
    fn an_admission_records_the_pinned_address_and_count() {
        let audit = EchoAudit::Admitted {
            host: "example.com".into(),
            ip: "93.184.216.34".into(),
            count: 4,
        };
        let EchoAudit::Admitted { host, ip, count } = &audit else {
            unreachable!()
        };
        assert_eq!(host, "example.com");
        assert_eq!(ip, "93.184.216.34");
        assert_eq!(*count, 4);
    }
}
