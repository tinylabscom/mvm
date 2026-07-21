//! Internal event types that flow from the bridge tasks to the
//! per-VM [`super::signer::signer_task`]: [`FlowEvent`] / [`FlowEventKind`],
//! the packet-observer wiring bundle [`ObserverWiring`], and the
//! NDJSON wire shape [`FlowEventWire`] subscribers consume.

use std::collections::HashSet;
use std::sync::Arc;

use crate::supervisor::audit::{FlowCloseReason, FlowDirection};
use crate::supervisor::network::Observer;
use crate::supervisor::network::latency::ObserverLatency;
use crate::supervisor::network::packet::FlowKey;
use crate::supervisor::network::stages::{ScanStage, SubstitutionStage};

/// Event the bridge tasks push into the signer mpsc. Visibility is
/// `pub` (not `pub(crate)`) so external observer
/// impls hosted in this same crate can be reached through
/// `BridgeConfig.observers` (a `pub` field whose element type is
/// `Arc<dyn Observer>`, which receives `&FlowEvent` in `on_flow_event`).
/// The struct stays unconstructible outside `mvm-supervisor` in
/// practice because every bridge variant lives inside this module.
#[derive(Debug, Clone)]
pub struct FlowEvent {
    pub flow_id: String,
    pub direction: FlowDirection,
    pub kind: FlowEventKind,
}

#[derive(Debug, Clone)]
pub enum FlowEventKind {
    Opened,
    Closed {
        reason: FlowCloseReason,
    },
    /// A host-allowlisted observer's `on_packet` forced a fail-closed
    /// flow kill. `reason` ∈ {`drop`,
    /// `modify_over_mtu`, `modify_unserializable`}.
    ObserverFault {
        observer: String,
        reason: String,
    },
}

/// Bounded mpsc capacity. The bridge `send().await`s — overflow
/// applies backpressure to the splice loop, which translates to
/// TCP / datagram flow control on the guest's network stack.
/// **Audit completeness > per-VM throughput.**
pub const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Frame-size ceiling for `Verdict::Modify` rebuilds. A rebuilt frame
/// larger than this cannot traverse the unixgram / length-prefixed
/// datagram path, so the flow is killed (fail-closed). Set to the
/// practical datagram max rather than the 1500 link MTU
/// so a legitimately large (e.g. TSO) original frame isn't spuriously
/// killed when an observer shrinks or keeps its payload size.
pub const BRIDGE_MTU: usize = 65_535;

/// Per-VM packet-observer wiring threaded into the bridge variants.
/// Bundled into one struct so the variant fns stay under the
/// `too_many_arguments` lint. `observers` mirrors the set
/// `signer_task` fans flow-events to; the same observer may implement both
/// `on_flow_event` and `on_packet`. `killed_flows` is shared across both
/// directions so a kill on one is honoured everywhere.
pub struct ObserverWiring {
    pub observers: Vec<Arc<dyn Observer>>,
    pub latency: Arc<ObserverLatency>,
    pub killed_flows: Arc<tokio::sync::Mutex<HashSet<FlowKey>>>,
    pub mtu: usize,
    pub transcript_capture_roots: Option<TranscriptCaptureRoots>,
    /// Egress stages. Default no-op; the secrets subsystem sets these so its
    /// substitution/leak-scan run on the live egress path without a code edit.
    pub substitution: Arc<dyn SubstitutionStage>,
    pub scan: Arc<dyn ScanStage>,
}

#[derive(Debug, Clone)]
pub struct TranscriptCaptureRoots {
    pub transcripts_dir: std::path::PathBuf,
    pub keys_dir: std::path::PathBuf,
}

/// Per-subscriber NDJSON wire shape. Stable contract for `nc -U`
/// consumers and the Swift bridge (which emits the same shape).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowEventWire {
    FlowOpened {
        flow_id: String,
        direction: String,
    },
    FlowClosed {
        flow_id: String,
        direction: String,
        reason: String,
    },
    FlowObserverFault {
        flow_id: String,
        direction: String,
        observer: String,
        reason: String,
    },
}

impl From<&FlowEvent> for FlowEventWire {
    fn from(ev: &FlowEvent) -> Self {
        match &ev.kind {
            FlowEventKind::Opened => FlowEventWire::FlowOpened {
                flow_id: ev.flow_id.clone(),
                direction: ev.direction.as_str().to_string(),
            },
            FlowEventKind::Closed { reason } => FlowEventWire::FlowClosed {
                flow_id: ev.flow_id.clone(),
                direction: ev.direction.as_str().to_string(),
                reason: reason.as_str().to_string(),
            },
            FlowEventKind::ObserverFault { observer, reason } => FlowEventWire::FlowObserverFault {
                flow_id: ev.flow_id.clone(),
                direction: ev.direction.as_str().to_string(),
                observer: observer.clone(),
                reason: reason.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // FlowEventWire serde
    // -----------------------------------------------------------------

    #[test]
    fn flow_event_wire_opened_serializes_as_expected() {
        let w = FlowEventWire::FlowOpened {
            flow_id: "vm-a-egress".to_string(),
            direction: "egress".to_string(),
        };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("\"kind\":\"flow_opened\""));
        assert!(json.contains("\"flow_id\":\"vm-a-egress\""));
        assert!(json.contains("\"direction\":\"egress\""));
        let parsed: FlowEventWire = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, w);
    }

    #[test]
    fn flow_event_wire_closed_serializes_with_reason() {
        let w = FlowEventWire::FlowClosed {
            flow_id: "vm-a-egress".to_string(),
            direction: "egress".to_string(),
            reason: "eof".to_string(),
        };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("\"kind\":\"flow_closed\""));
        assert!(json.contains("\"reason\":\"eof\""));
        let parsed: FlowEventWire = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, w);
    }

    #[test]
    fn flow_event_to_wire_converts_correctly() {
        let opened = FlowEvent {
            flow_id: "f1".to_string(),
            direction: FlowDirection::Egress,
            kind: FlowEventKind::Opened,
        };
        let wire = FlowEventWire::from(&opened);
        assert!(matches!(
            wire,
            FlowEventWire::FlowOpened { ref flow_id, .. } if flow_id == "f1"
        ));

        let closed = FlowEvent {
            flow_id: "f1".to_string(),
            direction: FlowDirection::Egress,
            kind: FlowEventKind::Closed {
                reason: FlowCloseReason::PolicyDropped,
            },
        };
        let wire = FlowEventWire::from(&closed);
        match wire {
            FlowEventWire::FlowClosed {
                flow_id, reason, ..
            } => {
                assert_eq!(flow_id, "f1");
                assert_eq!(reason, "policy_dropped");
            }
            other => panic!("expected FlowClosed, got {other:?}"),
        }
    }

    #[test]
    fn flow_event_observer_fault_wire_roundtrips() {
        let ev = FlowEvent {
            flow_id: "vm-egress".to_string(),
            direction: FlowDirection::Egress,
            kind: FlowEventKind::ObserverFault {
                observer: "test-redactor".to_string(),
                reason: "modify_over_mtu".to_string(),
            },
        };
        let wire = FlowEventWire::from(&ev);
        let json = serde_json::to_string(&wire).unwrap();
        assert!(json.contains("\"kind\":\"flow_observer_fault\""));
        assert!(json.contains("\"observer\":\"test-redactor\""));
        assert!(json.contains("\"reason\":\"modify_over_mtu\""));
        let parsed: FlowEventWire = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, wire);
    }
}
