//! The node-control wire types.
//!
//! Every type here fails closed on a field it does not know: a caller that
//! sends a request this build cannot fully understand is refused rather than
//! served a partial interpretation of it. New fields arrive with
//! `#[serde(default)]`, so a node one revision behind reads what it can and
//! nothing it cannot.

use serde::{Deserialize, Serialize};

use mvm_net::channel::VmInstanceIdentity;
use mvm_net::lease::NetworkLease;

use crate::netd::ForwardingCapabilities;

/// Wire version of the node-control protocol.
pub const NODE_CONTROL_VERSION: u32 = 1;

/// What a caller asks a node.
///
/// Every variant is answerable from state this node owns. There is
/// deliberately no request about another node: a node that answered one
/// would be asserting something it cannot verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeControlRequest {
    /// What this node is and what its forwarding backend can carry.
    DescribeNode(DescribeNode),
    /// The machines the caller owns on this node.
    ListMachines(ListMachines),
    /// One machine the caller owns.
    DescribeMachine(DescribeMachine),
}

/// Ask what this node is. Carries no fields today; a struct rather than a
/// unit variant so one can be added without changing the wire shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescribeNode {}

/// Ask for the caller's machines.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListMachines {}

/// Ask about one machine by its stable id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescribeMachine {
    pub vm_id: String,
}

/// One request, with the protocol version it was written against.
///
/// The version is outside the request rather than inside each variant, so a
/// node can refuse an unreadable message without first deciding what kind of
/// message it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeControlEnvelope {
    pub version: u32,
    pub request: NodeControlRequest,
}

impl NodeControlEnvelope {
    /// An envelope at this build's version.
    pub fn current(request: NodeControlRequest) -> Self {
        Self {
            version: NODE_CONTROL_VERSION,
            request,
        }
    }
}

/// What a node answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeControlResponse {
    Node(NodeDescription),
    Machines(MachineList),
    /// Boxed because a description carries a whole lease and the other
    /// variants are small; the wire shape is unaffected, a `Box` being
    /// transparent to serde.
    Machine(Box<MachineDescription>),
    Refused(Refusal),
}

/// What this node is, and what it will not do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDescription {
    pub version: u32,
    pub node_id: String,
    /// The selected forwarding backend's own report, carried through
    /// unchanged. A control plane admitting a workload against this node
    /// reads the same structure the node's admission reads, so the two
    /// cannot disagree about what is serveable.
    pub forwarding: ForwardingCapabilities,
    /// Why forwarding is not the packet-level path, when it is not. Present
    /// so a later refusal for a capability the fallback lacks arrives with
    /// its cause already known.
    #[serde(default)]
    pub forwarding_fallback_reason: Option<String>,
    /// Fleet-level work this node does not do. Reported rather than
    /// discovered by a caller whose request fails.
    pub unserved: Vec<Unserved>,
}

/// Fleet-level capabilities this node does not have.
///
/// Distinct from [`ForwardingCapabilities`], which reports what the packet
/// path can carry for a machine already on this node. These are about
/// whether a *second* node exists as far as this one is concerned, and each
/// one is a property no code in this repository can supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unserved {
    /// No issuer whose signing key is not this node's own. Without one a
    /// node can neither verify what a peer says nor learn a peer's key from
    /// anywhere but the peer.
    CrossNodeTrustRoot,
    /// Addresses are allocated per node against a per-process cursor, so a
    /// peer's address collides with a local machine's and the two are not
    /// distinguishable from the packet.
    CrossNodeAddressUniqueness,
    /// The policy language names addresses, not workloads, and an ingress
    /// declaration carries no source — so admitting a peer would admit
    /// everything that can reach this host's port.
    PeerScopedPolicy,
    /// Gateway decisions are counters and stderr lines, not chain-signed
    /// audit entries, so there is no local record for a cross-node
    /// decision to be part of.
    GatewayAuditChain,
}

impl Unserved {
    /// Everything this build does not serve. One list, so a caller cannot
    /// read a shorter one by asking a different way.
    pub const ALL: &'static [Unserved] = &[
        Unserved::CrossNodeTrustRoot,
        Unserved::CrossNodeAddressUniqueness,
        Unserved::PeerScopedPolicy,
        Unserved::GatewayAuditChain,
    ];
}

/// The machines a caller owns, by identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineList {
    pub machines: Vec<VmInstanceIdentity>,
}

/// One machine, with the signed grant it is running under.
///
/// The lease is carried whole rather than summarised: it is already the
/// object both sides authorize against, and a summary would be a second
/// representation of a policy that must not be able to drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineDescription {
    pub instance: VmInstanceIdentity,
    pub lease: NetworkLease,
    pub registered_at_millis: u64,
}

/// Why a request was not answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    pub reason: RefusalReason,
    /// Host-authored, and fixed per reason. Never carries what the caller
    /// asked for: a refusal that echoed the id back would confirm the id is
    /// worth asking about.
    pub detail: String,
}

impl Refusal {
    /// The single answer to every question about a machine the caller may
    /// not have.
    ///
    /// "No such machine" and "not yours" must be one response, byte for
    /// byte. A node that distinguished them would answer, for anyone who
    /// can open a connection to it, which machines exist here.
    pub fn not_found() -> Self {
        Self {
            reason: RefusalReason::NotFound,
            detail: "no such machine on this node".to_string(),
        }
    }

    pub fn unsupported_version(got: u32) -> Self {
        Self {
            reason: RefusalReason::UnsupportedVersion,
            detail: format!("node-control version {got} is not supported by this node"),
        }
    }

    pub fn malformed(detail: impl Into<String>) -> Self {
        Self {
            reason: RefusalReason::Malformed,
            detail: detail.into(),
        }
    }
}

/// The refusal taxonomy. Small on purpose: a caller acts on the class, and
/// a class per cause would leak the cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// The machine is not one this caller may be told about. Covers absent
    /// and not-owned alike.
    NotFound,
    /// The message named a protocol version this node does not read.
    UnsupportedVersion,
    /// The message did not parse, or carried a field this node does not
    /// know.
    Malformed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> NodeControlEnvelope {
        NodeControlEnvelope::current(NodeControlRequest::DescribeMachine(DescribeMachine {
            vm_id: "vm-a".to_string(),
        }))
    }

    #[test]
    fn a_request_envelope_roundtrips() {
        let json = serde_json::to_string(&envelope()).expect("encode");
        assert_eq!(
            serde_json::from_str::<NodeControlEnvelope>(&json).expect("decode"),
            envelope()
        );
    }

    /// A field this build does not know is a request it cannot fully honour.
    /// Serving it anyway would mean acting on an interpretation the caller
    /// did not ask for.
    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        let raw =
            r#"{"version":1,"request":{"kind":"describe_machine","vm_id":"vm-a"},"urgent":true}"#;
        assert!(serde_json::from_str::<NodeControlEnvelope>(raw).is_err());

        let nested =
            r#"{"version":1,"request":{"kind":"describe_machine","vm_id":"vm-a","scope":"all"}}"#;
        assert!(serde_json::from_str::<NodeControlEnvelope>(nested).is_err());
    }

    /// The refusal for a machine that is not there and the refusal for one
    /// the caller does not own are the same bytes, so nothing distinguishes
    /// them on the wire either.
    #[test]
    fn the_not_found_refusal_carries_nothing_caller_supplied() {
        let refusal = Refusal::not_found();
        assert_eq!(refusal, Refusal::not_found());
        assert!(!refusal.detail.contains("vm-"), "{}", refusal.detail);
    }

    #[test]
    fn a_response_roundtrips() {
        let response = NodeControlResponse::Refused(Refusal::not_found());
        let json = serde_json::to_string(&response).expect("encode");
        assert_eq!(
            serde_json::from_str::<NodeControlResponse>(&json).expect("decode"),
            response
        );
    }

    /// The node's forwarding report is the datapath's own structure. If it
    /// were copied into a second shape the two could disagree, and the
    /// disagreement would surface as a plan admitted by a control plane and
    /// refused by the node.
    #[test]
    fn the_node_description_carries_the_backends_own_capability_report() {
        let description = NodeDescription {
            version: NODE_CONTROL_VERSION,
            node_id: "node-1".to_string(),
            forwarding: ForwardingCapabilities::USERSPACE_SOCKETS,
            forwarding_fallback_reason: Some("no tunnel device".to_string()),
            unserved: Unserved::ALL.to_vec(),
        };
        let json = serde_json::to_string(&description).expect("encode");
        let back: NodeDescription = serde_json::from_str(&json).expect("decode");
        assert_eq!(back.forwarding, ForwardingCapabilities::USERSPACE_SOCKETS);
        assert!(!back.forwarding.icmp);
        assert_eq!(back, description);
    }
}
