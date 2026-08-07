//! The node-control decision: one function from (caller, request) to
//! answer.
//!
//! Every ownership decision is made here and nowhere else. The registry
//! stores who owns what and does not filter; the transport proves who is
//! asking and does not decide. That leaves exactly one place a caller can
//! be handed something it does not own, which is the only arrangement in
//! which "exactly one place" is checkable.

use crate::netd::ForwardingCapabilities;

use super::caller::CallerIdentity;
use super::registry::NodeRegistry;
use super::wire::{
    MachineDescription, MachineList, NODE_CONTROL_VERSION, NodeControlEnvelope, NodeControlRequest,
    NodeControlResponse, NodeDescription, Refusal, Unserved,
};

/// The node-control surface over one node's state.
#[derive(Debug)]
pub struct NodeControl {
    registry: NodeRegistry,
    forwarding: ForwardingCapabilities,
    fallback_reason: Option<String>,
}

impl NodeControl {
    /// Build the surface over a registry and the forwarding backend this
    /// node actually selected.
    ///
    /// The capabilities are passed in rather than probed here so that what
    /// this reports and what admission enforces are the same value, taken
    /// once.
    pub fn new(registry: NodeRegistry, forwarding: ForwardingCapabilities) -> Self {
        Self {
            registry,
            forwarding,
            fallback_reason: None,
        }
    }

    /// Why forwarding is not the packet-level path, when it is not.
    pub fn with_fallback_reason(mut self, reason: Option<String>) -> Self {
        self.fallback_reason = reason;
        self
    }

    pub fn registry(&self) -> &NodeRegistry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut NodeRegistry {
        &mut self.registry
    }

    /// Answer one request for one caller.
    pub fn handle(
        &self,
        caller: &CallerIdentity,
        envelope: &NodeControlEnvelope,
    ) -> NodeControlResponse {
        // Before the request is looked at: a message written against a
        // protocol this node does not read is not a message this node can
        // decide anything about.
        if envelope.version != NODE_CONTROL_VERSION {
            return NodeControlResponse::Refused(Refusal::unsupported_version(envelope.version));
        }
        match &envelope.request {
            NodeControlRequest::DescribeNode(_) => NodeControlResponse::Node(self.describe_node()),
            NodeControlRequest::ListMachines(_) => {
                NodeControlResponse::Machines(self.list_machines(caller))
            }
            NodeControlRequest::DescribeMachine(request) => {
                self.describe_machine(caller, &request.vm_id)
            }
        }
    }

    /// What this node is. Node-level and machine-free: it names no machine,
    /// so it discloses nothing about who is running what here.
    fn describe_node(&self) -> NodeDescription {
        NodeDescription {
            version: NODE_CONTROL_VERSION,
            node_id: self.registry.node_id().to_string(),
            forwarding: self.forwarding,
            forwarding_fallback_reason: self.fallback_reason.clone(),
            unserved: Unserved::ALL.to_vec(),
        }
    }

    fn list_machines(&self, caller: &CallerIdentity) -> MachineList {
        MachineList {
            machines: self
                .registry
                .iter()
                .filter(|record| caller.owns(record.owner_uid))
                .map(|record| record.instance.clone())
                .collect(),
        }
    }

    fn describe_machine(&self, caller: &CallerIdentity, vm_id: &str) -> NodeControlResponse {
        // The filter and the lookup are one expression on purpose: a
        // `get` whose result is checked a line later is a `get` whose
        // result can be returned by a path that forgot to check.
        match self
            .registry
            .get(vm_id)
            .filter(|record| caller.owns(record.owner_uid))
        {
            Some(record) => NodeControlResponse::Machine(Box::new(MachineDescription {
                instance: record.instance.clone(),
                lease: record.lease.clone(),
                registered_at_millis: record.registered_at_millis,
            })),
            None => NodeControlResponse::Refused(Refusal::not_found()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use mvm_net::channel::VmInstanceIdentity;
    use mvm_net::lease::{LeaseRequest, LocalLeaseAuthority, NetworkLease};

    use super::super::registry::MachineRecord;
    use super::super::wire::{
        DescribeMachine, DescribeNode, ListMachines, NodeControlEnvelope, RefusalReason,
    };
    use super::*;

    const OWNER: u32 = 501;
    const STRANGER: u32 = 502;
    const NOW: u64 = 1_000_000;

    fn lease(instance: &VmInstanceIdentity) -> NetworkLease {
        LocalLeaseAuthority::new(&instance.node_id, [7u8; 32]).issue(&LeaseRequest {
            instance,
            tenant_id: "default",
            ipv4: Ipv4Addr::new(10, 201, 0, 6),
            gateway_ipv4: Ipv4Addr::new(10, 201, 0, 5),
            dns_name: None,
            routes: &[],
            ingress: &[],
            egress_policy_digest: "sha256:egress",
            policy_epoch: 1,
            now_millis: NOW,
        })
    }

    fn record(vm_id: &str, owner_uid: u32) -> MachineRecord {
        let instance = VmInstanceIdentity::new("node-1", vm_id, "boot-1", "sha256:plan");
        let lease = lease(&instance);
        MachineRecord {
            instance,
            lease,
            owner_uid,
            registered_at_millis: NOW,
        }
    }

    fn node() -> NodeControl {
        let mut registry = NodeRegistry::new("node-1");
        registry.register(record("owned", OWNER)).expect("owned");
        registry
            .register(record("someone-elses", STRANGER))
            .expect("someone else's");
        NodeControl::new(registry, ForwardingCapabilities::USERSPACE_SOCKETS)
    }

    fn ask(request: NodeControlRequest, uid: u32) -> NodeControlResponse {
        node().handle(
            &CallerIdentity::new(uid, 20),
            &NodeControlEnvelope::current(request),
        )
    }

    /// The security witness. A caller asking about a machine it does not own
    /// is refused, and refused with the same answer it would get for a
    /// machine that does not exist — so the refusal is not a membership
    /// oracle either.
    #[test]
    fn a_caller_is_refused_a_machine_it_does_not_own() {
        let not_mine = ask(
            NodeControlRequest::DescribeMachine(DescribeMachine {
                vm_id: "someone-elses".to_string(),
            }),
            OWNER,
        );
        let absent = ask(
            NodeControlRequest::DescribeMachine(DescribeMachine {
                vm_id: "never-existed".to_string(),
            }),
            OWNER,
        );

        assert_eq!(
            not_mine,
            NodeControlResponse::Refused(Refusal::not_found()),
            "a machine another caller registered must not be described"
        );
        assert_eq!(
            serde_json::to_string(&not_mine).expect("encode"),
            serde_json::to_string(&absent).expect("encode"),
            "the two refusals must be the same bytes: a node that tells them \
             apart tells anyone who can connect which machines exist here"
        );
    }

    #[test]
    fn a_caller_is_answered_about_a_machine_it_does_own() {
        let response = ask(
            NodeControlRequest::DescribeMachine(DescribeMachine {
                vm_id: "owned".to_string(),
            }),
            OWNER,
        );
        let NodeControlResponse::Machine(machine) = response else {
            panic!("the owner must be answered: {response:?}");
        };
        assert_eq!(machine.instance.vm_id, "owned");
        assert_eq!(machine.registered_at_millis, NOW);
    }

    /// The listing is the other way to ask the same question, so it carries
    /// the same boundary. A scope applied to one and not the other is the
    /// classic way an ownership check is bypassed.
    #[test]
    fn a_listing_carries_only_the_callers_own_machines() {
        let response = ask(NodeControlRequest::ListMachines(ListMachines {}), OWNER);
        let NodeControlResponse::Machines(list) = response else {
            panic!("a listing must be answered: {response:?}");
        };
        let ids: Vec<&str> = list
            .machines
            .iter()
            .map(|instance| instance.vm_id.as_str())
            .collect();
        assert_eq!(ids, vec!["owned"]);
    }

    #[test]
    fn a_caller_that_owns_nothing_is_told_nothing_rather_than_refused() {
        let response = ask(NodeControlRequest::ListMachines(ListMachines {}), 999);
        assert_eq!(
            response,
            NodeControlResponse::Machines(MachineList::default()),
            "an empty listing is the true answer; a refusal would say that \
             machines exist"
        );
    }

    /// The node's own description names no machine, so any local caller may
    /// have it. What it must not do is understate what the backend cannot
    /// carry.
    #[test]
    fn the_node_description_reports_the_backends_capabilities_unchanged() {
        let response = ask(NodeControlRequest::DescribeNode(DescribeNode {}), STRANGER);
        let NodeControlResponse::Node(description) = response else {
            panic!("describe-node must be answered: {response:?}");
        };
        assert_eq!(
            description.forwarding,
            ForwardingCapabilities::USERSPACE_SOCKETS
        );
        assert!(!description.forwarding.icmp);
        assert!(!description.forwarding.arbitrary_ipv4);
        assert_eq!(description.node_id, "node-1");
    }

    /// A node says what it does not do, rather than leaving a control plane
    /// to find out by having a request fail.
    #[test]
    fn the_node_names_the_fleet_work_it_does_not_do() {
        let response = ask(NodeControlRequest::DescribeNode(DescribeNode {}), OWNER);
        let NodeControlResponse::Node(description) = response else {
            panic!("describe-node must be answered: {response:?}");
        };
        assert!(description.unserved.contains(&Unserved::CrossNodeTrustRoot));
        assert_eq!(description.unserved, Unserved::ALL.to_vec());
    }

    /// A version this node does not read is refused before the request is
    /// interpreted at all.
    #[test]
    fn a_request_at_an_unreadable_version_is_refused_before_it_is_interpreted() {
        let envelope = NodeControlEnvelope {
            version: NODE_CONTROL_VERSION + 1,
            request: NodeControlRequest::DescribeMachine(DescribeMachine {
                vm_id: "owned".to_string(),
            }),
        };
        let response = node().handle(&CallerIdentity::new(OWNER, 20), &envelope);
        let NodeControlResponse::Refused(refusal) = response else {
            panic!("an unreadable version must be refused: {response:?}");
        };
        assert_eq!(refusal.reason, RefusalReason::UnsupportedVersion);
    }
}
