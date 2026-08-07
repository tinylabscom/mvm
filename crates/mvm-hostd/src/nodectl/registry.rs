//! What this node knows about the machines running on it.
//!
//! One entry per registered machine boot, each carrying the uid of the
//! process that registered it. That uid is the whole of the ownership
//! model: it is the only thing a Unix transport can prove, and a boundary
//! that cannot be proved is not a boundary.
//!
//! Bounded like the rest of the module: a cap on entries, a cap on the size
//! of one entry, and at capacity the *new* registration is refused rather
//! than a live machine evicted — a node whose table can be churned is a
//! node where one caller can make another's machine unanswerable.

use std::collections::BTreeMap;

use mvm_net::channel::VmInstanceIdentity;
use mvm_net::lease::NetworkLease;

/// How many machine registrations one node holds.
///
/// Above the per-machine flow caps this daemon family already sets, and far
/// above any host that can actually run that many microVMs; the cap exists
/// so the table has a ceiling at all, not because it is expected to bind.
pub const MAX_REGISTERED_MACHINES: usize = 256;

/// The largest one registration may serialize to.
///
/// Measured on the serialized form rather than on each string's length,
/// because the serialized form is what the response frame is built from and
/// so is the number the memory ceiling below is actually about.
pub const MAX_RECORD_BYTES: usize = 4096;

/// Everything the registry itself can hold, at both caps.
pub const REGISTRY_BYTES: usize = MAX_REGISTERED_MACHINES * MAX_RECORD_BYTES;

/// One machine on this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineRecord {
    pub instance: VmInstanceIdentity,
    pub lease: NetworkLease,
    /// The uid that registered it. Host-supplied from the connection, never
    /// read out of a message.
    pub owner_uid: u32,
    pub registered_at_millis: u64,
}

/// Why a registration was refused. Every variant refuses the whole record:
/// a half-registered machine is one the node would answer about
/// inconsistently.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("this node already holds {cap} machines; the new registration is refused")]
    Full { cap: usize },
    #[error("a registration serializes to {size} bytes, over the {cap} byte cap")]
    RecordTooLarge { size: usize, cap: usize },
    #[error("the record names node {named:?}, this node is {here:?}")]
    WrongNode { named: String, here: String },
    #[error("the record's lease is bound to {bound} but the record names {named}")]
    LeaseMismatch { bound: String, named: String },
    #[error("a registration could not be measured against the size cap")]
    Unmeasurable,
}

/// The machines this node hosts.
#[derive(Debug, Clone)]
pub struct NodeRegistry {
    node_id: String,
    machines: BTreeMap<String, MachineRecord>,
}

impl NodeRegistry {
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            machines: BTreeMap::new(),
        }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn len(&self) -> usize {
        self.machines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.machines.is_empty()
    }

    /// Record a machine.
    ///
    /// Refuses before it mutates: a record that fails any check leaves the
    /// table exactly as it was.
    pub fn register(&mut self, record: MachineRecord) -> Result<(), RegistryError> {
        if record.instance.node_id != self.node_id {
            return Err(RegistryError::WrongNode {
                named: record.instance.node_id.clone(),
                here: self.node_id.clone(),
            });
        }
        // The same binding the lease verifier enforces. A record whose lease
        // names a different boot would have this node answering about a
        // machine under a grant that machine cannot use.
        let bound = record.lease.instance();
        if bound != record.instance {
            return Err(RegistryError::LeaseMismatch {
                bound: bound.audit_label(),
                named: record.instance.audit_label(),
            });
        }
        let size = measure(&record)?;
        if size > MAX_RECORD_BYTES {
            return Err(RegistryError::RecordTooLarge {
                size,
                cap: MAX_RECORD_BYTES,
            });
        }
        // A machine already here is replacing itself, so it spends no new
        // capacity; only a genuinely new one meets the cap.
        let replacing = self.machines.contains_key(&record.instance.vm_id);
        if !replacing && self.machines.len() >= MAX_REGISTERED_MACHINES {
            return Err(RegistryError::Full {
                cap: MAX_REGISTERED_MACHINES,
            });
        }
        self.machines.insert(record.instance.vm_id.clone(), record);
        Ok(())
    }

    pub fn deregister(&mut self, vm_id: &str) -> Option<MachineRecord> {
        self.machines.remove(vm_id)
    }

    /// The record for `vm_id`, whoever owns it. Ownership is applied by the
    /// service, not here, so there is exactly one place it can be forgotten.
    pub fn get(&self, vm_id: &str) -> Option<&MachineRecord> {
        self.machines.get(vm_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &MachineRecord> {
        self.machines.values()
    }
}

/// What one record costs in the response frame it will be written into.
///
/// Measured on the serialized identity and lease — the two parts that
/// travel — because the cap exists to keep the frame inside its bound, not
/// to describe the in-memory layout.
fn measure(record: &MachineRecord) -> Result<usize, RegistryError> {
    let identity = serde_json::to_vec(&record.instance).map_err(|_| RegistryError::Unmeasurable)?;
    let lease = serde_json::to_vec(&record.lease).map_err(|_| RegistryError::Unmeasurable)?;
    Ok(identity.len() + lease.len())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use mvm_net::lease::{LeaseRequest, LocalLeaseAuthority};

    use super::*;

    const OWNER: u32 = 501;
    const NOW: u64 = 1_000_000;

    fn instance(vm_id: &str) -> VmInstanceIdentity {
        VmInstanceIdentity::new("node-1", vm_id, "boot-1", "sha256:plan")
    }

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

    pub(super) fn record(vm_id: &str, owner_uid: u32) -> MachineRecord {
        let instance = instance(vm_id);
        let lease = lease(&instance);
        MachineRecord {
            instance,
            lease,
            owner_uid,
            registered_at_millis: NOW,
        }
    }

    #[test]
    fn a_registered_machine_is_readable_back() {
        let mut registry = NodeRegistry::new("node-1");
        registry.register(record("vm-a", OWNER)).expect("register");
        assert_eq!(registry.get("vm-a").expect("present").owner_uid, OWNER);
        assert_eq!(registry.len(), 1);
    }

    /// At capacity the arriving registration is refused and every live
    /// machine stays answerable. The other way round, a caller who can
    /// register can make someone else's machine vanish from the node.
    #[test]
    fn at_capacity_the_new_registration_is_dropped_and_no_live_machine_is_evicted() {
        let mut registry = NodeRegistry::new("node-1");
        for i in 0..MAX_REGISTERED_MACHINES {
            registry
                .register(record(&format!("vm-{i}"), OWNER))
                .expect("registering up to the cap");
        }
        let err = registry
            .register(record("one-too-many", OWNER))
            .expect_err("the cap must bind");
        assert_eq!(
            err,
            RegistryError::Full {
                cap: MAX_REGISTERED_MACHINES
            }
        );
        assert_eq!(registry.len(), MAX_REGISTERED_MACHINES);
        assert!(
            registry.get("vm-0").is_some(),
            "the first machine registered must still be there: a cap that \
             evicts is a cap one caller can use against another"
        );
        assert!(registry.get("one-too-many").is_none());
    }

    /// A record whose lease names a different boot is refused for the same
    /// reason the lease verifier refuses it: the two would then disagree
    /// about what the machine is running under.
    #[test]
    fn a_record_whose_lease_names_another_boot_is_refused() {
        let mut registry = NodeRegistry::new("node-1");
        let mut mismatched = record("vm-a", OWNER);
        mismatched.instance.boot_id = "boot-2".to_string();
        assert!(matches!(
            registry.register(mismatched),
            Err(RegistryError::LeaseMismatch { .. })
        ));
        assert!(registry.is_empty());
    }

    /// A node refuses a machine that names another node, before it reads
    /// anything else about it.
    #[test]
    fn a_record_for_another_node_is_refused() {
        let mut registry = NodeRegistry::new("node-2");
        assert!(matches!(
            registry.register(record("vm-a", OWNER)),
            Err(RegistryError::WrongNode { .. })
        ));
        assert!(registry.is_empty());
    }

    /// An oversized record would blow the response frame the ceiling is
    /// computed from, so it is refused at the door rather than found
    /// unserializable later.
    #[test]
    fn an_oversized_record_is_refused_before_it_is_stored() {
        let mut registry = NodeRegistry::new("node-1");
        let mut huge = record("vm-a", OWNER);
        huge.lease.routes = (0..512).map(|i| format!("10.0.{i}.0/24")).collect();
        assert!(matches!(
            registry.register(huge),
            Err(RegistryError::RecordTooLarge { .. })
        ));
        assert!(registry.is_empty());
    }

    /// Re-registering the same machine replaces its record rather than
    /// consuming a second slot — a machine that reboots must not spend the
    /// node's capacity twice.
    #[test]
    fn re_registering_a_machine_replaces_it_rather_than_growing_the_table() {
        let mut registry = NodeRegistry::new("node-1");
        registry.register(record("vm-a", OWNER)).expect("first");
        registry.register(record("vm-a", OWNER)).expect("second");
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn deregistering_removes_exactly_one_machine() {
        let mut registry = NodeRegistry::new("node-1");
        registry.register(record("vm-a", OWNER)).expect("a");
        registry.register(record("vm-b", OWNER)).expect("b");
        assert!(registry.deregister("vm-a").is_some());
        assert!(registry.deregister("vm-a").is_none());
        assert_eq!(registry.len(), 1);
    }
}
