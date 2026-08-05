//! The backend-neutral guest channel: typed services over whatever the VMM
//! uses to terminate the guest's vsock.
//!
//! A guest always speaks AF_VSOCK. What the *host* holds varies: Firecracker
//! hands us a per-port Unix socket that is its own termination of the
//! guest's virtio-vsock connection, libkrun does the same at a different
//! path, the in-house HVF VMM hands us an owned stream, QEMU exposes a real
//! AF_VSOCK socket, and a future Windows host would expose AF_HYPERV. All
//! five are the same fact — the host end of a guest vsock connection — and
//! none of them is an authorization input.
//!
//! That distinction is the whole point of this module. A UDS path, a CID, a
//! port number, and anything the guest says about itself are all reusable
//! and all forgeable-by-reuse. Authorization binds to
//! [`VmInstanceIdentity`], which the host mints per boot, and nothing above
//! this abstraction is allowed to see the endpoint's shape.

use std::fmt;

/// A typed guest channel.
///
/// Named services rather than bare port numbers, so a caller cannot ask for
/// "port 5260" and get whatever happens to be there; the backend owns the
/// mapping from service to endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuestService {
    /// The machine-control RPC: exec, fs, health, lifecycle.
    MachineControl,
    /// L3 tunnel negotiation, configuration, liveness, and shutdown.
    NetworkControl,
    /// L3 packet traffic. One connection per queue; version 1 opens queue 0.
    ///
    /// Separate from [`NetworkControl`](Self::NetworkControl) so bulk packet
    /// traffic can never block a shutdown or a health check.
    NetworkData { queue: u16 },
    /// One-shot workload exit reporting.
    WorkloadExit,
    /// The host-services broker.
    Broker,
    /// The egress substitution endpoint.
    Substitution,
}

impl GuestService {
    /// The vsock port this service uses today.
    ///
    /// Backends may map services to endpoints however they like; this is the
    /// port the guest dials, and it is the single place the mapping lives so
    /// the two ends cannot drift.
    pub fn port(self) -> u32 {
        match self {
            Self::WorkloadExit => 5251,
            Self::MachineControl => 5252,
            Self::Substitution => 5253,
            Self::NetworkControl => mvm_contract::l3::L3_CONTROL_PORT,
            Self::NetworkData { queue } => mvm_contract::l3::data_port(queue),
            Self::Broker => 5300,
        }
    }

    /// Stable label for audit and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MachineControl => "machine-control",
            Self::NetworkControl => "network-control",
            Self::NetworkData { .. } => "network-data",
            Self::WorkloadExit => "workload-exit",
            Self::Broker => "broker",
            Self::Substitution => "substitution",
        }
    }

    /// Whether this service carries bulk packet traffic.
    pub fn is_bulk(self) -> bool {
        matches!(self, Self::NetworkData { .. })
    }
}

impl fmt::Display for GuestService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkData { queue } => write!(f, "network-data[{queue}]"),
            other => write!(f, "{}", other.as_str()),
        }
    }
}

/// Host-owned identity of one VM boot.
///
/// Every field is assigned by the host. A guest cannot select, assert, or
/// influence any of them, which is why this — and not a CID, a socket path,
/// or a header field — is what authorization binds to.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct VmInstanceIdentity {
    /// The node this VM is running on.
    pub node_id: String,
    /// Stable identity of the machine across boots.
    pub vm_id: String,
    /// Fresh per boot. Two boots of the same `vm_id` never share one, which
    /// is what makes a restart unable to inherit the previous boot's
    /// session, lease, flows, DNS bindings, or ingress mappings.
    pub boot_id: String,
    /// Digest of the `ExecutionPlan` admitted for this boot.
    pub plan_digest: String,
}

impl VmInstanceIdentity {
    pub fn new(
        node_id: impl Into<String>,
        vm_id: impl Into<String>,
        boot_id: impl Into<String>,
        plan_digest: impl Into<String>,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            vm_id: vm_id.into(),
            boot_id: boot_id.into(),
            plan_digest: plan_digest.into(),
        }
    }

    /// Whether this is the same boot as `other`. Identity comparison is
    /// whole-value on purpose: matching on `vm_id` alone would let a
    /// restarted machine present as its predecessor.
    pub fn is_same_boot(&self, other: &Self) -> bool {
        self == other
    }

    /// Whether this is the same machine, possibly a different boot.
    pub fn is_same_machine(&self, other: &Self) -> bool {
        self.node_id == other.node_id && self.vm_id == other.vm_id
    }

    /// Compact form for audit fields.
    pub fn audit_label(&self) -> String {
        format!("{}/{}@{}", self.node_id, self.vm_id, self.boot_id)
    }
}

/// Why a channel operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    /// The backend has no endpoint for this instance.
    #[error("no guest channel for {instance} — the instance is not running or was revoked")]
    NoSuchInstance { instance: String },
    /// The backend does not offer this service.
    #[error("{backend} does not offer the {service} service")]
    ServiceUnavailable {
        backend: &'static str,
        service: GuestService,
    },
    /// Binding or connecting failed.
    #[error("{operation} for {service} on {instance} failed: {source}")]
    Io {
        operation: &'static str,
        service: GuestService,
        instance: String,
        source: std::io::Error,
    },
    /// The instance's channels were revoked.
    #[error("guest channels for {instance} are revoked")]
    Revoked { instance: String },
}

/// A connection to or from a guest, with its host-owned identity attached.
///
/// The identity is carried alongside the stream rather than looked up from
/// it: by the time anything reads a byte, which boot it belongs to is
/// already settled, and no later code has to re-derive it from an endpoint
/// property that could be reused.
pub struct GuestConnection<S> {
    pub instance: VmInstanceIdentity,
    pub service: GuestService,
    pub stream: S,
    /// The descriptor a poll loop can register, when the transport has
    /// one. `None` for in-memory streams, which are only ever driven
    /// synchronously.
    pub pollable_fd: Option<std::os::fd::RawFd>,
}

impl<S> GuestConnection<S> {
    pub fn new(instance: VmInstanceIdentity, service: GuestService, stream: S) -> Self {
        Self {
            instance,
            service,
            stream,
            pollable_fd: None,
        }
    }

    /// Record the descriptor this connection can be polled on.
    pub fn with_pollable_fd(mut self, fd: std::os::fd::RawFd) -> Self {
        self.pollable_fd = Some(fd);
        self
    }
}

impl<S> fmt::Debug for GuestConnection<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestConnection")
            .field("instance", &self.instance.audit_label())
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

/// Creates and revokes the host end of a guest's channels.
///
/// Implementations map each service onto whatever their VMM provides: a
/// Firecracker per-port UDS, a libkrun per-port UDS, an HVF-owned stream, a
/// native AF_VSOCK socket, or a future AF_HYPERV service. Callers see only
/// services and instances.
pub trait GuestChannelProvider: Send + Sync {
    /// Name of the backing transport, for audit and error messages.
    fn backend_name(&self) -> &'static str;

    /// Whether this backend can carry `service`.
    fn offers(&self, service: GuestService) -> bool;

    /// Start accepting connections for `service` from `instance`.
    ///
    /// The listener must exist before the VM starts, so a guest that dials
    /// immediately does not race the host.
    fn bind_service(
        &self,
        instance: &VmInstanceIdentity,
        service: GuestService,
    ) -> Result<Box<dyn GuestListener>, ChannelError>;

    /// Dial `service` on `instance` from the host side.
    fn connect_service(
        &self,
        instance: &VmInstanceIdentity,
        service: GuestService,
    ) -> Result<Box<dyn GuestStream>, ChannelError>;

    /// Tear down every channel for `instance` and refuse further ones.
    ///
    /// Called on stop, crash recovery, and lease revocation. Idempotent: it
    /// runs on paths that may have already run it.
    fn revoke_instance(&self, instance: &VmInstanceIdentity) -> Result<(), ChannelError>;
}

/// A duplex byte stream to a guest.
pub trait GuestStream: std::io::Read + std::io::Write + Send {}

impl<T: std::io::Read + std::io::Write + Send> GuestStream for T {}

/// Accepts connections for one service on one instance.
pub trait GuestListener: Send {
    /// Accept the next connection, tagged with the instance it belongs to.
    fn accept(&mut self) -> Result<GuestConnection<Box<dyn GuestStream>>, ChannelError>;

    /// Stop accepting and release the endpoint.
    fn close(&mut self) -> Result<(), ChannelError>;

    /// The instance this listener serves.
    fn instance(&self) -> &VmInstanceIdentity;

    /// The service this listener serves.
    fn service(&self) -> GuestService;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> VmInstanceIdentity {
        VmInstanceIdentity::new("node-1", "vm-a", "boot-1", "sha256:plan")
    }

    #[test]
    fn services_map_to_the_ports_both_ends_agree_on() {
        assert_eq!(GuestService::MachineControl.port(), 5252);
        assert_eq!(GuestService::WorkloadExit.port(), 5251);
        assert_eq!(GuestService::Substitution.port(), 5253);
        assert_eq!(GuestService::Broker.port(), 5300);
        assert_eq!(
            GuestService::NetworkControl.port(),
            mvm_contract::l3::L3_CONTROL_PORT
        );
        assert_eq!(
            GuestService::NetworkData { queue: 0 }.port(),
            mvm_contract::l3::L3_DATA_PORT_BASE
        );
    }

    #[test]
    fn every_service_has_a_distinct_port() {
        let ports = [
            GuestService::MachineControl.port(),
            GuestService::NetworkControl.port(),
            GuestService::NetworkData { queue: 0 }.port(),
            GuestService::WorkloadExit.port(),
            GuestService::Broker.port(),
            GuestService::Substitution.port(),
        ];
        let mut sorted = ports.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            ports.len(),
            "service ports collide: {ports:?}"
        );
    }

    #[test]
    fn network_control_and_network_data_are_different_services() {
        // The separation is a design constraint, not an implementation
        // detail: control must not queue behind bulk packet traffic.
        assert_ne!(
            GuestService::NetworkControl,
            GuestService::NetworkData { queue: 0 }
        );
        assert_ne!(
            GuestService::NetworkControl.port(),
            GuestService::NetworkData { queue: 0 }.port()
        );
        assert!(GuestService::NetworkData { queue: 0 }.is_bulk());
        assert!(!GuestService::NetworkControl.is_bulk());
        assert!(!GuestService::MachineControl.is_bulk());
    }

    #[test]
    fn bulk_packet_traffic_never_shares_the_machine_control_service() {
        assert_ne!(
            GuestService::NetworkData { queue: 0 }.port(),
            GuestService::MachineControl.port()
        );
    }

    #[test]
    fn each_queue_gets_its_own_service_and_port() {
        for q in 0..4u16 {
            assert_eq!(
                GuestService::NetworkData { queue: q }.port(),
                mvm_contract::l3::L3_DATA_PORT_BASE + u32::from(q)
            );
        }
    }

    #[test]
    fn a_new_boot_is_a_different_identity() {
        let first = identity();
        let second = VmInstanceIdentity::new("node-1", "vm-a", "boot-2", "sha256:plan");
        assert!(first.is_same_machine(&second));
        assert!(
            !first.is_same_boot(&second),
            "a restart must not present as its own predecessor"
        );
    }

    #[test]
    fn a_different_plan_digest_is_a_different_identity() {
        let first = identity();
        let second = VmInstanceIdentity::new("node-1", "vm-a", "boot-1", "sha256:other");
        assert!(!first.is_same_boot(&second));
    }

    #[test]
    fn identity_from_another_node_never_matches() {
        let here = identity();
        let there = VmInstanceIdentity::new("node-2", "vm-a", "boot-1", "sha256:plan");
        assert!(!here.is_same_machine(&there));
        assert!(!here.is_same_boot(&there));
    }

    #[test]
    fn the_audit_label_names_node_machine_and_boot() {
        assert_eq!(identity().audit_label(), "node-1/vm-a@boot-1");
    }

    #[test]
    fn service_display_names_the_queue() {
        assert_eq!(
            GuestService::NetworkData { queue: 3 }.to_string(),
            "network-data[3]"
        );
        assert_eq!(GuestService::MachineControl.to_string(), "machine-control");
    }

    #[test]
    fn a_connection_carries_its_instance_rather_than_deriving_it() {
        let conn = GuestConnection::new(identity(), GuestService::NetworkControl, Vec::<u8>::new());
        assert_eq!(conn.instance, identity());
        assert_eq!(conn.service, GuestService::NetworkControl);
        // The debug form is safe to log: identity and service, no bytes.
        let rendered = format!("{conn:?}");
        assert!(rendered.contains("node-1/vm-a@boot-1"), "{rendered}");
    }
}
