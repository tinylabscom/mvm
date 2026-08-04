//! The platform seam for forwarding admitted L3 packets.
//!
//! Everything above this trait is platform-neutral: framing, session
//! identity, policy, DNS, flow state, ingress, audit. Everything below it is
//! an implementation detail that sits **after** the vsock trust boundary — a
//! host TUN device, a network namespace, NAT rules. None of it is ever
//! attached to the guest or exposed as a hypervisor network device.
//!
//! The signature is the enforcement: [`send_to_network`] takes an
//! [`AdmittedPacket`], a type only `mvm_net::l3`'s admitter can construct.
//! There is no way to reach a datapath with bytes that have not been through
//! policy, because there is no way to name one.
//!
//! [`send_to_network`]: DatapathHandle::send_to_network

use std::net::{Ipv4Addr, Ipv6Addr};

use mvm_net::l3::{AdmittedPacket, IngressMapping};

/// What a forwarding backend can actually carry.
///
/// Reported rather than assumed, because the backends differ in kind: a
/// Linux host TUN moves arbitrary IP, while a userspace socket gateway can
/// only translate the transports it knows how to open sockets for. A plan
/// that needs something the selected backend lacks is refused at admission
/// — there is no degrade, and no "mostly works".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardingCapabilities {
    pub tcp: bool,
    pub udp: bool,
    /// Host-terminated DNS. Required for domain rules to mean anything.
    pub controlled_dns: bool,
    pub icmp: bool,
    /// Whether the backend can put an *arbitrary* packet of that family on
    /// the wire. A socket gateway cannot, in either family.
    pub arbitrary_ipv4: bool,
    pub arbitrary_ipv6: bool,
    /// Whether TCP and UDP flows are carried over IPv6 at all — a different
    /// question from `arbitrary_ipv6`, and the one a dual-stack workload is
    /// actually asking.
    pub ipv6_flows: bool,
    /// IP protocols other than TCP/UDP/ICMP.
    pub raw_ip_protocols: bool,
    pub declared_ingress: bool,
    pub multi_queue: bool,
    /// Whether the backend forwards whole IP packets, as opposed to
    /// translating flows into host sockets.
    pub full_packet_forwarding: bool,
    /// Whether it works by opening host sockets on the guest's behalf.
    pub userspace_socket_translation: bool,
}

impl ForwardingCapabilities {
    /// Nothing supported. The base every backend narrows from, so a new
    /// backend that forgets to set a flag is under-capable rather than
    /// over-claiming.
    pub const NONE: Self = Self {
        tcp: false,
        udp: false,
        controlled_dns: false,
        icmp: false,
        arbitrary_ipv4: false,
        arbitrary_ipv6: false,
        ipv6_flows: false,
        raw_ip_protocols: false,
        declared_ingress: false,
        multi_queue: false,
        full_packet_forwarding: false,
        userspace_socket_translation: false,
    };

    /// A full L3 packet path: whole packets of either family, every
    /// transport.
    pub const FULL_L3: Self = Self {
        tcp: true,
        udp: true,
        controlled_dns: true,
        icmp: true,
        arbitrary_ipv4: true,
        arbitrary_ipv6: true,
        ipv6_flows: true,
        raw_ip_protocols: true,
        declared_ingress: true,
        multi_queue: false,
        full_packet_forwarding: true,
        userspace_socket_translation: false,
    };

    /// A userspace socket gateway: ordinary application traffic in either
    /// family, nothing that needs to put an arbitrary IP packet on the wire.
    pub const USERSPACE_SOCKETS: Self = Self {
        tcp: true,
        udp: true,
        controlled_dns: true,
        icmp: false,
        arbitrary_ipv4: false,
        arbitrary_ipv6: false,
        ipv6_flows: true,
        raw_ip_protocols: false,
        declared_ingress: true,
        multi_queue: false,
        full_packet_forwarding: false,
        userspace_socket_translation: true,
    };

    /// Capabilities a plan needs that this backend does not have.
    pub fn shortfall(&self, required: &Self) -> Vec<&'static str> {
        let checks: [(bool, bool, &'static str); 10] = [
            (required.tcp, self.tcp, "tcp"),
            (required.udp, self.udp, "udp"),
            (
                required.controlled_dns,
                self.controlled_dns,
                "controlled_dns",
            ),
            (required.icmp, self.icmp, "icmp"),
            (
                required.arbitrary_ipv4,
                self.arbitrary_ipv4,
                "arbitrary_ipv4",
            ),
            (
                required.arbitrary_ipv6,
                self.arbitrary_ipv6,
                "arbitrary_ipv6",
            ),
            (required.ipv6_flows, self.ipv6_flows, "ipv6_flows"),
            (
                required.raw_ip_protocols,
                self.raw_ip_protocols,
                "raw_ip_protocols",
            ),
            (
                required.declared_ingress,
                self.declared_ingress,
                "declared_ingress",
            ),
            (required.multi_queue, self.multi_queue, "multi_queue"),
        ];
        checks
            .into_iter()
            .filter_map(|(req, have, name)| (req && !have).then_some(name))
            .collect()
    }

    /// Whether this backend can serve `required`.
    pub fn satisfies(&self, required: &Self) -> bool {
        self.shortfall(required).is_empty()
    }
}

/// What the gateway asks a platform to set up for one machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatapathRequest {
    /// Machine this datapath belongs to. Used to name devices, namespaces,
    /// and rule tables so teardown is unambiguous.
    pub machine_id: String,
    /// The host side of the point-to-point link.
    pub gateway: Ipv4Addr,
    /// The guest's assigned address. Return traffic for anything else is
    /// not this machine's.
    pub guest: Ipv4Addr,
    /// Prefix length of the /30.
    pub prefix_len: u8,
    /// The same pair in IPv6, when the session was issued one. `None` means
    /// this machine has no IPv6 address, and admission refuses the family
    /// before a packet ever reaches a backend.
    pub gateway_v6: Option<Ipv6Addr>,
    pub guest_v6: Option<Ipv6Addr>,
    pub mtu: u16,
    /// Ingress mappings the plan declared.
    ///
    /// Here rather than left to admission because the two backends need
    /// different things from a declaration: one that forwards whole packets
    /// needs nothing bound — an inbound packet reaches its device on its
    /// own — while one that translates flows into host sockets has to open
    /// a listener for each mapping, and can only do that if it is told what
    /// was declared. Admission still decides delivery either way; this is
    /// what makes the packet exist to be decided about.
    pub ingress: Vec<IngressMapping>,
}

/// Why a datapath could not be opened or used.
#[derive(Debug, thiserror::Error)]
pub enum DatapathError {
    /// This platform has no datapath in this build.
    #[error("{platform}: {detail}")]
    Unsupported {
        platform: &'static str,
        detail: String,
    },
    /// Setup failed.
    #[error("opening the {what} for {machine_id:?} failed: {source}")]
    SetupFailed {
        what: &'static str,
        machine_id: String,
        source: std::io::Error,
    },
    /// A privileged operation was refused.
    #[error("{operation} needs privileges this process does not have: {detail}")]
    PrivilegeRequired {
        operation: &'static str,
        detail: String,
    },
    /// The plan needs capabilities this backend does not have.
    #[error("{backend} cannot serve this plan: missing {}", .missing.join(", "))]
    CapabilityShortfall {
        backend: &'static str,
        missing: Vec<&'static str>,
    },
    /// I/O on an open datapath failed.
    #[error("datapath I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// What one bounded pass of host-to-guest work concluded.
///
/// Every such pass here takes a budget and stops at it, so each one has to
/// say which of the two things stopped it. A caller that waits on readiness
/// has already spent the edge that woke it, and a bound is not an edge:
/// nothing will report the remainder, so a pass cut off by its budget must
/// say so or what it left sits until the next tick.
///
/// One type for every such pass rather than one per site — the drain of the
/// host network in [`crate::netd::Gateway::poll_inbound`] and the pump of
/// each established flow in [`DatapathHandle::service`] ask the same
/// question and their answers are folded together by the same driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundDrain {
    /// Nothing more was waiting.
    Idle,
    /// The budget ran out with more still there.
    Backlogged,
}

/// An open per-machine datapath.
pub trait DatapathHandle: Send {
    /// Forward one admitted guest packet to the host network.
    ///
    /// Takes [`AdmittedPacket`] rather than `&[u8]` so this cannot be
    /// reached without having passed admission.
    fn send_to_network(&mut self, packet: &AdmittedPacket<'_>) -> Result<(), DatapathError>;

    /// Read one packet arriving for this machine. Returns the byte count.
    ///
    /// The bytes are still untrusted at this point: they go through inbound
    /// admission before any of them reach the guest.
    fn recv_from_network(&mut self, buf: &mut [u8]) -> Result<usize, DatapathError>;

    /// Advance whatever this backend can only advance when driven.
    ///
    /// A backend that forwards whole packets moves them inside the two
    /// calls above and needs nothing here, which is why the default is a
    /// no-op. A backend that translates flows into host sockets does not:
    /// a connect the guest asked for completes in the kernel, and until
    /// something reads that decision the guest is waiting on a handshake no
    /// one is finishing. That is the difference between "not yet" and a
    /// hang, so the driver calls this on the same tick it ages everything
    /// else, with the same clock.
    ///
    /// Reports [`InboundDrain::Backlogged`] when a bound inside this pass —
    /// not the far side going quiet — is what ended it, so the driver comes
    /// straight back rather than waiting on an edge already spent. A backend
    /// with nothing to advance has no bound to hit and says `Idle`.
    fn service(&mut self, _now_millis: u64) -> Result<InboundDrain, DatapathError> {
        Ok(InboundDrain::Idle)
    }

    /// Tear down every device, namespace, route, and rule this handle
    /// created. Idempotent: it runs on the normal stop path and on the
    /// failed-startup path, and must not care which got there first.
    fn close(&mut self) -> Result<(), DatapathError>;

    /// Human-readable name, for audit and diagnostics.
    fn description(&self) -> String;

    /// A descriptor that becomes readable when this datapath has work.
    ///
    /// `None` means the datapath makes progress only when called, so the
    /// driver polls it on its timer tick rather than on readiness.
    ///
    /// **The descriptor is valid only while this handle is open, and a
    /// registered one must be deregistered before the handle is closed.**
    /// Closing releases the number, and the next `open` anywhere in the
    /// process may be handed it — a poll set still holding the registration
    /// would then be reacting to an unrelated resource. A caller must read
    /// this once while the handle is open and register exactly that value;
    /// it must never re-read it around a close, and after a close this
    /// returns `None` rather than a number that no longer means anything.
    fn readiness_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }
}

/// Opens per-machine datapaths.
pub trait L3Datapath: Send + Sync {
    fn open(&self, req: &DatapathRequest) -> Result<Box<dyn DatapathHandle>, DatapathError>;

    /// Whether this platform can actually serve a datapath right now. The
    /// gateway checks this before admitting a tunnel, so an unsupported
    /// platform refuses at admission with a clear reason instead of failing
    /// halfway through a handshake.
    fn is_available(&self) -> Result<(), DatapathError>;

    /// What this backend can carry. Admission compares it against what the
    /// plan needs and refuses a mismatch rather than degrading.
    fn capabilities(&self) -> ForwardingCapabilities;
}

/// A datapath that keeps everything in memory: whatever is sent is
/// immediately readable as though the network had echoed it, optionally
/// after a caller-supplied transform.
///
/// Not `cfg(test)`: the unprivileged end-to-end test lives in another crate
/// and needs to construct one. It is what makes the whole gateway — session
/// binding, policy, DNS, ingress, cleanup — testable without root.
pub struct LoopbackDatapath {
    /// Applied to each admitted packet to produce the reply, if any. Shared
    /// with every handle it opens.
    responder: Responder,
}

/// Produces the reply, if any, for one forwarded packet.
type Responder = std::sync::Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

impl LoopbackDatapath {
    /// A datapath whose replies are produced by `responder`.
    pub fn new(responder: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static) -> Self {
        Self {
            responder: std::sync::Arc::new(responder),
        }
    }

    /// A datapath that swallows everything and never replies.
    pub fn sink() -> Self {
        Self::new(|_| None)
    }
}

impl L3Datapath for LoopbackDatapath {
    fn open(&self, req: &DatapathRequest) -> Result<Box<dyn DatapathHandle>, DatapathError> {
        Ok(Box::new(LoopbackHandle {
            machine_id: req.machine_id.clone(),
            pending: std::collections::VecDeque::new(),
            sent: Vec::new(),
            closed: false,
            responder: std::sync::Arc::clone(&self.responder),
        }))
    }

    fn is_available(&self) -> Result<(), DatapathError> {
        Ok(())
    }

    fn capabilities(&self) -> ForwardingCapabilities {
        ForwardingCapabilities::FULL_L3
    }
}

/// Handle for [`LoopbackDatapath`].
pub struct LoopbackHandle {
    machine_id: String,
    pending: std::collections::VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    closed: bool,
    responder: Responder,
}

impl LoopbackHandle {
    /// Every packet this handle was asked to forward.
    pub fn sent(&self) -> &[Vec<u8>] {
        &self.sent
    }

    /// Queue a packet as though it arrived from the host network.
    pub fn inject(&mut self, packet: Vec<u8>) {
        self.pending.push_back(packet);
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

impl DatapathHandle for LoopbackHandle {
    fn send_to_network(&mut self, packet: &AdmittedPacket<'_>) -> Result<(), DatapathError> {
        if self.closed {
            return Err(DatapathError::Io(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            )));
        }
        let bytes = packet.bytes().to_vec();
        if let Some(reply) = (self.responder)(&bytes) {
            self.pending.push_back(reply);
        }
        self.sent.push(bytes);
        Ok(())
    }

    fn recv_from_network(&mut self, buf: &mut [u8]) -> Result<usize, DatapathError> {
        match self.pending.pop_front() {
            Some(packet) => {
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok(n)
            }
            None => Err(DatapathError::Io(std::io::Error::from(
                std::io::ErrorKind::WouldBlock,
            ))),
        }
    }

    fn close(&mut self) -> Result<(), DatapathError> {
        self.closed = true;
        self.pending.clear();
        Ok(())
    }

    fn description(&self) -> String {
        format!("loopback datapath for {}", self.machine_id)
    }
}

/// A datapath that refuses, naming the platform it refuses for.
///
/// Kept for a platform that can serve no forwarding at all, and for the
/// tests that need a backend whose availability check fails. It is not what
/// a host without a tunnel device gets — that host forwards through
/// userspace sockets and is told so.
#[derive(Debug, Default)]
pub struct UnsupportedDatapath {
    pub platform: &'static str,
}

impl UnsupportedDatapath {
    pub fn new(platform: &'static str) -> Self {
        Self { platform }
    }

    fn refusal(&self) -> DatapathError {
        DatapathError::Unsupported {
            platform: self.platform,
            detail: "the L3 tunnel needs a host tunnel device, its routes, and firewall rules, \
                     all of which require privileges this process does not have on this platform"
                .to_string(),
        }
    }
}

impl L3Datapath for UnsupportedDatapath {
    fn open(&self, _req: &DatapathRequest) -> Result<Box<dyn DatapathHandle>, DatapathError> {
        Err(self.refusal())
    }

    fn is_available(&self) -> Result<(), DatapathError> {
        Err(self.refusal())
    }

    fn capabilities(&self) -> ForwardingCapabilities {
        ForwardingCapabilities::NONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> DatapathRequest {
        DatapathRequest {
            machine_id: "vm-a".into(),
            gateway: Ipv4Addr::new(10, 201, 0, 5),
            guest: Ipv4Addr::new(10, 201, 0, 6),
            prefix_len: 30,
            gateway_v6: None,
            guest_v6: None,
            mtu: 1500,
            ingress: Vec::new(),
        }
    }

    #[test]
    fn an_unsupported_platform_refuses_at_availability_check_time() {
        let dp = UnsupportedDatapath::new("macos");
        let err = dp.is_available().unwrap_err();
        assert!(matches!(
            err,
            DatapathError::Unsupported {
                platform: "macos",
                ..
            }
        ));
        assert!(dp.open(&request()).is_err());
    }

    #[test]
    fn the_unsupported_refusal_explains_what_is_missing() {
        let err = UnsupportedDatapath::new("macos")
            .is_available()
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("privileges"), "{msg}");
        assert!(msg.contains("macos"), "{msg}");
    }

    #[test]
    fn a_loopback_handle_reports_what_it_was_asked_to_forward() {
        let dp = LoopbackDatapath::sink();
        let handle = dp.open(&request()).unwrap();
        assert!(handle.description().contains("vm-a"));
    }

    #[test]
    fn a_closed_handle_drains_its_queue_and_refuses_further_sends() {
        let dp = LoopbackDatapath::sink();
        let mut handle = dp.open(&request()).unwrap();
        handle.close().unwrap();
        handle.close().unwrap(); // idempotent
        let mut buf = [0u8; 64];
        assert!(handle.recv_from_network(&mut buf).is_err());
    }

    #[test]
    fn a_full_l3_backend_satisfies_a_userspace_workload() {
        assert!(
            ForwardingCapabilities::FULL_L3.satisfies(&ForwardingCapabilities::USERSPACE_SOCKETS)
        );
    }

    #[test]
    fn a_userspace_gateway_cannot_serve_a_plan_that_needs_packet_forwarding() {
        let required = ForwardingCapabilities {
            icmp: true,
            arbitrary_ipv4: true,
            raw_ip_protocols: true,
            ..ForwardingCapabilities::USERSPACE_SOCKETS
        };
        let missing = ForwardingCapabilities::USERSPACE_SOCKETS.shortfall(&required);
        assert_eq!(missing, vec!["icmp", "arbitrary_ipv4", "raw_ip_protocols"]);
        assert!(!ForwardingCapabilities::USERSPACE_SOCKETS.satisfies(&required));
    }

    /// The two IPv6 questions are different questions, and the capability
    /// seam has to be able to answer them differently: this backend carries
    /// v6 flows, and cannot put an arbitrary v6 packet on the wire any more
    /// than it can an arbitrary v4 one.
    #[test]
    fn a_userspace_gateway_carries_v6_flows_without_claiming_arbitrary_v6() {
        let caps = ForwardingCapabilities::USERSPACE_SOCKETS;
        assert!(caps.ipv6_flows);
        assert!(!caps.arbitrary_ipv6);

        let required = ForwardingCapabilities {
            arbitrary_ipv6: true,
            ..ForwardingCapabilities::USERSPACE_SOCKETS
        };
        assert_eq!(caps.shortfall(&required), vec!["arbitrary_ipv6"]);
        assert!(!caps.satisfies(&required));
    }

    #[test]
    fn a_plan_that_only_needs_v6_flows_is_served_by_the_userspace_gateway() {
        let required = ForwardingCapabilities {
            tcp: true,
            udp: true,
            ipv6_flows: true,
            ..ForwardingCapabilities::NONE
        };
        assert!(ForwardingCapabilities::USERSPACE_SOCKETS.satisfies(&required));
        assert_eq!(
            ForwardingCapabilities::NONE.shortfall(&required),
            vec!["tcp", "udp", "ipv6_flows"]
        );
    }

    #[test]
    fn a_full_packet_path_carries_both_families() {
        let needs_v6_packets = ForwardingCapabilities {
            arbitrary_ipv6: true,
            ipv6_flows: true,
            ..ForwardingCapabilities::NONE
        };
        assert!(ForwardingCapabilities::FULL_L3.satisfies(&needs_v6_packets));
        assert_eq!(
            ForwardingCapabilities::USERSPACE_SOCKETS.shortfall(&needs_v6_packets),
            vec!["arbitrary_ipv6"],
            "a socket gateway carries the flows but cannot emit the packets"
        );
    }

    #[test]
    fn the_empty_capability_set_serves_nothing() {
        let required = ForwardingCapabilities {
            tcp: true,
            ..ForwardingCapabilities::NONE
        };
        assert_eq!(
            ForwardingCapabilities::NONE.shortfall(&required),
            vec!["tcp"]
        );
    }

    /// A backend that moves packets inside its send and receive calls has
    /// nothing to advance on a tick, and must not have to say so.
    #[test]
    fn a_backend_with_nothing_to_drive_is_serviced_without_implementing_it() {
        let dp = LoopbackDatapath::sink();
        let mut handle = dp.open(&request()).expect("open");
        assert!(handle.service(0).is_ok());
        assert!(handle.service(10_000).is_ok());
    }

    #[test]
    fn a_loopback_handle_has_no_readiness_descriptor() {
        let dp = LoopbackDatapath::sink();
        let handle = dp.open(&request()).expect("open");
        assert!(
            handle.readiness_fd().is_none(),
            "an in-memory datapath is driven synchronously and has nothing to poll"
        );
    }
}
