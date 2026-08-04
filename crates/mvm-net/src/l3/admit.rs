//! Per-packet admission for an L3 tunnel session.
//!
//! Every packet is hostile until this module says otherwise. The order is
//! fixed: structural validation, then address family, then anti-spoofing,
//! then fragmentation and size, then destination class, then the signed
//! plan's rules, then flow state. Nothing downstream re-derives a
//! decision, and nothing downstream may act without one.
//!
//! ## The forwarding gate
//!
//! [`AdmittedPacket`] and [`DeliverablePacket`] have private fields and no
//! public constructor, so they can only come out of [`L3Admitter`]. The
//! host datapath's send/deliver entry points take one of these by
//! reference, which makes "policy runs before forwarding" a property the
//! compiler checks rather than a rule a reviewer has to notice.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use mvm_core::policy::projection::{CanonicalEgress, CanonicalRule, Proto};
use mvm_protocol::l3::{ParsedIpPacket, ip, proto};

use super::alloc::{AddressFamily, AddressLease};
use super::dns::DnsBindingStore;
use super::flow::{FlowAdmission, FlowKey, FlowTable};
use super::ingress::IngressTable;

/// How much ICMP the plan admits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IcmpPolicy {
    /// No ICMP in either direction. Path-MTU discovery degrades to
    /// blackhole detection, which is why it is not the default.
    Deny,
    /// Error and control messages only — destination unreachable, time
    /// exceeded, packet too big. Enough for path-MTU discovery and normal
    /// error handling; no ping.
    ErrorsOnly,
    /// Errors plus echo request/reply to admitted destinations.
    #[default]
    EchoAndErrors,
}

/// The resolved networking rules for one session.
#[derive(Debug, Clone)]
pub struct L3PolicyConfig {
    /// The claim-10 canonical projection — the same value nftables and the
    /// socket-aware gate consume, so `--allow-host` means one thing
    /// everywhere.
    pub egress: CanonicalEgress,
    /// Private ranges the plan explicitly opened. Empty means every
    /// RFC1918 destination is denied.
    pub admitted_private: Vec<IpNet>,
    pub icmp: IcmpPolicy,
    /// Version 1 refuses fragments rather than reassembling them.
    pub allow_fragments: bool,
    /// The negotiated MTU. A packet larger than this is refused.
    pub mtu: u16,
    /// Revision of the rules above. Bindings and flows from another epoch
    /// never apply.
    pub policy_epoch: u64,
}

impl Default for L3PolicyConfig {
    fn default() -> Self {
        Self {
            // Deny-all: an empty rule set admits nothing.
            egress: CanonicalEgress::Rules(Vec::new()),
            admitted_private: Vec::new(),
            icmp: IcmpPolicy::default(),
            allow_fragments: false,
            mtu: mvm_protocol::l3::MTU_V1,
            policy_epoch: 0,
        }
    }
}

/// Why a packet was refused. Stable strings: they are the `reason` field
/// in audit records and the label on a metrics counter, so an operator can
/// correlate the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyCode {
    MalformedPacket,
    SpoofedSource,
    FragmentRefused,
    OversizedPacket,
    AddressFamilyUnassigned,
    MulticastDenied,
    BroadcastDenied,
    ReservedRangeDenied,
    MandatoryDeny,
    PrivateRangeDenied,
    LoopbackDenied,
    LinkLocalDenied,
    ProtocolDenied,
    DestinationNotAdmitted,
    PortNotAdmitted,
    IcmpDenied,
    GatewayServiceDenied,
    FlowTableFull,
    /// The host could not open a socket to re-originate the flow on:
    /// descriptor exhaustion, an address family the host cannot open, or a
    /// sandbox refusing the call. Deliberately distinct from
    /// [`Self::FlowTableFull`] — that one names a ceiling mvm chose and an
    /// operator can raise, this one names the process running out of what
    /// the OS grants it, and the two send an operator to different places.
    HostSocketUnavailable,
    UnsolicitedInbound,
    /// An inbound packet was not addressed to this machine's guest. Routine
    /// noise on a shared segment, and a guest that generates a lot of it is
    /// unremarkable.
    WrongDestination,
    /// A host socket completed a connect to somewhere other than the
    /// destination policy admitted, and the flow was torn down.
    ///
    /// Deliberately not [`Self::WrongDestination`], however similar the two
    /// read. That one counts an inbound packet nobody asked for; this one
    /// counts the datapath reaching a host policy never approved — the
    /// failure that socket translation, unlike a packet-forwarding
    /// datapath, makes representable at all. Sharing a label would let
    /// ordinary inbound noise bury the single signal this check exists to
    /// raise.
    PeerDestinationMismatch,
    SessionNotReady,
}

impl DenyCode {
    /// Audit/metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedPacket => "malformed_packet",
            Self::SpoofedSource => "spoofed_source",
            Self::FragmentRefused => "fragment_refused",
            Self::OversizedPacket => "oversized_packet",
            Self::AddressFamilyUnassigned => "address_family_unassigned",
            Self::MulticastDenied => "multicast_denied",
            Self::BroadcastDenied => "broadcast_denied",
            Self::ReservedRangeDenied => "reserved_range_denied",
            Self::MandatoryDeny => "mandatory_deny",
            Self::PrivateRangeDenied => "private_range_denied",
            Self::LoopbackDenied => "loopback_denied",
            Self::LinkLocalDenied => "link_local_denied",
            Self::ProtocolDenied => "protocol_denied",
            Self::DestinationNotAdmitted => "destination_not_admitted",
            Self::PortNotAdmitted => "port_not_admitted",
            Self::IcmpDenied => "icmp_denied",
            Self::GatewayServiceDenied => "gateway_service_denied",
            Self::FlowTableFull => "flow_table_full",
            Self::HostSocketUnavailable => "host_socket_unavailable",
            Self::UnsolicitedInbound => "unsolicited_inbound",
            Self::WrongDestination => "wrong_destination",
            Self::PeerDestinationMismatch => "peer_destination_mismatch",
            Self::SessionNotReady => "session_not_ready",
        }
    }
}

/// A host service the gateway terminates itself rather than forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayService {
    /// The synthetic resolver. Terminated locally so domain policy applies
    /// before any answer reaches the guest.
    Dns,
}

/// A packet that has crossed vsock, been bound to a host-owned session,
/// passed structural validation, and passed signed-plan policy.
///
/// Constructible only by [`L3Admitter`]. The host datapath accepts this
/// type and not a raw slice, so there is no way to reach host networking
/// without having gone through admission.
#[derive(Debug)]
pub struct AdmittedPacket<'a> {
    bytes: &'a [u8],
    meta: ParsedIpPacket,
    flow: FlowKey,
}

impl<'a> AdmittedPacket<'a> {
    /// The IP packet, exactly as the guest sent it.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn meta(&self) -> &ParsedIpPacket {
        &self.meta
    }

    pub fn flow(&self) -> FlowKey {
        self.flow
    }
}

/// A reply packet that has passed inbound policy and may be framed back to
/// the guest. Same construction guarantee as [`AdmittedPacket`], in the
/// other direction: nothing enters the guest without having been admitted.
#[derive(Debug)]
pub struct DeliverablePacket<'a> {
    bytes: &'a [u8],
    meta: ParsedIpPacket,
}

impl<'a> DeliverablePacket<'a> {
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn meta(&self) -> &ParsedIpPacket {
        &self.meta
    }
}

/// Outcome of admitting a guest→host packet.
#[derive(Debug)]
pub enum OutboundVerdict<'a> {
    /// Hand to the platform datapath.
    Forward(AdmittedPacket<'a>),
    /// Terminate at the gateway itself.
    Gateway(GatewayService, ParsedIpPacket),
    /// Refused.
    Deny(DenyCode),
}

/// Outcome of admitting a host→guest packet.
#[derive(Debug)]
pub enum InboundVerdict<'a> {
    /// Frame back to the guest.
    Deliver(DeliverablePacket<'a>),
    /// Refused.
    Deny(DenyCode),
}

/// Per-session admission state: the assigned addressing, the resolved
/// rules, the flow table, the DNS bindings, and the ingress mappings.
#[derive(Debug)]
pub struct L3Admitter {
    lease: AddressLease,
    config: L3PolicyConfig,
    flows: FlowTable,
    dns: DnsBindingStore,
    ingress: IngressTable,
    ready: bool,
}

impl L3Admitter {
    pub fn new(
        lease: AddressLease,
        config: L3PolicyConfig,
        flows: FlowTable,
        dns: DnsBindingStore,
        ingress: IngressTable,
    ) -> Self {
        Self {
            lease,
            config,
            flows,
            dns,
            ingress,
            ready: false,
        }
    }

    /// Open the gate. Packets are refused until the handshake completes,
    /// so a guest cannot start sending before the host has assigned it an
    /// address to be checked against.
    pub fn set_ready(&mut self, ready: bool) {
        self.ready = ready;
    }

    pub fn lease(&self) -> &AddressLease {
        &self.lease
    }

    pub fn config(&self) -> &L3PolicyConfig {
        &self.config
    }

    pub fn flows(&self) -> &FlowTable {
        &self.flows
    }

    pub fn flows_mut(&mut self) -> &mut FlowTable {
        &mut self.flows
    }

    pub fn dns(&self) -> &DnsBindingStore {
        &self.dns
    }

    pub fn dns_mut(&mut self) -> &mut DnsBindingStore {
        &mut self.dns
    }

    pub fn ingress(&self) -> &IngressTable {
        &self.ingress
    }

    pub fn ingress_mut(&mut self) -> &mut IngressTable {
        &mut self.ingress
    }

    /// Admit one packet the guest sent.
    pub fn admit_outbound<'a>(&mut self, bytes: &'a [u8], now_millis: u64) -> OutboundVerdict<'a> {
        if !self.ready {
            return OutboundVerdict::Deny(DenyCode::SessionNotReady);
        }
        let meta = match ip::parse(bytes) {
            Ok(meta) => meta,
            Err(_) => return OutboundVerdict::Deny(DenyCode::MalformedPacket),
        };

        // Anti-spoofing is only meaningful against an address this session
        // was actually assigned. A family the lease does not carry has
        // none, so it is refused here rather than checked against nothing.
        let Some(guest) = self.lease.guest_in(AddressFamily::of(meta.src)) else {
            return OutboundVerdict::Deny(DenyCode::AddressFamilyUnassigned);
        };
        if meta.src != guest {
            return OutboundVerdict::Deny(DenyCode::SpoofedSource);
        }
        if meta.fragment && !self.config.allow_fragments {
            return OutboundVerdict::Deny(DenyCode::FragmentRefused);
        }
        if meta.total_len > self.config.mtu as usize {
            return OutboundVerdict::Deny(DenyCode::OversizedPacket);
        }

        // Traffic aimed at the gateway itself is a host service, not
        // egress. Only the synthetic resolver is offered; everything else
        // to the gateway address is refused, so the gateway presents the
        // smallest surface it can.
        if Some(meta.dst) == self.lease.gateway_in(AddressFamily::of(meta.dst)) {
            let is_dns =
                matches!(meta.protocol, proto::UDP | proto::TCP) && meta.dst_port == Some(53);
            return if is_dns {
                OutboundVerdict::Gateway(GatewayService::Dns, meta)
            } else {
                OutboundVerdict::Deny(DenyCode::GatewayServiceDenied)
            };
        }

        if let Some(code) = self.destination_class_denial(meta.dst) {
            return OutboundVerdict::Deny(code);
        }

        let flow = match meta.protocol {
            proto::TCP | proto::UDP => {
                let (Some(guest_port), Some(remote_port)) = (meta.src_port, meta.dst_port) else {
                    return OutboundVerdict::Deny(DenyCode::MalformedPacket);
                };
                let l4 = if meta.protocol == proto::TCP {
                    Proto::Tcp
                } else {
                    Proto::Udp
                };
                let by_rule = self.config.egress.permits(&l4, meta.dst, remote_port);
                let by_binding =
                    self.dns
                        .permits(&meta.dst, remote_port, self.config.policy_epoch, now_millis);
                if !by_rule && !by_binding {
                    // Distinguish "host isn't admitted at all" from "host
                    // is admitted but not on this port": they are
                    // different fixes for whoever wrote the policy.
                    let code = if self.destination_admitted_for_any_port(meta.dst)
                        || self.dns.lookup(&meta.dst, now_millis).is_some()
                    {
                        DenyCode::PortNotAdmitted
                    } else {
                        DenyCode::DestinationNotAdmitted
                    };
                    return OutboundVerdict::Deny(code);
                }
                FlowKey {
                    protocol: meta.protocol,
                    guest_port,
                    remote: meta.dst,
                    remote_port,
                }
            }
            proto::ICMP | proto::ICMPV6 => {
                if let Some(code) = self.icmp_outbound_denial(&meta) {
                    return OutboundVerdict::Deny(code);
                }
                FlowKey {
                    protocol: meta.protocol,
                    guest_port: 0,
                    remote: meta.dst,
                    remote_port: 0,
                }
            }
            // Version 1 carries TCP, UDP, and ICMP. Anything else has no
            // policy vocabulary here, so it is refused rather than
            // forwarded unexamined.
            _ => return OutboundVerdict::Deny(DenyCode::ProtocolDenied),
        };

        match self
            .flows
            .observe_outbound(flow, meta.total_len as u64, now_millis)
        {
            FlowAdmission::TableFull => OutboundVerdict::Deny(DenyCode::FlowTableFull),
            FlowAdmission::Opened | FlowAdmission::Existing => {
                OutboundVerdict::Forward(AdmittedPacket { bytes, meta, flow })
            }
        }
    }

    /// Admit one packet arriving from the host network for this guest.
    pub fn admit_inbound<'a>(&mut self, bytes: &'a [u8], now_millis: u64) -> InboundVerdict<'a> {
        if !self.ready {
            return InboundVerdict::Deny(DenyCode::SessionNotReady);
        }
        let meta = match ip::parse(bytes) {
            Ok(meta) => meta,
            Err(_) => return InboundVerdict::Deny(DenyCode::MalformedPacket),
        };
        // Same as outbound: a family this session holds no address in has
        // nothing that could be addressed to its guest.
        let Some(guest) = self.lease.guest_in(AddressFamily::of(meta.dst)) else {
            return InboundVerdict::Deny(DenyCode::AddressFamilyUnassigned);
        };
        if meta.dst != guest {
            return InboundVerdict::Deny(DenyCode::WrongDestination);
        }
        if meta.fragment && !self.config.allow_fragments {
            return InboundVerdict::Deny(DenyCode::FragmentRefused);
        }
        if meta.total_len > self.config.mtu as usize {
            return InboundVerdict::Deny(DenyCode::OversizedPacket);
        }
        // A guest must not be able to inject a packet that appears to come
        // from itself.
        if meta.src == guest {
            return InboundVerdict::Deny(DenyCode::SpoofedSource);
        }

        // The gateway's own replies (synthetic DNS answers) are
        // host-originated and already policy-shaped.
        if Some(meta.src) == self.lease.gateway_in(AddressFamily::of(meta.src)) {
            return InboundVerdict::Deliver(DeliverablePacket { bytes, meta });
        }

        // ICMP errors are how path-MTU discovery and ordinary failure
        // signalling work. They arrive from routers that never appear in a
        // flow, so they are admitted on message type rather than on flow
        // match — and only the control types, never echo.
        if matches!(meta.protocol, proto::ICMP | proto::ICMPV6) {
            return match self.icmp_inbound_verdict(&meta, now_millis) {
                Some(code) => InboundVerdict::Deny(code),
                None => InboundVerdict::Deliver(DeliverablePacket { bytes, meta }),
            };
        }

        let (Some(remote_port), Some(guest_port)) = (meta.src_port, meta.dst_port) else {
            return InboundVerdict::Deny(DenyCode::MalformedPacket);
        };
        let flow = FlowKey {
            protocol: meta.protocol,
            guest_port,
            remote: meta.src,
            remote_port,
        };
        if self
            .flows
            .admit_inbound(&flow, meta.total_len as u64, now_millis)
        {
            return InboundVerdict::Deliver(DeliverablePacket { bytes, meta });
        }
        // Not return traffic. The only other way in is a declared ingress
        // mapping for this guest port.
        if self.ingress.admits(meta.protocol, guest_port) {
            match self
                .flows
                .observe_outbound(flow, meta.total_len as u64, now_millis)
            {
                FlowAdmission::TableFull => InboundVerdict::Deny(DenyCode::FlowTableFull),
                _ => InboundVerdict::Deliver(DeliverablePacket { bytes, meta }),
            }
        } else {
            InboundVerdict::Deny(DenyCode::UnsolicitedInbound)
        }
    }

    /// Address-class refusals, checked before any allow-list is consulted
    /// so no rule shape can open them.
    ///
    /// An IPv6 address that encodes an IPv4 one is refused for the reason
    /// that IPv4 address would be refused: [`embedded_v4`] runs first and
    /// its result goes through the whole v4 check, so only a natively IPv6
    /// destination ever reaches the v6 rules. Enumerating IPv6 hazards
    /// instead would be a list that has to be complete, and the datapath's
    /// destination-integrity assertion cannot be the backstop — it compares
    /// canonical forms, which collapses exactly the distinction an
    /// embedded-v4 bypass exploits.
    fn destination_class_denial(&self, dst: IpAddr) -> Option<DenyCode> {
        match dst {
            IpAddr::V4(v4) => self.v4_class_denial(v4),
            IpAddr::V6(v6) => match embedded_v4(v6) {
                Some(v4) => self.v4_class_denial(v4),
                None => self.v6_class_denial(v6),
            },
        }
    }

    fn v4_class_denial(&self, v4: Ipv4Addr) -> Option<DenyCode> {
        let dst = IpAddr::V4(v4);
        if v4.is_loopback() {
            return Some(DenyCode::LoopbackDenied);
        }
        if v4.is_link_local() {
            return Some(DenyCode::LinkLocalDenied);
        }
        if v4.is_multicast() {
            return Some(DenyCode::MulticastDenied);
        }
        if v4.is_broadcast() || v4 == self.lease.broadcast() {
            return Some(DenyCode::BroadcastDenied);
        }
        if v4.is_unspecified() || v4.octets()[0] == 0 || is_reserved_v4(v4) {
            return Some(DenyCode::ReservedRangeDenied);
        }
        if mvm_core::network_policy::is_mandatory_deny(dst) {
            return Some(DenyCode::MandatoryDeny);
        }
        if v4.is_private() && !self.private_range_admitted(dst) {
            return Some(DenyCode::PrivateRangeDenied);
        }
        None
    }

    /// Native IPv6 classes, mirroring the IPv4 rules above range for range.
    ///
    /// Link-local is a mandatory refusal rather than an opt-in one:
    /// `fe80::/10` is where NDP neighbours and routers live, so a guest
    /// reaching it reaches the host's own interfaces. There is deliberately
    /// no broadcast rule — IPv6 has none, and `ff02::1` is multicast.
    fn v6_class_denial(&self, v6: Ipv6Addr) -> Option<DenyCode> {
        let dst = IpAddr::V6(v6);
        if v6.is_loopback() {
            return Some(DenyCode::LoopbackDenied);
        }
        if is_v6_link_local(v6) {
            return Some(DenyCode::LinkLocalDenied);
        }
        if v6.is_multicast() {
            return Some(DenyCode::MulticastDenied);
        }
        if v6.is_unspecified() {
            return Some(DenyCode::ReservedRangeDenied);
        }
        if mvm_core::network_policy::is_mandatory_deny(dst) {
            return Some(DenyCode::MandatoryDeny);
        }
        if is_v6_unique_local(v6) && !self.private_range_admitted(dst) {
            return Some(DenyCode::PrivateRangeDenied);
        }
        None
    }

    fn private_range_admitted(&self, ip: IpAddr) -> bool {
        self.config
            .admitted_private
            .iter()
            .any(|net| net.contains(&ip))
    }

    /// Whether any canonical rule covers this address, ignoring the port.
    /// Used to tell a port refusal from a destination refusal, and to
    /// decide ICMP, which has no ports.
    fn destination_admitted_for_any_port(&self, ip: IpAddr) -> bool {
        match &self.config.egress {
            CanonicalEgress::Unrestricted => true,
            CanonicalEgress::Rules(rules) => {
                rules.iter().any(|r: &CanonicalRule| r.net.contains(&ip))
            }
        }
    }

    fn icmp_outbound_denial(&self, meta: &ParsedIpPacket) -> Option<DenyCode> {
        let Some((icmp_type, _)) = meta.icmp else {
            return Some(DenyCode::MalformedPacket);
        };
        match self.config.icmp {
            IcmpPolicy::Deny => Some(DenyCode::IcmpDenied),
            IcmpPolicy::ErrorsOnly => {
                if is_icmp_control(meta.protocol, icmp_type) {
                    self.icmp_destination_denial(meta)
                } else {
                    Some(DenyCode::IcmpDenied)
                }
            }
            IcmpPolicy::EchoAndErrors => {
                if is_icmp_control(meta.protocol, icmp_type)
                    || is_icmp_echo_request(meta.protocol, icmp_type)
                {
                    self.icmp_destination_denial(meta)
                } else {
                    Some(DenyCode::IcmpDenied)
                }
            }
        }
    }

    /// ICMP has no port, so destination admission is the port-agnostic
    /// question: does any rule cover this address at all.
    fn icmp_destination_denial(&self, meta: &ParsedIpPacket) -> Option<DenyCode> {
        if self.destination_admitted_for_any_port(meta.dst) {
            None
        } else {
            Some(DenyCode::DestinationNotAdmitted)
        }
    }

    fn icmp_inbound_verdict(&mut self, meta: &ParsedIpPacket, now_millis: u64) -> Option<DenyCode> {
        let Some((icmp_type, _)) = meta.icmp else {
            return Some(DenyCode::MalformedPacket);
        };
        if self.config.icmp == IcmpPolicy::Deny {
            return Some(DenyCode::IcmpDenied);
        }
        if is_icmp_control(meta.protocol, icmp_type) {
            // Path-MTU and unreachable messages must get through, or the
            // guest's TCP blackholes instead of adapting.
            return None;
        }
        if is_icmp_echo_reply(meta.protocol, icmp_type) {
            if self.config.icmp != IcmpPolicy::EchoAndErrors {
                return Some(DenyCode::IcmpDenied);
            }
            let flow = FlowKey {
                protocol: meta.protocol,
                guest_port: 0,
                remote: meta.src,
                remote_port: 0,
            };
            return if self
                .flows
                .admit_inbound(&flow, meta.total_len as u64, now_millis)
            {
                None
            } else {
                Some(DenyCode::UnsolicitedInbound)
            };
        }
        Some(DenyCode::IcmpDenied)
    }
}

/// ICMP error/control types that carry path-MTU and reachability
/// signalling. Everything else is not "normal error handling".
fn is_icmp_control(protocol: u8, icmp_type: u8) -> bool {
    match protocol {
        // v4: destination unreachable (which carries fragmentation-needed),
        // time exceeded, parameter problem.
        proto::ICMP => matches!(icmp_type, 3 | 11 | 12),
        // v6: destination unreachable, packet too big, time exceeded,
        // parameter problem.
        proto::ICMPV6 => matches!(icmp_type, 1..=4),
        _ => false,
    }
}

fn is_icmp_echo_request(protocol: u8, icmp_type: u8) -> bool {
    (protocol == proto::ICMP && icmp_type == 8) || (protocol == proto::ICMPV6 && icmp_type == 128)
}

fn is_icmp_echo_reply(protocol: u8, icmp_type: u8) -> bool {
    (protocol == proto::ICMP && icmp_type == 0) || (protocol == proto::ICMPV6 && icmp_type == 129)
}

/// The IPv4 address an IPv6 address encodes, if it encodes one.
///
/// Four encodings, and every one of them reaches `169.254.169.254`:
///
/// | form | prefix |
/// |---|---|
/// | v4-mapped | `::ffff:0:0/96` |
/// | v4-compatible (deprecated) | `::/96` |
/// | NAT64 well-known | `64:ff9b::/96` |
/// | 6to4 | `2002::/16` |
///
/// v4-mapped is the famous one. NAT64 and 6to4 are the forgotten ones, and
/// a NAT64 gateway on the host network makes the third genuinely routable.
/// This is the whole defence: whatever comes back here is range-checked as
/// the IPv4 address it is, so a caller cannot reach an IPv4 destination by
/// spelling it differently.
///
/// `::` and `::1` are excluded. RFC 4291 does not treat them as
/// v4-compatible addresses — they are the unspecified and loopback
/// addresses, and the native rules refuse them under their own names rather
/// than as `0.0.0.0` and `0.0.0.1`.
///
/// RFC 6052 also permits a NAT64 prefix at /32 through /64, where the
/// embedded address straddles the reserved octet. Only the well-known /96
/// is decoded here, because the others cannot be recognised without knowing
/// the operator's prefix, and guessing at one would extract an address the
/// packet does not carry. A destination in one of those forms is a native
/// IPv6 address to this check, and the surrounding posture is deny by
/// default: no rule covers it unless a plan wrote one.
pub(crate) fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let o = ip.octets();
    let low = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    if s[0..5] == [0, 0, 0, 0, 0] {
        return match s[5] {
            0xffff => Some(low),
            0 if !ip.is_unspecified() && !ip.is_loopback() => Some(low),
            _ => None,
        };
    }
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return Some(low);
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    None
}

/// `fe80::/10`.
fn is_v6_link_local(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// `fc00::/7` — IPv6's RFC1918.
fn is_v6_unique_local(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xfe00 == 0xfc00
}

/// Ranges that are neither routable nor private: this-network, shared
/// address space, documentation, benchmarking, reserved, and the former
/// class E.
fn is_reserved_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    matches!(o[0], 0)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)      // IETF protocol assignments
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)      // TEST-NET-1
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))  // benchmarking
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)   // TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)    // TEST-NET-3
        || o[0] >= 240 // reserved / limited broadcast
}

/// Clamp the MSS option in a TCP SYN so the negotiated segment size cannot
/// provoke fragmentation on a path smaller than the guest's MTU.
///
/// Rewrites in place and repairs the TCP checksum incrementally (RFC 1624),
/// which is why it takes `&mut`: recomputing the whole checksum would mean
/// touching the payload, and this function deliberately never reads it.
///
/// Returns `true` when an option was rewritten.
pub fn clamp_tcp_mss(packet: &mut [u8], max_mss: u16) -> bool {
    let Ok(meta) = ip::parse(packet) else {
        return false;
    };
    if meta.protocol != proto::TCP || meta.version != 4 || meta.fragment {
        return false;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    let tcp = match packet.get(ihl..meta.total_len) {
        Some(slice) if slice.len() >= 20 => slice,
        _ => return false,
    };
    // Only a SYN carries an MSS option.
    if tcp[13] & ip::TCP_SYN == 0 {
        return false;
    }
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset < 20 || data_offset > tcp.len() {
        return false;
    }

    let mut i = 20;
    while i + 1 < data_offset {
        let kind = tcp[i];
        match kind {
            0 => break,  // end of option list
            1 => i += 1, // no-op
            _ => {
                let len = tcp[i + 1] as usize;
                if len < 2 || i + len > data_offset {
                    return false;
                }
                if kind == 2 && len == 4 {
                    let old = u16::from_be_bytes([tcp[i + 2], tcp[i + 3]]);
                    if old <= max_mss {
                        return false;
                    }
                    let mss_at = ihl + i + 2;
                    let checksum_at = ihl + 16;
                    packet[mss_at..mss_at + 2].copy_from_slice(&max_mss.to_be_bytes());
                    let old_sum =
                        u16::from_be_bytes([packet[checksum_at], packet[checksum_at + 1]]);
                    let new_sum = incremental_checksum(old_sum, old, max_mss);
                    packet[checksum_at..checksum_at + 2].copy_from_slice(&new_sum.to_be_bytes());
                    return true;
                }
                i += len;
            }
        }
    }
    false
}

/// RFC 1624 eqn. 3: update a one's-complement checksum for a single
/// 16-bit field change without rescanning the packet.
fn incremental_checksum(old_sum: u16, old_field: u16, new_field: u16) -> u16 {
    let sum = (!old_sum) as u32 + (!old_field) as u32 + new_field as u32;
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l3::alloc::AddressAllocator;
    use crate::l3::flow::{FlowLimits, FlowTable};
    use crate::l3::ingress::{IngressMapping, IngressTable};
    use std::net::Ipv4Addr;

    const REMOTE: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

    fn lease() -> AddressLease {
        AddressAllocator::with_defaults().allocate().unwrap()
    }

    fn rule(net: &str, port: u16) -> CanonicalRule {
        CanonicalRule {
            proto: Proto::Tcp,
            net: net.parse().unwrap(),
            port_lo: port,
            port_hi: port,
        }
    }

    fn admitter_with(config: L3PolicyConfig) -> L3Admitter {
        let mut a = L3Admitter::new(
            lease(),
            config,
            FlowTable::with_defaults(),
            DnsBindingStore::with_defaults(),
            IngressTable::with_defaults(),
        );
        a.set_ready(true);
        a
    }

    /// Deny-all admitter — the default posture.
    fn closed() -> L3Admitter {
        admitter_with(L3PolicyConfig::default())
    }

    /// Admitter permitting TCP/443 to the example address.
    fn open_443() -> L3Admitter {
        admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Rules(vec![rule("93.184.216.34/32", 443)]),
            ..L3PolicyConfig::default()
        })
    }

    fn v4_packet(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[9] = protocol;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    fn tcp(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&src_port.to_be_bytes());
        t[2..4].copy_from_slice(&dst_port.to_be_bytes());
        t[12] = 0x50;
        t[13] = flags;
        t
    }

    fn udp(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut u = vec![0u8; 8];
        u[0..2].copy_from_slice(&src_port.to_be_bytes());
        u[2..4].copy_from_slice(&dst_port.to_be_bytes());
        u
    }

    fn icmp(icmp_type: u8) -> Vec<u8> {
        vec![icmp_type, 0, 0, 0]
    }

    fn out(a: &mut L3Admitter, pkt: &[u8]) -> Result<(), DenyCode> {
        match a.admit_outbound(pkt, 0) {
            OutboundVerdict::Forward(_) => Ok(()),
            OutboundVerdict::Gateway(..) => Ok(()),
            OutboundVerdict::Deny(code) => Err(code),
        }
    }

    #[test]
    fn an_allowed_destination_and_port_is_forwarded() {
        let mut a = open_443();
        let guest = a.lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        assert!(matches!(
            a.admit_outbound(&pkt, 0),
            OutboundVerdict::Forward(_)
        ));
        assert_eq!(a.flows().len(), 1);
    }

    #[test]
    fn a_forwarded_packet_carries_the_original_bytes() {
        let mut a = open_443();
        let guest = a.lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        let OutboundVerdict::Forward(admitted) = a.admit_outbound(&pkt, 0) else {
            panic!("expected forward");
        };
        assert_eq!(admitted.bytes(), &pkt[..]);
        assert_eq!(admitted.meta().dst_port, Some(443));
        assert_eq!(admitted.flow().remote_port, 443);
    }

    #[test]
    fn deny_all_is_the_default_posture() {
        let mut a = closed();
        let guest = a.lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::DestinationNotAdmitted));
    }

    #[test]
    fn an_admitted_host_on_an_unadmitted_port_is_a_port_refusal() {
        let mut a = open_443();
        let guest = a.lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 8080, ip::TCP_SYN));
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::PortNotAdmitted));
    }

    #[test]
    fn an_unadmitted_host_is_a_destination_refusal() {
        let mut a = open_443();
        let guest = a.lease().guest;
        let pkt = v4_packet(
            proto::TCP,
            guest,
            Ipv4Addr::new(1, 2, 3, 4),
            &tcp(50000, 443, ip::TCP_SYN),
        );
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::DestinationNotAdmitted));
    }

    #[test]
    fn a_spoofed_source_is_rejected() {
        let mut a = open_443();
        for spoof in [
            Ipv4Addr::new(10, 201, 0, 200),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::UNSPECIFIED,
        ] {
            let pkt = v4_packet(proto::TCP, spoof, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
            assert_eq!(
                out(&mut a, &pkt),
                Err(DenyCode::SpoofedSource),
                "source {spoof} must not be accepted"
            );
        }
    }

    #[test]
    fn a_guest_cannot_impersonate_the_gateway() {
        let mut a = open_443();
        let gateway = a.lease().gateway;
        let pkt = v4_packet(proto::TCP, gateway, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::SpoofedSource));
    }

    #[test]
    fn loopback_link_local_and_metadata_destinations_are_denied() {
        let mut a = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            ..L3PolicyConfig::default()
        });
        let guest = a.lease().guest;
        let cases = [
            (Ipv4Addr::new(127, 0, 0, 1), DenyCode::LoopbackDenied),
            (Ipv4Addr::new(169, 254, 1, 1), DenyCode::LinkLocalDenied),
            (Ipv4Addr::new(169, 254, 169, 254), DenyCode::LinkLocalDenied),
        ];
        for (dst, expected) in cases {
            let pkt = v4_packet(proto::TCP, guest, dst, &tcp(50000, 80, ip::TCP_SYN));
            assert_eq!(out(&mut a, &pkt), Err(expected), "destination {dst}");
        }
    }

    #[test]
    fn cgnat_is_denied_even_under_an_unrestricted_policy() {
        let mut a = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            ..L3PolicyConfig::default()
        });
        let guest = a.lease().guest;
        let pkt = v4_packet(
            proto::TCP,
            guest,
            Ipv4Addr::new(100, 64, 0, 1),
            &tcp(50000, 80, ip::TCP_SYN),
        );
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::MandatoryDeny));
    }

    #[test]
    fn multicast_and_broadcast_destinations_are_denied() {
        let mut a = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            ..L3PolicyConfig::default()
        });
        let guest = a.lease().guest;
        let broadcast = a.lease().broadcast();
        for (dst, expected) in [
            (Ipv4Addr::new(224, 0, 0, 1), DenyCode::MulticastDenied),
            (Ipv4Addr::new(255, 255, 255, 255), DenyCode::BroadcastDenied),
            (broadcast, DenyCode::BroadcastDenied),
        ] {
            let pkt = v4_packet(proto::UDP, guest, dst, &udp(5000, 5353));
            assert_eq!(out(&mut a, &pkt), Err(expected), "destination {dst}");
        }
    }

    #[test]
    fn reserved_ranges_are_denied() {
        let mut a = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            ..L3PolicyConfig::default()
        });
        let guest = a.lease().guest;
        for dst in [
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(203, 0, 113, 1),
            Ipv4Addr::new(240, 0, 0, 1),
        ] {
            let pkt = v4_packet(proto::TCP, guest, dst, &tcp(50000, 80, ip::TCP_SYN));
            assert_eq!(
                out(&mut a, &pkt),
                Err(DenyCode::ReservedRangeDenied),
                "destination {dst}"
            );
        }
    }

    #[test]
    fn private_ranges_are_denied_by_default_even_when_unrestricted() {
        let mut a = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            ..L3PolicyConfig::default()
        });
        let guest = a.lease().guest;
        for dst in [
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(172, 16, 0, 5),
            Ipv4Addr::new(192, 168, 1, 5),
        ] {
            let pkt = v4_packet(proto::TCP, guest, dst, &tcp(50000, 80, ip::TCP_SYN));
            assert_eq!(
                out(&mut a, &pkt),
                Err(DenyCode::PrivateRangeDenied),
                "\"private\" is not \"safe\": {dst} must be closed by default"
            );
        }
    }

    // ---- IPv6 destination classes -----------------------------------
    //
    // Driven through `destination_class_denial` directly. It is the whole
    // defence against an IPv4 address written in IPv6: the datapath's
    // destination-integrity assertion compares canonical forms, which
    // collapses exactly the distinction an embedded-v4 bypass exploits, so
    // nothing downstream would catch what this let through.

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().expect("a literal IPv6 address"))
    }

    /// Unrestricted, so nothing but the class check can be what refuses.
    fn wide_open() -> L3Admitter {
        admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            ..L3PolicyConfig::default()
        })
    }

    /// The four ways IPv6 can spell an IPv4 address. Each one reaches the
    /// cloud metadata service, and each must be refused for the reason the
    /// bare address is refused — not for being IPv6.
    #[test]
    fn a_v4_mapped_address_is_refused_for_the_embedded_addresss_reason() {
        assert_eq!(
            wide_open().destination_class_denial(v6("::ffff:169.254.169.254")),
            Some(DenyCode::LinkLocalDenied)
        );
    }

    #[test]
    fn a_v4_compatible_address_is_refused_for_the_embedded_addresss_reason() {
        assert_eq!(
            wide_open().destination_class_denial(v6("::169.254.169.254")),
            Some(DenyCode::LinkLocalDenied)
        );
    }

    #[test]
    fn a_nat64_address_is_refused_for_the_embedded_addresss_reason() {
        // A NAT64 gateway on the host network makes this one genuinely
        // routable, which is what makes it worth more than a curiosity.
        assert_eq!(
            wide_open().destination_class_denial(v6("64:ff9b::169.254.169.254")),
            Some(DenyCode::LinkLocalDenied)
        );
    }

    #[test]
    fn a_6to4_address_is_refused_for_the_embedded_addresss_reason() {
        assert_eq!(
            wide_open().destination_class_denial(v6("2002:a9fe:a9fe::")),
            Some(DenyCode::LinkLocalDenied)
        );
    }

    /// The extraction is not a special case wired to the metadata address:
    /// an embedded address goes through the *entire* v4 class check,
    /// allow-list included.
    #[test]
    fn an_embedded_private_address_follows_the_whole_v4_rule_including_the_allow_list() {
        assert_eq!(
            wide_open().destination_class_denial(v6("::ffff:10.42.0.7")),
            Some(DenyCode::PrivateRangeDenied)
        );
        let opened = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            admitted_private: vec!["10.42.0.0/16".parse().unwrap()],
            ..L3PolicyConfig::default()
        });
        assert_eq!(
            opened.destination_class_denial(v6("::ffff:10.42.0.7")),
            None,
            "the rule that opens 10.42.0.0/16 opens the same host written in IPv6"
        );
        assert_eq!(
            opened.destination_class_denial(v6("::ffff:10.43.0.7")),
            Some(DenyCode::PrivateRangeDenied),
            "and opens nothing beyond it"
        );
    }

    #[test]
    fn an_embedded_cgnat_address_is_mandatory_denied() {
        assert_eq!(
            wide_open().destination_class_denial(v6("::ffff:100.64.0.1")),
            Some(DenyCode::MandatoryDeny)
        );
    }

    /// Native IPv6 policy mirrors IPv4's. Link-local is mandatory rather
    /// than opt-in: `fe80::/10` is where NDP neighbours and routers live, so
    /// a guest reaching it reaches the host's own interfaces.
    #[test]
    fn native_v6_address_classes_are_refused_like_their_v4_analogues() {
        let a = wide_open();
        for (dst, expected) in [
            ("::1", DenyCode::LoopbackDenied),
            ("::", DenyCode::ReservedRangeDenied),
            ("fe80::1", DenyCode::LinkLocalDenied),
            ("febf:ffff::1", DenyCode::LinkLocalDenied),
            ("ff02::1", DenyCode::MulticastDenied),
            ("ff00::1", DenyCode::MulticastDenied),
        ] {
            assert_eq!(
                a.destination_class_denial(v6(dst)),
                Some(expected),
                "destination {dst}"
            );
        }
    }

    #[test]
    fn a_unique_local_v6_range_is_denied_unless_a_rule_opens_it() {
        assert_eq!(
            wide_open().destination_class_denial(v6("fd00:1234::5")),
            Some(DenyCode::PrivateRangeDenied),
            "fc00::/7 is IPv6's RFC1918 and is closed by default"
        );
        let opened = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            admitted_private: vec!["fd00:1234::/32".parse().unwrap()],
            ..L3PolicyConfig::default()
        });
        assert_eq!(opened.destination_class_denial(v6("fd00:1234::5")), None);
        assert_eq!(
            opened.destination_class_denial(v6("fd00:9999::5")),
            Some(DenyCode::PrivateRangeDenied)
        );
    }

    /// Without this the four tests above would pass on a class check that
    /// simply refused every IPv6 address.
    #[test]
    fn a_global_v6_destination_passes_the_class_check() {
        assert_eq!(
            wide_open().destination_class_denial(v6("2606:4700:4700::1111")),
            None
        );
    }

    #[test]
    fn an_explicit_cidr_rule_opens_a_private_range() {
        let mut a = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Rules(vec![rule("10.42.0.0/16", 5432)]),
            admitted_private: vec!["10.42.0.0/16".parse().unwrap()],
            ..L3PolicyConfig::default()
        });
        let guest = a.lease().guest;
        let allowed = v4_packet(
            proto::TCP,
            guest,
            Ipv4Addr::new(10, 42, 0, 7),
            &tcp(50000, 5432, ip::TCP_SYN),
        );
        assert_eq!(out(&mut a, &allowed), Ok(()));
        // A neighbouring private range stays shut.
        let denied = v4_packet(
            proto::TCP,
            guest,
            Ipv4Addr::new(10, 43, 0, 7),
            &tcp(50000, 5432, ip::TCP_SYN),
        );
        assert_eq!(out(&mut a, &denied), Err(DenyCode::PrivateRangeDenied));
    }

    #[test]
    fn an_explicit_ip_rule_works_without_any_dns_binding() {
        let mut a = open_443();
        let guest = a.lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        assert!(a.dns().is_empty());
        assert_eq!(out(&mut a, &pkt), Ok(()));
    }

    #[test]
    fn a_dns_binding_admits_a_destination_no_static_rule_covers() {
        let mut a = closed();
        let guest = a.lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::DestinationNotAdmitted));

        a.dns_mut()
            .bind_answer(
                "api.example.com",
                &[IpAddr::V4(REMOTE)],
                &[443],
                60_000,
                0,
                0,
            )
            .unwrap();
        assert_eq!(out(&mut a, &pkt), Ok(()));
    }

    #[test]
    fn a_direct_ip_connection_is_denied_when_only_a_domain_rule_exists() {
        let mut a = closed();
        let guest = a.lease().guest;
        a.dns_mut()
            .bind_answer(
                "api.example.com",
                &[IpAddr::V4(REMOTE)],
                &[443],
                60_000,
                0,
                0,
            )
            .unwrap();
        // A different address the guest simply guessed.
        let pkt = v4_packet(
            proto::TCP,
            guest,
            Ipv4Addr::new(93, 184, 216, 99),
            &tcp(50000, 443, ip::TCP_SYN),
        );
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::DestinationNotAdmitted));
    }

    #[test]
    fn an_expired_dns_binding_stops_admitting() {
        let mut a = closed();
        let guest = a.lease().guest;
        a.dns_mut()
            .bind_answer(
                "api.example.com",
                &[IpAddr::V4(REMOTE)],
                &[443],
                10_000,
                0,
                0,
            )
            .unwrap();
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        assert!(matches!(
            a.admit_outbound(&pkt, 9_999),
            OutboundVerdict::Forward(_)
        ));
        assert!(matches!(
            a.admit_outbound(&pkt, 10_000),
            OutboundVerdict::Deny(DenyCode::PortNotAdmitted | DenyCode::DestinationNotAdmitted)
        ));
    }

    #[test]
    fn dns_to_the_synthetic_resolver_is_terminated_at_the_gateway() {
        let mut a = closed();
        let guest = a.lease().guest;
        let gateway = a.lease().gateway;
        for pkt in [
            v4_packet(proto::UDP, guest, gateway, &udp(40000, 53)),
            v4_packet(proto::TCP, guest, gateway, &tcp(40000, 53, ip::TCP_SYN)),
        ] {
            assert!(
                matches!(
                    a.admit_outbound(&pkt, 0),
                    OutboundVerdict::Gateway(GatewayService::Dns, _)
                ),
                "DNS must terminate at the gateway, not be forwarded"
            );
        }
    }

    #[test]
    fn dns_to_any_other_destination_is_blocked() {
        let mut a = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            ..L3PolicyConfig::default()
        });
        let guest = a.lease().guest;
        // 8.8.8.8:53 under an otherwise unrestricted policy: still no.
        let pkt = v4_packet(
            proto::UDP,
            guest,
            Ipv4Addr::new(8, 8, 8, 8),
            &udp(40000, 53),
        );
        // Unrestricted admits it at L4, which is exactly why the gateway
        // must be the only resolver a plan points the guest at. The check
        // that matters is that an *allowlist* policy refuses it.
        assert_eq!(out(&mut a, &pkt), Ok(()));

        let mut a = open_443();
        let guest = a.lease().guest;
        let pkt = v4_packet(
            proto::UDP,
            guest,
            Ipv4Addr::new(8, 8, 8, 8),
            &udp(40000, 53),
        );
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::DestinationNotAdmitted));
    }

    #[test]
    fn non_dns_traffic_to_the_gateway_is_refused() {
        let mut a = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            ..L3PolicyConfig::default()
        });
        let guest = a.lease().guest;
        let gateway = a.lease().gateway;
        let pkt = v4_packet(proto::TCP, guest, gateway, &tcp(40000, 22, ip::TCP_SYN));
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::GatewayServiceDenied));
    }

    #[test]
    fn fragments_are_refused_rather_than_reassembled() {
        let mut a = open_443();
        let guest = a.lease().guest;
        let mut pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        pkt[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::FragmentRefused));
    }

    #[test]
    fn a_packet_larger_than_the_mtu_is_refused() {
        let mut a = open_443();
        let guest = a.lease().guest;
        let payload = vec![0u8; 1600];
        let mut pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, 0));
        pkt.extend_from_slice(&payload);
        let total = pkt.len();
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::OversizedPacket));
    }

    #[test]
    fn a_malformed_packet_is_refused() {
        let mut a = open_443();
        assert_eq!(out(&mut a, &[]), Err(DenyCode::MalformedPacket));
        assert_eq!(out(&mut a, &[0x45, 0x00]), Err(DenyCode::MalformedPacket));
    }

    // ---- IPv6 packets -----------------------------------------------

    const GUEST_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xc9, 0, 0, 0, 0, 0, 2);
    const GATEWAY_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xc9, 0, 0, 0, 0, 0, 1);
    const REMOTE_V6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);

    /// An admitter whose session holds both families, permitting TCP/443 to
    /// the example IPv6 address.
    fn open_443_v6() -> L3Admitter {
        let mut a = L3Admitter::new(
            lease().with_v6(GATEWAY_V6, GUEST_V6),
            L3PolicyConfig {
                egress: CanonicalEgress::Rules(vec![rule("2606:4700:4700::1111/128", 443)]),
                ..L3PolicyConfig::default()
            },
            FlowTable::with_defaults(),
            DnsBindingStore::with_defaults(),
            IngressTable::with_defaults(),
        );
        a.set_ready(true);
        a
    }

    fn v6_packet(protocol: u8, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        p[6] = protocol;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn an_admitted_v6_destination_and_port_is_forwarded() {
        let mut a = open_443_v6();
        let pkt = v6_packet(
            proto::TCP,
            GUEST_V6,
            REMOTE_V6,
            &tcp(50000, 443, ip::TCP_SYN),
        );
        assert_eq!(out(&mut a, &pkt), Ok(()));
        assert_eq!(a.flows().len(), 1);
    }

    #[test]
    fn a_v6_packet_is_refused_while_the_session_holds_no_v6_address() {
        // The deny code names the reason: nothing was assigned, so no
        // source could ever be anti-spoof clean.
        let mut a = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            ..L3PolicyConfig::default()
        });
        let pkt = v6_packet(
            proto::TCP,
            GUEST_V6,
            REMOTE_V6,
            &tcp(50000, 443, ip::TCP_SYN),
        );
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::AddressFamilyUnassigned));
    }

    #[test]
    fn a_spoofed_v6_source_is_rejected() {
        let mut a = open_443_v6();
        for spoof in [
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::UNSPECIFIED,
            GATEWAY_V6,
            Ipv6Addr::new(0xfd00, 0xc9, 0, 0, 0, 0, 0, 9),
        ] {
            let pkt = v6_packet(proto::TCP, spoof, REMOTE_V6, &tcp(50000, 443, ip::TCP_SYN));
            assert_eq!(
                out(&mut a, &pkt),
                Err(DenyCode::SpoofedSource),
                "source {spoof} must not be accepted"
            );
        }
    }

    /// An embedded-v4 destination is refused on the packet path too, not
    /// only when the class check is called directly.
    #[test]
    fn a_v6_packet_at_an_embedded_v4_metadata_address_is_refused() {
        let mut a = L3Admitter::new(
            lease().with_v6(GATEWAY_V6, GUEST_V6),
            L3PolicyConfig {
                egress: CanonicalEgress::Unrestricted,
                ..L3PolicyConfig::default()
            },
            FlowTable::with_defaults(),
            DnsBindingStore::with_defaults(),
            IngressTable::with_defaults(),
        );
        a.set_ready(true);
        for dst in [
            "::ffff:169.254.169.254",
            "::169.254.169.254",
            "64:ff9b::169.254.169.254",
            "2002:a9fe:a9fe::",
        ] {
            let pkt = v6_packet(
                proto::TCP,
                GUEST_V6,
                dst.parse().unwrap(),
                &tcp(50000, 80, ip::TCP_SYN),
            );
            assert_eq!(
                out(&mut a, &pkt),
                Err(DenyCode::LinkLocalDenied),
                "destination {dst}"
            );
        }
    }

    #[test]
    fn v6_dns_to_the_synthetic_resolver_is_terminated_at_the_gateway() {
        let mut a = open_443_v6();
        let pkt = v6_packet(proto::UDP, GUEST_V6, GATEWAY_V6, &udp(40000, 53));
        assert!(matches!(
            a.admit_outbound(&pkt, 0),
            OutboundVerdict::Gateway(GatewayService::Dns, _)
        ));
        let other = v6_packet(
            proto::TCP,
            GUEST_V6,
            GATEWAY_V6,
            &tcp(40000, 22, ip::TCP_SYN),
        );
        assert_eq!(out(&mut a, &other), Err(DenyCode::GatewayServiceDenied));
    }

    #[test]
    fn v6_return_traffic_for_an_admitted_flow_is_delivered() {
        let mut a = open_443_v6();
        let outbound = v6_packet(
            proto::TCP,
            GUEST_V6,
            REMOTE_V6,
            &tcp(50000, 443, ip::TCP_SYN),
        );
        out(&mut a, &outbound).unwrap();
        let reply = v6_packet(
            proto::TCP,
            REMOTE_V6,
            GUEST_V6,
            &tcp(443, 50000, ip::TCP_SYN | ip::TCP_ACK),
        );
        assert_eq!(inbound(&mut a, &reply, 1), Ok(()));
    }

    #[test]
    fn unsolicited_v6_inbound_traffic_is_dropped() {
        let mut a = open_443_v6();
        let pkt = v6_packet(
            proto::TCP,
            REMOTE_V6,
            GUEST_V6,
            &tcp(443, 50000, ip::TCP_SYN),
        );
        assert_eq!(inbound(&mut a, &pkt, 0), Err(DenyCode::UnsolicitedInbound));
    }

    #[test]
    fn v6_inbound_traffic_for_another_address_is_refused() {
        let mut a = open_443_v6();
        let elsewhere = Ipv6Addr::new(0xfd00, 0xc9, 0, 0, 0, 0, 0, 9);
        let pkt = v6_packet(proto::TCP, REMOTE_V6, elsewhere, &tcp(443, 50000, 0));
        assert_eq!(inbound(&mut a, &pkt, 0), Err(DenyCode::WrongDestination));
    }

    #[test]
    fn an_unknown_transport_protocol_is_refused() {
        let mut a = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            ..L3PolicyConfig::default()
        });
        let guest = a.lease().guest;
        let pkt = v4_packet(89, guest, REMOTE, &[0u8; 8]); // OSPF
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::ProtocolDenied));
    }

    #[test]
    fn packets_are_refused_until_the_handshake_completes() {
        let mut a = open_443();
        a.set_ready(false);
        let guest = a.lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::SessionNotReady));
    }

    #[test]
    fn the_flow_table_capacity_bounds_the_guest() {
        let mut a = L3Admitter::new(
            lease(),
            L3PolicyConfig {
                egress: CanonicalEgress::Rules(vec![rule("93.184.216.34/32", 443)]),
                ..L3PolicyConfig::default()
            },
            FlowTable::new(FlowLimits {
                max_flows: 2,
                ..FlowLimits::default()
            }),
            DnsBindingStore::with_defaults(),
            IngressTable::with_defaults(),
        );
        a.set_ready(true);
        let guest = a.lease().guest;
        for port in 0..2u16 {
            let pkt = v4_packet(
                proto::TCP,
                guest,
                REMOTE,
                &tcp(50000 + port, 443, ip::TCP_SYN),
            );
            assert_eq!(out(&mut a, &pkt), Ok(()));
        }
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50002, 443, ip::TCP_SYN));
        assert_eq!(out(&mut a, &pkt), Err(DenyCode::FlowTableFull));
    }

    // ---- inbound ----------------------------------------------------

    fn inbound(a: &mut L3Admitter, pkt: &[u8], now: u64) -> Result<(), DenyCode> {
        match a.admit_inbound(pkt, now) {
            InboundVerdict::Deliver(_) => Ok(()),
            InboundVerdict::Deny(code) => Err(code),
        }
    }

    #[test]
    fn return_traffic_for_an_admitted_flow_is_delivered() {
        let mut a = open_443();
        let guest = a.lease().guest;
        let outbound = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        out(&mut a, &outbound).unwrap();
        let reply = v4_packet(
            proto::TCP,
            REMOTE,
            guest,
            &tcp(443, 50000, ip::TCP_SYN | ip::TCP_ACK),
        );
        assert_eq!(inbound(&mut a, &reply, 1), Ok(()));
    }

    #[test]
    fn unsolicited_inbound_traffic_is_dropped() {
        let mut a = open_443();
        let guest = a.lease().guest;
        let unsolicited = v4_packet(proto::TCP, REMOTE, guest, &tcp(443, 50000, ip::TCP_SYN));
        assert_eq!(
            inbound(&mut a, &unsolicited, 0),
            Err(DenyCode::UnsolicitedInbound)
        );
    }

    #[test]
    fn a_declared_ingress_mapping_admits_a_new_inbound_flow() {
        let mut a = open_443();
        a.ingress_mut()
            .declare(IngressMapping::tcp("0.0.0.0".parse().unwrap(), 8080, 80))
            .unwrap();
        let guest = a.lease().guest;
        let pkt = v4_packet(proto::TCP, REMOTE, guest, &tcp(40000, 80, ip::TCP_SYN));
        assert_eq!(inbound(&mut a, &pkt, 0), Ok(()));
        // A port with no mapping stays shut.
        let other = v4_packet(proto::TCP, REMOTE, guest, &tcp(40000, 81, ip::TCP_SYN));
        assert_eq!(
            inbound(&mut a, &other, 0),
            Err(DenyCode::UnsolicitedInbound)
        );
    }

    #[test]
    fn inbound_traffic_for_another_address_is_refused() {
        let mut a = open_443();
        let pkt = v4_packet(
            proto::TCP,
            REMOTE,
            Ipv4Addr::new(10, 201, 9, 9),
            &tcp(443, 50000, 0),
        );
        assert_eq!(inbound(&mut a, &pkt, 0), Err(DenyCode::WrongDestination));
    }

    #[test]
    fn an_inbound_packet_claiming_the_guests_own_source_is_refused() {
        let mut a = open_443();
        let guest = a.lease().guest;
        let pkt = v4_packet(proto::TCP, guest, guest, &tcp(443, 50000, 0));
        assert_eq!(inbound(&mut a, &pkt, 0), Err(DenyCode::SpoofedSource));
    }

    #[test]
    fn a_gateway_originated_reply_is_delivered() {
        let mut a = closed();
        let guest = a.lease().guest;
        let gateway = a.lease().gateway;
        let dns_reply = v4_packet(proto::UDP, gateway, guest, &udp(53, 40000));
        assert_eq!(inbound(&mut a, &dns_reply, 0), Ok(()));
    }

    // ---- ICMP -------------------------------------------------------

    #[test]
    fn icmp_echo_to_an_admitted_destination_is_allowed_by_default() {
        let mut a = open_443();
        let guest = a.lease().guest;
        let ping = v4_packet(proto::ICMP, guest, REMOTE, &icmp(8));
        assert_eq!(out(&mut a, &ping), Ok(()));
        let pong = v4_packet(proto::ICMP, REMOTE, guest, &icmp(0));
        assert_eq!(inbound(&mut a, &pong, 1), Ok(()));
    }

    #[test]
    fn icmp_echo_to_an_unadmitted_destination_is_denied() {
        let mut a = open_443();
        let guest = a.lease().guest;
        let ping = v4_packet(proto::ICMP, guest, Ipv4Addr::new(1, 2, 3, 4), &icmp(8));
        assert_eq!(out(&mut a, &ping), Err(DenyCode::DestinationNotAdmitted));
    }

    #[test]
    fn an_unsolicited_echo_reply_is_dropped() {
        let mut a = open_443();
        let guest = a.lease().guest;
        let pong = v4_packet(proto::ICMP, REMOTE, guest, &icmp(0));
        assert_eq!(inbound(&mut a, &pong, 0), Err(DenyCode::UnsolicitedInbound));
    }

    #[test]
    fn path_mtu_discovery_messages_reach_the_guest_unsolicited() {
        // Fragmentation-needed arrives from a router that is in no flow.
        // If it were dropped, the guest's TCP would blackhole instead of
        // adapting — which is the whole reason this exception exists.
        let mut a = open_443();
        let guest = a.lease().guest;
        let router = Ipv4Addr::new(198, 51, 100, 1);
        let frag_needed = v4_packet(proto::ICMP, router, guest, &[3, 4, 0, 0]);
        assert_eq!(inbound(&mut a, &frag_needed, 0), Ok(()));
        let time_exceeded = v4_packet(proto::ICMP, router, guest, &[11, 0, 0, 0]);
        assert_eq!(inbound(&mut a, &time_exceeded, 0), Ok(()));
    }

    #[test]
    fn errors_only_policy_permits_control_messages_but_not_ping() {
        let mut a = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Rules(vec![rule("93.184.216.34/32", 443)]),
            icmp: IcmpPolicy::ErrorsOnly,
            ..L3PolicyConfig::default()
        });
        let guest = a.lease().guest;
        let ping = v4_packet(proto::ICMP, guest, REMOTE, &icmp(8));
        assert_eq!(out(&mut a, &ping), Err(DenyCode::IcmpDenied));
        let frag_needed = v4_packet(proto::ICMP, REMOTE, guest, &[3, 4, 0, 0]);
        assert_eq!(inbound(&mut a, &frag_needed, 0), Ok(()));
    }

    #[test]
    fn a_deny_icmp_policy_blocks_every_direction() {
        let mut a = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            icmp: IcmpPolicy::Deny,
            ..L3PolicyConfig::default()
        });
        let guest = a.lease().guest;
        assert_eq!(
            out(&mut a, &v4_packet(proto::ICMP, guest, REMOTE, &icmp(8))),
            Err(DenyCode::IcmpDenied)
        );
        assert_eq!(
            inbound(
                &mut a,
                &v4_packet(proto::ICMP, REMOTE, guest, &[3, 4, 0, 0]),
                0
            ),
            Err(DenyCode::IcmpDenied)
        );
    }

    #[test]
    fn an_exotic_icmp_type_is_denied_even_under_the_permissive_policy() {
        let mut a = admitter_with(L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            ..L3PolicyConfig::default()
        });
        let guest = a.lease().guest;
        // Redirect (5) would let a remote peer steer guest routing.
        let redirect = v4_packet(proto::ICMP, guest, REMOTE, &icmp(5));
        assert_eq!(out(&mut a, &redirect), Err(DenyCode::IcmpDenied));
        let inbound_redirect = v4_packet(proto::ICMP, REMOTE, guest, &icmp(5));
        assert_eq!(
            inbound(&mut a, &inbound_redirect, 0),
            Err(DenyCode::IcmpDenied)
        );
    }

    // ---- MSS clamping ----------------------------------------------

    fn syn_with_mss(mss: u16) -> Vec<u8> {
        let mut t = vec![0u8; 24];
        t[0..2].copy_from_slice(&50000u16.to_be_bytes());
        t[2..4].copy_from_slice(&443u16.to_be_bytes());
        t[12] = 0x60; // data offset 6 words = 24 bytes
        t[13] = ip::TCP_SYN;
        t[16..18].copy_from_slice(&0u16.to_be_bytes()); // checksum
        t[20] = 2; // MSS option kind
        t[21] = 4; // length
        t[22..24].copy_from_slice(&mss.to_be_bytes());
        v4_packet(proto::TCP, Ipv4Addr::new(10, 201, 0, 6), REMOTE, &t)
    }

    #[test]
    fn mss_is_clamped_down_to_the_path_limit() {
        let mut pkt = syn_with_mss(1460);
        assert!(clamp_tcp_mss(&mut pkt, 1400));
        assert_eq!(u16::from_be_bytes([pkt[42], pkt[43]]), 1400);
    }

    #[test]
    fn an_already_small_mss_is_left_alone() {
        let mut pkt = syn_with_mss(1200);
        assert!(!clamp_tcp_mss(&mut pkt, 1400));
        assert_eq!(u16::from_be_bytes([pkt[42], pkt[43]]), 1200);
    }

    #[test]
    fn clamping_repairs_the_tcp_checksum_incrementally() {
        // Start from a packet whose checksum is correct for MSS 1460, then
        // clamp and confirm the stored value equals a full recomputation.
        let mut pkt = syn_with_mss(1460);
        let correct = tcp_checksum(&pkt);
        pkt[36..38].copy_from_slice(&correct.to_be_bytes());
        assert!(clamp_tcp_mss(&mut pkt, 1400));
        let stored = u16::from_be_bytes([pkt[36], pkt[37]]);
        let recomputed = {
            let mut probe = pkt.clone();
            probe[36..38].copy_from_slice(&0u16.to_be_bytes());
            tcp_checksum(&probe)
        };
        assert_eq!(stored, recomputed);
    }

    #[test]
    fn clamping_ignores_non_syn_and_non_tcp_packets() {
        let mut ack = syn_with_mss(1460);
        ack[33] = ip::TCP_ACK; // flags byte: 20 (IP) + 13
        assert!(!clamp_tcp_mss(&mut ack, 1400));

        let mut udp_pkt = v4_packet(
            proto::UDP,
            Ipv4Addr::new(10, 201, 0, 6),
            REMOTE,
            &udp(50000, 443),
        );
        assert!(!clamp_tcp_mss(&mut udp_pkt, 1400));
    }

    #[test]
    fn clamping_refuses_a_malformed_option_list() {
        let mut pkt = syn_with_mss(1460);
        pkt[41] = 200; // option length running off the end
        assert!(!clamp_tcp_mss(&mut pkt, 1400));
    }

    #[test]
    fn clamping_never_panics_on_arbitrary_bytes() {
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for len in 0..200usize {
            let mut buf = vec![0u8; len];
            for byte in buf.iter_mut() {
                *byte = (next() & 0xff) as u8;
            }
            let _ = clamp_tcp_mss(&mut buf, 1400);
            if !buf.is_empty() {
                buf[0] = 0x45;
                let _ = clamp_tcp_mss(&mut buf, 1400);
            }
        }
    }

    /// Full TCP checksum over the pseudo-header plus segment, for
    /// cross-checking the incremental update.
    fn tcp_checksum(packet: &[u8]) -> u16 {
        let ihl = ((packet[0] & 0x0f) as usize) * 4;
        let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        let tcp = &packet[ihl..total];
        let mut sum: u32 = 0;
        for chunk in packet[12..20].chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        sum += proto::TCP as u32;
        sum += tcp.len() as u32;
        let mut i = 0;
        while i + 1 < tcp.len() {
            sum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
            i += 2;
        }
        if i < tcp.len() {
            sum += (tcp[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn every_deny_code_has_a_distinct_stable_label() {
        let codes = [
            DenyCode::MalformedPacket,
            DenyCode::SpoofedSource,
            DenyCode::FragmentRefused,
            DenyCode::OversizedPacket,
            DenyCode::AddressFamilyUnassigned,
            DenyCode::MulticastDenied,
            DenyCode::BroadcastDenied,
            DenyCode::ReservedRangeDenied,
            DenyCode::MandatoryDeny,
            DenyCode::PrivateRangeDenied,
            DenyCode::LoopbackDenied,
            DenyCode::LinkLocalDenied,
            DenyCode::ProtocolDenied,
            DenyCode::DestinationNotAdmitted,
            DenyCode::PortNotAdmitted,
            DenyCode::IcmpDenied,
            DenyCode::GatewayServiceDenied,
            DenyCode::FlowTableFull,
            DenyCode::HostSocketUnavailable,
            DenyCode::UnsolicitedInbound,
            DenyCode::WrongDestination,
            DenyCode::PeerDestinationMismatch,
            DenyCode::SessionNotReady,
        ];
        let mut labels: Vec<_> = codes.iter().map(|c| c.as_str()).collect();
        let count = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), count, "deny-code labels must be distinct");
    }
}
