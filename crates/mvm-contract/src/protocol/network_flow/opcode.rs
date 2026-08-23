//! FlowMux opcodes and the classes they group into.
//!
//! Anything not listed is rejected; there is no "unknown, pass through"
//! path. The numbering is grouped by class with gaps between groups so that
//! extending a class does not renumber the others, and so a decode failure
//! reads as "which class was this pretending to be".

/// A frame's operation. Discriminants are wire-stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum Opcode {
    // ── session (stream 0) ───────────────────────────────────────────
    /// guest→host: opens the multiplexed session and proposes features.
    Hello = 0x01,
    /// host→guest: the session is authenticated and open.
    HelloAck = 0x02,
    /// both: orderly session teardown with a reason.
    GoAway = 0x03,

    // ── TCP ──────────────────────────────────────────────────────────
    /// guest→host: open a TCP flow to a named destination.
    OpenTcp = 0x10,
    /// host→guest: the host connected; bytes may flow.
    Opened = 0x11,
    /// host→guest: the open was refused, with a typed reason.
    Refused = 0x12,
    /// both: stream payload bytes.
    Data = 0x13,
    /// both: grant the peer more send credit on this stream.
    WindowUpdate = 0x14,
    /// both: this side is done sending; the other direction stays open.
    HalfClose = 0x15,
    /// both: abortive teardown.
    Reset = 0x16,

    // ── UDP ──────────────────────────────────────────────────────────
    /// guest→host: open a UDP association.
    OpenUdp = 0x20,
    /// host→guest: the association is live.
    UdpOpened = 0x21,
    /// guest→host: one datagram to a destination.
    UdpSend = 0x22,
    /// host→guest: one datagram from a peer.
    UdpRecv = 0x23,
    /// both: tear the association down.
    CloseUdp = 0x24,

    // ── DNS ──────────────────────────────────────────────────────────
    /// guest→host: resolve a name.
    Resolve = 0x30,
    /// host→guest: the pinned answer.
    Resolved = 0x31,
    /// host→guest: resolution refused by policy.
    ResolveRefused = 0x32,

    // ── ingress (host-initiated) ─────────────────────────────────────
    /// host→guest: a declared listener accepted a connection.
    InboundOpen = 0x40,
    /// guest→host: the guest connected to its declared loopback target.
    InboundReady = 0x41,
    /// guest→host: the guest could not accept it.
    InboundRefused = 0x42,

    // ── typed transforms ─────────────────────────────────────────────
    /// guest→host: open a typed HTTP flow that may be transformed.
    OpenHttp = 0x50,
    /// guest→host: the request head, whole, in one frame.
    HttpRequestHead = 0x51,
    /// guest→host: a bounded chunk of request body.
    HttpRequestBody = 0x52,
    /// host→guest: the response head, whole, in one frame.
    HttpResponseHead = 0x53,
    /// host→guest: a bounded chunk of response body.
    HttpResponseBody = 0x54,
    /// host→guest: the exchange finished cleanly.
    HttpComplete = 0x55,

    // ── ICMP echo ────────────────────────────────────────────────────
    /// guest→host: one echo request to a destination.
    IcmpEcho = 0x60,
    /// host→guest: the matching echo reply.
    IcmpReply = 0x61,
    /// host→guest: the echo was refused by policy.
    IcmpRefused = 0x62,
}

/// What kind of flow an opcode belongs to. Used by the state machine to
/// refuse a frame that is well-formed but wrong for the stream it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlowClass {
    /// Session-level, carried on stream 0.
    Session,
    /// A TCP byte flow.
    Tcp,
    /// A UDP association.
    Udp,
    /// A one-shot DNS exchange.
    Dns,
    /// A host-initiated ingress connection.
    Ingress,
    /// A typed HTTP flow eligible for transformation.
    Http,
    /// A one-shot ICMP echo exchange. Mediated like every other flow: the
    /// host originates the socket, so the guest never holds a raw one.
    Icmp,
    /// Shared by every byte-carrying flow: `Data`, credit, and teardown.
    Common,
}

/// Which side may legitimately send an opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sender {
    /// Only the guest may send it.
    GuestOnly,
    /// Only the host may send it.
    HostOnly,
    /// Either side may send it.
    Either,
}

impl Opcode {
    /// Wire discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse a wire discriminant, or `None` for an unknown opcode.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => Self::Hello,
            0x02 => Self::HelloAck,
            0x03 => Self::GoAway,
            0x10 => Self::OpenTcp,
            0x11 => Self::Opened,
            0x12 => Self::Refused,
            0x13 => Self::Data,
            0x14 => Self::WindowUpdate,
            0x15 => Self::HalfClose,
            0x16 => Self::Reset,
            0x20 => Self::OpenUdp,
            0x21 => Self::UdpOpened,
            0x22 => Self::UdpSend,
            0x23 => Self::UdpRecv,
            0x24 => Self::CloseUdp,
            0x30 => Self::Resolve,
            0x31 => Self::Resolved,
            0x32 => Self::ResolveRefused,
            0x40 => Self::InboundOpen,
            0x41 => Self::InboundReady,
            0x42 => Self::InboundRefused,
            0x50 => Self::OpenHttp,
            0x51 => Self::HttpRequestHead,
            0x52 => Self::HttpRequestBody,
            0x53 => Self::HttpResponseHead,
            0x54 => Self::HttpResponseBody,
            0x55 => Self::HttpComplete,
            0x60 => Self::IcmpEcho,
            0x61 => Self::IcmpReply,
            0x62 => Self::IcmpRefused,
            _ => return None,
        })
    }

    /// Every opcode version 1 defines, in wire order. The single source the
    /// exhaustiveness tests and the fuzz seed corpus both read.
    pub const ALL: &'static [Self] = &[
        Self::Hello,
        Self::HelloAck,
        Self::GoAway,
        Self::OpenTcp,
        Self::Opened,
        Self::Refused,
        Self::Data,
        Self::WindowUpdate,
        Self::HalfClose,
        Self::Reset,
        Self::OpenUdp,
        Self::UdpOpened,
        Self::UdpSend,
        Self::UdpRecv,
        Self::CloseUdp,
        Self::Resolve,
        Self::Resolved,
        Self::ResolveRefused,
        Self::InboundOpen,
        Self::InboundReady,
        Self::InboundRefused,
        Self::OpenHttp,
        Self::HttpRequestHead,
        Self::HttpRequestBody,
        Self::HttpResponseHead,
        Self::HttpResponseBody,
        Self::HttpComplete,
        Self::IcmpEcho,
        Self::IcmpReply,
        Self::IcmpRefused,
    ];

    /// The class this opcode belongs to.
    #[must_use]
    pub const fn class(self) -> FlowClass {
        match self {
            Self::Hello | Self::HelloAck | Self::GoAway => FlowClass::Session,
            Self::OpenTcp => FlowClass::Tcp,
            Self::OpenUdp | Self::UdpOpened | Self::UdpSend | Self::UdpRecv | Self::CloseUdp => {
                FlowClass::Udp
            }
            Self::Resolve | Self::Resolved | Self::ResolveRefused => FlowClass::Dns,
            Self::InboundOpen | Self::InboundReady | Self::InboundRefused => FlowClass::Ingress,
            Self::OpenHttp
            | Self::HttpRequestHead
            | Self::HttpRequestBody
            | Self::HttpResponseHead
            | Self::HttpResponseBody
            | Self::HttpComplete => FlowClass::Http,
            Self::IcmpEcho | Self::IcmpReply | Self::IcmpRefused => FlowClass::Icmp,
            Self::Opened
            | Self::Refused
            | Self::Data
            | Self::WindowUpdate
            | Self::HalfClose
            | Self::Reset => FlowClass::Common,
        }
    }

    /// The flow classes this opcode may confirm an open for, or `None` if it
    /// is not a confirmation at all.
    ///
    /// `Opened` and `Refused` are shared: a TCP open and a typed-HTTP open
    /// are both answered by the same pair, because from the transport's point
    /// of view they are the same act — the host connected, or it did not.
    /// That sharing is exactly why the class field alone cannot decide
    /// whether a confirmation belongs on a stream, and why this relation is
    /// spelled out rather than inferred.
    #[must_use]
    pub const fn confirming_classes(self) -> Option<&'static [FlowClass]> {
        Some(match self {
            Self::Opened => &[FlowClass::Tcp, FlowClass::Http],
            Self::Refused => &[
                FlowClass::Tcp,
                FlowClass::Http,
                FlowClass::Udp,
                FlowClass::Dns,
            ],
            Self::UdpOpened => &[FlowClass::Udp],
            Self::Resolved | Self::ResolveRefused => &[FlowClass::Dns],
            // Like a DNS answer: the reply both confirms the one-shot flow and
            // ends it, so it must be admitted while the stream is still
            // Opening rather than requiring a separate confirmation first.
            Self::IcmpReply | Self::IcmpRefused => &[FlowClass::Icmp],
            Self::InboundReady | Self::InboundRefused => &[FlowClass::Ingress, FlowClass::Udp],
            _ => return None,
        })
    }

    /// Whether this opcode opens a stream.
    #[must_use]
    pub const fn is_open(self) -> bool {
        matches!(
            self,
            Self::OpenTcp
                | Self::OpenUdp
                | Self::Resolve
                | Self::InboundOpen
                | Self::OpenHttp
                | Self::IcmpEcho
        )
    }

    /// Whether this opcode terminates a stream in one step.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Reset
                | Self::Refused
                | Self::CloseUdp
                | Self::Resolved
                | Self::ResolveRefused
                | Self::InboundRefused
                | Self::HttpComplete
                | Self::IcmpReply
                | Self::IcmpRefused
        )
    }

    /// Whether this opcode rides on stream 0 rather than a flow.
    #[must_use]
    pub const fn is_session(self) -> bool {
        matches!(self.class(), FlowClass::Session)
    }

    /// Which side may send it.
    ///
    /// Direction is part of the contract, not a convention: an `Opened` from
    /// a guest would be the guest telling the host that the host connected.
    #[must_use]
    pub const fn sender(self) -> Sender {
        match self {
            Self::Hello
            | Self::OpenTcp
            | Self::OpenUdp
            | Self::UdpSend
            | Self::Resolve
            | Self::InboundReady
            | Self::InboundRefused
            | Self::OpenHttp
            | Self::HttpRequestHead
            | Self::HttpRequestBody
            | Self::IcmpEcho => Sender::GuestOnly,
            Self::HelloAck
            | Self::Opened
            | Self::Refused
            | Self::UdpOpened
            | Self::UdpRecv
            | Self::Resolved
            | Self::ResolveRefused
            | Self::InboundOpen
            | Self::HttpResponseHead
            | Self::HttpResponseBody
            | Self::HttpComplete
            | Self::IcmpReply
            | Self::IcmpRefused => Sender::HostOnly,
            Self::GoAway
            | Self::Data
            | Self::WindowUpdate
            | Self::HalfClose
            | Self::Reset
            | Self::CloseUdp => Sender::Either,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    fn every_opcode_round_trips_through_its_discriminant() {
        for op in Opcode::ALL {
            assert_eq!(Opcode::from_u8(op.as_u8()), Some(*op), "{op:?}");
        }
    }

    /// `ALL` is what the tests and the fuzz corpus enumerate, so a new
    /// opcode that is not listed there is invisible to both.
    #[test]
    fn all_lists_every_decodable_discriminant() {
        let listed: BTreeSet<u8> = Opcode::ALL.iter().map(|o| o.as_u8()).collect();
        let decodable: BTreeSet<u8> = (0u8..=255)
            .filter(|v| Opcode::from_u8(*v).is_some())
            .collect();
        assert_eq!(listed, decodable);
    }

    #[test]
    fn icmp_is_a_guest_request_answered_only_by_the_host() {
        // The guest asks; the host originates the socket and answers. A guest
        // that could send a reply or a refusal would be speaking for the host.
        assert_eq!(Opcode::IcmpEcho.sender(), Sender::GuestOnly);
        assert_eq!(Opcode::IcmpReply.sender(), Sender::HostOnly);
        assert_eq!(Opcode::IcmpRefused.sender(), Sender::HostOnly);
    }

    #[test]
    fn icmp_opcodes_share_one_flow_class() {
        for op in [Opcode::IcmpEcho, Opcode::IcmpReply, Opcode::IcmpRefused] {
            assert_eq!(op.class(), FlowClass::Icmp, "{op:?}");
        }
    }

    #[test]
    fn icmp_discriminants_are_the_bytes_the_wire_carries() {
        // Pinned rather than derived: these are a wire contract, so a
        // reordering of the enum must fail here instead of silently changing
        // what a peer sees.
        assert_eq!(Opcode::IcmpEcho.as_u8(), 0x60);
        assert_eq!(Opcode::IcmpReply.as_u8(), 0x61);
        assert_eq!(Opcode::IcmpRefused.as_u8(), 0x62);
        assert_eq!(Opcode::from_u8(0x60), Some(Opcode::IcmpEcho));
        assert_eq!(Opcode::from_u8(0x61), Some(Opcode::IcmpReply));
        assert_eq!(Opcode::from_u8(0x62), Some(Opcode::IcmpRefused));
    }

    #[test]
    fn all_has_no_duplicate_discriminants() {
        let unique: BTreeSet<u8> = Opcode::ALL.iter().map(|o| o.as_u8()).collect();
        assert_eq!(unique.len(), Opcode::ALL.len());
    }

    #[test]
    fn unknown_discriminants_are_rejected_rather_than_passed_through() {
        for v in [0x00u8, 0x04, 0x0f, 0x17, 0x25, 0x33, 0x43, 0x56, 0x7f, 0xff] {
            assert_eq!(Opcode::from_u8(v), None, "{v:#04x} should be unknown");
        }
    }

    #[test]
    fn only_session_opcodes_are_session_opcodes() {
        for op in Opcode::ALL {
            assert_eq!(op.is_session(), op.class() == FlowClass::Session, "{op:?}");
        }
    }

    #[test]
    fn every_open_opcode_names_a_flow_class_that_is_not_session_or_common() {
        for op in Opcode::ALL.iter().filter(|o| o.is_open()) {
            assert!(
                !matches!(op.class(), FlowClass::Session | FlowClass::Common),
                "{op:?} opens a stream but has no flow class"
            );
        }
    }

    /// An opcode that both opens and terminates would make the state
    /// machine's transition table ambiguous.
    #[test]
    fn no_opcode_both_opens_and_terminates() {
        for op in Opcode::ALL {
            assert!(!(op.is_open() && op.is_terminal()), "{op:?}");
        }
    }

    #[test]
    fn the_directional_opcodes_are_not_sendable_by_both_sides() {
        assert_eq!(Opcode::Opened.sender(), Sender::HostOnly);
        assert_eq!(Opcode::OpenTcp.sender(), Sender::GuestOnly);
        assert_eq!(Opcode::InboundOpen.sender(), Sender::HostOnly);
        assert_eq!(Opcode::InboundReady.sender(), Sender::GuestOnly);
        assert_eq!(Opcode::Data.sender(), Sender::Either);
    }
}
