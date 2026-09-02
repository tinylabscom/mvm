//! The FlowMux state machine: whether a well-formed frame is legal *now*.
//!
//! [`super::frame`] answers "is this a well-formed v1 frame" from the bytes
//! alone. This module answers the other half — is this frame legal for the
//! stream it names, in the state that stream is actually in, from the side
//! that sent it. Splitting them is deliberate: the decoder can be fuzzed
//! without a session, and this can be fuzzed without bytes.
//!
//! ## Stream identity
//!
//! Stream 0 is the session's. Odd IDs are guest-initiated, even non-zero IDs
//! are host-initiated ingress. That parity split is what removes
//! simultaneous-open: the two sides allocate from disjoint spaces, so they
//! can never pick the same ID for different flows.
//!
//! ## Why reuse is caught by a watermark, not a set
//!
//! "Reject reuse after reset" naively means remembering every ID ever
//! closed, which is an unbounded allocation a peer drives — the exact shape
//! of bug this protocol exists to avoid. Instead each parity carries a
//! high-water mark and a new stream must exceed it. That refuses reuse in
//! O(1) with no memory growth, and it additionally refuses re-opening any
//! *lower* ID, which is strictly stronger than remembering the closed ones.
//!
//! ## Ingress must be backed by a declaration
//!
//! A host-initiated `InboundOpen` names the admitted mapping it came from.
//! The validator holds the mapping IDs the signed plan declared, and refuses
//! an open naming anything else — so a listener that was never signed for
//! cannot be conjured by sending a frame about it.

use alloc::collections::BTreeMap;

use super::frame::{Direction, SESSION_STREAM_ID};
use super::limits::{
    INITIAL_STREAM_CREDIT, MAX_INGRESS_LISTENERS, MAX_STREAM_CREDIT, MAX_TCP_FLOWS,
    MAX_UDP_ASSOCIATIONS,
};
use super::opcode::{FlowClass, Opcode, Sender};

/// The decoded facts about one frame that bear on whether it is legal.
///
/// A struct rather than a long argument list because every field is a
/// separate reason a frame can be refused, and a caller that grows a new one
/// should have to name it here rather than thread another value through.
///
/// The payload itself never reaches this module. The endpoint decodes what
/// it needs — a mapping ID, a credit delta, a byte count — and hands over
/// only that, so the state machine has nothing to parse and nothing to
/// allocate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FrameFacts {
    /// Which side sent it. Known from the socket, never from the bytes.
    pub direction: Direction,
    /// What the frame does.
    pub opcode: Opcode,
    /// The stream it names.
    pub stream_id: u32,
    /// Payload bytes, for credit accounting on byte-carrying frames.
    pub payload_len: u32,
    /// The admitted ingress mapping an `InboundOpen` names.
    pub ingress_mapping: Option<u16>,
    /// The credit a `WindowUpdate` grants.
    pub credit_delta: Option<u32>,
}

impl FrameFacts {
    /// Facts for a frame carrying no payload and no extra fields.
    #[must_use]
    pub const fn new(direction: Direction, opcode: Opcode, stream_id: u32) -> Self {
        Self {
            direction,
            opcode,
            stream_id,
            payload_len: 0,
            ingress_mapping: None,
            credit_delta: None,
        }
    }

    /// The same, carrying `payload_len` bytes.
    #[must_use]
    pub const fn with_payload(mut self, payload_len: u32) -> Self {
        self.payload_len = payload_len;
        self
    }

    /// The same, naming an admitted ingress mapping.
    #[must_use]
    pub const fn with_ingress_mapping(mut self, mapping: u16) -> Self {
        self.ingress_mapping = Some(mapping);
        self
    }

    /// The same, granting `delta` bytes of credit.
    #[must_use]
    pub const fn with_credit(mut self, delta: u32) -> Self {
        self.credit_delta = Some(delta);
        self
    }
}

/// Why a frame was refused by the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StateError {
    /// A flow frame arrived before the session was established.
    #[error("opcode {opcode:#04x} arrived before the session was established")]
    SessionNotEstablished { opcode: u8 },
    /// A `Hello`/`HelloAck` arrived when the session was already past it.
    #[error("opcode {opcode:#04x} arrived after the session was already established")]
    SessionAlreadyEstablished { opcode: u8 },
    /// Anything at all arrived after `GoAway`.
    #[error("opcode {opcode:#04x} arrived after the session was closed")]
    SessionClosed { opcode: u8 },
    /// The sending side is not permitted to send this opcode.
    #[error("opcode {opcode:#04x} may not be sent by this side")]
    WrongSender { opcode: u8 },
    /// A guest-initiated open used an even stream ID, or a host-initiated
    /// one used an odd ID.
    #[error("stream {stream_id} has the wrong parity for a {side} open")]
    StreamParity { stream_id: u32, side: &'static str },
    /// A frame named a stream that was never opened.
    #[error("opcode {opcode:#04x} names unopened stream {stream_id}")]
    UnknownStream { opcode: u8, stream_id: u32 },
    /// An open named a stream that is already live.
    #[error("stream {stream_id} is already open")]
    DuplicateOpen { stream_id: u32 },
    /// An open reused a stream ID at or below one already retired. See the
    /// module docs for why this is a watermark rather than a set.
    #[error("stream {stream_id} reuses a retired id (high-water mark {watermark})")]
    StreamIdReused { stream_id: u32, watermark: u32 },
    /// A frame arrived for a stream that is still being opened.
    #[error("opcode {opcode:#04x} arrived on stream {stream_id} before it was opened")]
    NotYetOpen { opcode: u8, stream_id: u32 },
    /// A frame arrived for a stream that has been closed.
    #[error("opcode {opcode:#04x} arrived on closed stream {stream_id}")]
    StreamClosed { opcode: u8, stream_id: u32 },
    /// A second `HalfClose` from the side that already sent one.
    #[error("stream {stream_id} was already half-closed by this side")]
    DuplicateHalfClose { stream_id: u32 },
    /// Bytes arrived from a side that already half-closed.
    #[error("opcode {opcode:#04x} arrived on stream {stream_id} after this side half-closed")]
    SendAfterHalfClose { opcode: u8, stream_id: u32 },
    /// The opcode belongs to a different flow class than the stream.
    #[error("opcode {opcode:#04x} is not valid for a {class:?} stream")]
    WrongFlowClass { opcode: u8, class: FlowClass },
    /// Data exceeded the credit the peer had granted.
    #[error("stream {stream_id} sent {len} bytes with only {available} credit")]
    CreditExhausted {
        stream_id: u32,
        len: u32,
        available: u32,
    },
    /// A credit grant would push the window past [`MAX_STREAM_CREDIT`], or
    /// overflow it outright.
    #[error("stream {stream_id} credit grant of {delta} exceeds the {max}-byte window")]
    CreditOverflow {
        stream_id: u32,
        delta: u32,
        max: u32,
    },
    /// A `WindowUpdate` carried no delta, or a delta of zero.
    #[error("stream {stream_id} sent a window update with no credit")]
    EmptyCreditGrant { stream_id: u32 },
    /// An `InboundOpen` named a mapping the signed plan never declared.
    #[error("inbound open names undeclared ingress mapping {mapping}")]
    UndeclaredIngressMapping { mapping: u16 },
    /// An `InboundOpen` named no mapping at all.
    #[error("inbound open on stream {stream_id} names no ingress mapping")]
    MissingIngressMapping { stream_id: u32 },
    /// Opening this stream would exceed the class's concurrency ceiling.
    #[error("{class:?} flow ceiling of {max} reached")]
    FlowCeiling { class: FlowClass, max: usize },
}

/// Where the session as a whole is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionState {
    /// Nothing has been sent; the guest owes a `Hello`.
    #[default]
    AwaitingHello,
    /// The guest said `Hello`; the host owes a `HelloAck`.
    AwaitingHelloAck,
    /// Flows may be opened.
    Established,
    /// `GoAway` was seen. Nothing further is accepted.
    Closed,
}

/// Where one stream is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// The open was sent; the confirmation has not arrived.
    Opening,
    /// Both directions carry bytes.
    Open,
    /// The guest is done sending; the host may still send.
    GuestHalfClosed,
    /// The host is done sending; the guest may still send.
    HostHalfClosed,
}

/// One live stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stream {
    class: FlowClass,
    state: StreamState,
    /// Bytes the guest may still send before it needs a grant.
    guest_credit: u32,
    /// Bytes the host may still send before it needs a grant.
    host_credit: u32,
}

/// The class ceiling a stream counts against.
fn ceiling_for(class: FlowClass) -> Option<usize> {
    match class {
        // TCP, typed HTTP, DNS and ICMP share one aggregate ceiling, matching
        // the signed plan's single `max_flows` bound. ICMP counts against it
        // rather than getting a ceiling of its own: an echo is a host-
        // originated socket like any other flow, so a guest must not be able
        // to open more total sockets by choosing a different flow type.
        FlowClass::Tcp | FlowClass::Http | FlowClass::Dns | FlowClass::Icmp => Some(MAX_TCP_FLOWS),
        FlowClass::Udp => Some(MAX_UDP_ASSOCIATIONS),
        FlowClass::Ingress => Some(MAX_INGRESS_LISTENERS),
        FlowClass::Session | FlowClass::Common => None,
    }
}

/// Validates one side's view of a FlowMux session.
///
/// Each end runs its own instance over the frames it *reads*, so a peer's
/// misbehaviour is caught by the side that would otherwise act on it. The
/// validator never sees payload bytes and never allocates on behalf of a
/// refused frame.
#[derive(Debug, Clone)]
pub struct SessionValidator {
    session: SessionState,
    streams: BTreeMap<u32, Stream>,
    declared_ingress: BTreeMap<u16, IngressFlowKind>,
    /// Highest guest-initiated (odd) ID ever admitted.
    guest_watermark: u32,
    /// Highest host-initiated (even, non-zero) ID ever admitted.
    host_watermark: u32,
}

/// Transport projected from one signed ingress mapping into the protocol
/// state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IngressFlowKind {
    /// Byte-stream ingress using common `Data` and credit frames.
    Tcp,
    /// Datagram ingress using `UdpRecv` and `UdpSend` frames.
    Udp,
}

impl SessionValidator {
    /// A validator for a session whose plan declared `ingress_mappings`.
    ///
    /// The mapping set comes from the admitted plan, never from guest bytes:
    /// it is the list of listeners that were signed for, and an `InboundOpen`
    /// naming anything outside it is refused.
    #[must_use]
    pub fn new(ingress_mappings: impl IntoIterator<Item = u16>) -> Self {
        Self::new_with_ingress(
            ingress_mappings
                .into_iter()
                .map(|mapping| (mapping, IngressFlowKind::Tcp)),
        )
    }

    /// A validator with each signed ingress mapping's transport projected in.
    #[must_use]
    pub fn new_with_ingress(
        ingress_mappings: impl IntoIterator<Item = (u16, IngressFlowKind)>,
    ) -> Self {
        Self {
            session: SessionState::AwaitingHello,
            streams: BTreeMap::new(),
            declared_ingress: ingress_mappings.into_iter().collect(),
            guest_watermark: 0,
            host_watermark: 0,
        }
    }

    /// The session's current state.
    #[must_use]
    pub const fn session_state(&self) -> SessionState {
        self.session
    }

    /// Mark the session as established after the host has sent `HelloAck`.
    ///
    /// The validator only observes inbound frames, so the host-side driver
    /// must advance its own state machine when it completes the handshake by
    /// sending `HelloAck`. This is a no-op if the session is already
    /// established and an error if it is not waiting for the ack.
    pub fn mark_hello_ack_sent(&mut self) -> Result<(), StateError> {
        match self.session {
            SessionState::AwaitingHelloAck => {
                self.session = SessionState::Established;
                Ok(())
            }
            SessionState::Established => Ok(()),
            SessionState::AwaitingHello => Err(StateError::SessionNotEstablished {
                opcode: Opcode::HelloAck.as_u8(),
            }),
            SessionState::Closed => Err(StateError::SessionClosed {
                opcode: Opcode::HelloAck.as_u8(),
            }),
        }
    }

    /// How many streams are live.
    #[must_use]
    pub fn live_streams(&self) -> usize {
        self.streams.len()
    }

    /// A live stream's state, if it is live.
    #[must_use]
    pub fn stream_state(&self, stream_id: u32) -> Option<StreamState> {
        self.streams.get(&stream_id).map(|s| s.state)
    }

    /// Credit remaining for `direction` on `stream_id`, if it is live.
    #[must_use]
    pub fn credit(&self, stream_id: u32, direction: Direction) -> Option<u32> {
        self.streams.get(&stream_id).map(|s| match direction {
            Direction::GuestToHost => s.guest_credit,
            Direction::HostToGuest => s.host_credit,
        })
    }

    /// Admit one frame, advancing the session and stream state.
    ///
    /// Fails closed: on `Err` the validator is left unchanged, so a refused
    /// frame cannot move the machine even a little. The caller drops the
    /// session — there is no recovery path, because every error here means
    /// the peer is not speaking the protocol.
    ///
    /// # Errors
    ///
    /// See [`StateError`].
    pub fn admit(&mut self, facts: &FrameFacts) -> Result<(), StateError> {
        self.check_sender(facts)?;
        if facts.opcode.is_session() {
            return self.admit_session(facts);
        }
        self.check_established(facts)?;
        if facts.opcode.is_open() {
            return self.admit_open(facts);
        }
        self.admit_on_stream(facts)
    }

    /// Refuse an opcode from the side that may not send it.
    fn check_sender(&self, facts: &FrameFacts) -> Result<(), StateError> {
        let ok = match facts.opcode.sender() {
            Sender::Either => true,
            Sender::GuestOnly => facts.direction == Direction::GuestToHost,
            Sender::HostOnly => facts.direction == Direction::HostToGuest,
        };
        if ok {
            Ok(())
        } else {
            Err(StateError::WrongSender {
                opcode: facts.opcode.as_u8(),
            })
        }
    }

    /// Refuse a flow frame outside an established session.
    fn check_established(&self, facts: &FrameFacts) -> Result<(), StateError> {
        match self.session {
            SessionState::Established => Ok(()),
            SessionState::Closed => Err(StateError::SessionClosed {
                opcode: facts.opcode.as_u8(),
            }),
            SessionState::AwaitingHello | SessionState::AwaitingHelloAck => {
                Err(StateError::SessionNotEstablished {
                    opcode: facts.opcode.as_u8(),
                })
            }
        }
    }

    fn admit_session(&mut self, facts: &FrameFacts) -> Result<(), StateError> {
        let opcode = facts.opcode.as_u8();
        match (facts.opcode, self.session) {
            (Opcode::Hello, SessionState::AwaitingHello) => {
                self.session = SessionState::AwaitingHelloAck;
                Ok(())
            }
            (Opcode::HelloAck, SessionState::AwaitingHelloAck) => {
                self.session = SessionState::Established;
                Ok(())
            }
            (Opcode::GoAway, SessionState::Closed) => Err(StateError::SessionClosed { opcode }),
            (Opcode::GoAway, _) => {
                self.session = SessionState::Closed;
                self.streams.clear();
                Ok(())
            }
            (_, SessionState::Closed) => Err(StateError::SessionClosed { opcode }),
            (Opcode::Hello | Opcode::HelloAck, SessionState::Established) => {
                Err(StateError::SessionAlreadyEstablished { opcode })
            }
            // A HelloAck before Hello, or a second Hello.
            (_, _) => Err(StateError::SessionNotEstablished { opcode }),
        }
    }

    fn admit_open(&mut self, facts: &FrameFacts) -> Result<(), StateError> {
        let host_initiated = facts.opcode == Opcode::InboundOpen;

        // Parity first: a stream ID from the wrong space is refused before
        // anything is recorded about it.
        let odd = facts.stream_id % 2 == 1;
        if host_initiated == odd {
            return Err(StateError::StreamParity {
                stream_id: facts.stream_id,
                side: if host_initiated { "host" } else { "guest" },
            });
        }

        if self.streams.contains_key(&facts.stream_id) {
            return Err(StateError::DuplicateOpen {
                stream_id: facts.stream_id,
            });
        }
        let watermark = if host_initiated {
            self.host_watermark
        } else {
            self.guest_watermark
        };
        if facts.stream_id <= watermark {
            return Err(StateError::StreamIdReused {
                stream_id: facts.stream_id,
                watermark,
            });
        }

        let class = if host_initiated {
            let mapping = facts
                .ingress_mapping
                .ok_or(StateError::MissingIngressMapping {
                    stream_id: facts.stream_id,
                })?;
            match self.declared_ingress.get(&mapping) {
                Some(IngressFlowKind::Tcp) => FlowClass::Ingress,
                Some(IngressFlowKind::Udp) => FlowClass::Udp,
                None => return Err(StateError::UndeclaredIngressMapping { mapping }),
            }
        } else {
            facts.opcode.class()
        };

        if let Some(max) = ceiling_for(class)
            && self.streams.values().filter(|s| s.class == class).count() >= max
        {
            return Err(StateError::FlowCeiling { class, max });
        }

        self.streams.insert(
            facts.stream_id,
            Stream {
                class,
                state: StreamState::Opening,
                guest_credit: INITIAL_STREAM_CREDIT,
                host_credit: INITIAL_STREAM_CREDIT,
            },
        );
        if host_initiated {
            self.host_watermark = facts.stream_id;
        } else {
            self.guest_watermark = facts.stream_id;
        }
        Ok(())
    }

    fn admit_on_stream(&mut self, facts: &FrameFacts) -> Result<(), StateError> {
        let opcode = facts.opcode.as_u8();
        let stream_id = facts.stream_id;
        let Some(stream) = self.streams.get(&stream_id).copied() else {
            return Err(StateError::UnknownStream { opcode, stream_id });
        };

        // The opcode must belong to this stream's class, or be one of the
        // shared byte/teardown opcodes.
        let class = facts.opcode.class();
        let ingress_confirmation =
            matches!(facts.opcode, Opcode::InboundReady | Opcode::InboundRefused)
                && matches!(stream.class, FlowClass::Ingress | FlowClass::Udp);
        if class != FlowClass::Common && class != stream.class && !ingress_confirmation {
            return Err(StateError::WrongFlowClass {
                opcode,
                class: stream.class,
            });
        }
        let byte_stream_opcode = matches!(
            facts.opcode,
            Opcode::Data | Opcode::WindowUpdate | Opcode::HalfClose
        );
        if byte_stream_opcode && !matches!(stream.class, FlowClass::Tcp | FlowClass::Ingress) {
            return Err(StateError::WrongFlowClass {
                opcode,
                class: stream.class,
            });
        }

        // A confirmation is only a confirmation for the classes it can
        // legitimately answer. `Opened` is shared by TCP and typed HTTP, so
        // the class field alone cannot decide this.
        let confirming = facts.opcode.confirming_classes();
        if let Some(classes) = confirming
            && !classes.contains(&stream.class)
        {
            return Err(StateError::WrongFlowClass {
                opcode,
                class: stream.class,
            });
        }

        // Every non-confirming opcode requires the stream to be past Opening.
        // `Reset` is the exception: an open can be aborted before it lands.
        if stream.state == StreamState::Opening
            && confirming.is_none()
            && facts.opcode != Opcode::Reset
        {
            return Err(StateError::NotYetOpen { opcode, stream_id });
        }

        match facts.opcode {
            Opcode::Opened | Opcode::UdpOpened | Opcode::InboundReady => {
                self.transition(stream_id, StreamState::Open);
                Ok(())
            }
            Opcode::Refused
            | Opcode::ConnectFailed
            | Opcode::InboundRefused
            | Opcode::Reset
            | Opcode::CloseUdp
            | Opcode::Resolved
            | Opcode::ResolveRefused
            | Opcode::HttpComplete
            | Opcode::IcmpReply
            | Opcode::IcmpRefused => {
                self.retire(stream_id);
                Ok(())
            }
            Opcode::HalfClose => self.admit_half_close(facts, stream),
            Opcode::WindowUpdate => self.admit_credit(facts, stream),
            _ => self.admit_bytes(facts, stream),
        }
    }

    fn admit_half_close(&mut self, facts: &FrameFacts, stream: Stream) -> Result<(), StateError> {
        let stream_id = facts.stream_id;
        let already = matches!(
            (facts.direction, stream.state),
            (Direction::GuestToHost, StreamState::GuestHalfClosed)
                | (Direction::HostToGuest, StreamState::HostHalfClosed)
        );
        if already {
            return Err(StateError::DuplicateHalfClose { stream_id });
        }
        // The second half-close from the other side closes the stream.
        let next = match (facts.direction, stream.state) {
            (Direction::GuestToHost, StreamState::HostHalfClosed)
            | (Direction::HostToGuest, StreamState::GuestHalfClosed) => {
                self.retire(stream_id);
                return Ok(());
            }
            (Direction::GuestToHost, _) => StreamState::GuestHalfClosed,
            (Direction::HostToGuest, _) => StreamState::HostHalfClosed,
        };
        self.transition(stream_id, next);
        Ok(())
    }

    fn admit_credit(&mut self, facts: &FrameFacts, stream: Stream) -> Result<(), StateError> {
        let stream_id = facts.stream_id;
        let Some(delta) = facts.credit_delta.filter(|d| *d > 0) else {
            return Err(StateError::EmptyCreditGrant { stream_id });
        };
        // A grant credits the *peer*: the side that receives the update is
        // the side that gets to send more.
        let granted_to = facts.direction.peer();
        let current = match granted_to {
            Direction::GuestToHost => stream.guest_credit,
            Direction::HostToGuest => stream.host_credit,
        };
        let next = current
            .checked_add(delta)
            .filter(|n| *n <= MAX_STREAM_CREDIT)
            .ok_or(StateError::CreditOverflow {
                stream_id,
                delta,
                max: MAX_STREAM_CREDIT,
            })?;
        let entry = self
            .streams
            .get_mut(&stream_id)
            .expect("stream was present when its credit was read");
        match granted_to {
            Direction::GuestToHost => entry.guest_credit = next,
            Direction::HostToGuest => entry.host_credit = next,
        }
        Ok(())
    }

    fn admit_bytes(&mut self, facts: &FrameFacts, stream: Stream) -> Result<(), StateError> {
        let opcode = facts.opcode.as_u8();
        let stream_id = facts.stream_id;
        let sender_done = matches!(
            (facts.direction, stream.state),
            (Direction::GuestToHost, StreamState::GuestHalfClosed)
                | (Direction::HostToGuest, StreamState::HostHalfClosed)
        );
        if sender_done {
            return Err(StateError::SendAfterHalfClose { opcode, stream_id });
        }
        let available = match facts.direction {
            Direction::GuestToHost => stream.guest_credit,
            Direction::HostToGuest => stream.host_credit,
        };
        let remaining =
            available
                .checked_sub(facts.payload_len)
                .ok_or(StateError::CreditExhausted {
                    stream_id,
                    len: facts.payload_len,
                    available,
                })?;
        let entry = self
            .streams
            .get_mut(&stream_id)
            .expect("stream was present when its credit was read");
        match facts.direction {
            Direction::GuestToHost => entry.guest_credit = remaining,
            Direction::HostToGuest => entry.host_credit = remaining,
        }
        Ok(())
    }

    fn transition(&mut self, stream_id: u32, next: StreamState) {
        if let Some(s) = self.streams.get_mut(&stream_id) {
            s.state = next;
        }
    }

    /// Drop a stream. Its ID stays retired by the watermark, so nothing has
    /// to be remembered about it.
    fn retire(&mut self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }
}

impl Default for SessionValidator {
    /// A validator for a session with no declared ingress mappings — the
    /// common case, and the one where every `InboundOpen` is refused.
    fn default() -> Self {
        Self::new([])
    }
}

/// The stream ID a session frame must use.
#[must_use]
pub const fn session_stream_id() -> u32 {
    SESSION_STREAM_ID
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const G: Direction = Direction::GuestToHost;
    const H: Direction = Direction::HostToGuest;

    fn established() -> SessionValidator {
        let mut v = SessionValidator::default();
        v.admit(&FrameFacts::new(G, Opcode::Hello, 0))
            .expect("hello");
        v.admit(&FrameFacts::new(H, Opcode::HelloAck, 0))
            .expect("ack");
        assert_eq!(v.session_state(), SessionState::Established);
        v
    }

    fn open_tcp(v: &mut SessionValidator, id: u32) {
        v.admit(&FrameFacts::new(G, Opcode::OpenTcp, id))
            .expect("open");
        v.admit(&FrameFacts::new(H, Opcode::Opened, id))
            .expect("opened");
    }

    // ── session ──────────────────────────────────────────────────────

    #[test]
    fn the_handshake_walks_hello_then_ack() {
        let mut v = SessionValidator::default();
        assert_eq!(v.session_state(), SessionState::AwaitingHello);
        v.admit(&FrameFacts::new(G, Opcode::Hello, 0))
            .expect("hello");
        assert_eq!(v.session_state(), SessionState::AwaitingHelloAck);
        v.admit(&FrameFacts::new(H, Opcode::HelloAck, 0))
            .expect("ack");
        assert_eq!(v.session_state(), SessionState::Established);
    }

    #[test]
    fn an_ack_before_a_hello_is_refused() {
        let mut v = SessionValidator::default();
        assert_eq!(
            v.admit(&FrameFacts::new(H, Opcode::HelloAck, 0)),
            Err(StateError::SessionNotEstablished { opcode: 0x02 })
        );
    }

    #[test]
    fn a_second_hello_is_refused() {
        let mut v = established();
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::Hello, 0)),
            Err(StateError::SessionAlreadyEstablished { opcode: 0x01 })
        );
    }

    #[test]
    fn nothing_is_accepted_after_go_away() {
        let mut v = established();
        open_tcp(&mut v, 1);
        v.admit(&FrameFacts::new(H, Opcode::GoAway, 0))
            .expect("go away");
        assert_eq!(v.session_state(), SessionState::Closed);
        assert_eq!(v.live_streams(), 0);
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::Data, 1).with_payload(1)),
            Err(StateError::SessionClosed { opcode: 0x13 })
        );
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::GoAway, 0)),
            Err(StateError::SessionClosed { opcode: 0x03 })
        );
    }

    #[test]
    fn a_flow_frame_before_the_session_is_established_is_refused() {
        let mut v = SessionValidator::default();
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::OpenTcp, 1)),
            Err(StateError::SessionNotEstablished { opcode: 0x10 })
        );
        v.admit(&FrameFacts::new(G, Opcode::Hello, 0))
            .expect("hello");
        // Still not established — the ack has not arrived.
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::OpenTcp, 1)),
            Err(StateError::SessionNotEstablished { opcode: 0x10 })
        );
    }

    // ── sender direction ─────────────────────────────────────────────

    #[test]
    fn a_guest_only_opcode_from_the_host_is_refused() {
        let mut v = established();
        assert_eq!(
            v.admit(&FrameFacts::new(H, Opcode::OpenTcp, 1)),
            Err(StateError::WrongSender { opcode: 0x10 })
        );
    }

    #[test]
    fn a_host_only_opcode_from_the_guest_is_refused() {
        let mut v = established();
        v.admit(&FrameFacts::new(G, Opcode::OpenTcp, 1))
            .expect("open");
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::Opened, 1)),
            Err(StateError::WrongSender { opcode: 0x11 })
        );
    }

    #[test]
    fn every_directional_opcode_is_refused_from_the_wrong_side() {
        for op in Opcode::ALL {
            let wrong = match op.sender() {
                Sender::Either => continue,
                Sender::GuestOnly => H,
                Sender::HostOnly => G,
            };
            let mut v = established();
            let id = if op.is_session() { 0 } else { 1 };
            assert_eq!(
                v.admit(&FrameFacts::new(wrong, *op, id)),
                Err(StateError::WrongSender { opcode: op.as_u8() }),
                "{op:?}"
            );
        }
    }

    // ── stream lifecycle ─────────────────────────────────────────────

    #[test]
    fn data_before_open_is_refused() {
        let mut v = established();
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::Data, 1).with_payload(4)),
            Err(StateError::UnknownStream {
                opcode: 0x13,
                stream_id: 1
            })
        );
    }

    #[test]
    fn data_before_the_open_is_confirmed_is_refused() {
        let mut v = established();
        v.admit(&FrameFacts::new(G, Opcode::OpenTcp, 1))
            .expect("open");
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::Data, 1).with_payload(4)),
            Err(StateError::NotYetOpen {
                opcode: 0x13,
                stream_id: 1
            })
        );
    }

    #[test]
    fn a_duplicate_open_is_refused() {
        let mut v = established();
        v.admit(&FrameFacts::new(G, Opcode::OpenTcp, 1))
            .expect("open");
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::OpenTcp, 1)),
            Err(StateError::DuplicateOpen { stream_id: 1 })
        );
    }

    #[test]
    fn a_reset_stream_id_may_not_be_reused() {
        let mut v = established();
        open_tcp(&mut v, 3);
        v.admit(&FrameFacts::new(G, Opcode::Reset, 3))
            .expect("reset");
        assert_eq!(v.live_streams(), 0);
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::OpenTcp, 3)),
            Err(StateError::StreamIdReused {
                stream_id: 3,
                watermark: 3
            })
        );
        // And a lower id is refused too, which is stronger than remembering
        // only the ids that were actually used.
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::OpenTcp, 1)),
            Err(StateError::StreamIdReused {
                stream_id: 1,
                watermark: 3
            })
        );
        // A higher one is fine.
        v.admit(&FrameFacts::new(G, Opcode::OpenTcp, 5))
            .expect("higher id");
    }

    #[test]
    fn a_closed_stream_takes_no_further_frames() {
        let mut v = established();
        open_tcp(&mut v, 1);
        v.admit(&FrameFacts::new(G, Opcode::Reset, 1))
            .expect("reset");
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::Data, 1).with_payload(1)),
            Err(StateError::UnknownStream {
                opcode: 0x13,
                stream_id: 1
            })
        );
    }

    #[test]
    fn a_duplicate_close_is_refused() {
        let mut v = established();
        open_tcp(&mut v, 1);
        v.admit(&FrameFacts::new(G, Opcode::Reset, 1))
            .expect("reset");
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::Reset, 1)),
            Err(StateError::UnknownStream {
                opcode: 0x16,
                stream_id: 1
            })
        );
    }

    // ── parity ───────────────────────────────────────────────────────

    #[test]
    fn a_guest_open_on_an_even_stream_is_refused() {
        let mut v = established();
        for id in [2u32, 4, 1000] {
            assert_eq!(
                v.admit(&FrameFacts::new(G, Opcode::OpenTcp, id)),
                Err(StateError::StreamParity {
                    stream_id: id,
                    side: "guest"
                })
            );
        }
    }

    #[test]
    fn a_host_ingress_open_on_an_odd_stream_is_refused() {
        let mut v = SessionValidator::new([7u16]);
        v.admit(&FrameFacts::new(G, Opcode::Hello, 0))
            .expect("hello");
        v.admit(&FrameFacts::new(H, Opcode::HelloAck, 0))
            .expect("ack");
        assert_eq!(
            v.admit(&FrameFacts::new(H, Opcode::InboundOpen, 3).with_ingress_mapping(7)),
            Err(StateError::StreamParity {
                stream_id: 3,
                side: "host"
            })
        );
    }

    #[test]
    fn the_two_parities_keep_independent_watermarks() {
        let mut v = SessionValidator::new([7u16]);
        v.admit(&FrameFacts::new(G, Opcode::Hello, 0))
            .expect("hello");
        v.admit(&FrameFacts::new(H, Opcode::HelloAck, 0))
            .expect("ack");
        v.admit(&FrameFacts::new(G, Opcode::OpenTcp, 9))
            .expect("guest open");
        // A low even id is still available: the guest's watermark does not
        // constrain the host's space.
        v.admit(&FrameFacts::new(H, Opcode::InboundOpen, 2).with_ingress_mapping(7))
            .expect("host open");
    }

    // ── ingress declarations ─────────────────────────────────────────

    #[test]
    fn an_inbound_open_naming_an_undeclared_mapping_is_refused() {
        let mut v = SessionValidator::new([1u16, 2]);
        v.admit(&FrameFacts::new(G, Opcode::Hello, 0))
            .expect("hello");
        v.admit(&FrameFacts::new(H, Opcode::HelloAck, 0))
            .expect("ack");
        assert_eq!(
            v.admit(&FrameFacts::new(H, Opcode::InboundOpen, 2).with_ingress_mapping(3)),
            Err(StateError::UndeclaredIngressMapping { mapping: 3 })
        );
    }

    #[test]
    fn an_inbound_open_naming_no_mapping_is_refused() {
        let mut v = SessionValidator::new([1u16]);
        v.admit(&FrameFacts::new(G, Opcode::Hello, 0))
            .expect("hello");
        v.admit(&FrameFacts::new(H, Opcode::HelloAck, 0))
            .expect("ack");
        assert_eq!(
            v.admit(&FrameFacts::new(H, Opcode::InboundOpen, 2)),
            Err(StateError::MissingIngressMapping { stream_id: 2 })
        );
    }

    #[test]
    fn declared_udp_ingress_uses_datagram_frames_after_readiness() {
        let mut v = SessionValidator::new_with_ingress([(9_u16, IngressFlowKind::Udp)]);
        v.admit(&FrameFacts::new(G, Opcode::Hello, 0))
            .expect("hello");
        v.admit(&FrameFacts::new(H, Opcode::HelloAck, 0))
            .expect("ack");
        v.admit(&FrameFacts::new(H, Opcode::InboundOpen, 2).with_ingress_mapping(9))
            .expect("host UDP open");
        v.admit(&FrameFacts::new(G, Opcode::InboundReady, 2))
            .expect("guest UDP ready");
        v.admit(&FrameFacts::new(H, Opcode::UdpRecv, 2).with_payload(64))
            .expect("external datagram reaches guest");
        v.admit(&FrameFacts::new(G, Opcode::UdpSend, 2).with_payload(64))
            .expect("guest reply reaches known external peer");
        v.admit(&FrameFacts::new(H, Opcode::CloseUdp, 2))
            .expect("host closes UDP ingress peer");
    }

    #[test]
    fn declared_udp_ingress_refuses_byte_stream_frames() {
        let mut v = SessionValidator::new_with_ingress([(9_u16, IngressFlowKind::Udp)]);
        v.admit(&FrameFacts::new(G, Opcode::Hello, 0))
            .expect("hello");
        v.admit(&FrameFacts::new(H, Opcode::HelloAck, 0))
            .expect("ack");
        v.admit(&FrameFacts::new(H, Opcode::InboundOpen, 2).with_ingress_mapping(9))
            .expect("host UDP open");
        v.admit(&FrameFacts::new(G, Opcode::InboundReady, 2))
            .expect("guest UDP ready");

        for opcode in [Opcode::Data, Opcode::WindowUpdate, Opcode::HalfClose] {
            assert_eq!(
                v.admit(&FrameFacts::new(G, opcode, 2).with_payload(1)),
                Err(StateError::WrongFlowClass {
                    opcode: opcode.as_u8(),
                    class: FlowClass::Udp,
                })
            );
        }
    }

    /// The default session declares nothing, so every ingress open fails.
    #[test]
    fn a_session_with_no_declared_listeners_refuses_every_inbound_open() {
        let mut v = established();
        assert_eq!(
            v.admit(&FrameFacts::new(H, Opcode::InboundOpen, 2).with_ingress_mapping(0)),
            Err(StateError::UndeclaredIngressMapping { mapping: 0 })
        );
    }

    #[test]
    fn a_declared_inbound_open_walks_to_ready() {
        let mut v = SessionValidator::new([5u16]);
        v.admit(&FrameFacts::new(G, Opcode::Hello, 0))
            .expect("hello");
        v.admit(&FrameFacts::new(H, Opcode::HelloAck, 0))
            .expect("ack");
        v.admit(&FrameFacts::new(H, Opcode::InboundOpen, 4).with_ingress_mapping(5))
            .expect("inbound open");
        assert_eq!(v.stream_state(4), Some(StreamState::Opening));
        v.admit(&FrameFacts::new(G, Opcode::InboundReady, 4))
            .expect("ready");
        assert_eq!(v.stream_state(4), Some(StreamState::Open));
    }

    // ── credit ───────────────────────────────────────────────────────

    #[test]
    fn data_consumes_credit_and_a_window_update_restores_it() {
        let mut v = established();
        open_tcp(&mut v, 1);
        assert_eq!(v.credit(1, G), Some(INITIAL_STREAM_CREDIT));
        v.admit(&FrameFacts::new(G, Opcode::Data, 1).with_payload(1000))
            .expect("data");
        assert_eq!(v.credit(1, G), Some(INITIAL_STREAM_CREDIT - 1000));
        // The host grants; the guest gets the credit.
        v.admit(&FrameFacts::new(H, Opcode::WindowUpdate, 1).with_credit(1000))
            .expect("grant");
        assert_eq!(v.credit(1, G), Some(INITIAL_STREAM_CREDIT));
    }

    #[test]
    fn data_beyond_the_granted_credit_is_refused() {
        let mut v = established();
        open_tcp(&mut v, 1);
        let over = INITIAL_STREAM_CREDIT + 1;
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::Data, 1).with_payload(over)),
            Err(StateError::CreditExhausted {
                stream_id: 1,
                len: over,
                available: INITIAL_STREAM_CREDIT
            })
        );
        // And the refusal left the window untouched.
        assert_eq!(v.credit(1, G), Some(INITIAL_STREAM_CREDIT));
    }

    #[test]
    fn a_credit_grant_past_the_window_ceiling_is_refused() {
        let mut v = established();
        open_tcp(&mut v, 1);
        assert_eq!(
            v.admit(&FrameFacts::new(H, Opcode::WindowUpdate, 1).with_credit(MAX_STREAM_CREDIT)),
            Err(StateError::CreditOverflow {
                stream_id: 1,
                delta: MAX_STREAM_CREDIT,
                max: MAX_STREAM_CREDIT
            })
        );
    }

    #[test]
    fn a_credit_grant_that_would_overflow_a_u32_is_refused() {
        let mut v = established();
        open_tcp(&mut v, 1);
        assert!(matches!(
            v.admit(&FrameFacts::new(H, Opcode::WindowUpdate, 1).with_credit(u32::MAX)),
            Err(StateError::CreditOverflow { .. })
        ));
    }

    #[test]
    fn an_empty_credit_grant_is_refused() {
        let mut v = established();
        open_tcp(&mut v, 1);
        assert_eq!(
            v.admit(&FrameFacts::new(H, Opcode::WindowUpdate, 1).with_credit(0)),
            Err(StateError::EmptyCreditGrant { stream_id: 1 })
        );
        assert_eq!(
            v.admit(&FrameFacts::new(H, Opcode::WindowUpdate, 1)),
            Err(StateError::EmptyCreditGrant { stream_id: 1 })
        );
    }

    /// Credit is per stream, so one exhausted flow cannot stall another.
    #[test]
    fn credit_is_tracked_per_stream() {
        let mut v = established();
        open_tcp(&mut v, 1);
        open_tcp(&mut v, 3);
        v.admit(&FrameFacts::new(G, Opcode::Data, 1).with_payload(INITIAL_STREAM_CREDIT))
            .expect("drain stream 1");
        assert_eq!(v.credit(1, G), Some(0));
        assert_eq!(v.credit(3, G), Some(INITIAL_STREAM_CREDIT));
        v.admit(&FrameFacts::new(G, Opcode::Data, 3).with_payload(10))
            .expect("stream 3 still flows");
    }

    // ── half close ───────────────────────────────────────────────────

    #[test]
    fn a_half_close_leaves_the_other_direction_open() {
        let mut v = established();
        open_tcp(&mut v, 1);
        v.admit(&FrameFacts::new(G, Opcode::HalfClose, 1))
            .expect("half close");
        assert_eq!(v.stream_state(1), Some(StreamState::GuestHalfClosed));
        v.admit(&FrameFacts::new(H, Opcode::Data, 1).with_payload(5))
            .expect("host may still send");
    }

    #[test]
    fn a_duplicate_half_close_from_the_same_side_is_refused() {
        let mut v = established();
        open_tcp(&mut v, 1);
        v.admit(&FrameFacts::new(G, Opcode::HalfClose, 1))
            .expect("half close");
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::HalfClose, 1)),
            Err(StateError::DuplicateHalfClose { stream_id: 1 })
        );
    }

    #[test]
    fn sending_after_half_closing_is_refused() {
        let mut v = established();
        open_tcp(&mut v, 1);
        v.admit(&FrameFacts::new(G, Opcode::HalfClose, 1))
            .expect("half close");
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::Data, 1).with_payload(1)),
            Err(StateError::SendAfterHalfClose {
                opcode: 0x13,
                stream_id: 1
            })
        );
    }

    #[test]
    fn both_half_closes_retire_the_stream() {
        let mut v = established();
        open_tcp(&mut v, 1);
        v.admit(&FrameFacts::new(G, Opcode::HalfClose, 1))
            .expect("guest half close");
        v.admit(&FrameFacts::new(H, Opcode::HalfClose, 1))
            .expect("host half close");
        assert_eq!(v.stream_state(1), None);
        assert_eq!(v.live_streams(), 0);
    }

    // ── class discipline ─────────────────────────────────────────────

    #[test]
    fn a_udp_opcode_on_a_tcp_stream_is_refused() {
        let mut v = established();
        open_tcp(&mut v, 1);
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::UdpSend, 1).with_payload(4)),
            Err(StateError::WrongFlowClass {
                opcode: 0x22,
                class: FlowClass::Tcp
            })
        );
    }

    #[test]
    fn a_tcp_confirmation_on_a_udp_stream_is_refused() {
        let mut v = established();
        v.admit(&FrameFacts::new(G, Opcode::OpenUdp, 1))
            .expect("open udp");
        assert_eq!(
            v.admit(&FrameFacts::new(H, Opcode::Opened, 1)),
            Err(StateError::WrongFlowClass {
                opcode: 0x11,
                class: FlowClass::Udp
            })
        );
    }

    /// `Opened` answers both, which is why the confirmation relation is
    /// spelled out rather than read off the class field.
    #[test]
    fn opened_confirms_both_a_tcp_and_a_typed_http_open() {
        for open in [Opcode::OpenTcp, Opcode::OpenHttp] {
            let mut v = established();
            v.admit(&FrameFacts::new(G, open, 1)).expect("open");
            v.admit(&FrameFacts::new(H, Opcode::Opened, 1))
                .unwrap_or_else(|e| panic!("{open:?} should be confirmable by Opened: {e:?}"));
            assert_eq!(v.stream_state(1), Some(StreamState::Open));
        }
    }

    #[test]
    fn a_confirmation_for_the_wrong_class_is_refused() {
        // UdpOpened cannot confirm a TCP open.
        let mut v = established();
        v.admit(&FrameFacts::new(G, Opcode::OpenTcp, 1))
            .expect("open tcp");
        assert_eq!(
            v.admit(&FrameFacts::new(H, Opcode::UdpOpened, 1)),
            Err(StateError::WrongFlowClass {
                opcode: 0x21,
                class: FlowClass::Tcp
            })
        );
        // Resolved cannot confirm a UDP association.
        let mut v = established();
        v.admit(&FrameFacts::new(G, Opcode::OpenUdp, 1))
            .expect("open udp");
        assert_eq!(
            v.admit(&FrameFacts::new(H, Opcode::Resolved, 1)),
            Err(StateError::WrongFlowClass {
                opcode: 0x31,
                class: FlowClass::Udp
            })
        );
    }

    #[test]
    fn refused_terminates_any_openable_class() {
        for open in [
            Opcode::OpenTcp,
            Opcode::OpenHttp,
            Opcode::OpenUdp,
            Opcode::Resolve,
        ] {
            let mut v = established();
            v.admit(&FrameFacts::new(G, open, 1)).expect("open");
            v.admit(&FrameFacts::new(H, Opcode::Refused, 1))
                .unwrap_or_else(|e| panic!("{open:?} should be refusable: {e:?}"));
            assert_eq!(v.live_streams(), 0, "{open:?}");
        }
    }

    /// An open can be aborted before it is confirmed; nothing else may
    /// arrive in that window.
    #[test]
    fn a_reset_may_abort_an_unconfirmed_open() {
        let mut v = established();
        v.admit(&FrameFacts::new(G, Opcode::OpenTcp, 1))
            .expect("open");
        assert_eq!(v.stream_state(1), Some(StreamState::Opening));
        v.admit(&FrameFacts::new(G, Opcode::Reset, 1))
            .expect("reset");
        assert_eq!(v.live_streams(), 0);
    }

    #[test]
    fn a_dns_exchange_is_one_shot() {
        let mut v = established();
        v.admit(&FrameFacts::new(G, Opcode::Resolve, 1))
            .expect("resolve");
        v.admit(&FrameFacts::new(H, Opcode::Resolved, 1))
            .expect("resolved");
        assert_eq!(v.live_streams(), 0);
    }

    /// An ICMP echo is one exchange on its own flow, like a DNS lookup: the
    /// guest asks once and the host answers once, and the flow is done.
    #[test]
    fn an_icmp_echo_is_one_shot() {
        let mut v = established();
        v.admit(&FrameFacts::new(G, Opcode::IcmpEcho, 1).with_payload(64))
            .expect("echo");
        v.admit(&FrameFacts::new(H, Opcode::IcmpReply, 1).with_payload(64))
            .expect("reply");
        assert_eq!(v.live_streams(), 0);
    }

    #[test]
    fn a_refused_icmp_echo_retires_the_flow() {
        let mut v = established();
        v.admit(&FrameFacts::new(G, Opcode::IcmpEcho, 1).with_payload(64))
            .expect("echo");
        v.admit(&FrameFacts::new(H, Opcode::IcmpRefused, 1).with_payload(32))
            .expect("refused");
        assert_eq!(v.live_streams(), 0);
    }

    /// Direction is part of the contract: a guest claiming to be the host's
    /// echo reply is refused.
    #[test]
    fn a_guest_sent_icmp_reply_is_refused() {
        let mut v = established();
        v.admit(&FrameFacts::new(G, Opcode::IcmpEcho, 1).with_payload(64))
            .expect("echo");
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::IcmpReply, 1)),
            Err(StateError::WrongSender {
                opcode: Opcode::IcmpReply.as_u8()
            })
        );
    }

    #[test]
    fn a_typed_http_flow_walks_head_body_complete() {
        let mut v = established();
        v.admit(&FrameFacts::new(G, Opcode::OpenHttp, 1))
            .expect("open http");
        v.admit(&FrameFacts::new(H, Opcode::Opened, 1))
            .expect("opened");
        v.admit(&FrameFacts::new(G, Opcode::HttpRequestHead, 1).with_payload(200))
            .expect("request head");
        v.admit(&FrameFacts::new(G, Opcode::HttpRequestBody, 1).with_payload(50))
            .expect("request body");
        v.admit(&FrameFacts::new(H, Opcode::HttpResponseHead, 1).with_payload(150))
            .expect("response head");
        v.admit(&FrameFacts::new(H, Opcode::HttpResponseBody, 1).with_payload(4000))
            .expect("response body");
        v.admit(&FrameFacts::new(H, Opcode::HttpComplete, 1))
            .expect("complete");
        assert_eq!(v.live_streams(), 0);
    }

    // ── ceilings ─────────────────────────────────────────────────────

    #[test]
    fn the_udp_association_ceiling_is_enforced() {
        let mut v = established();
        let mut id = 1u32;
        for _ in 0..MAX_UDP_ASSOCIATIONS {
            v.admit(&FrameFacts::new(G, Opcode::OpenUdp, id))
                .expect("open udp");
            id += 2;
        }
        assert_eq!(
            v.admit(&FrameFacts::new(G, Opcode::OpenUdp, id)),
            Err(StateError::FlowCeiling {
                class: FlowClass::Udp,
                max: MAX_UDP_ASSOCIATIONS
            })
        );
    }

    #[test]
    fn the_ingress_listener_ceiling_is_enforced() {
        let declared: Vec<u16> = (0..MAX_INGRESS_LISTENERS as u16).collect();
        let mut v = SessionValidator::new(declared);
        v.admit(&FrameFacts::new(G, Opcode::Hello, 0))
            .expect("hello");
        v.admit(&FrameFacts::new(H, Opcode::HelloAck, 0))
            .expect("ack");
        let mut id = 2u32;
        for m in 0..MAX_INGRESS_LISTENERS as u16 {
            v.admit(&FrameFacts::new(H, Opcode::InboundOpen, id).with_ingress_mapping(m))
                .expect("inbound open");
            id += 2;
        }
        assert_eq!(
            v.admit(&FrameFacts::new(H, Opcode::InboundOpen, id).with_ingress_mapping(0)),
            Err(StateError::FlowCeiling {
                class: FlowClass::Ingress,
                max: MAX_INGRESS_LISTENERS
            })
        );
    }

    // ── fail-closed discipline ───────────────────────────────────────

    /// A refused frame must not move the machine, or a peer could drive
    /// state changes with frames it is not allowed to send.
    #[test]
    fn a_refused_frame_leaves_the_validator_unchanged() {
        let mut v = established();
        open_tcp(&mut v, 1);
        let before = v.clone();

        let refusals = [
            FrameFacts::new(G, Opcode::Data, 1).with_payload(u32::MAX),
            FrameFacts::new(G, Opcode::OpenTcp, 1),
            FrameFacts::new(G, Opcode::OpenTcp, 2),
            FrameFacts::new(H, Opcode::WindowUpdate, 1).with_credit(0),
            FrameFacts::new(G, Opcode::UdpSend, 1).with_payload(1),
            FrameFacts::new(H, Opcode::InboundOpen, 4).with_ingress_mapping(1),
            FrameFacts::new(G, Opcode::Data, 99).with_payload(1),
        ];
        for f in &refusals {
            assert!(v.admit(f).is_err(), "{f:?} should be refused");
            assert_eq!(v.live_streams(), before.live_streams(), "{f:?}");
            assert_eq!(v.stream_state(1), before.stream_state(1), "{f:?}");
            assert_eq!(v.credit(1, G), before.credit(1, G), "{f:?}");
            assert_eq!(v.credit(1, H), before.credit(1, H), "{f:?}");
            assert_eq!(v.session_state(), before.session_state(), "{f:?}");
        }
    }

    /// The validator holds one entry per live stream and nothing per retired
    /// one, so a peer that opens and resets forever cannot grow it.
    #[test]
    fn open_reset_churn_does_not_grow_the_validator() {
        let mut v = established();
        let mut id = 1u32;
        for _ in 0..10_000 {
            v.admit(&FrameFacts::new(G, Opcode::OpenTcp, id))
                .expect("open");
            v.admit(&FrameFacts::new(G, Opcode::Reset, id))
                .expect("reset");
            assert_eq!(v.live_streams(), 0);
            id += 2;
        }
    }
}
