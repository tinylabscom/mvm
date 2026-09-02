//! FlowMux — the one wire contract for workload networking.
//!
//! Guest and host share this module so there is exactly one definition of
//! what a frame is. It is `no_std + alloc` and `forbid(unsafe_code)` like
//! the rest of the crate, because the guest side of it links into the
//! sealed agent.
//!
//! Three pieces, deliberately separable:
//!
//! - [`limits`] — the ceilings a hostile peer cannot raise. Consts, not
//!   negotiated parameters.
//! - [`frame`] — the fixed-layout binary header and its state-independent
//!   decoder. Answers "is this a well-formed v1 frame" from bytes alone.
//! - [`state`] — the session and per-stream machine. Answers "is this frame
//!   legal right now, from this side".
//!
//! The split is what makes each half testable and fuzzable on its own: the
//! decoder needs no session, and the state machine needs no bytes. It is
//! also the honest division of labour — a frame can be perfectly well-formed
//! and still be an attack, and conflating the two checks is how one of them
//! ends up not really running.
//!
//! Everything here is transport-independent. It says nothing about vsock,
//! about who authenticated the session, or about what a payload means; those
//! belong to the endpoint that carries it.

pub mod frame;
pub mod hello;
pub mod limits;
pub mod opcode;
pub mod state;

/// The vsock port a workload's FlowMux session is carried on.
///
/// Lives here rather than in `mvm-net` because both ends need it and the
/// guest cannot reach `mvm-net`: `mvm-agentd` links the sealed agent and
/// depends only on this crate. `mvm_net::GuestService::NetworkFlow` maps to
/// this constant, so host and guest name one value instead of two literals
/// that can drift — the same arrangement `l3::L3_CONTROL_PORT` already uses.
pub const NETWORK_FLOW_PORT: u32 = 5253;

pub use frame::{
    Direction, FrameError, FrameHeader, MAGIC, ParsedFrame, SESSION_STREAM_ID, decode, encode,
    encode_into, peek_frame_len,
};
pub use limits::{
    HEADER_LEN, INITIAL_STREAM_CREDIT, LENGTH_PREFIX_LEN, MAX_DNS_NAME_LEN, MAX_FLOW_CREDIT_BYTES,
    MAX_FRAME_LEN, MAX_HTTP_HEAD_LEN, MAX_INGRESS_LISTENERS, MAX_PAYLOAD_LEN, MAX_STREAM_CREDIT,
    MAX_TCP_FLOWS, MAX_UDP_ASSOCIATIONS, MAX_UDP_DATAGRAM_LEN, MAX_WIRE_LEN, PROTOCOL_VERSION,
    UDP_ADDR_PREFIX_LEN,
};
pub use opcode::{FlowClass, Opcode, Sender};
pub use state::{
    FrameFacts, IngressFlowKind, SessionState, SessionValidator, StateError, StreamState,
};

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// The two halves compose: bytes off the wire produce facts the state
    /// machine can rule on, with nothing in between that has to interpret a
    /// payload.
    #[test]
    fn a_decoded_frame_drives_the_state_machine() {
        let mut wire: Vec<u8> = Vec::new();
        encode_into(&mut wire, Opcode::Hello, 0, b"").expect("hello");
        encode_into(&mut wire, Opcode::OpenTcp, 1, b"example.com:443").expect("open");
        encode_into(&mut wire, Opcode::Data, 1, b"GET / HTTP/1.1\r\n\r\n").expect("data");

        let mut guest_side = SessionValidator::default();
        // The host acks between the guest's frames; it is not on this wire.
        let mut rest = &wire[..];

        let hello = decode(rest).expect("decode hello");
        guest_side
            .admit(&FrameFacts::new(
                Direction::GuestToHost,
                hello.header.opcode,
                hello.header.stream_id,
            ))
            .expect("hello admitted");
        rest = &rest[hello.consumed..];

        guest_side
            .admit(&FrameFacts::new(
                Direction::HostToGuest,
                Opcode::HelloAck,
                0,
            ))
            .expect("ack admitted");

        let open = decode(rest).expect("decode open");
        guest_side
            .admit(&FrameFacts::new(
                Direction::GuestToHost,
                open.header.opcode,
                open.header.stream_id,
            ))
            .expect("open admitted");
        rest = &rest[open.consumed..];

        guest_side
            .admit(&FrameFacts::new(Direction::HostToGuest, Opcode::Opened, 1))
            .expect("opened admitted");

        let data = decode(rest).expect("decode data");
        guest_side
            .admit(
                &FrameFacts::new(
                    Direction::GuestToHost,
                    data.header.opcode,
                    data.header.stream_id,
                )
                .with_payload(data.header.payload_len),
            )
            .expect("data admitted");
        rest = &rest[data.consumed..];
        assert!(rest.is_empty());
    }

    /// A frame that decodes cleanly can still be refused by the state
    /// machine. That is the whole reason the two are separate.
    #[test]
    fn a_well_formed_frame_can_still_be_an_illegal_one() {
        let wire = encode(Opcode::Data, 1, b"payload").expect("encode");
        let parsed = decode(&wire).expect("decodes fine");

        let mut v = SessionValidator::default();
        let err = v
            .admit(
                &FrameFacts::new(
                    Direction::GuestToHost,
                    parsed.header.opcode,
                    parsed.header.stream_id,
                )
                .with_payload(parsed.header.payload_len),
            )
            .expect_err("but is not legal yet");
        assert_eq!(err, StateError::SessionNotEstablished { opcode: 0x13 });
    }
}
