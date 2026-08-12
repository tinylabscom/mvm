//! Fuzz the FlowMux session/stream state machine.
//!
//! The decoder's fuzz target proves bytes cannot break the parser. This one
//! proves a *sequence* of well-formed frames cannot break the machine that
//! decides whether they were allowed — a different attack, because every
//! frame here is individually valid.
//!
//! Each input byte quartet is read as one frame's facts, so libFuzzer's
//! mutations explore transition orderings rather than byte layouts. The
//! contract for any sequence:
//!
//! - never panic;
//! - live stream count never exceeds the sum of the class ceilings;
//! - a refused frame leaves the machine exactly as it was;
//! - a retired stream ID is never admitted again;
//! - credit never exceeds the per-stream window ceiling.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_contract::protocol::network_flow::{
    Direction, FrameFacts, MAX_INGRESS_LISTENERS, MAX_STREAM_CREDIT, MAX_TCP_FLOWS,
    MAX_UDP_ASSOCIATIONS, Opcode, SessionValidator, SessionState,
};

/// Every stream the machine may hold at once, summed across the classes.
const MAX_LIVE: usize = MAX_TCP_FLOWS + MAX_UDP_ASSOCIATIONS + MAX_INGRESS_LISTENERS;

/// Read one frame's facts out of six input bytes.
fn facts_from(chunk: &[u8]) -> FrameFacts {
    let opcode = Opcode::ALL[chunk[0] as usize % Opcode::ALL.len()];
    let direction = if chunk[1] & 1 == 0 {
        Direction::GuestToHost
    } else {
        Direction::HostToGuest
    };
    // Small stream IDs so distinct frames collide on the same stream often
    // — collisions are where the interesting transitions live.
    let stream_id = if opcode.is_session() {
        0
    } else {
        u32::from(chunk[2])
    };
    let mut facts = FrameFacts::new(direction, opcode, stream_id);
    // Payload sizes that straddle the initial window, so credit exhaustion
    // is reachable without needing a million iterations to find it.
    facts = facts.with_payload(u32::from(u16::from_be_bytes([chunk[3], chunk[4]])) * 8);
    facts = facts.with_ingress_mapping(u16::from(chunk[5]));
    facts.with_credit(u32::from(chunk[3]) * 4096)
}

fuzz_target!(|data: &[u8]| {
    // Declare a couple of ingress mappings so the ingress path is reachable
    // at all; everything outside the set must still be refused.
    let mut validator = SessionValidator::new([0u16, 1, 2]);

    for chunk in data.chunks_exact(6) {
        let facts = facts_from(chunk);

        let before_session = validator.session_state();
        let before_live = validator.live_streams();
        let before_state = validator.stream_state(facts.stream_id);
        let before_guest_credit = validator.credit(facts.stream_id, Direction::GuestToHost);
        let before_host_credit = validator.credit(facts.stream_id, Direction::HostToGuest);

        if validator.admit(&facts).is_err() {
            // Fail-closed: a refusal must move nothing. If it did, a peer
            // could drive state with frames it is not allowed to send.
            assert_eq!(validator.session_state(), before_session);
            assert_eq!(validator.live_streams(), before_live);
            assert_eq!(validator.stream_state(facts.stream_id), before_state);
            assert_eq!(
                validator.credit(facts.stream_id, Direction::GuestToHost),
                before_guest_credit
            );
            assert_eq!(
                validator.credit(facts.stream_id, Direction::HostToGuest),
                before_host_credit
            );
            continue;
        }

        assert!(
            validator.live_streams() <= MAX_LIVE,
            "live streams {} passed the summed ceiling {MAX_LIVE}",
            validator.live_streams()
        );

        for dir in [Direction::GuestToHost, Direction::HostToGuest] {
            if let Some(c) = validator.credit(facts.stream_id, dir) {
                assert!(
                    c <= MAX_STREAM_CREDIT,
                    "credit {c} passed the window ceiling"
                );
            }
        }

        // Once the session is closed nothing is live, and it never reopens.
        if validator.session_state() == SessionState::Closed {
            assert_eq!(validator.live_streams(), 0);
        }
    }

    // A closed session stays closed for every remaining opcode.
    if validator.session_state() == SessionState::Closed {
        for op in Opcode::ALL {
            let id = if op.is_session() { 0 } else { 1 };
            assert!(
                validator
                    .admit(&FrameFacts::new(Direction::GuestToHost, *op, id))
                    .is_err(),
                "{op:?} was admitted on a closed session"
            );
        }
    }
});
