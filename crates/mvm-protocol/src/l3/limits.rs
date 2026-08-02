//! Hard bounds for the L3-over-vsock protocol.
//!
//! Every value here is a ceiling a hostile guest cannot raise. They are
//! consts rather than negotiated parameters precisely so a `HELLO` cannot
//! talk the host into a larger allocation: negotiation may only ever pick
//! something at or below these.

/// Wire-protocol major version this build speaks. A peer announcing a
/// different major is rejected outright — we never negotiate downward,
/// because a downgrade path is an attack the guest gets to drive.
pub const PROTOCOL_VERSION: u8 = 1;

/// Fixed header size for version 1, in bytes.
pub const HEADER_LEN: usize = 24;

/// Largest payload any single frame may carry.
///
/// Sized to hold an MTU-sized packet plus room for the fixed-layout
/// control messages, and small enough that a per-connection preallocated
/// buffer pair is cheap even with many machines running.
pub const MAX_PAYLOAD_LEN: usize = 2048;

/// Largest complete frame (header + payload) after the length prefix.
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_PAYLOAD_LEN;

/// Bytes needed to hold one whole frame including its `u32` length prefix.
/// Buffer sizing constant for both ends.
pub const MAX_WIRE_LEN: usize = 4 + MAX_FRAME_LEN;

/// The one MTU version 1 offers. Fixed, not negotiated: a guest that could
/// choose its MTU could choose the host's buffer size.
pub const MTU_V1: u16 = 1500;

/// Smallest well-formed IPv4 header.
pub const MIN_IPV4_HEADER: usize = 20;

/// Fixed IPv6 header size.
pub const IPV6_HEADER_LEN: usize = 40;

/// Number of data queues version 1 runs. The wire format carries a
/// `queue_id`, so raising this needs no change to the wire format.
pub const QUEUE_COUNT_V1: u16 = 1;

/// Upper bound on queues any version may negotiate.
pub const MAX_QUEUES: u16 = 16;

/// Longest detail string an `ERROR` message may carry. Bounded so a peer
/// cannot use the error channel as an allocation lever.
pub const MAX_ERROR_DETAIL: usize = 128;

/// How many IPv6 extension headers the validator will walk before giving
/// up and rejecting the packet. Real traffic uses one or two; an attacker
/// chains them to burn CPU.
pub const MAX_IPV6_EXT_HEADERS: usize = 8;

/// Total bytes of IPv6 extension headers the validator will traverse.
/// Bounds the walk even when each individual header is small.
pub const MAX_IPV6_EXT_BYTES: usize = 512;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_mtu_sized_packet_fits_in_a_frame() {
        assert!(MTU_V1 as usize <= MAX_PAYLOAD_LEN);
    }

    #[test]
    fn frame_bounds_are_self_consistent() {
        assert_eq!(MAX_FRAME_LEN, HEADER_LEN + MAX_PAYLOAD_LEN);
        assert_eq!(MAX_WIRE_LEN, 4 + MAX_FRAME_LEN);
    }

    #[test]
    fn payload_length_fits_the_u16_wire_field() {
        assert!(MAX_PAYLOAD_LEN <= u16::MAX as usize);
    }

    #[test]
    fn v1_runs_one_queue_within_the_protocol_ceiling() {
        assert_eq!(QUEUE_COUNT_V1, 1);
        const { assert!(QUEUE_COUNT_V1 <= MAX_QUEUES) };
    }
}
