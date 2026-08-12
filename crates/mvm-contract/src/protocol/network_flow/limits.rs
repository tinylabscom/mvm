//! Hard bounds for the FlowMux protocol.
//!
//! Every value here is a ceiling a hostile guest cannot raise. They are
//! consts rather than negotiated parameters precisely so a `Hello` cannot
//! talk the host into a larger allocation: negotiation may only ever pick
//! something at or below these.

/// Wire-protocol major version this build speaks. A peer announcing a
/// different major is rejected outright — we never negotiate downward,
/// because a downgrade path is an attack the guest gets to drive.
pub const PROTOCOL_VERSION: u8 = 1;

/// Fixed header size for version 1, in bytes.
pub const HEADER_LEN: usize = 20;

/// Largest payload any single frame may carry: 64 KiB.
///
/// This is why the header's length field is a `u32` and not the `u16` the
/// packet tunnel used — 64 KiB is one byte past what a `u16` can express,
/// and a cap the length field cannot represent is a cap that is not really
/// enforced at the parse boundary.
pub const MAX_PAYLOAD_LEN: usize = 64 * 1024;

/// Largest complete frame (header + payload) after the length prefix.
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_PAYLOAD_LEN;

/// Bytes needed to hold one whole frame including its `u32` length prefix.
/// Buffer-sizing constant for both ends.
pub const MAX_WIRE_LEN: usize = LENGTH_PREFIX_LEN + MAX_FRAME_LEN;

/// Length of the `u32` big-endian frame-length prefix.
pub const LENGTH_PREFIX_LEN: usize = 4;

/// Longest DNS name a `Resolve` may carry, per RFC 1035's 255-octet
/// wire-format limit less the root label and length byte.
pub const MAX_DNS_NAME_LEN: usize = 253;

/// Longest single HTTP head (request or response) a typed transform flow
/// may carry. A head larger than this is refused rather than split, so the
/// inspector never has to reassemble one across frames to make a policy
/// decision about it.
pub const MAX_HTTP_HEAD_LEN: usize = 64 * 1024;

/// Largest UDP datagram payload, per the IPv4 maximum less the IP and UDP
/// headers. Fits inside [`MAX_PAYLOAD_LEN`] with room for the destination
/// prefix a `UdpSend` carries alongside it.
pub const MAX_UDP_DATAGRAM_LEN: usize = 65_507;

/// Bytes a `UdpSend`/`UdpRecv` spends on its address prefix: one tag byte,
/// a 16-byte address slot, and a big-endian port.
pub const UDP_ADDR_PREFIX_LEN: usize = 1 + 16 + 2;

/// Aggregate ceiling on concurrent TCP and typed-HTTP flows per VM. Carried
/// forward unchanged from the signed plan's existing `max_flows` default so
/// the transport swap does not quietly change what a workload may hold open.
pub const MAX_TCP_FLOWS: usize = 4096;

/// Ceiling on concurrent UDP associations per VM.
pub const MAX_UDP_ASSOCIATIONS: usize = 256;

/// Ceiling on declared ingress listeners per VM, carried forward from the
/// userspace datapath's existing bound.
pub const MAX_INGRESS_LISTENERS: usize = 16;

/// Bytes of send credit a stream starts with, expressed as a multiple of the
/// frame cap so the two move together: four frames in flight before the peer
/// has to grant more.
pub const INITIAL_STREAM_CREDIT: u32 = 4 * MAX_PAYLOAD_LEN as u32;

/// Most credit a single stream may accumulate. A `WindowUpdate` that would
/// push the window past this is refused, so a peer cannot use credit grants
/// to make the other end buffer without bound.
pub const MAX_STREAM_CREDIT: u32 = 64 * MAX_PAYLOAD_LEN as u32;

/// Worst-case bytes the endpoint may hold for flow state, ignoring payload
/// buffers: every admissible stream at its maximum credit window.
///
/// This is the number the endpoint's memory ceiling has to include. It is
/// derived here rather than restated at the call site so the two cannot
/// drift — raising a flow ceiling raises this automatically.
pub const MAX_FLOW_CREDIT_BYTES: u64 =
    (MAX_TCP_FLOWS + MAX_UDP_ASSOCIATIONS + MAX_INGRESS_LISTENERS) as u64
        * MAX_STREAM_CREDIT as u64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_bounds_are_self_consistent() {
        assert_eq!(MAX_FRAME_LEN, HEADER_LEN + MAX_PAYLOAD_LEN);
        assert_eq!(MAX_WIRE_LEN, LENGTH_PREFIX_LEN + MAX_FRAME_LEN);
    }

    /// The whole reason the length field is a `u32`.
    #[test]
    fn the_payload_cap_does_not_fit_a_u16_but_does_fit_a_u32() {
        const {
            assert!(MAX_PAYLOAD_LEN > u16::MAX as usize);
        };
        assert!(u32::try_from(MAX_PAYLOAD_LEN).is_ok());
    }

    #[test]
    fn a_maximal_udp_datagram_fits_in_one_frame_with_its_address_prefix() {
        const {
            assert!(MAX_UDP_DATAGRAM_LEN + UDP_ADDR_PREFIX_LEN <= MAX_PAYLOAD_LEN);
        };
    }

    #[test]
    fn a_maximal_http_head_fits_in_one_frame() {
        const {
            assert!(MAX_HTTP_HEAD_LEN <= MAX_PAYLOAD_LEN);
        };
    }

    #[test]
    fn a_maximal_dns_name_fits_in_one_frame() {
        const {
            assert!(MAX_DNS_NAME_LEN < MAX_PAYLOAD_LEN);
        };
    }

    /// The flow ceilings carried forward from the path being replaced.
    #[test]
    fn the_flow_ceilings_match_what_the_signed_plan_already_allowed() {
        assert_eq!(MAX_TCP_FLOWS, 4096);
        assert_eq!(MAX_UDP_ASSOCIATIONS, 256);
        assert_eq!(MAX_INGRESS_LISTENERS, 16);
    }

    #[test]
    fn credit_bounds_are_ordered_and_frame_derived() {
        const {
            assert!(INITIAL_STREAM_CREDIT < MAX_STREAM_CREDIT);
        };
        assert_eq!(INITIAL_STREAM_CREDIT % MAX_PAYLOAD_LEN as u32, 0);
        assert_eq!(MAX_STREAM_CREDIT % MAX_PAYLOAD_LEN as u32, 0);
    }

    /// The endpoint's memory ceiling has to include this, so it has to be
    /// derived from the ceilings rather than restated beside them.
    #[test]
    fn the_credit_ceiling_counts_every_admissible_stream() {
        let expected = (4096u64 + 256 + 16) * MAX_STREAM_CREDIT as u64;
        assert_eq!(MAX_FLOW_CREDIT_BYTES, expected);
    }

    /// A ceiling that overflowed would silently become no ceiling at all.
    #[test]
    fn the_credit_ceiling_does_not_overflow() {
        const { assert!(MAX_FLOW_CREDIT_BYTES < u64::MAX / 2) };
    }
}
