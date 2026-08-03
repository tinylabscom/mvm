//! Bounds for the userspace socket datapath.
//!
//! Consts rather than negotiated values: a ceiling a hostile guest can
//! raise is not a ceiling. This datapath is the first whose per-flow cost
//! is a file descriptor, so its cap is derived from the process budget
//! rather than inherited from the flow table.

use mvm_net::l3::config::DEFAULT_QUEUE_DEPTH;
use mvm_protocol::l3::limits::MTU_V1;

/// Ceiling on concurrent host sockets for one machine.
pub const DEFAULT_MAX_HOST_SOCKETS: usize = 1024;

/// Descriptors held back for the process itself: audit log, vsock,
/// control channel, logging, and slack.
pub const FD_RESERVE: usize = 64;

/// Concurrent half-open connections. Each parks a connecting descriptor,
/// so this is sized for a burst, not for a flood.
pub const DEFAULT_MAX_HALF_OPEN: usize = 128;

/// How long a half-open entry waits for its host connect.
pub const HALF_OPEN_TIMEOUT_MILLIS: u64 = 10_000;

pub const SOCKET_RX_BUFFER: usize = 16 * 1024;
pub const SOCKET_TX_BUFFER: usize = 16 * 1024;

/// The smallest payload a segment carries when neither end asks for
/// anything smaller: the IPv4 default maximum segment size of RFC 879 and
/// RFC 1122 §4.2.2.6, which is also smoltcp's `DEFAULT_MSS`.
///
/// This, not the MTU, is what sets a queue depth. A depth derived from
/// full-size segments is wrong for the ordinary case of a guest whose SYN
/// carries no MSS option: its window then becomes ~31 segments rather than
/// ~12, and a queue sized for 12 discards the rest of a perfectly normal
/// pass.
///
/// It is a floor for well-formed peers, not a bound a guest is held to.
/// smoltcp takes any non-zero MSS from the guest's SYN, so a guest that
/// asks for 64-byte segments turns one send buffer into 256 of them. No
/// queue depth can absorb that, which is the whole reason the guest-bound
/// queue counts what it discards instead of discarding it silently — see
/// [`super::device::GuestDevice::dropped_to_guest`]. The depth is sized
/// for honest peers; hostile ones become a visible number.
const DEFAULT_SEGMENT_PAYLOAD: usize = 536;

/// Polls one pump pass makes: one to take in what the guest sent, one to
/// emit what the pass produced. Each can put a pure ACK on the queue
/// beside the data segments.
const POLLS_PER_PASS: usize = 2;

/// Packets one flow's guest-facing device queues hold, per direction.
///
/// Derived from the socket buffers rather than inherited from
/// [`DEFAULT_QUEUE_DEPTH`], because this queue is **per flow**: a depth
/// chosen for one queue per machine multiplies by
/// [`DEFAULT_MAX_HOST_SOCKETS`] here, and at 256 packets that is three
/// quarters of a megabyte per flow — far more than the socket buffers the
/// ceiling was written around.
///
/// The size is what one pass legitimately moves: a full buffer's worth of
/// data at the default segment size, plus an ACK per poll. Sizing it for
/// the *byte* budget alone was the first attempt and was wrong in both
/// directions at once — it ignored that a pass emits ACKs as well as data,
/// and that a segment need not be full-size.
///
/// One constant rather than two, because both directions come out at the
/// same figure by the same argument: the guest cannot usefully queue more
/// than the stack's receive window (the stack discards the rest as out of
/// window) and the stack cannot emit more than its send buffer holds, and
/// both windows are the same size. Split them if that ever stops being
/// true.
pub const FLOW_QUEUE_DEPTH: usize = {
    let window = if SOCKET_RX_BUFFER > SOCKET_TX_BUFFER {
        SOCKET_RX_BUFFER
    } else {
        SOCKET_TX_BUFFER
    };
    window.div_ceil(DEFAULT_SEGMENT_PAYLOAD) + POLLS_PER_PASS
};

/// Worst-case bytes one established flow holds: both socket ring buffers,
/// plus both device queues full of MTU-sized packets.
///
/// The device queues belong in here because they are per-flow state whose
/// filling a guest drives. Leaving them out is what made the old formula
/// wrong by an order of magnitude the moment each flow got its own device
/// instead of sharing one per machine.
///
/// Not in here: the fixed per-flow structs — smoltcp's `Interface`, the
/// socket-set spine. Those are hundreds of bytes against this figure's tens
/// of kilobytes, and `a_flows_fixed_overhead_stays_small_beside_its_buffers`
/// pins them separately so they cannot grow into a second ceiling unseen.
pub const FLOW_BUFFER_BYTES: usize =
    SOCKET_RX_BUFFER + SOCKET_TX_BUFFER + 2 * FLOW_QUEUE_DEPTH * MTU_V1 as usize;

/// Worst-case buffer footprint for one machine at the socket cap: every
/// flow at its own bound, plus the machine-wide guest-facing device the
/// datapath handle owns.
pub const MEMORY_CEILING_BYTES: usize =
    DEFAULT_MAX_HOST_SOCKETS * FLOW_BUFFER_BYTES + 2 * DEFAULT_QUEUE_DEPTH * MTU_V1 as usize;

#[cfg(test)]
mod tests {
    use super::*;

    /// The ceiling is a number the host must be able to afford at the
    /// cap. Asserting it here means neither a buffer size nor a queue
    /// depth can silently multiply the worst-case footprint.
    ///
    /// Every term is spelled out rather than recomputed from the same
    /// expression the constant uses, so a change to the formula has to be
    /// argued for here rather than propagating into the assertion.
    #[test]
    fn the_per_machine_memory_ceiling_is_what_we_claim() {
        assert_eq!(SOCKET_RX_BUFFER + SOCKET_TX_BUFFER, 32 * 1024);
        // A 16 KiB window is 31 segments at the 536 byte default MSS, plus
        // one ACK per poll.
        assert_eq!(FLOW_QUEUE_DEPTH, 31 + 2);
        // 32 KiB of ring buffers + 2 × 33 × 1500 bytes of device queues.
        assert_eq!(FLOW_BUFFER_BYTES, 32_768 + 99_000);
        // 1024 flows at that, plus the handle's own 2 × 256 × 1500.
        assert_eq!(MEMORY_CEILING_BYTES, 1024 * 131_768 + 768_000);
        assert_eq!(MEMORY_CEILING_BYTES, 135_698_432);
        const {
            assert!(
                DEFAULT_MAX_HOST_SOCKETS < mvm_net::l3::flow::DEFAULT_MAX_FLOWS,
                "the socket cap must sit below the flow cap: a descriptor costs more than a table entry"
            );
        };
    }

    /// The device queues are the term that broke this formula once, by
    /// being sized for one queue per machine and then made per flow. They
    /// must stay the same order of magnitude as the socket buffers they
    /// sit beside — a depth inherited from the machine-wide default is
    /// twenty times that and would put the cap near a gigabyte.
    #[test]
    fn a_flows_device_queues_stay_the_size_of_its_socket_buffers() {
        let device = 2 * FLOW_QUEUE_DEPTH * MTU_V1 as usize;
        let sockets = SOCKET_RX_BUFFER + SOCKET_TX_BUFFER;
        assert!(
            device <= 4 * sockets,
            "a per-flow device queue of {device} bytes dwarfs its {sockets} bytes of socket buffers"
        );
        const {
            assert!(
                FLOW_QUEUE_DEPTH < DEFAULT_QUEUE_DEPTH,
                "the per-flow depth must sit below the machine-wide one: it multiplies by the socket cap"
            );
        };
    }

    /// The depth has to cover what one pass actually emits, or a normal
    /// full-throughput pass overflows the guest-bound queue — and that
    /// overflow costs the guest a retransmission timeout for a segment the
    /// host threw away. Sizing by byte budget alone gave 12, which is
    /// below the ~31 segments a 16 KiB window becomes at the default MSS.
    #[test]
    fn the_queue_depth_covers_a_full_pass_at_the_default_segment_size() {
        let segments = SOCKET_TX_BUFFER.div_ceil(DEFAULT_SEGMENT_PAYLOAD);
        assert!(
            FLOW_QUEUE_DEPTH >= segments + POLLS_PER_PASS,
            "a depth of {FLOW_QUEUE_DEPTH} cannot hold {segments} segments plus their ACKs"
        );
    }

    #[test]
    fn half_open_is_far_smaller_than_the_socket_cap() {
        const { assert!(DEFAULT_MAX_HALF_OPEN * 4 < DEFAULT_MAX_HOST_SOCKETS) };
    }
}
