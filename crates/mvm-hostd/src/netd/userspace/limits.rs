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

/// The least payload a full-size segment can carry: the MTU less the
/// largest header pair either address family produces — IPv6's 40 bytes,
/// TCP's 20, and up to 20 bytes of TCP options.
const MIN_SEGMENT_PAYLOAD: usize = MTU_V1 as usize - 80;

/// Packets one flow's guest-facing device queues hold, per direction.
///
/// Derived from the socket buffers rather than inherited from
/// [`DEFAULT_QUEUE_DEPTH`], because this queue is now **per flow**: a depth
/// chosen for one queue per machine multiplies by
/// [`DEFAULT_MAX_HOST_SOCKETS`] here, and at 256 packets that is three
/// quarters of a megabyte per flow — an order of magnitude more than the
/// socket buffers the ceiling was written around.
///
/// A window's worth is the right size in both directions. The guest cannot
/// usefully queue more than the stack's receive window, because the stack
/// discards the rest as out of window; and the stack cannot emit more than
/// its send buffer holds, which one pump pass then drains.
pub const FLOW_QUEUE_DEPTH: usize = {
    let window = if SOCKET_RX_BUFFER > SOCKET_TX_BUFFER {
        SOCKET_RX_BUFFER
    } else {
        SOCKET_TX_BUFFER
    };
    window.div_ceil(MIN_SEGMENT_PAYLOAD)
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
        assert_eq!(FLOW_QUEUE_DEPTH, 12);
        // 32 KiB of ring buffers + 2 × 12 × 1500 bytes of device queues.
        assert_eq!(FLOW_BUFFER_BYTES, 32_768 + 36_000);
        // 1024 flows at that, plus the handle's own 2 × 256 × 1500.
        assert_eq!(MEMORY_CEILING_BYTES, 1024 * 68_768 + 768_000);
        assert_eq!(MEMORY_CEILING_BYTES, 71_186_432);
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
            device <= 2 * sockets,
            "a per-flow device queue of {device} bytes dwarfs its {sockets} bytes of socket buffers"
        );
        const {
            assert!(
                FLOW_QUEUE_DEPTH < DEFAULT_QUEUE_DEPTH,
                "the per-flow depth must sit below the machine-wide one: it multiplies by the socket cap"
            );
        };
    }

    #[test]
    fn half_open_is_far_smaller_than_the_socket_cap() {
        const { assert!(DEFAULT_MAX_HALF_OPEN * 4 < DEFAULT_MAX_HOST_SOCKETS) };
    }
}
