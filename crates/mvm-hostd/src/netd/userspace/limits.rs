//! Bounds for the userspace socket datapath.
//!
//! Consts rather than negotiated values: a ceiling a hostile guest can
//! raise is not a ceiling. This datapath is the first whose per-flow cost
//! is a file descriptor, so its cap is derived from the process budget
//! rather than inherited from the flow table.

use mvm_net::l3::config::DEFAULT_QUEUE_DEPTH;
use mvm_protocol::l3::limits::MTU_V1;

/// Ceiling on concurrent host sockets for one machine.
///
/// Sized against [`FLOW_BUFFER_BYTES`], the real per-flow cost (both socket
/// ring buffers plus both per-flow device queues at MTU size) rather than
/// the 32 KiB of ring buffers alone: the per-flow figure is 176,768 bytes,
/// 5.4x the ring-buffer-only estimate this cap was first set against. At
/// 1024 that put the worst case per machine near 173 MiB; at 256 it is back
/// under 44 MiB, which is where the cap was always assumed to sit.
pub const DEFAULT_MAX_HOST_SOCKETS: usize = 256;

/// Descriptors held back for the process itself: audit log, vsock,
/// control channel, logging, and slack.
pub const FD_RESERVE: usize = 64;

/// Concurrent half-open connections. Each parks a connecting descriptor,
/// so this is sized for a burst, not for a flood — but the burst is real:
/// a page-load fan-out, a parallel package-manager install, or a sidecar
/// dialing its upstreams at startup can open dozens at once, and the
/// [`HALF_OPEN_TIMEOUT_MILLIS`] wait means slow or high-RTT destinations
/// linger long enough to stack on top of fresh SYNs. Past this count the
/// table drops the newcomer rather than queuing it, so this is sized
/// against that demand, not against a fraction of
/// [`DEFAULT_MAX_HOST_SOCKETS`] picked for tidiness.
pub const DEFAULT_MAX_HALF_OPEN: usize = 64;

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
/// emit what the pass produced.
pub(super) const POLLS_PER_PASS: usize = 2;

/// Control segments a poll can emit that ride on no data segment: a FIN
/// with an empty buffer, a reset, a zero-window probe. One per poll is
/// generous; the term exists so the derivation is not exactly tight.
const CONTROL_SEGMENTS_PER_POLL: usize = 1;

/// Guest→stack queue depth: a receive window's worth of segments at the
/// conservative floor.
///
/// Deeper buys nothing. The stack discards anything past its receive
/// window as out of window, so a guest cannot usefully have more than this
/// in flight however it chops it up.
pub const FLOW_RX_QUEUE_DEPTH: usize = SOCKET_RX_BUFFER.div_ceil(DEFAULT_SEGMENT_PAYLOAD);

/// Data segments one pump pass can put on the guest-bound queue.
///
/// A pass emits data in **two** rounds — whatever was unsent at the first
/// poll, then whatever the host read into the send buffer before the
/// second — and each round rounds up to a whole segment independently.
/// The two rounds share one send buffer's worth of bytes between them
/// (the second can only write into space the first left free), so the
/// count is a buffer's worth of segments plus one for the extra rounding.
pub(super) const DATA_SEGMENTS_PER_PASS: usize =
    SOCKET_TX_BUFFER.div_ceil(DEFAULT_SEGMENT_PAYLOAD) + (POLLS_PER_PASS - 1);

/// Stack→guest queue depth: the ACK burst a poll's ingress can produce,
/// plus the data a pass emits, plus control.
///
/// **The ACK term is the one that is easy to miss, and it dominates.**
/// smoltcp answers an ingested segment with an *immediate* ACK whenever
/// its reassembly hole is non-empty, inside the same ingress loop, once
/// per segment — and unlike its challenge ACK, that reply is not
/// rate-limited. One poll drains the whole guest→stack queue, so a poll
/// can emit as many ACKs as that queue was deep: the bound on the burst is
/// [`FLOW_RX_QUEUE_DEPTH`], not the number of polls.
///
/// The hole that triggers it needs no attacker. This datapath *models*
/// dropping a guest packet when the receive queue is full
/// ([`PushOutcome::DroppedQueueFull`](super::device::PushOutcome)); that
/// drop is itself a sequence hole, and every segment behind it then draws
/// its own ACK. Sizing this queue for two ACKs — a per-poll *egress*
/// figure applied to an *ingress* count — left a normal loaded flow
/// discarding the pass's data segments after smoltcp had already counted
/// them sent, which costs the guest a retransmission timeout apiece.
///
/// Separate from [`FLOW_RX_QUEUE_DEPTH`] because the two are no longer the
/// same argument: one bounds what a guest can usefully offer, the other
/// what the stack can produce in reply to it.
pub const FLOW_TX_QUEUE_DEPTH: usize =
    FLOW_RX_QUEUE_DEPTH + DATA_SEGMENTS_PER_PASS + POLLS_PER_PASS * CONTROL_SEGMENTS_PER_POLL;

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
/// of kilobytes, and `a_flows_inline_size_stays_pinned` pins them
/// separately so they cannot grow into a second ceiling unseen. That test
/// sees inline bytes only; a new *heap-allocating* field is covered by
/// neither, and has to be added here by hand.
pub const FLOW_BUFFER_BYTES: usize = SOCKET_RX_BUFFER
    + SOCKET_TX_BUFFER
    + (FLOW_RX_QUEUE_DEPTH + FLOW_TX_QUEUE_DEPTH) * MTU_V1 as usize;

/// Worst-case bytes the half-open table holds: one guest SYN per entry,
/// each bounded by the link MTU because that is what the datapath admits.
///
/// Held rather than parsed-and-discarded because the SYN is replayed into
/// the flow's own stack once the host side is real, so smoltcp answers the
/// packet the guest actually sent.
///
/// The resets these entries owe their guests when a connect fails do *not*
/// need a term of their own: they go onto the machine-wide device's
/// guest-bound queue, which is already counted below.
pub const HALF_OPEN_BUFFER_BYTES: usize = DEFAULT_MAX_HALF_OPEN * MTU_V1 as usize;

/// Worst-case buffer footprint for one machine at the socket cap: every
/// flow at its own bound, plus the machine-wide guest-facing device the
/// datapath handle owns, plus the SYNs its half-open table is holding.
///
/// An upper bound, not an attainable state: half-open and established
/// entries share one descriptor budget, so a machine cannot in fact hold
/// [`DEFAULT_MAX_HOST_SOCKETS`] flows *and* [`DEFAULT_MAX_HALF_OPEN`]
/// half-open entries at once. Summed anyway, because a ceiling that has to
/// be reasoned about to be believed is a ceiling nobody will re-check.
pub const MEMORY_CEILING_BYTES: usize = DEFAULT_MAX_HOST_SOCKETS * FLOW_BUFFER_BYTES
    + 2 * DEFAULT_QUEUE_DEPTH * MTU_V1 as usize
    + HALF_OPEN_BUFFER_BYTES;

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
        // A 16 KiB window is 31 segments at the 536 byte default MSS.
        assert_eq!(FLOW_RX_QUEUE_DEPTH, 31);
        // 31 ACKs (one per segment the ingress loop can take in behind a
        // hole) + 32 data segments (two rounding-up rounds over one send
        // buffer) + 2 control.
        assert_eq!(FLOW_TX_QUEUE_DEPTH, 31 + 32 + 2);
        // 32 KiB of ring buffers + (31 + 65) × 1500 bytes of device queues.
        assert_eq!(FLOW_BUFFER_BYTES, 32_768 + 144_000);
        // 64 held SYNs, each at most an MTU.
        assert_eq!(HALF_OPEN_BUFFER_BYTES, 96_000);
        // 256 flows at that, plus the handle's own 2 × 256 × 1500, plus the
        // SYNs the half-open table holds.
        assert_eq!(MEMORY_CEILING_BYTES, 256 * 176_768 + 768_000 + 96_000);
        assert_eq!(MEMORY_CEILING_BYTES, 46_116_608);
        const {
            assert!(
                DEFAULT_MAX_HOST_SOCKETS < mvm_net::l3::flow::DEFAULT_MAX_FLOWS,
                "the socket cap must sit below the flow cap: a descriptor costs more than a table entry"
            );
        };
    }

    /// The device queues are the term that broke this formula once, by
    /// being sized for one queue per machine and then made per flow.
    ///
    /// Measured against the machine-wide device rather than the socket
    /// buffers, because that is the mistake this guards: a per-flow queue
    /// multiplies by [`DEFAULT_MAX_HOST_SOCKETS`], so it has to stay a
    /// small fraction of the one queue a machine keeps. The socket-buffer
    /// comparison is kept as a second, weaker signal — at 144_000 against
    /// 32_768 the ratio is already 4.4, so it now catches only a further
    /// large jump, and the fraction-of-machine-wide bound is the one with
    /// real margin.
    #[test]
    fn a_flows_device_queues_stay_a_fraction_of_the_machine_wide_one() {
        let device = (FLOW_RX_QUEUE_DEPTH + FLOW_TX_QUEUE_DEPTH) * MTU_V1 as usize;
        let machine_wide = 2 * DEFAULT_QUEUE_DEPTH * MTU_V1 as usize;
        assert!(
            device * 4 < machine_wide,
            "a per-flow device queue of {device} bytes is no longer a small fraction of the \
             {machine_wide} byte machine-wide one, and it multiplies by the socket cap"
        );
        let sockets = SOCKET_RX_BUFFER + SOCKET_TX_BUFFER;
        assert!(
            device <= 5 * sockets,
            "a per-flow device queue of {device} bytes dwarfs its {sockets} bytes of socket buffers"
        );
        const {
            assert!(
                FLOW_RX_QUEUE_DEPTH < DEFAULT_QUEUE_DEPTH
                    && FLOW_TX_QUEUE_DEPTH < DEFAULT_QUEUE_DEPTH,
                "a per-flow depth must sit below the machine-wide one: it multiplies by the socket cap"
            );
        };
    }

    /// The guest-bound depth must cover an ACK burst *and* a pass's data,
    /// not one or the other.
    ///
    /// This re-derives the constant's own expression, so it pins the
    /// reasoning rather than an independent figure — treat
    /// `a_queue_full_drop_does_not_cost_the_guest_the_passs_data` in
    /// `tcp.rs` as the behavioural witness. What it is good for is naming
    /// the two terms separately, so dropping either is a failure with a
    /// message that says which.
    #[test]
    fn the_guest_bound_depth_covers_both_an_ack_burst_and_a_pass_of_data() {
        const {
            assert!(
                FLOW_TX_QUEUE_DEPTH >= FLOW_RX_QUEUE_DEPTH + DATA_SEGMENTS_PER_PASS,
                "the guest-bound depth cannot hold a full ACK burst beside a pass of data"
            );
            assert!(
                DATA_SEGMENTS_PER_PASS > SOCKET_TX_BUFFER.div_ceil(DEFAULT_SEGMENT_PAYLOAD),
                "a pass emits data in two independently rounded rounds, so one round is short"
            );
        };
    }

    /// This guard exists to express one thing: half-open entries must not
    /// be able to consume the whole socket budget, since each one holds a
    /// real descriptor and competes with established sockets for it. The
    /// ratio is what should give when the two constants are re-sized, not
    /// [`DEFAULT_MAX_HALF_OPEN`] — that number is set against real connect
    /// demand, and a guard tuned to make a demand-driven figure fit is a
    /// guard tuned to stop guarding. A quarter of the cap still leaves that
    /// property true.
    #[test]
    fn half_open_is_far_smaller_than_the_socket_cap() {
        const { assert!(DEFAULT_MAX_HALF_OPEN * 3 < DEFAULT_MAX_HOST_SOCKETS) };
    }
}
