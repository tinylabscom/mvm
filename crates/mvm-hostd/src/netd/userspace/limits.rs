//! Bounds for the userspace socket datapath.
//!
//! Consts rather than negotiated values: a ceiling a hostile guest can
//! raise is not a ceiling. This datapath is the first whose per-flow cost
//! is a file descriptor, so its cap is derived from the process budget
//! rather than inherited from the flow table.

use mvm_net::l3::config::DEFAULT_QUEUE_DEPTH;
use mvm_protocol::l3::limits::{MIN_IPV4_HEADER, MTU_V1};

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

/// Concurrent UDP associations, each holding a connected host datagram
/// socket.
///
/// A quarter of [`DEFAULT_MAX_HOST_SOCKETS`], the same share
/// [`DEFAULT_MAX_HALF_OPEN`] takes, and for the same reason: an
/// association parks a real descriptor out of the one budget TCP is also
/// drawing on, so datagram traffic must not be able to starve connections.
///
/// Sized against what a workload actually opens. DNS is not in the count —
/// it terminates above this seam and never reaches a host socket here — so
/// what is left is QUIC, NTP, syslog, and metrics exporters: a handful of
/// long-lived conversations per workload rather than the per-request fan-out
/// TCP sees. Past this count the table refuses the newcomer; nothing is
/// evicted, because evicting would let one guest flow end another's.
pub const DEFAULT_MAX_UDP_ASSOCIATIONS: usize = 64;

/// Datagrams one association may hand back in a single poll.
///
/// Derived, not chosen. Everything a poll produces goes onto the one
/// machine-wide guest-bound queue, which is [`DEFAULT_QUEUE_DEPTH`] deep,
/// so a full poll of every association at this rate exactly fills it.
/// Anything larger would be read off a host socket only to be discarded on
/// the way to the guest — a drop that costs a real datagram and buys
/// nothing.
///
/// It bounds one pass, not the conversation: whatever is left sits in the
/// kernel's own receive buffer and comes out on the next pass.
pub const DATAGRAMS_PER_ASSOCIATION_POLL: usize =
    DEFAULT_QUEUE_DEPTH / DEFAULT_MAX_UDP_ASSOCIATIONS;

/// The largest UDP payload this datapath carries in either direction: an
/// MTU-sized packet less its IPv4 and UDP headers.
///
/// The guest's link cannot carry more, and this datapath refuses fragments
/// rather than reassembling them, so a larger datagram has nowhere to go.
/// A reply above this is dropped rather than truncated — a short datagram
/// delivered as though it were whole is corrupt data the guest has no way
/// to detect.
pub const MAX_DATAGRAM_PAYLOAD_BYTES: usize =
    MTU_V1 as usize - MIN_IPV4_HEADER - mvm_protocol::l3::ip::UDP_HEADER_LEN;

/// How long an association lives, measured from the datagram that opened
/// it and never extended.
///
/// The figure is `mvm_net`'s datagram idle bound, so a host socket and the
/// flow-table entry that admitted it are not reclaimed on different clocks.
/// What is local to here is that it is **absolute**: a conversation's later
/// datagrams do not push it out.
///
/// UDP offers nothing that says a conversation ended, so an association can
/// only ever be reclaimed on a timer — and a timer traffic refreshes is one
/// a guest holds open for the machine's whole life by sending a byte a
/// minute, 64 descriptors at a time. The same argument that made the TCP
/// path's deadlines absolute rather than smoltcp's refreshable
/// `set_timeout`.
///
/// The cost is stated rather than hidden: a UDP conversation still running
/// after a minute is cut, and the guest's next datagram opens a fresh
/// association behind a different host source port, which its peer sees as
/// a rebind. That is the same event a NAT ahead of a real host would
/// produce, and long-lived datagram protocols already handle it. An
/// occasional rebind is the price of not handing a guest a descriptor it
/// can pin permanently.
pub const ASSOCIATION_LIFETIME_MILLIS: u64 = mvm_net::l3::flow::DEFAULT_DATAGRAM_IDLE_MILLIS;

/// How long a quiet established connection waits before the host starts
/// asking whether its peer is still there.
///
/// This, and not an idle timer, is how an established flow is reclaimed.
/// Idleness cannot distinguish a connection nobody is using from one nobody
/// is *answering*, and this datapath carries both: a Server-Sent Events
/// stream between events and a WebSocket between messages are idle **by
/// design**, indefinitely, and a reaper that measured quietness would kill
/// them and leave nothing in the logs but a dropped connection. A keepalive
/// probe asks the question idleness only guesses at.
///
/// Long enough that ordinary quiet connections cost no probes worth
/// counting, short enough that a descriptor behind a vanished peer comes
/// back in about a minute and a half rather than the two hours a platform
/// default would take.
pub const KEEPALIVE_IDLE_SECS: u64 = 60;

/// How long a flow whose host socket has failed waits for the guest to
/// take the bytes it is still owed, before resetting anyway.
///
/// The deferral in `deliver_then_reset` has to end somewhere. This is an
/// **absolute** deadline, taken once when the failure is latched and never
/// refreshed, which is the whole point: smoltcp's own
/// `TcpSocket::set_timeout` measures the gap between packets *the remote
/// sends*, so a guest that acknowledges without ever draining refreshes it
/// for free and holds the flow for as long as it likes. A deadline nothing
/// the guest does can move cannot be starved that way.
///
/// Ten seconds, the same scale as [`HALF_OPEN_TIMEOUT_MILLIS`], for the
/// same reason: the guest is one in-memory hop away, so a guest that has
/// not taken its last bytes in that long is not going to.
pub const RESET_DELIVERY_TIMEOUT_MILLIS: u64 = 10_000;

/// How long a flow waits for the guest to finish the handshake the host
/// side has already completed.
///
/// The host connect succeeded, so the guest was sent a SYN-ACK; a guest
/// that never answers it leaves the flow in SYN-RECEIVED, where **no host
/// error can ever occur** — there is nothing to read or write yet — so
/// neither the keepalive nor the reset deadline can reach it. Without this
/// the flow's descriptor, its buffers, and its slot in the socket budget
/// are held for the machine's whole life, and a guest that opens its budget
/// in flows it never completes takes the datapath out of service for good.
///
/// The guest is one in-memory hop away, so a handshake it has not finished
/// in ten seconds is one it is not going to.
pub const HANDSHAKE_COMPLETION_TIMEOUT_MILLIS: u64 = 10_000;

/// How long a flow lives after its peer has stopped sending.
///
/// Once the peer's half is closed the datapath stops reading that socket,
/// so — as with the handshake above — no host error can surface on it
/// again and nothing else would ever end the flow. Linux bounds the
/// equivalent state with `tcp_fin_timeout`, 60 seconds by default, and this
/// follows it rather than inventing a figure.
///
/// The trade-off is stated rather than hidden: a guest still uploading a
/// minute after its peer stopped sending is cut off. An absolute bound that
/// occasionally ends a slow conversation early is the cost of not offering
/// a guest a resource it can pin permanently, and a refreshable one would
/// be no bound at all.
pub const HALF_CLOSED_TIMEOUT_MILLIS: u64 = 60_000;

/// Gap between probes once the peer has stopped answering.
pub const KEEPALIVE_PROBE_INTERVAL_SECS: u64 = 10;

/// Unanswered probes before the connection is declared dead. With the two
/// figures above, a vanished peer surfaces as a socket error within
/// 60 + 3 x 10 seconds.
pub const KEEPALIVE_PROBE_RETRIES: u32 = 3;

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

/// Worst-case bytes the UDP path holds: the packets one poll synthesizes
/// for the guest, across every association at once.
///
/// This is the whole userspace footprint of an association, and the
/// arithmetic is worth reading rather than trusting. An association owns a
/// connected host socket, an admitted `SocketAddr`, and a deadline — all
/// inline, all tens of bytes, none of it heap. Its buffered datagrams live
/// in the *kernel's* socket receive buffer, which is not this process's
/// allocation and not what this ceiling counts. What this process does
/// allocate is the batch [`super::udp::UdpAssociations::poll`] returns:
/// [`DATAGRAMS_PER_ASSOCIATION_POLL`] packets per association, each an
/// IP+UDP packet bounded by the link MTU.
///
/// 64 associations x 4 datagrams x 1500 bytes. Transient — the batch is
/// drained onto the guest-bound queue and dropped — so this is a peak, not
/// a resident cost, and it is counted separately from that queue because
/// the two coexist while the batch is being moved onto it.
pub const UDP_BUFFER_BYTES: usize =
    DEFAULT_MAX_UDP_ASSOCIATIONS * DATAGRAMS_PER_ASSOCIATION_POLL * MTU_V1 as usize;

/// Worst-case buffer footprint for one machine at the socket cap: every
/// flow at its own bound, plus the machine-wide guest-facing device the
/// datapath handle owns, plus the SYNs its half-open table is holding, plus
/// the datagram batch its associations can produce in one poll.
///
/// An upper bound, not an attainable state: half-open entries, established
/// flows, and UDP associations share one descriptor budget, so a machine
/// cannot in fact hold [`DEFAULT_MAX_HOST_SOCKETS`] flows *and*
/// [`DEFAULT_MAX_HALF_OPEN`] half-open entries *and*
/// [`DEFAULT_MAX_UDP_ASSOCIATIONS`] associations at once. Summed anyway,
/// because a ceiling that has to be reasoned about to be believed is a
/// ceiling nobody will re-check.
pub const MEMORY_CEILING_BYTES: usize = DEFAULT_MAX_HOST_SOCKETS * FLOW_BUFFER_BYTES
    + 2 * DEFAULT_QUEUE_DEPTH * MTU_V1 as usize
    + HALF_OPEN_BUFFER_BYTES
    + UDP_BUFFER_BYTES;

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
        // A 256-deep guest-bound queue shared between 64 associations.
        assert_eq!(DATAGRAMS_PER_ASSOCIATION_POLL, 4);
        // 64 associations × 4 datagrams × 1500 bytes.
        assert_eq!(UDP_BUFFER_BYTES, 384_000);
        // 256 flows at that, plus the handle's own 2 × 256 × 1500, plus the
        // SYNs the half-open table holds, plus one poll's datagram batch.
        assert_eq!(
            MEMORY_CEILING_BYTES,
            256 * 176_768 + 768_000 + 96_000 + 384_000
        );
        assert_eq!(MEMORY_CEILING_BYTES, 46_500_608);
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

    /// Associations draw on the same descriptor budget TCP does, and the
    /// batch one poll produces is emptied onto the one machine-wide
    /// guest-bound queue. Both are properties of a *pair* of constants, so
    /// re-sizing either has to be argued for here rather than silently
    /// making a poll produce datagrams it can only drop.
    #[test]
    fn the_association_bounds_fit_the_budget_and_the_queue_they_share() {
        const {
            assert!(
                DEFAULT_MAX_UDP_ASSOCIATIONS * 3 < DEFAULT_MAX_HOST_SOCKETS,
                "associations must not be able to consume the socket budget TCP shares"
            );
            assert!(
                DATAGRAMS_PER_ASSOCIATION_POLL > 0,
                "an association that may take nothing per poll carries no traffic at all"
            );
            assert!(
                DEFAULT_MAX_UDP_ASSOCIATIONS * DATAGRAMS_PER_ASSOCIATION_POLL
                    <= DEFAULT_QUEUE_DEPTH,
                "a poll must not read more datagrams than the queue it empties onto can hold"
            );
        };
        // 1500 byte MTU less a 20 byte IPv4 header and an 8 byte UDP one.
        assert_eq!(MAX_DATAGRAM_PAYLOAD_BYTES, 1_472);
    }
}
