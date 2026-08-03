//! The guest-facing smoltcp device.
//!
//! smoltcp drives a TCP/IP stack through `phy::Device`, which expects a
//! NIC underneath. There is no NIC here — only two bounded queues that
//! stand in for one.
//!
//! Direction is inverted from what the names outside this module suggest,
//! because smoltcp is playing the role of the *remote peer* the guest is
//! talking to, not the guest itself. A packet the guest sent is, from
//! smoltcp's point of view, arriving from the network, so `push_from_guest`
//! feeds the device's receive queue. A packet smoltcp transmits is destined
//! for the guest, so it lands in the queue `pop_for_guest` drains. Get this
//! backwards and every connection runs in the wrong direction while still
//! compiling.
//!
//! Both queues are bounded. A guest that outruns the stack, or a stack that
//! outruns the guest's drain, hits the queue bound rather than the host's
//! memory.

use std::collections::VecDeque;

use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

/// What happened to a packet offered to a bounded queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// The packet was accepted.
    Queued,
    /// The queue was at capacity. The new packet was dropped; nothing
    /// already queued was evicted to make room, so an established
    /// conversation never loses a packet to a newcomer.
    DroppedQueueFull,
    /// The packet was larger than the link's MTU.
    ///
    /// Refused here rather than only at the datapath's own entry point, so
    /// that every way into these queues is covered by one check. The queues
    /// bound packet *count*; an oversized packet would sit in one at its
    /// full size and put the per-flow byte bound out by however much the
    /// sender chose.
    DroppedOversized,
}

/// How deep each of the two queues is allowed to be.
///
/// Named rather than two bare `usize` arguments in a row: the two are no
/// longer equal, and transposing them would give the guest-bound queue a
/// depth argued for the guest-facing one — a silent, expensive mistake
/// that reads correctly at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueDepths {
    /// Packets the guest may have waiting on the stack.
    pub from_guest: usize,
    /// Packets the stack may have waiting on the guest's drain.
    pub to_guest: usize,
}

impl QueueDepths {
    /// The same depth both ways, for a device whose stack emits nothing.
    pub fn symmetric(depth: usize) -> Self {
        Self {
            from_guest: depth,
            to_guest: depth,
        }
    }
}

/// The virtual NIC smoltcp drives, backed by two bounded packet queues.
pub struct GuestDevice {
    mtu: usize,
    depths: QueueDepths,
    /// Packets the guest sent, awaiting delivery to the stack. This is
    /// smoltcp's receive side — see the module doc for why.
    from_guest: VecDeque<Vec<u8>>,
    /// Packets the stack produced, awaiting delivery to the guest. This is
    /// smoltcp's transmit side.
    to_guest: VecDeque<Vec<u8>>,
    /// See [`GuestDevice::dropped_to_guest`].
    dropped_to_guest: u64,
}

impl GuestDevice {
    pub fn new(mtu: usize, depths: QueueDepths) -> Self {
        Self {
            mtu,
            depths,
            from_guest: VecDeque::new(),
            to_guest: VecDeque::new(),
            dropped_to_guest: 0,
        }
    }

    /// Admit a packet that arrived from the guest.
    ///
    /// The caller counts every non-`Queued` outcome as a metric, so each
    /// must be reported rather than swallowed.
    pub fn push_from_guest(&mut self, bytes: &[u8]) -> PushOutcome {
        if bytes.len() > self.mtu {
            return PushOutcome::DroppedOversized;
        }
        if self.from_guest.len() >= self.depths.from_guest {
            return PushOutcome::DroppedQueueFull;
        }
        self.from_guest.push_back(bytes.to_vec());
        PushOutcome::Queued
    }

    /// Queue a packet for the guest that the stack did not produce.
    ///
    /// The resets a datapath owes a guest whose *connect* failed have no
    /// stack behind them — the whole point of the deferred handshake is
    /// that no stack was ever built for a destination that refused — so
    /// they need a way onto this queue that does not go through a
    /// [`phy::TxToken`].
    ///
    /// Bounded and counted exactly like the stack's own path: same depth,
    /// same drop-the-newcomer rule, same counter. A second queue with its
    /// own bound would be a second thing to size and a second thing to get
    /// wrong.
    pub fn push_to_guest(&mut self, bytes: Vec<u8>) -> PushOutcome {
        if bytes.len() > self.mtu {
            return PushOutcome::DroppedOversized;
        }
        if self.to_guest.len() >= self.depths.to_guest {
            self.dropped_to_guest = self.dropped_to_guest.saturating_add(1);
            return PushOutcome::DroppedQueueFull;
        }
        self.to_guest.push_back(bytes);
        PushOutcome::Queued
    }

    /// Drain one packet the stack produced for the guest, oldest first.
    pub fn pop_for_guest(&mut self) -> Option<Vec<u8>> {
        self.to_guest.pop_front()
    }

    /// How many packets are waiting on the guest to drain them.
    pub fn pending_to_guest(&self) -> usize {
        self.to_guest.len()
    }

    /// How many guest-sent packets are waiting on the stack to consume
    /// them.
    pub fn pending_from_guest(&self) -> usize {
        self.from_guest.len()
    }

    /// Stack-produced packets dropped because the guest-bound queue was
    /// full.
    ///
    /// Counted, because unlike the guest-facing side this drop has no
    /// caller to return an outcome to. smoltcp hands a segment to the
    /// transmit token and considers it sent; discarding it silently costs
    /// the guest a retransmission timeout — seconds — with nothing
    /// anywhere to say why. A drop the host cannot see is a drop nobody
    /// will ever debug.
    ///
    /// The flow folds the delta into `GatewayMetrics::queue_drops_egress`
    /// each pass, so this is the debugger's view and the counter is the
    /// operator's.
    pub fn dropped_to_guest(&self) -> u64 {
        self.dropped_to_guest
    }

    /// Bytes held across both queues.
    ///
    /// The queues bound themselves by packet *count*, but the footprint a
    /// memory ceiling has to model is bytes, and the two differ by up to
    /// an MTU per packet. Summed on demand rather than tracked
    /// incrementally: it is a sum over at most a queue's depth of entries, and
    /// a running total is one more thing that can drift out of step with
    /// the queues it claims to describe.
    pub fn bytes_queued(&self) -> usize {
        let sum = |q: &VecDeque<Vec<u8>>| q.iter().map(Vec::len).sum::<usize>();
        sum(&self.from_guest) + sum(&self.to_guest)
    }

    /// Look at the oldest guest-sent packet without dequeuing it. Test-only:
    /// production callers drain through the smoltcp stack, which consumes
    /// via `Device::receive`, never by peeking.
    #[cfg(test)]
    pub(crate) fn peek_from_guest(&self) -> Option<&[u8]> {
        self.from_guest.front().map(Vec::as_slice)
    }
}

impl Device for GuestDevice {
    type RxToken<'a> = GuestRxToken;
    type TxToken<'a> = GuestTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.from_guest.pop_front()?;
        let queue_depth = self.depths.to_guest;
        let Self {
            to_guest,
            dropped_to_guest,
            ..
        } = self;
        Some((
            GuestRxToken { buffer },
            GuestTxToken {
                queue: to_guest,
                queue_depth,
                dropped: dropped_to_guest,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let queue_depth = self.depths.to_guest;
        let Self {
            to_guest,
            dropped_to_guest,
            ..
        } = self;
        Some(GuestTxToken {
            queue: to_guest,
            queue_depth,
            dropped: dropped_to_guest,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        // Bare IP, no Ethernet header and no ARP: the guest link carries
        // IP packets directly, so this is the only medium smoltcp is built
        // with in this workspace.
        caps.medium = Medium::Ip;
        caps
    }
}

/// Hands one guest-sent packet to the stack.
pub struct GuestRxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for GuestRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

/// Accepts one stack-produced packet destined for the guest.
pub struct GuestTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    queue_depth: usize,
    /// Where a discarded segment is recorded. See
    /// [`GuestDevice::dropped_to_guest`].
    dropped: &'a mut u64,
}

impl<'a> phy::TxToken for GuestTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        // The same drop-the-newcomer rule as the guest→stack side: if the
        // guest stalls its drain, the stack must not be able to grow this
        // queue without bound. Counted on the way out, because smoltcp has
        // already treated this segment as sent.
        if self.queue.len() < self.queue_depth {
            self.queue.push_back(buffer);
        } else {
            *self.dropped = self.dropped.saturating_add(1);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_stub() -> Vec<u8> {
        // Minimal well-formed-enough IPv4 header for queue plumbing; the
        // stack is not parsing it in these tests.
        vec![
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1,
        ]
    }

    #[test]
    fn a_packet_pushed_from_the_guest_is_visible_to_the_stack() {
        let mut dev = GuestDevice::new(1500, QueueDepths::symmetric(64));
        assert_eq!(dev.push_from_guest(&ipv4_stub()), PushOutcome::Queued);
        assert_eq!(dev.pending_from_guest(), 1);
    }

    #[test]
    fn the_queue_drops_rather_than_growing_without_bound() {
        let mut dev = GuestDevice::new(1500, QueueDepths::symmetric(2));
        let outcomes: Vec<_> = (0..10).map(|_| dev.push_from_guest(&ipv4_stub())).collect();
        assert_eq!(
            dev.pending_from_guest(),
            2,
            "a guest that outruns the stack must hit the queue bound, not the host's memory"
        );
        assert!(
            outcomes
                .iter()
                .filter(|o| **o == PushOutcome::DroppedQueueFull)
                .count()
                == 8,
            "every packet past the bound must report a drop, so the caller can count it"
        );
    }

    /// The queues bound packets; the ceiling is denominated in bytes. A
    /// count that did not translate to bytes would let the footprint be
    /// measured against the wrong quantity.
    #[test]
    fn the_queues_report_the_bytes_they_hold_not_just_the_packets() {
        let mut dev = GuestDevice::new(1500, QueueDepths::symmetric(4));
        assert_eq!(dev.bytes_queued(), 0);
        dev.push_from_guest(&ipv4_stub());
        dev.push_from_guest(&ipv4_stub());
        assert_eq!(dev.bytes_queued(), 2 * ipv4_stub().len());
        // Past the bound nothing is added, so nothing is counted either.
        let mut dev = GuestDevice::new(1500, QueueDepths::symmetric(1));
        for _ in 0..10 {
            dev.push_from_guest(&ipv4_stub());
        }
        assert_eq!(dev.bytes_queued(), ipv4_stub().len());
    }

    /// The device is the backstop for every entry point, not just the one
    /// the datapath handle guards.
    #[test]
    fn a_packet_larger_than_the_mtu_is_refused_by_the_device_itself() {
        let mut dev = GuestDevice::new(1500, QueueDepths::symmetric(4));
        assert_eq!(
            dev.push_from_guest(&vec![0u8; 1501]),
            PushOutcome::DroppedOversized
        );
        assert_eq!(dev.push_from_guest(&vec![0u8; 1500]), PushOutcome::Queued);
        assert_eq!(dev.pending_from_guest(), 1);
    }

    /// A host-originated packet takes the same bounded path as a
    /// stack-produced one, or it is a second unbounded queue in disguise.
    #[test]
    fn a_host_originated_packet_reaches_the_guest_under_the_same_bound() {
        let mut dev = GuestDevice::new(
            1500,
            QueueDepths {
                from_guest: 4,
                to_guest: 2,
            },
        );
        assert_eq!(dev.push_to_guest(ipv4_stub()), PushOutcome::Queued);
        assert_eq!(dev.push_to_guest(ipv4_stub()), PushOutcome::Queued);
        assert_eq!(dev.pending_to_guest(), 2);
        assert_eq!(
            dev.push_to_guest(ipv4_stub()),
            PushOutcome::DroppedQueueFull
        );
        assert_eq!(
            dev.dropped_to_guest(),
            1,
            "a drop on this path must be as countable as one on the stack's"
        );
        assert_eq!(
            dev.push_to_guest(vec![0u8; 1501]),
            PushOutcome::DroppedOversized
        );
        assert_eq!(dev.pop_for_guest(), Some(ipv4_stub()));
        assert_eq!(dev.pending_to_guest(), 1);
    }

    /// The two depths are not interchangeable, so a device built with
    /// them transposed must behave differently — otherwise nothing would
    /// catch the transposition at the call site.
    #[test]
    fn each_direction_is_bounded_by_its_own_depth() {
        let mut dev = GuestDevice::new(
            1500,
            QueueDepths {
                from_guest: 1,
                to_guest: 3,
            },
        );
        assert_eq!(dev.push_from_guest(&ipv4_stub()), PushOutcome::Queued);
        assert_eq!(
            dev.push_from_guest(&ipv4_stub()),
            PushOutcome::DroppedQueueFull,
            "the guest-facing queue must use its own depth, not the guest-bound one"
        );

        // And the guest-bound queue takes three before it starts counting.
        for _ in 0..4 {
            phy::TxToken::consume(
                Device::transmit(&mut dev, Instant::from_millis(0)).expect("a transmit token"),
                4,
                |b| b.fill(0),
            );
        }
        assert_eq!(
            dev.dropped_to_guest(),
            1,
            "a fourth segment against a depth of three is one drop, not four"
        );
    }

    #[test]
    fn a_full_queue_drops_the_new_packet_and_keeps_the_old() {
        let mut dev = GuestDevice::new(1500, QueueDepths::symmetric(1));
        let first = ipv4_stub();
        dev.push_from_guest(&first);
        let mut second = ipv4_stub();
        second[19] = 0x09; // distinguishable
        dev.push_from_guest(&second);
        // Whatever the stack receives must be the FIRST packet: at capacity
        // we drop the newcomer, we never evict a live entry.
        assert_eq!(dev.peek_from_guest(), Some(first.as_slice()));
    }
}
