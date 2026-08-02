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
}

/// The virtual NIC smoltcp drives, backed by two bounded packet queues.
pub struct GuestDevice {
    mtu: usize,
    queue_depth: usize,
    /// Packets the guest sent, awaiting delivery to the stack. This is
    /// smoltcp's receive side — see the module doc for why.
    from_guest: VecDeque<Vec<u8>>,
    /// Packets the stack produced, awaiting delivery to the guest. This is
    /// smoltcp's transmit side.
    to_guest: VecDeque<Vec<u8>>,
}

impl GuestDevice {
    pub fn new(mtu: usize, queue_depth: usize) -> Self {
        Self {
            mtu,
            queue_depth,
            from_guest: VecDeque::new(),
            to_guest: VecDeque::new(),
        }
    }

    /// Admit a packet that arrived from the guest.
    ///
    /// The caller counts `DroppedQueueFull` as a metric, so it must be
    /// reported rather than swallowed.
    pub fn push_from_guest(&mut self, bytes: &[u8]) -> PushOutcome {
        if self.from_guest.len() >= self.queue_depth {
            return PushOutcome::DroppedQueueFull;
        }
        self.from_guest.push_back(bytes.to_vec());
        PushOutcome::Queued
    }

    /// Drain one packet the stack produced for the guest, oldest first.
    pub fn pop_for_guest(&mut self) -> Option<Vec<u8>> {
        self.to_guest.pop_front()
    }

    /// How many guest-sent packets are waiting on the stack to consume
    /// them.
    pub fn pending_from_guest(&self) -> usize {
        self.from_guest.len()
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
        Some((
            GuestRxToken { buffer },
            GuestTxToken {
                queue: &mut self.to_guest,
                queue_depth: self.queue_depth,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(GuestTxToken {
            queue: &mut self.to_guest,
            queue_depth: self.queue_depth,
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
        // queue without bound.
        if self.queue.len() < self.queue_depth {
            self.queue.push_back(buffer);
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
        let mut dev = GuestDevice::new(1500, 64);
        assert_eq!(dev.push_from_guest(&ipv4_stub()), PushOutcome::Queued);
        assert_eq!(dev.pending_from_guest(), 1);
    }

    #[test]
    fn the_queue_drops_rather_than_growing_without_bound() {
        let mut dev = GuestDevice::new(1500, 2);
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

    #[test]
    fn a_full_queue_drops_the_new_packet_and_keeps_the_old() {
        let mut dev = GuestDevice::new(1500, 1);
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
