//! Peer, stream, retry and relay-usage bounds for a mailbox transport.
//!
//! [`ResourceLedger`] is plain state with no clock, socket or runtime, so every
//! bound is checkable without a network. A concrete adapter calls the ledger
//! before it acts and releases what it took when the work ends.

use std::collections::BTreeMap;

use super::{TransportIdentity, TransportPath};

/// Hard ceilings a configured [`ResourceLimits`] may not exceed.
const MAX_PEERS: u32 = 4096;
const MAX_STREAMS_PER_PEER: u32 = 256;
const MAX_RETRIES: u32 = 64;

/// Bounds on peers, streams, retries and relayed bytes. Every field is
/// non-zero and below a fixed ceiling; there is no unbounded mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    max_peers: u32,
    max_streams_per_peer: u32,
    max_retries: u32,
    max_relay_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_peers: 64,
            max_streams_per_peer: 8,
            max_retries: 5,
            max_relay_bytes: 64 * 1024 * 1024,
        }
    }
}

impl ResourceLimits {
    #[must_use]
    pub fn builder() -> ResourceLimitsBuilder {
        ResourceLimitsBuilder(Self::default())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ResourceLimitsBuilder(ResourceLimits);

impl ResourceLimitsBuilder {
    #[must_use]
    pub fn max_peers(mut self, value: u32) -> Self {
        self.0.max_peers = value;
        self
    }

    #[must_use]
    pub fn max_streams_per_peer(mut self, value: u32) -> Self {
        self.0.max_streams_per_peer = value;
        self
    }

    #[must_use]
    pub fn max_retries(mut self, value: u32) -> Self {
        self.0.max_retries = value;
        self
    }

    #[must_use]
    pub fn max_relay_bytes(mut self, value: u64) -> Self {
        self.0.max_relay_bytes = value;
        self
    }

    pub fn build(self) -> Result<ResourceLimits, ResourceLimitError> {
        let l = self.0;
        let in_range = |v: u32, ceiling: u32| (1..=ceiling).contains(&v);
        if in_range(l.max_peers, MAX_PEERS)
            && in_range(l.max_streams_per_peer, MAX_STREAMS_PER_PEER)
            && in_range(l.max_retries, MAX_RETRIES)
            && l.max_relay_bytes > 0
        {
            Ok(l)
        } else {
            Err(ResourceLimitError::InvalidLimits)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResourceLimitError {
    #[error("mailbox resource limits are invalid")]
    InvalidLimits,
    #[error("mailbox transport peer limit reached")]
    TooManyPeers,
    #[error("mailbox transport stream limit reached for this peer")]
    TooManyStreams,
    #[error("mailbox transport retry budget exhausted")]
    RetriesExhausted,
    #[error("mailbox relay usage budget exhausted")]
    RelayBudgetExhausted,
}

/// Live usage counted against [`ResourceLimits`].
#[derive(Debug)]
pub struct ResourceLedger {
    limits: ResourceLimits,
    streams: BTreeMap<TransportIdentity, u32>,
    retries: BTreeMap<TransportIdentity, u32>,
    relay_bytes: u64,
}

impl ResourceLedger {
    #[must_use]
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            streams: BTreeMap::new(),
            retries: BTreeMap::new(),
            relay_bytes: 0,
        }
    }

    /// Reserve a stream to `peer`, admitting the peer on its first stream.
    pub fn open_stream(&mut self, peer: TransportIdentity) -> Result<(), ResourceLimitError> {
        let known = self.streams.contains_key(&peer);
        if !known && self.streams.len() >= self.limits.max_peers as usize {
            return Err(ResourceLimitError::TooManyPeers);
        }
        let open = self.streams.entry(peer).or_insert(0);
        if *open >= self.limits.max_streams_per_peer {
            return Err(ResourceLimitError::TooManyStreams);
        }
        *open += 1;
        Ok(())
    }

    /// Release one stream; the peer is forgotten when its last stream closes.
    pub fn close_stream(&mut self, peer: &TransportIdentity) {
        if let Some(open) = self.streams.get_mut(peer) {
            *open = open.saturating_sub(1);
            if *open == 0 {
                self.streams.remove(peer);
            }
        }
    }

    /// Spend one of `peer`'s retries; refused once its budget is used up.
    /// Budgets are per peer, and tracking a new peer counts against `max_peers`.
    pub fn take_retry(&mut self, peer: &TransportIdentity) -> Result<(), ResourceLimitError> {
        if !self.retries.contains_key(peer) && self.retries.len() >= self.limits.max_peers as usize
        {
            return Err(ResourceLimitError::TooManyPeers);
        }
        let used = self.retries.entry(*peer).or_insert(0);
        if *used >= self.limits.max_retries {
            return Err(ResourceLimitError::RetriesExhausted);
        }
        *used += 1;
        Ok(())
    }

    /// A completed delivery to `peer` restores that peer's retry budget only.
    pub fn reset_retries(&mut self, peer: &TransportIdentity) {
        self.retries.remove(peer);
    }

    /// Drop everything held for an abandoned `peer`, freeing its slot. Only an
    /// adapter calls this; a live peer cannot reset its own budget by reconnecting.
    pub fn forget_peer(&mut self, peer: &TransportIdentity) {
        self.streams.remove(peer);
        self.retries.remove(peer);
    }

    /// Charge `bytes` to relay usage. Direct traffic is never charged.
    pub fn charge_relay(
        &mut self,
        path: TransportPath,
        bytes: u64,
    ) -> Result<(), ResourceLimitError> {
        if path == TransportPath::Direct {
            return Ok(());
        }
        let total = self.relay_bytes.saturating_add(bytes);
        if total > self.limits.max_relay_bytes {
            return Err(ResourceLimitError::RelayBudgetExhausted);
        }
        self.relay_bytes = total;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> TransportIdentity {
        TransportIdentity::from_bytes([n; 32])
    }

    fn small() -> ResourceLimits {
        ResourceLimits::builder()
            .max_peers(2)
            .max_streams_per_peer(2)
            .max_retries(2)
            .max_relay_bytes(10)
            .build()
            .expect("limits")
    }

    #[test]
    fn defaults_are_valid_and_zero_or_oversized_values_are_refused() {
        assert!(ResourceLimits::builder().build().is_ok());
        for bad in [
            ResourceLimits::builder().max_peers(0),
            ResourceLimits::builder().max_peers(MAX_PEERS + 1),
            ResourceLimits::builder().max_streams_per_peer(0),
            ResourceLimits::builder().max_retries(MAX_RETRIES + 1),
            ResourceLimits::builder().max_relay_bytes(0),
        ] {
            assert_eq!(bad.build(), Err(ResourceLimitError::InvalidLimits));
        }
        assert!(
            ResourceLimits::builder()
                .max_peers(MAX_PEERS)
                .max_streams_per_peer(MAX_STREAMS_PER_PEER)
                .max_retries(MAX_RETRIES)
                .build()
                .is_ok()
        );
    }

    #[test]
    fn streams_stop_at_the_per_peer_bound_and_free_on_close() {
        let mut ledger = ResourceLedger::new(small());
        ledger.open_stream(peer(1)).expect("first");
        ledger.open_stream(peer(1)).expect("at bound");
        assert_eq!(
            ledger.open_stream(peer(1)),
            Err(ResourceLimitError::TooManyStreams)
        );
        ledger.close_stream(&peer(1));
        ledger.open_stream(peer(1)).expect("slot freed");
    }

    #[test]
    fn peers_stop_at_the_peer_bound_and_a_closed_peer_frees_its_slot() {
        let mut ledger = ResourceLedger::new(small());
        ledger.open_stream(peer(1)).expect("p1");
        ledger.open_stream(peer(2)).expect("p2");
        assert_eq!(
            ledger.open_stream(peer(3)),
            Err(ResourceLimitError::TooManyPeers)
        );
        ledger
            .open_stream(peer(2))
            .expect("known peer still admitted");
        ledger.close_stream(&peer(1));
        ledger.open_stream(peer(3)).expect("slot freed");
    }

    #[test]
    fn retries_are_bounded_per_peer_until_that_peers_delivery_resets_them() {
        let mut ledger = ResourceLedger::new(small());
        ledger.take_retry(&peer(1)).expect("one");
        ledger.take_retry(&peer(1)).expect("two");
        assert_eq!(
            ledger.take_retry(&peer(1)),
            Err(ResourceLimitError::RetriesExhausted)
        );
        ledger.take_retry(&peer(2)).expect("peer B untouched");
        ledger.reset_retries(&peer(2));
        assert_eq!(
            ledger.take_retry(&peer(1)),
            Err(ResourceLimitError::RetriesExhausted)
        );
        ledger.reset_retries(&peer(1));
        ledger.take_retry(&peer(1)).expect("restored");
    }

    #[test]
    fn forgetting_exhausted_peers_frees_their_slots_for_new_peers() {
        let mut ledger = ResourceLedger::new(small());
        for n in [1, 2] {
            ledger.open_stream(peer(n)).expect("stream");
            ledger.take_retry(&peer(n)).expect("one");
            ledger.take_retry(&peer(n)).expect("two");
        }
        assert_eq!(
            ledger.take_retry(&peer(3)),
            Err(ResourceLimitError::TooManyPeers)
        );
        ledger.forget_peer(&peer(1));
        ledger.forget_peer(&peer(2));
        ledger.take_retry(&peer(3)).expect("slot freed");
        ledger.open_stream(peer(4)).expect("stream slot freed");
        assert_eq!(
            ledger.take_retry(&peer(1)),
            Ok(()),
            "a forgotten peer starts over"
        );
    }

    #[test]
    fn retry_tracking_cannot_grow_past_the_peer_bound() {
        let mut ledger = ResourceLedger::new(small());
        ledger.take_retry(&peer(1)).expect("p1");
        ledger.take_retry(&peer(2)).expect("p2");
        assert_eq!(
            ledger.take_retry(&peer(3)),
            Err(ResourceLimitError::TooManyPeers)
        );
    }

    #[test]
    fn relay_bytes_are_bounded_exactly_and_direct_is_free() {
        let mut ledger = ResourceLedger::new(small());
        ledger
            .charge_relay(TransportPath::CustomerRelay, 6)
            .expect("6");
        ledger
            .charge_relay(TransportPath::PublicRelay, 4)
            .expect("exactly 10");
        assert_eq!(
            ledger.charge_relay(TransportPath::CustomerRelay, 1),
            Err(ResourceLimitError::RelayBudgetExhausted)
        );
        ledger
            .charge_relay(TransportPath::Direct, u64::MAX)
            .expect("direct");
        assert_eq!(
            ledger.charge_relay(TransportPath::CustomerRelay, u64::MAX),
            Err(ResourceLimitError::RelayBudgetExhausted)
        );
    }
}
