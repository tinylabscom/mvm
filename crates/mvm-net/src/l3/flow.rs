//! Bounded per-machine flow state.
//!
//! Return traffic is admitted only against an outbound flow this table
//! recorded, so an unsolicited inbound packet has nowhere to match. The
//! table is capped and idle-expiring because a guest that can create
//! unbounded flow entries has a memory-exhaustion primitive against the
//! host.
//!
//! Time is a caller-supplied millisecond counter rather than an `Instant`
//! read: expiry is then a pure function of its inputs, so the tests assert
//! the behaviour instead of waiting for it.

use std::collections::BTreeMap;
use std::net::IpAddr;

/// Default cap on concurrent flows for one machine. A busy HTTP client
/// holds tens; a scanner wants millions. 4096 is comfortably above real
/// workloads and far below anything that threatens the host.
pub const DEFAULT_MAX_FLOWS: usize = 4096;

/// Default idle expiry for a TCP flow.
pub const DEFAULT_TCP_IDLE_MILLIS: u64 = 300_000;

/// Default idle expiry for a UDP or ICMP flow. Short, because there is no
/// close handshake to reclaim them.
pub const DEFAULT_DATAGRAM_IDLE_MILLIS: u64 = 60_000;

/// Identity of a flow, from the guest's point of view. The guest address
/// is not part of the key: a table belongs to exactly one session, which
/// owns exactly one guest address, so including it would only add a field
/// that can never vary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    /// IANA protocol number.
    pub protocol: u8,
    pub guest_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
}

/// Per-flow accounting. Byte and packet counts ride here so a flow-closed
/// audit entry can report them without a second lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowState {
    pub opened_at_millis: u64,
    pub last_seen_millis: u64,
    pub packets_out: u64,
    pub packets_in: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

/// What happened when an outbound packet met the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowAdmission {
    /// First packet of a flow; the entry was created.
    Opened,
    /// An existing flow; its activity timestamp moved.
    Existing,
    /// The table is at capacity. The packet is dropped — evicting a live
    /// flow to make room would let a guest displace its own established
    /// connections, turning a resource limit into a correctness bug.
    TableFull,
}

/// Aggregate counters. Exposed as metrics; never a log line per packet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowCounters {
    pub opened: u64,
    pub closed_idle: u64,
    pub closed_explicit: u64,
    pub rejected_table_full: u64,
    pub inbound_unsolicited: u64,
}

/// Sizing and timing for one machine's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowLimits {
    pub max_flows: usize,
    pub tcp_idle_millis: u64,
    pub datagram_idle_millis: u64,
}

impl Default for FlowLimits {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_FLOWS,
            tcp_idle_millis: DEFAULT_TCP_IDLE_MILLIS,
            datagram_idle_millis: DEFAULT_DATAGRAM_IDLE_MILLIS,
        }
    }
}

/// One machine's flow table.
#[derive(Debug)]
pub struct FlowTable {
    flows: BTreeMap<FlowKey, FlowState>,
    limits: FlowLimits,
    counters: FlowCounters,
}

impl FlowTable {
    pub fn new(limits: FlowLimits) -> Self {
        Self {
            flows: BTreeMap::new(),
            limits,
            counters: FlowCounters::default(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(FlowLimits::default())
    }

    /// Record an outbound packet, opening a flow if this is its first.
    pub fn observe_outbound(&mut self, key: FlowKey, bytes: u64, now_millis: u64) -> FlowAdmission {
        if let Some(state) = self.flows.get_mut(&key) {
            state.last_seen_millis = now_millis;
            state.packets_out += 1;
            state.bytes_out += bytes;
            return FlowAdmission::Existing;
        }
        if self.flows.len() >= self.limits.max_flows {
            self.counters.rejected_table_full += 1;
            return FlowAdmission::TableFull;
        }
        self.flows.insert(
            key,
            FlowState {
                opened_at_millis: now_millis,
                last_seen_millis: now_millis,
                packets_out: 1,
                packets_in: 0,
                bytes_out: bytes,
                bytes_in: 0,
            },
        );
        self.counters.opened += 1;
        FlowAdmission::Opened
    }

    /// Whether an inbound packet matches a live outbound flow. `key` must
    /// already be expressed from the guest's point of view — the caller
    /// reverses the tuple before asking.
    ///
    /// Returns `false` for anything unmatched, which is how unsolicited
    /// inbound traffic is dropped.
    pub fn admit_inbound(&mut self, key: &FlowKey, bytes: u64, now_millis: u64) -> bool {
        match self.flows.get_mut(key) {
            Some(state) => {
                state.last_seen_millis = now_millis;
                state.packets_in += 1;
                state.bytes_in += bytes;
                true
            }
            None => {
                self.counters.inbound_unsolicited += 1;
                false
            }
        }
    }

    /// Drop flows idle past their protocol's timeout. Returns the closed
    /// entries so the caller can emit one flow-closed audit record each,
    /// with final byte counts.
    pub fn expire_idle(&mut self, now_millis: u64) -> Vec<(FlowKey, FlowState)> {
        let tcp_idle = self.limits.tcp_idle_millis;
        let dgram_idle = self.limits.datagram_idle_millis;
        let expired: Vec<_> = self
            .flows
            .iter()
            .filter(|(key, state)| {
                let idle = now_millis.saturating_sub(state.last_seen_millis);
                let limit = if key.protocol == mvm_contract::l3::proto::TCP {
                    tcp_idle
                } else {
                    dgram_idle
                };
                idle >= limit
            })
            .map(|(key, state)| (*key, *state))
            .collect();
        for (key, _) in &expired {
            self.flows.remove(key);
        }
        self.counters.closed_idle += expired.len() as u64;
        expired
    }

    /// Close one flow explicitly (TCP RST/FIN teardown, or session end).
    pub fn close(&mut self, key: &FlowKey) -> Option<FlowState> {
        let state = self.flows.remove(key);
        if state.is_some() {
            self.counters.closed_explicit += 1;
        }
        state
    }

    /// Drop every flow. Called when a session ends, so no state outlives
    /// the boot it belonged to.
    pub fn clear(&mut self) -> Vec<(FlowKey, FlowState)> {
        let all: Vec<_> = self.flows.iter().map(|(k, v)| (*k, *v)).collect();
        self.flows.clear();
        self.counters.closed_explicit += all.len() as u64;
        all
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn counters(&self) -> FlowCounters {
        self.counters
    }

    pub fn limits(&self) -> FlowLimits {
        self.limits
    }

    pub fn get(&self, key: &FlowKey) -> Option<&FlowState> {
        self.flows.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::l3::proto;
    use std::net::Ipv4Addr;

    fn key(protocol: u8, guest_port: u16, remote_port: u16) -> FlowKey {
        FlowKey {
            protocol,
            guest_port,
            remote: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            remote_port,
        }
    }

    #[test]
    fn the_first_outbound_packet_opens_a_flow() {
        let mut table = FlowTable::with_defaults();
        assert_eq!(
            table.observe_outbound(key(proto::TCP, 50000, 443), 60, 0),
            FlowAdmission::Opened
        );
        assert_eq!(table.len(), 1);
        assert_eq!(table.counters().opened, 1);
    }

    #[test]
    fn subsequent_packets_reuse_the_flow_and_accumulate_bytes() {
        let mut table = FlowTable::with_defaults();
        let k = key(proto::TCP, 50000, 443);
        table.observe_outbound(k, 60, 0);
        assert_eq!(table.observe_outbound(k, 100, 10), FlowAdmission::Existing);
        let state = table.get(&k).unwrap();
        assert_eq!(state.packets_out, 2);
        assert_eq!(state.bytes_out, 160);
        assert_eq!(state.last_seen_millis, 10);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn return_traffic_is_admitted_only_for_an_established_flow() {
        let mut table = FlowTable::with_defaults();
        let k = key(proto::TCP, 50000, 443);
        assert!(
            !table.admit_inbound(&k, 60, 0),
            "inbound before any outbound must be refused"
        );
        table.observe_outbound(k, 60, 0);
        assert!(table.admit_inbound(&k, 1400, 5));
        assert_eq!(table.get(&k).unwrap().bytes_in, 1400);
    }

    #[test]
    fn unsolicited_inbound_is_counted_not_silently_ignored() {
        let mut table = FlowTable::with_defaults();
        for port in 0..5u16 {
            table.admit_inbound(&key(proto::TCP, 8080, port), 40, 0);
        }
        assert_eq!(table.counters().inbound_unsolicited, 5);
        assert!(
            table.is_empty(),
            "a refused inbound packet creates no state"
        );
    }

    #[test]
    fn a_flow_to_a_different_port_is_a_different_flow() {
        let mut table = FlowTable::with_defaults();
        table.observe_outbound(key(proto::TCP, 50000, 443), 60, 0);
        assert!(
            !table.admit_inbound(&key(proto::TCP, 50000, 8443), 60, 0),
            "a reply from an unrelated port must not match"
        );
    }

    #[test]
    fn a_flow_to_a_different_host_is_a_different_flow() {
        let mut table = FlowTable::with_defaults();
        table.observe_outbound(key(proto::TCP, 50000, 443), 60, 0);
        let other = FlowKey {
            remote: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ..key(proto::TCP, 50000, 443)
        };
        assert!(!table.admit_inbound(&other, 60, 0));
    }

    #[test]
    fn the_table_fails_closed_at_capacity_without_evicting_live_flows() {
        let mut table = FlowTable::new(FlowLimits {
            max_flows: 4,
            ..FlowLimits::default()
        });
        for port in 0..4u16 {
            assert_eq!(
                table.observe_outbound(key(proto::TCP, 40000 + port, 443), 60, 0),
                FlowAdmission::Opened
            );
        }
        assert_eq!(
            table.observe_outbound(key(proto::TCP, 49999, 443), 60, 0),
            FlowAdmission::TableFull
        );
        assert_eq!(table.len(), 4, "no live flow may be displaced");
        assert_eq!(table.counters().rejected_table_full, 1);
        // The established flows still work.
        assert!(table.admit_inbound(&key(proto::TCP, 40000, 443), 60, 1));
    }

    #[test]
    fn tcp_flows_expire_on_their_own_longer_timeout() {
        let mut table = FlowTable::with_defaults();
        let k = key(proto::TCP, 50000, 443);
        table.observe_outbound(k, 60, 0);
        assert!(table.expire_idle(DEFAULT_TCP_IDLE_MILLIS - 1).is_empty());
        let expired = table.expire_idle(DEFAULT_TCP_IDLE_MILLIS);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, k);
        assert!(table.is_empty());
        assert_eq!(table.counters().closed_idle, 1);
    }

    #[test]
    fn datagram_flows_expire_sooner_than_tcp_flows() {
        let mut table = FlowTable::with_defaults();
        let udp = key(proto::UDP, 50000, 53);
        let tcp = key(proto::TCP, 50000, 443);
        table.observe_outbound(udp, 60, 0);
        table.observe_outbound(tcp, 60, 0);
        let expired = table.expire_idle(DEFAULT_DATAGRAM_IDLE_MILLIS);
        assert_eq!(expired.len(), 1, "only the datagram flow should be gone");
        assert_eq!(expired[0].0, udp);
        assert!(table.get(&tcp).is_some());
    }

    #[test]
    fn activity_refreshes_the_idle_clock() {
        let mut table = FlowTable::with_defaults();
        let k = key(proto::UDP, 50000, 53);
        table.observe_outbound(k, 60, 0);
        table.observe_outbound(k, 60, DEFAULT_DATAGRAM_IDLE_MILLIS - 1);
        assert!(
            table.expire_idle(DEFAULT_DATAGRAM_IDLE_MILLIS).is_empty(),
            "a flow touched recently must survive"
        );
    }

    #[test]
    fn expiry_returns_final_counts_for_the_audit_record() {
        let mut table = FlowTable::with_defaults();
        let k = key(proto::UDP, 50000, 53);
        table.observe_outbound(k, 70, 0);
        table.admit_inbound(&k, 200, 1);
        // The inbound packet refreshed the clock, so expiry is measured
        // from t=1, not t=0.
        let expired = table.expire_idle(DEFAULT_DATAGRAM_IDLE_MILLIS + 1);
        let (_, state) = expired[0];
        assert_eq!(state.bytes_out, 70);
        assert_eq!(state.bytes_in, 200);
        assert_eq!(state.packets_out, 1);
        assert_eq!(state.packets_in, 1);
    }

    #[test]
    fn clearing_drops_every_flow_so_none_outlives_the_session() {
        let mut table = FlowTable::with_defaults();
        for port in 0..10u16 {
            table.observe_outbound(key(proto::TCP, 40000 + port, 443), 60, 0);
        }
        let closed = table.clear();
        assert_eq!(closed.len(), 10);
        assert!(table.is_empty());
        // Return traffic for a cleared flow no longer matches.
        assert!(!table.admit_inbound(&key(proto::TCP, 40000, 443), 60, 1));
    }

    #[test]
    fn explicit_close_removes_exactly_one_flow() {
        let mut table = FlowTable::with_defaults();
        let a = key(proto::TCP, 50000, 443);
        let b = key(proto::TCP, 50001, 443);
        table.observe_outbound(a, 60, 0);
        table.observe_outbound(b, 60, 0);
        assert!(table.close(&a).is_some());
        assert!(table.close(&a).is_none(), "closing twice is a no-op");
        assert_eq!(table.len(), 1);
        assert!(table.get(&b).is_some());
    }
}
