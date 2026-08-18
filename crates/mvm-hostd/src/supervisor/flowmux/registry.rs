//! Per-stream registries for one FlowMux session.
//!
//! A `StreamRegistry` owns the stream/association life cycle on the host side
//! of one FlowMux session: odd stream IDs for guest-initiated flows (`OpenTcp`,
//! `OpenUdp`), even IDs for host-initiated ingress, explicit state transitions,
//! and per-stream credit windows. It performs no I/O; the `FlowMuxSession`
//! drives sockets and the registry answers "is this ID valid?", "can we accept
//! another?", and "how much credit remains?".

use std::collections::BTreeMap;
use std::time::Duration;

use mvm_contract::protocol::network_flow::{Direction, MAX_STREAM_CREDIT};
use tracing::warn;

/// Why a stream/association operation was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    /// The requested stream ID is outside the allowed space or parity.
    #[error("invalid stream id {stream_id}")]
    InvalidStreamId { stream_id: u32 },
    /// A new flow cannot be admitted because the matching ceiling is hit.
    #[error("{class} ceiling reached ({limit})")]
    Ceiling { class: FlowClass, limit: usize },
    /// The stream ID is not currently live.
    #[error("stream {stream_id} is not live")]
    NotLive { stream_id: u32 },
    /// The operation is illegal in the stream's current state.
    #[error("stream {stream_id} is in state {state:?}")]
    IllegalState { stream_id: u32, state: StreamState },
}

/// The class of FlowMux flow that a registry entry represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowClass {
    Tcp,
    Udp,
    Dns,
    /// A typed HTTP flow the host may transform before forwarding.
    Http,
    /// A one-shot ICMP echo exchange.
    Icmp,
}

impl std::fmt::Display for FlowClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowClass::Tcp => write!(f, "tcp"),
            FlowClass::Udp => write!(f, "udp"),
            FlowClass::Dns => write!(f, "dns"),
            FlowClass::Http => write!(f, "http"),
            FlowClass::Icmp => write!(f, "icmp"),
        }
    }
}

/// Life-cycle state of a TCP stream or UDP association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// `OpenTcp`/`OpenUdp`/`InboundOpen` received, host has not yet confirmed.
    Opening,
    /// Host sent `Opened`/`UdpOpened`; data may flow.
    Open,
    /// One side has sent `Close`; the other direction may still send.
    HalfClosed,
    /// Fully closed; the ID is retired and may not be reused.
    Closed,
}

/// Per-stream bookkeeping. The payload bytes are held outside the registry by
/// the session's I/O tasks; here we only track windows and state.
#[derive(Debug)]
pub struct StreamEntry {
    pub class: FlowClass,
    pub state: StreamState,
    pub guest_credit: u32,
    pub host_credit: u32,
}

/// Resource ceilings and runtime bounds for one registry.
#[derive(Debug, Clone, Copy)]
pub struct RegistryLimits {
    pub max_tcp: usize,
    pub max_udp: usize,
    pub max_dns: usize,
    /// Concurrent typed HTTP flows.
    pub max_http: usize,
    /// Concurrent in-flight ICMP echoes.
    pub max_icmp: usize,
    pub initial_credit: u32,
    /// How long a UDP association may sit idle before the host closes it.
    pub udp_idle_timeout: Duration,
    /// Maximum distinct peers a single UDP association may communicate with.
    pub max_udp_peers: usize,
    /// New TCP connection attempts per second (burst == rate). Zero disables
    /// the limiter.
    pub tcp_connect_rate: u32,
    /// New UDP association opens per second (burst == rate). Zero disables.
    pub udp_open_rate: u32,
    /// DNS resolve requests per second (burst == rate). Zero disables.
    pub dns_resolve_rate: u32,
    /// ICMP echoes per second (burst == rate). Zero disables.
    pub icmp_echo_rate: u32,
    /// How long a relay waits for the guest to return credit before giving up
    /// on the stream. Sits beside `initial_credit` because it is the other half
    /// of the same window: one says how much room the guest starts with, this
    /// says how long the host will wait to get it back.
    pub credit_wait: Duration,
}

impl Default for RegistryLimits {
    fn default() -> Self {
        Self {
            max_tcp: 4096,
            max_udp: 256,
            max_dns: 256,
            max_http: 256,
            max_icmp: 64,
            initial_credit: 64 * 1024,
            udp_idle_timeout: Duration::from_secs(60),
            max_udp_peers: 16,
            tcp_connect_rate: 0,
            udp_open_rate: 0,
            dns_resolve_rate: 0,
            icmp_echo_rate: 0,
            credit_wait: Duration::from_secs(30),
        }
    }
}

/// Host-side registry for one authenticated FlowMux session.
#[derive(Debug)]
pub struct StreamRegistry {
    limits: RegistryLimits,
    next_guest_id: u32,
    next_host_id: u32,
    streams: BTreeMap<u32, StreamEntry>,
}

impl StreamRegistry {
    /// Create a registry with the given ceilings.
    #[must_use]
    pub fn new(limits: RegistryLimits) -> Self {
        Self {
            limits,
            next_guest_id: 1, // guest-initiated IDs are odd
            next_host_id: 0,  // host-initiated IDs are even
            streams: BTreeMap::new(),
        }
    }

    /// How many live streams of `class` exist.
    ///
    /// One filter for every class: the per-class wrappers below differed only
    /// in the variant they named, so a new class had to remember to add a
    /// fourth copy or be silently uncounted against its own ceiling.
    #[must_use]
    pub fn live_in_class(&self, class: FlowClass) -> usize {
        self.streams
            .values()
            .filter(|e| e.class == class && e.state != StreamState::Closed)
            .count()
    }

    /// How many live TCP streams exist.
    #[must_use]
    pub fn live_tcp(&self) -> usize {
        self.live_in_class(FlowClass::Tcp)
    }

    /// How many live UDP associations exist.
    #[must_use]
    pub fn live_udp(&self) -> usize {
        self.live_in_class(FlowClass::Udp)
    }

    /// How many live DNS resolution streams exist.
    #[must_use]
    pub fn live_dns(&self) -> usize {
        self.live_in_class(FlowClass::Dns)
    }

    /// How many live typed HTTP flows exist.
    #[must_use]
    pub fn live_http(&self) -> usize {
        self.live_in_class(FlowClass::Http)
    }

    /// Return the entry for a live stream, if any.
    #[must_use]
    pub fn get(&self, stream_id: u32) -> Option<&StreamEntry> {
        self.streams
            .get(&stream_id)
            .filter(|e| e.state != StreamState::Closed)
    }

    /// Allocate a fresh guest-initiated stream ID for `class` and record it as
    /// `Opening`. Guest-initiated IDs are odd and monotonically increasing.
    ///
    /// # Errors
    ///
    /// Returns `RegistryError::Ceiling` if the class ceiling is already hit, or
    /// `RegistryError::InvalidStreamId` if the ID space wrapped.
    pub fn alloc_guest(&mut self, class: FlowClass) -> Result<u32, RegistryError> {
        let limit = self.class_limit(class);
        if self.live_count(class) >= limit {
            return Err(RegistryError::Ceiling { class, limit });
        }
        let id = self.next_guest_id;
        if id.is_multiple_of(2) {
            // Defensive: the allocator should always produce odd IDs.
            return Err(RegistryError::InvalidStreamId { stream_id: id });
        }
        self.next_guest_id = id.checked_add(2).ok_or(RegistryError::InvalidStreamId {
            stream_id: u32::MAX,
        })?;
        self.insert(id, class);
        Ok(id)
    }

    /// Record a guest-initiated stream ID supplied by the peer. The ID must be
    /// odd, not already live, and within the class ceiling.
    pub fn open_guest(&mut self, stream_id: u32, class: FlowClass) -> Result<(), RegistryError> {
        if stream_id == 0 || stream_id.is_multiple_of(2) {
            return Err(RegistryError::InvalidStreamId { stream_id });
        }
        if self.live_count(class) >= self.class_limit(class) {
            return Err(RegistryError::Ceiling {
                class,
                limit: self.class_limit(class),
            });
        }
        if self.streams.contains_key(&stream_id) {
            return Err(RegistryError::IllegalState {
                stream_id,
                state: StreamState::Opening,
            });
        }
        self.next_guest_id = self.next_guest_id.max(stream_id + 2);
        self.insert(stream_id, class);
        Ok(())
    }

    /// Record a host-initiated stream ID supplied by the local ingress handler.
    /// The ID must be even, not already live, and within the class ceiling.
    pub fn open_host(&mut self, stream_id: u32, class: FlowClass) -> Result<(), RegistryError> {
        if !stream_id.is_multiple_of(2) {
            return Err(RegistryError::InvalidStreamId { stream_id });
        }
        if self.live_count(class) >= self.class_limit(class) {
            return Err(RegistryError::Ceiling {
                class,
                limit: self.class_limit(class),
            });
        }
        if self.streams.contains_key(&stream_id) {
            return Err(RegistryError::IllegalState {
                stream_id,
                state: StreamState::Opening,
            });
        }
        self.next_host_id = self.next_host_id.max(stream_id + 2);
        self.insert(stream_id, class);
        Ok(())
    }

    fn class_limit(&self, class: FlowClass) -> usize {
        match class {
            FlowClass::Tcp => self.limits.max_tcp,
            FlowClass::Udp => self.limits.max_udp,
            FlowClass::Dns => self.limits.max_dns,
            FlowClass::Http => self.limits.max_http,
            FlowClass::Icmp => self.limits.max_icmp,
        }
    }

    /// Allocate a fresh host-initiated (ingress) stream ID for `class` and
    /// record it as `Opening`. Host-initiated IDs are even and monotonically
    /// increasing.
    pub fn alloc_host(&mut self, class: FlowClass) -> Result<u32, RegistryError> {
        let limit = self.class_limit(class);
        if self.live_count(class) >= limit {
            return Err(RegistryError::Ceiling { class, limit });
        }
        let id = self.next_host_id;
        if !id.is_multiple_of(2) {
            return Err(RegistryError::InvalidStreamId { stream_id: id });
        }
        self.next_host_id = id.checked_add(2).ok_or(RegistryError::InvalidStreamId {
            stream_id: u32::MAX,
        })?;
        self.insert(id, class);
        Ok(id)
    }

    /// Confirm an `Opening` stream as `Open`. Called when the host finishes the
    /// external socket setup and sends `Opened`/`UdpOpened`.
    pub fn confirm(&mut self, stream_id: u32) -> Result<(), RegistryError> {
        let entry = self
            .streams
            .get_mut(&stream_id)
            .ok_or(RegistryError::NotLive { stream_id })?;
        if entry.state != StreamState::Opening {
            return Err(RegistryError::IllegalState {
                stream_id,
                state: entry.state,
            });
        }
        entry.state = StreamState::Open;
        Ok(())
    }

    /// Move a stream to `HalfClosed`. The first `Close` on an `Open` stream
    /// transitions here; a second `Close` (or `Reset`) fully retires it.
    pub fn half_close(&mut self, stream_id: u32) -> Result<(), RegistryError> {
        let entry = self
            .streams
            .get_mut(&stream_id)
            .ok_or(RegistryError::NotLive { stream_id })?;
        match entry.state {
            StreamState::Open => {
                entry.state = StreamState::HalfClosed;
                Ok(())
            }
            StreamState::HalfClosed | StreamState::Closed => {
                // Already half-closed or fully closed: treat as no-op rather
                // than an error so a duplicate close does not tear the session.
                Ok(())
            }
            state => Err(RegistryError::IllegalState { stream_id, state }),
        }
    }

    /// Retire a stream. `Reset` always retires immediately; a second `Close`
    /// on a `HalfClosed` stream also retires it.
    pub fn retire(&mut self, stream_id: u32) -> Result<(), RegistryError> {
        let entry = self
            .streams
            .get_mut(&stream_id)
            .ok_or(RegistryError::NotLive { stream_id })?;
        entry.state = StreamState::Closed;
        Ok(())
    }

    /// Consume `len` bytes of guest credit on `stream_id`.
    pub fn consume_guest_credit(&mut self, stream_id: u32, len: u32) -> Result<(), RegistryError> {
        let entry = self
            .streams
            .get_mut(&stream_id)
            .ok_or(RegistryError::NotLive { stream_id })?;
        if len > entry.guest_credit {
            return Err(RegistryError::IllegalState {
                stream_id,
                state: entry.state,
            });
        }
        entry.guest_credit -= len;
        Ok(())
    }

    /// Add `delta` bytes to the guest credit on `stream_id`.
    pub fn grant_guest_credit(&mut self, stream_id: u32, delta: u32) -> Result<(), RegistryError> {
        let entry = self
            .streams
            .get_mut(&stream_id)
            .ok_or(RegistryError::NotLive { stream_id })?;
        entry.guest_credit = entry
            .guest_credit
            .saturating_add(delta)
            .min(MAX_STREAM_CREDIT);
        Ok(())
    }

    /// Consume `len` bytes of host credit on `stream_id`.
    pub fn consume_host_credit(&mut self, stream_id: u32, len: u32) -> Result<(), RegistryError> {
        let entry = self
            .streams
            .get_mut(&stream_id)
            .ok_or(RegistryError::NotLive { stream_id })?;
        if len > entry.host_credit {
            return Err(RegistryError::IllegalState {
                stream_id,
                state: entry.state,
            });
        }
        entry.host_credit -= len;
        Ok(())
    }

    /// Add `delta` bytes to the host credit on `stream_id`.
    pub fn grant_host_credit(&mut self, stream_id: u32, delta: u32) -> Result<(), RegistryError> {
        let entry = self
            .streams
            .get_mut(&stream_id)
            .ok_or(RegistryError::NotLive { stream_id })?;
        entry.host_credit = entry
            .host_credit
            .saturating_add(delta)
            .min(MAX_STREAM_CREDIT);
        Ok(())
    }

    fn live_count(&self, class: FlowClass) -> usize {
        self.live_in_class(class)
    }

    fn insert(&mut self, stream_id: u32, class: FlowClass) {
        let prev = self.streams.insert(
            stream_id,
            StreamEntry {
                class,
                state: StreamState::Opening,
                guest_credit: self.limits.initial_credit,
                host_credit: self.limits.initial_credit,
            },
        );
        if prev.is_some() {
            warn!(stream_id, "stream ID collision in FlowMux registry");
        }
    }
}

/// Convenience: map an open opcode to its flow class.
pub fn class_for_open(opcode: mvm_contract::protocol::network_flow::Opcode) -> Option<FlowClass> {
    use mvm_contract::protocol::network_flow::Opcode;
    match opcode {
        Opcode::OpenTcp | Opcode::InboundOpen => Some(FlowClass::Tcp),
        Opcode::OpenUdp => Some(FlowClass::Udp),
        Opcode::Resolve => Some(FlowClass::Dns),
        Opcode::OpenHttp => Some(FlowClass::Http),
        Opcode::IcmpEcho => Some(FlowClass::Icmp),
        _ => None,
    }
}

/// Convenience: which direction a stream ID was initiated from.
pub fn initiator(stream_id: u32) -> Direction {
    if stream_id % 2 == 1 {
        Direction::GuestToHost
    } else {
        Direction::HostToGuest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_ids_are_odd_and_monotonic() {
        let mut reg = StreamRegistry::new(RegistryLimits::default());
        assert_eq!(reg.alloc_guest(FlowClass::Tcp).unwrap(), 1);
        assert_eq!(reg.alloc_guest(FlowClass::Tcp).unwrap(), 3);
        assert_eq!(reg.alloc_guest(FlowClass::Udp).unwrap(), 5);
    }

    #[test]
    fn host_ids_are_even_and_monotonic() {
        let mut reg = StreamRegistry::new(RegistryLimits::default());
        assert_eq!(reg.alloc_host(FlowClass::Tcp).unwrap(), 0);
        assert_eq!(reg.alloc_host(FlowClass::Tcp).unwrap(), 2);
        assert_eq!(reg.alloc_host(FlowClass::Udp).unwrap(), 4);
    }

    #[test]
    fn ceiling_refuses_newcomers() {
        let mut reg = StreamRegistry::new(RegistryLimits {
            max_tcp: 2,
            max_udp: 1,
            max_dns: 64,
            initial_credit: 1024,
            ..Default::default()
        });
        reg.alloc_guest(FlowClass::Tcp).unwrap();
        reg.alloc_guest(FlowClass::Tcp).unwrap();
        assert!(matches!(
            reg.alloc_guest(FlowClass::Tcp),
            Err(RegistryError::Ceiling {
                class: FlowClass::Tcp,
                limit: 2
            })
        ));
        reg.alloc_host(FlowClass::Udp).unwrap();
        assert!(matches!(
            reg.alloc_guest(FlowClass::Udp),
            Err(RegistryError::Ceiling {
                class: FlowClass::Udp,
                limit: 1
            })
        ));
    }

    #[test]
    fn state_machine_walks_opening_open_half_closed_closed() {
        let mut reg = StreamRegistry::new(RegistryLimits::default());
        let id = reg.alloc_guest(FlowClass::Tcp).unwrap();
        assert_eq!(reg.get(id).unwrap().state, StreamState::Opening);
        reg.confirm(id).unwrap();
        assert_eq!(reg.get(id).unwrap().state, StreamState::Open);
        reg.half_close(id).unwrap();
        assert_eq!(reg.get(id).unwrap().state, StreamState::HalfClosed);
        reg.half_close(id).unwrap(); // idempotent
        reg.retire(id).unwrap();
        assert!(reg.get(id).is_none());
    }

    #[test]
    fn credit_is_tracked() {
        let mut reg = StreamRegistry::new(RegistryLimits {
            max_tcp: 1,
            max_udp: 0,
            max_dns: 64,
            initial_credit: 100,
            ..Default::default()
        });
        let id = reg.alloc_guest(FlowClass::Tcp).unwrap();
        reg.consume_guest_credit(id, 30).unwrap();
        assert_eq!(reg.get(id).unwrap().guest_credit, 70);
        reg.grant_guest_credit(id, 10).unwrap();
        assert_eq!(reg.get(id).unwrap().guest_credit, 80);
        assert!(reg.consume_guest_credit(id, 81).is_err());
    }

    #[test]
    fn host_credit_is_tracked() {
        let mut reg = StreamRegistry::new(RegistryLimits {
            max_tcp: 1,
            max_udp: 0,
            max_dns: 64,
            initial_credit: 100,
            ..Default::default()
        });
        let id = reg.alloc_guest(FlowClass::Tcp).unwrap();
        reg.consume_host_credit(id, 30).unwrap();
        assert_eq!(reg.get(id).unwrap().host_credit, 70);
        reg.grant_host_credit(id, 10).unwrap();
        assert_eq!(reg.get(id).unwrap().host_credit, 80);
        assert!(reg.consume_host_credit(id, 81).is_err());
    }

    #[test]
    fn credit_grants_are_capped_at_max_stream_credit() {
        let mut reg = StreamRegistry::new(RegistryLimits {
            max_tcp: 1,
            max_udp: 0,
            max_dns: 64,
            initial_credit: 100,
            ..Default::default()
        });
        let id = reg.alloc_guest(FlowClass::Tcp).unwrap();
        reg.grant_guest_credit(id, u32::MAX).unwrap();
        reg.grant_host_credit(id, u32::MAX).unwrap();
        assert_eq!(reg.get(id).unwrap().guest_credit, MAX_STREAM_CREDIT);
        assert_eq!(reg.get(id).unwrap().host_credit, MAX_STREAM_CREDIT);
    }

    #[test]
    fn initiator_direction_matches_parity() {
        assert_eq!(initiator(1), Direction::GuestToHost);
        assert_eq!(initiator(0), Direction::HostToGuest);
        assert_eq!(initiator(42), Direction::HostToGuest);
    }
}
