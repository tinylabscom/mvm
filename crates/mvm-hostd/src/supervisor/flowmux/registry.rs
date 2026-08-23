//! Per-stream registries for one FlowMux session.
//!
//! A `StreamRegistry` owns the stream/association life cycle on the host side
//! of one FlowMux session: odd stream IDs for guest-initiated flows (`OpenTcp`,
//! `OpenUdp`), even IDs for host-initiated ingress, explicit state transitions,
//! and per-stream credit windows. It performs no I/O; the `FlowMuxSession`
//! drives sockets and the registry answers "is this ID valid?", "can we accept
//! another?", and "how much credit remains?".

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mvm_contract::protocol::network_flow::{Direction, MAX_STREAM_CREDIT};
use mvm_core::plan::NetworkLimits;
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
    /// VM-wide capacity held for as long as this stream is live.
    budget_permit: Option<VmBudgetPermit>,
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

impl RegistryLimits {
    /// Apply the signed plan ceilings while retaining host-owned timing,
    /// credit, peer, ICMP, and rate defaults.
    #[must_use]
    pub fn from_network_limits(network: NetworkLimits) -> Self {
        let mut limits = Self::default();
        let max_tcp_flows = usize_from_u32(network.max_tcp_flows);
        limits.max_tcp = max_tcp_flows;
        // The signed field is aggregate across opaque TCP and typed HTTP. The
        // VM budget enforces that aggregate; both per-session registries retain
        // the same upper bound so neither class is narrowed independently.
        limits.max_http = max_tcp_flows;
        limits.max_udp = usize_from_u32(network.max_udp_associations);
        limits.max_dns = usize_from_u32(network.max_dns_bindings);
        limits
    }
}

fn usize_from_u32(value: u32) -> usize {
    usize::try_from(value).expect("u32 network limit fits usize on supported targets")
}

/// A resource class whose capacity is owned once per VM, not once per session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmBudgetResource {
    TcpHttp,
    Udp,
    Dns,
    Icmp,
    IngressListener,
}

/// A VM-wide FlowMux resource owner shared by every authenticated session.
#[derive(Debug)]
pub struct VmFlowBudget {
    limits: VmFlowBudgetLimits,
    live: Mutex<VmFlowCounts>,
}

#[derive(Debug, Clone, Copy)]
struct VmFlowBudgetLimits {
    tcp_http: usize,
    udp: usize,
    dns: usize,
    icmp: usize,
    ingress_listeners: usize,
}

#[derive(Debug, Default)]
struct VmFlowCounts {
    tcp_http: usize,
    udp: usize,
    dns: usize,
    icmp: usize,
    ingress_listeners: usize,
}

/// A VM-wide capacity reservation. Dropping it returns the slot, including
/// when a session exits without explicitly retiring its live streams.
#[derive(Debug)]
pub struct VmBudgetPermit {
    budget: Arc<VmFlowBudget>,
    resource: VmBudgetResource,
}

/// A non-stream VM budget is exhausted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VmBudgetError {
    /// The requested resource has reached its admitted ceiling.
    #[error("{resource} ceiling reached ({limit})")]
    Ceiling {
        resource: &'static str,
        limit: usize,
    },
}

impl VmFlowBudget {
    /// Build the per-VM owner from signed ceilings plus the host's ICMP cap.
    #[must_use]
    pub fn new(network: NetworkLimits, max_icmp: usize) -> Self {
        Self {
            limits: VmFlowBudgetLimits {
                tcp_http: usize_from_u32(network.max_tcp_flows),
                udp: usize_from_u32(network.max_udp_associations),
                dns: usize_from_u32(network.max_dns_bindings),
                icmp: max_icmp,
                ingress_listeners: usize::from(network.max_ingress_listeners),
            },
            live: Mutex::new(VmFlowCounts::default()),
        }
    }

    pub(crate) fn from_registry_limits(limits: RegistryLimits) -> Self {
        Self {
            limits: VmFlowBudgetLimits {
                tcp_http: limits.max_tcp.max(limits.max_http),
                udp: limits.max_udp,
                dns: limits.max_dns,
                icmp: limits.max_icmp,
                // Ingress has no per-session registry path. A standalone
                // registry therefore leaves it unavailable; the endpoint
                // constructs the shared owner from signed `NetworkLimits`.
                ingress_listeners: 0,
            },
            live: Mutex::new(VmFlowCounts::default()),
        }
    }

    fn reserve_flow(self: &Arc<Self>, class: FlowClass) -> Result<VmBudgetPermit, RegistryError> {
        let resource = match class {
            FlowClass::Tcp | FlowClass::Http => VmBudgetResource::TcpHttp,
            FlowClass::Udp => VmBudgetResource::Udp,
            FlowClass::Dns => VmBudgetResource::Dns,
            FlowClass::Icmp => VmBudgetResource::Icmp,
        };
        self.reserve(resource)
            .map_err(|VmBudgetError::Ceiling { limit, .. }| RegistryError::Ceiling { class, limit })
    }

    /// Reserve one admitted ingress listener for the endpoint lifetime.
    pub fn reserve_ingress_listener(self: &Arc<Self>) -> Result<VmBudgetPermit, VmBudgetError> {
        self.reserve(VmBudgetResource::IngressListener)
    }

    fn reserve(
        self: &Arc<Self>,
        resource: VmBudgetResource,
    ) -> Result<VmBudgetPermit, VmBudgetError> {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        let (count, limit, name) = match resource {
            VmBudgetResource::TcpHttp => {
                (&mut live.tcp_http, self.limits.tcp_http, "tcp/http flow")
            }
            VmBudgetResource::Udp => (&mut live.udp, self.limits.udp, "udp association"),
            VmBudgetResource::Dns => (&mut live.dns, self.limits.dns, "dns binding"),
            VmBudgetResource::Icmp => (&mut live.icmp, self.limits.icmp, "icmp exchange"),
            VmBudgetResource::IngressListener => (
                &mut live.ingress_listeners,
                self.limits.ingress_listeners,
                "ingress listener",
            ),
        };
        if *count >= limit {
            return Err(VmBudgetError::Ceiling {
                resource: name,
                limit,
            });
        }
        *count += 1;
        drop(live);
        Ok(VmBudgetPermit {
            budget: Arc::clone(self),
            resource,
        })
    }
}

impl Drop for VmBudgetPermit {
    fn drop(&mut self) {
        let mut live = self.budget.live.lock().unwrap_or_else(|e| e.into_inner());
        let count = match self.resource {
            VmBudgetResource::TcpHttp => &mut live.tcp_http,
            VmBudgetResource::Udp => &mut live.udp,
            VmBudgetResource::Dns => &mut live.dns,
            VmBudgetResource::Icmp => &mut live.icmp,
            VmBudgetResource::IngressListener => &mut live.ingress_listeners,
        };
        if *count == 0 {
            warn!(resource = ?self.resource, "FlowMux VM budget release was unbalanced");
        } else {
            *count -= 1;
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
    budget: Arc<VmFlowBudget>,
}

impl StreamRegistry {
    /// Create a registry with the given ceilings.
    #[must_use]
    pub fn new(limits: RegistryLimits) -> Self {
        let budget = Arc::new(VmFlowBudget::from_registry_limits(limits));
        Self::with_budget(limits, budget)
    }

    /// Create a per-session registry drawing capacity from a shared VM owner.
    #[must_use]
    pub fn with_budget(limits: RegistryLimits, budget: Arc<VmFlowBudget>) -> Self {
        Self {
            limits,
            next_guest_id: 1, // guest-initiated IDs are odd
            next_host_id: 2,  // host-initiated flow IDs are non-zero and even
            streams: BTreeMap::new(),
            budget,
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
        let next_id = id.checked_add(2).ok_or(RegistryError::InvalidStreamId {
            stream_id: u32::MAX,
        })?;
        let permit = self.budget.reserve_flow(class)?;
        self.next_guest_id = next_id;
        self.insert(id, class, permit);
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
        let permit = self.budget.reserve_flow(class)?;
        self.next_guest_id = self.next_guest_id.max(stream_id + 2);
        self.insert(stream_id, class, permit);
        Ok(())
    }

    /// Record a host-initiated stream ID supplied by the local ingress handler.
    /// The ID must be even, not already live, and within the class ceiling.
    pub fn open_host(&mut self, stream_id: u32, class: FlowClass) -> Result<(), RegistryError> {
        if stream_id == 0 || !stream_id.is_multiple_of(2) {
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
        let permit = self.budget.reserve_flow(class)?;
        self.next_host_id = self.next_host_id.max(stream_id + 2);
        self.insert(stream_id, class, permit);
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
        let next_id = id.checked_add(2).ok_or(RegistryError::InvalidStreamId {
            stream_id: u32::MAX,
        })?;
        let permit = self.budget.reserve_flow(class)?;
        self.next_host_id = next_id;
        self.insert(id, class, permit);
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
        entry.budget_permit.take();
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

    /// Restore guest credit once at least half of the initial window has been
    /// consumed, returning the delta the peer must be told about.
    ///
    /// Batching updates avoids one authenticated frame per small payload while
    /// retaining a bounded window. A payload that consumes the whole window is
    /// replenished immediately; smaller writes share one update when the
    /// remaining credit reaches the low-water mark.
    pub fn replenish_guest_credit_if_low(
        &mut self,
        stream_id: u32,
    ) -> Result<Option<u32>, RegistryError> {
        let entry = self
            .streams
            .get_mut(&stream_id)
            .ok_or(RegistryError::NotLive { stream_id })?;
        let low_water = self.limits.initial_credit / 2;
        if entry.guest_credit > low_water {
            return Ok(None);
        }
        let delta = self
            .limits
            .initial_credit
            .saturating_sub(entry.guest_credit);
        entry.guest_credit = self.limits.initial_credit;
        Ok((delta > 0).then_some(delta))
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

    fn insert(&mut self, stream_id: u32, class: FlowClass, permit: VmBudgetPermit) {
        let prev = self.streams.insert(
            stream_id,
            StreamEntry {
                class,
                state: StreamState::Opening,
                guest_credit: self.limits.initial_credit,
                host_credit: self.limits.initial_credit,
                budget_permit: Some(permit),
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
        assert_eq!(reg.alloc_host(FlowClass::Tcp).unwrap(), 2);
        assert_eq!(reg.alloc_host(FlowClass::Tcp).unwrap(), 4);
        assert_eq!(reg.alloc_host(FlowClass::Udp).unwrap(), 6);
    }

    #[test]
    fn host_open_refuses_the_control_stream() {
        let mut reg = StreamRegistry::new(RegistryLimits::default());
        assert_eq!(
            reg.open_host(0, FlowClass::Tcp),
            Err(RegistryError::InvalidStreamId { stream_id: 0 })
        );
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
    fn guest_credit_updates_are_batched_at_half_window() {
        let mut reg = StreamRegistry::new(RegistryLimits {
            max_tcp: 1,
            max_udp: 0,
            max_dns: 64,
            initial_credit: 100,
            ..Default::default()
        });
        let id = reg.alloc_guest(FlowClass::Tcp).unwrap();

        reg.consume_guest_credit(id, 49).unwrap();
        assert_eq!(reg.replenish_guest_credit_if_low(id).unwrap(), None);
        assert_eq!(reg.get(id).unwrap().guest_credit, 51);

        reg.consume_guest_credit(id, 1).unwrap();
        assert_eq!(reg.replenish_guest_credit_if_low(id).unwrap(), Some(50));
        assert_eq!(reg.get(id).unwrap().guest_credit, 100);
    }

    #[test]
    fn whole_guest_window_is_replenished_immediately() {
        let mut reg = StreamRegistry::new(RegistryLimits {
            max_tcp: 1,
            max_udp: 0,
            max_dns: 64,
            initial_credit: 100,
            ..Default::default()
        });
        let id = reg.alloc_guest(FlowClass::Tcp).unwrap();

        reg.consume_guest_credit(id, 100).unwrap();
        assert_eq!(reg.replenish_guest_credit_if_low(id).unwrap(), Some(100));
        assert_eq!(reg.get(id).unwrap().guest_credit, 100);
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

    #[test]
    fn signed_limits_replace_registry_class_defaults() {
        let network = NetworkLimits::builder()
            .max_tcp_flows(7)
            .max_udp_associations(5)
            .max_dns_bindings(3)
            .max_ingress_listeners(2)
            .build()
            .unwrap();
        let limits = RegistryLimits::from_network_limits(network);

        assert_eq!(limits.max_tcp, 7);
        assert_eq!(limits.max_http, 7);
        assert_eq!(limits.max_udp, 5);
        assert_eq!(limits.max_dns, 3);
        assert_eq!(
            limits.initial_credit,
            RegistryLimits::default().initial_credit
        );
    }

    #[test]
    fn tcp_and_http_share_one_vm_ceiling_across_sessions() {
        let network = NetworkLimits::builder().max_tcp_flows(1).build().unwrap();
        let limits = RegistryLimits::from_network_limits(network);
        let budget = Arc::new(VmFlowBudget::new(network, limits.max_icmp));
        let mut first = StreamRegistry::with_budget(limits, Arc::clone(&budget));
        let mut second = StreamRegistry::with_budget(limits, budget);

        assert_eq!(first.alloc_guest(FlowClass::Tcp).unwrap(), 1);
        assert!(matches!(
            second.alloc_guest(FlowClass::Http),
            Err(RegistryError::Ceiling {
                class: FlowClass::Http,
                limit: 1
            })
        ));

        first.retire(1).unwrap();
        assert_eq!(
            second.alloc_guest(FlowClass::Http).unwrap(),
            1,
            "a refused global reservation must not consume the session's stream id"
        );
    }

    #[test]
    fn dropping_a_session_releases_every_vm_reservation() {
        let network = NetworkLimits::builder()
            .max_udp_associations(1)
            .build()
            .unwrap();
        let limits = RegistryLimits::from_network_limits(network);
        let budget = Arc::new(VmFlowBudget::new(network, limits.max_icmp));
        {
            let mut first = StreamRegistry::with_budget(limits, Arc::clone(&budget));
            first.open_guest(1, FlowClass::Udp).unwrap();
        }

        let mut second = StreamRegistry::with_budget(limits, budget);
        second.open_guest(1, FlowClass::Udp).unwrap();
    }

    #[test]
    fn ingress_listener_capacity_is_vm_wide_and_drop_guarded() {
        let network = NetworkLimits::builder()
            .max_ingress_listeners(1)
            .build()
            .unwrap();
        let budget = Arc::new(VmFlowBudget::new(network, 1));
        let first = budget.reserve_ingress_listener().unwrap();
        assert_eq!(
            budget.reserve_ingress_listener().unwrap_err(),
            VmBudgetError::Ceiling {
                resource: "ingress listener",
                limit: 1
            }
        );
        drop(first);
        assert!(budget.reserve_ingress_listener().is_ok());
    }
}
