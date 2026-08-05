//! The host-side substitution bridge — guest egress stream ↔ per-VM endpoint UDS.
//!
//! A pure byte relay: the guest's egress port streams to the per-VM
//! `mvm-substitution-endpoint`, which owns the whole egress decision — claim-10
//! default-deny and claims-12/13 secret substitution. The bridge opens the
//! endpoint on a stream's first frame and relays verbatim in both directions; it
//! never parses or gates. The stream may be raw TCP or the WireRequest
//! substitution protocol — the bridge is agnostic. Keyed by the guest vsock
//! `src_port`. With no endpoint configured, every stream fails closed.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use crate::vmm::vsock_transport::CONNECTION_IDLE_TIMEOUT;
use crate::vmm::vsock_transport::MAX_CONNECTIONS;

/// Per-drain read budget per endpoint connection.
const READ_CHUNK: usize = 16 * 1024;
/// Maximum number of active raw/SOCKS5/DNS/substitution streams per workload.
pub(crate) const MAX_EGRESS_STREAMS: usize = 128;
/// Sustained egress byte budget shared by all host-mediated workload streams.
pub(crate) const EGRESS_BYTES_PER_SECOND: u64 = 4 * 1024 * 1024;
/// Maximum burst accepted before the sustained budget must refill.
pub(crate) const EGRESS_BURST_BYTES: u64 = 8 * 1024 * 1024;

/// What the device should signal the guest after an inbound endpoint-relay frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndpointRelayAction {
    /// Opened + relayed to the endpoint (or a later frame on an open stream).
    Relayed,
    /// Refused: no endpoint or a connect failure. Fail-closed — the stream is
    /// reset and nothing leaves the host.
    Refused,
}

/// Result of draining the open endpoint sockets once.
pub(crate) struct EndpointRelayDrain {
    /// Bytes read per connection id, to frame back to the guest as `OP_RW`.
    pub ready: Vec<(u32, Vec<u8>)>,
    /// Connection ids that hit EOF / error and were closed.
    pub closed: Vec<u32>,
}

/// Shared per-workload egress budget. The egress and broker ports use one
/// instance so a workload cannot multiply its allowance by opening both paths.
#[derive(Clone)]
pub(crate) struct EgressBudget {
    state: Arc<Mutex<EgressBudgetState>>,
}

struct EgressBudgetState {
    active_streams: usize,
    byte_tokens: u64,
    last_refill: Instant,
}

impl EgressBudget {
    pub(crate) fn new() -> Self {
        Self::new_at(Instant::now())
    }

    fn new_at(now: Instant) -> Self {
        Self {
            state: Arc::new(Mutex::new(EgressBudgetState {
                active_streams: 0,
                byte_tokens: EGRESS_BURST_BYTES,
                last_refill: now,
            })),
        }
    }

    fn try_reserve_stream(&self) -> bool {
        let mut state = self.state.lock().expect("egress budget mutex poisoned");
        if state.active_streams >= MAX_EGRESS_STREAMS {
            return false;
        }
        state.active_streams += 1;
        true
    }

    fn release_stream(&self) {
        let mut state = self.state.lock().expect("egress budget mutex poisoned");
        state.active_streams = state.active_streams.saturating_sub(1);
    }

    fn try_consume(&self, bytes: usize) -> bool {
        self.try_consume_at(bytes, Instant::now())
    }

    fn try_consume_at(&self, bytes: usize, now: Instant) -> bool {
        let mut state = self.state.lock().expect("egress budget mutex poisoned");
        refill_tokens(&mut state, now);

        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        if bytes > state.byte_tokens {
            return false;
        }
        state.byte_tokens -= bytes;
        true
    }

    /// Reserve up to `max` bytes for a non-blocking read. The caller must
    /// refund bytes it reserved but did not receive from the socket.
    fn reserve_read(&self, max: usize, now: Instant) -> usize {
        let mut state = self.state.lock().expect("egress budget mutex poisoned");
        refill_tokens(&mut state, now);
        let max = u64::try_from(max).unwrap_or(u64::MAX);
        let reserved = state.byte_tokens.min(max);
        state.byte_tokens -= reserved;
        usize::try_from(reserved).unwrap_or(usize::MAX)
    }

    fn refund_read(&self, bytes: usize) {
        let mut state = self.state.lock().expect("egress budget mutex poisoned");
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        state.byte_tokens = state
            .byte_tokens
            .saturating_add(bytes)
            .min(EGRESS_BURST_BYTES);
    }
}

fn refill_tokens(state: &mut EgressBudgetState, now: Instant) {
    let elapsed_nanos = now.saturating_duration_since(state.last_refill).as_nanos();
    let refill = elapsed_nanos.saturating_mul(u128::from(EGRESS_BYTES_PER_SECOND)) / 1_000_000_000;
    let refill = u64::try_from(refill).unwrap_or(u64::MAX);
    state.byte_tokens = state
        .byte_tokens
        .saturating_add(refill)
        .min(EGRESS_BURST_BYTES);
    state.last_refill = now;
}

/// Backend-side byte relay between a guest connection id and a per-VM endpoint.
///
/// This is intentionally transport-only: the relay moves bytes between the guest
/// stream abstraction and the per-VM UDS endpoint. Policy, HTTP parsing, TLS, and
/// host client behavior stay above this seam.
pub(crate) trait GuestEndpointRelay {
    /// Relay guest→host bytes for `conn_id`. The first payload may open the
    /// endpoint connection. Implementations fail closed on missing endpoints or
    /// connect failures.
    fn relay_guest_bytes(&mut self, conn_id: u32, payload: &[u8]) -> EndpointRelayAction;

    /// Drain host→guest endpoint bytes once from every active connection.
    fn drain_endpoint_bytes(&mut self) -> EndpointRelayDrain;

    /// Close the endpoint side of `conn_id`.
    fn close_connection(&mut self, conn_id: u32);

    /// Whether any endpoint connections are still active.
    fn is_active(&self) -> bool;
}

/// The substitution transport for one guest.
pub(crate) struct SubstitutionBridge {
    /// Per-VM `mvm-substitution-endpoint` socket. `None` ⇒ no endpoint, fail-closed.
    endpoint: Option<PathBuf>,
    /// Open endpoint connections keyed by the guest vsock `src_port`.
    conns: HashMap<u32, EndpointConn>,
    /// Open-connection count, published for the run loop heartbeat so it keeps
    /// waking an idle guest while there's an endpoint reply to deliver.
    active: Option<Arc<AtomicUsize>>,
    budget: EgressBudget,
}

struct EndpointConn {
    stream: UnixStream,
    last_activity: Instant,
}

impl SubstitutionBridge {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_budget(EgressBudget::new())
    }

    pub(crate) fn with_budget(budget: EgressBudget) -> Self {
        Self {
            endpoint: None,
            conns: HashMap::new(),
            active: None,
            budget,
        }
    }

    /// Point the bridge at this VM's substitution-endpoint socket.
    pub fn set_endpoint(&mut self, path: &Path) {
        self.endpoint = Some(path.to_path_buf());
    }

    /// Share the open-connection counter with the run loop heartbeat.
    pub fn set_activity(&mut self, counter: Arc<AtomicUsize>) {
        self.active = Some(counter);
    }

    fn bump(&self, delta: i32) {
        if let Some(c) = &self.active {
            if delta >= 0 {
                c.fetch_add(delta as usize, Ordering::Relaxed);
            } else {
                c.fetch_sub((-delta) as usize, Ordering::Relaxed);
            }
        }
    }

    fn evict_idle_at(&mut self, now: Instant) -> Vec<u32> {
        let mut expired = Vec::new();
        self.conns.retain(|conn_id, conn| {
            let keep = now.saturating_duration_since(conn.last_activity) < CONNECTION_IDLE_TIMEOUT;
            if !keep {
                expired.push(*conn_id);
            }
            keep
        });
        for _ in &expired {
            self.budget.release_stream();
            self.bump(-1);
        }
        expired
    }

    pub(crate) fn close_all(&mut self) {
        let conn_ids: Vec<u32> = self.conns.keys().copied().collect();
        for conn_id in conn_ids {
            self.close_connection(conn_id);
        }
    }
}

impl SubstitutionBridge {
    /// Fds the host-I/O thread should watch for endpoint replies.
    pub fn poll_fds(&self) -> Vec<RawFd> {
        self.conns
            .values()
            .map(|conn| conn.stream.as_raw_fd())
            .collect()
    }
}

impl GuestEndpointRelay for SubstitutionBridge {
    fn relay_guest_bytes(&mut self, conn_id: u32, payload: &[u8]) -> EndpointRelayAction {
        if let Some(conn) = self.conns.get_mut(&conn_id) {
            if !self.budget.try_consume(payload.len()) {
                return EndpointRelayAction::Refused;
            }
            write_nonblocking(&mut conn.stream, payload);
            conn.last_activity = Instant::now();
            return EndpointRelayAction::Relayed;
        }
        if self.conns.len() >= MAX_CONNECTIONS {
            return EndpointRelayAction::Refused;
        }
        if !self.budget.try_reserve_stream() {
            return EndpointRelayAction::Refused;
        }
        let Some(path) = self.endpoint.clone() else {
            self.budget.release_stream();
            return EndpointRelayAction::Refused;
        };
        match UnixStream::connect(&path) {
            Ok(stream) => {
                let _ = stream.set_nonblocking(true);
                if !self.budget.try_consume(payload.len()) {
                    self.budget.release_stream();
                    return EndpointRelayAction::Refused;
                }
                let conn = self.conns.entry(conn_id).or_insert(EndpointConn {
                    stream,
                    last_activity: Instant::now(),
                });
                write_nonblocking(&mut conn.stream, payload);
                conn.last_activity = Instant::now();
                self.bump(1);
                EndpointRelayAction::Relayed
            }
            Err(_) => {
                self.budget.release_stream();
                EndpointRelayAction::Refused
            }
        }
    }

    fn drain_endpoint_bytes(&mut self) -> EndpointRelayDrain {
        let mut ready = Vec::new();
        let mut closed = self.evict_idle_at(Instant::now());
        for (conn_id, conn) in self.conns.iter_mut() {
            let allowance = self.budget.reserve_read(READ_CHUNK, Instant::now());
            if allowance == 0 {
                // The endpoint remains readable while the token bucket refills.
                // Avoid a hot loop in the host-I/O poller without tearing down a
                // valid TLS stream that is merely being rate-limited.
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            let mut buf = vec![0u8; allowance];
            match conn.stream.read(&mut buf) {
                Ok(0) => {
                    self.budget.refund_read(allowance);
                    closed.push(*conn_id);
                }
                Ok(n) => {
                    self.budget.refund_read(allowance.saturating_sub(n));
                    buf.truncate(n);
                    conn.last_activity = Instant::now();
                    ready.push((*conn_id, buf));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.budget.refund_read(allowance);
                }
                Err(_) => {
                    self.budget.refund_read(allowance);
                    closed.push(*conn_id);
                }
            }
        }
        for conn_id in &closed {
            self.close_connection(*conn_id);
        }
        EndpointRelayDrain { ready, closed }
    }

    fn close_connection(&mut self, conn_id: u32) {
        if self.conns.remove(&conn_id).is_some() {
            self.budget.release_stream();
            self.bump(-1);
        }
    }

    fn is_active(&self) -> bool {
        !self.conns.is_empty()
    }
}

/// Write `payload` to a non-blocking socket, briefly spinning past `WouldBlock` so
/// a small frame goes out without stalling the run loop indefinitely.
fn write_nonblocking(stream: &mut UnixStream, payload: &[u8]) {
    let mut off = 0;
    let mut spins = 0u32;
    while off < payload.len() {
        match stream.write(&payload[off..]) {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && spins < 10_000 => {
                spins += 1;
                std::thread::yield_now();
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::bind_unix_listener;
    use std::time::Duration;

    /// No endpoint configured → every stream is refused, nothing opened.
    #[test]
    fn no_endpoint_refuses_fail_closed() {
        let mut b = SubstitutionBridge::new();
        assert_eq!(
            b.relay_guest_bytes(5, b"1.2.3.4:80\n"),
            EndpointRelayAction::Refused
        );
        assert!(!b.is_active());
    }

    #[test]
    fn refuses_new_streams_at_the_connection_cap() {
        let mut b = SubstitutionBridge::new();
        let mut peers = Vec::with_capacity(MAX_CONNECTIONS);
        for conn_id in 0..MAX_CONNECTIONS as u32 {
            let (stream, peer) = UnixStream::pair().unwrap();
            b.conns.insert(
                conn_id,
                EndpointConn {
                    stream,
                    last_activity: Instant::now(),
                },
            );
            peers.push(peer);
        }

        assert_eq!(
            b.relay_guest_bytes(MAX_CONNECTIONS as u32, b"data"),
            EndpointRelayAction::Refused
        );
        assert_eq!(b.conns.len(), MAX_CONNECTIONS);
    }

    /// A raw first frame (not a WireRequest) is relayed byte-for-byte to the
    /// endpoint and the endpoint's reply drains back to the guest. The bridge
    /// never parses or gates.
    #[test]
    fn relays_raw_frame_both_directions() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");
        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = c.read(&mut buf).unwrap();
            let mut reply = b"OK:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            c.write_all(&reply).unwrap();
            buf[..n].to_vec()
        });

        let mut b = SubstitutionBridge::new();
        let active = Arc::new(AtomicUsize::new(0));
        b.set_activity(active.clone());
        b.set_endpoint(&sock);

        let raw = b"1.2.3.4:80\n";
        assert_eq!(b.relay_guest_bytes(3, raw), EndpointRelayAction::Relayed);
        assert!(b.is_active());
        assert_eq!(active.load(Ordering::Relaxed), 1);

        let got_by_endpoint = server.join().unwrap();
        assert_eq!(got_by_endpoint, raw, "endpoint got the raw bytes verbatim");

        let mut reply = None;
        for _ in 0..200 {
            let d = b.drain_endpoint_bytes();
            if let Some((cid, bytes)) = d.ready.into_iter().next() {
                assert_eq!(cid, 3);
                reply = Some(bytes);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let reply = reply.expect("endpoint reply drained back");
        assert!(reply.starts_with(b"OK:"));
        assert!(reply.ends_with(raw));
    }

    #[test]
    fn exhausted_download_budget_backpressures_without_closing_stream() {
        let mut bridge = SubstitutionBridge::new();
        let (stream, mut peer) = UnixStream::pair().unwrap();
        bridge.conns.insert(
            9,
            EndpointConn {
                stream,
                last_activity: Instant::now(),
            },
        );
        peer.write_all(&vec![b'x'; 1024]).unwrap();
        {
            let mut state = bridge.budget.state.lock().unwrap();
            state.byte_tokens = 0;
            state.last_refill = Instant::now() + Duration::from_secs(1);
        }

        let drained = bridge.drain_endpoint_bytes();

        assert!(drained.closed.is_empty());
        assert!(bridge.is_active());
    }

    /// A later frame on an already-open stream relays directly — no new endpoint
    /// connection is opened — and closing drops the endpoint connection.
    #[test]
    fn later_frames_relay_and_close_drops_connection() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");
        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        // The endpoint accepts exactly one connection and drains it; a second
        // accept (i.e. a second connection wrongly opened for the same stream)
        // would block, proving both frames share one connection.
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut all = Vec::new();
            let _ = c.read_to_end(&mut all);
            all
        });

        let mut b = SubstitutionBridge::new();
        let active = Arc::new(AtomicUsize::new(0));
        b.set_activity(active.clone());
        b.set_endpoint(&sock);

        assert_eq!(
            b.relay_guest_bytes(7, b"first"),
            EndpointRelayAction::Relayed
        );
        assert_eq!(active.load(Ordering::Relaxed), 1);
        // Second frame on the same open stream — no new connection.
        assert_eq!(
            b.relay_guest_bytes(7, b"second"),
            EndpointRelayAction::Relayed
        );
        assert_eq!(active.load(Ordering::Relaxed), 1);

        // Close drops the endpoint connection (the endpoint then sees EOF).
        b.close_connection(7);
        assert!(!b.is_active());
        assert_eq!(active.load(Ordering::Relaxed), 0);

        // The single endpoint connection received both frames' bytes concatenated.
        let got = server.join().unwrap();
        assert_eq!(got, b"firstsecond");
    }

    #[test]
    fn poll_fds_include_open_endpoint_streams() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");
        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        let server = std::thread::spawn(move || {
            let (_c, _) = listener.accept().unwrap();
        });

        let mut bridge = SubstitutionBridge::new();
        bridge.set_endpoint(&sock);
        assert!(bridge.poll_fds().is_empty());
        assert_eq!(
            bridge.relay_guest_bytes(7, b"first"),
            EndpointRelayAction::Relayed
        );
        assert_eq!(bridge.poll_fds().len(), 1);
        bridge.close_connection(7);
        assert!(bridge.poll_fds().is_empty());
        server.join().unwrap();
    }

    #[test]
    fn idle_endpoint_stream_is_evicted_and_activity_drops() {
        let mut b = SubstitutionBridge::new();
        let active = Arc::new(AtomicUsize::new(1));
        b.set_activity(active.clone());
        let (stream, _peer) = UnixStream::pair().unwrap();
        b.conns.insert(
            7,
            EndpointConn {
                stream,
                last_activity: Instant::now() - CONNECTION_IDLE_TIMEOUT - Duration::from_secs(1),
            },
        );

        let expired = b.evict_idle_at(Instant::now());

        assert_eq!(expired, vec![7]);
        assert!(!b.is_active());
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn egress_budget_caps_concurrency_and_releases_slots() {
        let budget = EgressBudget::new();
        for _ in 0..MAX_EGRESS_STREAMS {
            assert!(budget.try_reserve_stream());
        }
        assert!(!budget.try_reserve_stream());
        budget.release_stream();
        assert!(budget.try_reserve_stream());
    }

    #[test]
    fn egress_budget_refills_bytes_at_a_fixed_rate() {
        let now = Instant::now();
        let budget = EgressBudget::new_at(now);
        assert!(budget.try_consume_at(EGRESS_BURST_BYTES as usize, now));
        assert!(!budget.try_consume_at(1, now));
        assert!(budget.try_consume_at(
            EGRESS_BYTES_PER_SECOND as usize,
            now + Duration::from_secs(1)
        ));
        assert!(!budget.try_consume_at(1, now + Duration::from_secs(1)));
    }

    #[test]
    fn close_all_releases_every_endpoint_slot() {
        let mut bridge = SubstitutionBridge::new();
        let active = Arc::new(AtomicUsize::new(0));
        bridge.set_activity(active.clone());
        for conn_id in 0..3 {
            let (stream, _peer) = UnixStream::pair().unwrap();
            bridge.conns.insert(
                conn_id,
                EndpointConn {
                    stream,
                    last_activity: Instant::now(),
                },
            );
            assert!(bridge.budget.try_reserve_stream());
            bridge.bump(1);
        }

        bridge.close_all();

        assert!(!bridge.is_active());
        assert_eq!(active.load(Ordering::Relaxed), 0);
        assert!(bridge.budget.try_reserve_stream());
    }
}
