//! The host-side substitution bridge — guest egress stream ↔ per-VM endpoint UDS.
//!
//! A pure byte relay: the guest's egress port streams to the per-VM
//! `mvm-network-endpoint`, which owns the whole egress decision — claim-10
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
pub(crate) const READ_CHUNK: usize = 16 * 1024;
/// Maximum number of active raw/SOCKS5/DNS/substitution streams per workload.
pub(crate) const MAX_EGRESS_STREAMS: usize = 128;
/// Sustained egress byte rate shared by all host-mediated workload streams.
/// This is a refillable throughput limit, not a cumulative download-size cap.
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

/// How long to sleep between refill checks while an established stream waits
/// for byte tokens.
const BUDGET_REFILL_POLL: std::time::Duration = std::time::Duration::from_millis(1);

/// Host-side resource ceilings applied to one VM's relayed egress. `None` on any
/// field means that ceiling does not apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EgressLimits {
    /// Sustained byte rate, refilled continuously.
    pub bytes_per_second: Option<u64>,
    /// Concurrent relayed streams.
    pub max_streams: Option<usize>,
    /// Evict a relayed stream after this long with no traffic.
    pub idle_timeout: Option<std::time::Duration>,
}

impl EgressLimits {
    /// An untrusted workload: every ceiling applies.
    pub(crate) const fn workload() -> Self {
        Self {
            bytes_per_second: Some(EGRESS_BYTES_PER_SECOND),
            max_streams: Some(MAX_EGRESS_STREAMS),
            idle_timeout: Some(CONNECTION_IDLE_TIMEOUT),
        }
    }

    /// A trusted builder VM: it builds nix templates, reports stdout/stderr, and
    /// exits. It carries no untrusted workload, so none of the workload ceilings
    /// apply — each one only breaks builds. The rate cap throttles
    /// multi-gigabyte substituter pulls; the stream cap refuses connections once
    /// nix parallelizes past it; the idle timeout drops keep-alive connections
    /// while a derivation compiles.
    pub(crate) const fn trusted_builder() -> Self {
        Self {
            bytes_per_second: None,
            max_streams: None,
            idle_timeout: None,
        }
    }
}

/// Shared per-VM egress budget. The egress and broker ports use one instance so
/// a workload cannot multiply its allowance by opening both paths.
#[derive(Clone)]
pub(crate) struct EgressBudget {
    state: Arc<Mutex<EgressBudgetState>>,
    limits: EgressLimits,
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
        Self::at(now, EgressLimits::workload())
    }

    /// A budget carrying no workload ceiling — see [`EgressLimits::trusted_builder`].
    pub(crate) fn trusted_builder() -> Self {
        Self::trusted_builder_at(Instant::now())
    }

    fn trusted_builder_at(now: Instant) -> Self {
        Self::at(now, EgressLimits::trusted_builder())
    }

    fn at(now: Instant, limits: EgressLimits) -> Self {
        Self {
            state: Arc::new(Mutex::new(EgressBudgetState {
                active_streams: 0,
                byte_tokens: EGRESS_BURST_BYTES,
                last_refill: now,
            })),
            limits,
        }
    }

    /// How long a relayed stream may sit idle before eviction.
    fn idle_timeout(&self) -> Option<std::time::Duration> {
        self.limits.idle_timeout
    }

    /// Acquire `bytes` tokens, waiting for the bucket to refill if it is dry.
    ///
    /// Returns false only when `bytes` exceeds the burst ceiling — a payload no
    /// amount of waiting can admit. Everything else eventually succeeds, because
    /// tokens refill monotonically at a fixed rate.
    ///
    /// Throttling must never tear down an established stream: the host→guest
    /// drain already backpressures this way, and resetting the guest→host side
    /// instead killed in-flight TLS transfers mid-download.
    fn consume_waiting(&self, bytes: usize) -> bool {
        if self.limits.bytes_per_second.is_none() {
            return true;
        }
        if u64::try_from(bytes).unwrap_or(u64::MAX) > EGRESS_BURST_BYTES {
            return false;
        }
        while !self.try_consume(bytes) {
            std::thread::sleep(BUDGET_REFILL_POLL);
        }
        true
    }

    fn try_reserve_stream(&self) -> bool {
        let mut state = self.state.lock().expect("egress budget mutex poisoned");
        if let Some(max) = self.limits.max_streams
            && state.active_streams >= max
        {
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
        let Some(rate) = self.limits.bytes_per_second else {
            return true;
        };
        let mut state = self.state.lock().expect("egress budget mutex poisoned");
        refill_tokens(&mut state, rate, now);

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
        let Some(rate) = self.limits.bytes_per_second else {
            return max;
        };
        let mut state = self.state.lock().expect("egress budget mutex poisoned");
        refill_tokens(&mut state, rate, now);
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

fn refill_tokens(state: &mut EgressBudgetState, rate: u64, now: Instant) {
    let elapsed_nanos = now.saturating_duration_since(state.last_refill).as_nanos();
    let refill = elapsed_nanos.saturating_mul(u128::from(rate)) / 1_000_000_000;
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
    /// Open the endpoint side of `conn_id` before any guest bytes arrive.
    ///
    /// Needed because the endpoint speaks first on this channel: the FlowMux
    /// session handshake opens with the host's `SessionHello`, so a guest that
    /// has connected sits in a read. Deferring the endpoint dial to the first
    /// guest payload deadlocks that exchange — each side waits for the other.
    ///
    /// Returns `false` when the connection cannot be opened, which is the same
    /// fail-closed set [`Self::relay_guest_bytes`] refuses on: no endpoint
    /// bound, the per-guest connection cap, an exhausted stream budget, or a
    /// failed dial.
    fn open_connection(&mut self, conn_id: u32) -> bool;

    /// Relay guest→host bytes for `conn_id`, opening the endpoint connection if
    /// [`Self::open_connection`] has not already. Implementations fail closed on
    /// missing endpoints or connect failures.
    fn relay_guest_bytes(&mut self, conn_id: u32, payload: &[u8]) -> EndpointRelayAction;

    /// Drain host→guest endpoint bytes once from every active connection.
    #[allow(dead_code)]
    fn drain_endpoint_bytes(&mut self) -> EndpointRelayDrain;

    /// Drain endpoint bytes with a per-connection read limit.
    ///
    /// `limit(conn_id)` returns the maximum bytes to read for that connection.
    /// A limit of zero skips the connection, leaving any buffered bytes in the
    /// socket for a later drain.
    fn drain_endpoint_bytes_limited(
        &mut self,
        limit: &mut dyn FnMut(u32) -> usize,
    ) -> EndpointRelayDrain;

    /// Close the endpoint side of `conn_id`.
    fn close_connection(&mut self, conn_id: u32);

    /// Whether any endpoint connections are still active.
    fn is_active(&self) -> bool;
}

/// The substitution transport for one guest.
pub(crate) struct SubstitutionBridge {
    /// Per-VM `mvm-network-endpoint` socket. `None` ⇒ no endpoint, fail-closed.
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

    /// Swap the shared budget. Called during device setup, before any stream
    /// exists, so no in-flight reservation is stranded.
    pub(crate) fn set_budget(&mut self, budget: EgressBudget) {
        self.budget = budget;
    }

    /// Share the open-connection counter with the run loop heartbeat.
    pub fn set_activity(&mut self, counter: Arc<AtomicUsize>) {
        self.active = Some(counter);
    }

    pub(crate) fn has_binding(&self) -> bool {
        self.endpoint.is_some()
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
        let Some(idle_timeout) = self.budget.idle_timeout() else {
            return Vec::new();
        };
        let mut expired = Vec::new();
        self.conns.retain(|conn_id, conn| {
            let keep = now.saturating_duration_since(conn.last_activity) < idle_timeout;
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
    fn open_connection(&mut self, conn_id: u32) -> bool {
        if self.conns.contains_key(&conn_id) {
            return true;
        }
        if self.conns.len() >= MAX_CONNECTIONS {
            return false;
        }
        if !self.budget.try_reserve_stream() {
            return false;
        }
        let Some(path) = self.endpoint.clone() else {
            self.budget.release_stream();
            return false;
        };
        match UnixStream::connect(&path) {
            Ok(stream) => {
                let _ = stream.set_nonblocking(true);
                self.conns.insert(
                    conn_id,
                    EndpointConn {
                        stream,
                        last_activity: Instant::now(),
                    },
                );
                self.bump(1);
                true
            }
            Err(_) => {
                self.budget.release_stream();
                false
            }
        }
    }

    fn relay_guest_bytes(&mut self, conn_id: u32, payload: &[u8]) -> EndpointRelayAction {
        if !self.open_connection(conn_id) {
            return EndpointRelayAction::Refused;
        }
        if !self.budget.consume_waiting(payload.len()) {
            return EndpointRelayAction::Refused;
        }
        let conn = self
            .conns
            .get_mut(&conn_id)
            .expect("open_connection returned true, so the connection is present");
        write_nonblocking(&mut conn.stream, payload);
        conn.last_activity = Instant::now();
        EndpointRelayAction::Relayed
    }

    fn drain_endpoint_bytes(&mut self) -> EndpointRelayDrain {
        self.drain_endpoint_bytes_limited(&mut |_| READ_CHUNK)
    }

    fn drain_endpoint_bytes_limited(
        &mut self,
        limit: &mut dyn FnMut(u32) -> usize,
    ) -> EndpointRelayDrain {
        let mut ready = Vec::new();
        let mut closed = self.evict_idle_at(Instant::now());
        for (conn_id, conn) in self.conns.iter_mut() {
            let max = limit(*conn_id);
            if max == 0 {
                continue;
            }
            let allowance = self
                .budget
                .reserve_read(max.min(READ_CHUNK), Instant::now());

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

    /// Opening ahead of any guest bytes is what lets a host-first protocol
    /// greet the guest. It must still fail closed with nothing bound, and must
    /// hand the stream reservation back when it does — otherwise a guest that
    /// retries its connect burns the budget down and the endpoint that finally
    /// arrives can never be dialed.
    #[test]
    fn open_connection_fails_closed_without_an_endpoint_and_returns_the_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");

        let mut b = SubstitutionBridge::new();
        for conn_id in 0..MAX_EGRESS_STREAMS as u32 + 1 {
            assert!(!b.open_connection(conn_id), "nothing is bound yet");
        }
        assert!(!b.is_active());

        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        let server = std::thread::spawn(move || listener.accept().map(|(c, _)| c));
        b.set_endpoint(&sock);
        assert!(
            b.open_connection(0),
            "every refused open returned its reservation, so the budget has room"
        );
        drop(server.join().unwrap());
    }

    /// An opened connection is live before a single guest byte, and closing it
    /// gives the stream slot back.
    #[test]
    fn open_connection_is_active_before_any_guest_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");
        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        let server = std::thread::spawn(move || listener.accept().map(|(c, _)| c));

        let mut b = SubstitutionBridge::new();
        b.set_endpoint(&sock);
        assert!(b.open_connection(9));
        assert!(
            b.is_active(),
            "the endpoint side is open with no guest bytes"
        );
        // Idempotent: a second open on the same id reuses the connection.
        assert!(b.open_connection(9));
        assert_eq!(b.conns.len(), 1);

        b.close_connection(9);
        assert!(!b.is_active());
        drop(server.join().unwrap());
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
    fn an_established_stream_is_throttled_not_reset_when_the_budget_is_dry() {
        let sock =
            std::env::temp_dir().join(format!("mvm-egress-throttle-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = bind_unix_listener(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut sink = Vec::new();
            let _ = stream.read_to_end(&mut sink);
            sink.len()
        });

        let mut bridge = SubstitutionBridge::new();
        bridge.set_endpoint(&sock);
        assert_eq!(
            bridge.relay_guest_bytes(7, b"open"),
            EndpointRelayAction::Relayed
        );

        // Drain every token, then keep writing on the already-open stream. A
        // rate-limited stream must survive: resetting it here is what tore down
        // nix's in-flight TLS downloads mid-transfer.
        while bridge.budget.try_consume(64 * 1024) {}
        for _ in 0..4 {
            assert_eq!(
                bridge.relay_guest_bytes(7, &[b'x'; 1024]),
                EndpointRelayAction::Relayed,
                "an open stream must backpressure, never reset"
            );
        }

        bridge.close_connection(7);
        drop(bridge);
        assert_eq!(server.join().unwrap(), 4 + 4 * 1024);
        let _ = std::fs::remove_file(&sock);
    }

    #[test]
    fn a_payload_larger_than_the_burst_ceiling_is_refused() {
        // No amount of waiting admits this one, so it must fail closed rather
        // than spin forever.
        let budget = EgressBudget::new();
        let oversized = usize::try_from(EGRESS_BURST_BYTES).unwrap() + 1;
        assert!(!budget.consume_waiting(oversized));
    }

    #[test]
    fn a_trusted_builder_budget_ignores_the_byte_rate() {
        let now = Instant::now();
        let budget = EgressBudget::trusted_builder_at(now);
        let ten_mib = 10 * 1024 * 1024;
        for _ in 0..64 {
            assert!(budget.try_consume_at(ten_mib, now));
        }
        assert!(budget.consume_waiting(ten_mib));
        // Even a payload past the workload burst ceiling, which a metered
        // budget refuses outright.
        assert!(budget.consume_waiting(usize::try_from(EGRESS_BURST_BYTES).unwrap() + 1));
    }

    #[test]
    fn a_trusted_builder_budget_does_not_cap_concurrent_streams() {
        // nix parallelizes downloads well past the workload ceiling; refusing
        // there resets the connection.
        let budget = EgressBudget::trusted_builder();
        for _ in 0..(MAX_EGRESS_STREAMS * 4) {
            assert!(budget.try_reserve_stream());
        }
    }

    #[test]
    fn a_trusted_builder_stream_is_never_evicted_for_being_idle() {
        // A connection kept open while a derivation compiles must survive.
        let mut bridge = SubstitutionBridge::with_budget(EgressBudget::trusted_builder());
        let (stream, _peer) = UnixStream::pair().unwrap();
        bridge.conns.insert(
            7,
            EndpointConn {
                stream,
                last_activity: Instant::now() - CONNECTION_IDLE_TIMEOUT - Duration::from_secs(600),
            },
        );

        assert!(bridge.evict_idle_at(Instant::now()).is_empty());
        assert!(bridge.conns.contains_key(&7));
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
    fn egress_budget_has_no_lifetime_download_cap() {
        const FOUR_GIB: u64 = 4 * 1024 * 1024 * 1024;

        let now = Instant::now();
        let budget = EgressBudget::new_at(now);
        let chunk = usize::try_from(EGRESS_BYTES_PER_SECOND).unwrap();
        let seconds = FOUR_GIB / EGRESS_BYTES_PER_SECOND;

        for second in 0..seconds {
            assert!(budget.try_consume_at(chunk, now + Duration::from_secs(second)));
        }
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
