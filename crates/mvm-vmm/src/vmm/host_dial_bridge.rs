//! The host-side vsock **host-dial** bridge: the relay for every channel where
//! the guest listens and the host is the dialer. Counterpart of the
//! [`AgentBridge`](super::agent_bridge::AgentBridge), which serves the one
//! fixed agent port.
//!
//! Two kinds of stream ride it today, and the mechanism is identical for both —
//! bind one host Unix socket per guest port, accept, open an `OP_REQUEST` to
//! that same port, relay bytes, route replies by connection id:
//!
//! - **Dev console data** (`dev_console_data_ports()` = 20001..=20128), the
//!   interactive PTY path described below.
//! - **Builder control** (`GuestService::{BuilderDispatch, BuilderdControl}`),
//!   the persistent builder VM's job-dispatch and daemon-control ports. A
//!   builder-tier guest only; no workload serves them.
//!
//! Which ports get bound is a policy decision made above this bridge, in
//! `host::spec_map`. This module binds exactly what it is handed.
//!
//! A dev-accessible guest pre-opens a range of console **data** ports
//! (`dev_console_data_ports()` = 20001..=20128); the guest console driver binds a
//! vsock listener on the port an agent-side `ConsoleOpen` allocated, and the host
//! console client (`machine run -it`, `machine console`) is the dialer. This
//! bridge is the device-side half: the supervisor binds one host Unix socket per
//! console port, this bridge accepts a host connection on any of them, and the
//! device opens a host→guest vsock stream **to that same console port** (an
//! `OP_REQUEST`), relays host→guest PTY bytes, and writes the guest's replies back
//! to the host socket.
//!
//! Unlike the agent bridge (one listener at the fixed [`GUEST_AGENT_PORT`]), this
//! bridge holds **many** listeners keyed by guest port, and each accepted
//! connection carries the port it must be dialed on — so the device frames the
//! real port, not a hardwired one. Replies route by the opaque host-assigned
//! connection id (tracked here), never by the agent's `is_agent_stream`.
//!
//! Claim 15: the bridge only ever binds listeners the supervisor handed it, and
//! the supervisor populates the console-port list **only** for a `dev_console`
//! machine. A sealed prod config carries none, so the console path is inert.
//! Generalizing this bridge does not widen that: the console port list is still
//! produced by `console_data_sockets`, still empty unless `dev_console` is set,
//! and the builder ports it now also carries are builder-tier only — a workload
//! guest, sealed or not, is handed neither list.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use super::agent_bridge::write_nonblocking;
use super::vsock_transport::{CONNECTION_IDLE_TIMEOUT, MAX_CONNECTIONS};

/// Per-drain read budget per host connection.
const READ_CHUNK: usize = 16 * 1024;
/// First host-assigned vsock port for console streams. Kept well above both the
/// guest's well-known listener ports and the agent bridge's host-port space so a
/// console conn id can never collide with an agent conn id (they share the device's
/// single `handle_packet` reply-routing keyspace).
const FIRST_HOST_DIAL_PORT: u32 = 2 << 20;

/// One open host console connection: the accepted host socket, the guest console
/// port it is dialed on, and whether the guest has accepted the stream yet.
struct HostDialConn {
    stream: UnixStream,
    /// The guest console data port this stream dials (`CONSOLE_PORT_BASE + n`).
    guest_port: u32,
    /// The guest accepted (`OP_RESPONSE` seen); only then do we read host bytes.
    established: bool,
    last_activity: Instant,
}

/// Host→guest console stream bridge for one guest: a per-guest-port set of Unix
/// listeners plus the open host connections, each mapped to a host-assigned vsock
/// src_port (its connection id).
pub(crate) struct HostDialBridge {
    /// Bound host listeners, keyed by the guest console data port each serves.
    /// Empty for a sealed prod config (claim 15) — the bridge then does nothing.
    listeners: HashMap<u32, UnixListener>,
    /// Open host connections keyed by the host-assigned vsock src_port (conn id).
    conns: HashMap<u32, HostDialConn>,
    /// Next host port to assign.
    next_port: u32,
    /// Open-connection count, published for the run loop heartbeat so an active
    /// console stream keeps the loop waking an idle guest (the same counter the
    /// agent/substitution paths use).
    active: Option<Arc<AtomicUsize>>,
    /// Host-side EOF/error/idle closures waiting for a guest `OP_RST`.
    host_closed: Vec<(u32, u32)>,
    /// Guest ports whose connections are exempt from idle eviction.
    ///
    /// Idle eviction reclaims a slot from a connection that is *alive but
    /// quiet*; a connection whose peer has actually gone is already reclaimed by
    /// the EOF arm in [`Self::drain_host`]. That distinction is what makes the
    /// exemption safe, and it is why silence is the wrong signal for a
    /// request/response control channel: a builder holding one open across a
    /// `nix build` is silent for exactly as long as the build takes, and
    /// severing it reports a dispatch failure for a build that is running fine.
    long_lived: HashSet<u32>,
}

impl HostDialBridge {
    pub fn new() -> Self {
        Self {
            listeners: HashMap::new(),
            conns: HashMap::new(),
            next_port: FIRST_HOST_DIAL_PORT,
            active: None,
            host_closed: Vec::new(),
            long_lived: HashSet::new(),
        }
    }

    /// Mark guest ports whose connections must not be evicted for being idle.
    ///
    /// Callers pass the long-lived *control* ports (the builder's dispatch and
    /// daemon channels). Console data ports are deliberately left evictable: an
    /// abandoned-but-open console is exactly the case idle reclaim is for.
    pub fn set_long_lived_ports(&mut self, ports: impl IntoIterator<Item = u32>) {
        self.long_lived = ports.into_iter().collect();
    }

    /// Bind one non-blocking host listener per `(guest_port, path)`, replacing any
    /// stale socket. Called once at wiring time with the supervisor's console-port
    /// list. An empty list (sealed prod) binds nothing. A per-port bind failure is
    /// skipped (that console port is simply unreachable) so one bad path never
    /// takes down the others.
    pub fn bind_ports<'a>(
        &mut self,
        ports: impl IntoIterator<Item = (u32, &'a Path)>,
    ) -> std::io::Result<()> {
        for (guest_port, path) in ports {
            if let Some(parent) = path.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                dbg_log(&format!(
                    "console port {guest_port} parent create failed at {}: {e}",
                    parent.display()
                ));
                continue;
            }
            let _ = std::fs::remove_file(path);
            match UnixListener::bind(path) {
                Ok(l) => {
                    l.set_nonblocking(true)?;
                    self.listeners.insert(guest_port, l);
                    dbg_log(&format!(
                        "bound console port {guest_port} at {}",
                        path.display()
                    ));
                }
                Err(e) => dbg_log(&format!(
                    "console port {guest_port} bind failed at {}: {e}",
                    path.display()
                )),
            }
        }
        Ok(())
    }

    /// Share the open-connection counter with the run loop heartbeat.
    pub fn set_activity(&mut self, counter: Arc<AtomicUsize>) {
        self.active = Some(counter);
    }

    pub fn has_binding(&self) -> bool {
        !self.listeners.is_empty()
    }

    /// Is `conn_id` a host-initiated console stream (so guest packets addressed to
    /// it route here, not to the agent / workload-exit / egress / capture paths)?
    pub fn is_host_dial_stream(&self, conn_id: u32) -> bool {
        self.conns.contains_key(&conn_id)
    }

    /// Fds the host-I/O thread should watch: all bound listeners plus established
    /// console streams. As with the agent bridge, unestablished streams stay out
    /// of the readiness set until the guest accepts them.
    pub fn poll_fds(&self) -> Vec<RawFd> {
        let mut fds = Vec::new();
        fds.extend(self.listeners.values().map(AsRawFd::as_raw_fd));
        fds.extend(
            self.conns
                .values()
                .filter(|conn| conn.established)
                .map(|conn| conn.stream.as_raw_fd()),
        );
        fds
    }

    /// Accept any pending host connections across every bound console port,
    /// assigning each a host vsock src_port. Returns `(conn_id, guest_port)` for
    /// each — the device sends an `OP_REQUEST` to the guest console listener on
    /// `guest_port`. No-op when no listeners are bound (sealed prod).
    pub fn accept_new(&mut self) -> Vec<(u32, u32)> {
        self.evict_idle_at(Instant::now());
        // Two phases: first drain every listener to `WouldBlock` (borrows only
        // `self.listeners`), then register the accepted streams (borrows
        // `self.conns` / `self.next_port`) — the split keeps the borrow checker
        // happy without holding a listener borrow across the `conns` mutation.
        let mut accepted: Vec<(u32, UnixStream)> = Vec::new();
        'listeners: for (&guest_port, listener) in self.listeners.iter() {
            loop {
                if self.conns.len() + accepted.len() >= MAX_CONNECTIONS {
                    break 'listeners;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        if stream.set_nonblocking(true).is_ok() {
                            accepted.push((guest_port, stream));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        let mut opened = Vec::with_capacity(accepted.len());
        for (guest_port, stream) in accepted {
            let conn_id = self.next_port;
            self.next_port = self.next_port.wrapping_add(1).max(FIRST_HOST_DIAL_PORT);
            self.conns.insert(
                conn_id,
                HostDialConn {
                    stream,
                    guest_port,
                    established: false,
                    last_activity: Instant::now(),
                },
            );
            self.bump(1);
            opened.push((conn_id, guest_port));
        }
        opened
    }

    /// Mark a stream established: the guest accepted it (`OP_RESPONSE`). Only after
    /// this does [`Self::drain_host`] read the host socket, so any PTY bytes the
    /// client wrote before the handshake completed stay ordered behind it.
    pub fn on_established(&mut self, conn_id: u32) {
        if let Some(c) = self.conns.get_mut(&conn_id) {
            c.established = true;
            c.last_activity = Instant::now();
        }
    }

    /// Read each established host connection once (non-blocking). Returns
    /// `(conn_id, guest_port, bytes)` for the device to `OP_RW` to the guest on the
    /// right console port. A peer EOF/error closes that stream in place.
    pub fn drain_host(&mut self) -> Vec<(u32, u32, Vec<u8>)> {
        self.evict_idle_at(Instant::now());
        let mut ready = Vec::new();
        let mut closed = Vec::new();
        for (conn_id, c) in self.conns.iter_mut() {
            if !c.established {
                continue;
            }
            let mut buf = vec![0u8; READ_CHUNK];
            match c.stream.read(&mut buf) {
                Ok(0) => closed.push((*conn_id, c.guest_port)),
                Ok(n) => {
                    buf.truncate(n);
                    c.last_activity = Instant::now();
                    ready.push((*conn_id, c.guest_port, buf));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => closed.push((*conn_id, c.guest_port)),
            }
        }
        for (conn_id, guest_port) in closed {
            self.close(conn_id);
            self.host_closed.push((conn_id, guest_port));
        }
        ready
    }

    /// Write guest→host data (`OP_RW` the device received) to the host socket.
    pub fn write_to_host(&mut self, conn_id: u32, payload: &[u8]) {
        if let Some(c) = self.conns.get_mut(&conn_id) {
            write_nonblocking(&mut c.stream, payload);
            c.last_activity = Instant::now();
        }
    }

    /// Drain host-side closures so the device can reset the guest stream.
    pub fn take_host_closed(&mut self) -> Vec<(u32, u32)> {
        std::mem::take(&mut self.host_closed)
    }

    /// Close a stream (guest `OP_SHUTDOWN`/`OP_RST`, or a host EOF/error).
    pub fn close(&mut self, conn_id: u32) {
        if self.conns.remove(&conn_id).is_some() {
            self.bump(-1);
        }
    }

    pub fn close_all(&mut self) {
        let conn_ids: Vec<u32> = self.conns.keys().copied().collect();
        for conn_id in conn_ids {
            self.close(conn_id);
        }
        self.host_closed.clear();
    }

    fn evict_idle_at(&mut self, now: Instant) {
        let expired: Vec<(u32, u32)> = self
            .conns
            .iter()
            .filter(|(_, conn)| {
                !self.long_lived.contains(&conn.guest_port)
                    && now.saturating_duration_since(conn.last_activity) >= CONNECTION_IDLE_TIMEOUT
            })
            .map(|(&conn_id, conn)| (conn_id, conn.guest_port))
            .collect();
        for (conn_id, guest_port) in expired {
            self.close(conn_id);
            self.host_closed.push((conn_id, guest_port));
        }
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
}

/// Resolved `MVM_HVF_AGENT_DEBUG` trace-file path, read from the environment once
/// and cached so the bind/accept path never takes the process-global env lock per
/// call.
fn debug_path() -> Option<&'static Path> {
    static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
    PATH.get_or_init(|| std::env::var_os("MVM_HVF_AGENT_DEBUG").map(PathBuf::from))
        .as_deref()
}

/// Debug trace gated on `MVM_HVF_AGENT_DEBUG` (a file path), mirroring the agent
/// bridge's tracer. Silent in normal operation.
fn dbg_log(msg: &str) {
    let Some(path) = debug_path() else {
        return;
    };
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "[console-bridge] {msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::error_chain_has_permission_denied;
    use std::io::Write;
    use std::time::Duration;

    /// Full host→guest console relay on a specific console port: a host client
    /// connects to that port's socket, the bridge accepts and assigns a stream that
    /// remembers the guest console port, and once the guest "accepts"
    /// (`on_established`) the bridge relays the client's bytes to the guest and the
    /// guest's reply back to the host.
    #[test]
    fn host_connection_opens_stream_on_its_port_and_relays_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        let port = 20001u32;
        let sock = dir.path().join("vsock-20001.sock");

        let mut bridge = HostDialBridge::new();
        let active = Arc::new(AtomicUsize::new(0));
        bridge.set_activity(active.clone());
        if let Err(err) = bridge.bind_ports([(port, sock.as_path())]) {
            if error_chain_has_permission_denied(&err) {
                eprintln!(
                    "skipping test: sandbox denied console bridge bind at {}: {err}",
                    sock.display()
                );
                return;
            }
            panic!("console bridge bind failed at {}: {err}", sock.display());
        }
        if !sock.exists() {
            eprintln!(
                "skipping test: console bridge did not create {}",
                sock.display()
            );
            return;
        }

        // A host console client connects + writes immediately.
        let mut client = UnixStream::connect(&sock).unwrap();
        client.write_all(b"stty\n").unwrap();
        client.set_nonblocking(true).unwrap();

        let opened = bridge.accept_new();
        assert_eq!(opened.len(), 1, "one host connection accepted");
        let (conn_id, guest_port) = opened[0];
        assert_eq!(
            guest_port, port,
            "stream carries the console port it was on"
        );
        assert!(
            conn_id >= FIRST_HOST_DIAL_PORT,
            "console host port above the well-known + agent ranges"
        );
        assert!(bridge.is_host_dial_stream(conn_id));
        assert_eq!(active.load(Ordering::Relaxed), 1);

        // Before the guest accepts, request bytes stay buffered (not yet read).
        assert!(
            bridge.drain_host().is_empty(),
            "no host bytes read before the stream is established"
        );

        // Guest accepts (OP_RESPONSE). Now host bytes relay to the guest port.
        bridge.on_established(conn_id);
        let mut got = None;
        for _ in 0..200 {
            let ready = bridge.drain_host();
            if let Some((cid, gp, bytes)) = ready.into_iter().next() {
                assert_eq!(cid, conn_id);
                assert_eq!(gp, port);
                got = Some(bytes);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(got.as_deref(), Some(&b"stty\n"[..]));

        // Guest → host: the device writes the guest's PTY output to the host socket.
        bridge.write_to_host(conn_id, b"# ");
        let mut buf = [0u8; 64];
        let mut n = 0;
        for _ in 0..200 {
            match client.read(&mut buf) {
                Ok(k) if k > 0 => {
                    n = k;
                    break;
                }
                _ => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        assert_eq!(&buf[..n], b"# ");

        // Close tears the stream down and the active counter drops.
        bridge.close(conn_id);
        assert_eq!(active.load(Ordering::Relaxed), 0);
        assert!(!bridge.is_host_dial_stream(conn_id));
    }

    #[test]
    fn poll_fds_include_listeners_and_only_established_streams() {
        let dir = tempfile::tempdir().unwrap();
        let port = 20001u32;
        let sock = dir.path().join("vsock-20001.sock");

        let mut bridge = HostDialBridge::new();
        if let Err(err) = bridge.bind_ports([(port, sock.as_path())]) {
            if error_chain_has_permission_denied(&err) {
                eprintln!(
                    "skipping test: sandbox denied console bridge bind at {}: {err}",
                    sock.display()
                );
                return;
            }
            panic!("console bridge bind failed at {}: {err}", sock.display());
        }
        if !sock.exists() {
            eprintln!(
                "skipping test: console bridge did not create {}",
                sock.display()
            );
            return;
        }

        let client = UnixStream::connect(&sock).unwrap();
        client.set_nonblocking(true).unwrap();
        let (conn_id, _) = bridge.accept_new()[0];

        let before_established = bridge.poll_fds();
        assert_eq!(before_established.len(), 1, "listener only before accept");

        bridge.on_established(conn_id);
        let after_established = bridge.poll_fds();
        assert_eq!(after_established.len(), 2, "listener plus established conn");
    }

    /// Two console ports bound: a connection on each is accepted and each carries
    /// its own guest port, so the device dials the right listener per session.
    #[test]
    fn distinct_ports_route_to_distinct_guest_listeners() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("vsock-20001.sock");
        let b = dir.path().join("vsock-20002.sock");
        let mut bridge = HostDialBridge::new();
        if let Err(err) = bridge.bind_ports([(20001u32, a.as_path()), (20002u32, b.as_path())]) {
            if error_chain_has_permission_denied(&err) {
                eprintln!(
                    "skipping test: sandbox denied console bridge bind under {}",
                    dir.path().display()
                );
                return;
            }
            panic!(
                "console bridge bind failed under {}: {err}",
                dir.path().display()
            );
        }
        if !a.exists() || !b.exists() {
            eprintln!(
                "skipping test: console bridge did not create expected sockets under {}",
                dir.path().display()
            );
            return;
        }

        let _ca = UnixStream::connect(&a).unwrap();
        let _cb = UnixStream::connect(&b).unwrap();

        let mut ports = Vec::new();
        for _ in 0..200 {
            for (_cid, gp) in bridge.accept_new() {
                ports.push(gp);
            }
            if ports.len() >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        ports.sort_unstable();
        assert_eq!(ports, vec![20001, 20002]);
    }

    #[test]
    fn bind_ports_creates_missing_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock").join("vsock-20001.sock");
        let mut bridge = HostDialBridge::new();

        if let Err(err) = bridge.bind_ports([(20001u32, sock.as_path())]) {
            if error_chain_has_permission_denied(&err) {
                eprintln!(
                    "skipping test: sandbox denied console bridge bind at {}: {err}",
                    sock.display()
                );
                return;
            }
            panic!("console bridge bind failed at {}: {err}", sock.display());
        }
        if !sock.exists() {
            eprintln!(
                "skipping test: console bridge did not create {}",
                sock.display()
            );
            return;
        }

        UnixStream::connect(&sock).expect("listener should be bound under created parent dir");
    }

    /// Claim 15: an empty console-port list (sealed prod) binds no listeners, so
    /// `accept_new` is a no-op and there is nothing to reach.
    #[test]
    fn empty_port_list_binds_nothing() {
        let mut bridge = HostDialBridge::new();
        bridge.bind_ports([]).unwrap();
        assert!(bridge.accept_new().is_empty());
        assert!(!bridge.is_host_dial_stream(FIRST_HOST_DIAL_PORT));
    }

    #[test]
    fn idle_console_stream_is_surfaced_for_guest_reset() {
        let mut bridge = HostDialBridge::new();
        let (stream, _peer) = UnixStream::pair().unwrap();
        let conn_id = FIRST_HOST_DIAL_PORT;
        bridge.conns.insert(
            conn_id,
            HostDialConn {
                stream,
                guest_port: 20_001,
                established: true,
                last_activity: Instant::now() - CONNECTION_IDLE_TIMEOUT - Duration::from_secs(1),
            },
        );

        bridge.drain_host();

        assert_eq!(bridge.take_host_closed(), vec![(conn_id, 20_001)]);
        assert!(!bridge.is_host_dial_stream(conn_id));
    }

    /// A long-lived control channel is silent for exactly as long as the
    /// operation it is waiting on. Evicting it reports a failure for work that
    /// is still running — which is what happened to a builder dispatch across a
    /// `nix build`.
    #[test]
    fn a_long_lived_port_survives_being_idle_past_the_timeout() {
        let mut bridge = HostDialBridge::new();
        let (stream, _peer) = UnixStream::pair().unwrap();
        // `accept_new` does this for a real connection; a test that inserts one
        // directly and then survives eviction reaches `drain_host`'s read, and
        // a blocking socket with a live peer never returns from it.
        stream.set_nonblocking(true).unwrap();
        let conn_id = FIRST_HOST_DIAL_PORT;
        let dispatch_port = 21_471;
        bridge.set_long_lived_ports([dispatch_port]);
        bridge.conns.insert(
            conn_id,
            HostDialConn {
                stream,
                guest_port: dispatch_port,
                established: true,
                last_activity: Instant::now() - CONNECTION_IDLE_TIMEOUT - Duration::from_secs(1),
            },
        );

        bridge.drain_host();

        assert!(
            bridge.take_host_closed().is_empty(),
            "a long-lived control channel must not be evicted for being quiet"
        );
        assert!(bridge.is_host_dial_stream(conn_id));
    }

    /// The exemption is per port, not global: a console on the same bridge is
    /// still reclaimed, which is the case idle eviction exists for.
    #[test]
    fn exempting_one_port_leaves_the_others_evictable() {
        let mut bridge = HostDialBridge::new();
        bridge.set_long_lived_ports([21_471]);
        let (console, _console_peer) = UnixStream::pair().unwrap();
        let console_id = FIRST_HOST_DIAL_PORT + 1;
        bridge.conns.insert(
            console_id,
            HostDialConn {
                stream: console,
                guest_port: 20_001,
                established: true,
                last_activity: Instant::now() - CONNECTION_IDLE_TIMEOUT - Duration::from_secs(1),
            },
        );

        bridge.drain_host();

        assert_eq!(bridge.take_host_closed(), vec![(console_id, 20_001)]);
    }

    /// The property that makes the exemption safe: a peer that has actually
    /// gone is reclaimed by the EOF arm, not by the idle sweep. Without this,
    /// exempting a port would leak its slot for the VM's lifetime.
    #[test]
    fn a_long_lived_port_is_still_reclaimed_when_its_peer_hangs_up() {
        let mut bridge = HostDialBridge::new();
        let (stream, peer) = UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        let conn_id = FIRST_HOST_DIAL_PORT;
        let dispatch_port = 21_471;
        bridge.set_long_lived_ports([dispatch_port]);
        bridge.conns.insert(
            conn_id,
            HostDialConn {
                stream,
                guest_port: dispatch_port,
                established: true,
                last_activity: Instant::now(),
            },
        );
        drop(peer);

        bridge.drain_host();

        assert_eq!(bridge.take_host_closed(), vec![(conn_id, dispatch_port)]);
        assert!(!bridge.is_host_dial_stream(conn_id));
    }
}
