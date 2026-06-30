//! The host-side vsock agent bridge — the host→guest counterpart of
//! [`EgressProxy`](super::egress_proxy::EgressProxy).
//!
//! The guest agent listens on the guest's vsock [`GUEST_AGENT_PORT`] (5252); the
//! host is the client. A host process (the `machine invoke` / agent-RPC client)
//! connects to a Unix socket the supervisor exposes; this bridge accepts that
//! connection and opens a host→guest vsock stream to the agent: it emits an
//! `OP_REQUEST` to the guest, relays host→guest bytes once the guest accepts, and
//! writes the guest's replies back to the host socket.
//!
//! Like [`EgressProxy`] it is **transport-agnostic**: keyed by an opaque
//! connection id (the in-house VMM uses the host-assigned vsock `src_port`), it
//! speaks raw bytes, never a virtqueue or vsock header — the device owns the
//! framing. Each connection is read only once the guest has accepted it
//! (`on_established`), so a client that writes its request immediately leaves
//! those bytes buffered in the socket until the stream is up, preserving order.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Per-drain read budget per host connection.
const READ_CHUNK: usize = 16 * 1024;
/// First host-assigned vsock port. Host-initiated streams take ports from here up
/// so they never collide with the guest's well-known listener ports (5251/5252/
/// 5253) or each other.
const FIRST_HOST_PORT: u32 = 1 << 20;

struct AgentConn {
    stream: UnixStream,
    /// The guest accepted (`OP_RESPONSE` seen); only then do we read host bytes.
    established: bool,
}

/// Host→guest agent stream bridge for one guest: a Unix listener plus the open
/// host connections, each mapped to a host-assigned vsock src_port.
pub(crate) struct AgentBridge {
    /// Non-blocking listener at the host agent socket; `None` until [`Self::bind`].
    listener: Option<UnixListener>,
    /// Open host connections keyed by the host-assigned vsock src_port (conn id).
    conns: HashMap<u32, AgentConn>,
    /// Next host port to assign.
    next_port: u32,
    /// Open-connection count, published for the run loop heartbeat (it must keep
    /// waking an idle guest while there is an agent stream to service).
    active: Option<Arc<AtomicUsize>>,
}

impl AgentBridge {
    pub fn new() -> Self {
        Self {
            listener: None,
            conns: HashMap::new(),
            next_port: FIRST_HOST_PORT,
            active: None,
        }
    }

    /// Create the host agent listener at `path` (replacing any stale socket).
    /// Non-blocking so [`Self::accept_new`] never stalls the run loop.
    pub fn bind(&mut self, path: &Path) -> std::io::Result<()> {
        let _ = std::fs::remove_file(path);
        let l = UnixListener::bind(path)?;
        l.set_nonblocking(true)?;
        self.listener = Some(l);
        Ok(())
    }

    /// Share the open-connection counter with the run loop heartbeat.
    pub fn set_activity(&mut self, counter: Arc<AtomicUsize>) {
        self.active = Some(counter);
    }

    /// Is `conn_id` a host-initiated agent stream (so guest packets addressed to it
    /// route here, not to the workload-exit / egress / capture paths)?
    pub fn is_agent_stream(&self, conn_id: u32) -> bool {
        self.conns.contains_key(&conn_id)
    }

    /// Accept any pending host connections, assigning each a host vsock src_port.
    /// Returns the new conn ids — the device sends an `OP_REQUEST` to the guest
    /// agent (dst_port [`GUEST_AGENT_PORT`]) for each. No-op without a listener.
    pub fn accept_new(&mut self) -> Vec<u32> {
        let mut opened = Vec::new();
        let Some(listener) = &self.listener else {
            return opened;
        };
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    if stream.set_nonblocking(true).is_err() {
                        continue;
                    }
                    let conn_id = self.next_port;
                    self.next_port = self.next_port.wrapping_add(1).max(FIRST_HOST_PORT);
                    self.conns.insert(
                        conn_id,
                        AgentConn {
                            stream,
                            established: false,
                        },
                    );
                    self.bump(1);
                    opened.push(conn_id);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        opened
    }

    /// Mark a stream established: the guest accepted it (`OP_RESPONSE`). Only after
    /// this does [`Self::drain_host`] read the host socket, so request bytes the
    /// client wrote before the handshake completed stay ordered behind it.
    pub fn on_established(&mut self, conn_id: u32) {
        if let Some(c) = self.conns.get_mut(&conn_id) {
            c.established = true;
        }
    }

    /// Read each established host connection once (non-blocking). Returns
    /// `(conn_id, bytes)` for the device to `OP_RW` to the guest. A peer EOF/error
    /// closes that stream in place (dropping it from the open set).
    pub fn drain_host(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut ready = Vec::new();
        let mut closed = Vec::new();
        for (conn_id, c) in self.conns.iter_mut() {
            if !c.established {
                continue;
            }
            let mut buf = vec![0u8; READ_CHUNK];
            match c.stream.read(&mut buf) {
                Ok(0) => closed.push(*conn_id),
                Ok(n) => {
                    buf.truncate(n);
                    ready.push((*conn_id, buf));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => closed.push(*conn_id),
            }
        }
        for conn_id in closed {
            self.close(conn_id);
        }
        ready
    }

    /// Write guest→host data (`OP_RW` the device received) to the host socket.
    pub fn write_to_host(&mut self, conn_id: u32, payload: &[u8]) {
        if let Some(c) = self.conns.get_mut(&conn_id) {
            write_nonblocking(&mut c.stream, payload);
        }
    }

    /// Close a stream (guest `OP_SHUTDOWN`/`OP_RST`, or a host EOF/error).
    pub fn close(&mut self, conn_id: u32) {
        if self.conns.remove(&conn_id).is_some() {
            self.bump(-1);
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

/// Write `payload` to a non-blocking socket, briefly spinning past `WouldBlock` so
/// a small frame goes out without stalling the run loop indefinitely. Mirrors the
/// egress proxy's writer.
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
    use std::time::Duration;

    /// Full host→guest relay: a host client connects, the bridge accepts and
    /// assigns a stream, and once the guest "accepts" (on_established) the bridge
    /// relays the client's request to the guest and the guest's reply back.
    #[test]
    fn host_connection_opens_stream_and_relays_both_directions() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");

        let mut bridge = AgentBridge::new();
        let active = Arc::new(AtomicUsize::new(0));
        bridge.set_activity(active.clone());
        bridge.bind(&sock).unwrap();

        // A host RPC client connects + writes its request immediately.
        let mut client = UnixStream::connect(&sock).unwrap();
        client.write_all(b"GuestRequest").unwrap();
        client.set_nonblocking(true).unwrap();

        // The bridge accepts → one new stream → the device would OP_REQUEST it.
        let opened = bridge.accept_new();
        assert_eq!(opened.len(), 1, "one host connection accepted");
        let conn_id = opened[0];
        assert!(
            conn_id >= FIRST_HOST_PORT,
            "host port above the well-known range"
        );
        assert!(bridge.is_agent_stream(conn_id));
        assert_eq!(active.load(Ordering::Relaxed), 1);

        // Before the guest accepts, request bytes stay buffered (not yet read).
        assert!(
            bridge.drain_host().is_empty(),
            "no host bytes read before the stream is established"
        );

        // Guest accepts (OP_RESPONSE). Now the request relays to the guest.
        bridge.on_established(conn_id);
        let mut got = None;
        for _ in 0..200 {
            let ready = bridge.drain_host();
            if let Some((cid, bytes)) = ready.into_iter().next() {
                assert_eq!(cid, conn_id);
                got = Some(bytes);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(got.as_deref(), Some(&b"GuestRequest"[..]));

        // Guest → host: the device writes the agent's reply to the host socket.
        bridge.write_to_host(conn_id, b"GuestResponse");
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
        assert_eq!(&buf[..n], b"GuestResponse");

        // Close tears the stream down and the active counter drops.
        bridge.close(conn_id);
        assert_eq!(active.load(Ordering::Relaxed), 0);
        assert!(!bridge.is_agent_stream(conn_id));
    }

    /// No listener bound → accept is a no-op, never a panic.
    #[test]
    fn accept_without_listener_is_noop() {
        let mut bridge = AgentBridge::new();
        assert!(bridge.accept_new().is_empty());
    }
}
