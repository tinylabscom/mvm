//! The host-side substitution bridge — guest egress stream ↔ per-VM endpoint UDS.
//!
//! On the in-house VMM, [`EGRESS_PORT`](mvm_guest::vsock::EGRESS_PORT) (5253)
//! carries exactly one protocol — the WireRequest substitution protocol the
//! guest's forward-proxy speaks — and exactly one enforcer: the per-VM
//! `mvm-substitution-endpoint`, which decides claims 10/12/13 (ADR-101). This
//! bridge is the transport between the two: for each guest→host stream on 5253 it
//! opens a Unix-socket connection to that endpoint and relays bytes both ways.
//!
//! Like [`EgressProxy`](super::egress_proxy::EgressProxy) it is **a dumb byte
//! relay** keyed by an opaque connection id (the guest vsock `src_port`): it
//! parses no WireRequest and enforces no policy — every decision lives in the
//! endpoint it forwards to. The only judgement it makes is fail-closed: with no
//! endpoint configured, or if the endpoint socket can't be reached, the stream is
//! reset and no bytes leave the host (default-deny, ADR-100/claim-10).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Per-drain read budget per endpoint connection.
const READ_CHUNK: usize = 16 * 1024;

/// What the device should signal the guest after an inbound substitution frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubstitutionAction {
    /// Stream opened to the endpoint (or already open) — bytes relayed; no control
    /// reply beyond the credit update the device already sends.
    Relayed,
    /// No endpoint reachable — reset the stream. Fail-closed: a guest with no
    /// substitution endpoint gets no egress (default-deny).
    Refused,
}

/// Result of draining the open endpoint sockets once.
pub(crate) struct SubstitutionDrain {
    /// Bytes read per connection id, to frame back to the guest as `OP_RW`.
    pub ready: Vec<(u32, Vec<u8>)>,
    /// Connection ids that hit EOF / error and were closed.
    pub closed: Vec<u32>,
}

/// The substitution transport for one guest: the per-VM endpoint socket path plus
/// the open relay connections.
pub(crate) struct SubstitutionBridge {
    /// Per-VM `mvm-substitution-endpoint` Unix socket. `None` ⇒ no endpoint for
    /// this VM, so every stream is refused (fail-closed; the workload carries no
    /// admitted egress).
    endpoint: Option<PathBuf>,
    /// Open endpoint connections, keyed by the guest vsock `src_port` (conn id).
    conns: HashMap<u32, UnixStream>,
    /// Open-connection count, published for the host run loop's heartbeat (it must
    /// keep waking an idle guest while there's an endpoint reply to deliver). Same
    /// counter shape as the egress proxy / agent bridge.
    active: Option<Arc<AtomicUsize>>,
}

impl SubstitutionBridge {
    pub fn new() -> Self {
        Self {
            endpoint: None,
            conns: HashMap::new(),
            active: None,
        }
    }

    /// Point the bridge at this VM's substitution-endpoint socket. Until set (or if
    /// the path can't be reached), every stream is refused.
    pub fn set_endpoint(&mut self, path: &Path) {
        self.endpoint = Some(path.to_path_buf());
    }

    /// Whether a substitution endpoint is configured for this VM. The device uses
    /// this to decide, at configuration time (not by inspecting guest bytes),
    /// whether `EGRESS_PORT` routes here (WireRequest substitution) or to the
    /// legacy raw-TCP egress proxy.
    pub fn has_endpoint(&self) -> bool {
        self.endpoint.is_some()
    }

    /// Share the open-connection counter with the host run loop heartbeat.
    pub fn set_activity(&mut self, counter: Arc<AtomicUsize>) {
        self.active = Some(counter);
    }

    /// True while at least one endpoint connection is open (the heartbeat gate).
    pub fn has_active(&self) -> bool {
        !self.conns.is_empty()
    }

    /// Relay one inbound substitution frame on stream `conn_id` to the endpoint.
    /// The first frame opens the endpoint connection; later frames are written to
    /// it. The bridge interprets none of the bytes — the WireRequest framing and
    /// every claim-10/12/13 decision live in the endpoint. Replies stream back
    /// asynchronously via [`Self::drain`].
    pub fn handle_frame(&mut self, conn_id: u32, payload: &[u8]) -> SubstitutionAction {
        // Established stream → write this frame to the endpoint socket.
        if let Some(stream) = self.conns.get_mut(&conn_id) {
            write_nonblocking(stream, payload);
            return SubstitutionAction::Relayed;
        }

        // First frame: open a connection to the per-VM endpoint, or fail closed.
        let Some(path) = self.endpoint.clone() else {
            return SubstitutionAction::Refused; // no endpoint → no egress
        };
        match UnixStream::connect(&path) {
            Ok(stream) => {
                // Non-blocking so `drain` reads replies without stalling the run loop.
                let _ = stream.set_nonblocking(true);
                self.conns.insert(conn_id, stream);
                // Write the first frame now that the stream is established.
                if let Some(s) = self.conns.get_mut(&conn_id) {
                    write_nonblocking(s, payload);
                }
                self.bump(1);
                SubstitutionAction::Relayed
            }
            Err(_) => SubstitutionAction::Refused,
        }
    }

    /// Read each open endpoint socket once (non-blocking); a peer EOF or error
    /// closes that connection. The host→guest half of the relay.
    pub fn drain(&mut self) -> SubstitutionDrain {
        let mut ready = Vec::new();
        let mut closed = Vec::new();
        for (conn_id, stream) in self.conns.iter_mut() {
            let mut buf = vec![0u8; READ_CHUNK];
            match stream.read(&mut buf) {
                Ok(0) => closed.push(*conn_id), // peer EOF (endpoint closed the reply)
                Ok(n) => {
                    buf.truncate(n);
                    ready.push((*conn_id, buf));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => closed.push(*conn_id),
            }
        }
        for conn_id in &closed {
            if self.conns.remove(conn_id).is_some() {
                self.bump(-1);
            }
        }
        SubstitutionDrain { ready, closed }
    }

    /// Close a stream (guest `OP_SHUTDOWN`/`OP_RST`), tearing down its endpoint
    /// connection so the endpoint sees EOF on the relayed request.
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
/// egress proxy / agent bridge writer.
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
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    /// No endpoint configured → every stream is refused, nothing is opened.
    #[test]
    fn no_endpoint_refuses_fail_closed() {
        let mut b = SubstitutionBridge::new();
        assert_eq!(b.handle_frame(5, b"anything"), SubstitutionAction::Refused);
        assert!(!b.has_active());
    }

    /// An endpoint path that doesn't exist → the connect fails → refused (the
    /// guest gets no egress when the moat isn't up).
    #[test]
    fn unreachable_endpoint_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = SubstitutionBridge::new();
        b.set_endpoint(&dir.path().join("nope.sock"));
        assert_eq!(b.handle_frame(7, b"req"), SubstitutionAction::Refused);
        assert!(!b.has_active());
    }

    /// Full relay over a real Unix socket: a mock endpoint reads the guest's
    /// request bytes and writes a reply; the bridge relays the request to the
    /// endpoint and the reply back to the guest stream. This is the per-VM
    /// substitution transport end to end (minus the device framing).
    #[test]
    fn relays_request_to_endpoint_and_reply_back() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");

        // Mock endpoint: accept one connection, echo the request prefixed with
        // "REPLY:" so the test can tell the reply apart from the request.
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = c.read(&mut buf).unwrap();
            let mut reply = b"REPLY:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            c.write_all(&reply).unwrap();
        });

        let mut b = SubstitutionBridge::new();
        let active = Arc::new(AtomicUsize::new(0));
        b.set_activity(active.clone());
        b.set_endpoint(&sock);

        // Guest → host: first frame opens the endpoint connection and relays.
        assert_eq!(
            b.handle_frame(42, b"WireRequest"),
            SubstitutionAction::Relayed
        );
        assert!(b.has_active());
        assert_eq!(active.load(Ordering::Relaxed), 1);

        // host → guest: poll until the endpoint's reply arrives on the same stream.
        let mut got = None;
        for _ in 0..200 {
            let d = b.drain();
            if let Some((cid, bytes)) = d.ready.into_iter().next() {
                assert_eq!(cid, 42);
                got = Some(bytes);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(got.as_deref(), Some(&b"REPLY:WireRequest"[..]));
        server.join().unwrap();

        // The endpoint closed after replying → a later drain reports the stream
        // closed and the active counter drops to zero.
        for _ in 0..200 {
            let d = b.drain();
            if d.closed.contains(&42) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!b.has_active());
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }

    /// A second frame on an already-open stream writes to the same endpoint
    /// connection (it does not re-open one), so a chunked request stays on one
    /// endpoint stream.
    #[test]
    fn second_frame_reuses_the_open_connection() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            // Read both frames (they were written back-to-back on one stream).
            let mut total = Vec::new();
            for _ in 0..2 {
                let n = c.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                total.extend_from_slice(&buf[..n]);
                if total.len() >= 6 {
                    break;
                }
            }
            c.write_all(&total).unwrap();
        });

        let mut b = SubstitutionBridge::new();
        b.set_endpoint(&sock);
        assert_eq!(b.handle_frame(9, b"abc"), SubstitutionAction::Relayed);
        assert_eq!(b.handle_frame(9, b"def"), SubstitutionAction::Relayed);
        // Only one endpoint connection opened for the two frames.
        assert_eq!(b.conns.len(), 1);

        let mut got = Vec::new();
        for _ in 0..200 {
            let d = b.drain();
            for (_, bytes) in d.ready {
                got.extend_from_slice(&bytes);
            }
            if got.len() >= 6 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(&got, b"abcdef");
        server.join().unwrap();
    }
}
