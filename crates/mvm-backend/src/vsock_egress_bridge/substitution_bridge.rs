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
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Per-drain read budget per endpoint connection.
const READ_CHUNK: usize = 16 * 1024;

/// What the device should signal the guest after an inbound substitution frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubstitutionAction {
    /// Opened + relayed to the endpoint (or a later frame on an open stream).
    Relayed,
    /// Refused: no endpoint or a connect failure. Fail-closed — the stream is
    /// reset and nothing leaves the host.
    Refused,
}

/// Result of draining the open endpoint sockets once.
pub(crate) struct SubstitutionDrain {
    /// Bytes read per connection id, to frame back to the guest as `OP_RW`.
    pub ready: Vec<(u32, Vec<u8>)>,
    /// Connection ids that hit EOF / error and were closed.
    pub closed: Vec<u32>,
}

/// The substitution transport for one guest.
pub(crate) struct SubstitutionBridge {
    /// Per-VM `mvm-substitution-endpoint` socket. `None` ⇒ no endpoint, fail-closed.
    endpoint: Option<PathBuf>,
    /// Open endpoint connections keyed by the guest vsock `src_port`.
    conns: HashMap<u32, UnixStream>,
    /// Open-connection count, published for the run loop heartbeat so it keeps
    /// waking an idle guest while there's an endpoint reply to deliver.
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

    /// Point the bridge at this VM's substitution-endpoint socket.
    pub fn set_endpoint(&mut self, path: &Path) {
        self.endpoint = Some(path.to_path_buf());
    }

    /// Share the open-connection counter with the run loop heartbeat.
    pub fn set_activity(&mut self, counter: Arc<AtomicUsize>) {
        self.active = Some(counter);
    }

    /// True while at least one endpoint stream is open (the heartbeat gate).
    pub fn has_active(&self) -> bool {
        !self.conns.is_empty()
    }

    /// Relay one inbound frame on stream `conn_id`. The first frame opens the
    /// endpoint and relays; later frames relay directly. No endpoint or a connect
    /// failure fails closed — the endpoint is the sole gate.
    pub fn handle_frame(&mut self, conn_id: u32, payload: &[u8]) -> SubstitutionAction {
        if let Some(up) = self.conns.get_mut(&conn_id) {
            write_nonblocking(up, payload);
            return SubstitutionAction::Relayed;
        }
        let Some(path) = self.endpoint.clone() else {
            return SubstitutionAction::Refused;
        };
        match UnixStream::connect(&path) {
            Ok(stream) => {
                let _ = stream.set_nonblocking(true);
                let up = self.conns.entry(conn_id).or_insert(stream);
                write_nonblocking(up, payload);
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
        for (conn_id, up) in self.conns.iter_mut() {
            let mut buf = vec![0u8; READ_CHUNK];
            match up.read(&mut buf) {
                Ok(0) => closed.push(*conn_id), // endpoint closed the reply
                Ok(n) => {
                    buf.truncate(n);
                    ready.push((*conn_id, buf));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => closed.push(*conn_id),
            }
        }
        for conn_id in &closed {
            self.close(*conn_id);
        }
        SubstitutionDrain { ready, closed }
    }

    /// Close a stream (guest `OP_SHUTDOWN`/`OP_RST`), dropping its endpoint
    /// connection so the endpoint sees EOF.
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
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    /// No endpoint configured → every stream is refused, nothing opened.
    #[test]
    fn no_endpoint_refuses_fail_closed() {
        let mut b = SubstitutionBridge::new();
        assert_eq!(
            b.handle_frame(5, b"1.2.3.4:80\n"),
            SubstitutionAction::Refused
        );
        assert!(!b.has_active());
    }

    /// A raw first frame (not a WireRequest) is relayed byte-for-byte to the
    /// endpoint and the endpoint's reply drains back to the guest. The bridge
    /// never parses or gates.
    #[test]
    fn relays_raw_frame_both_directions() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
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
        assert_eq!(b.handle_frame(3, raw), SubstitutionAction::Relayed);
        assert!(b.has_active());
        assert_eq!(active.load(Ordering::Relaxed), 1);

        let got_by_endpoint = server.join().unwrap();
        assert_eq!(got_by_endpoint, raw, "endpoint got the raw bytes verbatim");

        let mut reply = None;
        for _ in 0..200 {
            let d = b.drain();
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

    /// A later frame on an already-open stream relays directly — no new endpoint
    /// connection is opened — and closing drops the endpoint connection.
    #[test]
    fn later_frames_relay_and_close_drops_connection() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
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

        assert_eq!(b.handle_frame(7, b"first"), SubstitutionAction::Relayed);
        assert_eq!(active.load(Ordering::Relaxed), 1);
        // Second frame on the same open stream — no new connection.
        assert_eq!(b.handle_frame(7, b"second"), SubstitutionAction::Relayed);
        assert_eq!(active.load(Ordering::Relaxed), 1);

        // Close drops the endpoint connection (the endpoint then sees EOF).
        b.close(7);
        assert!(!b.has_active());
        assert_eq!(active.load(Ordering::Relaxed), 0);

        // The single endpoint connection received both frames' bytes concatenated.
        let got = server.join().unwrap();
        assert_eq!(got, b"firstsecond");
    }
}
