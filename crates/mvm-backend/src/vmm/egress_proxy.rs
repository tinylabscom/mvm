//! The host-side vsock egress gateway (ADR-100), independent of the transport.
//!
//! A NIC-less guest asks the host to open an outbound connection over vsock: the
//! first frame on an egress stream is the connect target `"ip:port"`, decided here
//! against the claim-10 policy ([`EgressGate`], default-deny). An admitted target
//! gets a non-blocking host TCP connection; later frames are written to it and its
//! replies stream back. This type owns the policy + the open connections and
//! returns *reply frames* — it never touches a virtqueue, so the in-house VMM
//! device and (later) the external-VMM bridge can both drive it. The caller frames
//! the replies onto whatever rx path it has.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::egress_gate::{EgressGate, EgressVerdict};
use super::vsock::{Hdr, OP_CREDIT_UPDATE, OP_RST, OP_RW};

/// A host→guest reply for the caller to frame onto its rx path: the inbound header
/// to reply to (src/dst are swapped by the caller), the vsock op, and the bytes.
pub(crate) type Reply = (Hdr, u16, Vec<u8>);

/// Host TCP connect timeout for an admitted egress target.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Per-drain read budget per connection.
const READ_CHUNK: usize = 16 * 1024;

/// The egress gateway state for one guest: policy + open connections.
pub(crate) struct EgressProxy {
    /// Claim-10 decision (default-deny when absent → every request refused).
    gate: Option<EgressGate>,
    /// Open host TCP connections, keyed by the guest stream's `src_port`. Value is
    /// the non-blocking socket + the guest packet header (so [`Self::drain`] frames
    /// socket→guest bytes back on the right stream).
    conns: HashMap<u32, (TcpStream, Hdr)>,
    /// Open-connection count, published for the host run loop's heartbeat (it only
    /// needs to wake an idle guest while there's an open socket to deliver from).
    active: Option<Arc<AtomicUsize>>,
    /// Targets refused (claim-10) — for audit / verification.
    pub denied: Vec<String>,
    /// Targets admitted + connected — for audit / verification.
    pub allowed: Vec<String>,
}

impl EgressProxy {
    pub fn new() -> Self {
        Self {
            gate: None,
            conns: HashMap::new(),
            active: None,
            denied: Vec::new(),
            allowed: Vec::new(),
        }
    }

    /// Install the claim-10 policy. Without it, every request is refused.
    pub fn set_gate(&mut self, gate: EgressGate) {
        self.gate = Some(gate);
    }

    /// Share the open-connection counter with the host run loop's heartbeat.
    pub fn set_activity(&mut self, counter: Arc<AtomicUsize>) {
        self.active = Some(counter);
    }

    /// True while at least one egress connection is open (the heartbeat gate).
    pub fn has_active(&self) -> bool {
        !self.conns.is_empty()
    }

    /// Handle one inbound egress frame from the guest stream `src_port`. The first
    /// frame is the connect target `"ip:port"` (decided against the gate); later
    /// frames are written to the open socket. Returns control replies to frame back
    /// (credit-update on connect, RST on refusal / connect failure); data replies
    /// arrive asynchronously via [`Self::drain`].
    pub fn handle_request(&mut self, src_port: u32, hdr: Hdr, payload: &[u8]) -> Vec<Reply> {
        // Established stream → write this frame to the host socket.
        if let Some((stream, _)) = self.conns.get_mut(&src_port) {
            write_nonblocking(stream, payload);
            return Vec::new();
        }

        // First frame = the connect target.
        let target = String::from_utf8_lossy(payload).trim().to_string();
        let verdict = match &self.gate {
            Some(gate) => gate.decide_request(&target),
            None => EgressVerdict::Deny, // fail closed with no gateway installed
        };
        match verdict {
            EgressVerdict::Allow { ip, port } => {
                match TcpStream::connect_timeout(&SocketAddr::new(ip, port), CONNECT_TIMEOUT) {
                    Ok(stream) => {
                        // Non-blocking so `drain` reads replies without stalling.
                        let _ = stream.set_nonblocking(true);
                        self.conns.insert(src_port, (stream, hdr));
                        self.allowed.push(target);
                        self.bump(1);
                        vec![(hdr, OP_CREDIT_UPDATE, Vec::new())]
                    }
                    Err(_) => {
                        self.denied.push(format!("{target} (connect failed)"));
                        vec![(hdr, OP_RST, Vec::new())]
                    }
                }
            }
            EgressVerdict::Deny | EgressVerdict::Malformed => {
                self.denied.push(target);
                vec![(hdr, OP_RST, Vec::new())]
            }
        }
    }

    /// Read each open socket once (non-blocking) into `OP_RW` reply frames; a peer
    /// EOF or error closes that connection. The host→guest half of the proxy.
    pub fn drain(&mut self) -> Vec<Reply> {
        let mut replies = Vec::new();
        let mut closed = Vec::new();
        for (port, (stream, hdr)) in self.conns.iter_mut() {
            let mut buf = vec![0u8; READ_CHUNK];
            match stream.read(&mut buf) {
                Ok(0) => closed.push(*port), // peer EOF
                Ok(n) => {
                    buf.truncate(n);
                    replies.push((*hdr, OP_RW, buf));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => closed.push(*port),
            }
        }
        for port in &closed {
            if self.conns.remove(port).is_some() {
                self.bump(-1);
            }
        }
        replies
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
fn write_nonblocking(stream: &mut TcpStream, payload: &[u8]) {
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
    use mvm_core::policy::network_policy::NetworkPolicy;
    use std::net::TcpListener;

    fn deny_all_gate() -> EgressGate {
        EgressGate::default_deny()
    }

    /// No gate installed → every request is refused (RST) and recorded as denied.
    #[test]
    fn no_gate_refuses_and_records() {
        let mut p = EgressProxy::new();
        let replies = p.handle_request(5, Hdr::default(), b"93.184.216.34:80");
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].1, OP_RST);
        assert_eq!(p.denied, vec!["93.184.216.34:80".to_string()]);
        assert!(p.allowed.is_empty());
        assert!(!p.has_active());
    }

    /// A target the policy doesn't admit → RST + denied (claim-10 default-deny).
    #[test]
    fn policy_denied_target_is_refused() {
        let mut p = EgressProxy::new();
        p.set_gate(deny_all_gate());
        let replies = p.handle_request(7, Hdr::default(), b"1.1.1.1:443");
        assert_eq!(replies[0].1, OP_RST);
        assert_eq!(p.denied, vec!["1.1.1.1:443".to_string()]);
    }

    /// A malformed connect target fails closed (RST), never a connection.
    #[test]
    fn malformed_target_fails_closed() {
        let mut p = EgressProxy::new();
        // Unrestricted gate so the refusal is the *parse*, not the policy.
        let pins = mvm_core::policy::dns_pin::DnsPinRegistry::new();
        p.set_gate(EgressGate::from_network_policy(
            &NetworkPolicy::unrestricted(),
            &pins,
            "2026-01-01T00:00:00Z",
        ));
        let replies = p.handle_request(9, Hdr::default(), b"not-an-address");
        assert_eq!(replies[0].1, OP_RST);
        assert_eq!(p.denied, vec!["not-an-address".to_string()]);
    }

    /// Proxy mechanics: an established stream writes guest frames to the host
    /// socket, and `drain` reads the socket's reply into an `OP_RW` frame. (The
    /// gate is not consulted for an already-open stream, so a loopback echo server
    /// — which the gate would otherwise mandatory-deny — exercises the data path.)
    #[test]
    fn established_stream_proxies_both_directions() {
        // A loopback echo server.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).unwrap();
            sock.write_all(&buf[..n]).unwrap();
        });

        // Pre-seed an established connection (bypassing the gate, as for a live
        // admitted stream).
        let mut p = EgressProxy::new();
        let active = Arc::new(AtomicUsize::new(1));
        p.set_activity(active.clone());
        let stream = TcpStream::connect(addr).unwrap();
        stream.set_nonblocking(true).unwrap();
        p.conns.insert(42, (stream, Hdr::default()));
        assert!(p.has_active());

        // Guest → host: writing a frame on the established stream returns no control
        // reply, and the bytes reach the server.
        let replies = p.handle_request(42, Hdr::default(), b"ping");
        assert!(replies.is_empty());

        // host → guest: poll until the echo arrives as an OP_RW reply.
        let mut got = None;
        for _ in 0..200 {
            let r = p.drain();
            if let Some((_, op, bytes)) = r.into_iter().next() {
                assert_eq!(op, OP_RW);
                got = Some(bytes);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(got.as_deref(), Some(&b"ping"[..]));
        server.join().unwrap();

        // The server closed → a later drain sees EOF, closes the conn, and the
        // active counter drops to zero.
        for _ in 0..200 {
            let _ = p.drain();
            if !p.has_active() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!p.has_active());
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }
}
