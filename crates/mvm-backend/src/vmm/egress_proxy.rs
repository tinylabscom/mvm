//! The host-side vsock egress gateway (ADR-100), independent of the transport.
//!
//! A NIC-less guest asks the host to open an outbound connection: the first frame
//! on an egress stream is the connect target `"ip:port"`, decided here against the
//! claim-10 policy ([`EgressGate`], default-deny). An admitted target gets a
//! non-blocking host TCP connection; later frames are written to it and its replies
//! stream back. This type is **transport-agnostic** — it is keyed only by an opaque
//! connection id and speaks raw bytes + semantic [`EgressAction`]s, never touching a
//! virtqueue or a vsock header. The in-house VMM device drives it through a thin
//! header adapter; the external-VMM (libkrun) host-UDS path can drive the same core
//! with its own connection-id mapping.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::egress_gate::{EgressGate, EgressVerdict};

/// Host TCP connect timeout for an admitted egress target.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Per-drain read budget per connection.
const READ_CHUNK: usize = 16 * 1024;

/// What the caller should signal to the guest after an inbound egress frame. The
/// caller maps these onto its own transport (the in-house VMM sends a vsock
/// credit-update / RST; a UDS bridge closes or acks its stream).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EgressAction {
    /// Connection admitted + opened — acknowledge the established stream.
    Opened,
    /// Refused by policy or a connect failure — reset the stream.
    Refused,
    /// Bytes written to an already-open connection — no control reply.
    Wrote,
}

/// Result of draining the open egress sockets once.
pub(crate) struct EgressDrain {
    /// Bytes read per connection id, to deliver to the guest.
    pub ready: Vec<(u32, Vec<u8>)>,
    /// Connection ids that hit EOF / error and were closed.
    pub closed: Vec<u32>,
}

/// The egress gateway state for one guest: policy + open connections.
pub(crate) struct EgressProxy {
    /// Claim-10 decision (default-deny when absent → every request refused).
    gate: Option<EgressGate>,
    /// Open host TCP connections, keyed by an opaque per-stream connection id (the
    /// in-house VMM uses the guest vsock `src_port`; a UDS bridge its own id).
    conns: HashMap<u32, TcpStream>,
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

    /// Handle one inbound egress frame on stream `conn_id`. The first frame is the
    /// connect target `"ip:port"` (decided against the gate); later frames are
    /// written to the open socket. Returns the [`EgressAction`] the caller should
    /// signal; data replies arrive asynchronously via [`Self::drain`].
    pub fn handle_frame(&mut self, conn_id: u32, payload: &[u8]) -> EgressAction {
        // Established stream → write this frame to the host socket.
        if let Some(stream) = self.conns.get_mut(&conn_id) {
            write_nonblocking(stream, payload);
            return EgressAction::Wrote;
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
                        self.conns.insert(conn_id, stream);
                        self.allowed.push(target);
                        self.bump(1);
                        EgressAction::Opened
                    }
                    Err(_) => {
                        self.denied.push(format!("{target} (connect failed)"));
                        EgressAction::Refused
                    }
                }
            }
            EgressVerdict::Deny | EgressVerdict::Malformed => {
                self.denied.push(target);
                EgressAction::Refused
            }
        }
    }

    /// Read each open socket once (non-blocking); a peer EOF or error closes that
    /// connection. The host→guest half of the proxy.
    pub fn drain(&mut self) -> EgressDrain {
        let mut ready = Vec::new();
        let mut closed = Vec::new();
        for (conn_id, stream) in self.conns.iter_mut() {
            let mut buf = vec![0u8; READ_CHUNK];
            match stream.read(&mut buf) {
                Ok(0) => closed.push(*conn_id), // peer EOF
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
        EgressDrain { ready, closed }
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

    /// No gate installed → every request is refused and recorded as denied.
    #[test]
    fn no_gate_refuses_and_records() {
        let mut p = EgressProxy::new();
        assert_eq!(
            p.handle_frame(5, b"93.184.216.34:80"),
            EgressAction::Refused
        );
        assert_eq!(p.denied, vec!["93.184.216.34:80".to_string()]);
        assert!(p.allowed.is_empty());
        assert!(!p.has_active());
    }

    /// A target the policy doesn't admit → refused (claim-10 default-deny).
    #[test]
    fn policy_denied_target_is_refused() {
        let mut p = EgressProxy::new();
        p.set_gate(EgressGate::default_deny());
        assert_eq!(p.handle_frame(7, b"1.1.1.1:443"), EgressAction::Refused);
        assert_eq!(p.denied, vec!["1.1.1.1:443".to_string()]);
    }

    /// A malformed connect target fails closed, never a connection.
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
        assert_eq!(p.handle_frame(9, b"not-an-address"), EgressAction::Refused);
        assert_eq!(p.denied, vec!["not-an-address".to_string()]);
    }

    /// Proxy mechanics: an established stream writes guest frames to the host
    /// socket, and `drain` reads the socket's reply. (The gate is not consulted for
    /// an already-open stream, so a loopback echo server — which the gate would
    /// otherwise mandatory-deny — exercises the data path.)
    #[test]
    fn established_stream_proxies_both_directions() {
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
        p.conns.insert(42, stream);
        assert!(p.has_active());

        // Guest → host: an established-stream frame writes (no control action).
        assert_eq!(p.handle_frame(42, b"ping"), EgressAction::Wrote);

        // host → guest: poll until the echo arrives.
        let mut got = None;
        for _ in 0..200 {
            let d = p.drain();
            if let Some((cid, bytes)) = d.ready.into_iter().next() {
                assert_eq!(cid, 42);
                got = Some(bytes);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(got.as_deref(), Some(&b"ping"[..]));
        server.join().unwrap();

        // The server closed → a later drain reports the conn closed and the active
        // counter drops to zero.
        for _ in 0..200 {
            let d = p.drain();
            if d.closed.contains(&42) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!p.has_active());
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }
}
