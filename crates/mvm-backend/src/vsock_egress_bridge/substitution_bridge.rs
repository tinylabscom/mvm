//! The host-side substitution bridge — guest egress stream ↔ per-VM endpoint UDS.
//!
//! On the in-house VMM, the egress port carries one protocol — the WireRequest
//! substitution protocol the guest's forward-proxy speaks — and the host gateway
//! makes the whole egress decision before any byte reaches the wire:
//!
//! 1. **Claim-10** (this bridge): the destination host:port in the first
//!    WireRequest frame is checked against the same [`EgressGate`] the device's
//!    raw-egress path uses (default-deny). An unadmitted destination is refused
//!    here, before the endpoint is even contacted — so the secrets moat never
//!    sees traffic the network policy forbids.
//! 2. **Claims 12/13** (the endpoint): once admitted, the stream is relayed to
//!    the per-VM `mvm-substitution-endpoint`, which binding-checks the secret and
//!    substitutes the real credential.
//!
//! The two run as a pipeline on the same stream — every request passes both. The
//! bridge therefore peeks the first frame (it must, to decide claim-10 before
//! relaying — relaying first would leak bytes past the gate), then becomes a plain
//! byte relay for the rest of the connection. Keyed by the guest vsock `src_port`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use mvm_core::substitution_wire::WireRequest;
use url::Url;

use super::egress_gate::{EgressGate, EgressVerdict};

/// Per-drain read budget per endpoint connection.
const READ_CHUNK: usize = 16 * 1024;
/// Largest WireRequest frame we'll buffer to make the claim-10 decision — matches
/// the endpoint's own frame cap. A length prefix above this fails closed.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// What the device should signal the guest after an inbound substitution frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubstitutionAction {
    /// Admitted + relayed to the endpoint (or a later frame on an open stream).
    Relayed,
    /// Still buffering the first frame for the claim-10 decision — ack the bytes
    /// and wait; no endpoint connection yet.
    Pending,
    /// Refused: no endpoint, a denied/malformed destination, or a connect failure.
    /// Fail-closed — the stream is reset and nothing leaves the host.
    Refused,
}

/// Result of draining the open endpoint sockets once.
pub(crate) struct SubstitutionDrain {
    /// Bytes read per connection id, to frame back to the guest as `OP_RW`.
    pub ready: Vec<(u32, Vec<u8>)>,
    /// Connection ids that hit EOF / error and were closed.
    pub closed: Vec<u32>,
}

/// One guest substitution stream: buffered until the claim-10 decision, then a
/// plain relay to the endpoint.
struct SubstConn {
    /// Endpoint connection — `None` until the destination is admitted.
    upstream: Option<UnixStream>,
    /// Bytes buffered until the first WireRequest frame is parsed for the
    /// claim-10 decision. Emptied (flushed to the endpoint) once admitted.
    pending: Vec<u8>,
    /// The claim-10 decision is made and the endpoint is open → pure relay.
    admitted: bool,
}

/// The substitution transport for one guest.
pub(crate) struct SubstitutionBridge {
    /// Per-VM `mvm-substitution-endpoint` socket. `None` ⇒ no endpoint, fail-closed.
    endpoint: Option<PathBuf>,
    /// Claim-10 gate — the same policy the device's raw-egress path enforces.
    /// `None` ⇒ deny everything (fail closed with no policy installed).
    gate: Option<EgressGate>,
    /// Open streams keyed by the guest vsock `src_port`.
    conns: HashMap<u32, SubstConn>,
    /// Open-(admitted-)connection count, published for the run loop heartbeat so it
    /// keeps waking an idle guest while there's an endpoint reply to deliver.
    active: Option<Arc<AtomicUsize>>,
}

impl SubstitutionBridge {
    pub fn new() -> Self {
        Self {
            endpoint: None,
            gate: None,
            conns: HashMap::new(),
            active: None,
        }
    }

    /// Point the bridge at this VM's substitution-endpoint socket.
    pub fn set_endpoint(&mut self, path: &Path) {
        self.endpoint = Some(path.to_path_buf());
    }

    /// Install the claim-10 policy (the same gate the raw-egress path uses). Until
    /// set, every destination is refused.
    pub fn set_gate(&mut self, gate: EgressGate) {
        self.gate = Some(gate);
    }

    /// Whether a substitution endpoint is configured. The device uses this to
    /// decide, at configuration time (not by inspecting guest bytes), whether the
    /// egress port routes here or to the legacy raw-TCP egress proxy.
    pub fn has_endpoint(&self) -> bool {
        self.endpoint.is_some()
    }

    /// Share the open-connection counter with the run loop heartbeat.
    pub fn set_activity(&mut self, counter: Arc<AtomicUsize>) {
        self.active = Some(counter);
    }

    /// True while at least one admitted stream is open (the heartbeat gate). A
    /// still-buffering stream has no endpoint reply to drain, so it doesn't count.
    pub fn has_active(&self) -> bool {
        self.conns.values().any(|c| c.admitted)
    }

    /// Relay one inbound frame on stream `conn_id`. Buffers until the first
    /// WireRequest frame yields a claim-10 decision; on admit, opens the endpoint
    /// and relays; later frames on an admitted stream relay directly.
    pub fn handle_frame(&mut self, conn_id: u32, payload: &[u8]) -> SubstitutionAction {
        if let Some(conn) = self.conns.get_mut(&conn_id) {
            if conn.admitted {
                if let Some(up) = conn.upstream.as_mut() {
                    write_nonblocking(up, payload);
                }
                return SubstitutionAction::Relayed;
            }
            conn.pending.extend_from_slice(payload);
            return self.decide(conn_id);
        }
        // New stream — needs a configured endpoint, else fail closed.
        if self.endpoint.is_none() {
            return SubstitutionAction::Refused;
        }
        self.conns.insert(
            conn_id,
            SubstConn {
                upstream: None,
                pending: payload.to_vec(),
                admitted: false,
            },
        );
        self.decide(conn_id)
    }

    /// Make (or defer) the claim-10 decision for a buffering stream from its
    /// accumulated bytes.
    fn decide(&mut self, conn_id: u32) -> SubstitutionAction {
        let Some(conn) = self.conns.get(&conn_id) else {
            return SubstitutionAction::Refused;
        };
        let dest = match frame_destination(&conn.pending) {
            FrameDest::Incomplete => return SubstitutionAction::Pending,
            FrameDest::Malformed => {
                self.conns.remove(&conn_id);
                return SubstitutionAction::Refused;
            }
            FrameDest::Dest(d) => d,
        };
        // Claim-10: consult the same gate the raw-egress path uses. No gate, a
        // denied, or a malformed destination all fail closed.
        let admitted = matches!(
            self.gate.as_ref().map(|g| g.decide_request(&dest)),
            Some(EgressVerdict::Allow { .. })
        );
        if !admitted {
            self.conns.remove(&conn_id);
            return SubstitutionAction::Refused;
        }
        // Admitted: open the endpoint and flush the buffered frame(s).
        let Some(path) = self.endpoint.clone() else {
            self.conns.remove(&conn_id);
            return SubstitutionAction::Refused;
        };
        match UnixStream::connect(&path) {
            Ok(stream) => {
                let _ = stream.set_nonblocking(true);
                let conn = self
                    .conns
                    .get_mut(&conn_id)
                    .expect("conn present: just looked it up");
                let buffered = std::mem::take(&mut conn.pending);
                conn.upstream = Some(stream);
                conn.admitted = true;
                if let Some(up) = conn.upstream.as_mut() {
                    write_nonblocking(up, &buffered);
                }
                self.bump(1);
                SubstitutionAction::Relayed
            }
            Err(_) => {
                self.conns.remove(&conn_id);
                SubstitutionAction::Refused
            }
        }
    }

    /// Read each open endpoint socket once (non-blocking); a peer EOF or error
    /// closes that connection. The host→guest half of the relay.
    pub fn drain(&mut self) -> SubstitutionDrain {
        let mut ready = Vec::new();
        let mut closed = Vec::new();
        for (conn_id, conn) in self.conns.iter_mut() {
            let Some(up) = conn.upstream.as_mut() else {
                continue; // still buffering — nothing to read yet
            };
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
        if let Some(conn) = self.conns.remove(&conn_id)
            && conn.admitted
        {
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

/// The claim-10 target parsed from a buffered WireRequest frame.
enum FrameDest {
    /// Not enough bytes yet to parse the first frame.
    Incomplete,
    /// A complete-but-unparseable frame, or a target with no host:port — deny.
    Malformed,
    /// The `host:port` the gate decides against.
    Dest(String),
}

/// Parse the destination `host:port` from a buffered substitution stream's bytes:
/// a 4-byte big-endian length prefix + a JSON [`WireRequest`], from whose absolute
/// `url` the host and (scheme-default) port are taken. Returns `Incomplete` until
/// the whole frame is present, `Malformed` on a bad frame / target.
fn frame_destination(buf: &[u8]) -> FrameDest {
    if buf.len() < 4 {
        return FrameDest::Incomplete;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME_BYTES {
        return FrameDest::Malformed; // an absurd length prefix fails closed
    }
    if buf.len() < 4 + len {
        return FrameDest::Incomplete;
    }
    let Ok(req) = serde_json::from_slice::<WireRequest>(&buf[4..4 + len]) else {
        return FrameDest::Malformed;
    };
    match Url::parse(&req.url) {
        Ok(u) => match (u.host_str(), u.port_or_known_default()) {
            (Some(host), Some(port)) => FrameDest::Dest(format!("{host}:{port}")),
            _ => FrameDest::Malformed,
        },
        Err(_) => FrameDest::Malformed,
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
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
    use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    /// A gate admitting exactly `host:port`, with a self-pin so the gate can
    /// resolve the WireRequest host to a fixed IP.
    fn gate_allowing(host: &str, port: u16) -> EgressGate {
        let now = "2026-01-01T00:00:00Z";
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            host,
            vec!["93.184.216.34".parse().unwrap()],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let policy = NetworkPolicy::allow_list(vec![HostPort {
            host: host.into(),
            port,
        }]);
        EgressGate::from_network_policy(&policy, &pins, now)
    }

    /// Build a framed WireRequest (4-byte BE len + JSON) for `url`.
    fn wire_frame(url: &str) -> Vec<u8> {
        let req = WireRequest {
            method: "POST".into(),
            url: url.into(),
            headers: vec![("authorization".into(), "Bearer mvm-secret-abc".into())],
            body_b64: B64.encode(b"{}"),
        };
        let body = serde_json::to_vec(&req).unwrap();
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        frame
    }

    /// No endpoint configured → every stream is refused, nothing opened.
    #[test]
    fn no_endpoint_refuses_fail_closed() {
        let mut b = SubstitutionBridge::new();
        b.set_gate(gate_allowing("api.openai.com", 443));
        assert_eq!(
            b.handle_frame(5, &wire_frame("https://api.openai.com/v1")),
            SubstitutionAction::Refused
        );
        assert!(!b.has_active());
    }

    /// Claim-10: a destination the gate does not admit is refused at the bridge —
    /// the endpoint is never contacted (here it doesn't even exist, proving no
    /// connection was attempted before the gate).
    #[test]
    fn unadmitted_destination_refused_before_the_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = SubstitutionBridge::new();
        b.set_endpoint(&dir.path().join("subst.sock"));
        b.set_gate(gate_allowing("api.openai.com", 443));
        // A different host than the one admitted.
        assert_eq!(
            b.handle_frame(7, &wire_frame("https://evil.example.com/x")),
            SubstitutionAction::Refused
        );
        assert!(!b.has_active());
    }

    /// A complete frame that isn't a valid WireRequest fails closed (Refused),
    /// never relayed.
    #[test]
    fn malformed_frame_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = SubstitutionBridge::new();
        b.set_endpoint(&dir.path().join("subst.sock"));
        b.set_gate(gate_allowing("api.openai.com", 443));
        // 4-byte length prefix = 3, then 3 bytes of non-JSON.
        let frame = [0, 0, 0, 3, b'x', b'y', b'z'];
        assert_eq!(b.handle_frame(9, &frame), SubstitutionAction::Refused);
    }

    /// A frame split across two writes buffers (Pending) until complete, then is
    /// decided once whole.
    #[test]
    fn split_frame_buffers_until_complete() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut buf = [0u8; 512];
            let n = c.read(&mut buf).unwrap();
            c.write_all(&buf[..n]).unwrap();
        });

        let mut b = SubstitutionBridge::new();
        b.set_endpoint(&sock);
        b.set_gate(gate_allowing("api.openai.com", 443));

        let frame = wire_frame("https://api.openai.com/v1");
        let (head, tail) = frame.split_at(3); // less than the 4-byte length prefix
        assert_eq!(b.handle_frame(11, head), SubstitutionAction::Pending);
        assert_eq!(b.handle_frame(11, tail), SubstitutionAction::Relayed);
        assert!(b.has_active());

        let mut got = None;
        for _ in 0..200 {
            let d = b.drain();
            if let Some((cid, bytes)) = d.ready.into_iter().next() {
                assert_eq!(cid, 11);
                got = Some(bytes);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(got.as_deref(), Some(frame.as_slice()));
        server.join().unwrap();
    }

    /// Happy path: an admitted destination opens the endpoint, relays the request,
    /// and streams the endpoint's reply back.
    #[test]
    fn admitted_destination_relays_to_endpoint_and_back() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut buf = [0u8; 512];
            let n = c.read(&mut buf).unwrap();
            let mut reply = b"REPLY:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            c.write_all(&reply).unwrap();
        });

        let mut b = SubstitutionBridge::new();
        let active = Arc::new(AtomicUsize::new(0));
        b.set_activity(active.clone());
        b.set_endpoint(&sock);
        b.set_gate(gate_allowing("api.openai.com", 443));

        let frame = wire_frame("https://api.openai.com/v1");
        assert_eq!(b.handle_frame(42, &frame), SubstitutionAction::Relayed);
        assert!(b.has_active());
        assert_eq!(active.load(Ordering::Relaxed), 1);

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
        let got = got.expect("endpoint reply");
        assert!(got.starts_with(b"REPLY:"));
        server.join().unwrap();

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
}
