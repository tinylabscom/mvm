//! Plan 107 A3 — in-host-VM vsock forwarder (the nesting hop).
//!
//! The outer host can't reach a workload microVM's vsock directly:
//! the workload's Firecracker runs *inside* this host VM and exposes
//! its vsock as a Unix-domain socket at
//! `/var/lib/mvm/workloads/<id>/v.sock` (Firecracker hybrid-vsock).
//! This module bridges that gap.
//!
//! ## The hop
//!
//! ```text
//! outer host
//!   → host-VM AF_VSOCK port WORKLOAD_FORWARD_PORT  (libkrun UDS)
//!     → [this forwarder, inside the host VM]
//!       → workload Firecracker v.sock UDS  (CONNECT <port>\n / OK)
//!         → workload guest agent (vsock port, e.g. 5252)
//! ```
//!
//! ## Why one fixed port + a handshake (not a port per workload)
//!
//! libkrun registers its vsock ports when the host VM is *launched*
//! (`krun_add_vsock_port2`); ports can't be added per workload at
//! runtime. So the host VM exposes a single [`WORKLOAD_FORWARD_PORT`]
//! and the forwarder multiplexes: each inbound connection opens with
//! a length-prefixed `"<workload_id> <port>"` handshake naming which
//! workload + which guest port to reach. The forwarder resolves the
//! workload's `v.sock`, speaks Firecracker's hybrid-vsock CONNECT
//! handshake, then splices bytes both ways.
//!
//! ## No serde
//!
//! Same size-budget rationale as the rest of `mvm-host-vm-init`: the
//! handshake is hand-parsed, the CONNECT line hand-rolled. The
//! cross-platform core ([`handle_forward_conn`] and helpers) is
//! exercised by `cargo test` on every host against a fake `v.sock`
//! server — no VM required; only the AF_VSOCK listener (A3.b) is
//! Linux-only.

#![cfg(unix)]

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Fixed AF_VSOCK port the forwarder listens on inside the host VM,
/// registered at host-VM launch alongside the dispatch port (21471).
pub const WORKLOAD_FORWARD_PORT: u32 = 21472;

/// Plan 107 A3.4 — max concurrent forwarded vsock streams. A bounded
/// cap so a misbehaving outer host can't exhaust the host VM's
/// threads / fds by opening unbounded hop connections; the listener
/// fails closed (drops the new connection) at the cap. When Plan 102
/// W6.A.5's bridge guardrails land, the forwarder can defer to those;
/// until then this is the bound.
pub const MAX_CONCURRENT_FORWARDS: usize = 64;

/// Upper bound on the inbound handshake body. A handshake is just
/// `"<uuid> <port>"`, so this is generous; anything larger is junk.
const MAX_HANDSHAKE_BYTES: usize = 256;

/// Upper bound on a single CONNECT response line from Firecracker.
const MAX_CONNECT_LINE_BYTES: usize = 64;

/// Plan 107 A3.4 — bounds concurrent forwarded streams. The listener
/// calls [`ConnectionLimiter::try_acquire`] per accepted connection:
/// it returns a [`ConnectionPermit`] (which decrements the live count
/// on drop, i.e. when the handler thread ends) or `None` at capacity,
/// so the listener can fail closed instead of spawning unboundedly.
#[derive(Clone)]
pub struct ConnectionLimiter {
    active: Arc<AtomicUsize>,
    max: usize,
}

/// Live-slot reservation; releases the slot when dropped.
pub struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl ConnectionLimiter {
    pub fn new(max: usize) -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            max,
        }
    }

    /// Atomically reserve a slot if below the cap. Returns the permit
    /// or `None` when already at `max` in-flight connections.
    pub fn try_acquire(&self) -> Option<ConnectionPermit> {
        let mut cur = self.active.load(Ordering::Acquire);
        loop {
            if cur >= self.max {
                return None;
            }
            match self.active.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ConnectionPermit {
                        active: Arc::clone(&self.active),
                    });
                }
                Err(observed) => cur = observed,
            }
        }
    }

    /// Current number of live forwarded streams.
    pub fn active_count(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Parse the inbound multiplex handshake: a u32-BE length prefix
/// followed by a UTF-8 body `"<workload_id> <port>"`. Returns the
/// workload id and the guest vsock port to reach.
fn read_handshake<R: Read>(conn: &mut R) -> io::Result<(String, u32)> {
    let mut len_buf = [0u8; 4];
    conn.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_HANDSHAKE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("forward handshake length {len} out of range"),
        ));
    }
    let mut body = vec![0u8; len];
    conn.read_exact(&mut body)?;
    let text = String::from_utf8(body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let (id, port_str) = text.split_once(' ').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "forward handshake missing port")
    })?;
    if id.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "forward handshake empty workload_id",
        ));
    }
    let port: u32 = port_str.trim().parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "forward handshake port is not a u32",
        )
    })?;
    Ok((id.to_string(), port))
}

/// Read one `\n`-terminated line byte-by-byte (no buffering, so we
/// never over-read into the post-handshake byte stream). Caps at
/// `max` bytes.
fn read_line_unbuffered<R: Read>(conn: &mut R, max: usize) -> io::Result<String> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = conn.read(&mut byte)?;
        if n == 0 {
            break; // EOF before newline
        }
        if byte[0] == b'\n' {
            break;
        }
        out.push(byte[0]);
        if out.len() > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CONNECT response line too long",
            ));
        }
    }
    String::from_utf8(out).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Open the workload's Firecracker hybrid-vsock UDS and request the
/// given guest port via the `CONNECT <port>\n` / `OK ...` handshake.
/// Returns the connected stream positioned at the start of the raw
/// guest byte stream.
fn connect_firecracker_vsock(uds_path: &Path, port: u32) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(uds_path)?;
    // Firecracker hybrid-vsock expects `CONNECT <port>\n` (writeln!
    // appends exactly the `\n` terminator the protocol wants).
    writeln!(stream, "CONNECT {port}")?;
    stream.flush()?;
    let line = read_line_unbuffered(&mut stream, MAX_CONNECT_LINE_BYTES)?;
    // Firecracker answers "OK <assigned_host_port>" on success.
    if !line.starts_with("OK") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("firecracker vsock CONNECT {port} rejected: {:?}", line),
        ));
    }
    Ok(stream)
}

/// Copy bytes both directions between `a` and `b` until either side
/// closes, half-closing the peer's write side on each EOF so the
/// other copy unblocks. Returns when both directions are drained.
fn splice_bidirectional(a: UnixStream, b: UnixStream) -> io::Result<()> {
    let mut a_read = a.try_clone()?;
    let mut a_write = a;
    let mut b_read = b.try_clone()?;
    let mut b_write = b;

    let pump = std::thread::spawn(move || {
        let _ = io::copy(&mut a_read, &mut b_write);
        let _ = b_write.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut b_read, &mut a_write);
    let _ = a_write.shutdown(Shutdown::Write);
    let _ = pump.join();
    Ok(())
}

/// Handle one inbound forwarder connection end-to-end: read the
/// multiplex handshake, resolve the named workload's `v.sock` under
/// `base`, CONNECT to the requested guest port, and splice.
///
/// `inbound` is the accepted hop connection — a host-VM AF_VSOCK
/// socket in production (wrapped as a [`UnixStream`], which only
/// touches the fd's read/write/clone, agnostic to address family),
/// or a [`UnixStream`] pair in tests. `base` is the per-workload
/// state base dir (`/var/lib/mvm/workloads` in production).
pub fn handle_forward_conn(mut inbound: UnixStream, base: &Path) -> io::Result<()> {
    let (workload_id, port) = read_handshake(&mut inbound)?;
    // Fail closed on a workload_id that could escape the base dir.
    // Real ids are host-minted UUIDs (no `/`, no `..`).
    if workload_id.contains('/') || workload_id.contains("..") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("forward handshake unsafe workload_id: {workload_id:?}"),
        ));
    }
    let vsock_uds = base.join(&workload_id).join("v.sock");
    let upstream = connect_firecracker_vsock(&vsock_uds, port)?;
    splice_bidirectional(inbound, upstream)
}

/// Encode the multiplex handshake the way [`read_handshake`] parses
/// it: a u32-BE length prefix + `"<workload_id> <port>"`. Exposed so
/// the host-side `NestingHopTransport` (A3.c) and the tests share one
/// definition of the wire shape.
pub fn encode_handshake(workload_id: &str, port: u32) -> Vec<u8> {
    let body = format!("{workload_id} {port}");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    fn write_handshake(stream: &mut UnixStream, id: &str, port: u32) {
        stream.write_all(&encode_handshake(id, port)).unwrap();
    }

    #[test]
    fn workload_forward_port_literal_is_21472() {
        // The guest init deliberately doesn't depend on `mvm-guest`,
        // so this literal must stay in lock-step with the host side
        // (`mvm_guest::builder_agent::WORKLOAD_FORWARD_PORT`). If the
        // host changes the port, this pin fails and points at the
        // resync — same tactic as the dispatch-port pin.
        assert_eq!(WORKLOAD_FORWARD_PORT, 21472);
    }

    #[test]
    fn handshake_byte_layout_matches_host_encoder() {
        // The host side (`mvm_guest::builder_agent::
        // encode_workload_forward_handshake`) pins the *same* literal
        // bytes for this input. Keeping both pinned to the identical
        // layout is how the two no-shared-dep encoders stay in sync.
        let bytes = encode_handshake("ab", 5);
        assert_eq!(bytes, vec![0, 0, 0, 4, b'a', b'b', b' ', b'5']);
    }

    #[test]
    fn handshake_round_trips_through_encode_and_read() {
        let bytes = encode_handshake("00000000-0000-0000-0000-000000000001", 5252);
        let mut cursor = io::Cursor::new(bytes);
        let (id, port) = read_handshake(&mut cursor).unwrap();
        assert_eq!(id, "00000000-0000-0000-0000-000000000001");
        assert_eq!(port, 5252);
    }

    #[test]
    fn read_handshake_rejects_bad_inputs() {
        // zero length
        let mut z = io::Cursor::new(0u32.to_be_bytes().to_vec());
        assert!(read_handshake(&mut z).is_err());
        // over cap
        let mut big = io::Cursor::new(((MAX_HANDSHAKE_BYTES as u32) + 1).to_be_bytes().to_vec());
        assert!(read_handshake(&mut big).is_err());
        // missing port (no space)
        let body = b"justanid";
        let mut buf = (body.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(body);
        assert!(read_handshake(&mut io::Cursor::new(buf)).is_err());
        // non-numeric port
        let body = b"id xyz";
        let mut buf = (body.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(body);
        assert!(read_handshake(&mut io::Cursor::new(buf)).is_err());
    }

    /// Spawn a fake Firecracker hybrid-vsock server at `uds_path`:
    /// accept one connection, read the `CONNECT <port>\n` line, reply
    /// `ok_line`, then run `after(stream)` (e.g. echo). Returns the
    /// join handle + the CONNECT port it observed (via a channel).
    fn fake_vsock_server(
        uds_path: PathBuf,
        ok_line: &'static str,
        echo: bool,
    ) -> (
        std::thread::JoinHandle<()>,
        std::sync::mpsc::Receiver<String>,
    ) {
        let (tx, rx) = std::sync::mpsc::channel();
        let listener = UnixListener::bind(&uds_path).unwrap();
        let h = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            // Read the CONNECT line byte-by-byte.
            let line = read_line_unbuffered(&mut conn, 64).unwrap();
            let _ = tx.send(line);
            conn.write_all(ok_line.as_bytes()).unwrap();
            conn.flush().unwrap();
            if echo {
                let mut buf = [0u8; 1024];
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
        (h, rx)
    }

    #[test]
    fn connect_firecracker_vsock_speaks_connect_and_accepts_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let uds = tmp.path().join("v.sock");
        let (server, port_rx) = fake_vsock_server(uds.clone(), "OK 1024\n", false);
        let stream = connect_firecracker_vsock(&uds, 5252).expect("connect ok");
        drop(stream);
        let observed = port_rx.recv().unwrap();
        assert_eq!(observed, "CONNECT 5252");
        server.join().unwrap();
    }

    #[test]
    fn connect_firecracker_vsock_rejects_non_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let uds = tmp.path().join("v.sock");
        let (server, _rx) = fake_vsock_server(uds.clone(), "ERR no such port\n", false);
        let err = connect_firecracker_vsock(&uds, 5252).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        server.join().unwrap();
    }

    #[test]
    fn handle_forward_conn_splices_end_to_end() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let id = "00000000-0000-0000-0000-00000000abcd";
        std::fs::create_dir_all(base.join(id)).unwrap();
        let uds = base.join(id).join("v.sock");
        let (server, port_rx) = fake_vsock_server(uds, "OK 1024\n", true);

        let (mut client, inbound) = UnixStream::pair().unwrap();
        let base_owned = base.to_path_buf();
        let fwd = std::thread::spawn(move || handle_forward_conn(inbound, &base_owned));

        // Drive the hop from the outer-host side.
        write_handshake(&mut client, id, 5252);
        client.write_all(b"ping over the hop").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).unwrap();

        assert_eq!(echoed, b"ping over the hop");
        assert_eq!(port_rx.recv().unwrap(), "CONNECT 5252");
        fwd.join().unwrap().expect("forward conn ok");
        server.join().unwrap();
    }

    #[test]
    fn handle_forward_conn_rejects_path_traversal_id() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut client, inbound) = UnixStream::pair().unwrap();
        let base = tmp.path().to_path_buf();
        let fwd = std::thread::spawn(move || handle_forward_conn(inbound, &base));
        write_handshake(&mut client, "../../etc", 5252);
        let _ = client.shutdown(Shutdown::Write);
        let res = fwd.join().unwrap();
        assert!(res.is_err(), "path-traversal workload_id must fail closed");
    }

    // ── A3.4 guardrail: bounded concurrency ──────────────────────

    #[test]
    fn connection_limiter_caps_concurrency_and_releases_on_drop() {
        let limiter = ConnectionLimiter::new(2);
        let p1 = limiter.try_acquire().expect("1st slot");
        let p2 = limiter.try_acquire().expect("2nd slot");
        assert_eq!(limiter.active_count(), 2);
        // At cap → fail closed.
        assert!(
            limiter.try_acquire().is_none(),
            "must refuse beyond the cap"
        );
        // Dropping a permit frees exactly one slot.
        drop(p1);
        assert_eq!(limiter.active_count(), 1);
        let _p3 = limiter.try_acquire().expect("slot freed by drop");
        assert_eq!(limiter.active_count(), 2);
        assert!(limiter.try_acquire().is_none(), "at cap again");
        drop(p2);
    }

    #[test]
    fn connection_limiter_is_thread_safe() {
        use std::sync::Arc as StdArc;
        let limiter = StdArc::new(ConnectionLimiter::new(8));
        let mut handles = Vec::new();
        for _ in 0..32 {
            let l = StdArc::clone(&limiter);
            handles.push(std::thread::spawn(move || {
                // Acquire-and-release churn; the count must never
                // exceed the cap from any thread's view.
                if let Some(p) = l.try_acquire() {
                    assert!(l.active_count() <= 8);
                    drop(p);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(limiter.active_count(), 0, "all permits released");
    }

    // ── A3.5 framing/tamper/oversize ─────────────────────────────

    #[test]
    fn read_handshake_rejects_oversized_length_prefix() {
        // A huge length prefix must be rejected before any allocation
        // of the body (oversized-payload drop).
        let mut buf = u32::MAX.to_be_bytes().to_vec();
        buf.extend_from_slice(b"junk");
        let err = read_handshake(&mut io::Cursor::new(buf)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_handshake_rejects_non_utf8_body() {
        // Tampered (non-UTF-8) handshake body → rejected.
        let body = [0xff, 0xfe, b' ', b'5'];
        let mut buf = (body.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(&body);
        assert!(read_handshake(&mut io::Cursor::new(buf)).is_err());
    }

    #[test]
    fn handle_forward_conn_is_bit_equivalent_for_binary_payload() {
        // A3.3 parity: bytes through the hop are identical to direct —
        // including NULs and bytes that look like frame boundaries.
        use std::io::Read;
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let id = "00000000-0000-0000-0000-0000000000ff";
        std::fs::create_dir_all(base.join(id)).unwrap();
        let uds = base.join(id).join("v.sock");
        let listener = UnixListener::bind(&uds).unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let _connect_line = read_line_unbuffered(&mut conn, 64).unwrap();
            conn.write_all(b"OK 1024\n").unwrap();
            conn.flush().unwrap();
            // Echo everything (the workload side).
            let mut buf = Vec::new();
            conn.read_to_end(&mut buf).unwrap();
            conn.write_all(&buf).unwrap();
        });

        let payload: Vec<u8> = (0u16..=511).map(|b| (b % 256) as u8).collect();
        let (mut client, inbound) = UnixStream::pair().unwrap();
        let base_owned = base.to_path_buf();
        let fwd = std::thread::spawn(move || handle_forward_conn(inbound, &base_owned));

        write_handshake(&mut client, id, 5252);
        client.write_all(&payload).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).unwrap();

        assert_eq!(echoed, payload, "hop must preserve bytes exactly");
        fwd.join().unwrap().expect("forward conn ok");
        server.join().unwrap();
    }
}
