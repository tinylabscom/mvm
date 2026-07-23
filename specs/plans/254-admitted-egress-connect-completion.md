# Admitted-egress connect completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make an admitted (`--allow-host`) egress connection actually complete over the vsock seam instead of hanging until timeout.

**Architecture:** Two coupled fixes on the host↔guest raw-egress sub-protocol. (1a) The host sends a one-byte connect-result ack after `TcpStream::connect` returns; the in-guest proxy relays `200`/SOCKS-success only on OK, else `502`/failure — killing the current optimistic reply. (1b) The host gate returns *every* admitted pinned IP (IPv4 first) and the splice tries them in order with a short per-address budget, so an unreachable AAAA pin no longer strands the request. Implements ADR-032 Part 1 only; the DNS resolver (Part 2) is a separate plan.

**Tech Stack:** Rust, tokio (async host + guest paths) and a Linux blocking path (`#[cfg(target_os = "linux")]`); `mvm-core` (shared wire type), `mvm-agentd` (guest proxy), `mvm-hostd` (host egress), `mvm-runtime` (egress gate), `mvm-conformance` (cucumber BDD).

## Global Constraints

- No `#[allow(clippy::...)]` anywhere — restructure instead (introduce a struct/enum/helper).
- No spec/PR references in code comments (CI-gated): none of `Plan N`, `ADR-\d+`, `#\d+`, `W\d.` — reword to the concept.
- Traits/enums over stringly-typed flags; exhaustive matches (no `_ =>` on our own enums).
- No backwards-compat shims or aliases; hard-change the wire and the enum. Guest and host ship together from this one repo in the same `mvmctl`, so both sides change atomically — no protocol version bump, no capability flag.
- `mvm-protocol` stays `#![no_std]` + `forbid(unsafe_code)` **if touched** — this plan does **not** touch it (the shared type lands in `mvm-core`, which is std).
- Before every commit: `cargo nextest run` for the touched crates **and** `cargo clippy --workspace -- -D warnings` (or at minimum `-p <touched crate>`), plus `cargo fmt --all -- --check`.

---

## Overview

Root cause: an admitted HTTPS `CONNECT` through the in-guest proxy hangs because (1) the guest emits `200 Connection established` / SOCKS `REP_SUCCESS` **optimistically**, before the host confirms anything, so any host-side non-completion becomes a client hang instead of an error; and (2) the host gate selects a **single** resolved pinned IP and `splice` does **one** `TcpStream::connect` with no fallback, so an unreachable first address (typically an AAAA/IPv6 pin on an IPv4-only-egress host) stalls the whole request. The disallowed-HTTP path fast-fails with `403` only because it is a different host component (`http_forward`) that answers inline.

This plan implements the admitted-egress data-path fix:

- **1a — honest CONNECT handshake.** Add a one-byte host→guest connect-result ack on the raw-egress sub-protocol. The host sends `ConnectAck::Ok` only after `TcpStream::connect` returns success, `ConnectAck::Fail` otherwise. The guest reads the ack and emits `200`/`REP_SUCCESS` on `Ok`, `502`/`REP_GENERAL_FAILURE` on `Fail`. Kills the optimistic replies in `egress_client.rs`.
- **1b — happy-eyeballs over admitted IPs.** `EgressGate` returns **all** admitted pinned IPs (IPv4 first), and `raw_egress::splice` iterates them with a short per-address connect budget, first success wins.
- **1c — one `@live` BDD scenario** asserting the end-to-end run now exits 0 and returns the page body.

Part 2 (the DNS resolver) is explicitly **out of scope**.

### Wire-protocol change (read before implementing)

The raw-egress guest→host stream currently frames a first line — either `"host:port\n"` (raw CONNECT/SOCKS) or `"MVM_HTTP_FORWARD/1\n"` (host forward-proxy) — then splices. `raw_egress::read_target_line` (`crates/mvm-hostd/src/supervisor/raw_egress.rs:102`) reads that line byte-by-byte until `\n`.

This change **adds exactly one host→guest byte** on the raw CONNECT/SOCKS sub-path only (not the `MVM_HTTP_FORWARD/1` forward path, which already returns a real HTTP response the guest relays). After the host reads the target line, decides, and attempts the connect, it writes one `ConnectAck` byte, then splices. The guest reads that one byte (`read_exact`) before emitting its own proxy reply; remaining bytes stay buffered in the socket for the splice. The `"host:port\n"` framing is unchanged.

**No protocol version bump / no negotiation.** The guest (`mvm-agentd` bins, cross-compiled + embedded by `mvm-cli/build.rs`) and the host (`mvm-hostd` bins) build and ship from this one repo in the same `mvmctl`; there is no persisted or old-peer wire surface. Both sides change atomically.

---

## Task 1a — Honest CONNECT handshake (host ack + guest ack-gated reply)

**Files**

- Modify `crates/mvm-core/src/guest_netd.rs` (append `ConnectAck` after the consts; extend `#[cfg(test)] mod tests`).
- Modify `crates/mvm-agentd/src/guest_vsock_session.rs` (imports; add `read_connect_ack` to the `impl<U> HostVsockSession<U>` block).
- Modify `crates/mvm-agentd/src/egress_client.rs` (`serve_socks`, `serve_http_connect`; add `ProxyReplyStyle` + `write_connect_reply` + `complete_connect_session`; `connect_to_host_egress` unchanged; add tests).
- Modify `crates/mvm-hostd/src/supervisor/raw_egress.rs` (import `ConnectAck`; `handle_raw_conn` Deny/Malformed arm; `splice` — send ack; `handle_raw_conn_blocking` + add blocking ack writer; extend tests).
- Test paths: unit tests inline in each of the four files' `#[cfg(test)] mod tests`.

**Interfaces**

- Produces `mvm_core::guest_netd::ConnectAck`:
  ```rust
  pub enum ConnectAck { Ok, Fail }
  impl ConnectAck { pub fn as_byte(self) -> u8; pub fn from_byte(byte: u8) -> Option<ConnectAck>; }
  ```
- Produces `HostVsockSession::read_connect_ack(&mut self) -> ConnectAck` (fail-closed to `Fail` on EOF/unknown byte).
- Produces (guest, private): `enum ProxyReplyStyle { Socks, HttpConnect }`; `async fn write_connect_reply<C>(&mut C, ProxyReplyStyle, ConnectAck) -> io::Result<()>`; `async fn complete_connect_session<C, U>(C, HostVsockSession<U>, ProxyReplyStyle) -> io::Result<()>`.
- Produces (host, private): `async fn write_connect_ack_async<S: AsyncWrite + Unpin>(&mut S, ConnectAck) -> io::Result<()>`; `#[cfg(target_os = "linux")] fn write_connect_ack_blocking(&mut std::fs::File, ConnectAck) -> io::Result<()>`.
- Consumes existing: `reply`, `reply_http_connect_ok`, `write_http_response`, `HostVsockSession::{write_initial_bytes, splice}`; `raw_egress::splice` (still single-IP in 1a).

- [ ] **Step 1a.1 — Failing test: `ConnectAck` byte roundtrip (pure)**

In `crates/mvm-core/src/guest_netd.rs` `mod tests`, add:

```rust
#[test]
fn connect_ack_roundtrips_through_its_wire_byte() {
    assert_eq!(ConnectAck::from_byte(ConnectAck::Ok.as_byte()), Some(ConnectAck::Ok));
    assert_eq!(ConnectAck::from_byte(ConnectAck::Fail.as_byte()), Some(ConnectAck::Fail));
}

#[test]
fn connect_ack_ok_and_fail_are_distinct_bytes() {
    assert_ne!(ConnectAck::Ok.as_byte(), ConnectAck::Fail.as_byte());
}

#[test]
fn connect_ack_rejects_unknown_bytes_fail_closed() {
    assert_eq!(ConnectAck::from_byte(0x02), None);
    assert_eq!(ConnectAck::from_byte(0xff), None);
}
```

Run (expect FAIL — type does not exist): `cargo nextest run -p mvm-core connect_ack`

- [ ] **Step 1a.2 — Implement `ConnectAck`**

Append to `crates/mvm-core/src/guest_netd.rs` (after `DEFAULT_EGRESS_PROXY_URL`):

```rust
/// The host's connect-result acknowledgement on the raw-egress stream.
///
/// The in-guest proxy dials the host, writes the `"host:port\n"` target line,
/// then waits for this one byte before answering its own client. The host emits
/// it only after the outbound `connect` resolves — `Ok` once the tunnel is live,
/// `Fail` when the target was refused or unreachable — so the guest reply
/// (`200` / SOCKS success on `Ok`, `502` / SOCKS failure on `Fail`) is truthful
/// instead of assuming success the moment the stream opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectAck {
    /// The host connected to the admitted destination; tunnel bytes follow.
    Ok,
    /// The host refused or could not reach the destination; nothing follows.
    Fail,
}

impl ConnectAck {
    /// The single byte written on the wire.
    pub fn as_byte(self) -> u8 {
        match self {
            ConnectAck::Ok => 0x01,
            ConnectAck::Fail => 0x00,
        }
    }

    /// Parse a wire byte back into an ack. Any byte outside the two defined
    /// codes is rejected so a desynchronised stream never reads a tunnel data
    /// byte as a spurious `Ok`.
    pub fn from_byte(byte: u8) -> Option<ConnectAck> {
        if byte == ConnectAck::Ok.as_byte() {
            Some(ConnectAck::Ok)
        } else if byte == ConnectAck::Fail.as_byte() {
            Some(ConnectAck::Fail)
        } else {
            None
        }
    }
}
```

Run (expect PASS): `cargo nextest run -p mvm-core connect_ack`; then `cargo clippy -p mvm-core -- -D warnings`.
Commit: `feat(net): add ConnectAck wire type for the raw-egress connect handshake`

- [ ] **Step 1a.3 — Failing test: guest reads the ack and answers accordingly**

Add `use tokio::io::AsyncReadExt;` and `use mvm_core::guest_netd::ConnectAck;` where needed, then in `crates/mvm-agentd/src/egress_client.rs` `mod tests`:

```rust
#[tokio::test]
async fn http_connect_replies_502_when_host_nacks() {
    let (mut client, client_bridge) = tokio::io::duplex(256);
    let (upstream_bridge, mut host) = tokio::io::duplex(256);
    let session = HostVsockSession::new(upstream_bridge)
        .write_initial_bytes(b"example.com:443\n")
        .await
        .unwrap();
    let task = tokio::spawn(complete_connect_session(
        client_bridge,
        session,
        ProxyReplyStyle::HttpConnect,
    ));

    let mut line = vec![0u8; b"example.com:443\n".len()];
    host.read_exact(&mut line).await.unwrap();
    host.write_all(&[ConnectAck::Fail.as_byte()]).await.unwrap();
    host.shutdown().await.unwrap();

    let mut resp = Vec::new();
    client.read_to_end(&mut resp).await.unwrap();
    let text = std::str::from_utf8(&resp).unwrap();
    assert!(text.starts_with("HTTP/1.1 502"), "{text:?}");
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn http_connect_replies_200_then_splices_when_host_acks_ok() {
    let (mut client, client_bridge) = tokio::io::duplex(256);
    let (upstream_bridge, mut host) = tokio::io::duplex(256);
    let session = HostVsockSession::new(upstream_bridge)
        .write_initial_bytes(b"example.com:443\n")
        .await
        .unwrap();
    let task = tokio::spawn(complete_connect_session(
        client_bridge,
        session,
        ProxyReplyStyle::HttpConnect,
    ));

    let mut line = vec![0u8; b"example.com:443\n".len()];
    host.read_exact(&mut line).await.unwrap();
    host.write_all(&[ConnectAck::Ok.as_byte()]).await.unwrap();

    let expected = b"HTTP/1.1 200 Connection established\r\n\r\n";
    let mut ok = vec![0u8; expected.len()];
    client.read_exact(&mut ok).await.unwrap();
    assert_eq!(&ok, expected);

    client.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    host.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
    host.write_all(b"pong").await.unwrap();
    let mut back = [0u8; 4];
    client.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"pong");

    drop(client);
    drop(host);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn socks_replies_general_failure_when_host_nacks() {
    let (mut client, client_bridge) = tokio::io::duplex(256);
    let (upstream_bridge, mut host) = tokio::io::duplex(256);
    let session = HostVsockSession::new(upstream_bridge)
        .write_initial_bytes(b"1.2.3.4:443\n")
        .await
        .unwrap();
    let task = tokio::spawn(complete_connect_session(
        client_bridge,
        session,
        ProxyReplyStyle::Socks,
    ));

    let mut line = vec![0u8; b"1.2.3.4:443\n".len()];
    host.read_exact(&mut line).await.unwrap();
    host.write_all(&[ConnectAck::Fail.as_byte()]).await.unwrap();
    host.shutdown().await.unwrap();

    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], SOCKS5);
    assert_eq!(reply[1], REP_GENERAL_FAILURE);
    task.await.unwrap().unwrap();
}
```

Run (expect FAIL — `complete_connect_session` / `ProxyReplyStyle` absent): `cargo nextest run -p mvm-agentd egress_client`

- [ ] **Step 1a.4 — Implement guest ack read + reply-style state machine**

In `crates/mvm-agentd/src/guest_vsock_session.rs`: ensure the import line is
```rust
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
```
and add `use mvm_core::guest_netd::ConnectAck;`. In the `impl<U> HostVsockSession<U> where U: AsyncRead + AsyncWrite + Unpin` block, add:

```rust
/// Read the host's one-byte connect-result ack that follows the target-line
/// frame on the raw-egress protocol. Fail-closed: EOF or an unrecognised byte
/// is treated as a connect failure so the caller answers its client honestly.
pub async fn read_connect_ack(&mut self) -> ConnectAck {
    let mut byte = [0u8; 1];
    match self.upstream.read_exact(&mut byte).await {
        Ok(_) => ConnectAck::from_byte(byte[0]).unwrap_or(ConnectAck::Fail),
        Err(_) => ConnectAck::Fail,
    }
}
```

In `crates/mvm-agentd/src/egress_client.rs`, add near the top: `use mvm_core::guest_netd::ConnectAck;`, then add the state machine and rewrite the two `serve_*` fns. Replace the current `serve_socks` and `serve_http_connect` with:

```rust
/// Which client-facing proxy reply flavour a completed CONNECT-style session
/// answers with, so the ack->reply mapping is one exhaustive match rather than
/// duplicated per call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyReplyStyle {
    Socks,
    HttpConnect,
}

/// Emit the client-facing reply for a connect outcome. Exhaustive over the
/// (style, ack) matrix: SOCKS success/failure replies and HTTP `200`/`502`.
async fn write_connect_reply<C>(
    client: &mut C,
    style: ProxyReplyStyle,
    ack: ConnectAck,
) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    match (style, ack) {
        (ProxyReplyStyle::Socks, ConnectAck::Ok) => reply(client, REP_SUCCESS).await,
        (ProxyReplyStyle::Socks, ConnectAck::Fail) => reply(client, REP_GENERAL_FAILURE).await,
        (ProxyReplyStyle::HttpConnect, ConnectAck::Ok) => reply_http_connect_ok(client).await,
        (ProxyReplyStyle::HttpConnect, ConnectAck::Fail) => {
            write_http_response(client, "502 Bad Gateway").await
        }
    }
}

/// Finish a CONNECT-style request once the host session is open: read the host
/// connect ack, answer the client truthfully, and splice only on `Ok`. Generic
/// over both streams so it unit-tests over in-memory duplex pipes.
async fn complete_connect_session<C, U>(
    mut client: C,
    mut session: HostVsockSession<U>,
    style: ProxyReplyStyle,
) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let ack = session.read_connect_ack().await;
    write_connect_reply(&mut client, style, ack).await?;
    match ack {
        ConnectAck::Ok => session.splice(client).await,
        ConnectAck::Fail => Ok(()),
    }
}

async fn serve_socks(client: TcpStream, target: &str) -> std::io::Result<()> {
    match connect_to_host_egress(target).await {
        Ok(session) => complete_connect_session(client, session, ProxyReplyStyle::Socks).await,
        Err(err) => {
            let mut client = client;
            let _ = reply(&mut client, REP_GENERAL_FAILURE).await;
            Err(err)
        }
    }
}

async fn serve_http_connect(client: TcpStream, target: &str) -> std::io::Result<()> {
    match connect_to_host_egress(target).await {
        Ok(session) => {
            complete_connect_session(client, session, ProxyReplyStyle::HttpConnect).await
        }
        Err(err) => {
            let mut client = client;
            let _ = write_http_response(&mut client, "502 Bad Gateway").await;
            Err(err)
        }
    }
}
```

`connect_to_host_egress` is unchanged — it still opens the vsock and writes `"host:port\n"`; the optimistic reply is gone because `serve_*` no longer call `reply`/`reply_http_connect_ok` before the ack. `serve_http_forward` is untouched (no ack on the forward path).

Run (expect PASS): `cargo nextest run -p mvm-agentd egress_client` and `cargo nextest run -p mvm-agentd guest_vsock_session`.

- [ ] **Step 1a.5 — Failing test: host sends the ack (deny + failed connect)**

In `crates/mvm-hostd/src/supervisor/raw_egress.rs` `mod tests` (import `mvm_core::guest_netd::ConnectAck`):

```rust
#[tokio::test]
async fn denied_target_sends_fail_ack_then_closes() {
    let gate = EgressGate::default_deny();
    let (mut client, server) = tokio::io::duplex(1024);
    let h = tokio::spawn(async move {
        handle_raw_conn(server, &gate, Duration::from_secs(1)).await
    });
    client.write_all(b"93.184.216.34:80\n").await.unwrap();

    let mut ack = [0u8; 1];
    client.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack[0], ConnectAck::Fail.as_byte());

    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "no tunnel bytes after a Fail ack");
    h.await.unwrap().unwrap();
}

#[tokio::test]
async fn splice_sends_ok_ack_before_tunneling() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut b = [0u8; 4];
        sock.read_exact(&mut b).await.unwrap();
        sock.write_all(&b).await.unwrap();
    });

    let (mut client, guest) = tokio::io::duplex(1024);
    let splicer = tokio::spawn(async move {
        // 1a: single-IP splice. (Signature widens to `&[IpAddr]` in Task 1b,
        // and this call becomes `&[addr.ip()]`.)
        splice(guest, "echo", addr.ip(), addr.port(), Vec::new(), Duration::from_secs(2)).await
    });

    let mut ack = [0u8; 1];
    client.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack[0], ConnectAck::Ok.as_byte());

    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");

    client.shutdown().await.ok();
    drop(client);
    splicer.await.unwrap().unwrap();
    server.await.unwrap();
}
```

Also update the existing tests whose byte expectations change:
- `denied_target_closes_without_connecting`: it now reads the `Fail` ack first — replace with the assertion above (or delete it in favour of `denied_target_sends_fail_ack_then_closes`).
- `malformed_or_unterminated_first_line_fails_closed`: the **unterminated** half (no `\n` → `read_target_line` returns `None`) is unchanged (no ack). The **malformed-but-terminated** half (`"not-an-address\n"` → `Malformed`) now receives a `Fail` ack — read one ack byte == `ConnectAck::Fail.as_byte()`, then assert EOF.
- `splice_proxies_both_directions`: prepend a one-byte ack read (`assert_eq!(ack[0], ConnectAck::Ok.as_byte())`) before the leftover/`ping` assertions.

Run (expect FAIL): `cargo nextest run -p mvm-hostd raw_egress`

- [ ] **Step 1a.6 — Implement host ack (async + blocking)**

In `crates/mvm-hostd/src/supervisor/raw_egress.rs` add `use mvm_core::guest_netd::ConnectAck;`. Change `handle_raw_conn` Deny/Malformed arm:

```rust
EgressVerdict::Deny | EgressVerdict::Malformed => {
    eprintln!("raw-egress: refusing target {target}");
    write_connect_ack_async(&mut guest, ConnectAck::Fail).await?;
    Ok(())
}
```

Rewrite `splice` — 1a keeps the single `ip` param and adds the ack:

```rust
async fn splice<S>(
    mut guest: S,
    target: &str,
    ip: IpAddr,
    port: u16,
    leftover: Vec<u8>,
    timeout: Duration,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let connect = tokio::net::TcpStream::connect((ip, port));
    let mut upstream = match tokio::time::timeout(timeout, connect).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("raw-egress: connect to {ip}:{port} failed: {e}");
            write_connect_ack_async(&mut guest, ConnectAck::Fail).await?;
            return Ok(());
        }
        Err(_) => {
            eprintln!("raw-egress: connect to {ip}:{port} timed out after {timeout:?}");
            write_connect_ack_async(&mut guest, ConnectAck::Fail).await?;
            return Ok(());
        }
    };
    write_connect_ack_async(&mut guest, ConnectAck::Ok).await?;
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await?;
    }
    eprintln!("raw-egress: connected target {target} -> {ip}:{port}");
    if let Ok((guest_to_upstream, upstream_to_guest)) =
        tokio::io::copy_bidirectional(&mut guest, &mut upstream).await
    {
        eprintln!(
            "raw-egress: completed target {target} guest_to_upstream_bytes={guest_to_upstream} upstream_to_guest_bytes={upstream_to_guest}"
        );
    }
    Ok(())
}

async fn write_connect_ack_async<S>(guest: &mut S, ack: ConnectAck) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    guest.write_all(&[ack.as_byte()]).await?;
    guest.flush().await
}
```

In the blocking path, `handle_raw_conn_blocking`: change the Deny/Malformed arm and add the `Ok` ack after a successful connect:

```rust
let (ip, port) =
    match gate.decide_request_with(&target, |host| resolve_hostname_ips_pure(host, timeout)) {
        EgressVerdict::Allow { ip, port } => (ip, port),
        EgressVerdict::Deny | EgressVerdict::Malformed => {
            eprintln!("raw-egress: refusing target {target}");
            write_connect_ack_blocking(&mut guest, ConnectAck::Fail)?;
            return Ok(());
        }
    };

let upstream =
    match std::net::TcpStream::connect_timeout(&std::net::SocketAddr::new(ip, port), timeout) {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("raw-egress: connect to {ip}:{port} failed: {e}");
            write_connect_ack_blocking(&mut guest, ConnectAck::Fail)?;
            return Ok(());
        }
    };
write_connect_ack_blocking(&mut guest, ConnectAck::Ok)?;
eprintln!("raw-egress: connected target {target} -> {ip}:{port}");
// ... (unchanged: set_nonblocking / pump_bidirectional_poll)
```

Add the blocking ack writer (Linux-only):

```rust
#[cfg(target_os = "linux")]
fn write_connect_ack_blocking(guest: &mut std::fs::File, ack: ConnectAck) -> std::io::Result<()> {
    use std::io::Write;
    guest.write_all(&[ack.as_byte()])?;
    guest.flush()
}
```

Run (expect PASS): `cargo nextest run -p mvm-hostd raw_egress`; then `cargo nextest run -p mvm-core -p mvm-agentd -p mvm-hostd`, `cargo clippy -p mvm-core -p mvm-agentd -p mvm-hostd -- -D warnings`, `cargo fmt --all -- --check`.
Commit: `fix(net): gate the in-guest CONNECT reply on the host connect-result ack`

---

## Task 1b — Happy-eyeballs over all admitted pinned IPs

**Files**

- Modify `crates/mvm-runtime/src/vsock_egress_bridge/egress_gate.rs` (`EgressVerdict`; `decide_addr`; `decide_hostname_request`; add `admitted_ips`; update tests).
- Modify `crates/mvm-hostd/src/supervisor/raw_egress.rs` (`handle_raw_conn` Allow arm; `splice` signature `ip: IpAddr` → `ips: &[IpAddr]`; add `PER_IP_CONNECT_TIMEOUT` + `connect_first_admitted` (+ `_blocking`); `handle_raw_conn_blocking` Allow arm; update the 1a tests' `splice(...)` calls to `&[addr.ip()]`).
- Modify `crates/mvm-hostd/src/supervisor/http_forward.rs` (async `serve_http_forward` + `send_host_request`; blocking siblings) — compile-fix for the widened `Allow` variant, passing all IPs to reqwest `resolve_to_addrs`.
- No change at `crates/mvm-hostd/src/supervisor/substitution_proxy.rs` — its match is `EgressVerdict::Allow { .. }` (field-agnostic).
- Test paths: inline in `egress_gate.rs` and `raw_egress.rs` tests modules.

**Interfaces**

- Modifies `EgressVerdict::Allow { ip: IpAddr, port: u16 }` → `Allow { ips: Vec<IpAddr>, port: u16 }`.
- Produces (gate, private) `fn admitted_ips(egress: &CanonicalEgress, candidates: &[IpAddr], port: u16) -> Vec<IpAddr>` (pure; filters to policy-permitted, IPv4 before IPv6, stable within family).
- Modifies `EgressGate::{decide_addr, decide_hostname_request}` to the Vec form.
- Produces (host, private) `const PER_IP_CONNECT_TIMEOUT: Duration`; `async fn connect_first_admitted(&[IpAddr], u16, Duration) -> Option<tokio::net::TcpStream>`; `#[cfg(target_os = "linux")] fn connect_first_admitted_blocking(&[IpAddr], u16, Duration) -> Option<std::net::TcpStream>`.
- Modifies `raw_egress::splice(guest, target, ips: &[IpAddr], port, leftover, timeout)` and `http_forward::send_host_request{,_blocking}(.., admitted_ips: &[IpAddr], admitted_port, ..)`.

- [ ] **Step 1b.1 — Failing test: pure IP selection/ordering**

In `crates/mvm-runtime/src/vsock_egress_bridge/egress_gate.rs` `mod tests`:

```rust
#[test]
fn admitted_ips_keeps_only_permitted_and_orders_ipv4_first() {
    let egress = CanonicalEgress::Rules(vec![
        allow_rule("93.184.216.34/32", 443),
        allow_rule("2606:2800:220:1:248:1893:25c8:1946/128", 443),
    ]);
    let v4: IpAddr = "93.184.216.34".parse().unwrap();
    let v6: IpAddr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
    let unlisted: IpAddr = "8.8.8.8".parse().unwrap();

    // Resolver order is v6-first (as a dual-stack host often returns); the
    // unlisted address is dropped and the admitted set is reordered v4-first.
    let got = admitted_ips(&egress, &[v6, unlisted, v4], 443);
    assert_eq!(got, vec![v4, v6]);

    // Wrong port admits nothing.
    assert!(admitted_ips(&egress, &[v4, v6], 80).is_empty());
}

#[test]
fn hostname_request_returns_all_admitted_ips_ipv4_first() {
    use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
    use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

    let v6: IpAddr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
    let v4: IpAddr = "93.184.216.34".parse().unwrap();
    let mut pins = DnsPinRegistry::new();
    pins.add(DnsPin::at(
        "example.com",
        vec![v6, v4],
        "2025-01-01T00:00:00Z",
        "2030-01-01T00:00:00Z",
    ));
    let policy = NetworkPolicy::allow_list(vec![HostPort::new("example.com", 443)]);
    let gate = EgressGate::from_network_policy(&policy, &pins, "2026-01-01T00:00:00Z");

    match gate.decide_request("example.com:443") {
        EgressVerdict::Allow { ips, port } => {
            assert_eq!(ips, vec![v4, v6]);
            assert_eq!(port, 443);
        }
        EgressVerdict::Deny | EgressVerdict::Malformed => panic!("expected allow"),
    }
    assert_eq!(gate.decide_request("example.com:80"), EgressVerdict::Deny);
}
```

Every existing `egress_gate.rs` test asserting `Allow { ip: X, port }` must be updated to `Allow { ips: vec![X], port }` in the same step (they will fail to compile until then). NOTE: verify the exact constructor names (`CanonicalEgress::Rules`, `allow_rule`, `DnsPin::at`, `DnsPinRegistry::{new,add}`, `NetworkPolicy::allow_list`, `HostPort::new`) against the real code and adjust the test to the actual signatures before running. Run (expect FAIL — `admitted_ips` absent, variant shape mismatch): `cargo nextest run -p mvm-runtime egress_gate`

- [ ] **Step 1b.2 — Implement the widened verdict + selection**

In `egress_gate.rs`, change the enum:

```rust
pub enum EgressVerdict {
    /// The plan permits a TCP connection to this destination. `ips` are every
    /// admitted address (a pinned host can carry both an A and an AAAA record),
    /// IPv4 first; the caller connects to them in order, first success wins.
    Allow { ips: Vec<IpAddr>, port: u16 },
    Deny,
    Malformed,
}
```

`decide_addr`:

```rust
pub fn decide_addr(&self, ip: IpAddr, port: u16) -> EgressVerdict {
    if self.egress.permits(&Proto::Tcp, ip, port) {
        EgressVerdict::Allow { ips: vec![ip], port }
    } else {
        EgressVerdict::Deny
    }
}
```

`decide_hostname_request` — collect candidates once, filter through the pure helper:

```rust
fn decide_hostname_request<F>(&self, host: &str, port: u16, resolve: F) -> EgressVerdict
where
    F: Fn(&str) -> std::io::Result<Vec<IpAddr>>,
{
    let candidates = if let Some(pin) = self.pins.lookup(host) {
        pin.ips.clone()
    } else if matches!(self.egress, CanonicalEgress::Unrestricted) {
        match resolve(host) {
            Ok(ips) => ips,
            Err(_) => return EgressVerdict::Deny,
        }
    } else {
        return EgressVerdict::Deny;
    };
    let ips = admitted_ips(&self.egress, &candidates, port);
    if ips.is_empty() {
        EgressVerdict::Deny
    } else {
        EgressVerdict::Allow { ips, port }
    }
}
```

Add the pure helper (free function, below the `impl`):

```rust
/// Filter `candidates` to the addresses the policy admits on `port`, ordered so
/// IPv4 is tried before IPv6. Preferring IPv4 avoids stalling a connect on an
/// AAAA address when the host has no working IPv6 egress; the caller still falls
/// back to every admitted address, so a v4-only or v6-only destination is
/// unaffected. Stable within each family, so resolver order is otherwise kept.
fn admitted_ips(egress: &CanonicalEgress, candidates: &[IpAddr], port: u16) -> Vec<IpAddr> {
    let mut admitted: Vec<IpAddr> = candidates
        .iter()
        .copied()
        .filter(|ip| egress.permits(&Proto::Tcp, *ip, port))
        .collect();
    admitted.sort_by_key(|ip| match ip {
        IpAddr::V4(_) => 0u8,
        IpAddr::V6(_) => 1u8,
    });
    admitted
}
```

Run (expect PASS): `cargo nextest run -p mvm-runtime egress_gate`. Hold the commit to the end of Task 1b (the enum change breaks the host call sites until 1b.4/1b.5 update them; keep the workspace green before any commit).

- [ ] **Step 1b.3 — Failing test: connect fallover + splice over multiple IPs**

In `raw_egress.rs` `mod tests`:

```rust
#[tokio::test]
async fn connect_first_admitted_skips_unreachable_then_uses_reachable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accept = tokio::spawn(async move { let _ = listener.accept().await; });

    // TEST-NET-1 (RFC 5737) is not routable — the connect fails or is bounded
    // by the per-IP budget, then falls over to the reachable loopback address.
    let unreachable: IpAddr = "192.0.2.1".parse().unwrap();
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();

    let stream =
        connect_first_admitted(&[unreachable, loopback], port, Duration::from_secs(2)).await;
    assert!(stream.is_some(), "must fall over to the reachable address");
    accept.await.unwrap();
}

#[tokio::test]
async fn splice_sends_fail_ack_when_no_admitted_ip_is_reachable() {
    let (mut client, guest) = tokio::io::duplex(1024);
    let ips = vec!["192.0.2.1".parse::<IpAddr>().unwrap()];
    let splicer = tokio::spawn(async move {
        splice(guest, "unreachable", &ips, 443, Vec::new(), Duration::from_secs(1)).await
    });

    let mut ack = [0u8; 1];
    client.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack[0], ConnectAck::Fail.as_byte());

    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    splicer.await.unwrap().unwrap();
}
```

Update the 1a `splice_sends_ok_ack_before_tunneling` and `splice_proxies_both_directions` calls from `addr.ip()` to `&[addr.ip()]` (move an owned `let ips = vec![addr.ip()];` into the spawned closure so the borrow is `'static`).

Run (expect FAIL — `connect_first_admitted` absent, `splice` still single-IP): `cargo nextest run -p mvm-hostd raw_egress`

- [ ] **Step 1b.4 — Implement the multi-IP connect loop + splice**

In `raw_egress.rs`, add near the constants:

```rust
/// Per-address connect budget when trying an admitted set: small so an
/// unreachable address (e.g. an AAAA with no host IPv6 egress) fails over to the
/// next candidate quickly instead of stalling the request on the first.
const PER_IP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
```

Change `handle_raw_conn` Allow arm:

```rust
EgressVerdict::Allow { ips, port } => {
    splice(guest, &target, &ips, port, leftover, timeout).await
}
```

Rewrite `splice` to iterate (replacing the 1a body):

```rust
async fn splice<S>(
    mut guest: S,
    target: &str,
    ips: &[IpAddr],
    port: u16,
    leftover: Vec<u8>,
    timeout: Duration,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut upstream = match connect_first_admitted(ips, port, timeout).await {
        Some(stream) => stream,
        None => {
            eprintln!("raw-egress: no admitted address reachable for {target}");
            write_connect_ack_async(&mut guest, ConnectAck::Fail).await?;
            return Ok(());
        }
    };
    write_connect_ack_async(&mut guest, ConnectAck::Ok).await?;
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await?;
    }
    eprintln!("raw-egress: connected target {target}");
    if let Ok((guest_to_upstream, upstream_to_guest)) =
        tokio::io::copy_bidirectional(&mut guest, &mut upstream).await
    {
        eprintln!(
            "raw-egress: completed target {target} guest_to_upstream_bytes={guest_to_upstream} upstream_to_guest_bytes={upstream_to_guest}"
        );
    }
    Ok(())
}

/// Try each admitted address in order, first success wins, bounded overall by
/// `overall_timeout` and per-address by [`PER_IP_CONNECT_TIMEOUT`].
async fn connect_first_admitted(
    ips: &[IpAddr],
    port: u16,
    overall_timeout: Duration,
) -> Option<tokio::net::TcpStream> {
    let deadline = tokio::time::Instant::now() + overall_timeout;
    for ip in ips {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let budget = remaining.min(PER_IP_CONNECT_TIMEOUT);
        match tokio::time::timeout(budget, tokio::net::TcpStream::connect((*ip, port))).await {
            Ok(Ok(stream)) => return Some(stream),
            Ok(Err(e)) => eprintln!("raw-egress: connect to {ip}:{port} failed: {e}"),
            Err(_) => eprintln!("raw-egress: connect to {ip}:{port} timed out after {budget:?}"),
        }
    }
    None
}
```

Blocking path — `handle_raw_conn_blocking` Allow arm + connect loop:

```rust
let (ips, port) =
    match gate.decide_request_with(&target, |host| resolve_hostname_ips_pure(host, timeout)) {
        EgressVerdict::Allow { ips, port } => (ips, port),
        EgressVerdict::Deny | EgressVerdict::Malformed => {
            eprintln!("raw-egress: refusing target {target}");
            write_connect_ack_blocking(&mut guest, ConnectAck::Fail)?;
            return Ok(());
        }
    };

let upstream = match connect_first_admitted_blocking(&ips, port, timeout) {
    Some(stream) => stream,
    None => {
        eprintln!("raw-egress: no admitted address reachable for {target}");
        write_connect_ack_blocking(&mut guest, ConnectAck::Fail)?;
        return Ok(());
    }
};
write_connect_ack_blocking(&mut guest, ConnectAck::Ok)?;
// ... (unchanged: set_nonblocking / pump_bidirectional_poll)
```

```rust
#[cfg(target_os = "linux")]
fn connect_first_admitted_blocking(
    ips: &[IpAddr],
    port: u16,
    overall_timeout: Duration,
) -> Option<std::net::TcpStream> {
    let deadline = std::time::Instant::now() + overall_timeout;
    for ip in ips {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let budget = remaining.min(PER_IP_CONNECT_TIMEOUT);
        match std::net::TcpStream::connect_timeout(&std::net::SocketAddr::new(*ip, port), budget) {
            Ok(stream) => return Some(stream),
            Err(e) => eprintln!("raw-egress: connect to {ip}:{port} failed: {e}"),
        }
    }
    None
}
```

Run (expect PASS): `cargo nextest run -p mvm-hostd raw_egress`

- [ ] **Step 1b.5 — Compile-fix `http_forward` for the widened variant**

In `crates/mvm-hostd/src/supervisor/http_forward.rs`, async arm:

```rust
let (ips, port) = match gate.decide_request(&request.target) {
    EgressVerdict::Allow { ips, port } => (ips, port),
    EgressVerdict::Deny => {
        write_proxy_error_async(&mut guest, ProxyStatus::Forbidden).await?;
        return Ok(());
    }
    EgressVerdict::Malformed => {
        write_proxy_error_async(&mut guest, ProxyStatus::BadRequest).await?;
        return Ok(());
    }
};
// ...
let response = match send_host_request(&request, body, &ips, port, timeout).await { /* unchanged */ };
```

`send_host_request` signature `admitted_ip: IpAddr` → `admitted_ips: &[IpAddr]`, and the resolve override passes all (reqwest tries them):

```rust
if request.host.parse::<IpAddr>().is_err() {
    let socket_addrs: Vec<SocketAddr> = admitted_ips
        .iter()
        .map(|ip| SocketAddr::new(*ip, admitted_port))
        .collect();
    builder = builder.resolve_to_addrs(&request.host, &socket_addrs);
}
```

Apply the identical change to the blocking `serve_http_forward_blocking` and `send_host_request_blocking`. The `http_forward` tests use `default_deny` (Deny→403) and `unrestricted`+malformed (Malformed→400) — none match `Allow { .. }`, so they are unaffected.

Run (expect PASS): `cargo nextest run -p mvm-runtime -p mvm-hostd`; then `cargo clippy -p mvm-runtime -p mvm-hostd -- -D warnings`, `cargo fmt --all -- --check`, and `cargo build --workspace --all-targets` to catch any other `Allow` consumer.
Commit: `fix(net): connect to every admitted pinned IP, IPv4-first, on the egress splice`

---

## Task 1c — `@live` BDD scenario for an admitted egress round-trip

**Files**

- Create `features/suites/s2_egress_vsock/admitted_egress_live.feature`.
- No step code needed — reuses `When I run mvmctl with {string}`, `Then the command exits with code {int}`, `Then the output contains {string}` (`crates/mvm-conformance/tests/steps/cli.rs`). The `@live` tag is gated by `MVM_BDD_LIVE` in `crates/mvm-conformance/tests/conformance.rs` (`LIVE_TAG = "live"`).

**Interfaces**

- Consumes the existing `CliWorld` step facade and the `@live` lane. Produces no Rust.

- [ ] **Step 1c.1 — Add the scenario**

Create `features/suites/s2_egress_vsock/admitted_egress_live.feature`:

```gherkin
Feature: Admitted egress completes end-to-end over the vsock seam

  An allow-listed destination reached through the in-guest proxy connects and
  returns real bytes: the host confirms the outbound connect before the guest
  reports success, and it tries every admitted address so an unreachable IPv6
  pin never strands the request.

  @live
  Scenario: An admitted https destination returns its page body
    When I run mvmctl with "machine run --image alpine --allow-host example.com -- wget -q -O - https://example.com"
    Then the command exits with code 0
    And the output contains "Example Domain"
```

- [ ] **Step 1c.2 — Verify hermetic-lane skip and live-lane shape**

- Hermetic (default) lane — the scenario is skipped, suite still green:
  `cargo nextest run -p mvm-conformance` (expect PASS; `@live` skipped because `MVM_BDD_LIVE` is unset)
- Live lane (HVF host, after 1a+1b merged):
  `MVM_BDD_LIVE=1 cargo nextest run -p mvm-conformance` (expect PASS — exits 0, body contains `Example Domain`)

The live run is the regression that the prior symptom (`exit 124` hang) is fixed; it requires a working HVF backend host and is not part of the hermetic PR gate.

Commit: `test(bdd): assert an admitted allow-host https run completes over vsock egress`

---

## Sequencing & final gate

1a → 1b → 1c. Each task ends green independently; `splice` is edited by both 1a (add ack, single-IP) and 1b (generalise to `&[IpAddr]`), which is expected. Before the final push run the full named gate:

```
cargo fmt --all -- --check
cargo nextest run -p mvm-core -p mvm-agentd -p mvm-runtime -p mvm-hostd -p mvm-conformance
cargo test -p mvm-core -p mvm-agentd -p mvm-runtime -p mvm-hostd --doc
cargo clippy --workspace -- -D warnings
cargo build --workspace --all-targets
```

Deferred (Part 2, tracked separately): the DNS resolver — pin TTL/refresh and the policy-gated audited resolver. Not addressed here; 1b's IPv4-first happy-eyeballs is the data-path mitigation, not a resolver change.
