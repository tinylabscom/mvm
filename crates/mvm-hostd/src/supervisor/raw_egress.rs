//! The raw-TCP egress serve loop for the substitution endpoint.
//!
//! A NIC-less guest whose admitted plan carries no secrets reaches the host over
//! the same relayed EGRESS_PORT stream, but speaks raw TCP instead of the framed
//! WireRequest substitution protocol: the first line is the connect target
//! `"host:port\n"`, then it's a byte splice both ways. This module is the host end.
//!
//! The claim-10 decision is the shared [`EgressGate`] every backend agrees on —
//! never a second gate here. The connect + splice mechanics live in [`splice`],
//! separated from the gate decision so the data path is unit-testable against a
//! loopback echo server (the gate mandatory-denies loopback, so an admitted-target
//! splice test cannot route through the real gate).

use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::net::{SocketAddr, UdpSocket};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

#[cfg(target_os = "linux")]
use hickory_proto::op::{Message, MessageType, OpCode, Query};
#[cfg(target_os = "linux")]
use hickory_proto::rr::rdata::{A, AAAA};
#[cfg(target_os = "linux")]
use hickory_proto::rr::{Name, RData, RecordType};
#[cfg(target_os = "linux")]
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::supervisor::audit_recorder::Recorder;
use crate::supervisor::{
    dns_handler, egress_rate, http_forward, icmp_echo, icmp_handler, socks5_udp,
};
use mvm_core::guest_netd::ConnectAck;
use mvm_runtime::vmm::egress_gate::{EgressGate, EgressVerdict};

/// Cap on the first `host:port` line. A guest that never sends a `\n` inside this
/// many bytes is refused (fail closed) rather than read unbounded.
const MAX_TARGET_LINE: usize = 256;
/// Per-address connect budget when trying an admitted set: small so an
/// unreachable address (e.g. an AAAA with no host IPv6 egress) fails over to the
/// next candidate quickly instead of stalling the request on the first.
const PER_IP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(target_os = "linux")]
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Serve raw-TCP egress over a bound UDS listener: one tokio task per guest
/// connection, each gated then spliced. Runs until the listener errors.
pub async fn serve_raw_egress(
    listener: tokio::net::UnixListener,
    gate: Arc<EgressGate>,
    recorder: Option<Arc<Recorder>>,
    timeout: Duration,
) {
    let rate_guard = Arc::new(egress_rate::EgressRateGuard::default());
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let gate = Arc::clone(&gate);
                let recorder = recorder.clone();
                let rate_guard = Arc::clone(&rate_guard);
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_raw_conn(stream, &gate, recorder, rate_guard, timeout).await
                    {
                        tracing::warn!(error = %e, "raw egress connection failed");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "raw egress accept failed; stopping");
                return;
            }
        }
    }
}

/// Handle one guest connection: read the first `host:port` line, decide it against
/// the gate, and (only on `Allow`) connect + splice. Any refusal or malformed
/// target closes the connection without connecting — fail closed.
async fn handle_raw_conn<S>(
    mut guest: S,
    gate: &EgressGate,
    recorder: Option<Arc<Recorder>>,
    rate_guard: Arc<egress_rate::EgressRateGuard>,
    timeout: Duration,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some((target, leftover)) = read_target_line(&mut guest).await? else {
        // No `\n` within the cap → fail closed, close without connecting.
        return Ok(());
    };
    if target == http_forward::FRAME_LINE {
        return http_forward::serve_http_forward(guest, gate, timeout).await;
    }
    if target == dns_handler::FRAME_LINE {
        return dns_handler::serve_dns(guest, gate, recorder.as_deref(), &rate_guard, timeout)
            .await;
    }
    if target == socks5_udp::FRAME_LINE {
        return socks5_udp::serve(guest, gate, timeout).await;
    }
    if target == icmp_handler::FRAME_LINE {
        return icmp_handler::serve_icmp(
            guest,
            gate,
            recorder.as_deref(),
            &rate_guard,
            &icmp_echo::PingSocketEcho,
        )
        .await;
    }
    match gate.decide_request_with(&target, |host| resolve_hostname_ips_pure(host, timeout)) {
        EgressVerdict::Allow { ips, port } => {
            splice(guest, &target, &ips, port, leftover, timeout).await
        }
        // A raw tunnel's only reply is a one-byte nack, so the reason cannot
        // reach the guest here the way it does on the HTTP forward path. Log it
        // host-side rather than discarding it — otherwise the operator's only
        // signal is a connection that failed.
        verdict @ (EgressVerdict::Deny(_) | EgressVerdict::Malformed) => {
            match verdict {
                EgressVerdict::Deny(reason) => {
                    eprintln!("raw-egress: refusing target {target}: {reason}")
                }
                _ => eprintln!("raw-egress: refusing malformed target {target}"),
            }
            // Refused: nack the guest and close without ever opening a host socket.
            write_connect_ack_async(&mut guest, ConnectAck::Fail).await?;
            Ok(())
        }
    }
}

/// Read bytes until the first `\n`, bounded at [`MAX_TARGET_LINE`]. Returns the
/// trimmed target string plus any bytes already read past the `\n` (pipelined
/// request bytes that must be forwarded upstream first). `None` ⇒ EOF or the cap
/// was hit with no newline (fail closed).
async fn read_target_line<S>(guest: &mut S) -> std::io::Result<Option<(String, Vec<u8>)>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = guest.read(&mut byte).await?;
        if n == 0 {
            return Ok(None); // EOF before a newline
        }
        if byte[0] == b'\n' {
            let target = String::from_utf8_lossy(&buf).trim().to_string();
            // Anything already buffered past the `\n` this read didn't produce;
            // single-byte reads never overshoot, so leftover is empty here.
            return Ok(Some((target, Vec::new())));
        }
        buf.push(byte[0]);
        if buf.len() >= MAX_TARGET_LINE {
            return Ok(None); // unterminated / oversized → fail closed
        }
    }
}

/// Connect to the first reachable of `ips` and splice bytes both ways until
/// either side EOFs. `leftover` bytes (pipelined after the target line's `\n`)
/// are forwarded upstream before the bidirectional copy so nothing is dropped.
///
/// Split out from the gate decision so it's unit-testable against a loopback echo
/// server without routing through the real gate (which mandatory-denies loopback).
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
    // EOF on either side ends the copy; a reset surfaces as an error we swallow so
    // one torn-down connection never crashes the accept loop.
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
/// `overall_timeout` and per-address by [`PER_IP_CONNECT_TIMEOUT`]. This is the
/// happy-eyeballs fallover: a pinned host can carry both an A and an AAAA
/// record, and an unreachable IPv6 address (no host IPv6 egress) must not
/// strand an otherwise-admitted request.
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

/// Write the host's one-byte connect-result ack on the async raw-egress path.
async fn write_connect_ack_async<S>(guest: &mut S, ack: ConnectAck) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    guest.write_all(&[ack.as_byte()]).await?;
    guest.flush().await
}

/// Serve raw-TCP egress over a host **AF_VSOCK** listener — the QEMU path,
/// mirroring how `SubstitutionService::serve_vsock` structures its accept loop.
/// The hvf VMM relay uses the UDS path above; this is the thin vsock sibling
/// for backends that route guest→host over `vhost-vsock`.
///
/// Both `accept(2)` and the per-connection target-read + splice run with blocking
/// I/O. We intentionally avoid tokio's lazy `spawn_blocking` pool here: this
/// endpoint self-confines *after* the runtime is built, and the raw builder path
/// needs to keep working under seccomp even when no extra blocking-worker thread
/// may be created afterward. The connect + upstream splice reuse the same gate
/// decision as the UDS path.
#[cfg(target_os = "linux")]
pub async fn serve_raw_egress_vsock(
    listener: crate::supervisor::substitution_proxy::vsock::VsockListener,
    gate: Arc<EgressGate>,
    recorder: Option<Arc<Recorder>>,
    timeout: Duration,
) {
    use crate::supervisor::substitution_proxy::vsock;
    let rate_guard = Arc::new(egress_rate::EgressRateGuard::default());
    loop {
        let listen_fd = listener.raw_fd();
        let conn_fd = match vsock::accept(listen_fd) {
            Ok(fd) => fd,
            Err(e) => {
                tracing::warn!(error = %e, "raw egress vsock accept failed; stopping");
                return;
            }
        };
        let gate = Arc::clone(&gate);
        let recorder = recorder.clone();
        let rate_guard = Arc::clone(&rate_guard);
        if let Err(e) = spawn_raw_egress_connection(conn_fd, gate, recorder, rate_guard, timeout) {
            tracing::warn!(error = %e, "raw egress vsock connection thread failed to start");
        }
    }
}

/// Start one blocking raw-egress handler without holding up the AF_VSOCK
/// accept loop. The returned handle is intentionally detached by production
/// callers; tests may join it to await handler cleanup.
#[cfg(target_os = "linux")]
fn spawn_raw_egress_connection(
    conn_fd: std::os::fd::RawFd,
    gate: Arc<EgressGate>,
    recorder: Option<Arc<Recorder>>,
    rate_guard: Arc<egress_rate::EgressRateGuard>,
    timeout: Duration,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let spawn = std::thread::Builder::new()
        .name("mvm-raw-egress-vsock".to_string())
        .spawn(move || {
            if let Err(e) = handle_raw_conn_blocking(conn_fd, &gate, recorder, rate_guard, timeout)
            {
                tracing::warn!(error = %e, "raw egress vsock connection failed");
            }
        });
    match spawn {
        Ok(handle) => Ok(handle),
        Err(error) => {
            // The connection fd is still owned by this thread when thread
            // creation fails; adopt it so the failed connection is closed.
            unsafe {
                drop(OwnedFd::from_raw_fd(conn_fd));
            }
            Err(error)
        }
    }
}

#[cfg(target_os = "linux")]
fn handle_raw_conn_blocking(
    conn_fd: std::os::fd::RawFd,
    gate: &EgressGate,
    recorder: Option<Arc<Recorder>>,
    rate_guard: Arc<egress_rate::EgressRateGuard>,
    timeout: Duration,
) -> std::io::Result<()> {
    let owned = unsafe { OwnedFd::from_raw_fd(conn_fd) };
    let mut guest = std::fs::File::from(owned);

    let Some(target) = read_target_line_blocking(&mut guest)? else {
        return Ok(());
    };
    if target == http_forward::FRAME_LINE {
        return http_forward::serve_http_forward_blocking(guest, gate, timeout);
    }
    if target == dns_handler::FRAME_LINE {
        return dns_handler::serve_dns_blocking(
            guest,
            gate,
            recorder.as_deref(),
            &rate_guard,
            timeout,
        );
    }
    if target == icmp_handler::FRAME_LINE {
        return icmp_handler::serve_icmp_blocking(
            guest,
            gate,
            recorder.as_deref(),
            &rate_guard,
            &icmp_echo::PingSocketEcho,
        );
    }
    if target == socks5_udp::FRAME_LINE {
        return socks5_udp::serve_blocking(guest, gate, timeout);
    }
    let (ips, port) =
        match gate.decide_request_with(&target, |host| resolve_hostname_ips_pure(host, timeout)) {
            EgressVerdict::Allow { ips, port } => (ips, port),
            // As on the async path: a raw tunnel answers with a one-byte nack,
            // so the reason is logged host-side rather than discarded.
            verdict @ (EgressVerdict::Deny(_) | EgressVerdict::Malformed) => {
                match verdict {
                    EgressVerdict::Deny(reason) => {
                        eprintln!("raw-egress: refusing target {target}: {reason}")
                    }
                    _ => eprintln!("raw-egress: refusing malformed target {target}"),
                }
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
    eprintln!("raw-egress: connected target {target}");
    let guest_fd = guest.as_raw_fd();
    set_nonblocking(guest_fd)?;
    upstream.set_nonblocking(true)?;
    let stats = pump_bidirectional_poll(&guest, &upstream)?;
    eprintln!(
        "raw-egress: completed target {target} guest_to_upstream_bytes={} upstream_to_guest_bytes={} guest_eof={} upstream_eof={}",
        stats.guest_to_upstream_bytes,
        stats.upstream_to_guest_bytes,
        stats.guest_eof,
        stats.upstream_eof,
    );
    Ok(())
}

/// Write the host's one-byte connect-result ack on the blocking raw-egress path.
#[cfg(target_os = "linux")]
fn write_connect_ack_blocking(guest: &mut std::fs::File, ack: ConnectAck) -> std::io::Result<()> {
    use std::io::Write;
    guest.write_all(&[ack.as_byte()])?;
    guest.flush()
}

/// Blocking sibling of [`connect_first_admitted`] for the AF_VSOCK accept path.
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

#[cfg(target_os = "linux")]
fn read_target_line_blocking<R: std::io::Read>(reader: &mut R) -> std::io::Result<Option<String>> {
    let mut buf = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte)?;
        if n == 0 {
            return Ok(None);
        }
        if byte[0] == b'\n' {
            return Ok(Some(String::from_utf8_lossy(&buf).trim().to_string()));
        }
        buf.push(byte[0]);
        if buf.len() >= MAX_TARGET_LINE {
            return Ok(None);
        }
    }
}

#[cfg(target_os = "linux")]
fn pump_bidirectional_poll(
    guest: &std::fs::File,
    upstream: &std::net::TcpStream,
) -> std::io::Result<PumpStats> {
    let guest_fd = guest.as_raw_fd();
    let upstream_fd = upstream.as_raw_fd();
    let mut guest_open = true;
    let mut upstream_open = true;
    let mut guest_write_shutdown = false;
    let mut upstream_write_shutdown = false;
    let mut guest_to_upstream = Vec::new();
    let mut upstream_to_guest = Vec::new();
    let mut scratch_guest = [0u8; 16 * 1024];
    let mut scratch_upstream = [0u8; 16 * 1024];
    let mut stats = PumpStats::default();

    loop {
        let mut fds = [
            libc::pollfd {
                fd: guest_fd,
                events: 0,
                revents: 0,
            },
            libc::pollfd {
                fd: upstream_fd,
                events: 0,
                revents: 0,
            },
        ];

        if guest_open && guest_to_upstream.is_empty() {
            fds[0].events |= libc::POLLIN;
        }
        if !upstream_to_guest.is_empty() {
            fds[0].events |= libc::POLLOUT;
        }
        if upstream_open && upstream_to_guest.is_empty() {
            fds[1].events |= libc::POLLIN;
        }
        if !guest_to_upstream.is_empty() {
            fds[1].events |= libc::POLLOUT;
        }

        if fds[0].events == 0 && fds[1].events == 0 {
            break;
        }

        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        if (fds[0].revents & libc::POLLIN) != 0 && guest_to_upstream.is_empty() && guest_open {
            match read_into_buffer(guest_fd, &mut scratch_guest, &mut guest_to_upstream)? {
                ReadOutcome::Open(bytes) => stats.guest_to_upstream_bytes += bytes,
                ReadOutcome::Closed => {
                    guest_open = false;
                    stats.guest_eof = true;
                }
            }
        }
        if (fds[1].revents & libc::POLLIN) != 0 && upstream_to_guest.is_empty() && upstream_open {
            match read_into_buffer(upstream_fd, &mut scratch_upstream, &mut upstream_to_guest)? {
                ReadOutcome::Open(bytes) => stats.upstream_to_guest_bytes += bytes,
                ReadOutcome::Closed => {
                    upstream_open = false;
                    stats.upstream_eof = true;
                }
            }
        }
        if (fds[1].revents & libc::POLLOUT) != 0 && !guest_to_upstream.is_empty() {
            write_from_buffer(upstream_fd, &mut guest_to_upstream)?;
        }
        if (fds[0].revents & libc::POLLOUT) != 0 && !upstream_to_guest.is_empty() {
            write_from_buffer(guest_fd, &mut upstream_to_guest)?;
        }

        if !guest_open && guest_to_upstream.is_empty() && !upstream_write_shutdown {
            shutdown_write(upstream_fd)?;
            upstream_write_shutdown = true;
        }
        if !upstream_open && upstream_to_guest.is_empty() && !guest_write_shutdown {
            shutdown_write(guest_fd)?;
            guest_write_shutdown = true;
        }
    }

    Ok(stats)
}

#[cfg(target_os = "linux")]
enum ReadOutcome {
    Open(usize),
    Closed,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct PumpStats {
    guest_to_upstream_bytes: usize,
    upstream_to_guest_bytes: usize,
    guest_eof: bool,
    upstream_eof: bool,
}

#[cfg(target_os = "linux")]
fn set_nonblocking(fd: libc::c_int) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_into_buffer(
    fd: libc::c_int,
    scratch: &mut [u8],
    pending: &mut Vec<u8>,
) -> std::io::Result<ReadOutcome> {
    let rc = unsafe {
        libc::read(
            fd,
            scratch.as_mut_ptr().cast::<libc::c_void>(),
            scratch.len(),
        )
    };
    if rc == 0 {
        return Ok(ReadOutcome::Closed);
    }
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
            return Ok(ReadOutcome::Open(0));
        }
        return Err(err);
    }
    let bytes = rc as usize;
    pending.extend_from_slice(&scratch[..bytes]);
    Ok(ReadOutcome::Open(bytes))
}

#[cfg(target_os = "linux")]
fn write_from_buffer(fd: libc::c_int, pending: &mut Vec<u8>) -> std::io::Result<()> {
    while !pending.is_empty() {
        let rc = unsafe { libc::write(fd, pending.as_ptr().cast::<libc::c_void>(), pending.len()) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
                return Ok(());
            }
            return Err(err);
        }
        pending.drain(..rc as usize);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn shutdown_write(fd: libc::c_int) -> std::io::Result<()> {
    let rc = unsafe { libc::shutdown(fd, libc::SHUT_WR) };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOTCONN) {
        return Ok(());
    }
    Err(err)
}

#[cfg(target_os = "linux")]
pub(crate) fn resolve_hostname_ips_pure(
    host: &str,
    timeout: Duration,
) -> std::io::Result<Vec<IpAddr>> {
    let upstreams = load_upstreams_from_resolv_conf(RESOLV_CONF_PATH)?;
    if upstreams.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no nameservers found in {RESOLV_CONF_PATH}"),
        ));
    }
    let timeout = timeout.min(DNS_QUERY_TIMEOUT);
    let mut ips = Vec::new();
    ips.extend(query_upstreams(host, RecordType::A, &upstreams, timeout)?);
    ips.extend(query_upstreams(
        host,
        RecordType::AAAA,
        &upstreams,
        timeout,
    )?);
    if ips.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("dns lookup {host}: no A/AAAA records returned"),
        ));
    }
    Ok(ips)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn resolve_hostname_ips_pure(
    host: &str,
    timeout: Duration,
) -> std::io::Result<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;
    use std::sync::mpsc;
    use std::thread;

    let host = host.to_string();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = (host.as_str(), 0u16)
            .to_socket_addrs()
            .map(|iter| iter.map(|addr| addr.ip()).collect());
        let _ = tx.send(result);
    });

    let dns_timeout = timeout.min(Duration::from_secs(3));
    match rx.recv_timeout(dns_timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "DNS resolution timed out",
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(std::io::Error::other("DNS resolution thread disconnected"))
        }
    }
}

#[cfg(target_os = "linux")]
fn load_upstreams_from_resolv_conf(path: &str) -> std::io::Result<Vec<SocketAddr>> {
    let body = std::fs::read_to_string(path)?;
    let mut upstreams = Vec::new();
    for line in body.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        let Some(addr) = parts.next() else {
            continue;
        };
        let ip = addr.parse::<IpAddr>().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid nameserver {addr:?} in {path}: {e}"),
            )
        })?;
        upstreams.push(SocketAddr::new(ip, 53));
    }
    Ok(upstreams)
}

#[cfg(target_os = "linux")]
fn query_upstreams(
    host: &str,
    record_type: RecordType,
    upstreams: &[SocketAddr],
    timeout: Duration,
) -> std::io::Result<Vec<IpAddr>> {
    let packet = build_dns_query(host, record_type)?;
    let request = decode_dns_message(&packet)?;
    for upstream in upstreams {
        if let Ok(response) = query_upstream(*upstream, &packet, timeout) {
            let ips = parse_dns_response(&request, &response, record_type)?;
            if !ips.is_empty() {
                return Ok(ips);
            }
        }
    }
    Ok(Vec::new())
}

#[cfg(target_os = "linux")]
fn build_dns_query(host: &str, record_type: RecordType) -> std::io::Result<Vec<u8>> {
    let name = Name::from_ascii(host).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid dns hostname {host:?}: {e}"),
        )
    })?;
    let mut message = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, record_type));
    encode_dns_message(message)
}

#[cfg(target_os = "linux")]
fn encode_dns_message(message: Message) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut out);
    message.emit(&mut encoder).map_err(invalid_dns_data)?;
    Ok(out)
}

#[cfg(target_os = "linux")]
fn decode_dns_message(packet: &[u8]) -> std::io::Result<Message> {
    let mut decoder = hickory_proto::serialize::binary::BinDecoder::new(packet);
    Message::read(&mut decoder).map_err(invalid_dns_data)
}

#[cfg(target_os = "linux")]
fn parse_dns_response(
    request: &Message,
    packet: &[u8],
    record_type: RecordType,
) -> std::io::Result<Vec<IpAddr>> {
    let response = decode_dns_message(packet)?;
    if response.metadata.message_type != MessageType::Response
        || response.metadata.id != request.metadata.id
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "upstream DNS response did not match the forwarded query",
        ));
    }
    Ok(response
        .answers
        .iter()
        .filter_map(|answer| match (record_type, &answer.data) {
            (RecordType::A, RData::A(A(ipv4))) => Some(IpAddr::V4(*ipv4)),
            (RecordType::AAAA, RData::AAAA(AAAA(ipv6))) => Some(IpAddr::V6(*ipv6)),
            _ => None,
        })
        .collect())
}

#[cfg(target_os = "linux")]
fn query_upstream(
    upstream: SocketAddr,
    packet: &[u8],
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let bind_addr = match upstream.ip() {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.connect(upstream)?;
    socket.send(packet)?;
    let mut buf = vec![0u8; 1232];
    let len = socket.recv(&mut buf)?;
    buf.truncate(len);
    Ok(buf)
}

#[cfg(target_os = "linux")]
fn invalid_dns_data(err: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use hickory_proto::rr::{Name, Record};
    use mvm_core::policy::network_policy::NetworkPolicy;
    #[cfg(target_os = "linux")]
    use std::io::{Read, Write};
    #[cfg(target_os = "linux")]
    use std::net::{Ipv4Addr, Ipv6Addr};
    #[cfg(target_os = "linux")]
    use std::os::fd::IntoRawFd;
    #[cfg(target_os = "linux")]
    use std::os::unix::net::UnixStream;
    #[cfg(target_os = "linux")]
    use tempfile::tempdir;
    use tokio::io::AsyncWriteExt;

    /// A default-deny gate + a well-formed target ⇒ the host nacks the connect and
    /// closes without ever opening an upstream socket (fail closed).
    #[tokio::test]
    async fn denied_target_sends_fail_ack_then_closes() {
        let gate = EgressGate::default_deny();
        let (mut client, server) = tokio::io::duplex(1024);
        let h = tokio::spawn(async move {
            handle_raw_conn(
                server,
                &gate,
                None,
                Arc::new(egress_rate::EgressRateGuard::default()),
                Duration::from_secs(1),
            )
            .await
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

    /// An unterminated first line (no `\n` within the cap) fails closed: the
    /// handler returns without connecting.
    #[tokio::test]
    async fn malformed_or_unterminated_first_line_fails_closed() {
        // Unrestricted gate so any refusal here is the *parse*, not the policy.
        let pins = mvm_core::policy::dns_pin::DnsPinRegistry::new();
        let gate = EgressGate::from_network_policy(
            &NetworkPolicy::unrestricted(),
            &pins,
            "2026-01-01T00:00:00Z",
        );
        let (mut client, server) = tokio::io::duplex(4096);
        let h = tokio::spawn(async move {
            handle_raw_conn(
                server,
                &gate,
                None,
                Arc::new(egress_rate::EgressRateGuard::default()),
                Duration::from_secs(1),
            )
            .await
        });
        // Over-long line with no newline → read_target_line returns None → close.
        let junk = vec![b'x'; MAX_TARGET_LINE + 10];
        client.write_all(&junk).await.unwrap();
        client.shutdown().await.ok();
        let mut sink = Vec::new();
        let n = client.read_to_end(&mut sink).await.unwrap();
        assert_eq!(n, 0, "unterminated target must not splice");
        h.await.unwrap().unwrap();

        // A malformed but newline-terminated target is likewise refused with no splice.
        let (mut client2, server2) = tokio::io::duplex(1024);
        let gate2 = EgressGate::from_network_policy(
            &NetworkPolicy::unrestricted(),
            &mvm_core::policy::dns_pin::DnsPinRegistry::new(),
            "2026-01-01T00:00:00Z",
        );
        let h2 = tokio::spawn(async move {
            handle_raw_conn(
                server2,
                &gate2,
                None,
                Arc::new(egress_rate::EgressRateGuard::default()),
                Duration::from_secs(1),
            )
            .await
        });
        client2.write_all(b"not-an-address\n").await.unwrap();
        let mut ack2 = [0u8; 1];
        client2.read_exact(&mut ack2).await.unwrap();
        assert_eq!(ack2[0], ConnectAck::Fail.as_byte());
        let mut sink2 = Vec::new();
        let n2 = client2.read_to_end(&mut sink2).await.unwrap();
        assert_eq!(n2, 0, "malformed target must not splice");
        h2.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn dns_marker_dispatches_to_policy_gated_handler() {
        let gate = EgressGate::default_deny();
        let (mut client, server) = tokio::io::duplex(4096);
        let handler = tokio::spawn(async move {
            handle_raw_conn(
                server,
                &gate,
                None,
                Arc::new(egress_rate::EgressRateGuard::default()),
                Duration::from_secs(1),
            )
            .await
        });
        let query = [
            0x22, 0x22, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x07, b'b', b'l', b'o', b'c',
            b'k', b'e', b'd', 0x04, b't', b'e', b's', b't', 0, 0, 1, 0, 1,
        ];
        client
            .write_all(format!("{}\n", dns_handler::FRAME_LINE).as_bytes())
            .await
            .unwrap();
        client
            .write_all(
                &u16::try_from(query.len())
                    .expect("test query length fits in u16")
                    .to_be_bytes(),
            )
            .await
            .unwrap();
        client.write_all(&query).await.unwrap();

        let mut length = [0_u8; 2];
        client.read_exact(&mut length).await.unwrap();
        let mut response = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response[..2], &[0x22, 0x22]);
        assert_eq!(response[3] & 0x0f, 5);
        handler.await.unwrap().unwrap();
    }

    /// Drive the `splice` helper directly (bypassing the gate, which mandatory-
    /// denies loopback) against a loopback echo server: `"ping"` on the guest side
    /// echoes back, and pipelined `leftover` bytes reach upstream first.
    #[tokio::test]
    async fn splice_proxies_both_directions() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Echo server: read all, echo verbatim, until the peer half-closes.
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                sock.write_all(&buf[..n]).await.unwrap();
            }
        });

        let (mut client, guest) = tokio::io::duplex(1024);
        // `leftover` = bytes pipelined after the `\n`; they must reach upstream first.
        let splicer = tokio::spawn(async move {
            let target = format!("{}:{}", addr.ip(), addr.port());
            let ips = vec![addr.ip()];
            splice(
                guest,
                &target,
                &ips,
                addr.port(),
                b"lead".to_vec(),
                Duration::from_secs(2),
            )
            .await
        });

        let mut ack = [0u8; 1];
        client.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack[0], ConnectAck::Ok.as_byte());

        // The leftover "lead" is echoed back first, then our live "ping".
        client.write_all(b"ping").await.unwrap();
        let mut got = Vec::new();
        // Read until we've seen both the leftover and the live bytes.
        while got.len() < b"leadping".len() {
            let mut chunk = [0u8; 64];
            let n = client.read(&mut chunk).await.unwrap();
            assert!(n > 0, "splice closed before echoing all bytes");
            got.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(&got, b"leadping");

        // Half-close the guest so the echo server + splice wind down.
        client.shutdown().await.ok();
        drop(client);
        splicer.await.unwrap().unwrap();
        server.await.unwrap();
    }

    /// The ack precedes any tunnel bytes: `splice` writes `ConnectAck::Ok` right
    /// after the upstream connect succeeds and before relaying anything.
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
            let ips = vec![addr.ip()];
            splice(
                guest,
                "echo",
                &ips,
                addr.port(),
                Vec::new(),
                Duration::from_secs(2),
            )
            .await
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

    /// Happy-eyeballs fallover: an unreachable admitted address (e.g. an AAAA
    /// with no host IPv6 route) must not strand the connect — it falls over to
    /// the next admitted address instead.
    #[tokio::test]
    async fn connect_first_admitted_skips_unreachable_then_uses_reachable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        // TEST-NET-1 (RFC 5737) is not routable — packets sent to it are
        // silently dropped rather than rejected, so the connect consumes its
        // full `PER_IP_CONNECT_TIMEOUT` budget before falling over. The overall
        // timeout here must exceed that per-IP budget, leaving room for the
        // fallover attempt against the reachable loopback address.
        //
        // This one keeps the public address on purpose: the branch under test
        // is fallover after a *timeout*, which needs an address that blackholes
        // rather than refuses, and nothing loopback-local can produce that
        // portably. The cost is a real dependency on the ambient network
        // dropping TEST-NET-1 — behind a captive portal or an intercepting
        // resolver the first connect succeeds and this passes without
        // exercising fallover at all. The refused-fallover branch is covered
        // deterministically by `..._falls_over_from_unreachable_ipv6_to_ipv4`,
        // so a silent pass here does not leave fallover wholly unwitnessed.
        let unreachable: IpAddr = "192.0.2.1".parse().unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();

        let stream =
            connect_first_admitted(&[unreachable, loopback], port, Duration::from_secs(5)).await;
        assert!(stream.is_some(), "must fall over to the reachable address");
        accept.await.unwrap();
    }

    /// The issue's shape exactly: the first admitted address is an unreachable
    /// IPv6 (the guest resolved a dual-stack host to its AAAA and the host has
    /// no IPv6 egress) and the connect must fall over to the pinned IPv4.
    #[tokio::test]
    async fn connect_first_admitted_falls_over_from_unreachable_ipv6_to_ipv4() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        // `::1` on the same port, where only the IPv4 socket is listening, so
        // the v6 attempt is refused immediately and the fallover is genuinely
        // exercised. The previous fixture used 2001:db8::1 (RFC 3849
        // documentation range) and relied on the ambient network never routing
        // it. That is fragile in both directions: on a network that answers,
        // the v6 connect succeeds, `stream.is_some()` still holds, and the test
        // passes without ever testing fallover; on one that blackholes it, the
        // attempt burns its share of the 5s budget.
        let unreachable_v6: IpAddr = "::1".parse().unwrap();
        let loopback_v4: IpAddr = "127.0.0.1".parse().unwrap();

        let stream =
            connect_first_admitted(&[unreachable_v6, loopback_v4], port, Duration::from_secs(5))
                .await;
        assert!(
            stream.is_some(),
            "must fall over from the unreachable IPv6 to the IPv4 pin"
        );
        accept.await.unwrap();
    }

    /// When every admitted address is unreachable, `splice` nacks the guest and
    /// closes without ever tunneling bytes.
    #[tokio::test]
    async fn splice_sends_fail_ack_when_no_admitted_ip_is_reachable() {
        let (mut client, guest) = tokio::io::duplex(1024);

        // A closed loopback port, not a blackholed public address. The
        // previous fixture used 192.0.2.1 (RFC 5737 TEST-NET-1) and relied on
        // the ambient network dropping it so the connect would time out. That
        // is an assumption about whoever's network the suite happens to run
        // on: behind a captive portal or an intercepting resolver something
        // answers, the connect succeeds, and the test fails claiming the host
        // reached an unreachable address. Binding a port and dropping the
        // listener gives ECONNREFUSED on every platform and every network,
        // and returns immediately instead of burning the timeout.
        let closed_port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
            probe.local_addr().expect("probe addr").port()
        };
        let ips = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
        let splicer = tokio::spawn(async move {
            splice(
                guest,
                "unreachable",
                &ips,
                closed_port,
                Vec::new(),
                Duration::from_secs(1),
            )
            .await
        });

        let mut ack = [0u8; 1];
        client.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack[0], ConnectAck::Fail.as_byte());

        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        splicer.await.unwrap().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn raw_vsock_handlers_run_concurrently() {
        let (mut first_client, first_server) = UnixStream::pair().unwrap();
        let (mut second_client, second_server) = UnixStream::pair().unwrap();
        let gate = Arc::new(EgressGate::default_deny());
        let rate_guard = Arc::new(egress_rate::EgressRateGuard::default());

        let first = spawn_raw_egress_connection(
            first_server.into_raw_fd(),
            Arc::clone(&gate),
            None,
            Arc::clone(&rate_guard),
            Duration::from_secs(1),
        )
        .unwrap();
        let second = spawn_raw_egress_connection(
            second_server.into_raw_fd(),
            gate,
            None,
            rate_guard,
            Duration::from_secs(1),
        )
        .unwrap();

        // Keep the first handler blocked reading its target line. The second
        // handler must still run and reject its target instead of waiting for
        // the first connection to finish.
        first_client.write_all(b"blocked").unwrap();
        second_client.write_all(b"example.com:443\n").unwrap();
        let mut ack = [0_u8; 1];
        second_client.read_exact(&mut ack).unwrap();
        assert_eq!(ack[0], ConnectAck::Fail.as_byte());

        drop(first_client);
        first.join().unwrap();
        second.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn load_upstreams_from_resolv_conf_parses_nameservers() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("resolv.conf");
        std::fs::write(
            &path,
            "\
# comment
nameserver 1.1.1.1
options edns0 trust-ad
nameserver 2606:4700:4700::1111
",
        )
        .unwrap();

        let upstreams = load_upstreams_from_resolv_conf(path.to_str().unwrap()).unwrap();
        assert_eq!(
            upstreams,
            vec![
                "1.1.1.1:53".parse().unwrap(),
                "[2606:4700:4700::1111]:53".parse().unwrap(),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_dns_response_extracts_ip_answers() {
        let request =
            decode_dns_message(&build_dns_query("cache.nixos.org", RecordType::A).unwrap())
                .unwrap();

        let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
        response.add_query(Query::query(
            Name::from_ascii("cache.nixos.org").unwrap(),
            RecordType::A,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("cache.nixos.org").unwrap(),
            30,
            RData::A(A(Ipv4Addr::new(151, 101, 1, 91))),
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("cache.nixos.org").unwrap(),
            30,
            RData::AAAA(AAAA(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111))),
        ));

        let encoded = encode_dns_message(response).unwrap();
        let a_records = parse_dns_response(&request, &encoded, RecordType::A).unwrap();
        let aaaa_records = parse_dns_response(&request, &encoded, RecordType::AAAA).unwrap();

        assert_eq!(a_records, vec!["151.101.1.91".parse::<IpAddr>().unwrap()]);
        assert_eq!(
            aaaa_records,
            vec!["2606:4700::1111".parse::<IpAddr>().unwrap()]
        );
    }
}
