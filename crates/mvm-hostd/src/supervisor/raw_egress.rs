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
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use mvm_backend::vmm::egress_gate::{EgressGate, EgressVerdict};

/// Cap on the first `host:port` line. A guest that never sends a `\n` inside this
/// many bytes is refused (fail closed) rather than read unbounded.
const MAX_TARGET_LINE: usize = 256;

/// Serve raw-TCP egress over a bound UDS listener: one tokio task per guest
/// connection, each gated then spliced. Runs until the listener errors.
pub async fn serve_raw_egress(
    listener: tokio::net::UnixListener,
    gate: Arc<EgressGate>,
    timeout: Duration,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let gate = Arc::clone(&gate);
                tokio::spawn(async move {
                    if let Err(e) = handle_raw_conn(stream, &gate, timeout).await {
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
    timeout: Duration,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some((target, leftover)) = read_target_line(&mut guest).await? else {
        // No `\n` within the cap → fail closed, close without connecting.
        return Ok(());
    };
    match gate.decide_request(&target) {
        EgressVerdict::Allow { ip, port } => splice(guest, ip, port, leftover, timeout).await,
        EgressVerdict::Deny | EgressVerdict::Malformed => {
            // Refused: close without ever opening a host socket.
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

/// Connect to an admitted `(ip, port)` and splice bytes both ways until either
/// side EOFs. `leftover` bytes (pipelined after the target line's `\n`) are
/// forwarded upstream before the bidirectional copy so nothing is dropped.
///
/// Split out from the gate decision so it's unit-testable against a loopback echo
/// server without routing through the real gate (which mandatory-denies loopback).
async fn splice<S>(
    mut guest: S,
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
        // Connect error or timeout → close the guest side, no splice.
        Ok(Err(_)) | Err(_) => return Ok(()),
    };
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await?;
    }
    // EOF on either side ends the copy; a reset surfaces as an error we swallow so
    // one torn-down connection never crashes the accept loop.
    let _ = tokio::io::copy_bidirectional(&mut guest, &mut upstream).await;
    Ok(())
}

/// Serve raw-TCP egress over a host **AF_VSOCK** listener — the QEMU path,
/// mirroring how `SubstitutionService::serve_vsock` structures its accept loop.
/// The in-house VMM relay uses the UDS path above; this is the thin vsock sibling
/// for backends that route guest→host over `vhost-vsock`.
///
/// Both `accept(2)` and the per-connection target-read + splice run with blocking
/// I/O on `spawn_blocking` threads (tokio's async reactor doesn't interplay
/// reliably with an AF_VSOCK fd). The connect + upstream splice reuse the same
/// gate decision as the UDS path.
#[cfg(target_os = "linux")]
pub async fn serve_raw_egress_vsock(
    listener: crate::supervisor::substitution_proxy::vsock::VsockListener,
    gate: Arc<EgressGate>,
    timeout: Duration,
) {
    use crate::supervisor::substitution_proxy::vsock;
    loop {
        let listen_fd = listener.raw_fd();
        let accepted = tokio::task::spawn_blocking(move || vsock::accept(listen_fd)).await;
        let conn_fd = match accepted {
            Ok(Ok(fd)) => fd,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "raw egress vsock accept failed; stopping");
                return;
            }
            Err(e) => {
                tracing::warn!(error = %e, "raw egress vsock accept task panicked; stopping");
                return;
            }
        };
        let gate = Arc::clone(&gate);
        tokio::task::spawn_blocking(move || {
            if let Err(e) = handle_raw_conn_blocking(conn_fd, &gate, timeout) {
                tracing::warn!(error = %e, "raw egress vsock connection failed");
            }
        });
    }
}

/// Blocking sibling of [`handle_raw_conn`] for the AF_VSOCK fd: read the target
/// line, gate it, and (only on `Allow`) connect + splice with blocking std I/O.
/// The accepted fd is adopted so it closes on drop.
#[cfg(target_os = "linux")]
fn handle_raw_conn_blocking(
    conn_fd: std::os::fd::RawFd,
    gate: &EgressGate,
    timeout: Duration,
) -> std::io::Result<()> {
    use std::os::fd::{FromRawFd, OwnedFd};

    // Adopt the fd; a File over a socket fd gives blocking Read+Write, pumped
    // below via `std::io::copy` (no trait import needed at this scope).
    let owned = unsafe { OwnedFd::from_raw_fd(conn_fd) };
    let mut guest = std::fs::File::from(owned);

    let Some(target) = read_target_line_blocking(&mut guest)? else {
        return Ok(()); // no newline within the cap → fail closed
    };
    let (ip, port) = match gate.decide_request(&target) {
        EgressVerdict::Allow { ip, port } => (ip, port),
        EgressVerdict::Deny | EgressVerdict::Malformed => return Ok(()), // fail closed
    };
    let mut upstream =
        match std::net::TcpStream::connect_timeout(&std::net::SocketAddr::new(ip, port), timeout) {
            Ok(s) => s,
            Err(_) => return Ok(()), // connect error → close, no splice
        };
    // Bidirectional blocking pump: guest→upstream on this thread, upstream→guest
    // on a helper thread, each ending on the peer's EOF.
    let mut up_read = upstream.try_clone()?;
    let mut guest_write = guest.try_clone()?;
    let pump_back = std::thread::spawn(move || {
        let _ = std::io::copy(&mut up_read, &mut guest_write);
    });
    let _ = std::io::copy(&mut guest, &mut upstream);
    // Shut the write half so the helper's copy sees EOF and winds down.
    let _ = upstream.shutdown(std::net::Shutdown::Write);
    let _ = pump_back.join();
    Ok(())
}

/// Blocking read of the first `host:port` line, bounded at [`MAX_TARGET_LINE`].
/// `None` ⇒ EOF or the cap was hit with no newline (fail closed).
#[cfg(target_os = "linux")]
fn read_target_line_blocking<R: std::io::Read>(r: &mut R) -> std::io::Result<Option<String>> {
    let mut buf = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = r.read(&mut byte)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::network_policy::NetworkPolicy;
    use tokio::io::AsyncWriteExt;

    /// A default-deny gate + a well-formed target ⇒ the connection is closed and
    /// NO upstream connect happens (fail closed). We prove no connect by pointing
    /// the target at a port nothing listens on and asserting the guest side simply
    /// sees EOF quickly rather than a splice.
    #[tokio::test]
    async fn denied_target_closes_without_connecting() {
        let gate = EgressGate::default_deny();
        let (mut client, server) = tokio::io::duplex(1024);
        let h =
            tokio::spawn(
                async move { handle_raw_conn(server, &gate, Duration::from_secs(1)).await },
            );
        client.write_all(b"93.184.216.34:80\n").await.unwrap();
        // Denied ⇒ handler returns without connecting; the server half is dropped,
        // so the client read hits EOF.
        let mut sink = Vec::new();
        let n = client.read_to_end(&mut sink).await.unwrap();
        assert_eq!(n, 0, "denied target must not splice any bytes back");
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
        let h =
            tokio::spawn(
                async move { handle_raw_conn(server, &gate, Duration::from_secs(1)).await },
            );
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
        let h2 =
            tokio::spawn(
                async move { handle_raw_conn(server2, &gate2, Duration::from_secs(1)).await },
            );
        client2.write_all(b"not-an-address\n").await.unwrap();
        let mut sink2 = Vec::new();
        let n2 = client2.read_to_end(&mut sink2).await.unwrap();
        assert_eq!(n2, 0, "malformed target must not splice");
        h2.await.unwrap().unwrap();
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
            splice(
                guest,
                addr.ip(),
                addr.port(),
                b"lead".to_vec(),
                Duration::from_secs(2),
            )
            .await
        });

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
}
