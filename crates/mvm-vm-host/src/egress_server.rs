//! Host-side vsock egress server  for the external-VMM (libkrun) path.
//!
//! The in-guest `mvm-egress-client` dials the host egress vsock port and writes the
//! connect target as a newline-terminated `"host:port\n"` first line, then streams
//! bytes. libkrun forwards that guest vsock stream to a host-bound UDS
//! (`add_host_listen_port`). This server terminates that UDS: it reads the target
//! line, decides it against the claim-10 [`EgressGate`] (the same decision HVF's
//! in-house gateway makes), and on admit pumps bytes both ways to a fresh host TCP
//! connection. A refused target never reaches the network.
//!
//! Unlike the in-house VMM's poll-based egress relay (single-threaded run loop),
//! this is an async per-connection pump — the natural shape for the supervisor's
//! tokio runtime. The *decision* (`EgressGate`) is the shared core; the pump is
//! per-VMM.
//!
//! Why a newline delimiter: the UDS is a raw byte stream with no packet boundary
//! (unlike vsock on the in-house VMM), so the target needs an explicit terminator.
//! `BufReader` absorbs any workload bytes that arrive in the same read after the
//! newline and replays them into the proxy, so none are lost.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};

use mvm_backend::vmm::egress_gate::{EgressGate, EgressVerdict};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader};
use tokio::net::{TcpStream, UnixListener};

/// Cap on the target line so a malicious guest can't grow it unbounded before we
/// decide. Real targets (`"<host>:<port>\n"`) are well under this.
const MAX_TARGET_LINE: usize = 512;

/// Serve one accepted egress connection: read the `"host:port\n"` target, decide it
/// against `gate`, and on admit proxy bytes both ways to a host TCP connection
/// opened via `connect`. `connect` is injected so the decision + pump are testable
/// without a real outbound connection. A refused/malformed target closes the
/// connection without dialing.
pub async fn serve<S, C, Fut>(client: S, gate: &EgressGate, connect: C) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: FnOnce(IpAddr, u16) -> Fut,
    Fut: Future<Output = std::io::Result<TcpStream>>,
{
    let mut reader = BufReader::new(client);

    // First line = the connect target, newline-terminated.
    let mut line = Vec::new();
    let n = read_target_line(&mut reader, &mut line).await?;
    if n == 0 {
        return Ok(()); // EOF before a target — nothing to do
    }
    let target = String::from_utf8_lossy(&line).trim().to_string();

    match gate.decide_request(&target) {
        EgressVerdict::Allow { ip, port } => {
            let mut upstream = connect(ip, port).await?;
            // BufReader replays any workload bytes buffered after the newline.
            tokio::io::copy_bidirectional(&mut reader, &mut upstream)
                .await
                .map(|_| ())
        }
        EgressVerdict::Deny | EgressVerdict::Malformed => {
            tracing::warn!(%target, "egress refused (claim-10)");
            Ok(()) // drop the connection; never dial
        }
    }
}

/// Read up to and including the first `\n` (or [`MAX_TARGET_LINE`] bytes) into
/// `out`, returning the byte count. Bounded so an unterminated flood can't grow
/// memory without limit; bytes after the `\n` stay buffered for the proxy pump.
async fn read_target_line<R>(reader: &mut R, out: &mut Vec<u8>) -> std::io::Result<usize>
where
    R: AsyncReadExt + Unpin,
{
    for _ in 0..MAX_TARGET_LINE {
        match reader.read_u8().await {
            Ok(b) => {
                out.push(b);
                if b == b'\n' {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    Ok(out.len())
}

/// Accept egress connections on `listener` (the host-bound UDS libkrun forwards the
/// guest egress vsock stream to) and serve each against `gate`, dialing real host
/// TCP connections. Runs until the listener errors.
pub async fn run(listener: UnixListener, gate: EgressGate) -> std::io::Result<()> {
    let gate = std::sync::Arc::new(gate);
    loop {
        let (stream, _) = listener.accept().await?;
        let gate = gate.clone();
        tokio::spawn(async move {
            let connect = |ip: IpAddr, port: u16| async move {
                TcpStream::connect(SocketAddr::new(ip, port)).await
            };
            if let Err(e) = serve(stream, &gate, connect).await {
                tracing::warn!(error = %e, "egress server connection failed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::projection::{CanonicalEgress, CanonicalRule, Proto};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn allow(cidr: &str, port: u16) -> EgressGate {
        EgressGate::new(CanonicalEgress::Rules(vec![CanonicalRule {
            proto: Proto::Tcp,
            net: cidr.parse().unwrap(),
            port_lo: port,
            port_hi: port,
        }]))
    }

    /// Full admit path: parse the target line, gate admits a (non-mandatory-deny)
    /// public IP, the injected connector returns a loopback echo, and bytes proxy
    /// both ways — including workload bytes that arrived in the same read as the
    /// target line.
    #[tokio::test]
    async fn admitted_target_proxies_both_directions() {
        // Loopback echo the injected connector hands back (the gate never sees it).
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(&buf[..n]).await.unwrap();
        });

        let (mut client, server) = tokio::io::duplex(256);
        // Target line + a workload byte chunk in the SAME write (tests BufReader
        // replay of post-newline bytes).
        client.write_all(b"93.184.216.34:80\nping").await.unwrap();

        let gate = allow("93.184.216.34/32", 80);
        let task = tokio::spawn(async move {
            serve(server, &gate, move |_ip, _port| async move {
                TcpStream::connect(echo_addr).await
            })
            .await
            .unwrap();
        });

        let mut got = [0u8; 4];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        drop(client);
        task.await.unwrap();
    }

    /// A denied target is never dialed: the connector panics if called, and serve
    /// still returns cleanly (the connection is dropped).
    #[tokio::test]
    async fn denied_target_never_dials() {
        let (mut client, server) = tokio::io::duplex(256);
        client.write_all(b"1.1.1.1:443\n").await.unwrap();
        drop(client);

        let gate = EgressGate::default_deny();
        serve(server, &gate, |_ip, _port| async move {
            panic!("denied target must not dial");
        })
        .await
        .unwrap();
    }

    /// A target with no policy that parses but isn't admitted (wrong port) is
    /// refused, not dialed.
    #[tokio::test]
    async fn wrong_port_is_refused() {
        let (mut client, server) = tokio::io::duplex(256);
        client.write_all(b"93.184.216.34:8080\n").await.unwrap();
        drop(client);

        let gate = allow("93.184.216.34/32", 80); // only:80 admitted
        serve(server, &gate, |_ip, _port| async move {
            panic!("non-admitted port must not dial");
        })
        .await
        .unwrap();
    }

    /// EOF before any target line is a clean no-op.
    #[tokio::test]
    async fn eof_before_target_is_noop() {
        let (client, server) = tokio::io::duplex(8);
        drop(client);
        let gate = EgressGate::default_deny();
        serve(server, &gate, |_ip, _port| async move {
            panic!("no target → no dial");
        })
        .await
        .unwrap();
    }
}
