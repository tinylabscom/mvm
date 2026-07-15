//! Host-side vsock egress server  for the external-VMM (libkrun) path.
//!
//! The in-guest `mvm-egress-client` dials the host egress vsock port and writes the
//! connect target as a newline-terminated `"host:port\n"` first line, then streams
//! bytes. libkrun forwards that guest vsock stream to a host-bound UDS
//! (`add_host_listen_port`). This server terminates that UDS: it reads the target
//! line, decides it against the claim-10 [`EgressGate`] (the same decision HVF's
//! hvf gateway makes), and on admit pumps bytes both ways to a fresh host TCP
//! connection. A refused target never reaches the network.
//!
//! Unlike the hvf VMM's poll-based egress relay (single-threaded run loop),
//! this is an async per-connection pump — the natural shape for the supervisor's
//! tokio runtime. The *decision* (`EgressGate`) is the shared core; the pump is
//! per-VMM.
//!
//! Why a newline delimiter: the UDS is a raw byte stream with no packet boundary
//! (unlike vsock on the hvf VMM), so the target needs an explicit terminator.
//! `BufReader` absorbs any workload bytes that arrive in the same read after the
//! newline and replays them into the proxy, so none are lost.

use std::future::Future;
use std::net::SocketAddr;

use mvm_runtime::vmm::egress_gate::{EgressGate, EgressVerdict};
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
pub async fn serve<S, C, Fut, U>(
    client: S,
    gate: &EgressGate,
    mut connect: C,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = std::io::Result<U>>,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(client);

    // First line = the connect target, newline-terminated.
    let mut line = Vec::new();
    let n = read_target_line(&mut reader, &mut line).await?;
    if n == 0 {
        return Ok(()); // EOF before a target — nothing to do
    }
    let target = String::from_utf8_lossy(&line).trim().to_string();

    match gate.admitted_addrs(&target) {
        Ok(addrs) => {
            let mut last_error = None;
            let mut upstream = None;
            for addr in addrs {
                match connect(addr).await {
                    Ok(stream) => {
                        upstream = Some(stream);
                        break;
                    }
                    Err(err) => {
                        tracing::warn!(%target, %addr, error = %err, "egress connect failed");
                        last_error = Some(err);
                    }
                }
            }
            let Some(mut upstream) = upstream else {
                if let Some(err) = last_error {
                    tracing::warn!(%target, error = %err, "egress connect exhausted admitted addresses");
                }
                return Ok(());
            };
            // BufReader replays any workload bytes buffered after the newline.
            match tokio::io::copy_bidirectional(&mut reader, &mut upstream).await {
                Ok((guest_to_upstream, upstream_to_guest)) => {
                    tracing::debug!(
                        %target,
                        guest_to_upstream,
                        upstream_to_guest,
                        "egress splice completed"
                    );
                    Ok(())
                }
                Err(err) => Err(err),
            }
        }
        Err(EgressVerdict::Deny) | Err(EgressVerdict::Malformed) => {
            tracing::warn!(%target, "egress refused (claim-10)");
            Ok(()) // drop the connection; never dial
        }
        Err(EgressVerdict::Allow { .. }) => Ok(()),
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

/// Phase A guard: serve transparent-TCP vsock egress only when the host opted in,
/// the workload carries NO bound secrets (else the substitution endpoint owns
/// `EGRESS_PORT`), and `EGRESS_PORT` is actually forwarded. All three required —
/// fail closed on any missing.
pub fn should_serve_vsock_egress(
    host_listen_ports: &[u32],
    opt_in: bool,
    has_bound_secrets: bool,
) -> bool {
    opt_in && !has_bound_secrets && host_listen_ports.contains(&mvm_guest::vsock::EGRESS_PORT)
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
            let connect = |addr: SocketAddr| async move { TcpStream::connect(addr).await };
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
            serve(server, &gate, move |_addr| async move {
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
        serve::<_, _, _, tokio::io::DuplexStream>(server, &gate, |_addr| async move {
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
        serve::<_, _, _, tokio::io::DuplexStream>(server, &gate, |_addr| async move {
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
        serve::<_, _, _, tokio::io::DuplexStream>(server, &gate, |_addr| async move {
            panic!("no target → no dial");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn admitted_hostname_retries_later_permitted_address() {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "multi.example.test",
            vec![
                "192.0.2.10".parse().unwrap(),
                "198.51.100.20".parse().unwrap(),
            ],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let gate = EgressGate::from_network_policy(
            &NetworkPolicy::allow_list(vec![HostPort {
                host: "multi.example.test".into(),
                port: 443,
            }]),
            &pins,
            "2026-01-01T00:00:00Z",
        );

        let (mut client, server) = tokio::io::duplex(256);
        client
            .write_all(b"multi.example.test:443\nping")
            .await
            .unwrap();

        let task = tokio::spawn(async move {
            serve(server, &gate, move |addr| async move {
                if addr.ip().to_string() == "192.0.2.10" {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "synthetic first-address timeout",
                    ))
                } else {
                    let (mut upstream, remote) = tokio::io::duplex(256);
                    tokio::spawn(async move {
                        let (mut r, mut w) = tokio::io::split(remote);
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                    upstream.write_all(&[]).await?;
                    Ok(upstream)
                }
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

    #[test]
    fn serves_only_when_opted_in_no_secrets_and_port_present() {
        let egress = mvm_guest::vsock::EGRESS_PORT;
        // Happy path: opted in, no secrets, port listed.
        assert!(should_serve_vsock_egress(&[egress], true, false));
        // Any single disqualifier fails closed.
        assert!(!should_serve_vsock_egress(&[egress], false, false)); // not opted in
        assert!(!should_serve_vsock_egress(&[egress], true, true)); // has secrets
        assert!(!should_serve_vsock_egress(&[], true, false)); // port absent
    }
}
