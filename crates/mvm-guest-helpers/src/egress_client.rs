//! In-guest SOCKS5 → vsock egress client (ADR-100).
//!
//! A NIC-less workload reaches the network only through the host vsock egress
//! gateway. This is the guest-side translator: a SOCKS5 (no-auth, CONNECT) proxy on
//! loopback. Per connection it learns the target from the SOCKS handshake, opens an
//! AF_VSOCK stream to the host egress port, sends the target as the first frame (the
//! `"host:port"` the host `EgressProxy` expects), then pumps bytes both ways. The
//! workload keeps ordinary `connect()` semantics via the standard proxy env
//! (`ALL_PROXY=socks5h://127.0.0.1:<port>`); loopback works without a NIC.
//!
//! The host gateway makes the claim-10 decision — this client never does. A target
//! the host refuses tears down the vsock stream, which closes the SOCKS connection.

#![warn(missing_docs)]

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::addon_vsock_bridge::connect_host_vsock;

/// Host vsock port of the egress gateway.
///
/// Must match `mvm_guest::vsock::SUBSTITUTION_PORT`. mvm-guest is not a dep of this
/// crate (see `mvm-exit-report`) — keep in sync manually.
pub const EGRESS_VSOCK_PORT: u32 = 5253;

/// SOCKS protocol version 5.
const SOCKS5: u8 = 0x05;
/// SOCKS5 "no authentication required" method.
const METHOD_NO_AUTH: u8 = 0x00;
/// SOCKS5 "no acceptable methods".
const METHOD_NONE: u8 = 0xFF;
/// SOCKS5 CONNECT command.
const CMD_CONNECT: u8 = 0x01;
/// Address types.
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
/// Reply codes.
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

/// Pick the no-auth method from a client's advertised list (RFC 1928 §3).
fn select_method(methods: &[u8]) -> u8 {
    if methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        METHOD_NONE
    }
}

/// Format a SOCKS5 request address into the `"host:port"` string the host egress
/// gateway expects. IPv6 is bracketed. Domains pass through verbatim (the host
/// resolves + decides; until host-side DNS-over-vsock lands, a domain target is
/// refused there as non-numeric — that is the honest failure, not a silent one).
fn format_target(atyp: u8, addr: &[u8], port: u16) -> std::io::Result<String> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
    match atyp {
        ATYP_IPV4 => {
            let o: [u8; 4] = addr.try_into().map_err(|_| bad("socks: short ipv4"))?;
            Ok(format!("{}.{}.{}.{}:{port}", o[0], o[1], o[2], o[3]))
        }
        ATYP_IPV6 => {
            let o: [u8; 16] = addr.try_into().map_err(|_| bad("socks: short ipv6"))?;
            Ok(format!("[{}]:{port}", std::net::Ipv6Addr::from(o)))
        }
        ATYP_DOMAIN => {
            let host = std::str::from_utf8(addr).map_err(|_| bad("socks: domain not utf-8"))?;
            Ok(format!("{host}:{port}"))
        }
        _ => Err(bad("socks: unknown address type")),
    }
}

/// Run the SOCKS5 greeting + CONNECT request on `stream`, returning the requested
/// target as `"host:port"`. Leaves `stream` positioned for the reply (see
/// [`reply`]). Errors on a non-SOCKS5 greeting, an unsupported command, or a
/// malformed request — the caller closes the connection.
pub async fn negotiate<S>(stream: &mut S) -> std::io::Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let invalid = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());

    // Greeting: VER, NMETHODS, METHODS...
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != SOCKS5 {
        return Err(invalid("socks: not version 5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;
    let method = select_method(&methods);
    stream.write_all(&[SOCKS5, method]).await?;
    stream.flush().await?;
    if method == METHOD_NONE {
        return Err(invalid("socks: no acceptable auth method"));
    }

    // Request: VER, CMD, RSV, ATYP, ADDR..., PORT(2).
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != SOCKS5 {
        return Err(invalid("socks: request not version 5"));
    }
    if req[1] != CMD_CONNECT {
        // Reply "command not supported" before closing.
        let _ = reply(stream, REP_CMD_NOT_SUPPORTED).await;
        return Err(invalid("socks: only CONNECT is supported"));
    }
    let atyp = req[3];
    let addr = match atyp {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            a.to_vec()
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            a.to_vec()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut a = vec![0u8; len[0] as usize];
            stream.read_exact(&mut a).await?;
            a
        }
        _ => return Err(invalid("socks: unknown address type")),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    format_target(atyp, &addr, u16::from_be_bytes(port))
}

/// Send a SOCKS5 reply with code `rep` and a zero bind address (RFC 1928 §6).
pub async fn reply<S>(stream: &mut S, rep: u8) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // VER, REP, RSV, ATYP=ipv4, BND.ADDR=0.0.0.0, BND.PORT=0.
    stream
        .write_all(&[SOCKS5, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    stream.flush().await
}

/// Serve one accepted SOCKS client: negotiate the target, open the host egress
/// stream, frame the target, then proxy bytes both ways.
async fn serve(mut client: TcpStream) -> std::io::Result<()> {
    let target = negotiate(&mut client).await?;
    let mut upstream = match connect_host_vsock(EGRESS_VSOCK_PORT).await {
        Ok(u) => u,
        Err(e) => {
            let _ = reply(&mut client, REP_GENERAL_FAILURE).await;
            return Err(e);
        }
    };
    // First frame on the egress stream = the connect target (the host decides).
    upstream.write_all(target.as_bytes()).await?;
    upstream.flush().await?;
    reply(&mut client, REP_SUCCESS).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map(|_| ())
}

/// Bind the loopback SOCKS5 listener at `listen` and serve egress indefinitely.
pub async fn run(listen: std::net::SocketAddr) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(%listen, vsock_port = EGRESS_VSOCK_PORT, "egress SOCKS5 client started");
    loop {
        match listener.accept().await {
            Ok((client, peer)) => {
                tracing::debug!(%peer, "accepted egress client connection");
                tokio::spawn(async move {
                    if let Err(e) = serve(client).await {
                        tracing::warn!(error = %e, "egress client connection failed");
                    }
                });
            }
            Err(e) => tracing::warn!(error = %e, "egress client accept failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_method_prefers_no_auth() {
        assert_eq!(select_method(&[0x00, 0x01, 0x02]), METHOD_NO_AUTH);
        assert_eq!(select_method(&[0x02]), METHOD_NONE);
        assert_eq!(select_method(&[]), METHOD_NONE);
    }

    #[test]
    fn format_target_ipv4() {
        assert_eq!(
            format_target(ATYP_IPV4, &[93, 184, 216, 34], 80).unwrap(),
            "93.184.216.34:80"
        );
    }

    #[test]
    fn format_target_ipv6_is_bracketed() {
        let mut a = [0u8; 16];
        a[15] = 1; // ::1
        assert_eq!(format_target(ATYP_IPV6, &a, 443).unwrap(), "[::1]:443");
    }

    #[test]
    fn format_target_domain_passes_through() {
        assert_eq!(
            format_target(ATYP_DOMAIN, b"example.com", 443).unwrap(),
            "example.com:443"
        );
    }

    #[test]
    fn format_target_rejects_unknown_atyp_and_short_addr() {
        assert!(format_target(0x09, &[1, 2, 3, 4], 80).is_err());
        assert!(format_target(ATYP_IPV4, &[1, 2], 80).is_err());
    }

    /// Drive a full SOCKS5 IPv4 CONNECT handshake over an in-memory duplex and
    /// assert the negotiated target + that the method-select and success replies
    /// are well-formed.
    #[tokio::test]
    async fn negotiate_parses_ipv4_connect() {
        let (mut client, mut server) = tokio::io::duplex(256);

        let driver = tokio::spawn(async move {
            // Greeting: v5, 1 method, no-auth.
            client
                .write_all(&[SOCKS5, 1, METHOD_NO_AUTH])
                .await
                .unwrap();
            // Method selection reply.
            let mut sel = [0u8; 2];
            client.read_exact(&mut sel).await.unwrap();
            assert_eq!(sel, [SOCKS5, METHOD_NO_AUTH]);
            // CONNECT 1.2.3.4:443.
            client
                .write_all(&[SOCKS5, CMD_CONNECT, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0x01, 0xBB])
                .await
                .unwrap();
            client
        });

        let target = negotiate(&mut server).await.unwrap();
        assert_eq!(target, "1.2.3.4:443");

        // The success reply is a well-formed SOCKS5 reply.
        reply(&mut server, REP_SUCCESS).await.unwrap();
        let mut client = driver.await.unwrap();
        let mut buf = [0u8; 10];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], SOCKS5);
        assert_eq!(buf[1], REP_SUCCESS);
        assert_eq!(buf[3], ATYP_IPV4);
    }

    /// A non-CONNECT command is refused with REP_CMD_NOT_SUPPORTED.
    #[tokio::test]
    async fn negotiate_refuses_non_connect() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let driver = tokio::spawn(async move {
            client
                .write_all(&[SOCKS5, 1, METHOD_NO_AUTH])
                .await
                .unwrap();
            let mut sel = [0u8; 2];
            client.read_exact(&mut sel).await.unwrap();
            // CMD = 0x02 (BIND), not CONNECT.
            client
                .write_all(&[SOCKS5, 0x02, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0, 80])
                .await
                .unwrap();
            client
        });
        assert!(negotiate(&mut server).await.is_err());
        let mut client = driver.await.unwrap();
        let mut buf = [0u8; 10];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[1], REP_CMD_NOT_SUPPORTED);
    }
}
