//! In-guest loopback proxy → vsock egress client.
//!
//! A NIC-less workload reaches the network only through the host vsock egress
//! gateway. This is the guest-side translator: a loopback proxy that accepts
//! SOCKS5 CONNECT plus ordinary HTTP-proxy requests on the same loopback port.
//! Raw tunnels still send `"host:port\n"` as the first host frame. Absolute-form
//! HTTP requests send one reserved frame line plus the original request bytes so
//! the host forward-proxy path can parse, gate, and originate them itself.
//!
//! The host gateway makes the claim-10 decision — this client never does. A target
//! the host refuses tears down the raw tunnel or returns an HTTP proxy error.

#![warn(missing_docs)]

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::guest_vsock_session::HostVsockSession;

const EGRESS_VSOCK_PORT_ENV: &str = "MVM_EGRESS_VSOCK_PORT";

/// Host vsock port of the egress gateway.
///
/// Must match [`crate::vsock::EGRESS_PORT`] — duplicated here (like
/// `mvm-exit-report`'s copy of `WORKLOAD_EXIT_PORT`); keep in sync manually.
pub const EGRESS_VSOCK_PORT: u32 = 5253;

fn configured_egress_vsock_port() -> u32 {
    match std::env::var(EGRESS_VSOCK_PORT_ENV) {
        Ok(value) => match value.parse::<u32>() {
            Ok(port) if port > 0 => port,
            _ => {
                eprintln!(
                    "mvm-egress-client: ignoring invalid {EGRESS_VSOCK_PORT_ENV}={value:?}; using default {EGRESS_VSOCK_PORT}"
                );
                EGRESS_VSOCK_PORT
            }
        },
        Err(_) => EGRESS_VSOCK_PORT,
    }
}

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
const MAX_HTTP_REQUEST_BYTES: usize = 16 * 1024;
const MAX_HTTP_FORWARD_BODY_LEN: u64 = 8 * 1024 * 1024;
const HTTP_FORWARD_FRAME: &[u8] = b"MVM_HTTP_FORWARD/1\n";

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProxyRoute {
    Socks { target: String },
    HttpConnect { target: String },
    HttpForward { head: Vec<u8>, content_length: u64 },
}

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
    let mut version = [0u8; 1];
    stream.read_exact(&mut version).await?;
    negotiate_with_prefetched(stream, version[0]).await
}

async fn negotiate_with_prefetched<S>(stream: &mut S, version: u8) -> std::io::Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let invalid = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());

    // Greeting: VER, NMETHODS, METHODS...
    if version != SOCKS5 {
        return Err(invalid("socks: not version 5"));
    }
    let mut head = [0u8; 1];
    stream.read_exact(&mut head).await?;
    let mut methods = vec![0u8; head[0] as usize];
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

async fn read_route<S>(stream: &mut S) -> std::io::Result<ProxyRoute>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await?;
    if first[0] == SOCKS5 {
        return Ok(ProxyRoute::Socks {
            target: negotiate_with_prefetched(stream, first[0]).await?,
        });
    }
    read_http_proxy_route(stream, first[0]).await
}

async fn read_http_proxy_route<S>(stream: &mut S, first: u8) -> std::io::Result<ProxyRoute>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = read_http_head_after_prefix(stream, &[first]).await?;
    let request_line = std::str::from_utf8(&head)
        .map_err(|_| invalid_http("HTTP proxy head not UTF-8"))?
        .split_once('\n')
        .map(|(line, _)| line)
        .ok_or_else(|| invalid_http("HTTP proxy request missing request line"))?
        .trim_end_matches('\r');
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| invalid_http("HTTP proxy request missing method"))?;
    let target = parts
        .next()
        .ok_or_else(|| invalid_http("HTTP proxy request missing target"))?;
    let version = parts
        .next()
        .ok_or_else(|| invalid_http("HTTP proxy request missing version"))?;
    if parts.next().is_some() {
        return Err(invalid_http("HTTP proxy request line has too many fields"));
    }
    if !version.starts_with("HTTP/") {
        return Err(invalid_http("HTTP proxy request version is invalid"));
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        return Ok(ProxyRoute::HttpConnect {
            target: parse_authority_target(target, 443)?,
        });
    }
    if !starts_with_ascii_case_insensitive(target, b"http://")
        && !starts_with_ascii_case_insensitive(target, b"https://")
    {
        return Err(invalid_http(
            "HTTP proxy request target must be an absolute http(s) URI",
        ));
    }
    let content_length = parse_http_content_length(&head)?;
    Ok(ProxyRoute::HttpForward {
        head,
        content_length,
    })
}

async fn read_http_head_after_prefix<R>(client: &mut R, prefix: &[u8]) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut head = Vec::with_capacity(512);
    head.extend_from_slice(prefix);
    if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
        return Ok(head);
    }
    let mut byte = [0u8; 1];
    while head.len() < MAX_HTTP_REQUEST_BYTES {
        let n = client.read(&mut byte).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "proxy client closed before HTTP header completed",
            ));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            return Ok(head);
        }
    }
    Err(invalid_http("HTTP proxy request head exceeded limit"))
}

async fn reply_http_connect_ok<S>(stream: &mut S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    stream.flush().await
}

async fn reply_http_bad_request<S>(stream: &mut S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_http_response(stream, "400 Bad Request").await
}

async fn write_http_response<S>(stream: &mut S, status: &str) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    stream.flush().await
}

async fn serve(mut client: TcpStream) -> std::io::Result<()> {
    let route = match read_route(&mut client).await {
        Ok(route) => route,
        Err(err) => {
            let _ = reply_http_bad_request(&mut client).await;
            return Err(err);
        }
    };
    match route {
        ProxyRoute::Socks { target } => serve_socks(client, &target).await,
        ProxyRoute::HttpConnect { target } => serve_http_connect(client, &target).await,
        ProxyRoute::HttpForward {
            head,
            content_length,
        } => serve_http_forward(client, &head, content_length).await,
    }
}

async fn serve_socks(mut client: TcpStream, target: &str) -> std::io::Result<()> {
    let session = match connect_to_host_egress(target).await {
        Ok(session) => session,
        Err(err) => {
            let _ = reply(&mut client, REP_GENERAL_FAILURE).await;
            return Err(err);
        }
    };
    reply(&mut client, REP_SUCCESS).await?;
    session.splice(client).await
}

async fn serve_http_connect(mut client: TcpStream, target: &str) -> std::io::Result<()> {
    let session = match connect_to_host_egress(target).await {
        Ok(session) => session,
        Err(err) => {
            let _ = write_http_response(&mut client, "502 Bad Gateway").await;
            return Err(err);
        }
    };
    reply_http_connect_ok(&mut client).await?;
    session.splice(client).await
}

async fn serve_http_forward(
    mut client: TcpStream,
    head: &[u8],
    content_length: u64,
) -> std::io::Result<()> {
    let body = read_exact_body(&mut client, content_length).await?;
    let mut framed = Vec::with_capacity(HTTP_FORWARD_FRAME.len() + head.len() + body.len());
    framed.extend_from_slice(HTTP_FORWARD_FRAME);
    framed.extend_from_slice(head);
    framed.extend_from_slice(&body);
    let mut upstream = HostVsockSession::connect(configured_egress_vsock_port())
        .await?
        .write_initial_bytes(&framed)
        .await?
        .into_inner();
    tokio::io::copy(&mut upstream, &mut client)
        .await
        .map(|_| ())
}

async fn read_exact_body<S>(stream: &mut S, content_length: u64) -> std::io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let len = usize::try_from(content_length)
        .map_err(|_| invalid_http("HTTP proxy request body is too large"))?;
    let mut body = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut body).await?;
    }
    Ok(body)
}

async fn connect_to_host_egress(target: &str) -> std::io::Result<HostVsockSession<TcpStream>> {
    let target_line = format!("{target}\n");
    HostVsockSession::connect(configured_egress_vsock_port())
        .await?
        .write_initial_bytes(target_line.as_bytes())
        .await
}

fn parse_http_content_length(head: &[u8]) -> std::io::Result<u64> {
    let mut content_length = None;
    for line in std::str::from_utf8(head)
        .map_err(|_| invalid_http("HTTP proxy head not UTF-8"))?
        .lines()
        .skip(1)
    {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(invalid_http("HTTP proxy header is missing ':'"));
        };
        if !name.trim().eq_ignore_ascii_case("content-length") {
            continue;
        }
        if content_length.is_some() {
            return Err(invalid_http(
                "HTTP proxy request has duplicate content-length",
            ));
        }
        let len = value
            .trim()
            .parse::<u64>()
            .map_err(|_| invalid_http("HTTP proxy content-length is invalid"))?;
        if len > MAX_HTTP_FORWARD_BODY_LEN {
            return Err(invalid_http("HTTP proxy request body is too large"));
        }
        content_length = Some(len);
    }
    Ok(content_length.unwrap_or(0))
}

fn parse_authority_target(authority: &str, default_port: u16) -> std::io::Result<String> {
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid_http("HTTP proxy authority is invalid"));
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| invalid_http("HTTP proxy IPv6 authority is missing ']'"))?;
        let host = &authority[..=end + 1];
        let after = &rest[end + 1..];
        if after.is_empty() {
            (host, default_port)
        } else if let Some(port) = after.strip_prefix(':') {
            (host, parse_http_port(port)?)
        } else {
            return Err(invalid_http("HTTP proxy IPv6 authority has invalid suffix"));
        }
    } else {
        if authority.matches(':').count() > 1 {
            return Err(invalid_http("HTTP proxy IPv6 authority must be bracketed"));
        }
        match authority.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() => (host, parse_http_port(port)?),
            Some(_) => return Err(invalid_http("HTTP proxy authority host is empty")),
            None => (authority, default_port),
        }
    };
    if host.is_empty() {
        return Err(invalid_http("HTTP proxy authority host is empty"));
    }
    Ok(format!("{host}:{port}"))
}

fn parse_http_port(port: &str) -> std::io::Result<u16> {
    if port.is_empty() {
        return Err(invalid_http("HTTP proxy authority port is empty"));
    }
    port.parse::<u16>()
        .map_err(|_| invalid_http("HTTP proxy authority port is invalid"))
}

fn starts_with_ascii_case_insensitive(value: &str, prefix: &[u8]) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= prefix.len()
        && bytes[..prefix.len()]
            .iter()
            .zip(prefix)
            .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
}

fn invalid_http(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

/// Bind the loopback SOCKS5 listener at `listen` and serve egress indefinitely.
pub async fn run(listen: std::net::SocketAddr) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(
        %listen,
        vsock_port = configured_egress_vsock_port(),
        "egress SOCKS5 client started"
    );
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

/// Bind the loopback SOCKS5 listener at `listen` and serve until `shutdown`
/// flips to `true`.
pub async fn run_until_shutdown(
    listen: std::net::SocketAddr,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(
        %listen,
        vsock_port = EGRESS_VSOCK_PORT,
        "egress proxy client started"
    );
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if *shutdown.borrow() => return Ok(()),
                    Ok(()) => continue,
                    Err(_) => return Ok(()),
                }
            }
            accepted = listener.accept() => {
                match accepted {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_vsock_session::HostVsockSession;
    use tokio::io::DuplexStream;

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
        a[15] = 1; //::1
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

    #[tokio::test]
    async fn serve_frames_target_line_then_proxies_bytes() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let (upstream_bridge, mut upstream_side) = tokio::io::duplex(256);

        let task = tokio::spawn(async move {
            let target = negotiate(&mut server).await.unwrap();
            let session = HostVsockSession::new(upstream_bridge)
                .write_initial_bytes(format!("{target}\n").as_bytes())
                .await
                .unwrap();
            reply(&mut server, REP_SUCCESS).await.unwrap();
            session.splice(server).await.unwrap();
        });

        client
            .write_all(&[SOCKS5, 1, METHOD_NO_AUTH])
            .await
            .unwrap();
        let mut sel = [0u8; 2];
        client.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [SOCKS5, METHOD_NO_AUTH]);

        client
            .write_all(&[
                SOCKS5,
                CMD_CONNECT,
                0x00,
                ATYP_DOMAIN,
                11,
                b'e',
                b'x',
                b'a',
                b'm',
                b'p',
                b'l',
                b'e',
                b'.',
                b'c',
                b'o',
                b'm',
                0x01,
                0xBB,
            ])
            .await
            .unwrap();

        let mut success = [0u8; 10];
        client.read_exact(&mut success).await.unwrap();
        assert_eq!(success[1], REP_SUCCESS);

        let mut target_line = [0u8; 16];
        upstream_side.read_exact(&mut target_line).await.unwrap();
        assert_eq!(&target_line, b"example.com:443\n");

        client.write_all(b"ping").await.unwrap();
        let mut payload = [0u8; 4];
        upstream_side.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");

        upstream_side.write_all(b"pong").await.unwrap();
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        drop(client);
        drop(upstream_side);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn serve_http_connect_frames_target_line_then_proxies_bytes() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let (upstream_bridge, mut upstream_side) = tokio::io::duplex(256);

        let task = tokio::spawn(async move {
            let route = read_route(&mut server).await.unwrap();
            let target = match route {
                ProxyRoute::HttpConnect { target } => target,
                other => panic!("unexpected route: {other:?}"),
            };
            let session = HostVsockSession::new(upstream_bridge)
                .write_initial_bytes(format!("{target}\n").as_bytes())
                .await
                .unwrap();
            reply_http_connect_ok(&mut server).await.unwrap();
            session.splice(server).await.unwrap();
        });

        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();

        let mut ok = vec![0u8; b"HTTP/1.1 200 Connection established\r\n\r\n".len()];
        client.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"HTTP/1.1 200 Connection established\r\n\r\n");

        let mut target_line = [0u8; 16];
        upstream_side.read_exact(&mut target_line).await.unwrap();
        assert_eq!(&target_line, b"example.com:443\n");

        client.write_all(b"ping").await.unwrap();
        let mut payload = [0u8; 4];
        upstream_side.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");

        upstream_side.write_all(b"pong").await.unwrap();
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        drop(client);
        drop(upstream_side);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn serve_http_connect_accepts_lf_only_headers() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let (upstream_bridge, mut upstream_side) = tokio::io::duplex(256);

        let task = tokio::spawn(async move {
            let route = read_route(&mut server).await.unwrap();
            let target = match route {
                ProxyRoute::HttpConnect { target } => target,
                other => panic!("unexpected route: {other:?}"),
            };
            let session = HostVsockSession::new(upstream_bridge)
                .write_initial_bytes(format!("{target}\n").as_bytes())
                .await
                .unwrap();
            reply_http_connect_ok(&mut server).await.unwrap();
            session.splice(server).await.unwrap();
        });

        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\nHost: example.com:443\n\n")
            .await
            .unwrap();

        let mut ok = vec![0u8; b"HTTP/1.1 200 Connection established\r\n\r\n".len()];
        client.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"HTTP/1.1 200 Connection established\r\n\r\n");

        let mut target_line = [0u8; 16];
        upstream_side.read_exact(&mut target_line).await.unwrap();
        assert_eq!(&target_line, b"example.com:443\n");

        drop(client);
        drop(upstream_side);
        task.await.unwrap();
    }

    #[test]
    fn http_proxy_absolute_https_forwards_to_host_proxy() {
        let route = parse_http_proxy_route(
            b"GET https://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            route,
            ProxyRoute::HttpForward {
                head: b"GET https://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
                    .to_vec(),
                content_length: 0,
            }
        );
    }

    #[test]
    fn http_proxy_forward_parses_fixed_body_length() {
        let route = parse_http_proxy_route(
            b"POST https://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            route,
            ProxyRoute::HttpForward {
                head: b"POST https://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n".to_vec(),
                content_length: 4,
            }
        );
    }

    #[test]
    fn http_proxy_connect_parses_host_port() {
        let route = parse_http_proxy_route(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            route,
            ProxyRoute::HttpConnect {
                target: "example.com:443".to_string()
            }
        );
    }

    #[test]
    fn http_proxy_rejects_origin_form_without_proxy_target() {
        assert!(parse_http_proxy_route(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn http_forward_keeps_response_path_after_client_write_shutdown() {
        let head = b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (mut client, proxy_client) = tokio::io::duplex(512);
        let (proxy_upstream, mut host) = tokio::io::duplex(512);
        let handler = tokio::spawn(proxy_single_http_forward(
            proxy_client,
            HostVsockSession::new(proxy_upstream),
            head,
            0,
        ));

        client.shutdown().await.unwrap();

        let mut framed = vec![0u8; HTTP_FORWARD_FRAME.len() + head.len()];
        host.read_exact(&mut framed).await.unwrap();
        assert_eq!(&framed[..HTTP_FORWARD_FRAME.len()], HTTP_FORWARD_FRAME);
        assert_eq!(&framed[HTTP_FORWARD_FRAME.len()..], head);
        host.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        host.shutdown().await.unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&response).unwrap(),
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
        );
        handler.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn http_forward_streams_fixed_body_before_response() {
        let head =
            b"POST https://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n";
        let (mut client, proxy_client) = tokio::io::duplex(512);
        let (proxy_upstream, mut host) = tokio::io::duplex(512);
        let handler = tokio::spawn(proxy_single_http_forward(
            proxy_client,
            HostVsockSession::new(proxy_upstream),
            head,
            4,
        ));

        client.write_all(b"test").await.unwrap();
        client.shutdown().await.unwrap();

        let mut framed = vec![0u8; HTTP_FORWARD_FRAME.len() + head.len() + 4];
        host.read_exact(&mut framed).await.unwrap();
        assert_eq!(&framed[..HTTP_FORWARD_FRAME.len()], HTTP_FORWARD_FRAME);
        assert_eq!(
            &framed[HTTP_FORWARD_FRAME.len()..HTTP_FORWARD_FRAME.len() + head.len()],
            head
        );
        assert_eq!(&framed[HTTP_FORWARD_FRAME.len() + head.len()..], b"test");
        host.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        host.shutdown().await.unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&response).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        );
        handler.await.unwrap().unwrap();
    }

    fn parse_http_proxy_route(head: &[u8]) -> std::io::Result<ProxyRoute> {
        let text =
            std::str::from_utf8(head).map_err(|_| invalid_http("HTTP proxy head not UTF-8"))?;
        let raw_request_line = text
            .split_once('\n')
            .map(|(line, _)| line)
            .ok_or_else(|| invalid_http("HTTP proxy request missing request line"))?;
        let request_line = raw_request_line.trim_end_matches('\r');
        let mut parts = request_line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| invalid_http("HTTP proxy request missing method"))?;
        let target = parts
            .next()
            .ok_or_else(|| invalid_http("HTTP proxy request missing target"))?;
        let version = parts
            .next()
            .ok_or_else(|| invalid_http("HTTP proxy request missing version"))?;
        if parts.next().is_some() {
            return Err(invalid_http("HTTP proxy request line has too many fields"));
        }
        if !version.starts_with("HTTP/") {
            return Err(invalid_http("HTTP proxy request version is invalid"));
        }
        if method.eq_ignore_ascii_case("CONNECT") {
            return Ok(ProxyRoute::HttpConnect {
                target: parse_authority_target(target, 443)?,
            });
        }
        if !starts_with_ascii_case_insensitive(target, b"http://")
            && !starts_with_ascii_case_insensitive(target, b"https://")
        {
            return Err(invalid_http(
                "HTTP proxy request target must be an absolute http(s) URI",
            ));
        }
        Ok(ProxyRoute::HttpForward {
            head: head.to_vec(),
            content_length: parse_http_content_length(head)?,
        })
    }

    async fn proxy_single_http_forward(
        client: DuplexStream,
        upstream: HostVsockSession<DuplexStream>,
        head: &[u8],
        content_length: u64,
    ) -> std::io::Result<()> {
        let mut client = client;
        let body = read_exact_body(&mut client, content_length).await?;
        let mut framed = Vec::with_capacity(HTTP_FORWARD_FRAME.len() + head.len() + body.len());
        framed.extend_from_slice(HTTP_FORWARD_FRAME);
        framed.extend_from_slice(head);
        framed.extend_from_slice(&body);
        let mut upstream = upstream.write_initial_bytes(&framed).await?.into_inner();
        tokio::io::copy(&mut upstream, &mut client)
            .await
            .map(|_| ())
    }
}
