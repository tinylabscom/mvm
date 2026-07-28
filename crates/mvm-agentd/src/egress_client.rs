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

use crate::guest_vsock_session::{HostVsockSession, HostVsockStream};
use mvm_core::guest_netd::ConnectAck;
use mvm_core::socks5_udp::{self, Datagram};

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
const CMD_UDP_ASSOCIATE: u8 = 0x03;
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
    SocksUdpAssociate,
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
    match negotiate_request_with_prefetched(stream, version[0]).await? {
        SocksRequest::Connect(target) => Ok(target),
        SocksRequest::UdpAssociate => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socks: UDP ASSOCIATE is not a CONNECT request",
        )),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SocksRequest {
    Connect(String),
    UdpAssociate,
}

async fn negotiate_request_with_prefetched<S>(
    stream: &mut S,
    version: u8,
) -> std::io::Result<SocksRequest>
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
    if req[1] != CMD_CONNECT && req[1] != CMD_UDP_ASSOCIATE {
        // Reply "command not supported" before closing.
        let _ = reply(stream, REP_CMD_NOT_SUPPORTED).await;
        return Err(invalid("socks: unsupported command"));
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
    let target = format_target(atyp, &addr, u16::from_be_bytes(port))?;
    if req[1] == CMD_UDP_ASSOCIATE {
        Ok(SocksRequest::UdpAssociate)
    } else {
        Ok(SocksRequest::Connect(target))
    }
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
        return match negotiate_request_with_prefetched(stream, first[0]).await? {
            SocksRequest::Connect(target) => Ok(ProxyRoute::Socks { target }),
            SocksRequest::UdpAssociate => Ok(ProxyRoute::SocksUdpAssociate),
        };
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
        ProxyRoute::SocksUdpAssociate => serve_socks_udp(client).await,
        ProxyRoute::HttpConnect { target } => serve_http_connect(client, &target).await,
        ProxyRoute::HttpForward {
            head,
            content_length,
        } => serve_http_forward(client, &head, content_length).await,
    }
}

async fn serve_socks_udp(control: TcpStream) -> std::io::Result<()> {
    let upstream = HostVsockSession::connect(configured_egress_vsock_port())
        .await?
        .write_initial_bytes(format!("{}\n", socks5_udp::FRAME_LINE).as_bytes())
        .await?
        .into_inner();
    serve_socks_udp_with_upstream(control, upstream).await
}

async fn serve_socks_udp_with_upstream<C, U>(mut control: C, mut upstream: U) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let port = udp.local_addr()?.port();
    control
        .write_all(&[SOCKS5, REP_SUCCESS, 0, ATYP_IPV4, 127, 0, 0, 1])
        .await?;
    control.write_all(&port.to_be_bytes()).await?;
    control.flush().await?;

    let mut udp_buffer = vec![0_u8; socks5_udp::MAX_DATAGRAM_BYTES];
    let mut control_buffer = [0_u8; 1];
    let mut last_peer = None;

    loop {
        tokio::select! {
            result = udp.recv_from(&mut udp_buffer) => {
                let (length, peer) = result?;
                let packet = match Datagram::decode(&udp_buffer[..length]) {
                    Ok(packet) => packet,
                    Err(_) => continue,
                };
                let frame = packet
                    .encode()
                    .map_err(|_| invalid_udp("UDP datagram is too large"))?;
                write_udp_frame(&mut upstream, &frame).await?;
                last_peer = Some(peer);
            }
            result = read_udp_frame(&mut upstream) => {
                let Some(frame) = result? else { return Ok(()); };
                let packet = match Datagram::decode(&frame) {
                    Ok(packet) => packet,
                    Err(_) => continue,
                };
                if let Some(peer) = last_peer {
                    udp.send_to(&packet.payload, peer).await?;
                }
            }
            result = control.read(&mut control_buffer) => {
                if result? == 0 {
                    return Ok(());
                }
            }
        }
    }
}

async fn read_udp_frame<S>(stream: &mut S) -> std::io::Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0_u8; 2];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > socks5_udp::MAX_DATAGRAM_BYTES {
        return Err(invalid_udp("invalid UDP frame length"));
    }
    let mut frame = vec![0_u8; length];
    stream.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

async fn write_udp_frame<S>(stream: &mut S, frame: &[u8]) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let length = u16::try_from(frame.len()).map_err(|_| invalid_udp("UDP frame is too large"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(frame).await?;
    stream.flush().await
}

fn invalid_udp(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_string())
}

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

async fn connect_to_host_egress(
    target: &str,
) -> std::io::Result<HostVsockSession<HostVsockStream>> {
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

/// Loopback DNS stub forwarding queries over the host-vsock egress seam.
pub mod dns_stub {
    use std::sync::Arc;

    use mvm_core::guest_netd::DNS_FRAME_LINE;
    use mvm_core::protocol::dns::MAX_DNS_MESSAGE;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};

    use crate::guest_vsock_session::HostVsockSession;

    use super::configured_egress_vsock_port;

    /// Bind UDP and TCP DNS listeners and forward each query over host vsock.
    pub async fn run_dns_stub(listen: std::net::SocketAddr) -> std::io::Result<()> {
        if !listen.ip().is_loopback() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "DNS stub listen address must be loopback",
            ));
        }
        let udp = UdpSocket::bind(listen).await?;
        let tcp = TcpListener::bind(listen).await?;
        tracing::info!(%listen, "guest DNS stub started");
        tokio::try_join!(serve_udp(udp), serve_tcp(tcp)).map(|_| ())
    }

    async fn serve_udp(socket: UdpSocket) -> std::io::Result<()> {
        let socket = Arc::new(socket);
        let mut buffer = vec![0_u8; MAX_DNS_MESSAGE + 1];
        loop {
            let (length, peer) = socket.recv_from(&mut buffer).await?;
            if length > MAX_DNS_MESSAGE {
                tracing::warn!(%peer, length, "dropping oversized UDP DNS query");
                continue;
            }
            let query = buffer[..length].to_vec();
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                match forward_query_over_vsock(&query).await {
                    Ok(response) => {
                        if let Err(error) = socket.send_to(&response, peer).await {
                            tracing::warn!(%error, %peer, "sending UDP DNS response failed");
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, %peer, "forwarding UDP DNS query failed");
                    }
                }
            });
        }
    }

    async fn serve_tcp(listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (stream, peer) = listener.accept().await?;
            tokio::spawn(async move {
                if let Err(error) = serve_tcp_connection(stream).await {
                    tracing::warn!(%error, %peer, "serving TCP DNS connection failed");
                }
            });
        }
    }

    async fn serve_tcp_connection(mut stream: TcpStream) -> std::io::Result<()> {
        loop {
            let mut length = [0_u8; 2];
            if stream.read(&mut length[..1]).await? == 0 {
                return Ok(());
            }
            stream.read_exact(&mut length[1..]).await?;
            let length = usize::from(u16::from_be_bytes(length));
            validate_dns_length(length)?;
            let mut query = vec![0_u8; length];
            stream.read_exact(&mut query).await?;
            let response = forward_query_over_vsock(&query).await?;
            let response_length =
                u16::try_from(response.len()).map_err(|_| invalid_dns_length())?;
            stream.write_all(&response_length.to_be_bytes()).await?;
            stream.write_all(&response).await?;
            stream.flush().await?;
        }
    }

    async fn forward_query_over_vsock(query: &[u8]) -> std::io::Result<Vec<u8>> {
        let session = HostVsockSession::connect(configured_egress_vsock_port()).await?;
        forward_query_over_session(session, query).await
    }

    async fn forward_query_over_session<U>(
        session: HostVsockSession<U>,
        query: &[u8],
    ) -> std::io::Result<Vec<u8>>
    where
        U: AsyncRead + AsyncWrite + Unpin,
    {
        validate_dns_length(query.len())?;
        let query_length = u16::try_from(query.len()).map_err(|_| invalid_dns_length())?;
        let mut upstream = session.into_inner();
        upstream.write_all(DNS_FRAME_LINE.as_bytes()).await?;
        upstream.write_all(b"\n").await?;
        upstream.write_all(&query_length.to_be_bytes()).await?;
        upstream.write_all(query).await?;
        upstream.flush().await?;

        let mut response_length = [0_u8; 2];
        upstream.read_exact(&mut response_length).await?;
        let response_length = usize::from(u16::from_be_bytes(response_length));
        validate_dns_length(response_length)?;
        let mut response = vec![0_u8; response_length];
        upstream.read_exact(&mut response).await?;
        Ok(response)
    }

    fn validate_dns_length(length: usize) -> std::io::Result<()> {
        if length > MAX_DNS_MESSAGE {
            Err(invalid_dns_length())
        } else {
            Ok(())
        }
    }

    fn invalid_dns_length() -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS frame exceeds the configured message limit",
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[tokio::test]
        async fn stub_frames_marker_length_and_query_then_reads_response() {
            let (mut host, stub) = tokio::io::duplex(4096);
            let session = HostVsockSession::new(stub);
            let task = tokio::spawn(forward_query_over_session(session, b"QUERYBYTES"));

            let mut line = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                host.read_exact(&mut byte).await.unwrap();
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            assert_eq!(line, b"MVM_DNS/1\n");

            let mut length = [0_u8; 2];
            host.read_exact(&mut length).await.unwrap();
            assert_eq!(usize::from(u16::from_be_bytes(length)), 10);
            let mut query = [0_u8; 10];
            host.read_exact(&mut query).await.unwrap();
            assert_eq!(&query, b"QUERYBYTES");

            host.write_all(&4_u16.to_be_bytes()).await.unwrap();
            host.write_all(b"RESP").await.unwrap();
            assert_eq!(task.await.unwrap().unwrap(), b"RESP");
        }

        #[test]
        fn dns_frames_are_bounded_at_the_shared_codec_limit() {
            assert!(validate_dns_length(MAX_DNS_MESSAGE).is_ok());
            let error = validate_dns_length(MAX_DNS_MESSAGE + 1).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }

        #[tokio::test]
        async fn dns_stub_rejects_a_non_loopback_listener() {
            let error = run_dns_stub("0.0.0.0:0".parse().unwrap())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
    }
}

fn spawn_default_dns_stub() -> Option<tokio::task::JoinHandle<()>> {
    let listen = match mvm_core::guest_netd::DEFAULT_DNS_STUB_LISTEN.parse() {
        Ok(listen) => listen,
        Err(error) => {
            tracing::warn!(%error, "default DNS stub address is invalid");
            return None;
        }
    };
    Some(tokio::spawn(async move {
        if let Err(error) = dns_stub::run_dns_stub(listen).await {
            tracing::warn!(%error, %listen, "guest DNS stub unavailable; proxy remains active");
        }
    }))
}

/// Bind the loopback SOCKS5 listener at `listen` and serve egress indefinitely.
pub async fn run(listen: std::net::SocketAddr) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let _dns_task = spawn_default_dns_stub();
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
    let dns_task = spawn_default_dns_stub();
    tracing::info!(
        %listen,
        vsock_port = EGRESS_VSOCK_PORT,
        "egress proxy client started"
    );
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if *shutdown.borrow() => break,
                    Ok(()) => continue,
                    Err(_) => break,
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
    if let Some(dns_task) = dns_task {
        dns_task.abort();
    }
    Ok(())
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
    async fn udp_associate_frames_datagrams_over_the_upstream() {
        let (mut client, control) = tokio::io::duplex(4096);
        let (upstream, mut upstream_side) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            let mut control = control;
            assert_eq!(
                read_route(&mut control).await.expect("read UDP route"),
                ProxyRoute::SocksUdpAssociate
            );
            serve_socks_udp_with_upstream(control, upstream)
                .await
                .expect("UDP relay succeeds");
        });

        client
            .write_all(&[
                SOCKS5,
                1,
                METHOD_NO_AUTH,
                SOCKS5,
                CMD_UDP_ASSOCIATE,
                0,
                ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await
            .expect("write associate request");

        let mut selection = [0_u8; 2];
        client
            .read_exact(&mut selection)
            .await
            .expect("method reply");
        assert_eq!(selection, [SOCKS5, METHOD_NO_AUTH]);
        let mut association = [0_u8; 10];
        client
            .read_exact(&mut association)
            .await
            .expect("associate reply");
        assert_eq!(association[..4], [SOCKS5, REP_SUCCESS, 0, ATYP_IPV4]);
        let relay_port = u16::from_be_bytes([association[8], association[9]]);

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind UDP client");
        let packet = Datagram {
            address: mvm_core::socks5_udp::Address::Ip("192.0.2.1".parse().expect("valid address")),
            port: 5353,
            payload: b"query".to_vec(),
        };
        let encoded = packet.encode().expect("encode packet");
        socket
            .send_to(&encoded, ("127.0.0.1", relay_port))
            .await
            .expect("send UDP packet");

        let mut length = [0_u8; 2];
        upstream_side
            .read_exact(&mut length)
            .await
            .expect("upstream frame length");
        let mut frame = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        upstream_side
            .read_exact(&mut frame)
            .await
            .expect("upstream frame");
        assert_eq!(Datagram::decode(&frame).expect("decode frame"), packet);

        let response = Datagram {
            address: mvm_core::socks5_udp::Address::Ip("192.0.2.1".parse().expect("valid address")),
            port: 5353,
            payload: b"answer".to_vec(),
        }
        .encode()
        .expect("encode response");
        upstream_side
            .write_all(
                &u16::try_from(response.len())
                    .expect("response fits")
                    .to_be_bytes(),
            )
            .await
            .expect("response length");
        upstream_side
            .write_all(&response)
            .await
            .expect("response frame");

        let mut received = [0_u8; 32];
        let (length, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            socket.recv_from(&mut received),
        )
        .await
        .expect("UDP response timeout")
        .expect("UDP response");
        assert_eq!(&received[..length], b"answer");

        drop(client);
        drop(upstream_side);
        task.await.expect("relay joins");
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
