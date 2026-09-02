//! Shared SOCKS5/HTTP proxy parsing and reply helpers for the FlowMux
//! loopback egress adapter (`flowmux_egress`).
//!
//! The legacy raw-egress line-prelude dispatch lived here; it has been deleted
//! in favor of one authenticated FlowMux session owned by `mvm-egress-client`.

#![warn(missing_docs)]

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use mvm_core::guest_netd::ConnectAck;

/// SOCKS protocol version 5.
const SOCKS5: u8 = 0x05;
/// SOCKS5 "no authentication required" method.
const METHOD_NO_AUTH: u8 = 0x00;
/// SOCKS5 "no acceptable methods".
const METHOD_NONE: u8 = 0xFF;
/// SOCKS5 CONNECT command.
const CMD_CONNECT: u8 = 0x01;
/// SOCKS5 UDP ASSOCIATE command.
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProxyRoute {
    Socks { target: String },
    SocksUdpAssociate,
    HttpConnect { target: String },
    HttpForward { head: Vec<u8> },
}

/// Pick the no-auth method from a client's advertised list (RFC 1928 §3).
pub(crate) fn select_method(methods: &[u8]) -> u8 {
    if methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        METHOD_NONE
    }
}

/// Format a SOCKS5 request address into a `"host:port"` string.
///
/// IPv6 is bracketed. Domains pass through verbatim — the host resolves and
/// decides, so a domain target refused by policy is a truthful host failure,
/// not a silent guest-side drop.
pub(crate) fn format_target(atyp: u8, addr: &[u8], port: u16) -> std::io::Result<String> {
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

#[derive(Debug, PartialEq, Eq)]
enum SocksRequest {
    Connect(String),
    UdpAssociate,
}

/// Finish a SOCKS5 negotiation whose version byte the caller has already
/// consumed and matched. Only [`read_route`] may call this, and only on that
/// branch — the stream position is the contract between them.
async fn negotiate_request<S>(stream: &mut S) -> std::io::Result<SocksRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let invalid = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());

    // Greeting, resumed *after* the VER byte: NMETHODS, METHODS...
    //
    // `read_route` has already read and matched VER to dispatch here, so
    // re-reading two bytes would take NMETHODS as the version and the first
    // method as the count. For curl's `05 01 00` that reads as version 1 and
    // rejects a perfectly good greeting — while the client, still waiting on a
    // method reply, sees whatever comes next as a malformed SOCKS5 response.
    let mut nmethods = [0u8; 1];
    stream.read_exact(&mut nmethods).await?;
    let mut methods = vec![0u8; nmethods[0] as usize];
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

/// Send a SOCKS5 reply with code `rep` and a zero bind address.
pub(crate) async fn reply<S>(stream: &mut S, rep: u8) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // VER, REP, RSV, ATYP=ipv4, BND.ADDR=0.0.0.0, BND.PORT=0.
    stream
        .write_all(&[SOCKS5, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    stream.flush().await
}

pub(crate) async fn read_route<S>(stream: &mut S) -> std::io::Result<ProxyRoute>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await?;
    if first[0] == SOCKS5 {
        return match negotiate_request(stream).await? {
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
    Ok(ProxyRoute::HttpForward { head })
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

pub(crate) async fn reply_http_connect_ok<S>(stream: &mut S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    stream.flush().await
}

pub(crate) async fn reply_http_bad_request<S>(stream: &mut S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_http_response(stream, "400 Bad Request").await
}

pub(crate) async fn write_http_response<S>(stream: &mut S, status: &str) -> std::io::Result<()>
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

/// Where an absolute-form HTTP forward request wants to go, and whether the
/// origin expects TLS there.
///
/// The scheme is carried out rather than folded into the port because the two
/// answers have opposite consequences. A `http://` request is forwarded
/// verbatim, which is what a forward proxy is for. A `https://` one cannot be:
/// this proxy relays bytes and never originates TLS, so forwarding the head
/// would put a cleartext request on port 443.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpForwardTarget {
    /// `host:port`, defaulted per scheme when the authority names no port.
    pub(crate) target: String,
    /// The absolute-form URI named `https`.
    pub(crate) tls: bool,
}

/// Extract the TCP target (`host:port`) from an absolute-form HTTP forward
/// request head. HTTP targets use port 80 by default; HTTPS targets use 443.
pub(crate) fn http_forward_target(head: &[u8]) -> std::io::Result<HttpForwardTarget> {
    let text = std::str::from_utf8(head).map_err(|_| invalid_http("HTTP proxy head not UTF-8"))?;
    let request_line = text
        .split_once('\n')
        .map(|(line, _)| line)
        .ok_or_else(|| invalid_http("HTTP proxy request missing request line"))?
        .trim_end_matches('\r');
    let mut parts = request_line.split_whitespace();
    let _method = parts
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
    if !starts_with_ascii_case_insensitive(target, b"http://")
        && !starts_with_ascii_case_insensitive(target, b"https://")
    {
        return Err(invalid_http(
            "HTTP proxy request target must be an absolute http(s) URI",
        ));
    }
    let authority = target
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(target);
    let authority = authority.split(['/', '?']).next().unwrap_or(authority);
    let tls = target.len() >= 8 && target[..8].eq_ignore_ascii_case("https://");
    let default_port = if tls { 443 } else { 80 };
    Ok(HttpForwardTarget {
        target: parse_authority_target(authority, default_port)?,
        tls,
    })
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

/// Which client-facing proxy reply flavour a completed CONNECT-style session
/// answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyReplyStyle {
    Socks,
    HttpConnect,
}

/// Emit the client-facing reply for a connect outcome.
pub(crate) async fn write_connect_reply<C>(
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The exact bytes curl puts on the wire for `socks5h://…`: a greeting of
    /// VER=5, NMETHODS=1, METHOD=no-auth, then a CONNECT for a domain.
    ///
    /// Nothing drove `read_route` with a real greeting before, which is how a
    /// double-read of the version byte reached a builder VM: the guest logged
    /// `socks: not version 5` and curl logged `Received invalid version in
    /// initial SOCKS5 response`, neither of which names the offset.
    #[tokio::test]
    async fn read_route_accepts_a_real_socks5_connect_greeting() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let writer = tokio::spawn(async move {
            client
                .write_all(&[SOCKS5, 1, METHOD_NO_AUTH])
                .await
                .unwrap();
            let host = b"cache.nixos.org";
            let mut req = vec![SOCKS5, CMD_CONNECT, 0, ATYP_DOMAIN, host.len() as u8];
            req.extend_from_slice(host);
            req.extend_from_slice(&443u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
            // Read back the method reply the server owes us, so the assertion
            // below is about a completed negotiation rather than half of one.
            let mut method_reply = [0u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();
            method_reply
        });

        let route = read_route(&mut server).await.expect("a valid greeting");
        assert!(
            matches!(&route, ProxyRoute::Socks { target } if target == "cache.nixos.org:443"),
            "unexpected route: {route:?}"
        );
        assert_eq!(writer.await.unwrap(), [SOCKS5, METHOD_NO_AUTH]);
    }

    #[tokio::test]
    async fn read_route_accepts_a_socks5_udp_associate() {
        let (mut client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            client
                .write_all(&[SOCKS5, 1, METHOD_NO_AUTH])
                .await
                .unwrap();
            let mut req = vec![SOCKS5, CMD_UDP_ASSOCIATE, 0, ATYP_IPV4];
            req.extend_from_slice(&[0, 0, 0, 0]);
            req.extend_from_slice(&0u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
            let mut method_reply = [0u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();
        });

        let route = read_route(&mut server).await.expect("a valid greeting");
        assert!(matches!(route, ProxyRoute::SocksUdpAssociate), "{route:?}");
    }

    /// An HTTP proxy client on the same port must still route as HTTP — the
    /// version-byte read is a dispatch, not a filter.
    #[tokio::test]
    async fn read_route_still_routes_http_connect() {
        let (mut client, mut server) = tokio::io::duplex(512);
        tokio::spawn(async move {
            client
                .write_all(
                    b"CONNECT cache.nixos.org:443 HTTP/1.1\r\nHost: cache.nixos.org:443\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let route = read_route(&mut server).await.expect("a valid CONNECT");
        assert!(
            matches!(&route, ProxyRoute::HttpConnect { target } if target == "cache.nixos.org:443"),
            "unexpected route: {route:?}"
        );
    }

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

    #[test]
    fn http_proxy_connect_parses_host_port() {
        let route = read_http_proxy_route_blocking(
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
    fn http_proxy_absolute_uri_forwards_to_host_proxy() {
        let route = read_http_proxy_route_blocking(
            b"GET https://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();
        assert!(
            matches!(route, ProxyRoute::HttpForward { .. }),
            "unexpected route: {route:?}"
        );
        assert_eq!(
            route.head().unwrap(),
            b"GET https://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        );
        let forward = http_forward_target(route.head().unwrap()).unwrap();
        assert_eq!(forward.target, "example.com:443");
        assert!(forward.tls, "the scheme has to survive the parse");
    }

    #[test]
    fn http_forward_target_uses_port_80_for_http() {
        let forward = http_forward_target(b"GET http://example.com/ HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(forward.target, "example.com:80");
        assert!(!forward.tls, "a http:// request is forwardable as-is");
    }

    /// The port is right and the scheme is reported, which is what stops the
    /// head being forwarded in cleartext to a port that expects TLS.
    #[test]
    fn http_forward_target_uses_port_443_for_https_and_reports_tls() {
        let forward = http_forward_target(b"GET https://example.com/ HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(forward.target, "example.com:443");
        assert!(forward.tls);
    }

    /// An explicit port does not change what the scheme means: `https://` on
    /// any port still expects TLS the proxy cannot originate.
    #[test]
    fn an_explicit_port_does_not_hide_the_https_scheme() {
        let forward =
            http_forward_target(b"GET https://example.com:8080/ HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(forward.target, "example.com:8080");
        assert!(forward.tls);
    }

    #[test]
    fn http_forward_target_honours_explicit_port() {
        assert_eq!(
            http_forward_target(b"GET http://example.com:8080/ HTTP/1.1\r\n\r\n")
                .unwrap()
                .target,
            "example.com:8080"
        );
    }

    #[test]
    fn http_proxy_rejects_origin_form_without_proxy_target() {
        assert!(
            read_http_proxy_route_blocking(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").is_err()
        );
    }

    impl ProxyRoute {
        fn head(&self) -> Option<&[u8]> {
            match self {
                ProxyRoute::HttpForward { head } => Some(head),
                _ => None,
            }
        }
    }

    fn read_http_proxy_route_blocking(head: &[u8]) -> std::io::Result<ProxyRoute> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (mut writer, mut reader) = tokio::io::duplex(256);
            writer.write_all(head).await.unwrap();
            drop(writer);
            let mut first = [0u8; 1];
            reader.read_exact(&mut first).await.unwrap();
            read_http_proxy_route(&mut reader, first[0]).await
        })
    }
}
