//! Host-side HTTP forward-proxy mode for the raw vsock egress channel.
//!
//! The guest helper sends a reserved first frame followed by an absolute-form
//! HTTP request head. The host parses the request, applies the same claim-10
//! [`EgressGate`] used by raw TCP tunnels, then originates the HTTP request with
//! the host TLS/client stack. The guest never receives TLS credentials and never
//! makes the outbound network connection itself.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use mvm_backend::vmm::egress_gate::{EgressGate, EgressVerdict};
use reqwest::header::{HeaderName, HeaderValue};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(target_os = "linux")]
use std::io::{Read, Write};

/// Reserved first line on the raw egress stream for host HTTP forward mode.
pub const FRAME_LINE: &str = "MVM_HTTP_FORWARD/1";

const MAX_HTTP_HEAD_LEN: usize = 16 * 1024;
const MAX_REQUEST_BODY_LEN: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
struct ForwardRequest {
    method: String,
    url: url::Url,
    target: String,
    host: String,
    headers: Vec<(HeaderName, HeaderValue)>,
    content_length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyStatus {
    BadRequest,
    Forbidden,
    NotImplemented,
    BadGateway,
}

impl ProxyStatus {
    fn line(self) -> &'static str {
        match self {
            Self::BadRequest => "400 Bad Request",
            Self::Forbidden => "403 Forbidden",
            Self::NotImplemented => "501 Not Implemented",
            Self::BadGateway => "502 Bad Gateway",
        }
    }
}

/// Serve one host-side absolute-form HTTP proxy request over an async guest
/// stream. This owns the complete L7 path after the reserved frame has been
/// consumed by the raw-egress dispatcher.
pub async fn serve_http_forward<S>(
    mut guest: S,
    gate: &EgressGate,
    timeout: Duration,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = match read_http_head(&mut guest).await {
        Ok(head) => head,
        Err(error) => {
            write_proxy_error_async(&mut guest, ProxyStatus::BadRequest).await?;
            return Err(error);
        }
    };
    let request = match parse_forward_request(&head) {
        Ok(request) => request,
        Err(status) => {
            write_proxy_error_async(&mut guest, status).await?;
            return Ok(());
        }
    };
    let (ip, port) = match gate.decide_request(&request.target) {
        EgressVerdict::Allow { ip, port } => (ip, port),
        EgressVerdict::Deny => {
            write_proxy_error_async(&mut guest, ProxyStatus::Forbidden).await?;
            return Ok(());
        }
        EgressVerdict::Malformed => {
            write_proxy_error_async(&mut guest, ProxyStatus::BadRequest).await?;
            return Ok(());
        }
    };
    let body = match read_request_body_async(&mut guest, request.content_length).await {
        Ok(body) => body,
        Err(error) => {
            write_proxy_error_async(&mut guest, ProxyStatus::BadRequest).await?;
            return Err(error);
        }
    };
    let response = match send_host_request(&request, body, ip, port, timeout).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(error = %error, target = %request.target, "host HTTP forward request failed");
            write_proxy_error_async(&mut guest, ProxyStatus::BadGateway).await?;
            return Ok(());
        }
    };
    write_upstream_response_async(&mut guest, response, &request.method).await
}

/// Blocking sibling used by Linux AF_VSOCK accept threads.
#[cfg(target_os = "linux")]
pub fn serve_http_forward_blocking<S>(
    mut guest: S,
    gate: &EgressGate,
    timeout: Duration,
) -> std::io::Result<()>
where
    S: Read + Write,
{
    let head = match read_http_head_blocking(&mut guest) {
        Ok(head) => head,
        Err(error) => {
            write_proxy_error_blocking(&mut guest, ProxyStatus::BadRequest)?;
            return Err(error);
        }
    };
    let request = match parse_forward_request(&head) {
        Ok(request) => request,
        Err(status) => {
            write_proxy_error_blocking(&mut guest, status)?;
            return Ok(());
        }
    };
    let (ip, port) = match gate.decide_request(&request.target) {
        EgressVerdict::Allow { ip, port } => (ip, port),
        EgressVerdict::Deny => {
            write_proxy_error_blocking(&mut guest, ProxyStatus::Forbidden)?;
            return Ok(());
        }
        EgressVerdict::Malformed => {
            write_proxy_error_blocking(&mut guest, ProxyStatus::BadRequest)?;
            return Ok(());
        }
    };
    let body = match read_request_body_blocking(&mut guest, request.content_length) {
        Ok(body) => body,
        Err(error) => {
            write_proxy_error_blocking(&mut guest, ProxyStatus::BadRequest)?;
            return Err(error);
        }
    };
    let response = match send_host_request_blocking(&request, body, ip, port, timeout) {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(error = %error, target = %request.target, "host HTTP forward request failed");
            write_proxy_error_blocking(&mut guest, ProxyStatus::BadGateway)?;
            return Ok(());
        }
    };
    write_upstream_response_blocking(&mut guest, response, &request.method)
}

async fn read_http_head<R>(guest: &mut R) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while head.len() < MAX_HTTP_HEAD_LEN {
        let n = guest.read(&mut byte).await?;
        if n == 0 {
            return Err(invalid_input(
                "HTTP proxy request ended before header terminator",
            ));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
    Err(invalid_input("HTTP proxy request head exceeded limit"))
}

#[cfg(target_os = "linux")]
fn read_http_head_blocking<R>(guest: &mut R) -> std::io::Result<Vec<u8>>
where
    R: Read,
{
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while head.len() < MAX_HTTP_HEAD_LEN {
        let n = guest.read(&mut byte)?;
        if n == 0 {
            return Err(invalid_input(
                "HTTP proxy request ended before header terminator",
            ));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
    Err(invalid_input("HTTP proxy request head exceeded limit"))
}

fn parse_forward_request(head: &[u8]) -> Result<ForwardRequest, ProxyStatus> {
    let text = std::str::from_utf8(head).map_err(|_| ProxyStatus::BadRequest)?;
    let head_text = text
        .strip_suffix("\r\n\r\n")
        .ok_or(ProxyStatus::BadRequest)?;
    let mut lines = head_text.split("\r\n");
    let request_line = lines.next().ok_or(ProxyStatus::BadRequest)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(ProxyStatus::BadRequest)?;
    let uri = parts.next().ok_or(ProxyStatus::BadRequest)?;
    let version = parts.next().ok_or(ProxyStatus::BadRequest)?;
    if parts.next().is_some() || !version.starts_with("HTTP/") {
        return Err(ProxyStatus::BadRequest);
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        return Err(ProxyStatus::BadRequest);
    }

    let url = url::Url::parse(uri).map_err(|_| ProxyStatus::BadRequest)?;
    match url.scheme() {
        "http" | "https" => {}
        _ => return Err(ProxyStatus::BadRequest),
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(ProxyStatus::BadRequest);
    }
    let port = url.port_or_known_default().ok_or(ProxyStatus::BadRequest)?;
    let host = url.host().ok_or(ProxyStatus::BadRequest)?;
    let target = match host {
        url::Host::Domain(host) => format!("{host}:{port}"),
        url::Host::Ipv4(ip) => format!("{ip}:{port}"),
        url::Host::Ipv6(ip) => format!("[{ip}]:{port}"),
    };
    let host = url.host_str().ok_or(ProxyStatus::BadRequest)?.to_string();
    let (headers, content_length) = parse_forward_headers(lines)?;
    Ok(ForwardRequest {
        method: method.to_string(),
        url,
        target,
        host,
        headers,
        content_length,
    })
}

fn parse_forward_headers<'a, I>(
    lines: I,
) -> Result<(Vec<(HeaderName, HeaderValue)>, u64), ProxyStatus>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut parsed = Vec::new();
    let mut connection_tokens = Vec::new();
    let mut content_length = None;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(ProxyStatus::BadRequest)?;
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            return Err(ProxyStatus::BadRequest);
        }
        if name.eq_ignore_ascii_case("connection") {
            connection_tokens.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|token| !token.is_empty())
                    .map(|token| token.to_ascii_lowercase()),
            );
            continue;
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(ProxyStatus::BadRequest);
            }
            let len = value.parse::<u64>().map_err(|_| ProxyStatus::BadRequest)?;
            if len > MAX_REQUEST_BODY_LEN {
                return Err(ProxyStatus::BadRequest);
            }
            content_length = Some(len);
            continue;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(ProxyStatus::NotImplemented);
        }
        if is_static_hop_by_hop_header(name) {
            continue;
        }
        let header_name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| ProxyStatus::BadRequest)?;
        let header_value = HeaderValue::from_str(value).map_err(|_| ProxyStatus::BadRequest)?;
        parsed.push((header_name, header_value));
    }

    parsed.retain(|(name, _)| {
        !connection_tokens
            .iter()
            .any(|token| token.eq_ignore_ascii_case(name.as_str()))
    });

    Ok((parsed, content_length.unwrap_or(0)))
}

async fn read_request_body_async<R>(guest: &mut R, len: u64) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let len = usize::try_from(len).map_err(|_| invalid_input("request body too large"))?;
    let mut body = vec![0u8; len];
    if len > 0 {
        guest.read_exact(&mut body).await?;
    }
    Ok(body)
}

#[cfg(target_os = "linux")]
fn read_request_body_blocking<R>(guest: &mut R, len: u64) -> std::io::Result<Vec<u8>>
where
    R: Read,
{
    let len = usize::try_from(len).map_err(|_| invalid_input("request body too large"))?;
    let mut body = vec![0u8; len];
    if len > 0 {
        guest.read_exact(&mut body)?;
    }
    Ok(body)
}

async fn send_host_request(
    request: &ForwardRequest,
    body: Vec<u8>,
    admitted_ip: IpAddr,
    admitted_port: u16,
    timeout: Duration,
) -> std::io::Result<reqwest::Response> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate()
        .connect_timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    if request.host.parse::<IpAddr>().is_err() {
        builder = builder.resolve_to_addrs(
            &request.host,
            &[SocketAddr::new(admitted_ip, admitted_port)],
        );
    }
    let client = builder.build().map_err(other)?;
    let method = reqwest::Method::from_bytes(request.method.as_bytes()).map_err(invalid_input)?;
    let mut req = client.request(method, request.url.clone());
    for (name, value) in &request.headers {
        req = req.header(name.clone(), value.clone());
    }
    if !body.is_empty() {
        req = req.body(body);
    }
    req.send().await.map_err(other)
}

#[cfg(target_os = "linux")]
fn send_host_request_blocking(
    request: &ForwardRequest,
    body: Vec<u8>,
    admitted_ip: IpAddr,
    admitted_port: u16,
    timeout: Duration,
) -> std::io::Result<reqwest::blocking::Response> {
    let mut builder = reqwest::blocking::Client::builder()
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate()
        .connect_timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    if request.host.parse::<IpAddr>().is_err() {
        builder = builder.resolve_to_addrs(
            &request.host,
            &[SocketAddr::new(admitted_ip, admitted_port)],
        );
    }
    let client = builder.build().map_err(other)?;
    let method = reqwest::Method::from_bytes(request.method.as_bytes()).map_err(invalid_input)?;
    let mut req = client.request(method, request.url.clone());
    for (name, value) in &request.headers {
        req = req.header(name.clone(), value.clone());
    }
    if !body.is_empty() {
        req = req.body(body);
    }
    req.send().map_err(other)
}

async fn write_upstream_response_async<W>(
    guest: &mut W,
    mut response: reqwest::Response,
    request_method: &str,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let status = response.status();
    let chunk_response = should_chunk_response_body(request_method, status, response.headers());
    write_response_head_async(guest, status, response.headers(), chunk_response).await?;
    guest.flush().await?;
    while let Some(chunk) = response.chunk().await.map_err(other)? {
        if chunk_response {
            write_chunk_async(guest, &chunk).await?;
        } else {
            guest.write_all(&chunk).await?;
        }
    }
    if chunk_response {
        guest.write_all(b"0\r\n\r\n").await?;
    }
    guest.flush().await
}

#[cfg(target_os = "linux")]
fn write_upstream_response_blocking<W>(
    guest: &mut W,
    mut response: reqwest::blocking::Response,
    request_method: &str,
) -> std::io::Result<()>
where
    W: Write,
{
    let status = response.status();
    let chunk_response = should_chunk_response_body(request_method, status, response.headers());
    write_response_head_blocking(guest, status, response.headers(), chunk_response)?;
    guest.flush()?;
    if chunk_response {
        let mut buf = [0u8; 8192];
        loop {
            let n = response.read(&mut buf)?;
            if n == 0 {
                break;
            }
            write_chunk_blocking(guest, &buf[..n])?;
        }
        guest.write_all(b"0\r\n\r\n")?;
    } else {
        std::io::copy(&mut response, guest)?;
    }
    guest.flush()
}

async fn write_response_head_async<W>(
    guest: &mut W,
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    chunk_response: bool,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let reason = status.canonical_reason().unwrap_or("");
    guest
        .write_all(format!("HTTP/1.1 {} {reason}\r\n", status.as_u16()).as_bytes())
        .await?;
    let connection_tokens = connection_tokens(headers);
    for (name, value) in headers {
        if should_strip_response_header(name.as_str(), &connection_tokens) {
            continue;
        }
        guest.write_all(name.as_str().as_bytes()).await?;
        guest.write_all(b": ").await?;
        guest.write_all(value.as_bytes()).await?;
        guest.write_all(b"\r\n").await?;
    }
    if chunk_response {
        guest.write_all(b"Transfer-Encoding: chunked\r\n").await?;
    }
    guest.write_all(b"Connection: close\r\n\r\n").await
}

#[cfg(target_os = "linux")]
fn write_response_head_blocking<W>(
    guest: &mut W,
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    chunk_response: bool,
) -> std::io::Result<()>
where
    W: Write,
{
    let reason = status.canonical_reason().unwrap_or("");
    guest.write_all(format!("HTTP/1.1 {} {reason}\r\n", status.as_u16()).as_bytes())?;
    let connection_tokens = connection_tokens(headers);
    for (name, value) in headers {
        if should_strip_response_header(name.as_str(), &connection_tokens) {
            continue;
        }
        guest.write_all(name.as_str().as_bytes())?;
        guest.write_all(b": ")?;
        guest.write_all(value.as_bytes())?;
        guest.write_all(b"\r\n")?;
    }
    if chunk_response {
        guest.write_all(b"Transfer-Encoding: chunked\r\n")?;
    }
    guest.write_all(b"Connection: close\r\n\r\n")
}

async fn write_chunk_async<W>(guest: &mut W, chunk: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    guest
        .write_all(format!("{:X}\r\n", chunk.len()).as_bytes())
        .await?;
    guest.write_all(chunk).await?;
    guest.write_all(b"\r\n").await
}

#[cfg(target_os = "linux")]
fn write_chunk_blocking<W>(guest: &mut W, chunk: &[u8]) -> std::io::Result<()>
where
    W: Write,
{
    guest.write_all(format!("{:X}\r\n", chunk.len()).as_bytes())?;
    guest.write_all(chunk)?;
    guest.write_all(b"\r\n")
}

async fn write_proxy_error_async<W>(guest: &mut W, status: ProxyStatus) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    guest
        .write_all(
            format!(
                "HTTP/1.1 {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                status.line()
            )
            .as_bytes(),
        )
        .await?;
    guest.flush().await
}

#[cfg(target_os = "linux")]
fn write_proxy_error_blocking<W>(guest: &mut W, status: ProxyStatus) -> std::io::Result<()>
where
    W: Write,
{
    guest.write_all(
        format!(
            "HTTP/1.1 {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            status.line()
        )
        .as_bytes(),
    )?;
    guest.flush()
}

fn connection_tokens(headers: &reqwest::header::HeaderMap) -> Vec<String> {
    headers
        .get_all(reqwest::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

fn should_strip_response_header(name: &str, connection_tokens: &[String]) -> bool {
    is_static_hop_by_hop_header(name)
        || connection_tokens
            .iter()
            .any(|token| token.eq_ignore_ascii_case(name))
}

fn should_chunk_response_body(
    request_method: &str,
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> bool {
    !request_method.eq_ignore_ascii_case("HEAD")
        && response_status_allows_body(status)
        && !headers.contains_key(reqwest::header::CONTENT_LENGTH)
}

fn response_status_allows_body(status: reqwest::StatusCode) -> bool {
    !status.is_informational()
        && status != reqwest::StatusCode::NO_CONTENT
        && status != reqwest::StatusCode::NOT_MODIFIED
}

fn is_static_hop_by_hop_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("host")
}

fn invalid_input<E>(error: E) -> std::io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
}

fn other<E>(error: E) -> std::io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    std::io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::network_policy::NetworkPolicy;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn parses_absolute_https_target_and_strips_proxy_headers() {
        let req = parse_forward_request(
            b"GET https://example.com/path?q=1 HTTP/1.1\r\nHost: wrong.example\r\nConnection: X-Drop\r\nX-Drop: gone\r\nProxy-Authorization: secret\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.target, "example.com:443");
        assert_eq!(req.url.as_str(), "https://example.com/path?q=1");
        assert_eq!(req.content_length, 0);
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.headers[0].0.as_str(), "accept");
    }

    #[test]
    fn rejects_origin_form_and_userinfo() {
        assert_eq!(
            parse_forward_request(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap_err(),
            ProxyStatus::BadRequest
        );
        assert_eq!(
            parse_forward_request(b"GET https://user@example.com/ HTTP/1.1\r\n\r\n").unwrap_err(),
            ProxyStatus::BadRequest
        );
    }

    #[test]
    fn rejects_chunked_request_body() {
        assert_eq!(
            parse_forward_request(
                b"POST https://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .unwrap_err(),
            ProxyStatus::NotImplemented
        );
    }

    #[test]
    fn response_header_filter_preserves_content_length() {
        assert!(!should_strip_response_header("content-length", &[]));
        assert!(should_strip_response_header("transfer-encoding", &[]));
        assert!(should_strip_response_header(
            "x-drop",
            &[String::from("x-drop")]
        ));
    }

    #[test]
    fn chunk_response_body_only_when_length_missing_and_body_allowed() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert!(should_chunk_response_body(
            "GET",
            reqwest::StatusCode::OK,
            &headers
        ));
        headers.insert(
            reqwest::header::CONTENT_LENGTH,
            HeaderValue::from_static("2"),
        );
        assert!(!should_chunk_response_body(
            "GET",
            reqwest::StatusCode::OK,
            &headers
        ));
        headers.clear();
        assert!(!should_chunk_response_body(
            "HEAD",
            reqwest::StatusCode::OK,
            &headers
        ));
        assert!(!should_chunk_response_body(
            "GET",
            reqwest::StatusCode::NO_CONTENT,
            &headers
        ));
    }

    #[tokio::test]
    async fn response_head_writes_explicit_chunked_framing_when_length_missing() {
        let headers = reqwest::header::HeaderMap::new();
        let (mut client, mut server) = tokio::io::duplex(512);
        let task = tokio::spawn(async move {
            write_response_head_async(&mut server, reqwest::StatusCode::OK, &headers, true)
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });

        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        let response = std::str::from_utf8(&buf).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Transfer-Encoding: chunked\r\n"));
        assert!(response.ends_with("Connection: close\r\n\r\n"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn denied_forward_request_returns_403_without_network() {
        let gate = EgressGate::default_deny();
        let (mut client, server) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            serve_http_forward(server, &gate, Duration::from_secs(1))
                .await
                .unwrap();
        });

        client
            .write_all(b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        let response = std::str::from_utf8(&buf).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 403 Forbidden"),
            "{response:?}"
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_forward_request_returns_400() {
        let gate = EgressGate::from_network_policy(
            &NetworkPolicy::unrestricted(),
            &mvm_core::policy::dns_pin::DnsPinRegistry::new(),
            "2026-01-01T00:00:00Z",
        );
        let (mut client, server) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            serve_http_forward(server, &gate, Duration::from_secs(1))
                .await
                .unwrap();
        });

        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        let response = std::str::from_utf8(&buf).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request"),
            "{response:?}"
        );
        task.await.unwrap();
    }
}
