//! Reconstruct a `ProxyRequest` (the substitution stack's input) from a raw
//! origin-form HTTP/1.1 request the terminator read off a redirected socket.
use crate::supervisor::substitution_proxy::ProxyRequest;
use anyhow::{Context, Result, bail};
use std::net::SocketAddr;

pub fn proxy_request_from_origin_form(raw: &[u8], orig_dst: SocketAddr) -> Result<ProxyRequest> {
    let split = find_subslice(raw, b"\r\n\r\n").context("request has no header terminator")?;
    let head = std::str::from_utf8(&raw[..split]).context("request head not UTF-8")?;
    let body = raw[split + 4..].to_vec();

    let mut lines = head.split("\r\n");
    let request_line = lines.next().context("empty request")?;
    let mut parts = request_line.split(' ');
    let method = parts
        .next()
        .filter(|m| !m.is_empty())
        .context("no method")?;
    let target = parts.next().context("no request target")?;
    let version = parts.next().context("no HTTP version")?;
    if !version.starts_with("HTTP/") {
        bail!("malformed request line: {request_line:?}");
    }
    // Origin-form (`/path`) is the transparent path; absolute-form means a
    // proxy-configured client, not ours.
    if !target.starts_with('/') {
        bail!("expected origin-form target, got {target:?}");
    }

    let mut headers = Vec::new();
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .with_context(|| format!("malformed header: {line:?}"))?;
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("host") {
            host = Some(value.to_string());
        }
        headers.push((name.to_string(), value.to_string()));
    }

    // The Host header is the name the guest dialed — `prepare_request`'s
    // claim-12 bind-check keys on it. Fall back to the original-dst IP (HTTP/1.0).
    let host = host.unwrap_or_else(|| orig_dst.ip().to_string());
    let host_no_port = host.split(':').next().unwrap_or(&host);
    let url = format!("http://{host_no_port}{target}");
    Ok(ProxyRequest {
        method: method.to_string(),
        url,
        headers,
        body,
    })
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    #[test]
    fn builds_proxy_request_url_from_host_header() {
        let raw = b"GET /v1/x HTTP/1.1\r\nhost: api.openai.com\r\nauthorization: Bearer mvm-secret-abc\r\n\r\n";
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 80));
        let req = proxy_request_from_origin_form(raw, dst).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "http://api.openai.com/v1/x");
        assert_eq!(
            req.headers[1],
            ("authorization".into(), "Bearer mvm-secret-abc".into())
        );
    }

    #[test]
    fn rejects_absolute_form_target() {
        let raw = b"GET http://x/ HTTP/1.1\r\nhost: x\r\n\r\n";
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 80));
        assert!(proxy_request_from_origin_form(raw, dst).is_err());
    }
}
