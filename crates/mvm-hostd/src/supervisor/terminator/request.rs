//! Reconstruct a `ProxyRequest` (the substitution stack's input) from a raw
//! origin-form HTTP/1.1 request read off a terminated flow.
use crate::supervisor::network_endpoint_proxy::ProxyRequest;
use anyhow::{Context, Result, bail};

/// Build a request whose destination is the authority the flow was opened
/// against, refusing when the request's own `Host` header names a different
/// host.
///
/// This is the substitution-bypass check. The flow was admitted — by the
/// egress gate and by the bound-secret lookup — against the authority the
/// guest named when it opened the flow. Taking the destination from the
/// decrypted `Host` header instead would let a guest open a flow to a bound
/// host and then address the request somewhere else, which is the difference
/// between a credential going where policy says it may and going wherever the
/// request asks. A request with no `Host` header at all is refused rather than
/// defaulted to the authority: HTTP/1.1 requires one, and defaulting would
/// make the absence of the check indistinguishable from the check passing.
pub fn proxy_request_from_connect_authority(
    raw: &[u8],
    scheme: &str,
    authority_host: &str,
) -> Result<ProxyRequest> {
    let parsed = parse_origin_form(raw)?;
    let host = parsed
        .host
        .clone()
        .context("request carries no Host header")?;
    let host = host_without_port(&host);
    if !host.eq_ignore_ascii_case(authority_host) {
        bail!("request Host does not match the flow authority {authority_host:?}");
    }
    Ok(parsed.into_request(scheme, authority_host))
}

/// The method of a raw request, when its request line is readable.
///
/// Separate from the full parse because a request can be unservable for a
/// reason that has nothing to do with its method — a transfer-coded body, a
/// pipelined follow-up — and the refusal still has to know whether a body may
/// be written back.
pub fn method_of(raw: &[u8]) -> Option<&str> {
    let line_end = super::find_subslice(raw, b"\r\n")?;
    let line = std::str::from_utf8(&raw[..line_end]).ok()?;
    line.split(' ').next().filter(|method| !method.is_empty())
}

/// The `host` part of a `host[:port]` authority, brackets kept.
///
/// An IPv6 literal authority is bracketed — `[::1]:443` — so splitting on the
/// first colon yields `[`, which matches nothing and compares against nothing.
/// The bracketed form keeps its brackets, which is also the form
/// `parse_host_port` hands back for the flow authority, so the two agree.
/// A bare `::1` has no unambiguous port to strip and is returned whole, which
/// refuses with a reason rather than silently naming the wrong host.
fn host_without_port(host: &str) -> &str {
    if host.starts_with('[') {
        return match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        };
    }
    match host.rsplit_once(':') {
        Some((name, port))
            if !name.is_empty()
                && !name.contains(':')
                && !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            name
        }
        _ => host,
    }
}

/// One origin-form HTTP/1.1 request, split into the parts both destination
/// rules build a [`ProxyRequest`] from.
struct ParsedRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    host: Option<String>,
    body: Vec<u8>,
}

impl ParsedRequest {
    fn into_request(self, scheme: &str, host: &str) -> ProxyRequest {
        ProxyRequest {
            method: self.method,
            url: format!("{scheme}://{host}{}", self.target),
            headers: self.headers,
            body: self.body,
        }
    }
}

fn parse_origin_form(raw: &[u8]) -> Result<ParsedRequest> {
    let split =
        super::find_subslice(raw, b"\r\n\r\n").context("request has no header terminator")?;
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
    // Origin-form (`/path`) is what a client sends inside its tunnel;
    // absolute-form means a request addressed to a proxy, not to this flow.
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

    Ok(ParsedRequest {
        method: method.to_string(),
        target: target.to_string(),
        headers,
        host,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_authority_request_keeps_its_headers_in_order() {
        let raw = b"GET /v1/x HTTP/1.1\r\nhost: api.openai.com\r\nauthorization: Bearer mvm-secret-abc\r\n\r\n";
        let req = proxy_request_from_connect_authority(raw, "https", "api.openai.com").unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "https://api.openai.com/v1/x");
        assert_eq!(
            req.headers[1],
            ("authorization".into(), "Bearer mvm-secret-abc".into())
        );
    }

    #[test]
    fn rejects_absolute_form_target() {
        let raw = b"GET http://x/ HTTP/1.1\r\nhost: x\r\n\r\n";
        assert!(proxy_request_from_connect_authority(raw, "https", "x").is_err());
    }

    #[test]
    fn an_authority_request_takes_its_url_from_the_authority() {
        let raw = b"POST /v1/chat HTTP/1.1\r\nhost: api.openai.com:443\r\n\r\nbody";
        let req = proxy_request_from_connect_authority(raw, "https", "api.openai.com")
            .expect("a matching Host is accepted");
        assert_eq!(req.url, "https://api.openai.com/v1/chat");
        assert_eq!(req.body, b"body");
    }

    #[test]
    fn an_authority_request_matches_its_host_case_insensitively() {
        let raw = b"GET / HTTP/1.1\r\nHost: API.OpenAI.com\r\n\r\n";
        assert!(proxy_request_from_connect_authority(raw, "https", "api.openai.com").is_ok());
    }

    #[test]
    fn an_authority_request_with_a_different_host_is_refused() {
        let raw = b"GET /steal HTTP/1.1\r\nhost: attacker.example\r\n\r\n";
        assert!(proxy_request_from_connect_authority(raw, "https", "api.openai.com").is_err());
    }

    #[test]
    fn an_authority_request_without_a_host_header_is_refused() {
        let raw = b"GET / HTTP/1.1\r\naccept: */*\r\n\r\n";
        assert!(proxy_request_from_connect_authority(raw, "https", "api.openai.com").is_err());
    }

    /// A bracketed IPv6 authority keeps its brackets, which is the form
    /// `parse_host_port` hands back, so the two agree instead of comparing
    /// `[` against an address.
    #[test]
    fn the_method_is_readable_without_a_full_parse() {
        assert_eq!(
            method_of(b"HEAD /x HTTP/1.1\r\nhost: y\r\n\r\n"),
            Some("HEAD")
        );
        assert_eq!(method_of(b"POST /x HTTP/1.1\r\n\r\n"), Some("POST"));
        // No request line yet, and a leading space is not a method.
        assert_eq!(method_of(b"GET /x HTTP/1.1"), None);
        assert_eq!(method_of(b" /x HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn a_bracketed_ipv6_authority_keeps_its_brackets() {
        assert_eq!(host_without_port("[::1]:443"), "[::1]");
        assert_eq!(host_without_port("[2001:db8::1]"), "[2001:db8::1]");
        let raw = b"GET / HTTP/1.1\r\nhost: [::1]:443\r\n\r\n";
        let req = proxy_request_from_connect_authority(raw, "https", "[::1]")
            .expect("a bracketed literal matches its own authority");
        assert_eq!(req.url, "https://[::1]/");
    }

    #[test]
    fn an_unbracketed_ipv6_literal_is_not_cut_at_its_last_colon() {
        assert_eq!(host_without_port("::1"), "::1");
        assert_eq!(host_without_port("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn a_named_host_still_loses_its_port() {
        assert_eq!(host_without_port("api.openai.com:443"), "api.openai.com");
        assert_eq!(host_without_port("api.openai.com"), "api.openai.com");
        // A trailing colon with no digits is not a port.
        assert_eq!(host_without_port("api.openai.com:"), "api.openai.com:");
    }
}
