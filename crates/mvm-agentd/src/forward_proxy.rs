//! The in-guest forward-proxy front (substitution model ii).
//!
//! The workload points `HTTP_PROXY`/`HTTPS_PROXY` (or the SDK's thin client) at
//! this guest-local proxy and makes ordinary requests carrying an opaque
//! placeholder (from `mvm.secret()`) where a credential goes. The proxy parses
//! the proxied request into a `WireRequest` and relays it to the host
//! substitution endpoint over FlowMux ([`crate::flowmux_sync`]); the host substitutes
//! the real credential and makes the **real TLS** upstream (model ii — no
//! in-guest TLS MITM). This module is the request parser; the listen/relay loop
//! sits on top.
//!
//! Proxied requests are **absolute-form**: the request target is the full URL
//! (`POST https://api.openai.com/v1 HTTP/1.1`), so the proxy learns the real
//! destination — including its `https` scheme — without terminating any TLS.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_core::substitution_wire::{WireRequest, WireResponse};

/// Guest-local TCP port the forward proxy listens on; the workload's
/// `HTTP_PROXY`/`HTTPS_PROXY` points here. Loopback-only — never exposed off the
/// guest. Distinct from the vsock ports in [`crate::vsock`].
pub const FORWARD_PROXY_PORT: u16 = 18080;

/// The `HTTP_PROXY` value the workload's env is set to.
pub fn proxy_env_url() -> String {
    format!("http://127.0.0.1:{FORWARD_PROXY_PORT}")
}

/// Cap on a single proxied request we'll buffer (defensive — the workload is
/// our own tenant, but a runaway request shouldn't OOM the proxy).
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

/// Headers the proxy must not pass through verbatim: they describe *this*
/// hop's framing, which we re-derive (fixed body, `connection: close`).
const HOP_BY_HOP: &[&str] = &["content-length", "transfer-encoding", "connection"];

/// Parse one absolute-form HTTP/1.1 proxied request into a [`WireRequest`].
/// The body (after the blank line) is taken per `Content-Length` when present,
/// else the remaining bytes; it is base64-encoded into `body_b64`.
pub fn parse_proxied_request(raw: &[u8]) -> Result<WireRequest> {
    let split = find_subslice(raw, b"\r\n\r\n").context("request has no header terminator")?;
    let head = std::str::from_utf8(&raw[..split]).context("request head is not UTF-8")?;
    let body = &raw[split + 4..];

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
    // Proxy requests carry the full URL (absolute-form). Origin-form (`/path`)
    // would hide the destination — refuse it rather than guess a host.
    if !(target.starts_with("http://") || target.starts_with("https://")) {
        bail!("proxied request target must be absolute (http(s)://…), got {target:?}");
    }

    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .with_context(|| format!("malformed header line: {line:?}"))?;
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().ok();
        }
        headers.push((name.to_string(), value.to_string()));
    }

    // Honor Content-Length when present (a pipelined next request may trail the
    // body); otherwise take the rest. Guard the slice so a bogus length can't
    // panic.
    let body = match content_length {
        Some(n) if n <= body.len() => &body[..n],
        _ => body,
    };

    Ok(WireRequest {
        method: method.to_string(),
        url: target.to_string(),
        headers,
        body_b64: B64.encode(body),
    })
}

/// Render a host [`WireResponse`] as an HTTP/1.1 response for the workload.
/// The destination's status + headers pass through; framing headers are
/// re-derived (`content-length` from the actual body, `connection: close`) so
/// the workload's client reads a well-formed, self-delimiting response. A
/// `Refused` (unbound destination, unknown placeholder) becomes a `502`.
pub fn render_response(resp: &WireResponse) -> Result<Vec<u8>> {
    let (status, passthrough, body) = match resp {
        WireResponse::Ok {
            status,
            headers,
            body_b64,
        } => {
            let body = B64
                .decode(body_b64)
                .context("response body is not base64")?;
            (*status, headers.as_slice(), body)
        }
        WireResponse::Refused { message } => {
            // The substitution endpoint refused — surface it as a gateway error.
            (
                502u16,
                [].as_slice(),
                format!("substitution refused: {message}").into_bytes(),
            )
        }
    };

    let mut out = format!("HTTP/1.1 {status} {}\r\n", reason_phrase(status)).into_bytes();
    for (name, value) in passthrough {
        if HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h)) {
            continue;
        }
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"connection: close\r\n\r\n");
    out.extend_from_slice(&body);
    Ok(out)
}

/// A minimal reason phrase. Clients ignore it, but a real word reads better in
/// logs than an empty token; unknown codes get a generic phrase.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// Environment variable naming the host substitution endpoint's Unix
/// socket on the shared-kernel container tier: the endpoint lives on a
/// host-owned directory bind-mounted into the container, so the forward
/// proxy relays to it over AF_UNIX instead of the vsock `EGRESS_PORT` (a
/// container has no vsock). Unset on microVM backends, which keep the
/// vsock path.
pub const EGRESS_ENDPOINT_SOCK_ENV: &str = "MVM_AGENT_EGRESS_ENDPOINT_SOCK";

/// The bind-mounted substitution-endpoint socket a shared-kernel container
/// relays egress through, when the host backend configured one. `None` on
/// microVM backends and on container boots with no endpoint (no bound
/// secrets and a deny-egress policy), where every proxied request must
/// fail closed rather than silently bypass the gate.
pub fn egress_endpoint_socket() -> Option<std::path::PathBuf> {
    let path = std::env::var(EGRESS_ENDPOINT_SOCK_ENV).ok()?;
    (!path.is_empty()).then_some(std::path::PathBuf::from(path))
}

/// Start the guest-local forward proxy: bind loopback [`FORWARD_PROXY_PORT`] and
/// serve, relaying each request to the host substitution endpoint — over a
/// guest→host AF_VSOCK connection on microVM backends, or over the
/// bind-mounted endpoint Unix socket on the shared-kernel container tier.
/// Blocks; the guest init runs it on its own
/// thread. This is the production entry point — `serve` +
/// `flowmux_sync::SyncFlowMux::exchange_http` are the unit-tested parts it
/// composes.
pub fn start_forward_proxy(relay_timeout_secs: u64) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", FORWARD_PROXY_PORT))
        .with_context(|| format!("binding forward proxy on 127.0.0.1:{FORWARD_PROXY_PORT}"))?;
    let timeout = std::time::Duration::from_secs(relay_timeout_secs.max(1));
    serve(&listener, move |req| {
        // One session per request, torn down after it. A workload's proxied
        // requests are independent and infrequent, so the handshake cost buys
        // a simpler failure model than a shared session that has to be
        // re-established under the proxy's feet.
        let mut flowmux = crate::flowmux_sync::SyncFlowMux::connect()?;
        flowmux.set_read_timeout(timeout)?;
        flowmux.exchange_http(req)
    })
}

/// Serve the guest-local forward proxy on `listener`: for each connection, read
/// one proxied request, relay it to the host substitution endpoint via `relay`,
/// and write the response back (`connection: close`, one request per
/// connection). `relay` is injected — production passes a closure over
/// [`crate::flowmux_sync::SyncFlowMux::exchange_http`]; tests pass a mock host.
///
/// A bad request or a relay error becomes a `502` to the workload, never a
/// panic; the accept loop keeps running.
pub fn serve<R>(listener: &TcpListener, relay: R) -> Result<()>
where
    R: Fn(&WireRequest) -> Result<WireResponse>,
{
    for conn in listener.incoming() {
        let mut stream = conn.context("accept on forward-proxy listener")?;
        if let Err(e) = handle_connection(&mut stream, &relay) {
            tracing::warn!(error = %e, "forward-proxy connection failed");
        }
    }
    Ok(())
}

fn handle_connection<R>(stream: &mut TcpStream, relay: &R) -> Result<()>
where
    R: Fn(&WireRequest) -> Result<WireResponse>,
{
    let raw = read_http_request(stream)?;
    // A parse failure or a relay error is surfaced to the workload as a 502 —
    // never the host's internals, never a panic.
    //
    // Logged as well as answered generically. A relay that cannot open its session fails
    // every request identically, and a `502` a client reports as "Bad Gateway"
    // without its body is indistinguishable from a destination the policy
    // refused. Whoever is reading the guest console should see which it was.
    //
    // The full chain belongs only in the trusted guest log. Returning it to an
    // untrusted workload would disclose filesystem and endpoint details.
    let resp = match parse_proxied_request(&raw) {
        Ok(req) => relay(&req).unwrap_or_else(|e| {
            tracing::warn!(error = format!("{e:#}"), "forward-proxy relay failed");
            WireResponse::Refused {
                message: "forward proxy relay failed".to_string(),
            }
        }),
        Err(e) => WireResponse::Refused {
            message: format!("bad proxied request: {e:#}"),
        },
    };
    let out = render_response(&resp)?;
    stream.write_all(&out).context("writing proxy response")?;
    stream.flush().ok();
    Ok(())
}

/// Read one full HTTP/1.1 request off `stream`: headers up to `\r\n\r\n`, then
/// the `Content-Length` body (if any). Bounded by [`MAX_REQUEST_BYTES`].
fn read_http_request(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];

    // 1. Read until the header terminator.
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_REQUEST_BYTES {
            bail!("proxied request headers exceed {MAX_REQUEST_BYTES} bytes");
        }
        let n = stream.read(&mut chunk).context("reading request headers")?;
        if n == 0 {
            bail!("connection closed before request headers completed");
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    // 2. Read the Content-Length body, if any.
    let content_length = content_length_of(&buf[..header_end]);
    if let Some(len) = content_length {
        let have = buf.len() - header_end;
        let mut remaining = len.saturating_sub(have);
        while remaining > 0 {
            if buf.len() > MAX_REQUEST_BYTES {
                bail!("proxied request body exceeds {MAX_REQUEST_BYTES} bytes");
            }
            let n = stream.read(&mut chunk).context("reading request body")?;
            if n == 0 {
                bail!("connection closed before Content-Length body completed");
            }
            buf.extend_from_slice(&chunk[..n]);
            remaining = remaining.saturating_sub(n);
        }
    }
    Ok(buf)
}

/// Parse a `Content-Length` value out of an already-read header block.
fn content_length_of(head: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n")
        .skip(1) // request line
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
}

/// First index of `needle` in `haystack`, or `None`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_endpoint_socket_reads_the_env_only_when_set_and_non_empty() {
        let mut env = mvm_core::util::test_env::TestEnv::new();

        env.remove(EGRESS_ENDPOINT_SOCK_ENV);
        assert_eq!(egress_endpoint_socket(), None);
        env.set(EGRESS_ENDPOINT_SOCK_ENV, "");
        assert_eq!(egress_endpoint_socket(), None);
        env.set(
            EGRESS_ENDPOINT_SOCK_ENV,
            "/run/mvm/substitution-endpoint.sock",
        );
        assert_eq!(
            egress_endpoint_socket(),
            Some(std::path::PathBuf::from(
                "/run/mvm/substitution-endpoint.sock"
            ))
        );
    }

    #[test]
    fn parses_a_get_with_absolute_url_and_headers() {
        let raw = b"GET http://api.example.com/v1/x HTTP/1.1\r\n\
                    host: api.example.com\r\n\
                    authorization: Bearer mvm-secret-abc\r\n\r\n";
        let req = parse_proxied_request(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "http://api.example.com/v1/x");
        assert_eq!(
            req.headers,
            vec![
                ("host".to_string(), "api.example.com".to_string()),
                (
                    "authorization".to_string(),
                    "Bearer mvm-secret-abc".to_string()
                ),
            ]
        );
        assert_eq!(req.body_b64, "");
    }

    #[test]
    fn parses_an_https_post_with_a_body() {
        let raw = b"POST https://api.openai.com/v1 HTTP/1.1\r\n\
                    content-type: application/json\r\n\
                    content-length: 2\r\n\r\n\
                    {}";
        let req = parse_proxied_request(raw).unwrap();
        assert_eq!(req.method, "POST");
        // The real https destination survives — the proxy makes no TLS itself.
        assert_eq!(req.url, "https://api.openai.com/v1");
        assert_eq!(B64.decode(&req.body_b64).unwrap(), b"{}");
    }

    #[test]
    fn honors_content_length_and_drops_trailing_bytes() {
        // A pipelined second request trails the first body; only `len` is taken.
        let raw = b"POST https://x/y HTTP/1.1\r\ncontent-length: 3\r\n\r\nabcGET https://x/z HTTP/1.1\r\n\r\n";
        let req = parse_proxied_request(raw).unwrap();
        assert_eq!(B64.decode(&req.body_b64).unwrap(), b"abc");
    }

    #[test]
    fn rejects_origin_form_target() {
        let raw = b"GET /v1/x HTTP/1.1\r\nhost: api.example.com\r\n\r\n";
        assert!(parse_proxied_request(raw).is_err());
    }

    #[test]
    fn rejects_request_without_header_terminator() {
        let raw = b"GET http://x/ HTTP/1.1\r\nhost: x\r\n";
        assert!(parse_proxied_request(raw).is_err());
    }

    #[test]
    fn rejects_a_malformed_request_line() {
        let raw = b"GARBAGE\r\n\r\n";
        assert!(parse_proxied_request(raw).is_err());
    }

    #[test]
    fn an_oversized_content_length_does_not_panic() {
        let raw = b"POST https://x/y HTTP/1.1\r\ncontent-length: 9999\r\n\r\nshort";
        // Falls back to the actual remaining bytes rather than slicing OOB.
        let req = parse_proxied_request(raw).unwrap();
        assert_eq!(B64.decode(&req.body_b64).unwrap(), b"short");
    }

    #[test]
    fn renders_an_ok_response_with_recomputed_framing() {
        let resp = WireResponse::Ok {
            status: 200,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                // Stale framing headers from the destination must be dropped.
                ("content-length".into(), "999".into()),
                ("transfer-encoding".into(), "chunked".into()),
            ],
            body_b64: B64.encode(b"pong"),
        };
        let out = String::from_utf8(render_response(&resp).unwrap()).unwrap();
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "got: {out}");
        assert!(out.contains("content-type: application/json\r\n"));
        assert!(out.contains("content-length: 4\r\n")); // recomputed for "pong"
        assert!(!out.contains("999"), "stale content-length must be dropped");
        assert!(!out.to_lowercase().contains("transfer-encoding"));
        assert!(out.ends_with("\r\n\r\npong"));
    }

    #[test]
    fn renders_a_refusal_as_502() {
        let out = String::from_utf8(
            render_response(&WireResponse::Refused {
                message: "destination not bound".into(),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(
            out.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "got: {out}"
        );
        assert!(out.ends_with("substitution refused: destination not bound"));
    }

    #[test]
    fn proxy_env_url_is_loopback_on_the_proxy_port() {
        assert_eq!(proxy_env_url(), "http://127.0.0.1:18080");
        assert_eq!(FORWARD_PROXY_PORT, 18080);
    }

    /// A relay error must be actionable without exposing the privileged
    /// process's filesystem or endpoint details to the workload.
    #[test]
    fn a_relay_failure_is_reported_without_exposing_its_cause() {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::thread;

        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping proxy relay-failure test: {err}");
                return;
            }
            Err(err) => panic!("proxy test listener bind failed: {err}"),
        };
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let mut conn = listener.accept().unwrap().0;
            let relay = |_: &WireRequest| -> Result<WireResponse> {
                Err(anyhow::anyhow!("Permission denied (os error 13)")
                    .context("reading the guest signing key"))
            };
            handle_connection(&mut conn, &relay).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(b"GET http://api.example.com/ HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        server.join().unwrap();

        assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
        assert!(
            resp.contains("forward proxy relay failed"),
            "the workload still needs an actionable failure class: {resp}"
        );
        assert!(
            !resp.contains("reading the guest signing key") && !resp.contains("Permission denied"),
            "privileged relay details must stay in the guest log: {resp}"
        );
    }

    #[test]
    fn serve_relays_a_request_and_writes_back_the_response() {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::sync::mpsc;
        use std::thread;

        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping proxy relay test: {err}");
                return;
            }
            Err(err) => panic!("proxy test listener bind failed: {err}"),
        };
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();

        // Proxy thread: serve exactly one connection via a mock relay that
        // records the request it saw and returns a canned 200.
        let server = thread::spawn(move || {
            let conn = listener.accept().unwrap().0;
            let relay = |req: &WireRequest| {
                tx.send(req.clone()).unwrap();
                Ok(WireResponse::Ok {
                    status: 200,
                    headers: vec![],
                    body_b64: B64.encode(b"pong"),
                })
            };
            // Drive one connection through the same path `serve` uses.
            let mut conn = conn;
            handle_connection(&mut conn, &relay).unwrap();
        });

        // Client: a workload speaking absolute-form HTTP to the proxy.
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(
                b"POST https://api.openai.com/v1 HTTP/1.1\r\n\
                  authorization: Bearer mvm-secret-abc\r\n\
                  content-length: 2\r\n\r\n{}",
            )
            .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();

        // The relay saw the placeholder-bearing request with the real https URL.
        let seen = rx.recv().unwrap();
        assert_eq!(seen.url, "https://api.openai.com/v1");
        assert_eq!(
            seen.headers[0],
            ("authorization".into(), "Bearer mvm-secret-abc".into())
        );
        assert_eq!(B64.decode(&seen.body_b64).unwrap(), b"{}");
        // The workload got the rendered 200.
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "got: {resp}");
        assert!(resp.ends_with("\r\n\r\npong"));
        server.join().unwrap();
    }
}
