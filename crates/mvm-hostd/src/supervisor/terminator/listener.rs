//! The forward leg of the transparent egress terminator: serialize a prepared
//! (credential-substituted) request back to origin-form HTTP/1.1 and splice it
//! to the real destination, returning the response bytes verbatim.
//!
//! Stage 1b is `http` only. We forward over a raw TCP stream rather than a
//! reqwest round-trip so the destination's response (chunked encoding,
//! trailers, exact header casing) reaches the guest BYTE-FOR-BYTE — a reqwest
//! decode-then-reserialize would mangle it. TLS termination (https) is Stage 2.
//!
//! The accept loop that drives this (`SubstitutionService::serve_terminator`)
//! is Linux-only (it needs `SO_ORIGINAL_DST`) and lives in
//! `substitution_proxy.rs` so it can reuse the service's private registry /
//! resolver / recorder. These serializer + splice helpers are pure and stay
//! unit-testable on every host.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use url::Url;

use crate::supervisor::substitution_proxy::PreparedRequest;

/// 16 MiB cap on a single destination response — mirrors `read.rs`'s request
/// bound so a hostile/buggy upstream can't drive an unbounded host allocation.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Connect + read timeout for the forward leg, matching the endpoint's default
/// `forward_timeout_secs`.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(30);

/// Serialize a [`PreparedRequest`] back to an origin-form HTTP/1.1 request: the
/// request line carries only the path+query (derived from `req.url`), and we
/// force `Connection: close` so the upstream closes after responding and the
/// splice can read the body to EOF without parsing framing.
pub fn prepared_to_origin_form_bytes(req: &PreparedRequest) -> Result<Vec<u8>> {
    let url =
        Url::parse(&req.url).with_context(|| format!("prepared url not parseable: {}", req.url))?;
    let mut target = url.path().to_string();
    if let Some(q) = url.query() {
        target.push('?');
        target.push_str(q);
    }

    let mut out = Vec::with_capacity(256 + req.body.len());
    out.extend_from_slice(format!("{} {} HTTP/1.1\r\n", req.method, target).as_bytes());
    // Drop any guest-supplied Connection header; we dictate the framing.
    for (name, value) in &req.headers {
        if name.eq_ignore_ascii_case("connection") {
            continue;
        }
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(&req.body);
    Ok(out)
}

/// Forward `req` to `orig_dst` over a raw TCP splice and return the response
/// bytes verbatim. This is the `forward` closure handed to
/// [`super::handler::handle_request`]; substitution + the claim-12 bind-check
/// have already run by the time we're called.
pub fn forward_http_raw(req: &PreparedRequest, orig_dst: SocketAddr) -> Result<Vec<u8>> {
    let wire = prepared_to_origin_form_bytes(req)?;

    let mut stream = TcpStream::connect_timeout(&orig_dst, FORWARD_TIMEOUT)
        .with_context(|| format!("connecting to forward destination {orig_dst}"))?;
    stream.set_read_timeout(Some(FORWARD_TIMEOUT))?;
    stream.set_write_timeout(Some(FORWARD_TIMEOUT))?;
    stream
        .write_all(&wire)
        .context("writing forwarded request")?;
    stream.flush().ok();

    // Read to EOF (upstream closes after the response — we forced
    // `Connection: close`), bounded so a runaway upstream can't OOM the host.
    let mut resp = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream
            .read(&mut chunk)
            .context("reading forward response")?;
        if n == 0 {
            break;
        }
        if resp.len() + n > MAX_RESPONSE_BYTES {
            bail!("forward response exceeds {MAX_RESPONSE_BYTES} bytes");
        }
        resp.extend_from_slice(&chunk[..n]);
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn req(method: &str, url: &str, headers: &[(&str, &str)], body: &[u8]) -> PreparedRequest {
        PreparedRequest {
            method: method.into(),
            url: url.into(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_vec(),
        }
    }

    #[test]
    fn serializes_get_to_origin_form_with_connection_close() {
        let r = req(
            "GET",
            "http://api.openai.com/v1/x?q=1",
            &[("host", "api.openai.com"), ("authorization", "Bearer REAL")],
            b"",
        );
        let bytes = prepared_to_origin_form_bytes(&r).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        // Origin-form path+query derived from the url (not the absolute url).
        assert_eq!(
            text,
            "GET /v1/x?q=1 HTTP/1.1\r\nhost: api.openai.com\r\nauthorization: Bearer REAL\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn drops_guest_connection_header_and_forces_close() {
        let r = req(
            "POST",
            "http://h/p",
            &[("connection", "keep-alive"), ("content-length", "2")],
            b"{}",
        );
        let text = String::from_utf8(prepared_to_origin_form_bytes(&r).unwrap()).unwrap();
        // The guest's keep-alive is gone; exactly one Connection header, = close.
        assert_eq!(text.matches("Connection").count(), 1);
        assert!(text.contains("Connection: close\r\n"));
        assert!(!text.contains("keep-alive"));
        assert!(text.ends_with("\r\n\r\n{}"));
    }

    #[test]
    fn forward_http_raw_round_trips_against_a_loopback_destination() {
        // A one-shot upstream: accept, drain the request, write a canned reply,
        // close (signalling EOF so the splice's read-to-EOF terminates).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            // Read until the request header terminator so we don't reply early.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = conn.read(&mut chunk).unwrap();
                buf.extend_from_slice(&chunk[..n]);
                if n == 0 || buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                .unwrap();
            // drop(conn) closes the write side → EOF for the forwarder.
            buf
        });

        let r = req(
            "GET",
            &format!("http://127.0.0.1:{}/v1/x", addr.port()),
            &[("host", "x")],
            b"",
        );
        let resp = forward_http_raw(&r, addr).unwrap();
        let got = server.join().unwrap();

        // The upstream received our forwarded origin-form request.
        let sent = String::from_utf8(got).unwrap();
        assert!(sent.starts_with("GET /v1/x HTTP/1.1\r\n"), "got: {sent:?}");
        // The forwarder returned the canned response verbatim.
        assert_eq!(resp, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
    }
}
