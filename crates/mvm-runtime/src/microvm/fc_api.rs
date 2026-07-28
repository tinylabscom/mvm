//! Native HTTP/1.1 client for the Firecracker API socket.
//!
//! Firecracker speaks plain HTTP/1.1 over a Unix domain socket. Every call was
//! previously a `curl` subprocess; on the warm-restore path that is four
//! process spawns (pause, snapshot create, read device model, resume) in the
//! critical section, which is a meaningful share of the restore latency budget.
//!
//! This talks to the socket directly. The wire format is small enough to build
//! and parse by hand, so it costs no dependency: one request per connection
//! with `Connection: close`, which means the response body is "everything until
//! EOF" and no keep-alive or chunked-transfer state machine is needed.
//!
//! Request building and response parsing are pure functions so the wire format
//! is unit-testable without a live VMM.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// How long to wait on connect/read/write before giving up.
///
/// A live Firecracker answers these calls in well under a millisecond. This
/// only exists so a wedged VMM surfaces as an error instead of hanging the
/// caller forever — `curl` had no timeout here, so this is strictly tighter.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// A parsed Firecracker API response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FcResponse {
    pub(crate) status: u16,
    pub(crate) body: String,
}

impl FcResponse {
    /// Firecracker uses conventional HTTP status classes: 2xx on success,
    /// 4xx for a malformed or rejected request, 5xx for an internal fault.
    fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Serialize a request. `body` is sent as JSON when present.
///
/// `Connection: close` is deliberate — it lets the reader treat EOF as the end
/// of the body rather than tracking keep-alive framing.
fn build_request(method: &str, path: &str, body: Option<&str>) -> Vec<u8> {
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n"
    );
    if let Some(body) = body {
        req.push_str("Content-Type: application/json\r\n");
        // Length in bytes, not chars — a multi-byte body would otherwise be
        // truncated by the server.
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    let mut out = req.into_bytes();
    if let Some(body) = body {
        out.extend_from_slice(body.as_bytes());
    }
    out
}

/// Parse a raw HTTP/1.1 response into its status and body.
///
/// Tolerates a body that is absent (204 and most Firecracker PUTs) and does not
/// require `Content-Length`, since the connection close delimits the body.
fn parse_response(raw: &[u8]) -> Result<FcResponse> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP response: no header/body separator")?;
    let head = std::str::from_utf8(&raw[..split])
        .context("malformed HTTP response: headers are not valid UTF-8")?;
    let body = String::from_utf8_lossy(&raw[split + 4..]).into_owned();

    let status_line = head
        .lines()
        .next()
        .context("malformed HTTP response: empty status line")?;
    // "HTTP/1.1 204 No Content" -> 204
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .context("malformed HTTP response: status line has no code")?
        .parse()
        .with_context(|| format!("malformed HTTP response: bad status line {status_line:?}"))?;

    Ok(FcResponse { status, body })
}

/// Send one request to the Firecracker API socket and read the response.
///
/// Returns the parsed response whatever the status — status interpretation is
/// the caller's job via [`call`].
fn round_trip(socket: &Path, method: &str, path: &str, body: Option<&str>) -> Result<FcResponse> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connecting to Firecracker API socket {}", socket.display()))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .with_context(|| "setting Firecracker API socket timeouts")?;

    stream
        .write_all(&build_request(method, path, body))
        .with_context(|| format!("sending {method} {path} to Firecracker"))?;
    stream
        .flush()
        .with_context(|| format!("flushing {method} {path} to Firecracker"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .with_context(|| format!("reading Firecracker response to {method} {path}"))?;

    parse_response(&raw).with_context(|| format!("parsing Firecracker response to {method} {path}"))
}

/// Call the Firecracker API, failing on any non-2xx status.
///
/// Returns the response body so callers that need it (`GET /vm/config`) can
/// parse it; callers that don't can discard it.
pub(crate) fn call(socket: &Path, method: &str, path: &str, body: Option<&str>) -> Result<String> {
    let resp = round_trip(socket, method, path, body)?;
    if !resp.is_success() {
        bail!("{method} {path} failed: HTTP {} {}", resp.status, resp.body);
    }
    Ok(resp.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::os::unix::net::UnixListener;

    #[test]
    fn build_request_without_body_sends_no_content_length() {
        let req = String::from_utf8(build_request("GET", "/vm/config", None)).unwrap();
        assert!(
            req.starts_with("GET /vm/config HTTP/1.1\r\n"),
            "got: {req:?}"
        );
        assert!(!req.contains("Content-Length"), "got: {req:?}");
        assert!(req.ends_with("\r\n\r\n"), "headers must terminate: {req:?}");
    }

    #[test]
    fn build_request_with_body_sets_json_content_type_and_length() {
        let body = r#"{"state":"Paused"}"#;
        let req = String::from_utf8(build_request("PATCH", "/vm", Some(body))).unwrap();
        assert!(
            req.contains("Content-Type: application/json\r\n"),
            "got: {req:?}"
        );
        assert!(
            req.contains(&format!("Content-Length: {}\r\n", body.len())),
            "got: {req:?}"
        );
        assert!(req.ends_with(body), "body must be appended: {req:?}");
    }

    /// Content-Length counts bytes. A char count would truncate the body
    /// server-side and the request would hang or be rejected.
    #[test]
    fn build_request_content_length_counts_bytes_not_chars() {
        let body = r#"{"note":"café"}"#;
        assert_ne!(
            body.len(),
            body.chars().count(),
            "fixture must be multi-byte"
        );
        let req = String::from_utf8(build_request("PUT", "/x", Some(body))).unwrap();
        assert!(
            req.contains(&format!("Content-Length: {}\r\n", body.len())),
            "got: {req:?}"
        );
    }

    #[test]
    fn parse_response_reads_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"vcpu_count\":2}";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, r#"{"vcpu_count":2}"#);
    }

    /// Firecracker answers most PUT/PATCH calls with an empty 204.
    #[test]
    fn parse_response_handles_empty_body() {
        let resp = parse_response(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert_eq!(resp.status, 204);
        assert_eq!(resp.body, "");
        assert!(resp.is_success());
    }

    #[test]
    fn parse_response_surfaces_error_status() {
        let raw = b"HTTP/1.1 400 Bad Request\r\n\r\n{\"fault_message\":\"nope\"}";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 400);
        assert!(!resp.is_success());
    }

    #[test]
    fn parse_response_rejects_garbage() {
        assert!(parse_response(b"not http at all").is_err());
        assert!(
            parse_response(b"HTTP/1.1\r\n\r\n").is_err(),
            "no status code"
        );
    }

    /// Serve one canned response on a real Unix socket, so the client is
    /// exercised end to end — connect, write, read, parse — without a VMM.
    fn serve_once(
        dir: &Path,
        response: &'static str,
    ) -> (std::path::PathBuf, std::thread::JoinHandle<String>) {
        let sock = dir.join("fc.socket");
        let listener = UnixListener::bind(&sock).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            // Read just the request head; the client sends Connection: close
            // but keeps the socket open for the reply.
            let mut reader = std::io::BufReader::new(conn.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                request.push_str(&line);
            }
            conn.write_all(response.as_bytes()).unwrap();
            conn.flush().unwrap();
            drop(conn);
            request
        });
        (sock, handle)
    }

    #[test]
    fn call_round_trips_against_a_real_socket() {
        let dir = tempfile::tempdir().unwrap();
        let (sock, server) =
            serve_once(dir.path(), "HTTP/1.1 200 OK\r\n\r\n{\"machine-config\":{}}");

        let body = call(&sock, "GET", "/vm/config", None).unwrap();
        assert_eq!(body, r#"{"machine-config":{}}"#);

        let request = server.join().unwrap();
        assert!(
            request.starts_with("GET /vm/config HTTP/1.1\r\n"),
            "server saw: {request:?}"
        );
    }

    #[test]
    fn call_fails_on_non_2xx_and_reports_the_fault_body() {
        let dir = tempfile::tempdir().unwrap();
        let (sock, server) = serve_once(
            dir.path(),
            "HTTP/1.1 400 Bad Request\r\n\r\n{\"fault_message\":\"bad drive\"}",
        );

        let err = call(&sock, "PUT", "/drives/rootfs", Some("{}")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("400"), "got: {msg}");
        assert!(msg.contains("bad drive"), "fault body must surface: {msg}");
        let _ = server.join().unwrap();
    }

    #[test]
    fn call_errors_when_the_socket_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let err = call(&dir.path().join("nope.socket"), "GET", "/vm/config", None).unwrap_err();
        assert!(
            err.to_string()
                .contains("connecting to Firecracker API socket"),
            "got: {err}"
        );
    }
}
