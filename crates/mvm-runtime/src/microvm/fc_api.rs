//! Native HTTP/1.1 client for the Firecracker API socket.
//!
//! Firecracker speaks plain HTTP/1.1 over a Unix domain socket. Every call was
//! previously a `curl` subprocess; on the warm-restore path that is four
//! process spawns (pause, snapshot create, read device model, resume) in the
//! critical section, which is a meaningful share of the restore latency budget.
//!
//! This talks to the socket directly. The wire format is small enough to build
//! and parse by hand, so it costs no dependency: one request per connection.
//! Firecracker replies with `Connection: keep-alive` even when asked to close,
//! so the response body is read using `Content-Length` (or treated as empty for
//! 204 responses) rather than waiting for EOF.
//!
//! Request building and response parsing are pure functions so the wire format
//! is unit-testable without a live VMM.

use std::io::{BufRead, BufReader, Read, Write};
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
/// `Connection: close` is sent to discourage keep-alive, but Firecracker
/// currently replies with `Connection: keep-alive` anyway, so the reader
/// must parse `Content-Length` rather than rely on EOF delimiting.
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
/// Tolerates a body that is absent (204 and most Firecracker PUTs). When a
/// `Content-Length` header is present the caller reads exactly that many body
/// bytes; when it is absent the body is treated as empty. Firecracker keeps the
/// connection alive even after a 204, so EOF cannot be used as a delimiter.
fn parse_response(head: &str, body: &[u8]) -> Result<FcResponse> {
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

    let body = String::from_utf8_lossy(body).into_owned();
    Ok(FcResponse { status, body })
}

/// Read the response head up to and including the terminal `\r\n\r\n`.
fn read_head(reader: &mut impl BufRead) -> Result<String> {
    let mut head = Vec::new();
    reader
        .read_until(b'\n', &mut head)
        .with_context(|| "reading Firecracker response status line")?;
    if head.is_empty() {
        bail!("Firecracker closed connection before sending a response");
    }
    loop {
        let mut line = Vec::new();
        reader
            .read_until(b'\n', &mut line)
            .with_context(|| "reading Firecracker response header")?;
        if line.is_empty() {
            bail!("Firecracker closed connection while reading headers");
        }
        head.extend_from_slice(&line);
        if line == b"\r\n" || line == b"\n" {
            break;
        }
    }
    String::from_utf8(head).context("Firecracker response headers are not valid UTF-8")
}

/// Extract the `Content-Length` value from a response header block, if present.
fn content_length(head: &str) -> Option<usize> {
    head.lines().find_map(|line| {
        let mut parts = line.splitn(2, ':');
        let name = parts.next()?;
        if name.eq_ignore_ascii_case("Content-Length") {
            let value = parts.next()?.trim();
            value.parse::<usize>().ok()
        } else {
            None
        }
    })
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

    // Firecracker keeps connections alive even when asked to close them, so the
    // response must be framed by its headers rather than by EOF. A bodied
    // response always carries `Content-Length`; a 204 has no body. If neither
    // applies, fall back to reading until the server closes the connection.
    let mut reader = BufReader::new(stream);
    let head = read_head(&mut reader)
        .with_context(|| format!("reading Firecracker response headers to {method} {path}"))?;
    let body_len = content_length(&head);
    let mut body_buf = Vec::new();
    if let Some(len) = body_len {
        body_buf.resize(len, 0);
        reader
            .read_exact(&mut body_buf)
            .with_context(|| format!("reading Firecracker response body to {method} {path}"))?;
    } else if parse_response(&head, &[])?.status != 204 {
        reader
            .read_to_end(&mut body_buf)
            .with_context(|| format!("reading Firecracker response body to {method} {path}"))?;
    }

    parse_response(&head, &body_buf)
        .with_context(|| format!("parsing Firecracker response to {method} {path}"))
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
        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
        let body = br#"{\"vcpu_count\":2}"#;
        let resp = parse_response(head, body).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, r#"{\"vcpu_count\":2}"#);
    }

    /// Firecracker answers most PUT/PATCH calls with an empty 204.
    #[test]
    fn parse_response_handles_empty_body() {
        let head = "HTTP/1.1 204 No Content\r\n\r\n";
        let resp = parse_response(head, &[]).unwrap();
        assert_eq!(resp.status, 204);
        assert_eq!(resp.body, "");
        assert!(resp.is_success());
    }

    #[test]
    fn parse_response_surfaces_error_status() {
        let head = "HTTP/1.1 400 Bad Request\r\n\r\n";
        let body = br#"{\"fault_message\":\"nope\"}"#;
        let resp = parse_response(head, body).unwrap();
        assert_eq!(resp.status, 400);
        assert!(!resp.is_success());
    }

    #[test]
    fn parse_response_rejects_garbage() {
        assert!(parse_response("not http at all", &[]).is_err());
        assert!(
            parse_response("HTTP/1.1\r\n\r\n", &[]).is_err(),
            "no status code"
        );
    }

    #[test]
    fn content_length_parses_header_case_insensitively() {
        let head = "HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n";
        assert_eq!(content_length(head), Some(17));
        let head_lower = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
        assert_eq!(content_length(head_lower), Some(0));
        let head_missing = "HTTP/1.1 204 No Content\r\n\r\n";
        assert_eq!(content_length(head_missing), None);
    }
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
