//! Native HTTP/1.1 client for the Firecracker API socket.
//!
//! Firecracker speaks plain HTTP/1.1 over a Unix domain socket. Every call was
//! previously a `curl` subprocess; on the warm-restore path that is four
//! process spawns (pause, snapshot create, read device model, resume) in the
//! critical section, which is a meaningful share of the restore latency budget.
//!
//! This talks to the socket directly. The wire format is small enough to build
//! and parse by hand, so it costs no dependency.
//!
//! **The body is framed by `Content-Length`, never by EOF.** Firecracker answers
//! with `Connection: keep-alive` and holds the socket open even when the request
//! asks it to close, so reading until EOF blocks until the socket timeout fires
//! instead of returning the response. Observed against a live Firecracker:
//!
//! ```text
//! HTTP/1.1 200
//! Server: Firecracker API
//! Connection: keep-alive
//! Content-Length: 364
//! ```
//!
//! Header parsing and body framing are pure functions over a `BufRead`, so the
//! keep-alive behaviour is reproducible in unit tests without a live VMM.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// How long to wait on connect/read/write before giving up.
///
/// A live Firecracker answers these calls in well under a millisecond. This
/// only exists so a wedged VMM surfaces as an error instead of hanging the
/// caller forever; correct framing means it is not reached in normal operation.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Guard against a malformed or hostile `Content-Length` causing a huge
/// allocation. Firecracker's largest response (`GET /vm/config`) is well under
/// a kilobyte.
const MAX_BODY_BYTES: usize = 1 << 20;

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
/// `Connection: close` states the intent to use one request per connection.
/// Firecracker does not honour it, which is why the reader must not depend on
/// the server closing.
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

/// Pull the status code out of a response head.
fn parse_status(head: &str) -> Result<u16> {
    let status_line = head
        .lines()
        .next()
        .context("malformed HTTP response: empty status line")?;
    // "HTTP/1.1 204 No Content" -> 204
    status_line
        .split_whitespace()
        .nth(1)
        .context("malformed HTTP response: status line has no code")?
        .parse()
        .with_context(|| format!("malformed HTTP response: bad status line {status_line:?}"))
}

/// How many body bytes the response head promises.
///
/// `None` means no `Content-Length` header, which for Firecracker means an
/// empty body (its `204`s carry no length). A `Transfer-Encoding` response
/// would need chunked decoding; Firecracker never sends one, so it is rejected
/// loudly rather than mis-framed silently.
fn body_length(head: &str) -> Result<Option<usize>> {
    let mut len = None;
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            bail!("unsupported Transfer-Encoding {value:?} in Firecracker response");
        }
        if name.eq_ignore_ascii_case("content-length") {
            let parsed: usize = value
                .parse()
                .with_context(|| format!("malformed Content-Length {value:?}"))?;
            if parsed > MAX_BODY_BYTES {
                bail!("Firecracker response Content-Length {parsed} exceeds {MAX_BODY_BYTES}");
            }
            len = Some(parsed);
        }
    }
    Ok(len)
}

/// Read one response: headers up to the blank line, then exactly as many body
/// bytes as `Content-Length` promises.
///
/// Never reads to EOF — the server keeps the connection open, so an EOF-framed
/// read would block until the socket timeout.
fn read_response<R: BufRead>(reader: &mut R) -> Result<FcResponse> {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .context("reading Firecracker response headers")?;
        if n == 0 {
            bail!("Firecracker closed the connection before finishing the response headers");
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        head.push_str(&line);
    }

    let status = parse_status(&head)?;
    let body = match body_length(&head)? {
        Some(0) | None => String::new(),
        Some(len) => {
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).with_context(|| {
                format!("reading {len} body byte(s) from the Firecracker response")
            })?;
            String::from_utf8_lossy(&buf).into_owned()
        }
    };

    Ok(FcResponse { status, body })
}

/// Send one request to the Firecracker API socket and read the response.
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

    let mut reader = BufReader::new(&stream);
    read_response(&mut reader)
        .with_context(|| format!("reading Firecracker response to {method} {path}"))
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
    use std::io::{Cursor, Read};
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;

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

    /// The regression. A real Firecracker answers `Connection: keep-alive` and
    /// leaves the socket open, so more bytes may sit in the stream after this
    /// response. Framing on `Content-Length` must stop exactly at the body; a
    /// reader that consumed to EOF would swallow the trailing bytes.
    #[test]
    fn read_response_stops_at_content_length_and_ignores_trailing_bytes() {
        let wire = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Server: Firecracker API\r\n",
            "Connection: keep-alive\r\n",
            "Content-Length: 16\r\n",
            "\r\n",
            r#"{"vcpu_count":2}"#,
            "HTTP/1.1 200 OK\r\n\r\nLEFTOVER-FROM-NEXT-RESPONSE",
        );
        let mut cur = Cursor::new(wire.as_bytes());
        let resp = read_response(&mut cur).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.body, r#"{"vcpu_count":2}"#,
            "body must stop at Content-Length, not run to EOF"
        );
    }

    /// Firecracker answers most PUT/PATCH calls with an empty 204 and no
    /// `Content-Length`.
    #[test]
    fn read_response_treats_absent_content_length_as_empty_body() {
        let wire = "HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n";
        let mut cur = Cursor::new(wire.as_bytes());
        let resp = read_response(&mut cur).unwrap();
        assert_eq!(resp.status, 204);
        assert_eq!(resp.body, "");
        assert!(resp.is_success());
    }

    #[test]
    fn read_response_surfaces_error_status_with_its_fault_body() {
        let body = r#"{"fault_message":"nope"}"#;
        let wire = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut cur = Cursor::new(wire.as_bytes());
        let resp = read_response(&mut cur).unwrap();
        assert_eq!(resp.status, 400);
        assert!(!resp.is_success());
        assert!(resp.body.contains("nope"));
    }

    #[test]
    fn read_response_rejects_garbage_and_truncation() {
        assert!(read_response(&mut Cursor::new(&b"not http at all"[..])).is_err());
        assert!(
            read_response(&mut Cursor::new(&b"HTTP/1.1\r\n\r\n"[..])).is_err(),
            "no status code"
        );
        assert!(
            read_response(&mut Cursor::new(
                &b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort"[..]
            ))
            .is_err(),
            "body shorter than Content-Length must fail, not silently truncate"
        );
    }

    /// Chunked framing would be mis-read as an empty body. Fail loudly instead.
    #[test]
    fn read_response_rejects_chunked_transfer_encoding() {
        let wire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n";
        let err = read_response(&mut Cursor::new(wire.as_bytes())).unwrap_err();
        assert!(err.to_string().contains("Transfer-Encoding"), "got: {err}");
    }

    #[test]
    fn body_length_rejects_absurd_content_length() {
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n", usize::MAX);
        assert!(body_length(&head).is_err());
    }

    /// Serve one canned response over a real socket **without closing it**,
    /// mirroring Firecracker's keep-alive behaviour. The connection is held
    /// open until the test releases it, so a client that framed on EOF would
    /// block here instead of returning.
    fn serve_keep_alive(
        dir: &Path,
        response: &'static str,
    ) -> (
        std::path::PathBuf,
        mpsc::Sender<()>,
        std::thread::JoinHandle<()>,
    ) {
        let sock = dir.join("fc.socket");
        let listener = UnixListener::bind(&sock).unwrap();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut req = [0u8; 1024];
            let _ = conn.read(&mut req);
            conn.write_all(response.as_bytes()).unwrap();
            conn.flush().unwrap();
            // Hold the connection open — this is what reproduces the bug.
            let _ = release_rx.recv();
        });
        (sock, release_tx, handle)
    }

    #[test]
    fn call_returns_against_a_keep_alive_server() {
        let dir = tempfile::tempdir().unwrap();
        let (sock, release, server) = serve_keep_alive(
            dir.path(),
            "HTTP/1.1 200 OK\r\nServer: Firecracker API\r\nConnection: keep-alive\r\nContent-Length: 21\r\n\r\n{\"machine-config\":{}}",
        );

        let body = call(&sock, "GET", "/vm/config", None).expect("must not hang on keep-alive");
        assert_eq!(body, r#"{"machine-config":{}}"#);

        let _ = release.send(());
        server.join().unwrap();
    }

    #[test]
    fn call_fails_on_non_2xx_and_reports_the_fault_body() {
        let dir = tempfile::tempdir().unwrap();
        let (sock, release, server) = serve_keep_alive(
            dir.path(),
            "HTTP/1.1 400 Bad Request\r\nConnection: keep-alive\r\nContent-Length: 28\r\n\r\n{\"fault_message\":\"bad drive\"}",
        );

        let err = call(&sock, "PUT", "/drives/rootfs", Some("{}")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("400"), "got: {msg}");
        assert!(msg.contains("bad drive"), "fault body must surface: {msg}");

        let _ = release.send(());
        server.join().unwrap();
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
