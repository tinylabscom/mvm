//! Bounded HTTP/1.1 request reader for the transparent egress terminator.
//!
//! Ported from `crates/mvm-agentd/src/forward_proxy.rs`. The terminator reads
//! raw redirected TCP bytes off a blocking socket and needs the same
//! headers→body logic.

use std::io::Read;

/// 16 MiB cap on a single redirected request (defensive against runaway
/// allocations; the same bound as the guest-side forward proxy).
pub const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

/// Why a request could not be read.
///
/// The causes are separated because the caller reacts to each differently: a
/// peer that closed between requests is an ordinary keep-alive end, a peer that
/// closed part-way through is a truncated request worth logging, an oversized
/// request is an attempt worth logging, and a transfer-coded body is something
/// to answer rather than to close on. Collapsing them made a 16 MiB header
/// overflow indistinguishable from a client hanging up politely.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The peer closed with nothing buffered — it is done sending requests.
    #[error("peer closed between requests")]
    Closed,
    /// The peer closed part-way through a request.
    #[error("connection closed before the request completed")]
    Truncated,
    /// The request exceeded [`MAX_REQUEST_BYTES`].
    #[error("request exceeds the {MAX_REQUEST_BYTES} byte limit")]
    TooLarge,
    /// A `Transfer-Encoding` request body.
    ///
    /// This reader frames a body by `Content-Length` only. A transfer-coded
    /// body read as if it had none would hand the chunk framing to the
    /// substitution pipeline as body content and spend a real credential on a
    /// corrupted request, so it is refused instead.
    #[error("transfer-coded request bodies are not supported")]
    TransferCoded,
    /// Bytes arrived behind the request this reader returned.
    ///
    /// Not raised by the reader, which only reports the [`HttpRequest::residue`]
    /// it saw: the caller decides whether serving a second request it has not
    /// inspected is acceptable, and on a credentialed flow it is not. It lives
    /// here so a caller has one enum to describe why a request was not served
    /// and one place to answer from.
    #[error("pipelined requests are not supported on this connection")]
    Pipelined,
    /// The socket failed.
    #[error("request read failed: {0}")]
    Io(#[source] std::io::Error),
}

/// One request read off the stream, and whatever arrived behind it.
pub struct HttpRequest {
    /// Exactly the header block plus the declared `Content-Length` body, and
    /// nothing else.
    pub request: Vec<u8>,
    /// Bytes that arrived past the end of `request`.
    ///
    /// A single read returns up to a full buffer, so a pipelining client's
    /// next request is often already in hand when this one ends. Handing those
    /// bytes back as part of the body would make the declared length disagree
    /// with what was actually read — and every length check downstream is
    /// written against the declared one, so they would all pass on the wrong
    /// number.
    pub residue: Vec<u8>,
}

/// Read one full HTTP/1.1 request off `stream`: headers up to `\r\n\r\n`,
/// then the `Content-Length` body (if any). Bounded by [`MAX_REQUEST_BYTES`].
///
/// Generic over `Read` so it serves both the cleartext `:80` path (a raw
/// `TcpStream`) and the `:443` path (a decrypted `rustls` stream).
pub fn read_http_request<R: Read>(stream: &mut R) -> Result<HttpRequest, ReadError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];

    // Phase 1: accumulate until we see the header terminator.
    let header_end = loop {
        if let Some(pos) = super::find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_REQUEST_BYTES {
            return Err(ReadError::TooLarge);
        }
        let n = stream.read(&mut chunk).map_err(ReadError::Io)?;
        if n == 0 {
            return Err(if buf.is_empty() {
                ReadError::Closed
            } else {
                ReadError::Truncated
            });
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    if is_transfer_coded(&buf[..header_end]) {
        return Err(ReadError::TransferCoded);
    }

    // Phase 2: read the Content-Length body, if declared.
    let body_len = content_length_of(&buf[..header_end]).unwrap_or(0);
    let end = header_end.saturating_add(body_len);
    if end > MAX_REQUEST_BYTES {
        return Err(ReadError::TooLarge);
    }
    while buf.len() < end {
        let n = stream.read(&mut chunk).map_err(ReadError::Io)?;
        if n == 0 {
            return Err(ReadError::Truncated);
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    // Cut at the declared end. Anything past it belongs to the next request,
    // not to this one's body.
    let residue = buf.split_off(end);
    Ok(HttpRequest {
        request: buf,
        residue,
    })
}

/// Whether an already-read header block declares a `Transfer-Encoding`.
fn is_transfer_coded(head: &[u8]) -> bool {
    header_lines(head).is_some_and(|mut lines| {
        lines.any(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding") && !value.is_empty()
        })
    })
}

/// Parse a `Content-Length` value out of an already-read header block.
fn content_length_of(head: &[u8]) -> Option<usize> {
    header_lines(head)?
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
}

/// The trimmed `(name, value)` pairs of an already-read header block, or
/// `None` when it is not UTF-8.
fn header_lines(head: &[u8]) -> Option<impl Iterator<Item = (&str, &str)>> {
    let text = std::str::from_utf8(head).ok()?;
    Some(
        text.split("\r\n")
            .skip(1) // skip request line
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim(), value.trim())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use crate::supervisor::terminator::find_subslice;

    /// Write `data` into a loopback pair, return the reader end.
    fn pipe(data: &[u8]) -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let data = data.to_vec();
        thread::spawn(move || {
            let mut w = TcpStream::connect(addr).unwrap();
            w.write_all(&data).unwrap();
            // drop closes the write side, signalling EOF to the reader
        });
        listener.accept().unwrap().0
    }

    #[test]
    fn reads_a_get_request_with_no_body() {
        let raw = b"GET /v1/x HTTP/1.1\r\nhost: api.openai.com\r\n\r\n";
        let mut stream = pipe(raw);
        let got = read_http_request(&mut stream).unwrap();
        assert_eq!(got.request, raw);
        assert!(got.residue.is_empty());
    }

    #[test]
    fn reads_a_post_request_honoring_content_length() {
        let raw = b"POST /v1 HTTP/1.1\r\ncontent-length: 2\r\n\r\n{}";
        let mut stream = pipe(raw);
        let got = read_http_request(&mut stream).unwrap();
        assert_eq!(got.request, raw);
        assert!(got.residue.is_empty());
    }

    #[test]
    fn content_length_body_is_present_in_returned_buffer() {
        // The declared body bytes are present in the returned buffer; the
        // caller (parse/handler) trims to content-length as needed.
        let raw = b"POST /y HTTP/1.1\r\ncontent-length: 3\r\n\r\nabc";
        let mut stream = pipe(raw);
        let got = read_http_request(&mut stream).unwrap();
        let hdr_end = find_subslice(&got.request, b"\r\n\r\n").unwrap() + 4;
        assert_eq!(&got.request[hdr_end..], b"abc");
    }

    /// A pipelining client's next request arrives in the same read as this
    /// one's body. It must not be counted as body: `body_len` is what every
    /// length check downstream is written against, so a body that is longer
    /// than declared makes all of them pass on the wrong number — and a
    /// placeholder sitting in those extra bytes never passes header
    /// substitution at all.
    #[test]
    fn bytes_past_the_declared_length_are_residue_not_body() {
        let raw = b"POST /y HTTP/1.1\r\ncontent-length: 3\r\n\r\nabcGET /next HTTP/1.1\r\nhost: x\r\n\r\n";
        let mut stream = pipe(raw);
        let got = read_http_request(&mut stream).unwrap();
        let hdr_end = find_subslice(&got.request, b"\r\n\r\n").unwrap() + 4;
        assert_eq!(&got.request[hdr_end..], b"abc");
        assert_eq!(got.residue, b"GET /next HTTP/1.1\r\nhost: x\r\n\r\n");
    }

    #[test]
    fn a_transfer_coded_request_is_refused_rather_than_read_as_bodyless() {
        let raw = b"POST /y HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let mut stream = pipe(raw);
        assert!(matches!(
            read_http_request(&mut stream),
            Err(ReadError::TransferCoded)
        ));
    }

    #[test]
    fn a_close_with_nothing_buffered_is_not_a_truncation() {
        let mut stream = pipe(b"");
        assert!(matches!(
            read_http_request(&mut stream),
            Err(ReadError::Closed)
        ));
    }

    #[test]
    fn errors_on_connection_closed_before_headers_complete() {
        let raw = b"GET /v1 HTTP/1.1\r\nhost: x"; // no \r\n\r\n
        let mut stream = pipe(raw);
        assert!(matches!(
            read_http_request(&mut stream),
            Err(ReadError::Truncated)
        ));
    }

    #[test]
    fn errors_on_connection_closed_before_the_declared_body_completes() {
        let raw = b"POST /y HTTP/1.1\r\ncontent-length: 8\r\n\r\nshort";
        let mut stream = pipe(raw);
        assert!(matches!(
            read_http_request(&mut stream),
            Err(ReadError::Truncated)
        ));
    }

    #[test]
    fn an_oversized_declared_body_is_refused_before_it_is_read() {
        let raw = format!(
            "POST /y HTTP/1.1\r\ncontent-length: {}\r\n\r\n",
            MAX_REQUEST_BYTES + 1
        );
        let mut stream = pipe(raw.as_bytes());
        assert!(matches!(
            read_http_request(&mut stream),
            Err(ReadError::TooLarge)
        ));
    }

    #[test]
    fn find_subslice_locates_the_needle() {
        assert_eq!(find_subslice(b"hello\r\n\r\nworld", b"\r\n\r\n"), Some(5));
        assert_eq!(find_subslice(b"no terminator", b"\r\n\r\n"), None);
        assert_eq!(find_subslice(b"\r\n\r\n", b"\r\n\r\n"), Some(0));
    }

    #[test]
    fn find_subslice_returns_none_for_needle_longer_than_haystack() {
        assert_eq!(find_subslice(b"ab", b"\r\n\r\n"), None);
    }
}
