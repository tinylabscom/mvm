//! Bounded HTTP/1.1 request reader for the transparent egress terminator.
//!
//! Ported from `crates/mvm-guest/src/forward_proxy.rs`. The terminator reads
//! raw redirected TCP bytes off a blocking socket and needs the same
//! headers→body logic. `find_subslice` is `pub(super)` so `request.rs` can
//! reference it via the parent module rather than duplicating it.

use std::io::Read;
use std::net::TcpStream;

use anyhow::{Context, Result, bail};

/// 16 MiB cap on a single redirected request (defensive against runaway
/// allocations; the same bound as the guest-side forward proxy).
pub const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

/// Read one full HTTP/1.1 request off `stream`: headers up to `\r\n\r\n`,
/// then the `Content-Length` body (if any). Bounded by [`MAX_REQUEST_BYTES`].
pub fn read_http_request(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];

    // Phase 1: accumulate until we see the header terminator.
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_REQUEST_BYTES {
            bail!("request headers exceed {MAX_REQUEST_BYTES} bytes");
        }
        let n = stream.read(&mut chunk).context("reading request headers")?;
        if n == 0 {
            bail!("connection closed before request headers completed");
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    // Phase 2: read the Content-Length body, if declared.
    if let Some(len) = content_length_of(&buf[..header_end]) {
        let have = buf.len() - header_end;
        let mut remaining = len.saturating_sub(have);
        while remaining > 0 {
            if buf.len() > MAX_REQUEST_BYTES {
                bail!("request body exceeds {MAX_REQUEST_BYTES} bytes");
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

/// First index of `needle` in `haystack`, or `None`.
pub(super) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Parse a `Content-Length` value out of an already-read header block.
fn content_length_of(head: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n")
        .skip(1) // skip request line
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

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
        assert_eq!(got, raw);
    }

    #[test]
    fn reads_a_post_request_honoring_content_length() {
        let raw = b"POST /v1 HTTP/1.1\r\ncontent-length: 2\r\n\r\n{}";
        let mut stream = pipe(raw);
        let got = read_http_request(&mut stream).unwrap();
        assert_eq!(got, raw);
    }

    #[test]
    fn content_length_body_is_present_in_returned_buffer() {
        // The declared body bytes are present in the returned buffer; the
        // caller (parse/handler) trims to content-length as needed.
        let raw = b"POST /y HTTP/1.1\r\ncontent-length: 3\r\n\r\nabc";
        let mut stream = pipe(raw);
        let got = read_http_request(&mut stream).unwrap();
        let hdr_end = find_subslice(&got, b"\r\n\r\n").unwrap() + 4;
        // At least the declared 3 body bytes are present.
        assert!(got.len() >= hdr_end + 3);
        assert_eq!(&got[hdr_end..hdr_end + 3], b"abc");
    }

    #[test]
    fn errors_on_connection_closed_before_headers_complete() {
        let raw = b"GET /v1 HTTP/1.1\r\nhost: x"; // no \r\n\r\n
        let mut stream = pipe(raw);
        assert!(read_http_request(&mut stream).is_err());
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
