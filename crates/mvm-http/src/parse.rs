//! Response-head and chunked-body parsing.
//!
//! Everything here is a pure function over bytes with no IO, so the fuzz
//! target drives exactly the code the network drives. The head parse itself
//! delegates to `httparse`; what this module owns is the part that decides
//! **how long the body is**, which is where HTTP/1.1 request smuggling lives.

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

/// Hard ceiling on the response head. Without it a server that never sends
/// `\r\n\r\n` grows the read buffer without bound.
pub const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Maximum header count accepted in a response head.
pub const MAX_HEADERS: usize = 128;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("malformed response head: {0}")]
    Malformed(String),
    #[error("response head exceeded {MAX_HEAD_BYTES} bytes")]
    HeadTooLarge,
    #[error("response declared both Content-Length and Transfer-Encoding")]
    LengthAndTransferEncoding,
    #[error("response declared conflicting Content-Length values")]
    ConflictingContentLength,
    #[error("unsupported Transfer-Encoding: {0}")]
    UnsupportedTransferEncoding(String),
    #[error("malformed chunked body: {0}")]
    MalformedChunk(String),
}

/// How the body's end is determined. Resolved once, from the head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLength {
    /// No body regardless of headers — HEAD, 1xx, 204, 304.
    None,
    /// Exactly `n` bytes follow.
    Fixed(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Neither framing header: the body runs to connection close.
    UntilClose,
}

/// A parsed response head plus how many bytes of the input it consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body_length: BodyLength,
    /// Offset in the input at which the body begins.
    pub consumed: usize,
}

/// Parse a response head. Returns `Ok(None)` when `buf` does not yet hold a
/// complete head and more bytes should be read.
///
/// `request_was_head` matters because a HEAD response carries a
/// `Content-Length` describing the body it *would* have sent. Treating that as
/// a body to read desynchronises the connection.
pub fn parse_head(buf: &[u8], request_was_head: bool) -> Result<Option<Head>, ParseError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    let consumed = match resp.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => {
            if buf.len() > MAX_HEAD_BYTES {
                return Err(ParseError::HeadTooLarge);
            }
            return Ok(None);
        }
        Err(e) => return Err(ParseError::Malformed(e.to_string())),
    };

    let code = resp
        .code
        .ok_or_else(|| ParseError::Malformed("missing status code".into()))?;
    let status =
        StatusCode::from_u16(code).map_err(|_| ParseError::Malformed(format!("status {code}")))?;

    let mut map = HeaderMap::with_capacity(resp.headers.len());
    for h in resp.headers.iter() {
        let name = HeaderName::from_bytes(h.name.as_bytes())
            .map_err(|_| ParseError::Malformed(format!("header name {:?}", h.name)))?;
        let value = HeaderValue::from_bytes(h.value)
            .map_err(|_| ParseError::Malformed(format!("header value for {:?}", h.name)))?;
        map.append(name, value);
    }

    let body_length = resolve_body_length(&map, status, request_was_head)?;
    Ok(Some(Head {
        status,
        headers: map,
        body_length,
        consumed,
    }))
}

/// Decide the body framing. Fails closed on the ambiguities that make request
/// smuggling possible rather than picking a winner the way lenient servers do.
fn resolve_body_length(
    headers: &HeaderMap,
    status: StatusCode,
    request_was_head: bool,
) -> Result<BodyLength, ParseError> {
    let has_te = headers.contains_key(http::header::TRANSFER_ENCODING);
    let has_cl = headers.contains_key(http::header::CONTENT_LENGTH);

    // RFC 9112 §6.1 permits ignoring Content-Length when Transfer-Encoding is
    // present. Ignoring it is precisely the disagreement between two hops that
    // smuggling exploits, so refuse instead.
    if has_te && has_cl {
        return Err(ParseError::LengthAndTransferEncoding);
    }

    // Statuses that never carry a body. Checked before the framing headers so a
    // 204 advertising a length cannot desynchronise the connection.
    if request_was_head
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
    {
        return Ok(BodyLength::None);
    }

    if has_te {
        let mut encodings = headers.get_all(http::header::TRANSFER_ENCODING).iter();
        let value = encodings
            .next()
            .ok_or_else(|| ParseError::Malformed("empty Transfer-Encoding".into()))?;
        if encodings.next().is_some() {
            return Err(ParseError::UnsupportedTransferEncoding(
                "multiple Transfer-Encoding headers".into(),
            ));
        }
        let text = value
            .to_str()
            .map_err(|_| ParseError::Malformed("non-ASCII Transfer-Encoding".into()))?
            .trim()
            .to_ascii_lowercase();
        // Only identity-or-chunked is supported. `gzip, chunked` and friends
        // would need a decoder chain; refusing is honest and keeps the framing
        // decision single-valued.
        if text == "chunked" {
            return Ok(BodyLength::Chunked);
        }
        return Err(ParseError::UnsupportedTransferEncoding(text));
    }

    if has_cl {
        let mut lengths = headers.get_all(http::header::CONTENT_LENGTH).iter();
        let first = lengths
            .next()
            .ok_or_else(|| ParseError::Malformed("empty Content-Length".into()))?;
        let parse_one = |v: &HeaderValue| -> Result<u64, ParseError> {
            let s = v
                .to_str()
                .map_err(|_| ParseError::Malformed("non-ASCII Content-Length".into()))?
                .trim();
            // `u64::from_str` accepts a leading `+`; HTTP does not.
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ParseError::Malformed(format!("Content-Length {s:?}")));
            }
            s.parse::<u64>()
                .map_err(|_| ParseError::Malformed(format!("Content-Length {s:?}")))
        };
        let n = parse_one(first)?;
        // Duplicate Content-Length headers are only tolerable when they agree.
        for v in lengths {
            if parse_one(v)? != n {
                return Err(ParseError::ConflictingContentLength);
            }
        }
        return Ok(BodyLength::Fixed(n));
    }

    Ok(BodyLength::UntilClose)
}

/// One step of chunked decoding over a buffer.
#[derive(Debug, PartialEq, Eq)]
pub enum ChunkStep {
    /// A chunk's data spans `data` within the input; `consumed` bytes of input
    /// were used including the size line and trailing CRLF.
    Data {
        start: usize,
        len: usize,
        consumed: usize,
    },
    /// The terminal zero-length chunk; `consumed` covers it and any trailer.
    End { consumed: usize },
    /// Not enough input yet.
    Incomplete,
}

/// Maximum accepted chunk-size line, including extensions.
const MAX_CHUNK_LINE: usize = 1024;

/// Decode the next chunk header from `buf`.
///
/// Chunk extensions (`;name=value` after the size) are parsed and discarded;
/// a size that is not plain hex is rejected rather than coerced, since
/// `0x10`-style or whitespace-padded sizes are a classic smuggling primitive.
pub fn next_chunk(buf: &[u8]) -> Result<ChunkStep, ParseError> {
    let line_end = match find_crlf(buf) {
        Some(i) => i,
        None => {
            if buf.len() > MAX_CHUNK_LINE {
                return Err(ParseError::MalformedChunk(
                    "chunk size line too long".into(),
                ));
            }
            return Ok(ChunkStep::Incomplete);
        }
    };
    if line_end > MAX_CHUNK_LINE {
        return Err(ParseError::MalformedChunk(
            "chunk size line too long".into(),
        ));
    }
    let line = &buf[..line_end];
    // Split off any chunk extension.
    let size_bytes = match line.iter().position(|&b| b == b';') {
        Some(i) => &line[..i],
        None => line,
    };
    if size_bytes.is_empty() || !size_bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(ParseError::MalformedChunk(format!(
            "chunk size {:?}",
            String::from_utf8_lossy(size_bytes)
        )));
    }
    let text = std::str::from_utf8(size_bytes)
        .map_err(|_| ParseError::MalformedChunk("non-UTF8 chunk size".into()))?;
    let size = u64::from_str_radix(text, 16)
        .map_err(|_| ParseError::MalformedChunk(format!("chunk size {text:?}")))?;
    let after_line = line_end + 2;

    if size == 0 {
        // Terminal chunk: consume the trailer section up to the final CRLF.
        return match find_double_crlf_terminator(&buf[after_line..]) {
            Some(n) => Ok(ChunkStep::End {
                consumed: after_line + n,
            }),
            None => Ok(ChunkStep::Incomplete),
        };
    }

    let size = usize::try_from(size)
        .map_err(|_| ParseError::MalformedChunk("chunk size exceeds usize".into()))?;
    let need = after_line
        .checked_add(size)
        .and_then(|n| n.checked_add(2))
        .ok_or_else(|| ParseError::MalformedChunk("chunk size overflow".into()))?;
    if buf.len() < need {
        return Ok(ChunkStep::Incomplete);
    }
    if &buf[after_line + size..after_line + size + 2] != b"\r\n" {
        return Err(ParseError::MalformedChunk(
            "chunk not CRLF-terminated".into(),
        ));
    }
    Ok(ChunkStep::Data {
        start: after_line,
        len: size,
        consumed: need,
    })
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// After a `0\r\n`, consume optional trailer lines up to the closing CRLF.
fn find_double_crlf_terminator(buf: &[u8]) -> Option<usize> {
    // The common case is an immediate CRLF with no trailers.
    if buf.starts_with(b"\r\n") {
        return Some(2);
    }
    // Otherwise scan for the blank line that ends the trailer section.
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(bytes: &str) -> Result<Option<Head>, ParseError> {
        parse_head(bytes.as_bytes(), false)
    }

    #[test]
    fn parses_a_minimal_response() {
        let h = head("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
            .unwrap()
            .unwrap();
        assert_eq!(h.status, StatusCode::OK);
        assert_eq!(h.body_length, BodyLength::Fixed(3));
        assert_eq!(
            &b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n"[..].len(),
            &h.consumed
        );
    }

    #[test]
    fn incomplete_head_asks_for_more() {
        assert!(head("HTTP/1.1 200 OK\r\nContent-Len").unwrap().is_none());
    }

    #[test]
    fn oversized_head_is_refused_rather_than_buffered() {
        // One unterminated header value, so httparse keeps returning Partial
        // and the size guard is the thing that has to stop the growth.
        let mut s = String::from("HTTP/1.1 200 OK\r\nX-Pad: ");
        s.push_str(&"a".repeat(MAX_HEAD_BYTES + 1));
        assert_eq!(head(&s), Err(ParseError::HeadTooLarge));
    }

    #[test]
    fn too_many_headers_is_refused() {
        // The other unbounded direction: header *count* rather than byte size.
        let mut s = String::from("HTTP/1.1 200 OK\r\n");
        for i in 0..=MAX_HEADERS {
            s.push_str(&format!("X-Pad-{i}: v\r\n"));
        }
        s.push_str("\r\n");
        assert!(matches!(head(&s), Err(ParseError::Malformed(_))));
    }

    #[test]
    fn content_length_with_transfer_encoding_is_refused() {
        // The smuggling classic: two hops disagree about which header wins.
        let r = head("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(r, Err(ParseError::LengthAndTransferEncoding));
    }

    #[test]
    fn conflicting_content_lengths_are_refused_but_agreeing_ones_pass() {
        assert_eq!(
            head("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n"),
            Err(ParseError::ConflictingContentLength)
        );
        let h = head("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(h.body_length, BodyLength::Fixed(3));
    }

    #[test]
    fn non_digit_content_length_is_refused() {
        for bad in ["+3", "3a", "0x3", "-1", " ", ""] {
            let s = format!("HTTP/1.1 200 OK\r\nContent-Length: {bad}\r\n\r\n");
            assert!(
                matches!(head(&s), Err(ParseError::Malformed(_))),
                "Content-Length {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn bodyless_statuses_ignore_a_declared_length() {
        for code in ["204 No Content", "304 Not Modified", "100 Continue"] {
            let s = format!("HTTP/1.1 {code}\r\nContent-Length: 5\r\n\r\n");
            let h = head(&s).unwrap().unwrap();
            assert_eq!(h.body_length, BodyLength::None, "{code}");
        }
    }

    #[test]
    fn head_request_response_declares_no_body() {
        let h = parse_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n",
            /* request_was_head */ true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(h.body_length, BodyLength::None);
    }

    #[test]
    fn chunked_is_recognised_and_other_encodings_refused() {
        let h = head("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(h.body_length, BodyLength::Chunked);
        assert!(matches!(
            head("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"),
            Err(ParseError::UnsupportedTransferEncoding(_))
        ));
    }

    #[test]
    fn no_framing_headers_means_read_until_close() {
        let h = head("HTTP/1.1 200 OK\r\n\r\n").unwrap().unwrap();
        assert_eq!(h.body_length, BodyLength::UntilClose);
    }

    #[test]
    fn decodes_a_chunk_and_the_terminator() {
        let buf = b"5\r\nhello\r\n";
        assert_eq!(
            next_chunk(buf).unwrap(),
            ChunkStep::Data {
                start: 3,
                len: 5,
                consumed: 10
            }
        );
        assert_eq!(
            next_chunk(b"0\r\n\r\n").unwrap(),
            ChunkStep::End { consumed: 5 }
        );
    }

    #[test]
    fn chunk_extensions_are_accepted_and_ignored() {
        assert_eq!(
            next_chunk(b"5;foo=bar\r\nhello\r\n").unwrap(),
            ChunkStep::Data {
                start: 11,
                len: 5,
                consumed: 18
            }
        );
    }

    #[test]
    fn non_hex_chunk_sizes_are_refused() {
        // `0x5` and a space-padded size are smuggling primitives against
        // parsers that coerce rather than reject.
        for bad in [
            &b"0x5\r\nhello\r\n"[..],
            b" 5\r\nhello\r\n",
            b"+5\r\nhello\r\n",
        ] {
            assert!(
                matches!(next_chunk(bad), Err(ParseError::MalformedChunk(_))),
                "chunk size {:?} must be refused",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn chunk_without_crlf_terminator_is_refused() {
        assert!(matches!(
            next_chunk(b"5\r\nhelloXX"),
            Err(ParseError::MalformedChunk(_))
        ));
    }

    #[test]
    fn partial_chunk_asks_for_more() {
        assert_eq!(next_chunk(b"5\r\nhel").unwrap(), ChunkStep::Incomplete);
        assert_eq!(next_chunk(b"5\r\n").unwrap(), ChunkStep::Incomplete);
        assert_eq!(next_chunk(b"").unwrap(), ChunkStep::Incomplete);
    }

    #[test]
    fn oversized_chunk_size_line_is_refused() {
        let long = format!("{}\r\n", "a".repeat(MAX_CHUNK_LINE + 1));
        assert!(matches!(
            next_chunk(long.as_bytes()),
            Err(ParseError::MalformedChunk(_))
        ));
    }

    #[test]
    fn terminal_chunk_consumes_trailers() {
        let buf = b"0\r\nX-Trailer: v\r\n\r\n";
        assert_eq!(
            next_chunk(buf).unwrap(),
            ChunkStep::End {
                consumed: buf.len()
            }
        );
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        // A cheap stand-in for the fuzz target: every prefix of a valid
        // response, and some deliberate garbage, must return not panic.
        let full = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        for i in 0..=full.len() {
            let _ = parse_head(&full[..i], false);
            let _ = next_chunk(&full[..i]);
        }
        for junk in [
            &b"\x00\xff\r\n\r\n"[..],
            b"HTTP/9.9 999 \r\n\r\n",
            b"\r\n\r\n",
        ] {
            let _ = parse_head(junk, false);
            let _ = next_chunk(junk);
        }
    }
}
