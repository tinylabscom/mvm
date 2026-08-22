//! Bounded host-owned HTTP transformation for declared FlowMux ingress.
//!
//! The public listener and any TLS private key stay in the endpoint. This
//! module sees decrypted HTTP/1.1, rewrites it into unambiguous chunked framing,
//! and streams sanitized bytes to the guest loopback service. The reverse leg
//! reinjects only request-scoped opaque tokens and redacts again before bytes
//! return to the external peer.

use std::io::{Read, Write};

use mvm_core::policy::{RedactionAction, ReversibleReplacementAction};

use super::network::stages::{RedactingSubstitution, RedactionHits};
use super::network_endpoint_proxy::{ForwardResponse, StreamingRedactor};
use super::reversible_replacement::{
    ReplacementEngine, ReplacementFlow, StreamingReinjector, StreamingReplacer,
};

const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 128;
const MAX_BODY_BYTES: u64 = 16 * 1024 * 1024;
const IO_CHUNK_BYTES: usize = 16 * 1024;

/// Payload-free outcome metadata suitable for the signed audit stream.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IngressTransformSummary {
    pub request_rewrites: u64,
    pub response_reinjections: u64,
    pub redaction_events: u64,
}

/// A bounded transformation refusal. No variant carries request, response, or
/// secret bytes, so callers may safely place the error class in diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum IngressTransformError {
    #[error("ingress HTTP I/O failed")]
    Io(#[source] std::io::Error),
    #[error("malformed ingress HTTP: {0}")]
    Malformed(&'static str),
    #[error("ingress HTTP head exceeds its bound")]
    HeadTooLarge,
    #[error("ingress HTTP body exceeds its bound")]
    BodyTooLarge,
    #[error("ambiguous ingress HTTP framing")]
    AmbiguousFraming,
    #[error("unsupported ingress HTTP transfer encoding")]
    UnsupportedTransferEncoding,
    #[error("ingress sensitive-data transformation failed closed")]
    SensitiveData,
}

impl From<std::io::Error> for IngressTransformError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

impl IngressTransformError {
    /// Stable payload-free refusal token for audit labels.
    pub const fn audit_reason(&self) -> &'static str {
        match self {
            Self::Io(_) => "io",
            Self::Malformed(_) => "malformed_http",
            Self::HeadTooLarge => "head_too_large",
            Self::BodyTooLarge => "body_too_large",
            Self::AmbiguousFraming => "ambiguous_framing",
            Self::UnsupportedTransferEncoding => "unsupported_transfer_encoding",
            Self::SensitiveData => "sensitive_data_transform_failed",
        }
    }
}

/// Per-connection policy state. A new value is created from the endpoint's
/// signed redaction/replacement projection for every accepted connection, so
/// request-scoped tokens cannot be replayed across peers.
pub struct IngressTransformer {
    tenant: String,
    redaction: RedactionAction,
    replacement: ReversibleReplacementAction,
    redactor: RedactingSubstitution,
    replacement_engine: ReplacementEngine,
}

impl IngressTransformer {
    pub(crate) fn new(
        tenant: &str,
        redaction: RedactionAction,
        replacement: ReversibleReplacementAction,
    ) -> Self {
        Self {
            tenant: tenant.to_string(),
            redaction,
            replacement,
            redactor: RedactingSubstitution::with_default_rules(),
            replacement_engine: ReplacementEngine::new(),
        }
    }

    /// Transform one request/response exchange, then require connection close.
    /// This intentionally declines pipelining: a single bounded exchange keeps
    /// the request-scoped replacement table and HTTP framing lifecycle aligned.
    pub fn relay_once<E: Read + Write, G: Read + Write>(
        &self,
        external: &mut E,
        guest: &mut G,
    ) -> Result<IngressTransformSummary, IngressTransformError> {
        let mut external_reader = BufferedReader::new(external);
        let request = external_reader.read_head(MessageKind::Request)?;
        let request_was_head = request.method.as_deref() == Some("HEAD");
        let mut replacement_flow = self
            .replacement_engine
            .start_flow(&self.tenant, &self.replacement);
        let mut summary = IngressTransformSummary::default();

        let request_head =
            self.transform_request_head(&request, &mut replacement_flow, &mut summary)?;
        guest.write_all(&request_head)?;
        stream_request_body(
            &mut external_reader,
            guest,
            request.framing,
            &self.redactor,
            &self.redaction,
            &mut replacement_flow,
            &mut summary,
        )?;
        guest.flush()?;

        let mut guest_reader = BufferedReader::new(guest);
        let response = guest_reader.read_head(MessageKind::Response { request_was_head })?;
        let response_head =
            self.transform_response_head(&response, &mut replacement_flow, &mut summary)?;
        external_reader.inner.write_all(&response_head)?;
        stream_response_body(
            &mut guest_reader,
            external_reader.inner,
            response.framing,
            &self.redactor,
            &self.redaction,
            &mut replacement_flow,
            &mut summary,
        )?;
        external_reader.inner.flush()?;
        Ok(summary)
    }

    fn transform_request_head(
        &self,
        head: &ParsedHead,
        replacement_flow: &mut ReplacementFlow,
        summary: &mut IngressTransformSummary,
    ) -> Result<Vec<u8>, IngressTransformError> {
        let mut headers = head.headers.clone();
        for (name, value) in &mut headers {
            let (replaced, proofs) = replacement_flow.replace_header_value(name.clone(), value);
            add_count(&mut summary.request_rewrites, proofs.len());
            *value = self.redact_bytes(&replaced, summary)?;
        }
        serialize_head(head, headers, head.framing.has_body())
    }

    fn transform_response_head(
        &self,
        head: &ParsedHead,
        replacement_flow: &mut ReplacementFlow,
        summary: &mut IngressTransformSummary,
    ) -> Result<Vec<u8>, IngressTransformError> {
        let mut response = ForwardResponse {
            status: head.status.unwrap_or(500),
            headers: head
                .headers
                .iter()
                .map(|(name, value)| {
                    Ok((
                        name.clone(),
                        std::str::from_utf8(value)
                            .map_err(|_| IngressTransformError::Malformed("non-UTF-8 header"))?
                            .to_string(),
                    ))
                })
                .collect::<Result<Vec<_>, IngressTransformError>>()?,
            body: Vec::new(),
        };
        let proofs = replacement_flow.reinject_response(&mut response);
        add_count(&mut summary.response_reinjections, proofs.len());
        let mut headers = Vec::with_capacity(response.headers.len());
        for (name, value) in response.headers {
            headers.push((name, self.redact_bytes(value.as_bytes(), summary)?));
        }
        serialize_head(head, headers, head.framing.has_body())
    }

    fn redact_bytes(
        &self,
        bytes: &[u8],
        summary: &mut IngressTransformSummary,
    ) -> Result<Vec<u8>, IngressTransformError> {
        let Some((redacted, hits)) = self.redactor.redact_bytes_for(bytes, &self.redaction) else {
            return Ok(bytes.to_vec());
        };
        if hits.detector_failures > 0 {
            return Err(IngressTransformError::SensitiveData);
        }
        add_hits(summary, &hits);
        Ok(redacted)
    }
}

#[derive(Debug, Clone, Copy)]
enum MessageKind {
    Request,
    Response { request_was_head: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    None,
    Fixed(u64),
    Chunked,
    UntilClose,
}

impl BodyFraming {
    const fn has_body(self) -> bool {
        !matches!(self, Self::None | Self::Fixed(0))
    }
}

struct ParsedHead {
    start_line: Vec<u8>,
    method: Option<String>,
    status: Option<u16>,
    headers: Vec<(String, Vec<u8>)>,
    framing: BodyFraming,
}

struct BufferedReader<'a, R> {
    inner: &'a mut R,
    pending: Vec<u8>,
}

impl<'a, R: Read> BufferedReader<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        Self {
            inner,
            pending: Vec::new(),
        }
    }

    fn read_head(&mut self, kind: MessageKind) -> Result<ParsedHead, IngressTransformError> {
        let consumed = loop {
            if let Some(end) = find_subslice(&self.pending, b"\r\n\r\n") {
                break end + 4;
            }
            if self.pending.len() >= MAX_HEAD_BYTES {
                return Err(IngressTransformError::HeadTooLarge);
            }
            self.read_more()?;
        };
        let tail = self.pending.split_off(consumed);
        let head_bytes = std::mem::replace(&mut self.pending, tail);
        parse_head(&head_bytes, kind)
    }

    fn read_more(&mut self) -> Result<(), IngressTransformError> {
        let mut chunk = [0_u8; IO_CHUNK_BYTES];
        let count = self.inner.read(&mut chunk)?;
        if count == 0 {
            return Err(IngressTransformError::Malformed(
                "unexpected connection close",
            ));
        }
        self.pending.extend_from_slice(&chunk[..count]);
        Ok(())
    }

    fn take_exact(&mut self, count: usize) -> Result<Vec<u8>, IngressTransformError> {
        while self.pending.len() < count {
            self.read_more()?;
        }
        let tail = self.pending.split_off(count);
        Ok(std::mem::replace(&mut self.pending, tail))
    }

    fn read_line(&mut self) -> Result<Vec<u8>, IngressTransformError> {
        loop {
            if let Some(end) = find_subslice(&self.pending, b"\r\n") {
                if end > MAX_HEAD_BYTES {
                    return Err(IngressTransformError::HeadTooLarge);
                }
                let line = self.take_exact(end + 2)?;
                return Ok(line[..end].to_vec());
            }
            if self.pending.len() >= MAX_HEAD_BYTES {
                return Err(IngressTransformError::HeadTooLarge);
            }
            self.read_more()?;
        }
    }
}

fn parse_head(bytes: &[u8], kind: MessageKind) -> Result<ParsedHead, IngressTransformError> {
    let start_end = find_subslice(bytes, b"\r\n")
        .ok_or(IngressTransformError::Malformed("missing start line"))?;
    let start_line = bytes[..start_end].to_vec();
    let mut parsed_headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let (method, status, headers) = match kind {
        MessageKind::Request => {
            let mut request = httparse::Request::new(&mut parsed_headers);
            match request.parse(bytes) {
                Ok(httparse::Status::Complete(_)) => {}
                _ => return Err(IngressTransformError::Malformed("request head")),
            }
            (request.method.map(str::to_string), None, request.headers)
        }
        MessageKind::Response { .. } => {
            let mut response = httparse::Response::new(&mut parsed_headers);
            match response.parse(bytes) {
                Ok(httparse::Status::Complete(_)) => {}
                _ => return Err(IngressTransformError::Malformed("response head")),
            }
            (None, response.code, response.headers)
        }
    };
    let headers = headers
        .iter()
        .map(|header| (header.name.to_string(), header.value.to_vec()))
        .collect::<Vec<_>>();
    let framing = resolve_framing(&headers, kind, status)?;
    Ok(ParsedHead {
        start_line,
        method,
        status,
        headers,
        framing,
    })
}

fn resolve_framing(
    headers: &[(String, Vec<u8>)],
    kind: MessageKind,
    status: Option<u16>,
) -> Result<BodyFraming, IngressTransformError> {
    let transfer = header_values(headers, "transfer-encoding");
    let lengths = header_values(headers, "content-length");
    if !transfer.is_empty() && !lengths.is_empty() {
        return Err(IngressTransformError::AmbiguousFraming);
    }
    if matches!(
        kind,
        MessageKind::Response {
            request_was_head: true
        }
    ) || status.is_some_and(|code| (100..200).contains(&code) || code == 204 || code == 304)
    {
        return Ok(BodyFraming::None);
    }
    if !transfer.is_empty() {
        if transfer.len() != 1 || !transfer[0].eq_ignore_ascii_case(b"chunked") {
            return Err(IngressTransformError::UnsupportedTransferEncoding);
        }
        return Ok(BodyFraming::Chunked);
    }
    if let Some(first) = lengths.first() {
        let parsed = parse_content_length(first)?;
        for value in lengths.iter().skip(1) {
            if parse_content_length(value)? != parsed {
                return Err(IngressTransformError::AmbiguousFraming);
            }
        }
        if parsed > MAX_BODY_BYTES {
            return Err(IngressTransformError::BodyTooLarge);
        }
        return Ok(BodyFraming::Fixed(parsed));
    }
    match kind {
        MessageKind::Request => Ok(BodyFraming::None),
        MessageKind::Response { .. } => Ok(BodyFraming::UntilClose),
    }
}

fn header_values<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Vec<&'a [u8]> {
    headers
        .iter()
        .filter(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_slice())
        .collect()
}

fn parse_content_length(value: &[u8]) -> Result<u64, IngressTransformError> {
    let value = std::str::from_utf8(value)
        .map_err(|_| IngressTransformError::AmbiguousFraming)?
        .trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(IngressTransformError::AmbiguousFraming);
    }
    value
        .parse()
        .map_err(|_| IngressTransformError::AmbiguousFraming)
}

fn serialize_head(
    parsed: &ParsedHead,
    headers: Vec<(String, Vec<u8>)>,
    has_body: bool,
) -> Result<Vec<u8>, IngressTransformError> {
    let mut out = Vec::with_capacity(parsed.start_line.len() + 256);
    out.extend_from_slice(&parsed.start_line);
    out.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("trailer")
        {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&value);
        out.extend_from_slice(b"\r\n");
        if out.len() > MAX_HEAD_BYTES {
            return Err(IngressTransformError::HeadTooLarge);
        }
    }
    if has_body {
        out.extend_from_slice(b"transfer-encoding: chunked\r\n");
    }
    out.extend_from_slice(b"connection: close\r\n\r\n");
    if out.len() > MAX_HEAD_BYTES {
        return Err(IngressTransformError::HeadTooLarge);
    }
    Ok(out)
}

fn stream_request_body<R: Read, W: Write>(
    reader: &mut BufferedReader<'_, R>,
    writer: &mut W,
    framing: BodyFraming,
    redactor: &RedactingSubstitution,
    action: &RedactionAction,
    replacement_flow: &mut ReplacementFlow,
    summary: &mut IngressTransformSummary,
) -> Result<(), IngressTransformError> {
    if !framing.has_body() {
        return Ok(());
    }
    let mut replacer = StreamingReplacer::new();
    let mut streaming_redactor = StreamingRedactor::new();
    let mut transformed = 0_u64;
    read_body(reader, framing, |chunk| {
        let (replaced, proofs) = replacer
            .push(replacement_flow, chunk)
            .map_err(|_| IngressTransformError::SensitiveData)?;
        add_count(&mut summary.request_rewrites, proofs.len());
        emit_redacted_chunk(
            writer,
            redactor,
            action,
            &mut streaming_redactor,
            &replaced,
            summary,
            &mut transformed,
        )
    })?;
    let (replaced, proofs) = replacer.finish(replacement_flow);
    add_count(&mut summary.request_rewrites, proofs.len());
    emit_redacted_chunk(
        writer,
        redactor,
        action,
        &mut streaming_redactor,
        &replaced,
        summary,
        &mut transformed,
    )?;
    let (tail, hits) = streaming_redactor
        .finish(redactor, action)
        .map_err(|_| IngressTransformError::SensitiveData)?;
    add_hits(summary, &hits);
    write_bounded_chunk(writer, &tail, &mut transformed)?;
    writer.write_all(b"0\r\n\r\n")?;
    Ok(())
}

fn stream_response_body<R: Read, W: Write>(
    reader: &mut BufferedReader<'_, R>,
    writer: &mut W,
    framing: BodyFraming,
    redactor: &RedactingSubstitution,
    action: &RedactionAction,
    replacement_flow: &mut ReplacementFlow,
    summary: &mut IngressTransformSummary,
) -> Result<(), IngressTransformError> {
    if !framing.has_body() {
        return Ok(());
    }
    let mut reinjector = StreamingReinjector::new();
    let mut streaming_redactor = StreamingRedactor::new();
    let mut transformed = 0_u64;
    read_body(reader, framing, |chunk| {
        let (reinjected, proofs) = reinjector.push(replacement_flow, chunk);
        add_count(&mut summary.response_reinjections, proofs.len());
        emit_redacted_chunk(
            writer,
            redactor,
            action,
            &mut streaming_redactor,
            &reinjected,
            summary,
            &mut transformed,
        )
    })?;
    let (reinjected, proofs) = reinjector.finish(replacement_flow);
    add_count(&mut summary.response_reinjections, proofs.len());
    emit_redacted_chunk(
        writer,
        redactor,
        action,
        &mut streaming_redactor,
        &reinjected,
        summary,
        &mut transformed,
    )?;
    let (tail, hits) = streaming_redactor
        .finish(redactor, action)
        .map_err(|_| IngressTransformError::SensitiveData)?;
    add_hits(summary, &hits);
    write_bounded_chunk(writer, &tail, &mut transformed)?;
    writer.write_all(b"0\r\n\r\n")?;
    Ok(())
}

fn emit_redacted_chunk<W: Write>(
    writer: &mut W,
    redactor: &RedactingSubstitution,
    action: &RedactionAction,
    streaming: &mut StreamingRedactor,
    input: &[u8],
    summary: &mut IngressTransformSummary,
    transformed: &mut u64,
) -> Result<(), IngressTransformError> {
    let (ready, hits) = streaming
        .push(redactor, action, input)
        .map_err(|_| IngressTransformError::SensitiveData)?;
    add_hits(summary, &hits);
    write_bounded_chunk(writer, &ready, transformed)
}

fn write_bounded_chunk<W: Write>(
    writer: &mut W,
    bytes: &[u8],
    transformed: &mut u64,
) -> Result<(), IngressTransformError> {
    if bytes.is_empty() {
        return Ok(());
    }
    *transformed = transformed.saturating_add(bytes.len() as u64);
    if *transformed > MAX_BODY_BYTES {
        return Err(IngressTransformError::BodyTooLarge);
    }
    write!(writer, "{:x}\r\n", bytes.len())?;
    writer.write_all(bytes)?;
    writer.write_all(b"\r\n")?;
    Ok(())
}

fn read_body<R: Read>(
    reader: &mut BufferedReader<'_, R>,
    framing: BodyFraming,
    mut consume: impl FnMut(&[u8]) -> Result<(), IngressTransformError>,
) -> Result<(), IngressTransformError> {
    let mut total = 0_u64;
    match framing {
        BodyFraming::None => {}
        BodyFraming::Fixed(length) => {
            let mut remaining = length;
            while remaining > 0 {
                let count = usize::try_from(remaining.min(IO_CHUNK_BYTES as u64))
                    .map_err(|_| IngressTransformError::BodyTooLarge)?;
                let bytes = reader.take_exact(count)?;
                consume(&bytes)?;
                remaining -= count as u64;
            }
        }
        BodyFraming::Chunked => loop {
            let line = reader.read_line()?;
            let size_text =
                std::str::from_utf8(line.split(|byte| *byte == b';').next().unwrap_or_default())
                    .map_err(|_| IngressTransformError::Malformed("chunk size"))?
                    .trim();
            let size = u64::from_str_radix(size_text, 16)
                .map_err(|_| IngressTransformError::Malformed("chunk size"))?;
            if size == 0 {
                loop {
                    if reader.read_line()?.is_empty() {
                        break;
                    }
                }
                break;
            }
            total = total.saturating_add(size);
            if total > MAX_BODY_BYTES {
                return Err(IngressTransformError::BodyTooLarge);
            }
            let mut remaining = size;
            while remaining > 0 {
                let count = usize::try_from(remaining.min(IO_CHUNK_BYTES as u64))
                    .map_err(|_| IngressTransformError::BodyTooLarge)?;
                let bytes = reader.take_exact(count)?;
                consume(&bytes)?;
                remaining -= count as u64;
            }
            if reader.take_exact(2)? != b"\r\n" {
                return Err(IngressTransformError::Malformed("chunk terminator"));
            }
        },
        BodyFraming::UntilClose => {
            if !reader.pending.is_empty() {
                total = reader.pending.len() as u64;
                let pending = std::mem::take(&mut reader.pending);
                consume(&pending)?;
            }
            let mut chunk = [0_u8; IO_CHUNK_BYTES];
            loop {
                let count = reader.inner.read(&mut chunk)?;
                if count == 0 {
                    break;
                }
                total = total.saturating_add(count as u64);
                if total > MAX_BODY_BYTES {
                    return Err(IngressTransformError::BodyTooLarge);
                }
                consume(&chunk[..count])?;
            }
        }
    }
    Ok(())
}

fn add_hits(summary: &mut IngressTransformSummary, hits: &RedactionHits) {
    let count = hits
        .secrets
        .len()
        .saturating_add(hits.pii.len())
        .saturating_add(hits.entropy)
        .saturating_add(hits.names);
    add_count(&mut summary.redaction_events, count);
}

fn add_count(target: &mut u64, count: usize) {
    *target = target.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use mvm_core::policy::{RedactionAction, ReversibleReplacementAction};

    use super::*;

    fn transformer() -> IngressTransformer {
        IngressTransformer::new(
            "tenant-a",
            RedactionAction::default(),
            ReversibleReplacementAction {
                enabled: true,
                ..Default::default()
            },
        )
    }

    #[test]
    fn content_length_request_and_response_become_bounded_chunked_streams() {
        let secret = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let request = format!(
            "POST /echo HTTP/1.1\r\nhost: service\r\ncontent-length: {}\r\n\r\n{}",
            secret.len(),
            secret
        );
        let mut external = Cursor::new(request.into_bytes());
        let guest_response = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_vec();
        let mut guest = ScriptedDuplex::new(guest_response);
        let summary = transformer().relay_once(&mut external, &mut guest).unwrap();

        let guest_request = String::from_utf8(guest.written).unwrap();
        assert!(guest_request.contains("transfer-encoding: chunked"));
        assert!(!guest_request.contains(secret));
        assert!(summary.request_rewrites > 0 || summary.redaction_events > 0);
    }

    #[test]
    fn ambiguous_request_framing_is_refused_before_guest_delivery() {
        let request =
            b"POST / HTTP/1.1\r\ncontent-length: 1\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n";
        let mut external = Cursor::new(request.to_vec());
        let mut guest = ScriptedDuplex::new(Vec::new());
        assert!(matches!(
            transformer().relay_once(&mut external, &mut guest),
            Err(IngressTransformError::AmbiguousFraming)
        ));
        assert!(guest.written.is_empty());
    }

    #[test]
    fn oversized_request_head_is_refused_before_guest_delivery() {
        let mut external = Cursor::new(vec![b'a'; MAX_HEAD_BYTES]);
        let mut guest = ScriptedDuplex::new(Vec::new());

        assert!(matches!(
            transformer().relay_once(&mut external, &mut guest),
            Err(IngressTransformError::HeadTooLarge)
        ));
        assert!(guest.written.is_empty());
    }

    #[test]
    fn oversized_declared_request_body_is_refused_before_guest_delivery() {
        let request = format!(
            "POST / HTTP/1.1\r\ncontent-length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let mut external = Cursor::new(request.into_bytes());
        let mut guest = ScriptedDuplex::new(Vec::new());

        assert!(matches!(
            transformer().relay_once(&mut external, &mut guest),
            Err(IngressTransformError::BodyTooLarge)
        ));
        assert!(guest.written.is_empty());
    }

    #[test]
    fn unsupported_transfer_encoding_is_refused_before_guest_delivery() {
        let request = b"POST / HTTP/1.1\r\ntransfer-encoding: gzip\r\n\r\nbody";
        let mut external = Cursor::new(request.to_vec());
        let mut guest = ScriptedDuplex::new(Vec::new());

        assert!(matches!(
            transformer().relay_once(&mut external, &mut guest),
            Err(IngressTransformError::UnsupportedTransferEncoding)
        ));
        assert!(guest.written.is_empty());
    }

    #[test]
    fn chunked_body_split_token_is_sanitized_before_guest_delivery() {
        let first = "sk-aaaaaaaaaaaaaaaa";
        let second = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let request = format!(
            "POST / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            first.len(),
            first,
            second.len(),
            second
        );
        let mut external = Cursor::new(request.into_bytes());
        let mut guest =
            ScriptedDuplex::new(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n".to_vec());
        transformer().relay_once(&mut external, &mut guest).unwrap();
        let written = String::from_utf8(guest.written).unwrap();
        assert!(!written.contains(&format!("{first}{second}")));
    }

    #[test]
    fn response_token_split_across_http_chunks_is_reinjected_once() {
        let secret = b"sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let engine = ReplacementEngine::new();
        let replacement = ReversibleReplacementAction {
            enabled: true,
            ..Default::default()
        };
        let mut flow = engine.start_flow("tenant-a", &replacement);
        let (token, proofs) = flow.replace_body(secret);
        assert_eq!(proofs.len(), 1);
        let split = token.len() / 2;
        let first = &token[..split];
        let second = &token[split..];
        let encoded = format!(
            "{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            first.len(),
            String::from_utf8_lossy(first),
            second.len(),
            String::from_utf8_lossy(second)
        );
        let mut encoded = Cursor::new(encoded.into_bytes());
        let mut reader = BufferedReader::new(&mut encoded);
        let mut external = Vec::new();
        let mut summary = IngressTransformSummary::default();

        stream_response_body(
            &mut reader,
            &mut external,
            BodyFraming::Chunked,
            &RedactingSubstitution::with_default_rules(),
            &RedactionAction::default(),
            &mut flow,
            &mut summary,
        )
        .unwrap();

        assert_eq!(summary.response_reinjections, 1);
        assert!(find_subslice(&external, secret).is_none());
        assert!(find_subslice(&external, &token).is_none());
        assert!(summary.redaction_events > 0);
    }

    struct ScriptedDuplex {
        read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl ScriptedDuplex {
        fn new(read: Vec<u8>) -> Self {
            Self {
                read: Cursor::new(read),
                written: Vec::new(),
            }
        }
    }

    impl Read for ScriptedDuplex {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(buffer)
        }
    }

    impl Write for ScriptedDuplex {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
