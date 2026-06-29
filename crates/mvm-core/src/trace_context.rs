//! Distributed trace context for end-to-end correlation.
//!
//! A W3C-`traceparent`-shaped [`TraceContext`] (`trace_id` + `span_id`) is
//! threaded guest → broker → audit so one run is correlatable across every hop
//! and recorded alongside the existing `correlation_id` in the chain-signed
//! audit log. This module is the type + wire format (hex / `traceparent`);
//! generation uses the runtime RNG at the edge, and parsing fails closed on
//! malformed or all-zero ids.

use core::fmt;

const HEX: &[u8; 16] = b"0123456789abcdef";

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn from_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[2 * i])?;
        let lo = hex_nibble(bytes[2 * i + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

/// A 16-byte trace identifier (W3C `trace-id`). All-zero is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceId(pub [u8; 16]);

/// An 8-byte span identifier (W3C `parent-id`/`span-id`). All-zero is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpanId(pub [u8; 8]);

impl TraceId {
    pub fn to_hex(self) -> String {
        to_hex(&self.0)
    }
    fn is_valid(self) -> bool {
        self.0 != [0u8; 16]
    }
}

impl SpanId {
    pub fn to_hex(self) -> String {
        to_hex(&self.0)
    }
    fn is_valid(self) -> bool {
        self.0 != [0u8; 8]
    }
}

/// Why a `traceparent` could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceError {
    /// Not `version-traceid-spanid-flags`, or a field had the wrong length/hex.
    Malformed,
    /// A version this parser does not support.
    UnsupportedVersion,
    /// trace-id or span-id was all zeroes (invalid per W3C).
    AllZeroId,
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceError::Malformed => write!(f, "malformed traceparent"),
            TraceError::UnsupportedVersion => write!(f, "unsupported traceparent version"),
            TraceError::AllZeroId => write!(f, "traceparent has an all-zero id"),
        }
    }
}

impl std::error::Error for TraceError {}

/// A distributed trace context: the trace it belongs to plus the current span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceContext {
    pub trace_id: TraceId,
    pub span_id: SpanId,
}

impl TraceContext {
    pub fn new(trace_id: TraceId, span_id: SpanId) -> Self {
        Self { trace_id, span_id }
    }

    /// Render as a W3C `traceparent` header value (`00-<trace>-<span>-01`).
    pub fn to_traceparent(self) -> String {
        format!("00-{}-{}-01", self.trace_id.to_hex(), self.span_id.to_hex())
    }

    /// Parse a W3C `traceparent`, failing closed on malformed or all-zero ids.
    pub fn parse_traceparent(s: &str) -> Result<Self, TraceError> {
        let mut parts = s.split('-');
        let (Some(version), Some(trace), Some(span), Some(_flags), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(TraceError::Malformed);
        };
        if version != "00" {
            return Err(TraceError::UnsupportedVersion);
        }
        let trace_id = TraceId(from_hex::<16>(trace).ok_or(TraceError::Malformed)?);
        let span_id = SpanId(from_hex::<8>(span).ok_or(TraceError::Malformed)?);
        if !trace_id.is_valid() || !span_id.is_valid() {
            return Err(TraceError::AllZeroId);
        }
        Ok(Self { trace_id, span_id })
    }

    /// Derive a child context in the same trace with a new span.
    pub fn child(self, span_id: SpanId) -> Self {
        Self {
            trace_id: self.trace_id,
            span_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceparent_round_trips() {
        let tc = TraceContext::new(TraceId([0x4b; 16]), SpanId([0x1a; 8]));
        let s = tc.to_traceparent();
        assert_eq!(s, "00-4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b-1a1a1a1a1a1a1a1a-01");
        assert_eq!(TraceContext::parse_traceparent(&s).unwrap(), tc);
    }

    #[test]
    fn parse_rejects_malformed() {
        assert_eq!(
            TraceContext::parse_traceparent("00-tooshort-1a1a1a1a1a1a1a1a-01").unwrap_err(),
            TraceError::Malformed
        );
        assert_eq!(
            TraceContext::parse_traceparent("00-4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b-1a1a1a1a1a1a1a1a")
                .unwrap_err(),
            TraceError::Malformed,
            "missing flags field"
        );
        assert_eq!(
            TraceContext::parse_traceparent(
                "zz-4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b-1a1a1a1a1a1a1a1a-01"
            )
            .unwrap_err(),
            TraceError::UnsupportedVersion
        );
    }

    #[test]
    fn parse_rejects_all_zero_ids() {
        assert_eq!(
            TraceContext::parse_traceparent(
                "00-00000000000000000000000000000000-1a1a1a1a1a1a1a1a-01"
            )
            .unwrap_err(),
            TraceError::AllZeroId
        );
        assert_eq!(
            TraceContext::parse_traceparent(
                "00-4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b-0000000000000000-01"
            )
            .unwrap_err(),
            TraceError::AllZeroId
        );
    }

    #[test]
    fn child_keeps_trace_and_changes_span() {
        let root = TraceContext::new(TraceId([0x4b; 16]), SpanId([0x1a; 8]));
        let child = root.child(SpanId([0x2b; 8]));
        assert_eq!(child.trace_id, root.trace_id);
        assert_ne!(child.span_id, root.span_id);
    }
}
