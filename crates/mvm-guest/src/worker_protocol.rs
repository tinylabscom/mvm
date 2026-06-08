//! Wire types for the agent ↔ warm-process worker pipe — plan 43 / ADR-0011.
//!
//! Each worker is a long-running wrapper process spawned by the
//! agent at boot. The agent talks to it over its stdin/stdout pipes
//! using length-prefixed JSON frames (4-byte big-endian length, then
//! body). One frame in per call ([`WorkerCallRequest`]), one frame
//! out per call ([`WorkerCallResponse`]).
//!
//! These types are `pub` so mvmforge's runner-wrapper crate can
//! depend on `mvm-guest` directly for the schema — single source of
//! truth, no risk of independent drift between agent and wrapper.
//!
//! `serde(deny_unknown_fields)` on every type satisfies ADR-002 §W4.1
//! / `prod-agent-no-exec` companion contract.

use std::io::{self, Read, Write};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Frame size cap matching the vsock framing (`vsock.rs` MAX_FRAME_SIZE).
/// 256 KiB covers stdin payloads up to ~190 KiB after base64 expansion;
/// payloads larger than that need the streaming chunked-output v2 work
/// (sprint 45 deferred follow-up), not warm-process.
pub const MAX_PIPE_FRAME_SIZE: usize = 256 * 1024;

/// Request frame: agent → worker. One per call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCallRequest {
    /// Bytes piped to the user function. Base64-encoded over JSON.
    #[serde(with = "base64_bytes")]
    pub stdin: Vec<u8>,
    /// Caller's own deadline. The agent enforces this via a
    /// SIGKILL-on-expiry watchdog regardless of whether the wrapper
    /// honors it; the field is informational for the wrapper.
    pub timeout_secs: u64,
    /// Env vars injected into the workload after `env_clear()` (Plan 129).
    /// Empty for a plain call; omitted on the wire defaults to empty.
    #[serde(default)]
    pub env: Vec<(String, String)>,
}

/// Response frame: worker → agent. One per call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCallResponse {
    /// Buffered stdout from the call.
    #[serde(with = "base64_bytes")]
    pub stdout: Vec<u8>,
    /// Buffered stderr from the call. Stays as user output verbatim
    /// — the wrapper does **not** mix structured envelope JSON into
    /// stderr (that gadget is what `controls` exists to replace).
    #[serde(with = "base64_bytes")]
    pub stderr: Vec<u8>,
    /// Per-call control-channel records. Replaces the old `stderr`
    /// envelope-mixing pattern: wrappers emit structured envelopes
    /// through this field, leaving stderr as opaque user output the
    /// host streams to its caller verbatim. Phase 4c — see
    /// `mvm_guest::vsock::EntrypointEvent::Control` for the wire
    /// shape.
    ///
    /// `#[serde(default)]` makes this backward-compatible: a worker
    /// built before Phase 4c that doesn't know about the field will
    /// produce a response without it, and that still deserializes
    /// to an empty Vec. Today's in-tree Python and Node wrappers
    /// haven't been flipped yet (Phase 4d will), so this field is
    /// almost always empty in real boots.
    #[serde(default)]
    pub controls: Vec<WorkerControlRecord>,
    pub outcome: WorkerOutcome,
}

/// One control record on the warm-worker → agent wire. Mirrors
/// `mvm_guest::entrypoint::ControlRecord` but with base64-encoded
/// payload bytes (since the worker frame is JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerControlRecord {
    /// JSON-encoded record header.
    pub header_json: String,
    /// Opaque per-record payload, base64-encoded over JSON.
    #[serde(with = "base64_bytes")]
    pub payload: Vec<u8>,
}

/// Terminal disposition of a single call. The agent maps this onto
/// the existing host-facing `EntrypointEvent` envelope so the
/// `mvmctl invoke` wire stays identical to the cold tier.
///
/// Externally tagged (`{"exit": {...}}` or `{"error": {...}}`) so
/// the inner `Error::kind` field doesn't collide with serde's tag
/// machinery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum WorkerOutcome {
    /// User code returned. `code` is the wrapper's own exit code; 0
    /// for happy path, non-zero for user-code faults that the
    /// wrapper has converted to a sanitized envelope.
    Exit { code: i32 },
    /// Transport-level failure inside the wrapper itself, before or
    /// after user code (e.g. the wrapper failed to deserialize the
    /// request, or panicked outside a call). Maps to
    /// `EntrypointEvent::Error` host-side. Conventionally `kind` is
    /// one of `"wrapper_crash"`, `"timeout"`, or
    /// `"internal_error"`; the agent maps unknown values onto
    /// `RunEntrypointError::InternalError`.
    Error { kind: String, message: String },
}

mod base64_bytes {
    use super::{B64, Deserializer, Engine, Serializer};
    use serde::Deserialize;
    use serde::de::Error as _;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(d)?;
        B64.decode(encoded.as_bytes()).map_err(D::Error::custom)
    }
}

/// Write a single length-prefixed JSON frame. 4-byte big-endian
/// length, then body. Caps the body at [`MAX_PIPE_FRAME_SIZE`] so a
/// runaway serializer doesn't wedge a worker's pipe.
pub fn write_pipe_frame<W: Write, T: Serialize>(w: &mut W, value: &T) -> io::Result<()> {
    let body = serde_json::to_vec(value).map_err(io::Error::other)?;
    if body.len() > MAX_PIPE_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "frame too large: {} bytes (max {})",
                body.len(),
                MAX_PIPE_FRAME_SIZE
            ),
        ));
    }
    let len = (body.len() as u32).to_be_bytes();
    w.write_all(&len)?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Read a single length-prefixed JSON frame. EOF on the length read
/// surfaces as `UnexpectedEof`; oversized lengths surface as
/// `InvalidData` *before* allocating the body buffer (defence
/// against a hostile or buggy peer).
pub fn read_pipe_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len > MAX_PIPE_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {frame_len} bytes (max {MAX_PIPE_FRAME_SIZE})"),
        ));
    }
    let mut body = vec![0u8; frame_len];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_request() {
        let req = WorkerCallRequest {
            stdin: b"hello world".to_vec(),
            timeout_secs: 30,
            env: vec![("HTTP_PROXY".into(), "http://127.0.0.1:18080".into())],
        };
        let mut buf = Vec::new();
        write_pipe_frame(&mut buf, &req).unwrap();
        let mut cur = Cursor::new(buf);
        let back: WorkerCallRequest = read_pipe_frame(&mut cur).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn roundtrip_response_exit() {
        let resp = WorkerCallResponse {
            stdout: b"output bytes".to_vec(),
            stderr: vec![],
            controls: Vec::new(),
            outcome: WorkerOutcome::Exit { code: 0 },
        };
        let mut buf = Vec::new();
        write_pipe_frame(&mut buf, &resp).unwrap();
        let mut cur = Cursor::new(buf);
        let back: WorkerCallResponse = read_pipe_frame(&mut cur).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn roundtrip_response_error() {
        let resp = WorkerCallResponse {
            stdout: vec![],
            stderr: b"sanitized envelope".to_vec(),
            controls: Vec::new(),
            outcome: WorkerOutcome::Error {
                kind: "wrapper_crash".into(),
                message: "panic in user code".into(),
            },
        };
        let mut buf = Vec::new();
        write_pipe_frame(&mut buf, &resp).unwrap();
        let mut cur = Cursor::new(buf);
        let back: WorkerCallResponse = read_pipe_frame(&mut cur).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn binary_payload_roundtrips() {
        let payload: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
        let req = WorkerCallRequest {
            stdin: payload.clone(),
            timeout_secs: 5,
            env: vec![],
        };
        let mut buf = Vec::new();
        write_pipe_frame(&mut buf, &req).unwrap();
        let mut cur = Cursor::new(buf);
        let back: WorkerCallRequest = read_pipe_frame(&mut cur).unwrap();
        assert_eq!(back.stdin, payload);
    }

    #[test]
    fn truncated_length_prefix_errors() {
        let mut cur = Cursor::new(vec![0u8, 0u8]);
        let res: io::Result<WorkerCallRequest> = read_pipe_frame(&mut cur);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn oversized_length_rejected_without_allocating() {
        let mut buf = Vec::new();
        let huge = (MAX_PIPE_FRAME_SIZE as u32 + 1).to_be_bytes();
        buf.extend_from_slice(&huge);
        let mut cur = Cursor::new(buf);
        let res: io::Result<WorkerCallRequest> = read_pipe_frame(&mut cur);
        let err = res.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn truncated_body_errors() {
        let mut buf = Vec::new();
        let len = 100u32.to_be_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&[0u8; 20]); // short body
        let mut cur = Cursor::new(buf);
        let res: io::Result<WorkerCallRequest> = read_pipe_frame(&mut cur);
        let err = res.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn garbage_body_returns_other_error() {
        let mut buf = Vec::new();
        let body = b"not json";
        let len = (body.len() as u32).to_be_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(body);
        let mut cur = Cursor::new(buf);
        let res: io::Result<WorkerCallRequest> = read_pipe_frame(&mut cur);
        assert!(res.is_err());
    }

    #[test]
    fn deny_unknown_fields_on_request() {
        let json = br#"{"stdin": "AA==", "timeout_secs": 1, "smuggled": true}"#;
        let mut buf = Vec::new();
        let len = (json.len() as u32).to_be_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(json);
        let mut cur = Cursor::new(buf);
        let res: io::Result<WorkerCallRequest> = read_pipe_frame(&mut cur);
        assert!(res.is_err());
    }

    #[test]
    fn write_oversized_payload_returns_invalid_data() {
        // The cap is a *frame* cap; a payload that base64-expands
        // past the cap should fail at write time, not corrupt the
        // worker's pipe by writing a partial frame.
        let huge_stdin = vec![0u8; MAX_PIPE_FRAME_SIZE]; // base64 of this expands past 256KiB
        let req = WorkerCallRequest {
            stdin: huge_stdin,
            timeout_secs: 1,
            env: vec![],
        };
        let mut buf = Vec::new();
        let res = write_pipe_frame(&mut buf, &req);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
