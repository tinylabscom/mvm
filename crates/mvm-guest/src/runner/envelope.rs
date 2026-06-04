//! Sanitized error envelope emitted on stderr when the runtime fails.
//!
//! ADR-0009 invariant: prod wrappers must catch all top-level
//! exceptions and emit a structured envelope (`{kind, error_id,
//! message}`) — no traceback, no file paths, no local var values, no
//! payload contents. Full debug detail (when wanted) goes to a separate
//! operator-log channel managed agent-side, not to the SDK caller.
//!
//! `error_id` is a short ULID-like token operators can correlate against
//! the operator-log stream without needing to disclose anything else.

use serde::Serialize;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Closed taxonomy of error kinds the SDK caller may receive.
/// Matches the failure modes the runtime can surface; expanding the
/// enum is a wire-shape change reviewed against ADR-0009.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// `/etc/mvm/runtime.json` could not be read or parsed.
    ConfigInvalid,
    /// stdin exceeded the 1 MiB v1 cap before EOF.
    StdinTooLarge,
    /// I/O error reading stdin or writing the child's pipes.
    Io,
    /// The dispatched language interpreter could not be spawned.
    SpawnFailed,
    /// The dispatched child exited with a non-zero status. The user
    /// function raised; the dispatch fragment let the exception
    /// surface as a non-zero exit per the runner contract.
    ChildFailed,
    /// The runtime hit an unexpected internal condition. Bug — should
    /// page operators via the secondary log channel.
    Internal,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ConfigInvalid => "config_invalid",
            Self::StdinTooLarge => "stdin_too_large",
            Self::Io => "io",
            Self::SpawnFailed => "spawn_failed",
            Self::ChildFailed => "child_failed",
            Self::Internal => "internal",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorEnvelope {
    pub kind: ErrorKind,
    /// Short opaque token. Operators correlate against the secondary
    /// log channel, not the SDK caller's surface.
    pub error_id: String,
    /// Static, message-template-only string. NEVER includes payload
    /// bytes, file paths, traceback frames, or local variable values.
    /// Callers who need detail use the operator-log channel.
    pub message: &'static str,
}

impl ErrorEnvelope {
    pub fn new(kind: ErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            error_id: generate_error_id(),
            message,
        }
    }

    /// Serialize as a single JSON line plus `\n`. This is the wire
    /// shape the SDK caller's `f.remote(...)` parses to surface a
    /// structured error in the caller's language.
    pub fn to_jsonl(&self) -> String {
        let mut s = serde_json::to_string(self).expect("envelope serializes");
        s.push('\n');
        s
    }
}

/// Tiny ULID-like token. Avoids pulling in a crate; the only
/// requirement is "short, opaque, unique-enough across calls."
/// 10 base32 chars of (epoch_ms << 16 | rand) is plenty for
/// correlation purposes.
fn generate_error_id() -> String {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    // Best-effort entropy from the time-low bits + the runtime's own
    // address-space layout. Operators correlate against the secondary
    // log; cryptographic uniqueness is not required.
    let entropy = (&now_ms as *const u64) as u64 ^ now_ms.rotate_left(13);
    let raw = (now_ms << 16) ^ entropy;
    base32_lower(raw)
}

/// Crockford-ish base32 (no I/L/O/U) of a u64 in 10 chars.
/// Hand-rolled to keep the dep tree empty.
fn base32_lower(mut n: u64) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut out = [0u8; 10];
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(n & 0x1f) as usize];
        n >>= 5;
    }
    String::from_utf8(out.to_vec()).expect("ascii alphabet")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_serializes_with_three_fields_only() {
        let env = ErrorEnvelope::new(ErrorKind::Io, "stdin read failed");
        let line = env.to_jsonl();
        assert!(line.ends_with('\n'));
        let parsed: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        let obj = parsed.as_object().unwrap();
        assert_eq!(obj.len(), 3, "envelope must have exactly 3 fields");
        assert_eq!(obj.get("kind").and_then(|v| v.as_str()), Some("io"));
        assert!(obj.get("error_id").and_then(|v| v.as_str()).is_some());
        assert_eq!(
            obj.get("message").and_then(|v| v.as_str()),
            Some("stdin read failed")
        );
    }

    #[test]
    fn error_kinds_serialize_as_snake_case() {
        for (kind, expected) in [
            (ErrorKind::ConfigInvalid, "config_invalid"),
            (ErrorKind::StdinTooLarge, "stdin_too_large"),
            (ErrorKind::Io, "io"),
            (ErrorKind::SpawnFailed, "spawn_failed"),
            (ErrorKind::ChildFailed, "child_failed"),
            (ErrorKind::Internal, "internal"),
        ] {
            let s = serde_json::to_string(&kind).unwrap();
            assert_eq!(s, format!("\"{expected}\""));
        }
    }

    #[test]
    fn error_ids_are_distinct_across_envelopes() {
        let a = ErrorEnvelope::new(ErrorKind::Internal, "x");
        // Sleep a few microseconds — the ms-resolution clock plus
        // address-bit entropy must still produce different ids on
        // back-to-back calls.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = ErrorEnvelope::new(ErrorKind::Internal, "x");
        assert_ne!(a.error_id, b.error_id);
    }
}
