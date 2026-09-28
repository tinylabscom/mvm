//! The error envelope a function-entrypoint wrapper leaves on stderr when the
//! user's function raises.
//!
//! The guest wrapper writes one line, `MVM_ENVELOPE: {"kind", "error_id",
//! "message"}`, and exits non-zero. Other stderr lines may come before it (a
//! dev-mode traceback) or after it (anything the interpreter prints on the way
//! out), so the parser takes the *last* marked line, and it never guesses: a
//! line that does not parse as exactly the three string fields is not an
//! envelope, and the caller falls back to reporting the exit code and the tail
//! of stderr.
//!
//! The bytes are workload output, so nothing here trusts them beyond their
//! shape. The message is whatever the guest chose to say; in production the
//! wrapper has already scrubbed it.

use serde::{Deserialize, Serialize};

/// The prefix the wrapper writes ahead of the envelope's JSON body.
pub const ENVELOPE_MARKER: &str = "MVM_ENVELOPE: ";

/// The longest envelope line the parser will look at. A wrapper's envelope is
/// a class name, a 16-hex id and a scrubbed message, so anything past this is
/// not one, and bounding it keeps a pathological stderr from costing a parse
/// of megabytes.
const MAX_ENVELOPE_LINE: usize = 64 * 1024;

/// What the guest reported about the exception the user's function raised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteErrorEnvelope {
    /// The exception class the guest reported.
    pub kind: String,
    /// The correlation id the guest minted for this failure.
    pub error_id: String,
    /// The message the guest reported.
    pub message: String,
}

/// The last well-formed envelope in `stderr`, or `None` when there is none.
///
/// Only the last marked line counts: an earlier one may be a user's own print
/// of the marker, and the wrapper writes its envelope immediately before it
/// exits.
#[must_use]
pub fn parse_last_envelope(stderr: &[u8]) -> Option<RemoteErrorEnvelope> {
    let text = String::from_utf8_lossy(stderr);
    let body = text
        .lines()
        .rev()
        .find_map(|line| line.trim_end().strip_prefix(ENVELOPE_MARKER))?;
    if body.len() > MAX_ENVELOPE_LINE {
        return None;
    }
    serde_json::from_str(body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope_line(kind: &str, id: &str, message: &str) -> String {
        format!(
            "{ENVELOPE_MARKER}{}\n",
            serde_json::json!({"kind": kind, "error_id": id, "message": message})
        )
    }

    #[test]
    fn a_wrapper_envelope_parses_into_its_three_fields() {
        let stderr = envelope_line("ValueError", "0123456789abcdef", "bad input");
        assert_eq!(
            parse_last_envelope(stderr.as_bytes()),
            Some(RemoteErrorEnvelope {
                kind: "ValueError".into(),
                error_id: "0123456789abcdef".into(),
                message: "bad input".into(),
            })
        );
    }

    #[test]
    fn a_traceback_ahead_of_the_envelope_is_skipped() {
        let stderr = format!(
            "Traceback (most recent call last):\n  File \"x.py\"\nKeyError: 'a'\n\n{}",
            envelope_line("KeyError", "feedfacecafebeef", "'a'")
        );
        let envelope = parse_last_envelope(stderr.as_bytes()).expect("an envelope");
        assert_eq!(envelope.kind, "KeyError");
    }

    #[test]
    fn the_last_marked_line_wins() {
        let stderr = format!(
            "{}noise\n{}",
            envelope_line("First", "1111111111111111", "printed by the user"),
            envelope_line("Second", "2222222222222222", "the real one")
        );
        let envelope = parse_last_envelope(stderr.as_bytes()).expect("an envelope");
        assert_eq!(envelope.kind, "Second");
    }

    #[test]
    fn stderr_without_a_marker_has_no_envelope() {
        assert_eq!(parse_last_envelope(b"segfault\n"), None);
        assert_eq!(parse_last_envelope(b""), None);
    }

    #[test]
    fn a_malformed_body_is_not_an_envelope() {
        assert_eq!(parse_last_envelope(b"MVM_ENVELOPE: {not json}\n"), None);
        assert_eq!(
            parse_last_envelope(b"MVM_ENVELOPE: {\"kind\":\"X\",\"error_id\":\"y\"}\n"),
            None,
            "a missing field is not an envelope"
        );
    }

    #[test]
    fn an_unknown_field_is_not_an_envelope() {
        let stderr = format!(
            "{ENVELOPE_MARKER}{}\n",
            serde_json::json!({"kind": "X", "error_id": "y", "message": "z", "extra": 1})
        );
        assert_eq!(parse_last_envelope(stderr.as_bytes()), None);
    }

    #[test]
    fn a_crlf_line_ending_still_parses() {
        let stderr = envelope_line("E", "abcdabcdabcdabcd", "m").replace('\n', "\r\n");
        assert!(parse_last_envelope(stderr.as_bytes()).is_some());
    }

    #[test]
    fn an_oversized_line_is_refused() {
        let message = "x".repeat(MAX_ENVELOPE_LINE + 1);
        let stderr = envelope_line("E", "abcdabcdabcdabcd", &message);
        assert_eq!(parse_last_envelope(stderr.as_bytes()), None);
    }
}
