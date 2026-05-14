//! `/job/result` file format. Plan 71 W3.
//!
//! One JSON object on one line, written by `mvm-builder-init` after
//! the job command exits or before poweroff if the init itself fails
//! to launch the job. The host reads this file as the
//! ground-truth "did the build succeed" signal — exit code 0 + the
//! expected artifacts in `/out` means "ship it", anything else means
//! "surface the failure". The format intentionally stays tiny so a
//! corrupted virtio-blk write is recoverable: a partial line is
//! a parse failure, which the host treats as "result file
//! unreadable, fall back to the host-side timeout signal".

use serde::{Deserialize, Serialize};

/// Maximum number of bytes of captured stderr the result file
/// carries. The builder VM streams full stderr live over vsock
/// (plan 57 §W4); this tail is only here so a post-mortem `cat
/// /job/result` shows the last screen of error output without
/// needing to scroll the vsock log. 4 KiB is one terminal screen at
/// 80×50.
pub const STDERR_TAIL_MAX_BYTES: usize = 4096;

/// What `mvm-builder-init` writes to `/job/result` after the job
/// command exits (or before poweroff on init-level failure).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobResult {
    /// Exit code of `/bin/sh -eu /job/cmd.sh`, or one of the
    /// reserved init-level codes:
    ///   2 — `/job/cmd.sh` missing or unreadable.
    ///   3 — failed to mount essentials.
    ///   4 — failed to mount `/dev/vdb` (persistent `/nix` store).
    ///   5 — failed to bring up `eth0` (only in non-offline mode).
    pub code: i32,
    /// Up to [`STDERR_TAIL_MAX_BYTES`] of the job command's stderr,
    /// or a short init-level error message on reserved codes.
    pub stderr_tail: String,
}

impl JobResult {
    /// Build a result with the stderr tail pre-truncated to
    /// [`STDERR_TAIL_MAX_BYTES`].
    pub fn new(code: i32, stderr: impl Into<String>) -> Self {
        let mut tail = stderr.into();
        truncate_to_byte_boundary(&mut tail, STDERR_TAIL_MAX_BYTES);
        Self {
            code,
            stderr_tail: tail,
        }
    }

    /// Convenience constructors for the init-level reserved codes.
    pub fn cmd_missing(detail: impl Into<String>) -> Self {
        Self::new(2, detail)
    }

    pub fn mount_essentials_failed(detail: impl Into<String>) -> Self {
        Self::new(3, detail)
    }

    pub fn mount_nix_store_failed(detail: impl Into<String>) -> Self {
        Self::new(4, detail)
    }

    pub fn network_failed(detail: impl Into<String>) -> Self {
        Self::new(5, detail)
    }

    /// Serialize as a single line — one JSON object, no trailing
    /// newline. Callers append a `\n` if they want one.
    pub fn to_json_line(&self) -> String {
        // `serde_json::to_string` returns "no trailing newline, no
        // pretty-printing, no embedded newlines in keys" which is
        // exactly the on-disk shape we want.
        serde_json::to_string(self).expect("JobResult is always-serializable")
    }

    /// Parse from the on-disk format. Returns `None` if the file is
    /// empty, truncated, or otherwise unparseable — the host treats
    /// this case as "unreadable result, fall back to timeout
    /// signal".
    pub fn parse(line: &str) -> Option<Self> {
        serde_json::from_str(line.trim_end_matches('\n')).ok()
    }
}

/// Trim `s` to at most `max` bytes without cutting through a UTF-8
/// codepoint. Used by [`JobResult::new`] so the stderr tail stays
/// valid JSON even when the underlying capture cuts off mid-rune.
fn truncate_to_byte_boundary(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut boundary = max;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    s.truncate(boundary);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_ascii() {
        let r = JobResult::new(0, "ok");
        let line = r.to_json_line();
        let parsed = JobResult::parse(&line).unwrap();
        assert_eq!(r, parsed);
    }

    #[test]
    fn round_trip_with_trailing_newline() {
        let r = JobResult::new(7, "boom");
        let mut line = r.to_json_line();
        line.push('\n');
        let parsed = JobResult::parse(&line).unwrap();
        assert_eq!(r, parsed);
    }

    #[test]
    fn parse_returns_none_on_garbage() {
        assert!(JobResult::parse("").is_none());
        assert!(JobResult::parse("not json").is_none());
        // Truncated JSON: missing closing brace.
        assert!(JobResult::parse("{\"code\":0,\"stderr_tail\":\"oop").is_none());
    }

    #[test]
    fn stderr_tail_truncates_to_max_bytes() {
        let big = "x".repeat(STDERR_TAIL_MAX_BYTES + 100);
        let r = JobResult::new(1, big);
        assert_eq!(r.stderr_tail.len(), STDERR_TAIL_MAX_BYTES);
    }

    #[test]
    fn stderr_tail_truncation_preserves_utf8_boundaries() {
        // Each "你" is 3 bytes. Build a string whose byte length sits
        // exactly STDERR_TAIL_MAX_BYTES + 1 — truncate must back up
        // to a codepoint boundary, never producing a mid-rune cut
        // that would invalidate the JSON.
        let unit = "你";
        let runes = (STDERR_TAIL_MAX_BYTES / 3) + 2;
        let big: String = unit.repeat(runes);
        let r = JobResult::new(1, big);
        assert!(r.stderr_tail.len() <= STDERR_TAIL_MAX_BYTES);
        assert!(
            r.stderr_tail.is_char_boundary(r.stderr_tail.len()),
            "truncation left a partial codepoint"
        );
        // Survives JSON round-trip.
        let parsed = JobResult::parse(&r.to_json_line()).unwrap();
        assert_eq!(r, parsed);
    }

    #[test]
    fn reserved_codes_match_lib_doc() {
        assert_eq!(JobResult::cmd_missing("").code, 2);
        assert_eq!(JobResult::mount_essentials_failed("").code, 3);
        assert_eq!(JobResult::mount_nix_store_failed("").code, 4);
        assert_eq!(JobResult::network_failed("").code, 5);
    }

    #[test]
    fn json_line_has_no_embedded_newlines() {
        // The host parser reads a single line; an embedded newline
        // in stderr_tail must be JSON-escaped so the line stays
        // whole.
        let r = JobResult::new(1, "first\nsecond\n");
        let line = r.to_json_line();
        assert!(!line.contains('\n'), "raw newline in: {line}");
    }
}
