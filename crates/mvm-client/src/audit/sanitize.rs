//! Free-text sanitization for the verified-audit service boundary.
//!
//! Every string that leaves this service and could reach a UI passes
//! through here first: terminal control sequences are stripped, control
//! characters dropped, lengths capped, sensitive label keys filtered, and
//! values that look like host filesystem paths redacted. A signed audit
//! entry is authentic, but its label values may carry guest-influenced
//! bytes — authenticity is not display-safety.

use std::borrow::Cow;

/// Maximum characters in a rendered `detail` string.
pub const MAX_DETAIL_LEN: usize = 512;

/// Maximum characters in a single field (event name, machine, label value).
pub const MAX_FIELD_LEN: usize = 128;

/// Replacement emitted for values that look like host filesystem paths.
pub const REDACTED_PATH: &str = "[redacted-path]";

/// Marker appended when a string was truncated at the cap.
const TRUNCATION_MARK: char = '…';

/// Strip terminal control sequences and control characters, then cap the
/// result at `max_len` characters (appending a truncation mark when cut).
pub fn sanitize_free_text(input: &str, max_len: usize) -> String {
    cap_chars(&strip_control_sequences(input), max_len)
}

/// Label keys whose values must never be rendered. Substring match on the
/// lowercased key; over-redaction is acceptable, leakage is not.
const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "credential",
    "private",
    "env",
    "key",
    "auth",
];

/// True when a label key names material that must not be rendered
/// (secret values, environment values, credentials, key material).
pub fn is_sensitive_label_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEY_FRAGMENTS.iter().any(|f| lower.contains(f))
}

/// Sanitize one label value for display: host-path-looking values are
/// replaced wholesale, everything else is control-stripped and capped.
pub fn sanitize_label_value(value: &str) -> String {
    match redact_host_path(value) {
        Cow::Borrowed(v) => sanitize_free_text(v, MAX_FIELD_LEN),
        Cow::Owned(redacted) => redacted,
    }
}

/// Replace values that look like filesystem paths. Any absolute path is
/// treated as a potential host path — a UI consumer never needs one, and
/// guessing which absolute paths are "safe" is how leaks happen.
fn redact_host_path(value: &str) -> Cow<'_, str> {
    let trimmed = value.trim_start();
    if trimmed.starts_with('/') || trimmed.starts_with("~/") || value.contains("/.mvm") {
        Cow::Owned(REDACTED_PATH.to_string())
    } else {
        Cow::Borrowed(value)
    }
}

/// Parser state for [`strip_control_sequences`].
enum StripState {
    /// Plain text.
    Normal,
    /// Saw ESC; the next char decides the sequence family.
    Escape,
    /// Inside a CSI sequence (`ESC [` … final byte 0x40–0x7e).
    Csi,
    /// Inside an OSC sequence (`ESC ]` … BEL or `ESC \`).
    Osc,
}

/// Remove ANSI escape sequences (CSI, OSC, and two-char escapes) and all
/// remaining control characters. The output is single-line printable text.
fn strip_control_sequences(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut state = StripState::Normal;
    for c in input.chars() {
        state = match state {
            StripState::Normal => match c {
                '\u{1b}' => StripState::Escape,
                c if c.is_control() => StripState::Normal, // drop
                c => {
                    out.push(c);
                    StripState::Normal
                }
            },
            StripState::Escape => match c {
                '[' => StripState::Csi,
                ']' => StripState::Osc,
                // Two-character escape (ESC + one byte): swallow it.
                _ => StripState::Normal,
            },
            StripState::Csi => {
                // Parameter (0x30–0x3f) and intermediate (0x20–0x2f) bytes
                // continue the sequence; a final byte (0x40–0x7e) ends it.
                if ('\u{40}'..='\u{7e}').contains(&c) {
                    StripState::Normal
                } else {
                    StripState::Csi
                }
            }
            StripState::Osc => match c {
                // OSC terminates on BEL or on ESC (which begins ST `ESC \`).
                '\u{07}' => StripState::Normal,
                '\u{1b}' => StripState::Escape,
                _ => StripState::Osc,
            },
        };
    }
    out
}

/// Cap `s` at `max` characters, appending a truncation mark when cut.
fn cap_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push(TRUNCATION_MARK);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_passes_through() {
        assert_eq!(sanitize_free_text("plan.admitted", 64), "plan.admitted");
    }

    #[test]
    fn csi_color_sequence_is_stripped() {
        assert_eq!(
            sanitize_free_text("\u{1b}[31mred\u{1b}[0m text", 64),
            "red text"
        );
    }

    #[test]
    fn osc_title_sequence_is_stripped() {
        assert_eq!(
            sanitize_free_text("\u{1b}]0;evil title\u{07}after", 64),
            "after"
        );
        // OSC terminated by ST (ESC \) instead of BEL.
        assert_eq!(
            sanitize_free_text("\u{1b}]0;evil\u{1b}\\after", 64),
            "after"
        );
    }

    #[test]
    fn bare_control_chars_are_dropped() {
        assert_eq!(sanitize_free_text("a\rb\nc\td\u{7f}e\u{0}f", 64), "abcdef");
    }

    #[test]
    fn oversized_input_is_capped_with_mark() {
        let long = "x".repeat(600);
        let out = sanitize_free_text(&long, MAX_DETAIL_LEN);
        assert_eq!(out.chars().count(), MAX_DETAIL_LEN);
        assert!(out.ends_with(TRUNCATION_MARK));
    }

    #[test]
    fn exact_cap_is_not_truncated() {
        let exact = "y".repeat(MAX_FIELD_LEN);
        assert_eq!(sanitize_free_text(&exact, MAX_FIELD_LEN), exact);
    }

    #[test]
    fn sensitive_keys_are_detected_case_insensitively() {
        for key in [
            "secret",
            "API_TOKEN",
            "Password",
            "db_credential",
            "private_half",
            "env_vars",
            "key_id",
            "authorization",
        ] {
            assert!(is_sensitive_label_key(key), "{key} must be sensitive");
        }
        for key in ["workload", "cert_fingerprint", "image", "verb", "plan"] {
            assert!(!is_sensitive_label_key(key), "{key} must be renderable");
        }
    }

    #[test]
    fn absolute_paths_are_redacted() {
        assert_eq!(
            sanitize_label_value("/Users/alice/.mvm/keys"),
            REDACTED_PATH
        );
        assert_eq!(sanitize_label_value("/home/bob/thing"), REDACTED_PATH);
        assert_eq!(sanitize_label_value("~/state"), REDACTED_PATH);
        assert_eq!(sanitize_label_value("rel/.mvm/audit"), REDACTED_PATH);
    }

    #[test]
    fn non_path_values_survive_redaction() {
        assert_eq!(sanitize_label_value("sha256:abc123"), "sha256:abc123");
        assert_eq!(sanitize_label_value("worker-vm"), "worker-vm");
    }

    /// Property: for random inputs the sanitizer output never contains a
    /// control character and never exceeds the cap. Hand-rolled property
    /// loop over seeded random bytes, matching the repo's pattern.
    #[test]
    fn property_sanitized_output_is_always_display_safe() {
        use rand::{RngExt, SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(0x5a17);
        for _ in 0..200 {
            let len = rng.random_range(0..1024);
            let bytes: Vec<u8> = (0..len).map(|_| rng.random::<u8>()).collect();
            let input = String::from_utf8_lossy(&bytes);
            let out = sanitize_free_text(&input, MAX_DETAIL_LEN);
            assert!(
                out.chars().all(|c| !c.is_control()),
                "control char survived sanitization: {out:?}"
            );
            assert!(out.chars().count() <= MAX_DETAIL_LEN);
        }
    }

    /// Property: sanitization is idempotent — cleaning clean text is a no-op.
    #[test]
    fn property_sanitization_is_idempotent() {
        use rand::{RngExt, SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(0xf00d);
        for _ in 0..200 {
            let len = rng.random_range(0..600);
            let bytes: Vec<u8> = (0..len).map(|_| rng.random::<u8>()).collect();
            let input = String::from_utf8_lossy(&bytes);
            let once = sanitize_free_text(&input, MAX_DETAIL_LEN);
            let twice = sanitize_free_text(&once, MAX_DETAIL_LEN);
            assert_eq!(once, twice);
        }
    }
}
