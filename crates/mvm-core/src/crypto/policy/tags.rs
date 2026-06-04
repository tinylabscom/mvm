//! Tag input validation.
//!
//! Tags are tenant-controlled key/value pairs attached to sandboxes,
//! templates, and audit-event envelopes. They flow into JSON-line audit
//! records, signed-event webhook bodies, and Prometheus metric labels —
//! every one of which has its own injection class. A single chokepoint
//! validator keeps the constraints consistent.
//!
//! # Constraints
//!
//! - Keys match `[a-zA-Z0-9._-]{1,64}`. Conservative; mirrors what
//!   Prometheus, Kubernetes, and AWS allow as label-key intersections.
//! - Values are UTF-8, no ASCII control chars (rejects `\n`, `\r`,
//!   `\t`, `\0`, etc.), max 256 bytes. Control-char rejection prevents
//!   audit-line injection: a tag value with `\n` would otherwise let a
//!   tenant forge an audit record.
//! - Per-sandbox aggregate: ≤ 32 entries, ≤ 4 KiB total bytes
//!   (sum of key-len + value-len). Matches the "tags as metadata, not a
//!   datastore" intent and bounds memory in `InstanceState`.

use std::collections::BTreeMap;

use thiserror::Error;

/// Maximum key length, in bytes.
pub const MAX_TAG_KEY_LEN: usize = 64;
/// Maximum value length, in bytes.
pub const MAX_TAG_VALUE_LEN: usize = 256;
/// Maximum number of tag entries per object.
pub const MAX_TAGS: usize = 32;
/// Maximum aggregate bytes (sum of key+value lengths) per tag map.
pub const MAX_TAG_BYTES: usize = 4 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TagValidationError {
    #[error("too many tags ({count}, max {MAX_TAGS})")]
    TooMany { count: usize },
    #[error("tag map exceeds {MAX_TAG_BYTES} byte aggregate (got {bytes})")]
    AggregateTooLarge { bytes: usize },
    #[error("tag key empty")]
    KeyEmpty,
    #[error("tag key {key:?} exceeds {MAX_TAG_KEY_LEN} bytes")]
    KeyTooLong { key: String },
    #[error("tag key {key:?} contains disallowed character {ch:?}")]
    KeyBadChar { key: String, ch: char },
    #[error("tag value for {key:?} exceeds {MAX_TAG_VALUE_LEN} bytes")]
    ValueTooLong { key: String },
    #[error("tag value for {key:?} contains ASCII control character (0x{byte:02x})")]
    ValueControlChar { key: String, byte: u8 },
}

pub struct InputValidator;

impl InputValidator {
    /// Validate a single tag key against the charset + length rules.
    pub fn validate_tag_key(key: &str) -> Result<(), TagValidationError> {
        if key.is_empty() {
            return Err(TagValidationError::KeyEmpty);
        }
        if key.len() > MAX_TAG_KEY_LEN {
            return Err(TagValidationError::KeyTooLong {
                key: key.to_string(),
            });
        }
        for ch in key.chars() {
            let ok = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-');
            if !ok {
                return Err(TagValidationError::KeyBadChar {
                    key: key.to_string(),
                    ch,
                });
            }
        }
        Ok(())
    }

    /// Validate a single tag value against the charset + length rules.
    pub fn validate_tag_value(key: &str, value: &str) -> Result<(), TagValidationError> {
        if value.len() > MAX_TAG_VALUE_LEN {
            return Err(TagValidationError::ValueTooLong {
                key: key.to_string(),
            });
        }
        for &b in value.as_bytes() {
            // Reject every C0 control + DEL. Lets through every printable
            // UTF-8 (encoded bytes ≥ 0x80) — non-ASCII is fine.
            if b < 0x20 || b == 0x7f {
                return Err(TagValidationError::ValueControlChar {
                    key: key.to_string(),
                    byte: b,
                });
            }
        }
        Ok(())
    }

    /// Validate an entire tag map against count + aggregate rules.
    pub fn validate_tag_map(tags: &BTreeMap<String, String>) -> Result<(), TagValidationError> {
        if tags.len() > MAX_TAGS {
            return Err(TagValidationError::TooMany { count: tags.len() });
        }
        let mut total = 0usize;
        for (k, v) in tags {
            Self::validate_tag_key(k)?;
            Self::validate_tag_value(k, v)?;
            total = total.saturating_add(k.len()).saturating_add(v.len());
        }
        if total > MAX_TAG_BYTES {
            return Err(TagValidationError::AggregateTooLarge { bytes: total });
        }
        Ok(())
    }

    /// Parse a `KEY=VALUE` CLI argument into a (key, value) pair, validating
    /// each side. The split is on the first `=`; values may contain further
    /// `=` characters.
    pub fn parse_tag_arg(arg: &str) -> Result<(String, String), TagValidationError> {
        let (key, value) = match arg.split_once('=') {
            Some((k, v)) => (k.trim(), v),
            None => (arg.trim(), ""),
        };
        Self::validate_tag_key(key)?;
        Self::validate_tag_value(key, value)?;
        Ok((key.to_string(), value.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_accept_charset() {
        for k in ["a", "A", "0", ".", "_", "-", "abc.def_ghi-123"] {
            InputValidator::validate_tag_key(k).unwrap_or_else(|e| panic!("{k:?}: {e}"));
        }
    }

    #[test]
    fn keys_reject_empty_and_too_long() {
        assert!(matches!(
            InputValidator::validate_tag_key(""),
            Err(TagValidationError::KeyEmpty)
        ));
        let long = "a".repeat(MAX_TAG_KEY_LEN + 1);
        assert!(matches!(
            InputValidator::validate_tag_key(&long),
            Err(TagValidationError::KeyTooLong { .. })
        ));
    }

    #[test]
    fn keys_reject_bad_chars() {
        for k in [
            "bad space",
            "bad/slash",
            "bad:colon",
            "bad\nnewline",
            "bad😀",
        ] {
            assert!(
                matches!(
                    InputValidator::validate_tag_key(k),
                    Err(TagValidationError::KeyBadChar { .. })
                ),
                "should reject {k:?}",
            );
        }
    }

    #[test]
    fn values_accept_unicode() {
        for v in ["", "hello", "with spaces", "héllo", "日本語", "emoji 😀 ok"] {
            InputValidator::validate_tag_value("k", v).unwrap_or_else(|e| panic!("{v:?}: {e}"));
        }
    }

    #[test]
    fn values_reject_control_chars() {
        for v in ["new\nline", "tab\there", "null\0byte", "esc\x1b"] {
            assert!(
                matches!(
                    InputValidator::validate_tag_value("k", v),
                    Err(TagValidationError::ValueControlChar { .. })
                ),
                "should reject {v:?}",
            );
        }
    }

    #[test]
    fn values_reject_too_long() {
        let long = "a".repeat(MAX_TAG_VALUE_LEN + 1);
        assert!(matches!(
            InputValidator::validate_tag_value("k", &long),
            Err(TagValidationError::ValueTooLong { .. })
        ));
    }

    #[test]
    fn map_rejects_too_many() {
        let tags: BTreeMap<String, String> = (0..MAX_TAGS + 1)
            .map(|i| (format!("k{i}"), "v".to_string()))
            .collect();
        assert!(matches!(
            InputValidator::validate_tag_map(&tags),
            Err(TagValidationError::TooMany { .. })
        ));
    }

    #[test]
    fn map_rejects_aggregate_overflow() {
        // 17 entries × ~256 bytes value > 4 KiB
        let tags: BTreeMap<String, String> = (0..17)
            .map(|i| (format!("k{i}"), "v".repeat(MAX_TAG_VALUE_LEN)))
            .collect();
        assert!(matches!(
            InputValidator::validate_tag_map(&tags),
            Err(TagValidationError::AggregateTooLarge { .. })
        ));
    }

    #[test]
    fn map_accepts_typical() {
        let mut tags = BTreeMap::new();
        tags.insert("job".to_string(), "etl".to_string());
        tags.insert("env".to_string(), "production".to_string());
        tags.insert("owner".to_string(), "alice@example.com".to_string());
        InputValidator::validate_tag_map(&tags).unwrap();
    }

    #[test]
    fn parse_tag_arg_splits_on_first_eq() {
        let (k, v) = InputValidator::parse_tag_arg("color=red=hot").unwrap();
        assert_eq!(k, "color");
        assert_eq!(v, "red=hot");
    }

    #[test]
    fn parse_tag_arg_handles_no_eq() {
        let (k, v) = InputValidator::parse_tag_arg("flag").unwrap();
        assert_eq!(k, "flag");
        assert_eq!(v, "");
    }

    #[test]
    fn parse_tag_arg_validates_both_sides() {
        assert!(matches!(
            InputValidator::parse_tag_arg("bad space=value"),
            Err(TagValidationError::KeyBadChar { .. })
        ));
        assert!(matches!(
            InputValidator::parse_tag_arg("k=bad\nvalue"),
            Err(TagValidationError::ValueControlChar { .. })
        ));
    }
}
