//! Byte-safe adapter for supplemental sensitive-data detectors.
//!
//! The egress boundary accepts arbitrary bytes. Text detectors therefore scan
//! only validated UTF-8 islands, and every dependency-provided span is checked
//! before it can index or rewrite the original payload.

use leakguard::{Kind, Redactor};
use mvm_core::policy::SensitiveClass;

/// A validated sensitive byte span. It deliberately carries no matched value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensitiveMatch {
    pub class: SensitiveClass,
    pub category: &'static str,
    pub start: usize,
    pub end: usize,
}

/// A detector invariant failed. Fields are structural metadata only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DetectionError {
    #[error("detector returned unsupported category {category}")]
    UnsupportedCategory { category: String },
    #[error("detector returned invalid byte span {start}..{end} for {input_len}-byte input")]
    InvalidSpan {
        start: usize,
        end: usize,
        input_len: usize,
    },
    #[error("detector returned overlapping or unsorted byte span at {start}")]
    OverlappingSpan { start: usize },
}

/// Byte-oriented sensitive detector contract used by MVM enforcement paths.
pub trait SensitiveDetector: Send + Sync {
    fn detect(&self, input: &[u8]) -> Result<Vec<SensitiveMatch>, DetectionError>;
}

/// Reviewed LeakGuard credential detectors that supplement MVM's curated set.
pub struct LeakGuardCredentialDetector {
    redactor: Redactor,
}

impl LeakGuardCredentialDetector {
    pub fn new() -> Self {
        Self {
            redactor: Redactor::only(&[
                Kind::Jwt,
                Kind::UrlCredentials,
                Kind::PrivateKey,
                Kind::AzureConnectionString,
                Kind::TelegramToken,
                Kind::DiscordToken,
            ]),
        }
    }
}

impl Default for LeakGuardCredentialDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SensitiveDetector for LeakGuardCredentialDetector {
    fn detect(&self, input: &[u8]) -> Result<Vec<SensitiveMatch>, DetectionError> {
        let mut found = Vec::new();
        for_each_utf8_island(input, |base, text| {
            for matched in self.redactor.find(text) {
                let category = category_for(&matched.kind)?;
                validate_span(text, matched.start, matched.end)?;
                found.push(SensitiveMatch {
                    class: SensitiveClass::Secret,
                    category,
                    start: base + matched.start,
                    end: base + matched.end,
                });
            }
            Ok(())
        })?;
        found.sort_by_key(|matched| matched.start);
        validate_order(&found)?;
        Ok(found)
    }
}

/// Replace validated spans with one fixed mask without exposing matched bytes.
pub fn mask_matches(
    input: &[u8],
    matches: &[SensitiveMatch],
    mask: &[u8],
) -> Result<Vec<u8>, DetectionError> {
    validate_order(matches)?;
    let mut output = Vec::with_capacity(input.len());
    let mut cursor = 0usize;
    for matched in matches {
        if matched.end > input.len() || matched.start >= matched.end {
            return Err(DetectionError::InvalidSpan {
                start: matched.start,
                end: matched.end,
                input_len: input.len(),
            });
        }
        output.extend_from_slice(&input[cursor..matched.start]);
        output.extend_from_slice(mask);
        cursor = matched.end;
    }
    output.extend_from_slice(&input[cursor..]);
    Ok(output)
}

fn for_each_utf8_island(
    input: &[u8],
    mut inspect: impl FnMut(usize, &str) -> Result<(), DetectionError>,
) -> Result<(), DetectionError> {
    let mut cursor = 0usize;
    while cursor < input.len() {
        match std::str::from_utf8(&input[cursor..]) {
            Ok(text) => {
                inspect(cursor, text)?;
                break;
            }
            Err(error) => {
                let valid_len = error.valid_up_to();
                if valid_len > 0 {
                    let end = cursor + valid_len;
                    let text = std::str::from_utf8(&input[cursor..end])
                        .expect("valid_up_to identifies valid UTF-8");
                    inspect(cursor, text)?;
                    cursor = end;
                }
                let Some(invalid_len) = error.error_len() else {
                    break;
                };
                cursor += invalid_len;
            }
        }
    }
    Ok(())
}

fn validate_span(input: &str, start: usize, end: usize) -> Result<(), DetectionError> {
    if start >= end
        || end > input.len()
        || !input.is_char_boundary(start)
        || !input.is_char_boundary(end)
    {
        return Err(DetectionError::InvalidSpan {
            start,
            end,
            input_len: input.len(),
        });
    }
    Ok(())
}

fn validate_order(matches: &[SensitiveMatch]) -> Result<(), DetectionError> {
    let mut cursor = 0usize;
    for matched in matches {
        if matched.start < cursor {
            return Err(DetectionError::OverlappingSpan {
                start: matched.start,
            });
        }
        cursor = matched.end;
    }
    Ok(())
}

fn category_for(kind: &Kind) -> Result<&'static str, DetectionError> {
    match kind {
        Kind::Jwt => Ok("jwt"),
        Kind::UrlCredentials => Ok("url_credentials"),
        Kind::PrivateKey => Ok("pem_private_key"),
        Kind::AzureConnectionString => Ok("azure_connection_string"),
        Kind::TelegramToken => Ok("telegram_token"),
        Kind::DiscordToken => Ok("discord_token"),
        other => Err(DetectionError::UnsupportedCategory {
            category: other.label().to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_each_utf8_island_and_preserves_global_offsets() {
        let detector = LeakGuardCredentialDetector::new();
        let jwt = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature1234";
        let mut input = vec![0xff];
        input.extend_from_slice(jwt);
        input.push(0xfe);
        input.extend_from_slice(b"tail");

        let matches = detector.detect(&input).expect("valid detector output");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].start, 1);
        assert_eq!(matches[0].end, 1 + jwt.len());
        let masked = mask_matches(&input, &matches, b"XXX").expect("validated spans");
        assert_eq!(masked[0], 0xff);
        assert_eq!(&masked[1..4], b"XXX");
        assert!(masked.ends_with(b"\xfetail"));
    }

    #[test]
    fn invalid_or_overlapping_spans_are_errors_without_reading_values() {
        let invalid = SensitiveMatch {
            class: SensitiveClass::Secret,
            category: "fixture",
            start: 2,
            end: 20,
        };
        assert!(matches!(
            mask_matches(b"short", &[invalid], b"XXX"),
            Err(DetectionError::InvalidSpan { .. })
        ));

        let overlapping = [
            SensitiveMatch {
                class: SensitiveClass::Secret,
                category: "fixture",
                start: 0,
                end: 3,
            },
            SensitiveMatch {
                class: SensitiveClass::Secret,
                category: "fixture",
                start: 2,
                end: 4,
            },
        ];
        assert!(matches!(
            mask_matches(b"value", &overlapping, b"XXX"),
            Err(DetectionError::OverlappingSpan { .. })
        ));
    }

    #[test]
    fn reviewed_credential_families_have_stable_categories() {
        let detector = LeakGuardCredentialDetector::new();
        let cases = [
            (
                "url_credentials",
                "https://alice:synthetic-password@example.invalid/path".to_string(),
            ),
            ("telegram_token", format!("12345678:{}", "A".repeat(35))),
            (
                "discord_token",
                format!("M{}.{}.{}", "A".repeat(22), "B".repeat(6), "C".repeat(30)),
            ),
        ];

        for (expected, input) in cases {
            let matches = detector.detect(input.as_bytes()).expect("valid spans");
            assert_eq!(matches.len(), 1, "input category {expected}: {matches:?}");
            assert_eq!(matches[0].category, expected);
            let masked =
                mask_matches(input.as_bytes(), &matches, b"XXX").expect("detector spans are valid");
            assert_ne!(masked, input.as_bytes(), "{expected} was not masked");
        }
    }
}
