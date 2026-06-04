//! TTL / duration parsing with sane bounds.
//!
//! Used by `--ttl 30m`, `mvmctl set-ttl`, and the supervisor reaper.
//! Accepts a small subset of human-friendly suffixes (`s`, `m`, `h`,
//! `d`) plus a bare-integer-seconds form. We deliberately avoid the
//! `humantime` crate's larger surface (years, months, microseconds)
//! because those don't make sense for sandbox lifetimes and only serve
//! to widen the parser attack surface.

use std::time::Duration;

use thiserror::Error;

/// Hard upper bound on a single TTL: 30 days. Sandboxes that need to
/// outlive that should renew explicitly.
pub const MAX_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Hard lower bound: 1 second. Anything tighter is reaper jitter
/// territory and signals user error.
pub const MIN_TTL: Duration = Duration::from_secs(1);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TtlParseError {
    #[error("ttl is empty")]
    Empty,
    #[error("ttl {0:?} is missing a numeric component")]
    NoNumber(String),
    #[error("ttl {0:?} has unknown suffix")]
    UnknownSuffix(String),
    #[error("ttl numeric component {0:?} is not a non-negative integer")]
    BadNumber(String),
    #[error("ttl {dur:?} below minimum {min:?}")]
    BelowMin { dur: Duration, min: Duration },
    #[error("ttl {dur:?} above maximum {max:?}")]
    AboveMax { dur: Duration, max: Duration },
}

/// Parse `30s`, `5m`, `2h`, `7d`, or a bare positive integer (seconds).
pub fn parse_ttl(s: &str) -> Result<Duration, TtlParseError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(TtlParseError::Empty);
    }

    let last = trimmed.chars().last().expect("non-empty after trim");
    let (num_str, multiplier) = if last.is_ascii_digit() {
        (trimmed, 1u64)
    } else {
        let mult = match last {
            's' | 'S' => 1,
            'm' | 'M' => 60,
            'h' | 'H' => 60 * 60,
            'd' | 'D' => 24 * 60 * 60,
            _ => return Err(TtlParseError::UnknownSuffix(trimmed.to_string())),
        };
        let head = &trimmed[..trimmed.len() - last.len_utf8()];
        if head.is_empty() {
            return Err(TtlParseError::NoNumber(trimmed.to_string()));
        }
        (head, mult)
    };

    let n: u64 = num_str
        .parse()
        .map_err(|_| TtlParseError::BadNumber(num_str.to_string()))?;
    let secs = n.saturating_mul(multiplier);
    let dur = Duration::from_secs(secs);

    if dur < MIN_TTL {
        return Err(TtlParseError::BelowMin { dur, min: MIN_TTL });
    }
    if dur > MAX_TTL {
        return Err(TtlParseError::AboveMax { dur, max: MAX_TTL });
    }
    Ok(dur)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_suffixes() {
        assert_eq!(parse_ttl("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_ttl("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_ttl("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_ttl("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_ttl("1d").unwrap(), Duration::from_secs(86400));
    }

    #[test]
    fn parses_bare_seconds() {
        assert_eq!(parse_ttl("60").unwrap(), Duration::from_secs(60));
    }

    #[test]
    fn case_insensitive_suffixes() {
        assert_eq!(parse_ttl("5M").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_ttl("2H").unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(parse_ttl(""), Err(TtlParseError::Empty)));
        assert!(matches!(parse_ttl("   "), Err(TtlParseError::Empty)));
    }

    #[test]
    fn rejects_below_min() {
        assert!(matches!(
            parse_ttl("0s"),
            Err(TtlParseError::BelowMin { .. })
        ));
        assert!(matches!(
            parse_ttl("0"),
            Err(TtlParseError::BelowMin { .. })
        ));
    }

    #[test]
    fn rejects_above_max() {
        assert!(matches!(
            parse_ttl("31d"),
            Err(TtlParseError::AboveMax { .. })
        ));
    }

    #[test]
    fn rejects_unknown_suffix() {
        assert!(matches!(
            parse_ttl("1y"),
            Err(TtlParseError::UnknownSuffix(_))
        ));
        assert!(matches!(
            parse_ttl("5ms"),
            Err(TtlParseError::BadNumber(_)) | Err(TtlParseError::UnknownSuffix(_))
        ));
    }

    #[test]
    fn rejects_bad_number() {
        assert!(matches!(
            parse_ttl("abcs"),
            Err(TtlParseError::BadNumber(_))
        ));
        assert!(matches!(parse_ttl("-5m"), Err(TtlParseError::BadNumber(_))));
    }

    #[test]
    fn rejects_suffix_without_number() {
        assert!(matches!(parse_ttl("m"), Err(TtlParseError::NoNumber(_))));
    }

    #[test]
    fn saturating_arithmetic_does_not_panic() {
        // u64::MAX seconds * 86400 would overflow without saturation.
        let _ = parse_ttl("99999999999999999d"); // returns AboveMax, not a panic
    }
}
