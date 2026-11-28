use std::time::Duration;

use mvm_contract::timestamp::{ParseTimestampError, UtcTimestamp};

/// Shared wall-clock seam for code that needs deterministic time in tests.
///
/// Kept sync and object-safe so crates that only need a "what time is it now?"
/// dependency do not have to pull in async/runtime abstractions.
pub trait Clock: Send + Sync {
    fn now(&self) -> UtcTimestamp;
}

/// Production wall clock, read through [`utc_timestamp_now`].
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UtcTimestamp {
        utc_timestamp_now()
    }
}

/// Render whole seconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ`.
/// Seconds outside the representable years 0000..=9999 clamp to the nearest
/// bound, so no input can panic or emit a year the format has no width for.
fn rfc3339_from_unix_secs(secs: i64) -> String {
    // 0000-01-01T00:00:00Z and 9999-12-31T23:59:59Z.
    let secs = secs.clamp(-62_167_219_200, 253_402_300_799);
    UtcTimestamp::from_unix(secs, 0)
        .unwrap_or(UtcTimestamp::UNIX_EPOCH)
        .to_string()
}

/// Whole seconds since the Unix epoch, rounded toward negative infinity for
/// instants before it (the rounding `chrono` applies).
fn unix_secs_floor(at: std::time::SystemTime) -> i64 {
    match at.duration_since(std::time::SystemTime::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => {
            let d = e.duration();
            let back = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
            let whole = if d.subsec_nanos() > 0 {
                back.saturating_add(1)
            } else {
                back
            };
            -whole
        }
    }
}

/// Return the current UTC timestamp in ISO 8601 format.
pub fn utc_now() -> String {
    rfc3339_from_system_time(std::time::SystemTime::now())
}

/// `at` as a [`UtcTimestamp`], nanosecond precision, saturating at the epoch
/// for an instant before 1970. Errors when `at` is past year 9999, which the
/// type cannot hold.
pub fn utc_timestamp_at(at: std::time::SystemTime) -> Result<UtcTimestamp, ParseTimestampError> {
    let since_epoch = at
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    UtcTimestamp::from_unix(
        i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX),
        since_epoch.subsec_nanos(),
    )
    .ok_or(ParseTimestampError)
}

/// The current instant as a [`UtcTimestamp`], or an error when the host clock
/// is past year 9999. Every production path that can refuse uses this one, so
/// a bad clock refuses the operation instead of aborting the process.
pub fn try_utc_timestamp_now() -> Result<UtcTimestamp, ParseTimestampError> {
    utc_timestamp_at(std::time::SystemTime::now())
}

/// [`try_utc_timestamp_now`] for a caller with no refusal to make, such as an
/// audit stamp: a host clock past year 9999 reads as the last representable
/// instant, so every validity window and deadline compared to it has passed.
pub fn utc_timestamp_now() -> UtcTimestamp {
    try_utc_timestamp_now().unwrap_or(UtcTimestamp::MAX)
}

/// Render a `SystemTime` as the same ISO 8601 / RFC 3339 shape [`utc_now`]
/// emits, so a filesystem timestamp and a recorded one are comparable by eye
/// and by `parse_iso8601`.
pub fn rfc3339_from_system_time(at: std::time::SystemTime) -> String {
    rfc3339_from_unix_secs(unix_secs_floor(at))
}

/// Return the UTC timestamp `dur` seconds from now in ISO 8601 format.
/// Saturates at `9999-12-31T23:59:59Z` rather than panicking on
/// overflow — callers downstream of `crate::crypto::policy::parse_ttl`
/// already cap the duration to 30d, but this saturates anyway as
/// defense in depth.
pub fn utc_plus_duration(dur: Duration) -> String {
    let secs = i64::try_from(dur.as_secs()).unwrap_or(i64::MAX);
    rfc3339_from_unix_secs(unix_secs_floor(std::time::SystemTime::now()).saturating_add(secs))
}

/// Parse an ISO 8601 / RFC 3339 timestamp emitted by `utc_now` /
/// `utc_plus_duration`. Returns `None` if the string can't be parsed,
/// so callers (e.g. the supervisor reaper) can treat malformed
/// expirations as "no TTL" rather than panicking on disk-format drift.
/// Return the current wall-clock time as whole seconds since the Unix epoch.
/// Saturates at zero if the system clock is before 1970-01-01.
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The current wall-clock time in milliseconds since the Unix epoch, the unit
/// agent-session events are stamped in. Saturates at zero before 1970 and at
/// `u64::MAX` past the representable range.
pub fn now_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

pub fn parse_iso8601(s: &str) -> Option<UtcTimestamp> {
    s.parse().ok()
}

/// The current instant in the `+00:00` form `chrono`'s `to_rfc3339` printed,
/// for labels, receipts and records that have always carried it. A host clock
/// past year 9999 renders as the last representable instant.
pub fn utc_now_rfc3339() -> String {
    utc_timestamp_now().to_rfc3339_offset()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_offset_keeps_the_chrono_form() {
        let at = |secs, nanos| {
            UtcTimestamp::from_unix(secs, nanos)
                .unwrap()
                .to_rfc3339_offset()
        };
        assert_eq!(at(1_790_812_800, 0), "2026-10-01T00:00:00+00:00");
        assert_eq!(
            at(1_790_812_800, 123_000_000),
            "2026-10-01T00:00:00.123+00:00"
        );
        assert_eq!(
            at(1_790_812_800, 123_456_000),
            "2026-10-01T00:00:00.123456+00:00"
        );
        assert_eq!(at(-1, 999_999_999), "1969-12-31T23:59:59.999999999+00:00");
        assert_eq!(at(-62_167_219_200, 0), "0000-01-01T00:00:00+00:00");
        assert_eq!(
            at(253_402_300_799, 1_000),
            "9999-12-31T23:59:59.000001+00:00"
        );
        assert!(utc_now_rfc3339().ends_with("+00:00"));
    }

    #[test]
    fn a_clock_past_year_9999_is_an_error_not_a_panic() {
        let end = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(253_402_300_800);
        assert!(utc_timestamp_at(end).is_err());
        assert!(utc_timestamp_at(end - Duration::from_secs(1)).is_ok());
        assert!(try_utc_timestamp_now().is_ok());
    }

    #[test]
    fn test_utc_now_format() {
        let ts = utc_now();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn utc_plus_duration_advances() {
        let now = utc_timestamp_now();
        let later = parse_iso8601(&utc_plus_duration(Duration::from_secs(60))).unwrap();
        let delta = later.whole_secs_since(now);
        // Allow a generous slack for slow CI hosts.
        assert!((58..=62).contains(&delta), "delta={delta}");
    }

    #[test]
    fn utc_plus_duration_saturates() {
        // u64::MAX seconds must not panic; it clamps to the last renderable second.
        assert_eq!(
            utc_plus_duration(Duration::from_secs(u64::MAX)),
            "9999-12-31T23:59:59Z"
        );
    }

    /// Expected strings are the ones chrono's `%Y-%m-%dT%H:%M:%SZ` printed.
    #[test]
    fn rfc3339_from_system_time_is_byte_identical_to_chrono() {
        use std::time::{Duration as D, UNIX_EPOCH};
        let cases = [
            (UNIX_EPOCH, "1970-01-01T00:00:00Z"),
            (
                UNIX_EPOCH + D::from_secs(1_709_251_199),
                "2024-02-29T23:59:59Z",
            ),
            // The fraction truncates, never rounds.
            (
                UNIX_EPOCH + D::new(1_709_251_199, 999_999_999),
                "2024-02-29T23:59:59Z",
            ),
            (
                UNIX_EPOCH + D::from_secs(2_147_483_648),
                "2038-01-19T03:14:08Z",
            ),
            (
                UNIX_EPOCH + D::from_secs(253_402_300_799),
                "9999-12-31T23:59:59Z",
            ),
            (UNIX_EPOCH - D::from_secs(1), "1969-12-31T23:59:59Z"),
            // A sub-second before the epoch floors to 23:59:59.
            (UNIX_EPOCH - D::new(0, 1), "1969-12-31T23:59:59Z"),
            (
                UNIX_EPOCH - D::new(86_400 * 365, 500_000_000),
                "1968-12-31T23:59:59Z",
            ),
        ];
        for (at, want) in cases {
            assert_eq!(rfc3339_from_system_time(at), want, "{at:?}");
        }
    }

    #[test]
    fn utc_now_matches_the_timestamp_clock_within_a_second() {
        let ours = parse_iso8601(&utc_now()).expect("parses");
        assert!(utc_timestamp_now().whole_secs_since(ours).abs() <= 1);
    }

    #[test]
    fn emitted_z_form_and_offset_form_parse_to_the_same_instant() {
        let z = parse_iso8601("2024-02-29T23:59:59Z").unwrap();
        let off = parse_iso8601("2024-03-01T01:59:59+02:00").unwrap();
        let zero = parse_iso8601("2024-02-29T23:59:59+00:00").unwrap();
        assert_eq!(z, off);
        assert_eq!(z, zero);
        assert_eq!(z.to_string(), "2024-02-29T23:59:59Z");
    }

    #[test]
    fn parse_iso8601_edge_cases() {
        assert!(parse_iso8601("2024-02-30T00:00:00Z").is_none());
        assert!(parse_iso8601("2024-03-01T24:00:00Z").is_none());
        assert!(parse_iso8601("2024-03-01T00:00:00").is_none());
        assert!(parse_iso8601(" 2024-03-01T00:00:00Z").is_none());
        let frac = parse_iso8601("2024-02-29T23:59:59.987Z").unwrap();
        assert_eq!(frac.unix_secs(), 1_709_251_199);
    }

    #[test]
    fn parse_iso8601_roundtrips() {
        let now = utc_now();
        let parsed = parse_iso8601(&now).expect("roundtrip");
        assert_eq!(parsed.to_string(), now);
    }

    #[test]
    fn parse_iso8601_rejects_garbage() {
        assert!(parse_iso8601("").is_none());
        assert!(parse_iso8601("not a date").is_none());
        assert!(parse_iso8601("2024-13-99T99:99:99Z").is_none());
    }
}
