use std::time::Duration;

use chrono::{DateTime, Utc};

/// Shared wall-clock seam for code that needs deterministic time in tests.
///
/// Kept sync and object-safe so crates that only need a "what time is it now?"
/// dependency do not have to pull in async/runtime abstractions.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

/// Production wall clock backed by `chrono::Utc::now()`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Render whole seconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ`.
/// Seconds outside the representable years 0000..=9999 clamp to the nearest
/// bound, so no input can panic or emit a year the format has no width for.
fn rfc3339_from_unix_secs(secs: i64) -> String {
    // 0000-01-01T00:00:00Z and 9999-12-31T23:59:59Z.
    let secs = secs.clamp(-62_167_219_200, 253_402_300_799);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Hinnant's civil-from-days, shifted to a March-based year.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
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

pub fn parse_iso8601(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let now = chrono::Utc::now();
        let later_str = utc_plus_duration(Duration::from_secs(60));
        let later = chrono::DateTime::parse_from_rfc3339(&later_str)
            .unwrap()
            .with_timezone(&chrono::Utc);
        let delta = (later - now).num_seconds();
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

    fn chrono_secs_form(at: std::time::SystemTime) -> String {
        DateTime::<Utc>::from(at)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }

    #[test]
    fn rfc3339_from_system_time_is_byte_identical_to_chrono() {
        use std::time::{Duration as D, SystemTime, UNIX_EPOCH};
        let cases = [
            UNIX_EPOCH,
            UNIX_EPOCH + D::from_secs(1_709_251_199), // 2024-02-29T23:59:59Z, leap day
            UNIX_EPOCH + D::new(1_709_251_199, 999_999_999), // fraction truncates, never rounds
            UNIX_EPOCH + D::from_secs(2_147_483_648), // past i32
            UNIX_EPOCH + D::from_secs(253_402_300_799), // 9999-12-31T23:59:59Z
            UNIX_EPOCH - D::from_secs(1),
            UNIX_EPOCH - D::new(0, 1), // sub-second before the epoch floors to 23:59:59
            UNIX_EPOCH - D::new(86_400 * 365, 500_000_000),
        ];
        for at in cases {
            assert_eq!(rfc3339_from_system_time(at), chrono_secs_form(at), "{at:?}");
        }
        let _ = SystemTime::now();
    }

    #[test]
    fn hand_written_rendering_matches_chrono_across_spread() {
        use std::time::{Duration as D, UNIX_EPOCH};
        let check = |secs: i64| {
            let t = if secs >= 0 {
                UNIX_EPOCH + D::from_secs(secs as u64)
            } else {
                UNIX_EPOCH - D::from_secs(secs.unsigned_abs())
            };
            assert_eq!(rfc3339_from_system_time(t), chrono_secs_form(t), "{secs}");
        };
        // Every day boundary +/- 1s from 1900 to 2200.
        let mut day = -2_208_988_800_i64;
        while day <= 7_258_118_400 {
            for d in [-1, 0, 1] {
                check(day + d);
            }
            day += 86_400;
        }
        // Deterministic xorshift spread over years 0001..=9999.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            check((x % 253_402_300_800) as i64 - 62_135_596_800);
        }
    }

    #[test]
    fn utc_now_matches_chrono_now_within_a_second() {
        let ours = parse_iso8601(&utc_now()).expect("parses");
        assert!((Utc::now() - ours).num_seconds().abs() <= 1);
    }

    #[test]
    fn emitted_z_form_and_chrono_offset_form_parse_to_the_same_instant() {
        let z = parse_iso8601("2024-02-29T23:59:59Z").unwrap();
        let off = parse_iso8601("2024-03-01T01:59:59+02:00").unwrap();
        let zero = parse_iso8601("2024-02-29T23:59:59+00:00").unwrap();
        assert_eq!(z, off);
        assert_eq!(z, zero);
        assert_eq!(
            z.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "2024-02-29T23:59:59Z"
        );
    }

    #[test]
    fn parse_iso8601_edge_cases() {
        assert!(parse_iso8601("2024-02-30T00:00:00Z").is_none());
        assert!(parse_iso8601("2024-03-01T24:00:00Z").is_none());
        assert!(parse_iso8601("2024-03-01T00:00:00").is_none());
        assert!(parse_iso8601(" 2024-03-01T00:00:00Z").is_none());
        let frac = parse_iso8601("2024-02-29T23:59:59.987Z").unwrap();
        assert_eq!(frac.timestamp(), 1_709_251_199);
    }

    #[test]
    fn parse_iso8601_roundtrips() {
        let now = utc_now();
        let parsed = parse_iso8601(&now).expect("roundtrip");
        let formatted = parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        assert_eq!(formatted, now);
    }

    #[test]
    fn parse_iso8601_rejects_garbage() {
        assert!(parse_iso8601("").is_none());
        assert!(parse_iso8601("not a date").is_none());
        assert!(parse_iso8601("2024-13-99T99:99:99Z").is_none());
    }
}
