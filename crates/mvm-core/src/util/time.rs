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

/// Return the current UTC timestamp in ISO 8601 format.
pub fn utc_now() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Return the UTC timestamp `dur` seconds from now in ISO 8601 format.
/// Saturates at `chrono::DateTime::MAX_UTC` rather than panicking on
/// overflow — callers downstream of `crate::crypto::policy::parse_ttl`
/// already cap the duration to 30d, but this saturates anyway as
/// defense in depth.
pub fn utc_plus_duration(dur: Duration) -> String {
    let secs = i64::try_from(dur.as_secs()).unwrap_or(i64::MAX);
    let delta = chrono::Duration::try_seconds(secs).unwrap_or(chrono::Duration::MAX);
    let dt = Utc::now()
        .checked_add_signed(delta)
        .unwrap_or(DateTime::<Utc>::MAX_UTC);
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Parse an ISO 8601 / RFC 3339 timestamp emitted by `utc_now` /
/// `utc_plus_duration`. Returns `None` if the string can't be parsed,
/// so callers (e.g. the supervisor reaper) can treat malformed
/// expirations as "no TTL" rather than panicking on disk-format drift.
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
        // u64::MAX seconds should not panic; returns MAX_UTC.
        let s = utc_plus_duration(Duration::from_secs(u64::MAX));
        assert!(s.ends_with('Z'));
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
