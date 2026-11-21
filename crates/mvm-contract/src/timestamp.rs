//! A UTC instant at nanosecond precision whose serialized form is exactly the
//! one `chrono::DateTime<Utc>` writes, so signed and hashed evidence does not
//! change when a field moves to it.
//!
//! Writing: `YYYY-MM-DDTHH:MM:SS[.fff[fff[fff]]]Z` — no fraction when the
//! nanoseconds are zero, otherwise the shortest of 3, 6 or 9 digits.
//!
//! Reading is deliberately stricter than chrono: only canonical RFC 3339 is
//! accepted (fixed-width digits, uppercase `T` and `Z`, a UTC or `±HH:MM`
//! offset, 1-9 fraction digits, years 0000-9999, no leap second). The range is
//! the year-0000..=9999 span, so a value outside it cannot be constructed
//! instead of being written with chrono's `+`/`-` year prefix.

use core::fmt;
use core::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// 0000-01-01T00:00:00Z and 9999-12-31T23:59:59Z as Unix seconds.
const MIN_SECS: i64 = -62_167_219_200;
const MAX_SECS: i64 = 253_402_300_799;

/// Instants order by (seconds, nanoseconds), which the field order gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTimestamp {
    secs: i64,
    nanos: u32,
}

/// The text was not canonical RFC 3339 or named an instant outside 0000..=9999.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseTimestampError;

impl fmt::Display for ParseTimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a canonical RFC 3339 UTC timestamp in years 0000-9999")
    }
}

impl core::error::Error for ParseTimestampError {}

impl UtcTimestamp {
    /// `None` when `nanos` is a full second or more, or the instant is outside
    /// years 0000..=9999.
    pub fn from_unix(secs: i64, nanos: u32) -> Option<Self> {
        ((MIN_SECS..=MAX_SECS).contains(&secs) && nanos < 1_000_000_000)
            .then_some(Self { secs, nanos })
    }

    /// Whole seconds since the Unix epoch (floored for instants before it).
    pub fn unix_secs(self) -> i64 {
        self.secs
    }

    /// The nanoseconds past [`Self::unix_secs`].
    pub fn subsec_nanos(self) -> u32 {
        self.nanos
    }

    /// Milliseconds since the Unix epoch, floored.
    pub fn unix_millis(self) -> i64 {
        self.secs * 1_000 + i64::from(self.nanos / 1_000_000)
    }

    /// Whole seconds from `earlier` to `self`, truncated toward zero.
    pub fn whole_secs_since(self, earlier: Self) -> i64 {
        let nanos = |t: Self| i128::from(t.secs) * 1_000_000_000 + i128::from(t.nanos);
        // Both lie within years 0000..=9999, so the quotient fits an i64.
        ((nanos(self) - nanos(earlier)) / 1_000_000_000) as i64
    }

    /// `None` when the result leaves years 0000..=9999.
    pub fn checked_add_secs(self, secs: i64) -> Option<Self> {
        Self::from_unix(self.secs.checked_add(secs)?, self.nanos)
    }
}

#[cfg(feature = "protocol")]
/// Temporary bridge for fields still typed `chrono::DateTime<Utc>` (the plan's
/// validity pair, the host clock); it goes with chrono. Refuses, rather than
/// clamps, an instant outside years 0000..=9999 or a leap-second nanosecond.
impl TryFrom<chrono::DateTime<chrono::Utc>> for UtcTimestamp {
    type Error = ParseTimestampError;

    fn try_from(dt: chrono::DateTime<chrono::Utc>) -> Result<Self, Self::Error> {
        Self::from_unix(dt.timestamp(), dt.timestamp_subsec_nanos()).ok_or(ParseTimestampError)
    }
}

/// Hinnant's days-from-civil; `month` is 1..=12.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Hinnant's civil-from-days, the inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        yoe + era * 400 + i64::from(month <= 2),
        month,
        doy - (153 * mp + 2) / 5 + 1,
    )
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl fmt::Display for UtcTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (year, month, day) = civil_from_days(self.secs.div_euclid(86_400));
        let rem = self.secs.rem_euclid(86_400);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
            rem / 3_600,
            rem % 3_600 / 60,
            rem % 60
        )?;
        match self.nanos {
            0 => {}
            n if n % 1_000_000 == 0 => write!(f, ".{:03}", n / 1_000_000)?,
            n if n % 1_000 == 0 => write!(f, ".{:06}", n / 1_000)?,
            n => write!(f, ".{n:09}")?,
        }
        f.write_str("Z")
    }
}

/// A fixed-width run of ASCII digits as a number.
fn digits(b: &[u8]) -> Option<i64> {
    b.iter().try_fold(0i64, |acc, d| {
        d.is_ascii_digit().then(|| acc * 10 + i64::from(d - b'0'))
    })
}

/// The fraction's nanoseconds: 1 to 9 digits, scaled to nine.
fn fraction_nanos(b: &[u8]) -> Option<u32> {
    if b.is_empty() || b.len() > 9 {
        return None;
    }
    let scale = 10i64.pow(u32::try_from(9 - b.len()).ok()?);
    u32::try_from(digits(b)? * scale).ok()
}

/// The zone as seconds east of UTC: `Z`, or `+HH:MM` / `-HH:MM` within 23:59.
fn offset_secs(b: &[u8]) -> Option<i64> {
    match b {
        b"Z" => Some(0),
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let (h, m) = (digits(&[*h1, *h2])?, digits(&[*m1, *m2])?);
            if h > 23 || m > 59 {
                return None;
            }
            let secs = h * 3_600 + m * 60;
            Some(if *sign == b'-' { -secs } else { secs })
        }
        _ => None,
    }
}

impl FromStr for UtcTimestamp {
    type Err = ParseTimestampError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse(s.as_bytes()).ok_or(ParseTimestampError)
    }
}

fn parse(b: &[u8]) -> Option<UtcTimestamp> {
    // `YYYY-MM-DDTHH:MM:SS` is 19 bytes; the zone and any fraction follow.
    let (head, rest) = b.split_at_checked(19)?;
    let &[
        y0,
        y1,
        y2,
        y3,
        b'-',
        mo0,
        mo1,
        b'-',
        d0,
        d1,
        b'T',
        h0,
        h1,
        b':',
        mi0,
        mi1,
        b':',
        s0,
        s1,
    ] = head
    else {
        return None;
    };
    let (year, month, day) = (
        digits(&[y0, y1, y2, y3])?,
        digits(&[mo0, mo1])?,
        digits(&[d0, d1])?,
    );
    let (hour, min, sec) = (digits(&[h0, h1])?, digits(&[mi0, mi1])?, digits(&[s0, s1])?);
    if !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hour > 23
        || min > 59
        || sec > 59
    {
        return None;
    }
    let (nanos, zone) = match rest.split_first()? {
        (b'.', tail) => {
            let end = tail.iter().position(|c| !c.is_ascii_digit())?;
            (fraction_nanos(&tail[..end])?, &tail[end..])
        }
        _ => (0, rest),
    };
    let local = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + min * 60 + sec;
    UtcTimestamp::from_unix(local - offset_secs(zone)?, nanos)
}

impl Serialize for UtcTimestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for UtcTimestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = UtcTimestamp;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a canonical RFC 3339 UTC timestamp")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<UtcTimestamp, E> {
                v.parse().map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for UtcTimestamp {
    fn is_referenceable() -> bool {
        false
    }

    // The name and id chrono's impl reports (its id carries the spaces of a
    // stringified path), so a schema naming this type is identical to one that
    // named `DateTime<Utc>`.
    fn schema_name() -> alloc::string::String {
        "DateTime".into()
    }

    fn schema_id() -> alloc::borrow::Cow<'static, str> {
        "chrono :: DateTime".into()
    }

    fn json_schema(_: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            format: Some("date-time".into()),
            ..Default::default()
        }
        .into()
    }
}

#[cfg(test)]
mod tests;
