//! Differential tests with chrono as the oracle.

use super::*;
use chrono::{DateTime, Utc};

fn chrono_at(secs: i64, nanos: u32) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, nanos).unwrap()
}

fn chrono_json(secs: i64, nanos: u32) -> String {
    serde_json::to_string(&chrono_at(secs, nanos)).unwrap()
}

fn ours(secs: i64, nanos: u32) -> UtcTimestamp {
    UtcTimestamp::from_unix(secs, nanos).unwrap()
}

/// Serialize equal to chrono, and the text parses back to the same instant
/// under both parsers.
fn assert_agrees(secs: i64, nanos: u32) {
    let ts = ours(secs, nanos);
    let json = serde_json::to_string(&ts).unwrap();
    assert_eq!(json, chrono_json(secs, nanos), "serialize {secs} {nanos}");
    assert_eq!(serde_json::from_str::<UtcTimestamp>(&json).unwrap(), ts);
    let c: DateTime<Utc> = serde_json::from_str(&json).unwrap();
    assert_eq!((c.timestamp(), c.timestamp_subsec_nanos()), (secs, nanos));
}

const NANOS: [u32; 8] = [
    0,
    1,
    1_000,
    1_000_000,
    120_000_000,
    123_456_789,
    500_000_000,
    999_999_999,
];

#[test]
fn every_day_boundary_in_1900_to_2200_serializes_like_chrono() {
    let (from, to) = (-2_208_988_800i64, 7_258_118_400i64);
    let mut i = 0usize;
    let mut midnight = from;
    while midnight < to {
        for s in [midnight - 1, midnight, midnight + 1] {
            assert_agrees(s, NANOS[i % NANOS.len()]);
            i += 1;
        }
        midnight += 86_400;
    }
}

#[test]
fn pseudo_random_instants_across_every_year_serialize_like_chrono() {
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let span = (MAX_SECS - MIN_SECS + 1) as u64;
    for i in 0..200_000usize {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        assert_agrees(MIN_SECS + ((x >> 11) % span) as i64, NANOS[i % NANOS.len()]);
    }
    for edge in [MIN_SECS, MAX_SECS] {
        assert_agrees(edge, 999_999_999);
    }
}

#[test]
fn a_string_we_accept_is_accepted_by_chrono_as_the_same_instant() {
    let accepted = [
        "2024-02-29T23:59:59Z",
        "2024-02-29T23:59:59.5Z",
        "2024-02-29T23:59:59.123456789Z",
        "2024-02-29T23:59:59.000Z",
        "0000-01-01T00:00:00Z",
        "9999-12-31T23:59:59.999999999Z",
        "2000-02-29T12:00:00+05:30",
        "2026-11-20T00:00:00-23:59",
        "2026-11-20T23:59:59+23:59",
        "2026-11-20T10:00:00+00:00",
        "2026-11-20T10:00:00-00:00",
        "1969-12-31T23:59:59.999999999Z",
        "0001-01-01T00:00:00+00:01",
    ];
    for s in accepted {
        let ts: UtcTimestamp = s.parse().unwrap_or_else(|_| panic!("rejected {s}"));
        let c = DateTime::parse_from_rfc3339(s).unwrap();
        assert_eq!(
            (c.timestamp(), c.timestamp_subsec_nanos()),
            (ts.unix_secs(), ts.subsec_nanos()),
            "{s}"
        );
    }
}

/// Mutate one byte of canonical strings; whatever the strict parser still
/// accepts, chrono must accept as the same instant.
#[test]
fn accepted_mutations_are_a_subset_of_chrono() {
    let mut x = 0x1234_5678_9ABC_DEF0u64;
    let mut next = || {
        x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        (x >> 33) as usize
    };
    let alphabet = b"0123456789-:.+TZtz u";
    let mut accepted = 0;
    for i in 0..200_000usize {
        let s = chrono_json(
            MIN_SECS + (next() as i64 * 99_991) % (MAX_SECS - MIN_SECS),
            NANOS[i % 8],
        );
        let mut b = s.trim_matches('"').as_bytes().to_vec();
        let at = next() % b.len();
        b[at] = alphabet[next() % alphabet.len()];
        let Ok(text) = core::str::from_utf8(&b) else {
            continue;
        };
        if let Ok(ts) = text.parse::<UtcTimestamp>() {
            accepted += 1;
            let c = DateTime::parse_from_rfc3339(text).unwrap_or_else(|_| panic!("{text}"));
            assert_eq!(
                (c.timestamp(), c.timestamp_subsec_nanos()),
                (ts.unix_secs(), ts.subsec_nanos()),
                "{text}"
            );
        }
    }
    assert!(accepted > 1_000, "mutation set too weak: {accepted}");
}

/// Each row is refused by the strict parser; the flag records whether chrono
/// 0.4's relaxed grammar accepts it (the narrowing this type introduces).
#[test]
fn non_canonical_forms_are_rejected() {
    let rows: [(&str, bool); 36] = [
        ("2026-11-20t10:00:00Z", true),
        ("2026-11-20T10:00:00z", true),
        ("2026-11-20 10:00:00Z", true),
        ("2026-1-2T3:4:5Z", true),
        ("26-11-20T10:00:00Z", true),
        (" 2026-11-20T10:00:00Z", true),
        ("2026-11-20T10:00:00Z ", true),
        ("2026-11-20T10:00:00 Z", true),
        ("2026-11-20T10:00:00UTC", true),
        ("2026-11-20T10:00:00+0000", true),
        ("2026-11-20T10:00:00.1234567890Z", true),
        ("2026-11-20T10:00:60Z", true),
        ("+10000-11-20T10:00:00Z", true),
        ("-0001-11-20T10:00:00Z", true),
        ("0000-01-01T00:00:00+00:01", true),
        ("9999-12-31T23:59:59-00:01", true),
        ("2026-11-20T10:00:00.Z", false),
        ("2026-11-20T10:00:00,5Z", false),
        ("2026-11-20T10:00:00", false),
        ("2026-11-20T10:00Z", false),
        ("2026-11-20T10:00:00+05", false),
        ("2026-11-20T24:00:00Z", false),
        ("2026-11-20T10:00:00+24:00", false),
        ("2026-11-20T10:00:00+23:60", false),
        ("2026-11-20T10:60:00Z", false),
        ("2026-02-29T10:00:00Z", false),
        ("2100-02-29T10:00:00Z", false),
        ("2026-13-01T10:00:00Z", false),
        ("2026-00-10T10:00:00Z", false),
        ("2026-04-31T10:00:00Z", false),
        ("2026-11-20T10:00:00Zjunk", false),
        ("2026-11-20T10:00:00.5", false),
        ("2026-11-20T10:00:00+05:3", false),
        ("2026-11-20T+1:00:00Z", false),
        ("", false),
        ("2026-11-20", false),
    ];
    for (s, chrono_accepts) in rows {
        assert!(s.parse::<UtcTimestamp>().is_err(), "accepted {s:?}");
        assert!(serde_json::from_str::<UtcTimestamp>(&format!("{s:?}")).is_err());
        assert_eq!(
            serde_json::from_str::<DateTime<Utc>>(&format!("{s:?}")).is_ok(),
            chrono_accepts,
            "chrono on {s:?}"
        );
    }
}

#[test]
fn a_non_string_json_value_is_rejected() {
    assert!(serde_json::from_str::<UtcTimestamp>("1700000000").is_err());
    assert!(serde_json::from_str::<UtcTimestamp>("null").is_err());
}

#[test]
fn construction_refuses_out_of_range_and_full_second_nanos() {
    assert!(UtcTimestamp::from_unix(MIN_SECS - 1, 0).is_none());
    assert!(UtcTimestamp::from_unix(MAX_SECS + 1, 0).is_none());
    assert!(UtcTimestamp::from_unix(0, 1_000_000_000).is_none());
    assert!(ours(MAX_SECS, 0).checked_add_secs(1).is_none());
    assert_eq!(ours(10, 7).checked_add_secs(-11), Some(ours(-1, 7)));
}

#[test]
fn accessors_and_ordering_follow_the_instant() {
    let t = ours(-1, 999_000_000);
    assert_eq!(t.unix_millis(), -1_000 + 999);
    assert!(ours(-1, 999_999_999) < ours(0, 0));
    assert!(ours(5, 1) > ours(5, 0));
}

#[cfg(feature = "schema")]
#[test]
fn the_schema_is_exactly_chromos() {
    use schemars::JsonSchema;
    let mut generator = schemars::r#gen::SchemaGenerator::default();
    let theirs = serde_json::to_value(DateTime::<Utc>::json_schema(&mut generator)).unwrap();
    let mine = serde_json::to_value(UtcTimestamp::json_schema(&mut generator)).unwrap();
    assert_eq!(mine, theirs);
    assert_eq!(UtcTimestamp::schema_name(), DateTime::<Utc>::schema_name());
    assert_eq!(UtcTimestamp::schema_id(), DateTime::<Utc>::schema_id());
    assert_eq!(
        UtcTimestamp::is_referenceable(),
        DateTime::<Utc>::is_referenceable()
    );
}

#[test]
fn whole_secs_since_truncates_toward_zero_like_chrono() {
    use chrono::{DateTime, Utc};
    for (a, an, b, bn) in [
        (301, 100, 0, 900),
        (0, 900, 301, 100),
        (5, 0, 5, 0),
        (-3, 5, 4, 0),
    ] {
        let chrono_secs = (DateTime::<Utc>::from_timestamp(a, an).unwrap()
            - DateTime::<Utc>::from_timestamp(b, bn).unwrap())
        .num_seconds();
        assert_eq!(ours(a, an).whole_secs_since(ours(b, bn)), chrono_secs);
    }
    assert_eq!(
        ours(MAX_SECS, 0).whole_secs_since(ours(MIN_SECS, 0)),
        MAX_SECS - MIN_SECS
    );
}

#[test]
fn duration_since_keeps_nanoseconds_and_refuses_a_later_earlier() {
    use core::time::Duration;
    assert_eq!(
        ours(301, 100).duration_since(ours(0, 900)),
        Some(Duration::new(300, 999_999_200))
    );
    assert_eq!(ours(5, 0).duration_since(ours(5, 0)), Some(Duration::ZERO));
    assert_eq!(ours(0, 900).duration_since(ours(301, 100)), None);
    assert_eq!(
        ours(MAX_SECS, 0).duration_since(ours(MIN_SECS, 0)),
        Some(Duration::from_secs((MAX_SECS - MIN_SECS) as u64))
    );
}

#[cfg(feature = "protocol")]
#[test]
fn the_chrono_bridge_keeps_the_instant_and_refuses_what_it_cannot_hold() {
    for (secs, nanos) in [
        (0, 0),
        (1_784_205_296, 123_456_789),
        (MIN_SECS, 0),
        (MAX_SECS, 999_999_999),
    ] {
        assert_eq!(
            UtcTimestamp::try_from(chrono_at(secs, nanos)),
            Ok(ours(secs, nanos))
        );
    }
    // Year 10000 and year -1 (chrono's `+`/`-` prefixed range), and a leap second.
    for dt in [
        chrono_at(MAX_SECS + 1, 0),
        chrono_at(MIN_SECS - 1, 0),
        chrono_at(59, 1_500_000_000),
    ] {
        assert_eq!(UtcTimestamp::try_from(dt), Err(ParseTimestampError));
    }
}

#[cfg(feature = "protocol")]
#[test]
fn the_chrono_grant_bridge_round_trips_at_the_range_edges() {
    for (secs, nanos) in [
        (0, 0),
        (1_784_205_296, 123_456_789),
        (MIN_SECS, 0),
        (MAX_SECS, 999_999_999),
    ] {
        let t = ours(secs, nanos);
        let dt: DateTime<Utc> = t.into();
        assert_eq!(dt, chrono_at(secs, nanos));
        assert_eq!(UtcTimestamp::try_from(dt), Ok(t));
    }
}
