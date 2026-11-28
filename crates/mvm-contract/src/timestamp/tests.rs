//! Pinned oracle tests. Every expected value below was produced by chrono 0.4
//! (the serializer these bytes must stay identical to) before chrono left the
//! workspace; the digests cover the full generated sequences.

use super::*;
use sha2::{Digest, Sha256};

fn ours(secs: i64, nanos: u32) -> UtcTimestamp {
    UtcTimestamp::from_unix(secs, nanos).unwrap()
}

fn json(secs: i64, nanos: u32) -> String {
    serde_json::to_string(&ours(secs, nanos)).unwrap()
}

/// Serialize, then parse back to the same instant.
fn round_trip(secs: i64, nanos: u32) -> String {
    let text = json(secs, nanos);
    assert_eq!(
        serde_json::from_str::<UtcTimestamp>(&text).unwrap(),
        ours(secs, nanos)
    );
    text
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
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
    let (mut i, mut midnight, mut digest) = (0usize, from, Sha256::new());
    while midnight < to {
        for s in [midnight - 1, midnight, midnight + 1] {
            digest.update(round_trip(s, NANOS[i % NANOS.len()]).as_bytes());
            digest.update(b"\n");
            i += 1;
        }
        midnight += 86_400;
    }
    assert_eq!(i, 328_719);
    assert_eq!(
        hex(&digest.finalize()),
        "77491b37e3801bd4cf54c80bab10ff544bda202310b776541b8a60de996d19ba"
    );
}

#[test]
fn pseudo_random_instants_across_every_year_serialize_like_chrono() {
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let span = (MAX_SECS - MIN_SECS + 1) as u64;
    let mut digest = Sha256::new();
    for i in 0..200_000usize {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let text = round_trip(MIN_SECS + ((x >> 11) % span) as i64, NANOS[i % NANOS.len()]);
        digest.update(text.as_bytes());
        digest.update(b"\n");
    }
    assert_eq!(
        hex(&digest.finalize()),
        "29e8c5cf13b0264ad7eaa72ecb5b33434efd80436f748c624e655c5bb4ca9492"
    );
    assert_eq!(
        json(MIN_SECS, 999_999_999),
        r#""0000-01-01T00:00:00.999999999Z""#
    );
    assert_eq!(
        json(MAX_SECS, 999_999_999),
        r#""9999-12-31T23:59:59.999999999Z""#
    );
}

#[test]
fn a_string_we_accept_is_accepted_by_chrono_as_the_same_instant() {
    let accepted = [
        ("2024-02-29T23:59:59Z", 1709251199, 0),
        ("2024-02-29T23:59:59.5Z", 1709251199, 500000000),
        ("2024-02-29T23:59:59.123456789Z", 1709251199, 123456789),
        ("2024-02-29T23:59:59.000Z", 1709251199, 0),
        ("0000-01-01T00:00:00Z", -62167219200, 0),
        ("9999-12-31T23:59:59.999999999Z", 253402300799, 999999999),
        ("2000-02-29T12:00:00+05:30", 951805800, 0),
        ("2026-11-20T00:00:00-23:59", 1795219140, 0),
        ("2026-11-20T23:59:59+23:59", 1795132859, 0),
        ("2026-11-20T10:00:00+00:00", 1795168800, 0),
        ("2026-11-20T10:00:00-00:00", 1795168800, 0),
        ("1969-12-31T23:59:59.999999999Z", -1, 999999999),
        ("0001-01-01T00:00:00+00:01", -62135596860, 0),
    ];
    for (s, secs, nanos) in accepted {
        let ts: UtcTimestamp = s.parse().unwrap_or_else(|_| panic!("rejected {s}"));
        assert_eq!((ts.unix_secs(), ts.subsec_nanos()), (secs, nanos), "{s}");
    }
}

/// Mutate one byte of canonical strings; whatever the strict parser still
/// accepts, chrono accepted as the same instant (the digest pins both).
#[test]
fn accepted_mutations_are_a_subset_of_chrono() {
    let mut x = 0x1234_5678_9ABC_DEF0u64;
    let mut next = || {
        x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        (x >> 33) as usize
    };
    let alphabet = b"0123456789-:.+TZtz u";
    let (mut accepted, mut digest) = (0, Sha256::new());
    for i in 0..200_000usize {
        let s = json(
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
            digest.update(format!("{text} {} {}\n", ts.unix_secs(), ts.subsec_nanos()).as_bytes());
        }
    }
    assert_eq!(accepted, 61_999);
    assert_eq!(
        hex(&digest.finalize()),
        "8bdfb1d04dd757a56369547136adf429bac2c96627de7a3b18dbf4b5da14e713"
    );
}

/// Each row is refused by the strict parser; the flag records whether chrono
/// 0.4's relaxed grammar accepted it (the narrowing this type introduced).
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
    for (s, _chrono_accepted) in rows {
        assert!(s.parse::<UtcTimestamp>().is_err(), "accepted {s:?}");
        assert!(serde_json::from_str::<UtcTimestamp>(&format!("{s:?}")).is_err());
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
    let mine = serde_json::to_value(UtcTimestamp::json_schema(&mut generator)).unwrap();
    assert_eq!(
        mine,
        serde_json::json!({"type": "string", "format": "date-time"})
    );
    assert_eq!(UtcTimestamp::schema_name(), "DateTime");
    assert_eq!(UtcTimestamp::schema_id(), "chrono :: DateTime");
    assert!(!UtcTimestamp::is_referenceable());
}

#[test]
fn whole_secs_since_truncates_toward_zero_like_chrono() {
    for (a, an, b, bn, want) in [
        (301, 100, 0, 900, 300),
        (0, 900, 301, 100, -300),
        (5, 0, 5, 0, 0),
        (-3, 5, 4, 0, -6),
    ] {
        assert_eq!(ours(a, an).whole_secs_since(ours(b, bn)), want);
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

#[test]
fn the_epoch_constant_is_the_chrono_epoch() {
    assert_eq!(
        serde_json::to_string(&UtcTimestamp::UNIX_EPOCH).unwrap(),
        r#""1970-01-01T00:00:00Z""#
    );
    assert_eq!(UtcTimestamp::UNIX_EPOCH, ours(0, 0));
}

#[test]
fn duration_arithmetic_stays_in_range() {
    use core::time::Duration;
    let t = ours(10, 900_000_000);
    assert_eq!(
        t.checked_add(Duration::new(1, 200_000_000)),
        Some(ours(12, 100_000_000))
    );
    assert_eq!(
        t.checked_sub(Duration::new(11, 0)),
        Some(ours(-1, 900_000_000))
    );
    assert_eq!(
        t.checked_sub(Duration::new(10, 950_000_000)),
        Some(ours(-1, 950_000_000))
    );
    assert_eq!(UtcTimestamp::MAX, ours(MAX_SECS, 999_999_999));
    assert!(
        UtcTimestamp::MAX
            .checked_add(Duration::from_nanos(1))
            .is_none()
    );
    assert!(
        ours(MIN_SECS, 0)
            .checked_sub(Duration::from_nanos(1))
            .is_none()
    );
    assert!(t.checked_add(Duration::MAX).is_none());
}
