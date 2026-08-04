//! `FreshnessClaims` — the wire DTO half of plan validity. The window +
//! nonce-replay checks that consume it (`Freshness`, `CheckedFreshness`,
//! `check_window`, `NonceStore`, and the fail-closed `checked` conversion)
//! live in `mvm-core::plan::validity`.

use chrono::{DateTime, Utc};

use crate::plan::types::Nonce;

/// Freshness block embedded inside a signed payload (e.g. a signed plan or
/// a signed reconcile request). It lives inside the signed bytes, so
/// tampering with the window or nonce breaks signature verification
/// upstream.
///
/// Fields are optional on the wire so a payload that predates the block
/// still deserializes; the fail-closed conversion to a verifiable value
/// lives in `mvm-core::plan::validity::checked`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FreshnessClaims {
    #[serde(default)]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(default)]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub nonce: Option<Nonce>,
}

impl FreshnessClaims {
    pub fn new(valid_from: DateTime<Utc>, valid_until: DateTime<Utc>, nonce: Nonce) -> Self {
        Self {
            valid_from: Some(valid_from),
            valid_until: Some(valid_until),
            nonce: Some(nonce),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    /// Locks the byte-identity assumption the whole DTO split rests on:
    /// `DateTime<Utc>` must serialize the same RFC-3339 bytes under the
    /// scoped no_std chrono as it does under the workspace's default
    /// `std` + `clock` chrono, since signed plans are verified over exact
    /// bytes across the mvmd/mvm repo boundary.
    #[test]
    fn datetime_utc_serializes_rfc3339_byte_identical() {
        let dt = Utc.with_ymd_and_hms(2026, 7, 16, 12, 34, 56).unwrap();
        assert_eq!(
            serde_json::to_vec(&dt).unwrap(),
            br#""2026-07-16T12:34:56Z""#
        );
    }

    #[test]
    fn freshness_claims_serde_roundtrips() {
        let dt = Utc.with_ymd_and_hms(2026, 7, 16, 12, 34, 56).unwrap();
        let claims = FreshnessClaims::new(dt, dt, Nonce::from_bytes([7u8; 16]));
        let json = serde_json::to_string(&claims).unwrap();
        let back: FreshnessClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims, back);
    }

    #[test]
    fn absent_fields_deserialize_to_none() {
        let claims: FreshnessClaims = serde_json::from_str("{}").unwrap();
        assert_eq!(claims, FreshnessClaims::default());
    }
}
