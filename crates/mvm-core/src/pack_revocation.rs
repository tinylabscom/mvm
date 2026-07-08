//! Signed, fetchable pack revocation list.
//!
//! `pack_trust::PackTrustConfig.revocations` is a hand-placed, operator-owned
//! list — fine once an operator has curated a trust config, useless on a
//! fresh install that has never seen one. This module adds the other half:
//! a list the project itself signs and publishes, so a fresh install can
//! learn about a revoked pack without any local config. `CombinedRevocations`
//! lets a caller union the two sources into one `PackRevocationChecker`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::pack_trust::{RevokedPack, revocation_status};
use crate::packs::{KeylessTrust, PackRevocationChecker, RevocationStatus, Sha256Hex};
use crate::plan::bundle::KeyId;

pub const PACK_REVOCATION_SCHEMA_VERSION: u32 = 1;

/// The project-signed counterpart to `PackTrustConfig.revocations`. Carries
/// its own validity window (`issued_at`/`not_after`) since, unlike an
/// operator's hand-placed config, a fetched list can go stale if the
/// publishing pipeline stalls — a caller that trusted a stale list would
/// miss a real revocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackRevocationList {
    pub schema_version: u32,
    #[serde(default)]
    pub revocations: Vec<RevokedPack>,
    pub issued_at: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl PackRevocationChecker for PackRevocationList {
    fn status(&self, key_id: &KeyId, pack_hash: &Sha256Hex) -> RevocationStatus {
        revocation_status(&self.revocations, key_id, pack_hash)
    }
}

/// Unions any number of revocation sources: a pack is revoked if *any*
/// source revokes it. Lets a caller feed both the fetched
/// `PackRevocationList` and the on-disk `PackTrustConfig` to `verify_pack_at`
/// / `verify_pack_keyless_at` as a single checker.
pub struct CombinedRevocations<'a>(pub Vec<&'a dyn PackRevocationChecker>);

impl PackRevocationChecker for CombinedRevocations<'_> {
    fn status(&self, key_id: &KeyId, pack_hash: &Sha256Hex) -> RevocationStatus {
        for source in &self.0 {
            if let revoked @ RevocationStatus::Revoked { .. } = source.status(key_id, pack_hash) {
                return revoked;
            }
        }
        RevocationStatus::Good
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PackRevocationError {
    #[error("pack revocation list signature is invalid: {0}")]
    SignatureInvalid(String),
    #[error("pack revocation list is not valid JSON: {0}")]
    Parse(String),
    #[error("pack revocation list schema version {found} not supported (expected {supported})")]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("pack revocation list is stale: not_after {not_after} (now {now})")]
    Stale {
        not_after: DateTime<Utc>,
        now: DateTime<Utc>,
    },
}

/// Verify a fetched revocation list's cosign signature, then parse and
/// validate it. Signature verification runs first and the JSON is parsed
/// only after it succeeds — `list_bytes` is untrusted network input until
/// then. Tries every identity in `keyless.accepted_identities` in order and
/// succeeds if any one verifies.
#[cfg(feature = "manifest-verify")]
pub fn verify_pack_revocation_list(
    list_bytes: &[u8],
    cosign_bundle: &[u8],
    keyless: &KeylessTrust,
    now: DateTime<Utc>,
) -> Result<PackRevocationList, PackRevocationError> {
    let mut failure: Option<String> = None;
    let verified = keyless.accepted_identities.iter().any(|identity| {
        match crate::crypto::image_verify::verify_signed_payload(
            list_bytes,
            cosign_bundle,
            identity,
            &keyless.issuer,
        ) {
            Ok(()) => true,
            Err(error) => {
                failure = Some(error.to_string());
                false
            }
        }
    });
    if !verified {
        return Err(PackRevocationError::SignatureInvalid(
            failure.unwrap_or_else(|| {
                "no accepted identities configured for keyless verification".to_string()
            }),
        ));
    }
    let list: PackRevocationList = serde_json::from_slice(list_bytes)
        .map_err(|error| PackRevocationError::Parse(error.to_string()))?;
    if list.schema_version != PACK_REVOCATION_SCHEMA_VERSION {
        return Err(PackRevocationError::UnsupportedSchema {
            found: list.schema_version,
            supported: PACK_REVOCATION_SCHEMA_VERSION,
        });
    }
    if list.not_after <= now {
        return Err(PackRevocationError::Stale {
            not_after: list.not_after,
            now,
        });
    }
    Ok(list)
}

/// No-feature fallback: refuse every fetched revocation list. Builds
/// without `manifest-verify` drop the sigstore dependency tree in exchange
/// for losing the ability to verify a fetched list; the on-disk
/// `PackTrustConfig` revocation path is unaffected.
#[cfg(not(feature = "manifest-verify"))]
pub fn verify_pack_revocation_list(
    _list_bytes: &[u8],
    _cosign_bundle: &[u8],
    _keyless: &KeylessTrust,
    _now: DateTime<Utc>,
) -> Result<PackRevocationList, PackRevocationError> {
    Err(PackRevocationError::SignatureInvalid(
        "manifest-verify feature disabled in this build; rebuild mvmctl with \
         default features to verify a fetched pack revocation list"
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::pack_trust::PackTrustConfig;

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0)
            .single()
            .expect("valid timestamp")
    }

    fn key_id(seed: u8) -> KeyId {
        use ed25519_dalek::SigningKey;
        KeyId::from_pubkey(&SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    fn sample_list() -> PackRevocationList {
        PackRevocationList {
            schema_version: PACK_REVOCATION_SCHEMA_VERSION,
            revocations: vec![RevokedPack {
                key_id: key_id(1),
                pack_hash: None,
                reason: "key compromised".to_string(),
            }],
            issued_at: utc(2026, 1, 1),
            not_after: utc(2026, 12, 31),
        }
    }

    #[test]
    fn list_roundtrips() {
        let list = sample_list();
        let json = serde_json::to_string(&list).expect("serialize");
        let recovered: PackRevocationList = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, list);
    }

    #[test]
    fn unknown_field_is_rejected() {
        let mut value = serde_json::to_value(sample_list()).expect("to_value");
        value
            .as_object_mut()
            .expect("object")
            .insert("surprise".to_string(), serde_json::Value::Bool(true));
        let err = serde_json::from_value::<PackRevocationList>(value).expect_err("rejected");
        assert!(err.to_string().contains("surprise"), "got: {err}");
    }

    #[test]
    fn whole_key_entry_revokes_any_pack_hash() {
        let list = sample_list();
        let id = key_id(1);
        assert!(matches!(
            list.status(&id, &Sha256Hex::from_bytes(b"anything")),
            RevocationStatus::Revoked { .. }
        ));
        assert!(matches!(
            list.status(&id, &Sha256Hex::from_bytes(b"else")),
            RevocationStatus::Revoked { .. }
        ));
    }

    #[test]
    fn pinned_entry_revokes_only_that_pack_hash() {
        let bad = Sha256Hex::from_bytes(b"bad-pack");
        let good = Sha256Hex::from_bytes(b"good-pack");
        let id = key_id(2);
        let list = PackRevocationList {
            schema_version: PACK_REVOCATION_SCHEMA_VERSION,
            revocations: vec![RevokedPack {
                key_id: id.clone(),
                pack_hash: Some(bad.clone()),
                reason: "bad build".to_string(),
            }],
            issued_at: utc(2026, 1, 1),
            not_after: utc(2026, 12, 31),
        };
        assert!(matches!(
            list.status(&id, &bad),
            RevocationStatus::Revoked { .. }
        ));
        assert_eq!(list.status(&id, &good), RevocationStatus::Good);
    }

    #[test]
    fn no_matching_entry_is_good() {
        let list = sample_list();
        let unrelated = key_id(9);
        assert_eq!(
            list.status(&unrelated, &Sha256Hex::from_bytes(b"pack")),
            RevocationStatus::Good
        );
    }

    #[test]
    fn combined_revoked_if_either_source_revokes() {
        let id = key_id(1);
        let list = sample_list(); // revokes key_id(1) wholesale
        let empty_config = PackTrustConfig::default();
        let combined = CombinedRevocations(vec![&list, &empty_config]);
        assert!(matches!(
            combined.status(&id, &Sha256Hex::from_bytes(b"pack")),
            RevocationStatus::Revoked { .. }
        ));
    }

    #[test]
    fn combined_good_if_neither_source_revokes() {
        let unrelated = key_id(42);
        let list = sample_list();
        let empty_config = PackTrustConfig::default();
        let combined = CombinedRevocations(vec![&list, &empty_config]);
        assert_eq!(
            combined.status(&unrelated, &Sha256Hex::from_bytes(b"pack")),
            RevocationStatus::Good
        );
    }

    #[cfg(feature = "manifest-verify")]
    #[test]
    fn garbage_bundle_is_signature_invalid() {
        let keyless = crate::release_trust::revocation_keyless_trust();
        let list_bytes = serde_json::to_vec(&sample_list()).expect("json");
        let err = verify_pack_revocation_list(
            &list_bytes,
            b"not a real bundle",
            &keyless,
            utc(2026, 6, 1),
        )
        .expect_err("garbage bundle must fail signature verification");
        assert!(matches!(err, PackRevocationError::SignatureInvalid(_)));
    }

    #[cfg(not(feature = "manifest-verify"))]
    #[test]
    fn no_feature_build_always_refuses() {
        let keyless = crate::release_trust::revocation_keyless_trust();
        let list_bytes = serde_json::to_vec(&sample_list()).expect("json");
        let err = verify_pack_revocation_list(&list_bytes, b"anything", &keyless, utc(2026, 6, 1))
            .expect_err("no-feature build always refuses");
        assert!(matches!(err, PackRevocationError::SignatureInvalid(_)));
    }
}
