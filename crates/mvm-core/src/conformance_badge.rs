//! Signed, offline-verifiable conformance badges for MVM-SEC claims.
//!
//! A [`ConformanceBadge`] is a signed export of the existing claim/witness
//! program (`model/claims.toml` + test corpus). It lets a runtime or SDK prove
//! which MVM-SEC claims it satisfies without requiring a live CI query.
//!
//! The wire format is influenced by Project NANDA's `sm-conformance`, but
//! re-implemented on mvm's existing Ed25519/JCS/SHA-256 stack.
//!
//! # Important
//!
//! A badge is **not** the source of truth for conformance. The source of truth
//! remains `model/claims.toml`, the actual tests, and the `xtask` gates. A badge
//! is a portable, signed snapshot of a passing run.

use crate::did_key::DidKey;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The signed payload of a conformance badge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceBadge {
    /// Wire schema version. Const `1` for this version.
    #[serde(default = "schema_version_default")]
    pub schema_version: u32,
    /// Runtime or SDK name, e.g. `mvmctl`.
    pub runtime: String,
    /// Protocol versions covered, e.g. `["0.1"]`.
    pub protocol_versions: Vec<String>,
    /// `sha256:<hex>` over the conformance vector corpus.
    pub suite_digest: String,
    /// RFC 3339 UTC timestamp of when the suite completed.
    pub completed_at: String,
    /// Exit status of the suite runner.
    pub exit_status: i64,
    /// Counts from the suite run.
    pub passed: u64,
    pub failed: u64,
    pub skipped: u64,
    pub xfailed: u64,
    pub xpassed: u64,
    pub errored: u64,
    /// Optional total vector count (self-attested).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_vectors: Option<u64>,
    /// Identities of any skipped vectors.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub skipped_vectors: BTreeSet<String>,
    /// MVM-SEC claim IDs covered by this badge.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub claims: BTreeSet<String>,
    /// Kinds of evidence each claim rests on, derived from `model/claims.toml`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub witness_kinds: BTreeMap<String, Vec<String>>,
    /// Namespace-prefixed extensions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
}

fn schema_version_default() -> u32 {
    1
}

/// A signed conformance badge envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedConformanceBadge {
    /// The signed payload.
    pub payload: ConformanceBadge,
    /// `did:key` of the signer.
    pub signed_by: String,
    /// RFC 3339 UTC timestamp of signing. **Not signed** — forgeable.
    pub signed_at: String,
    /// Base64 Ed25519 signature over `canonical_json(payload)`.
    pub signature: String,
}

/// Admission / verification policy for a conformance badge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BadgeAdmission {
    /// If true, verify only the signature and schema; do not gate the run
    /// result. Use with care — a verified badge with `failed: 99` is still
    /// cryptographically valid.
    pub signature_only: bool,
    /// Expected `suite_digest`. A badge pinning a different corpus is rejected.
    pub expected_suite_digest: Option<String>,
    /// Expected total vector count. Catches an honest partial run.
    pub expected_total_vectors: Option<u64>,
    /// Maximum allowed skipped vectors.
    pub max_skipped: Option<u64>,
    /// Skipped vector IDs that are forbidden.
    pub forbid_skip: BTreeSet<String>,
    /// Require `skipped_vectors` to be present when `skipped > 0`.
    pub require_skip_ids: bool,
    /// Expected `extensions.mvm.build` value.
    pub expected_build: Option<String>,
    /// Maximum age in days of the signed `completed_at`.
    pub max_age_days: Option<u64>,
}

/// Error type for badge operations.
#[derive(Debug, thiserror::Error)]
pub enum BadgeError {
    /// The payload value space was violated.
    #[error("payload contains a value outside the signed value space: {0}")]
    InvalidValueSpace(String),
    /// JSON serialization or deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// Signing or verification failed.
    #[error("signature error: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
    /// The `signed_by` field did not match the signature's public key.
    #[error("signed_by did:key does not match the signature key")]
    SignerMismatch,
    /// The badge recorded failures or errors.
    #[error(
        "badge records failed={failed}, errored={errored}, exit_status={exit_status}, xfailed={xfailed}"
    )]
    NonPassing {
        failed: u64,
        errored: u64,
        exit_status: i64,
        xfailed: u64,
    },
    /// The `suite_digest` did not match the expected value.
    #[error("suite_digest mismatch: expected {expected}, got {actual}")]
    SuiteDigestMismatch { expected: String, actual: String },
    /// The `total_vectors` count did not match the expected value.
    #[error("total_vectors mismatch: expected {expected}, got {actual}")]
    TotalVectorsMismatch { expected: u64, actual: u64 },
    /// Too many vectors were skipped.
    #[error("too many skipped vectors: {actual} > {max}")]
    TooManySkipped { max: u64, actual: u64 },
    /// A forbidden vector was skipped.
    #[error("skipped vector {0} is forbidden")]
    ForbiddenSkip(String),
    /// `skipped_vectors` was required but missing or incomplete.
    #[error("skipped vector IDs are required but missing or incomplete")]
    MissingSkipIds,
    /// The `extensions.mvm.build` value did not match.
    #[error("build mismatch: expected {expected}, got {actual}")]
    BuildMismatch { expected: String, actual: String },
    /// The badge was too old.
    #[error("badge is older than {max_age_days} days")]
    TooOld { max_age_days: u64 },
    /// The badge timestamp was too far in the future.
    #[error("badge timestamp is in the future")]
    FutureTimestamp,
    /// The `did:key` could not be parsed.
    #[error("did:key parse error: {0}")]
    DidKey(#[from] crate::did_key::DidKeyError),
    /// An I/O error occurred while computing a corpus digest.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl ConformanceBadge {
    /// Prefix for corpus digests.
    pub const DIGEST_PREFIX: &'static str = "sha256:";

    /// Compute the `suite_digest` over a corpus directory.
    ///
    /// The digest is over all `*.json` files, sorted by POSIX-relative path,
    /// with NUL-delimited path bytes and raw file bytes. This matches the
    /// stability rules from `sm-conformance` so the same corpus produces the
    /// same digest across platforms.
    pub fn compute_suite_digest(corpus_dir: impl AsRef<Path>) -> Result<String, BadgeError> {
        let corpus_dir = corpus_dir.as_ref();
        let mut entries: Vec<(PathBuf, Vec<u8>)> = Vec::new();
        Self::collect_json_files(corpus_dir, corpus_dir, &mut entries)?;
        entries.sort_by(|(a, _), (b, _)| a.as_os_str().cmp(b.as_os_str()));

        let mut hasher = Sha256::new();
        for (path, bytes) in entries {
            hasher.update(path.as_os_str().as_encoded_bytes());
            hasher.update([0u8]);
            hasher.update(&bytes);
        }
        Ok(format!(
            "{}{}",
            Self::DIGEST_PREFIX,
            hex::encode(hasher.finalize())
        ))
    }

    fn collect_json_files(
        root: &Path,
        current: &Path,
        out: &mut Vec<(PathBuf, Vec<u8>)>,
    ) -> Result<(), BadgeError> {
        for entry in std::fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                Self::collect_json_files(root, &path, out)?;
            } else if path.extension().map(|ext| ext == "json").unwrap_or(false) {
                let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
                let bytes = std::fs::read(&path)?;
                out.push((relative, bytes));
            }
        }
        Ok(())
    }

    /// Return the `extensions.mvm.build` value, if present.
    pub fn build(&self) -> Option<&str> {
        self.extensions.get("mvm.build").and_then(|v| v.as_str())
    }

    /// Verify the self-attested accounting, independent of signature.
    ///
    /// Checks that `passed + failed + skipped + xfailed + xpassed + errored`
    /// equals `total_vectors` when `total_vectors` is present.
    pub fn verify_accounting(&self) -> Result<(), BadgeError> {
        if let Some(total) = self.total_vectors {
            let sum = self
                .passed
                .saturating_add(self.failed)
                .saturating_add(self.skipped)
                .saturating_add(self.xfailed)
                .saturating_add(self.xpassed)
                .saturating_add(self.errored);
            if sum != total {
                return Err(BadgeError::TotalVectorsMismatch {
                    expected: total,
                    actual: sum,
                });
            }
        }
        Ok(())
    }
}

impl SignedConformanceBadge {
    /// Sign a conformance badge payload.
    pub fn sign(
        payload: ConformanceBadge,
        signing_key: &SigningKey,
        signed_at: impl Into<String>,
    ) -> Result<Self, BadgeError> {
        payload.verify_accounting()?;
        let did = DidKey::from_verifying_key(signing_key.verifying_key());
        let canonical = canonical_json(&payload)?;
        let signature = signing_key.sign(&canonical);
        Ok(Self {
            payload,
            signed_by: did.to_did_key(),
            signed_at: signed_at.into(),
            signature: BASE64_STANDARD.encode(signature.to_bytes()),
        })
    }

    /// Verify the badge signature and reject non-passing runs.
    ///
    /// A badge recording any failures, errors, or a non-zero exit status is
    /// rejected. Use [`Self::verify_with_admission`] with
    /// `signature_only: true` to verify only the signature.
    pub fn verify(&self) -> Result<(), BadgeError> {
        self.verify_with_admission(&BadgeAdmission::default())
    }

    /// Verify with an explicit admission policy.
    pub fn verify_with_admission(&self, admission: &BadgeAdmission) -> Result<(), BadgeError> {
        self.payload.verify_accounting()?;

        let did = DidKey::parse(&self.signed_by)?;
        let vk = did.verifying_key();
        let canonical = canonical_json(&self.payload)?;
        let sig_bytes = BASE64_STANDARD
            .decode(&self.signature)
            .map_err(|e| BadgeError::InvalidValueSpace(format!("base64: {e}")))?;
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)?;
        vk.verify(&canonical, &sig)?;
        if *vk != *DidKey::parse(&self.signed_by)?.verifying_key() {
            return Err(BadgeError::SignerMismatch);
        }

        if !admission.signature_only
            && (self.payload.failed != 0
                || self.payload.errored != 0
                || self.payload.exit_status != 0
                || self.payload.xfailed != 0)
        {
            return Err(BadgeError::NonPassing {
                failed: self.payload.failed,
                errored: self.payload.errored,
                exit_status: self.payload.exit_status,
                xfailed: self.payload.xfailed,
            });
        }

        if let Some(expected) = &admission.expected_suite_digest
            && expected != &self.payload.suite_digest
        {
            return Err(BadgeError::SuiteDigestMismatch {
                expected: expected.clone(),
                actual: self.payload.suite_digest.clone(),
            });
        }

        if let Some(expected) = admission.expected_total_vectors {
            let actual = self.payload.total_vectors.unwrap_or(0);
            if expected != actual {
                return Err(BadgeError::TotalVectorsMismatch { expected, actual });
            }
        }

        if let Some(max) = admission.max_skipped
            && self.payload.skipped > max
        {
            return Err(BadgeError::TooManySkipped {
                max,
                actual: self.payload.skipped,
            });
        }

        if admission.require_skip_ids
            && self.payload.skipped > 0
            && self.payload.skipped_vectors.len() as u64 != self.payload.skipped
        {
            return Err(BadgeError::MissingSkipIds);
        }

        for forbidden in &admission.forbid_skip {
            if self.payload.skipped_vectors.contains(forbidden) {
                return Err(BadgeError::ForbiddenSkip(forbidden.clone()));
            }
        }

        if let Some(expected) = &admission.expected_build {
            let actual = self.payload.build().unwrap_or("");
            if expected != actual {
                return Err(BadgeError::BuildMismatch {
                    expected: expected.clone(),
                    actual: actual.to_string(),
                });
            }
        }

        if let Some(max_age_days) = admission.max_age_days {
            let completed = chrono::DateTime::parse_from_rfc3339(&self.payload.completed_at)
                .map_err(|e| BadgeError::InvalidValueSpace(format!("completed_at: {e}")))?;
            let now = chrono::Utc::now();
            if completed > now + chrono::TimeDelta::minutes(5) {
                return Err(BadgeError::FutureTimestamp);
            }
            let age = now - completed.to_utc();
            if age > chrono::TimeDelta::days(max_age_days as i64) {
                return Err(BadgeError::TooOld { max_age_days });
            }
        }

        Ok(())
    }
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, BadgeError> {
    let json_value = serde_json::to_value(value)?;
    validate_value_space(&json_value)?;
    Ok(serde_jcs::to_vec(&json_value)?)
}

fn validate_value_space(value: &Value) -> Result<(), BadgeError> {
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(()),
        Value::Number(n) => Err(BadgeError::InvalidValueSpace(format!(
            "float or non-integer number: {n}"
        ))),
        Value::String(s) => {
            if s.is_ascii() {
                Ok(())
            } else {
                Err(BadgeError::InvalidValueSpace(format!(
                    "non-ASCII string: {s:?}"
                )))
            }
        }
        Value::Array(values) => {
            for v in values {
                validate_value_space(v)?;
            }
            Ok(())
        }
        Value::Object(entries) => {
            for (k, v) in entries {
                if !k.is_ascii() {
                    return Err(BadgeError::InvalidValueSpace(format!(
                        "non-ASCII object key: {k:?}"
                    )));
                }
                validate_value_space(v)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    fn sample_badge() -> ConformanceBadge {
        ConformanceBadge {
            schema_version: 1,
            runtime: "mvmctl".into(),
            protocol_versions: vec!["0.1".into()],
            suite_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .into(),
            completed_at: "2026-08-06T00:00:00+00:00".into(),
            exit_status: 0,
            passed: 42,
            failed: 0,
            skipped: 0,
            xfailed: 0,
            xpassed: 0,
            errored: 0,
            total_vectors: Some(42),
            skipped_vectors: BTreeSet::new(),
            claims: BTreeSet::from(["MVM-SEC-08".into(), "MVM-SEC-09".into()]),
            witness_kinds: BTreeMap::new(),
            extensions: BTreeMap::from([("mvm.build".into(), serde_json::json!("abc123"))]),
        }
    }

    fn signed_sample() -> SignedConformanceBadge {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        SignedConformanceBadge::sign(sample_badge(), &signing_key, "2026-08-06T00:00:00+00:00")
            .unwrap()
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signed = signed_sample();
        signed.verify().expect("verify own badge");
    }

    #[test]
    fn failing_badge_rejected() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let mut badge = sample_badge();
        badge.failed = 1;
        badge.total_vectors = Some(43);
        let signed =
            SignedConformanceBadge::sign(badge, &signing_key, "2026-08-06T00:00:00+00:00").unwrap();
        assert!(signed.verify().is_err());
    }

    #[test]
    fn suite_digest_mismatch_rejected() {
        let signed = signed_sample();
        let mut admission = BadgeAdmission::default();
        admission.expected_suite_digest = Some("sha256:deadbeef".into());
        assert!(signed.verify_with_admission(&admission).is_err());
    }

    #[test]
    fn build_mismatch_rejected() {
        let signed = signed_sample();
        let mut admission = BadgeAdmission::default();
        admission.expected_build = Some("wrong".into());
        assert!(signed.verify_with_admission(&admission).is_err());
    }

    #[test]
    fn forbidden_skip_rejected() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let mut badge = sample_badge();
        badge.skipped = 1;
        badge.total_vectors = Some(43);
        badge.skipped_vectors.insert("hard-vector".into());
        let signed =
            SignedConformanceBadge::sign(badge, &signing_key, "2026-08-06T00:00:00+00:00").unwrap();
        let mut admission = BadgeAdmission::default();
        admission.forbid_skip.insert("hard-vector".into());
        assert!(signed.verify_with_admission(&admission).is_err());
    }

    #[test]
    fn corpus_digest_is_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("corpus");
        std::fs::create_dir(&dir).unwrap();
        let mut a = std::fs::File::create(dir.join("a.json")).unwrap();
        a.write_all(b"{\"x\":1}").unwrap();
        let mut b = std::fs::File::create(dir.join("b.json")).unwrap();
        b.write_all(b"{\"y\":2}").unwrap();

        let d1 = ConformanceBadge::compute_suite_digest(&dir).unwrap();
        let d2 = ConformanceBadge::compute_suite_digest(&dir).unwrap();
        assert_eq!(d1, d2);
        assert!(d1.starts_with("sha256:"));
    }

    #[test]
    fn corpus_digest_changes_on_content_change() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("corpus");
        std::fs::create_dir(&dir).unwrap();
        let mut a = std::fs::File::create(dir.join("a.json")).unwrap();
        a.write_all(b"{\"x\":1}").unwrap();

        let d1 = ConformanceBadge::compute_suite_digest(&dir).unwrap();
        let mut a = std::fs::File::create(dir.join("a.json")).unwrap();
        a.write_all(b"{\"x\":2}").unwrap();
        let d2 = ConformanceBadge::compute_suite_digest(&dir).unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn non_ascii_extension_rejected() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let mut badge = sample_badge();
        badge
            .extensions
            .insert("mvm.label".into(), serde_json::json!("Müller"));
        assert!(
            SignedConformanceBadge::sign(badge, &signing_key, "2026-08-06T00:00:00+00:00").is_err()
        );
    }
}
