//! Signed-image verification primitive.
//!
//! Plan 36 / ADR 005. Extends W5.1 (`apple_container.rs::verify_artifact_hash`)
//! by elevating the trust anchor from "TLS-fetched checksum file" to
//! "cosign-keyless-signed manifest." The `SignedManifest` schema records
//! every artifact's SHA-256 plus the input closure (Nix store hash, source
//! git SHA, flake lockfile content hashes) so the input bytes are
//! recoverable from the signed manifest alone.
//!
//! This module is consumed by mvmctl on `dev up` (mvm plan 36) and by mvmd
//! on pool image verification (mvmd plan 23). The typed `VerifyError`
//! contract lets mvmd's reconciliation loop pattern-match outcomes
//! instead of crash-looping on `anyhow::Error`.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current manifest schema version. Bump whenever fields change in a way
/// older verifiers can't ignore. Older verifiers must reject unknown
/// schema versions (fail-closed) rather than skip unknown fields.
pub const SCHEMA_VERSION: u32 = 1;

/// SHA-256 digest of a single named artifact in a signed manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDigest {
    /// Filename as published in the GitHub Release (e.g.
    /// `dev-rootfs-aarch64.ext4`). Used to look up the digest entry by
    /// the filename the consumer downloaded; the manifest is not
    /// position-dependent.
    pub name: String,
    /// Lowercase hex SHA-256 of the artifact bytes.
    pub sha256: String,
}

/// Cosign-keyless-signed manifest of a release's image bundle.
///
/// Fields beyond `artifacts` exist so the verified manifest is itself a
/// useful audit record: a verifier can answer "what input closure
/// produced these bytes?" without re-deriving from source. mvmd consumes
/// `addressed_advisories` to decide whether a pool image addresses a
/// CVE under reconciliation; mvmctl ignores the field today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifest {
    pub schema_version: u32,
    pub version: String,
    pub arch: String,
    pub variant: String,
    pub rootfs_format: String,
    pub artifacts: Vec<ArtifactDigest>,
    pub nix_store_hash: String,
    pub source_git_sha: String,
    pub flake_locks: BTreeMap<String, String>,
    #[serde(default)]
    pub addressed_advisories: Vec<String>,
    pub built_at: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl SignedManifest {
    /// Look up a single artifact digest by its published filename.
    /// Returns `None` if the manifest doesn't list that artifact.
    pub fn artifact(&self, name: &str) -> Option<&ArtifactDigest> {
        self.artifacts.iter().find(|a| a.name == name)
    }
}

/// Cosign-signed revocation list pulled from the `revocations` release
/// tag. Append-only across releases; checked at most once per 24h with a
/// 7-day fresh window for offline-tolerant operation. The `revoked_at`
/// timestamp is the manifest field; `reason` is surfaced verbatim in the
/// hard-fail error so operators understand the recall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationList {
    pub schema_version: u32,
    pub revocations: Vec<RevocationEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub version: String,
    pub variant: String,
    pub arch: String,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
}

impl RevocationList {
    /// Return the matching entry, if any, for a given manifest.
    pub fn entry_for(&self, m: &SignedManifest) -> Option<&RevocationEntry> {
        self.revocations
            .iter()
            .find(|r| r.version == m.version && r.variant == m.variant && r.arch == m.arch)
    }
}

/// Errors returned by every verification entry point.
///
/// Typed (not `anyhow`) because mvmd's reconciliation loop must pattern-
/// match outcomes — Revoked vs Expired vs DigestMismatch demand different
/// reactions (skip + alert vs warn vs treat as supply-chain incident).
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("manifest signature is invalid: {reason}")]
    SignatureInvalid { reason: String },

    #[error("artifact {name} digest mismatch: expected sha256={expected}, got sha256={actual}")]
    DigestMismatch {
        name: String,
        expected: String,
        actual: String,
    },

    #[error("manifest is for {manifest_version} but runtime is {runtime_version}")]
    VersionSkew {
        manifest_version: String,
        runtime_version: String,
    },

    #[error("manifest schema version {found} is newer than this build supports ({supported})")]
    UnsupportedSchema { found: u32, supported: u32 },

    #[error("manifest version {version} was revoked at {since}: {reason}")]
    Revoked {
        version: String,
        since: DateTime<Utc>,
        reason: String,
    },

    #[error("manifest expired at {not_after} (now {now})")]
    Expired {
        not_after: DateTime<Utc>,
        now: DateTime<Utc>,
    },

    #[error("manifest does not list expected artifact {name}")]
    ArtifactNotInManifest { name: String },

    #[error("manifest parse failed: {0}")]
    Parse(String),

    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Result alias used throughout this module.
pub type VerifyResult<T> = Result<T, VerifyError>;

/// Parse a manifest from raw JSON bytes and reject unsupported schema
/// versions. Always run this *after* signature verification — JSON
/// parsing of attacker-controlled bytes should not be trusted on its
/// own.
pub fn parse_manifest(bytes: &[u8]) -> VerifyResult<SignedManifest> {
    let manifest: SignedManifest =
        serde_json::from_slice(bytes).map_err(|e| VerifyError::Parse(e.to_string()))?;
    if manifest.schema_version > SCHEMA_VERSION {
        return Err(VerifyError::UnsupportedSchema {
            found: manifest.schema_version,
            supported: SCHEMA_VERSION,
        });
    }
    Ok(manifest)
}

/// Verify the signature on a manifest and return the parsed result on
/// success.
///
/// `cosign_bundle` is the modern Sigstore format produced by
/// `cosign sign-blob --bundle`; the existing release workflow already
/// uses this format for `mvmctl` tarballs and the SBOM
/// (`release.yml::Sign release tarballs and SBOM`). Plan 36 reuses the
/// same format for image manifests.
///
/// `expected_identity` is the *exact* SAN that the signing certificate
/// must carry — e.g.
/// `https://github.com/auser/mvm/.github/workflows/release.yml@refs/tags/v0.14.0`.
/// Caller builds it from the manifest's expected version so each tagged
/// release verifies against its own bound identity. Sigstore's
/// `Identity` policy is exact-match only; there is no glob/regex
/// option, which is by design — wildcarding the identity would be a
/// trust regression.
///
/// `expected_issuer` is the OIDC issuer; for GitHub Actions keyless
/// signing it's `https://token.actions.githubusercontent.com`.
///
/// On success returns the manifest parsed from the verified bytes —
/// callers should never trust the manifest content before this returns
/// `Ok`. On failure returns `SignatureInvalid` with a message suitable
/// for surfacing to operators.
///
/// Compiled out when the `manifest-verify` Cargo feature is disabled;
/// the no-feature variant returns `SignatureInvalid` unconditionally,
/// preserving the fail-closed contract.
#[cfg(feature = "manifest-verify")]
pub fn verify_manifest(
    manifest_bytes: &[u8],
    cosign_bundle: &[u8],
    expected_identity: &str,
    expected_issuer: &str,
) -> VerifyResult<SignedManifest> {
    use sigstore::bundle::Bundle;
    use sigstore::bundle::verify::{blocking::Verifier, policy::Identity};

    let bundle: Bundle =
        serde_json::from_slice(cosign_bundle).map_err(|e| VerifyError::SignatureInvalid {
            reason: format!("cosign bundle parse failed: {e}"),
        })?;

    // `Verifier::production()` fetches Sigstore's public-good TUF root
    // on first construction. The fetch is blocking and one-shot per
    // process; subsequent calls reuse the in-memory trust state. A
    // network-down host on first run will surface as SignatureInvalid
    // with a clear "trust root init failed" reason.
    let verifier = Verifier::production().map_err(|e| VerifyError::SignatureInvalid {
        reason: format!("sigstore trust root init failed: {e}"),
    })?;

    let policy = Identity::new(expected_identity, expected_issuer);

    // `offline = false` lets the verifier consult Rekor for the
    // transparency log entry. Plan 36's "offline-bundle" path
    // (`offline = true`) is reachable when the bundle already includes
    // the inclusion proof inline — wire that into mvmd's reconciliation
    // loop in plan 23 Phase 1, where re-querying Rekor on every pool
    // verify is too expensive.
    verifier
        .verify(manifest_bytes, bundle, &policy, false)
        .map_err(|e| VerifyError::SignatureInvalid {
            reason: format!("manifest signature verification failed: {e}"),
        })?;

    parse_manifest(manifest_bytes)
}

/// No-feature fallback: refuse to accept any manifest as signed.
///
/// Builds without `manifest-verify` (e.g. `cargo install
/// --no-default-features`) drop the heavy `sigstore` dependency tree
/// in exchange for losing manifest verification. The fail-closed
/// contract is preserved so a downstream caller can't accidentally
/// accept unsigned manifests after a feature-flag flip.
#[cfg(not(feature = "manifest-verify"))]
pub fn verify_manifest(
    _manifest_bytes: &[u8],
    _cosign_bundle: &[u8],
    _expected_identity: &str,
    _expected_issuer: &str,
) -> VerifyResult<SignedManifest> {
    Err(VerifyError::SignatureInvalid {
        reason: "manifest-verify feature is disabled in this build; rebuild \
                 mvmctl with default features or set MVM_SKIP_COSIGN_VERIFY=1 \
                 in an emergency rotation."
            .to_string(),
    })
}

/// Confirm a manifest's `version` field matches the runtime's expected
/// version. Plan 36 pins `manifest.version == env!("CARGO_PKG_VERSION")`
/// exactly — no "newer is fine," because every release has its own
/// signed manifest and the trust chain is tag-bound.
pub fn check_version_pin(manifest: &SignedManifest, runtime_version: &str) -> VerifyResult<()> {
    if manifest.version == runtime_version {
        Ok(())
    } else {
        Err(VerifyError::VersionSkew {
            manifest_version: manifest.version.clone(),
            runtime_version: runtime_version.to_string(),
        })
    }
}

/// Reject a manifest whose `not_after` has passed. mvmctl's caller
/// should treat the result as a warning (advise upgrade); mvmd's caller
/// should treat it as a hard fail.
pub fn check_not_after(manifest: &SignedManifest, now: DateTime<Utc>) -> VerifyResult<()> {
    if now <= manifest.not_after {
        Ok(())
    } else {
        Err(VerifyError::Expired {
            not_after: manifest.not_after,
            now,
        })
    }
}

/// Reject a manifest whose version appears in the revocation list.
pub fn check_revocation(
    manifest: &SignedManifest,
    revocations: &RevocationList,
) -> VerifyResult<()> {
    match revocations.entry_for(manifest) {
        Some(entry) => Err(VerifyError::Revoked {
            version: entry.version.clone(),
            since: entry.revoked_at,
            reason: entry.reason.clone(),
        }),
        None => Ok(()),
    }
}

/// Stream `path` through SHA-256 and compare to `expected.sha256`. On
/// mismatch, delete the file and return `DigestMismatch`. The
/// delete-on-mismatch behaviour matches W5.1
/// (`apple_container.rs::verify_artifact_hash`).
///
/// Callers that want to keep the file for forensics should hash it
/// directly with `sha256_file` and compare manually.
pub fn verify_artifact(path: &Path, expected: &ArtifactDigest) -> VerifyResult<()> {
    let actual = sha256_file(path)?;
    if actual == expected.sha256.to_ascii_lowercase() {
        return Ok(());
    }
    // Best-effort cleanup; ignore failure (the caller already gets a
    // DigestMismatch and the right thing for them to do is bail).
    let _ = fs::remove_file(path);
    Err(VerifyError::DigestMismatch {
        name: expected.name.clone(),
        expected: expected.sha256.to_ascii_lowercase(),
        actual,
    })
}

/// Stream a file through SHA-256 and return the lowercase hex digest.
/// Public for callers that want to verify an artifact without the
/// delete-on-mismatch behaviour of `verify_artifact`.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn sample_manifest() -> SignedManifest {
        SignedManifest {
            schema_version: 1,
            version: "0.14.0".to_string(),
            arch: "aarch64".to_string(),
            variant: "dev".to_string(),
            rootfs_format: "ext4".to_string(),
            artifacts: vec![
                ArtifactDigest {
                    name: "dev-vmlinux-aarch64".to_string(),
                    sha256: "a".repeat(64),
                },
                ArtifactDigest {
                    name: "dev-rootfs-aarch64.ext4".to_string(),
                    sha256: "b".repeat(64),
                },
            ],
            nix_store_hash: "abc123".to_string(),
            source_git_sha: "deadbeef".to_string(),
            flake_locks: BTreeMap::from([
                (
                    "nix/flake.nix".to_string(),
                    format!("sha256:{}", "c".repeat(64)),
                ),
                (
                    "nix/images/builder/flake.lock".to_string(),
                    format!("sha256:{}", "d".repeat(64)),
                ),
            ]),
            addressed_advisories: vec![],
            built_at: Utc.with_ymd_and_hms(2026, 4, 30, 18, 0, 0).unwrap(),
            not_after: Utc.with_ymd_and_hms(2026, 7, 29, 18, 0, 0).unwrap(),
        }
    }

    fn write_temp(bytes: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    fn hex_sha256(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        format!("{:x}", h.finalize())
    }

    #[test]
    fn manifest_roundtrips_via_json() {
        let m = sample_manifest();
        let bytes = serde_json::to_vec(&m).unwrap();
        let parsed = parse_manifest(&bytes).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn artifact_lookup_by_name() {
        let m = sample_manifest();
        assert!(m.artifact("dev-vmlinux-aarch64").is_some());
        assert!(m.artifact("does-not-exist").is_none());
    }

    #[test]
    fn unsupported_schema_version_fails_closed() {
        let mut m = sample_manifest();
        m.schema_version = SCHEMA_VERSION + 1;
        let bytes = serde_json::to_vec(&m).unwrap();
        match parse_manifest(&bytes) {
            Err(VerifyError::UnsupportedSchema { found, supported }) => {
                assert_eq!(found, SCHEMA_VERSION + 1);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedSchema, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_garbage() {
        match parse_manifest(b"not json") {
            Err(VerifyError::Parse(_)) => {}
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn version_pin_matches() {
        let m = sample_manifest();
        check_version_pin(&m, "0.14.0").unwrap();
    }

    #[test]
    fn version_pin_skew_fails() {
        let m = sample_manifest();
        match check_version_pin(&m, "0.14.1") {
            Err(VerifyError::VersionSkew {
                manifest_version,
                runtime_version,
            }) => {
                assert_eq!(manifest_version, "0.14.0");
                assert_eq!(runtime_version, "0.14.1");
            }
            other => panic!("expected VersionSkew, got {other:?}"),
        }
    }

    #[test]
    fn not_after_fresh_passes() {
        let m = sample_manifest();
        let now = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        check_not_after(&m, now).unwrap();
    }

    #[test]
    fn not_after_expired_fails() {
        let m = sample_manifest();
        let now = Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
        match check_not_after(&m, now) {
            Err(VerifyError::Expired {
                not_after,
                now: returned_now,
            }) => {
                assert_eq!(not_after, m.not_after);
                assert_eq!(returned_now, now);
            }
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn revocation_miss_passes() {
        let m = sample_manifest();
        let revs = RevocationList {
            schema_version: 1,
            revocations: vec![RevocationEntry {
                version: "0.13.0".to_string(),
                variant: "dev".to_string(),
                arch: "aarch64".to_string(),
                reason: "irrelevant".to_string(),
                revoked_at: Utc::now(),
            }],
        };
        check_revocation(&m, &revs).unwrap();
    }

    #[test]
    fn revocation_hit_fails() {
        let m = sample_manifest();
        let when = Utc.with_ymd_and_hms(2026, 5, 15, 0, 0, 0).unwrap();
        let revs = RevocationList {
            schema_version: 1,
            revocations: vec![RevocationEntry {
                version: "0.14.0".to_string(),
                variant: "dev".to_string(),
                arch: "aarch64".to_string(),
                reason: "CVE-2026-0001 in nix daemon".to_string(),
                revoked_at: when,
            }],
        };
        match check_revocation(&m, &revs) {
            Err(VerifyError::Revoked {
                version,
                since,
                reason,
            }) => {
                assert_eq!(version, "0.14.0");
                assert_eq!(since, when);
                assert!(reason.contains("CVE-2026-0001"));
            }
            other => panic!("expected Revoked, got {other:?}"),
        }
    }

    #[test]
    fn revocation_does_not_match_different_arch_or_variant() {
        let m = sample_manifest();
        let when = Utc.with_ymd_and_hms(2026, 5, 15, 0, 0, 0).unwrap();
        let revs = RevocationList {
            schema_version: 1,
            revocations: vec![
                // Same version, different arch — must not match.
                RevocationEntry {
                    version: "0.14.0".to_string(),
                    variant: "dev".to_string(),
                    arch: "x86_64".to_string(),
                    reason: "wrong arch".to_string(),
                    revoked_at: when,
                },
                // Same version + arch, different variant — must not match.
                RevocationEntry {
                    version: "0.14.0".to_string(),
                    variant: "builder".to_string(),
                    arch: "aarch64".to_string(),
                    reason: "wrong variant".to_string(),
                    revoked_at: when,
                },
            ],
        };
        check_revocation(&m, &revs).unwrap();
    }

    #[test]
    fn verify_artifact_accepts_matching_digest() {
        let bytes = b"hello world\n";
        let f = write_temp(bytes);
        let expected = ArtifactDigest {
            name: "test".to_string(),
            sha256: hex_sha256(bytes),
        };
        verify_artifact(f.path(), &expected).unwrap();
        assert!(f.path().exists(), "matching artifact must not be deleted");
    }

    #[test]
    fn verify_artifact_rejects_and_deletes_on_mismatch() {
        let f = write_temp(b"actual contents");
        let path = f.path().to_path_buf();
        let expected = ArtifactDigest {
            name: "test".to_string(),
            sha256: hex_sha256(b"different contents"),
        };
        match verify_artifact(&path, &expected) {
            Err(VerifyError::DigestMismatch {
                name,
                expected: e,
                actual,
            }) => {
                assert_eq!(name, "test");
                assert_eq!(e, hex_sha256(b"different contents"));
                assert_eq!(actual, hex_sha256(b"actual contents"));
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
        // NamedTempFile leaves the underlying handle, but the file at
        // the recorded path should be gone after delete-on-mismatch.
        assert!(!path.exists(), "tampered artifact must be deleted");
    }

    #[test]
    fn verify_artifact_propagates_io_error_for_missing_file() {
        let expected = ArtifactDigest {
            name: "ghost".to_string(),
            sha256: "0".repeat(64),
        };
        match verify_artifact(Path::new("/definitely/does/not/exist"), &expected) {
            Err(VerifyError::Io(_)) => {}
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn verify_artifact_accepts_uppercase_expected_digest() {
        // sha256sum default output is lowercase, but a manifest emitter
        // could provide uppercase. Accept either; canonicalise on
        // comparison.
        let bytes = b"case test\n";
        let f = write_temp(bytes);
        let expected = ArtifactDigest {
            name: "test".to_string(),
            sha256: hex_sha256(bytes).to_ascii_uppercase(),
        };
        verify_artifact(f.path(), &expected).unwrap();
    }

    #[test]
    fn verify_manifest_rejects_garbage_bundle() {
        // Hand verify_manifest something that can't possibly be a
        // sigstore bundle. The error must come back as SignatureInvalid
        // (not Parse — Parse is reserved for the manifest-JSON parse
        // step that runs *after* signature verification). The exact
        // reason wording differs between feature-on (sigstore parse
        // error) and feature-off (feature-disabled), so we only assert
        // the variant.
        match verify_manifest(b"{}", b"not a bundle", "identity", "issuer") {
            Err(VerifyError::SignatureInvalid { .. }) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[cfg(not(feature = "manifest-verify"))]
    #[test]
    fn verify_manifest_no_feature_fails_closed() {
        // Without the feature, every call must return SignatureInvalid
        // with a wording that points the operator at how to recover.
        match verify_manifest(b"{}", b"bundle", "id", "issuer") {
            Err(VerifyError::SignatureInvalid { reason }) => {
                assert!(reason.contains("manifest-verify feature is disabled"));
            }
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }
}
