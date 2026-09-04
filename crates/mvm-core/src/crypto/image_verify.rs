//! Signed-image verification primitive.
//!
//! Extends the bare `verify_artifact` hash check below by elevating the trust
//! anchor from "TLS-fetched checksum file" to "cosign-keyless-signed
//! manifest." The `SignedManifest` schema records every artifact's SHA-256
//! plus the input closure (Nix store hash, source git SHA, flake lockfile
//! content hashes) so the input bytes are recoverable from the signed
//! manifest alone.
//!
//! This module is consumed by mvmctl (e.g. `mvmctl up`) and by mvmd on pool image
//! verification. The typed `VerifyError` contract lets mvmd's reconciliation
//! loop pattern-match outcomes instead of crash-looping on `anyhow::Error`.

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
/// (`release.yml::Sign release tarballs and SBOM`). Image manifests
/// reuse the same format.
///
/// `expected_identity` is the *exact* SAN that the signing certificate
/// must carry — e.g.
/// `https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.14.0`.
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
    verify_cosign_bundle(
        manifest_bytes,
        cosign_bundle,
        expected_identity,
        expected_issuer,
    )?;
    parse_manifest(manifest_bytes)
}

/// Verify a cosign bundle over `artifact` against the exact SAN identity and
/// OIDC issuer, returning `Ok(())` only when the signature, certificate chain,
/// and transparency-log inclusion proof all check out.
///
/// Verification is offline: the Sigstore trust root (Fulcio CA + Rekor and
/// CT-log public keys) is embedded in `sigstore-trust-root`, and the bundle
/// carries its own inline inclusion proof and signed entry timestamp, so no
/// network or async runtime is involved. The trust root refreshes by bumping
/// the crate. Identity/issuer mismatches fail closed inside `verify`.
#[cfg(feature = "manifest-verify")]
fn verify_cosign_bundle(
    artifact: &[u8],
    cosign_bundle: &[u8],
    expected_identity: &str,
    expected_issuer: &str,
) -> VerifyResult<()> {
    use sigstore_trust_root::{SIGSTORE_PRODUCTION_TRUSTED_ROOT, TrustedRoot};
    use sigstore_types::Bundle;
    use sigstore_verify::{VerificationPolicy, verify};

    let bundle_json =
        std::str::from_utf8(cosign_bundle).map_err(|e| VerifyError::SignatureInvalid {
            reason: format!("cosign bundle is not valid UTF-8: {e}"),
        })?;
    let bundle = Bundle::from_json(bundle_json).map_err(|e| VerifyError::SignatureInvalid {
        reason: format!("cosign bundle parse failed: {e}"),
    })?;

    let trusted_root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT).map_err(|e| {
        VerifyError::SignatureInvalid {
            reason: format!("sigstore trust root init failed: {e}"),
        }
    })?;

    let policy = VerificationPolicy::default()
        .require_identity(expected_identity)
        .require_issuer(expected_issuer);

    verify(artifact, &bundle, &policy, &trusted_root).map_err(|e| {
        VerifyError::SignatureInvalid {
            reason: format!("signature verification failed: {e}"),
        }
    })?;
    Ok(())
}

/// Verify a cosign-signed JSON payload (any shape), returning the
/// validated bytes on success. Same trust contract as `verify_manifest`
/// — Sigstore bundle signature checked against the expected identity
/// and issuer — but generic over the payload type so callers can
/// reuse the verifier for revocation lists, advisory feeds, or any
/// other signed JSON the project publishes.
///
/// This exists so `mvm-cli`'s revocation-list fetcher doesn't have to
/// depend on the `sigstore` crate directly: the verification primitive
/// stays inside this crate.
#[cfg(feature = "manifest-verify")]
pub fn verify_signed_payload(
    payload_bytes: &[u8],
    cosign_bundle: &[u8],
    expected_identity: &str,
    expected_issuer: &str,
) -> VerifyResult<()> {
    verify_cosign_bundle(
        payload_bytes,
        cosign_bundle,
        expected_identity,
        expected_issuer,
    )
}

#[cfg(not(feature = "manifest-verify"))]
pub fn verify_signed_payload(
    _payload_bytes: &[u8],
    _cosign_bundle: &[u8],
    _expected_identity: &str,
    _expected_issuer: &str,
) -> VerifyResult<()> {
    Err(VerifyError::SignatureInvalid {
        reason: "manifest-verify feature is disabled in this build; rebuild \
                 mvmctl with `--features user`, or set MVM_SKIP_COSIGN_VERIFY=1 \
                 in an emergency rotation."
            .to_string(),
    })
}

/// No-feature fallback: refuse to accept any manifest as signed.
///
/// `manifest-verify` is off unless something turns it on — `mvm-core`'s
/// `default` is empty — so this arm is what an ordinary `cargo build` compiles.
/// The workspace `user` feature enables it, and released binaries carry `user`
/// (see `MVMCTL_RELEASE_FEATURES` in `release.yml`), which is why a downloaded
/// mvmctl verifies manifests and a locally built one does not. The fail-closed
/// contract is preserved either way, so a caller cannot accidentally accept an
/// unsigned manifest after a feature-flag flip.
///
/// The refusal used to advise rebuilding "with default features", which does
/// nothing at all: the default set does not include this. A reader following
/// that instruction stayed broken and had no reason to doubt the message.
#[cfg(not(feature = "manifest-verify"))]
pub fn verify_manifest(
    _manifest_bytes: &[u8],
    _cosign_bundle: &[u8],
    _expected_identity: &str,
    _expected_issuer: &str,
) -> VerifyResult<SignedManifest> {
    Err(VerifyError::SignatureInvalid {
        reason: "manifest-verify feature is disabled in this build; rebuild \
                 mvmctl with `--features user`, or set MVM_SKIP_COSIGN_VERIFY=1 \
                 in an emergency rotation."
            .to_string(),
    })
}

/// Confirm a manifest's `version` field matches the runtime's expected
/// version. Pins `manifest.version == env!("CARGO_PKG_VERSION")` exactly
/// — no "newer is fine," because every release has its own signed
/// manifest and the trust chain is tag-bound.
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
/// mismatch, delete the file and return `DigestMismatch`.
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
#[tracing::instrument(name = "sha256_file.uncached", skip_all, fields(path = %path.display()))]
pub fn sha256_file(path: &Path) -> io::Result<String> {
    use io::Read as _;
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut read_total: u64 = 0;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        read_total += n as u64;
        hasher.update(&buf[..n]);
    }
    // Reported here rather than at the call sites because this is the function
    // that actually reads the bytes; a caller that forgot to report would make
    // a launch look cheaper than it was, which is the direction that hides
    // regressions.
    crate::launch_trace::record_artifact_bytes_hashed(read_total);
    Ok(hex::encode(hasher.finalize()))
}

/// SHA-256 of a file, cached in a `<path>.sha256cache` sidecar keyed on the
/// file's size + mtime. Returns the cached digest when the sidecar matches the
/// file's current size/mtime; otherwise hashes the file, writes the sidecar
/// (best-effort), and returns the fresh digest.
///
/// Admission re-hashes the rootfs on every boot to bind the plan's image
/// digest (claim 8). For an immutable cached image that hundreds-of-MB hash is
/// identical every time, and re-reading it each boot dominates `up`. Keying on
/// size+mtime keeps the cache sound: any rewrite of the file (different
/// content) moves its mtime and forces a re-hash, so a stale digest can never
/// be admitted. A read-only cache dir simply means the next boot re-hashes.
pub fn sha256_file_cached(path: &Path) -> io::Result<String> {
    sha256_file_cached_with_source(path).map(|(hex, _)| hex)
}

/// Where a [`sha256_file_cached`] digest came from.
///
/// Returned so the sidecar being *used* is directly assertable. The cost this
/// cache exists to avoid is linear in artifact size and invisible in a digest
/// that is correct either way, so "it hit" has to be observable on its own —
/// otherwise a regression to hashing every call still passes every test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestSource {
    /// Served from the sidecar; the artifact was not read.
    Sidecar,
    /// Hashed from the artifact, reading this many bytes.
    Hashed(u64),
}

/// [`sha256_file_cached`], reporting whether the sidecar served the digest.
#[tracing::instrument(name = "sha256_file.cached", skip_all, fields(path = %path.display()))]
pub fn sha256_file_cached_with_source(path: &Path) -> io::Result<(String, DigestSource)> {
    let meta = fs::metadata(path)?;
    let size = meta.len();
    let mtime_nanos = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos());

    let sidecar = sha256_cache_path(path);
    if let Some(mtime) = mtime_nanos
        && let Ok(contents) = fs::read_to_string(&sidecar)
        && let Some(hex) = parse_sha256_sidecar(&contents, size, mtime)
    {
        return Ok((hex, DigestSource::Sidecar));
    }

    let hex = sha256_file(path)?;
    if let Some(mtime) = mtime_nanos {
        let _ = write_sha256_sidecar(&sidecar, &hex, size, mtime);
    }
    Ok((hex, DigestSource::Hashed(size)))
}

/// Where [`sha256_file_cached`] keeps `path`'s digest.
///
/// Public because whoever *deletes* an artifact has to delete this beside it.
/// The entry is keyed on the file's size+mtime, so an orphaned sidecar can be
/// served to a replacement that lands on the same pair.
#[must_use]
pub fn sha256_cache_path(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".sha256cache");
    std::path::PathBuf::from(s)
}

/// Parse a `"<hex> <size> <mtime_nanos>"` sidecar, returning the digest only
/// when its size+mtime still match the file being hashed.
fn parse_sha256_sidecar(contents: &str, size: u64, mtime_nanos: u128) -> Option<String> {
    let mut it = contents.split_whitespace();
    let hex = it.next()?;
    let cached_size: u64 = it.next()?.parse().ok()?;
    let cached_mtime: u128 = it.next()?.parse().ok()?;
    (cached_size == size && cached_mtime == mtime_nanos && hex.len() == 64).then(|| hex.to_string())
}

/// Write the sidecar atomically (temp + rename) so a concurrent boot never
/// reads a torn line. Best-effort; the caller ignores failure.
fn write_sha256_sidecar(sidecar: &Path, hex: &str, size: u64, mtime_nanos: u128) -> io::Result<()> {
    let mut tmp_os = sidecar.as_os_str().to_os_string();
    tmp_os.push(format!(".{}.tmp", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp_os);
    fs::write(&tmp, format!("{hex} {size} {mtime_nanos}\n"))?;
    fs::rename(&tmp, sidecar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn sha256_file_cached_matches_uncached_and_invalidates_on_change() {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(b"hello").expect("write");
        f.flush().expect("flush");
        let p = f.path().to_path_buf();
        let sidecar = sha256_cache_path(&p);

        let direct = sha256_file(&p).expect("direct hash");
        // First cached call computes + writes the sidecar.
        assert_eq!(sha256_file_cached(&p).expect("cached1"), direct);
        assert!(sidecar.exists(), "sidecar written");
        // Second call serves from the sidecar (same digest).
        assert_eq!(sha256_file_cached(&p).expect("cached2"), direct);

        // Mutating the file (size + mtime change) invalidates the cache.
        f.write_all(b" world").expect("append");
        f.flush().expect("flush");
        let direct2 = sha256_file(&p).expect("direct hash 2");
        assert_ne!(direct2, direct, "content changed");
        assert_eq!(
            sha256_file_cached(&p).expect("cached3"),
            direct2,
            "stale digest must never be served after a content change"
        );

        let _ = fs::remove_file(&sidecar);
    }

    /// A cache hit must not read the artifact. The digest is correct either
    /// way, so without asserting the source directly a regression to hashing
    /// on every call would pass every other test in this module while costing
    /// a full re-read of the artifact on every launch.
    #[test]
    fn a_sidecar_hit_serves_the_digest_without_reading_the_artifact() {
        let mut f = NamedTempFile::new().expect("tempfile");
        let body = b"the quick brown fox";
        f.write_all(body).expect("write");
        f.flush().expect("flush");
        let p = f.path().to_path_buf();
        let sidecar = sha256_cache_path(&p);
        let _ = fs::remove_file(&sidecar);

        let (miss, miss_source) = sha256_file_cached_with_source(&p).expect("cached miss");
        assert_eq!(
            miss_source,
            DigestSource::Hashed(body.len() as u64),
            "a sidecar miss reads the whole artifact"
        );

        let (hit, hit_source) = sha256_file_cached_with_source(&p).expect("cached hit");
        assert_eq!(hit, miss, "a hit serves the digest the miss computed");
        assert_eq!(
            hit_source,
            DigestSource::Sidecar,
            "a sidecar hit must not read the artifact"
        );

        // A rewrite moves size+mtime, so the next call must read again rather
        // than serve the digest of content that is gone.
        f.write_all(b" jumps").expect("append");
        f.flush().expect("flush");
        let (fresh, fresh_source) = sha256_file_cached_with_source(&p).expect("after rewrite");
        assert_ne!(fresh, miss, "content changed, so the digest must change");
        assert!(
            matches!(fresh_source, DigestSource::Hashed(_)),
            "a rewritten artifact must be re-read, not served from a stale sidecar"
        );

        let _ = fs::remove_file(&sidecar);
    }

    #[test]
    fn parse_sha256_sidecar_rejects_size_or_mtime_drift() {
        let hex = "a".repeat(64);
        let line = format!("{hex} 100 200");
        assert_eq!(parse_sha256_sidecar(&line, 100, 200), Some(hex.clone()));
        assert_eq!(parse_sha256_sidecar(&line, 101, 200), None, "size drift");
        assert_eq!(parse_sha256_sidecar(&line, 100, 201), None, "mtime drift");
        assert_eq!(parse_sha256_sidecar("garbage", 100, 200), None);
        assert_eq!(
            parse_sha256_sidecar("short 100 200", 100, 200),
            None,
            "non-64-char digest rejected"
        );
    }

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
        hex::encode(h.finalize())
    }

    /// Contract test pinning the on-wire shape produced by
    /// `scripts/generate-image-manifest.sh`. If either side drifts —
    /// the script reorders keys, drops a field, or this struct gains
    /// a required field — this test fires. Keep both producer and
    /// consumer in lock-step.
    #[test]
    fn parses_release_pipeline_manifest_shape() {
        // Verbatim sample of what scripts/generate-image-manifest.sh
        // emits for ARCH=aarch64 VARIANT=dev ROOTFS_EXT=ext4 with
        // fake artifact bytes. Re-generate with:
        //   ARCH=aarch64 VARIANT=dev ROOTFS_EXT=ext4 \
        //     STORE_PATH=/nix/store/abc123def456-mvm-mvm-dev-dev \
        //     STAGING_DIR=$d VERSION=0.13.0 \
        //     SOURCE_GIT_SHA=deadbeef0123456789 \
        //     bash scripts/generate-image-manifest.sh
        let json = r#"{
          "schema_version": 1,
          "version": "0.14.0",
          "arch": "aarch64",
          "variant": "dev",
          "rootfs_format": "ext4",
          "artifacts": [
            {"name": "dev-vmlinux-aarch64",
             "sha256": "b29be84bdecbb915f70659e08ba51472d05746b011b8acf965f49e94ff22d5b5"},
            {"name": "dev-rootfs-aarch64.ext4",
             "sha256": "a6a24f174bd25221b00bb2bb4888eb04e5ef3d20033c38188e44b902f23564bc"}
          ],
          "nix_store_hash": "abc123def456",
          "source_git_sha": "deadbeef0123456789",
          "flake_locks": {
            "nix/flake.lock": "sha256:d235bed6112b0fff283680a0fd3a718437db27ce3782aa554f2912f042e4026a",
            "nix/images/builder/flake.lock": "sha256:4c72ffe504f50c461b314ff86bf0394c15ffa04e457d07624c9280f04e152600"
          },
          "addressed_advisories": [],
          "built_at": "2026-05-01T00:26:37Z",
          "not_after":  "2026-07-30T00:26:37Z"
        }"#;
        let m = parse_manifest(json.as_bytes()).expect("release-pipeline JSON must parse");
        assert_eq!(m.schema_version, SCHEMA_VERSION);
        assert_eq!(m.version, "0.14.0");
        assert_eq!(m.arch, "aarch64");
        assert_eq!(m.variant, "dev");
        assert_eq!(m.rootfs_format, "ext4");
        assert_eq!(m.artifacts.len(), 2);
        assert!(m.artifact("dev-vmlinux-aarch64").is_some());
        assert_eq!(
            m.artifact("dev-rootfs-aarch64.ext4").unwrap().sha256,
            "a6a24f174bd25221b00bb2bb4888eb04e5ef3d20033c38188e44b902f23564bc"
        );
        assert_eq!(m.nix_store_hash, "abc123def456");
        assert_eq!(m.flake_locks.len(), 2);
        assert!(m.flake_locks.contains_key("nix/flake.lock"));
        assert!(m.addressed_advisories.is_empty());
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
