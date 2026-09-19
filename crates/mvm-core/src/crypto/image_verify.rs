//! Keyless signature verification and streaming SHA-256 for published artifacts.
//!
//! Two primitives every artifact acquisition path shares: checking a detached
//! cosign bundle over a payload against an exact signing identity, and hashing
//! a file without holding it in memory (optionally through a size+mtime keyed
//! sidecar). What a verified payload *means* — an image set, a pack manifest, a
//! revocation list — belongs to the module that parses it; this one only
//! answers whether the bytes were signed and what they hash to.

use std::fs;
use std::io;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Why a signature was not accepted.
///
/// A single variant, kept as an enum so the no-feature build and the verifying
/// build return the same type and a caller's `match` does not depend on which
/// one it was compiled into.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("signature is invalid: {reason}")]
    SignatureInvalid { reason: String },
}

/// Result alias used throughout this module.
pub type VerifyResult<T> = Result<T, VerifyError>;

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

/// Verify a cosign-signed payload of any shape against the exact SAN
/// `expected_identity` and OIDC `expected_issuer`.
///
/// `cosign_bundle` is the Sigstore bundle `cosign sign-blob
/// --new-bundle-format` emits. The identity match is exact — Sigstore's
/// `Identity` policy has no glob or regex form, and wildcarding it would be a
/// trust regression — so each release verifies against its own tag-bound
/// identity. For GitHub Actions keyless signing the issuer is
/// `https://token.actions.githubusercontent.com`.
///
/// Callers must not trust the payload's contents before this returns `Ok`.
/// The verification primitive stays in this crate so no caller depends on the
/// sigstore crates directly.
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

/// Verify `payload_bytes` against `cosign_bundle` under whichever of
/// `identities` signed it, succeeding as soon as one verifies.
///
/// A keyless trust root is a *set* of accepted identities — a release train
/// spans more than one workflow ref over its life — so every keyless caller
/// needs this loop. One copy, so the "try each, report the last failure,
/// refuse an empty set" shape cannot drift between them.
pub fn verify_signed_payload_under_any_identity(
    payload_bytes: &[u8],
    cosign_bundle: &[u8],
    identities: &[&str],
    expected_issuer: &str,
) -> VerifyResult<()> {
    let mut failure: Option<VerifyError> = None;
    for identity in identities {
        match verify_signed_payload(payload_bytes, cosign_bundle, identity, expected_issuer) {
            Ok(()) => return Ok(()),
            Err(error) => failure = Some(error),
        }
    }
    Err(failure.unwrap_or_else(|| VerifyError::SignatureInvalid {
        reason: "no accepted identities configured for keyless verification".to_string(),
    }))
}

/// Stream a file through SHA-256 and return the lowercase hex digest.
#[tracing::instrument(name = "sha256_file.uncached", skip_all, fields(path = %path.display()))]
pub fn sha256_file(path: &Path) -> io::Result<String> {
    sha256_reader(fs::File::open(path)?)
}

/// Stream any reader through SHA-256 and return the lowercase hex digest.
///
/// For callers that must hash an already-open descriptor rather than reopen a
/// path: a check over a name can be satisfied by one file and the use handed
/// another.
pub fn sha256_reader(mut reader: impl io::Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut read_total: u64 = 0;
    loop {
        let n = reader.read(&mut buf)?;
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
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Hashing an open reader gives the same digest as hashing the file by
    /// path, across a buffer boundary, and the empty input hashes to the
    /// well-known empty digest.
    #[test]
    fn sha256_reader_agrees_with_sha256_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let bytes: Vec<u8> = (0..200_000_u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &bytes).unwrap();

        let by_path = sha256_file(&path).unwrap();
        let by_reader = sha256_reader(std::fs::File::open(&path).unwrap()).unwrap();
        assert_eq!(by_reader, by_path);
        assert_eq!(sha256_reader(bytes.as_slice()).unwrap(), by_path);
        assert_eq!(
            sha256_reader(std::io::empty()).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

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

    #[test]
    fn a_garbage_bundle_is_refused_as_an_invalid_signature() {
        // The reason differs between the verifying build (a sigstore parse
        // error) and the no-feature build (the feature is off), so only the
        // variant is asserted.
        let err = verify_signed_payload(b"{}", b"not a bundle", "identity", "issuer")
            .expect_err("bytes that are not a bundle must be refused");
        assert!(matches!(err, VerifyError::SignatureInvalid { .. }));
    }

    #[test]
    fn an_empty_identity_set_is_refused_rather_than_admitted() {
        let err = verify_signed_payload_under_any_identity(b"{}", b"bundle", &[], "issuer")
            .expect_err("no accepted identity must never mean any identity");
        assert!(matches!(err, VerifyError::SignatureInvalid { .. }));
    }

    #[cfg(not(feature = "manifest-verify"))]
    #[test]
    fn a_build_without_the_verifier_refuses_and_names_the_feature() {
        let err = verify_signed_payload(b"{}", b"bundle", "id", "issuer")
            .expect_err("a non-verifying build must refuse");
        assert!(
            err.to_string()
                .contains("manifest-verify feature is disabled")
        );
    }
}
