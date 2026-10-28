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

/// The certificate identity a verified keyless signature was minted under.
///
/// Returned only after the signature, certificate chain, and transparency-log
/// inclusion proof have all checked out, so holding one is evidence the
/// payload was signed by whoever the certificate names. What that identity is
/// *allowed* to sign is the caller's policy, not this module's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSigner {
    /// The certificate's subject alternative name — for a CI workflow, the
    /// workflow file bound to the ref it ran under.
    pub identity: String,
    /// The OIDC issuer recorded in the certificate.
    pub issuer: String,
}

/// Verify a cosign bundle over `artifact` under `expected_issuer`, and under
/// `expected_identity` when one is given, returning the certificate identity
/// the signature was minted under.
///
/// Verification is offline: the Sigstore trust root (Fulcio CA + Rekor and
/// CT-log public keys) is embedded in `sigstore-trust-root`, and the bundle
/// carries its own inline inclusion proof and signed entry timestamp, so no
/// network or async runtime is involved. The trust root refreshes by bumping
/// the crate. Identity/issuer mismatches fail closed inside `verify`.
#[cfg(feature = "manifest-verify")]
fn verify_cosign_bundle<'a>(
    artifact: impl Into<sigstore_types::Artifact<'a>>,
    cosign_bundle: &[u8],
    expected_identity: Option<&str>,
    expected_issuer: &str,
) -> VerifyResult<VerifiedSigner> {
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

    let mut policy = VerificationPolicy::default().require_issuer(expected_issuer);
    if let Some(identity) = expected_identity {
        policy = policy.require_identity(identity);
    }

    let result = verify(artifact, &bundle, &policy, &trusted_root).map_err(|e| {
        VerifyError::SignatureInvalid {
            reason: format!("signature verification failed: {e}"),
        }
    })?;
    // The issuer was required above, so a verified result always carries it;
    // a certificate with no SAN names nobody and cannot satisfy any policy.
    let identity = result
        .identity
        .ok_or_else(|| VerifyError::SignatureInvalid {
            reason: "signing certificate carries no identity (SAN)".to_string(),
        })?;
    Ok(VerifiedSigner {
        identity,
        issuer: result.issuer.unwrap_or_else(|| expected_issuer.to_string()),
    })
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
        Some(expected_identity),
        expected_issuer,
    )
    .map(|_| ())
}

/// Verify a signed large blob from its independently computed SHA-256 digest.
///
/// The caller must stream and hash the exact file bytes it intends to admit,
/// then retain those bytes against replacement until use. Sigstore checks the
/// bundle against the 32-byte digest without allocating the whole artifact.
#[cfg(feature = "manifest-verify")]
pub fn verify_signed_sha256(
    sha256_hex: &str,
    cosign_bundle: &[u8],
    expected_identity: &str,
    expected_issuer: &str,
) -> VerifyResult<()> {
    let digest = sigstore_types::Sha256Hash::from_hex(sha256_hex).map_err(|error| {
        VerifyError::SignatureInvalid {
            reason: format!("artifact SHA-256 is invalid: {error}"),
        }
    })?;
    verify_cosign_bundle(
        digest,
        cosign_bundle,
        Some(expected_identity),
        expected_issuer,
    )
    .map(|_| ())
}

#[cfg(not(feature = "manifest-verify"))]
pub fn verify_signed_sha256(
    _sha256_hex: &str,
    _cosign_bundle: &[u8],
    _expected_identity: &str,
    _expected_issuer: &str,
) -> VerifyResult<()> {
    Err(VerifyError::SignatureInvalid {
        reason: VERIFIER_DISABLED_REASON.to_string(),
    })
}

#[cfg(not(feature = "manifest-verify"))]
pub fn verify_signed_payload(
    _payload_bytes: &[u8],
    _cosign_bundle: &[u8],
    _expected_identity: &str,
    _expected_issuer: &str,
) -> VerifyResult<()> {
    Err(VerifyError::SignatureInvalid {
        reason: VERIFIER_DISABLED_REASON.to_string(),
    })
}

/// Why a build compiled without the verifier refuses every keyless signature.
#[cfg(not(feature = "manifest-verify"))]
const VERIFIER_DISABLED_REASON: &str = "manifest-verify feature is disabled in this build; rebuild \
     mvmctl with `--features user`, or set MVM_SKIP_COSIGN_VERIFY=1 in an emergency rotation.";

/// Verify a cosign-signed payload under `expected_issuer` alone and return
/// the certificate identity it was signed under.
///
/// For callers whose trust policy is a *pattern* over identities rather than
/// a closed set — a publisher trusted for any tag of one workflow, say — and
/// which therefore cannot enumerate exact identities for
/// [`verify_signed_payload_under_any_identity`]. The cryptographic checks are
/// identical; only the identity comparison moves to the caller, which must
/// match [`VerifiedSigner::identity`] before trusting the payload. The issuer
/// is still pinned here, so an identity is never compared across issuers.
#[cfg(feature = "manifest-verify")]
pub fn verify_signed_payload_signer(
    payload_bytes: &[u8],
    cosign_bundle: &[u8],
    expected_issuer: &str,
) -> VerifyResult<VerifiedSigner> {
    verify_cosign_bundle(payload_bytes, cosign_bundle, None, expected_issuer)
}

#[cfg(not(feature = "manifest-verify"))]
pub fn verify_signed_payload_signer(
    _payload_bytes: &[u8],
    _cosign_bundle: &[u8],
    _expected_issuer: &str,
) -> VerifyResult<VerifiedSigner> {
    Err(VerifyError::SignatureInvalid {
        reason: VERIFIER_DISABLED_REASON.to_string(),
    })
}

/// Whether this build carries the keyless verifier at all.
///
/// A build without it refuses every keyless signature, which is the right
/// answer at a gate but the wrong *explanation*: a caller reporting on a file
/// should be able to say "this build cannot check keyless signatures" rather
/// than "this signature is invalid".
#[must_use]
pub const fn keyless_verifier_available() -> bool {
    cfg!(feature = "manifest-verify")
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
    verify_signed_payload_and_signer_under_any_identity(
        payload_bytes,
        cosign_bundle,
        identities,
        expected_issuer,
    )
    .map(|_| ())
}

/// Verify against a closed identity set and return the identity that signed
/// the payload. The returned signer is the certificate subject that satisfied
/// the exact-identity policy, not a name copied from the payload.
pub fn verify_signed_payload_and_signer_under_any_identity(
    payload_bytes: &[u8],
    cosign_bundle: &[u8],
    identities: &[&str],
    expected_issuer: &str,
) -> VerifyResult<VerifiedSigner> {
    let mut failure: Option<VerifyError> = None;
    for identity in identities {
        match verify_signed_payload_with_signer(
            payload_bytes,
            cosign_bundle,
            identity,
            expected_issuer,
        ) {
            Ok(signer) => return Ok(signer),
            Err(error) => failure = Some(error),
        }
    }
    Err(failure.unwrap_or_else(|| VerifyError::SignatureInvalid {
        reason: "no accepted identities configured for keyless verification".to_string(),
    }))
}

#[cfg(feature = "manifest-verify")]
fn verify_signed_payload_with_signer(
    payload_bytes: &[u8],
    cosign_bundle: &[u8],
    expected_identity: &str,
    expected_issuer: &str,
) -> VerifyResult<VerifiedSigner> {
    verify_cosign_bundle(
        payload_bytes,
        cosign_bundle,
        Some(expected_identity),
        expected_issuer,
    )
}

#[cfg(not(feature = "manifest-verify"))]
fn verify_signed_payload_with_signer(
    _payload_bytes: &[u8],
    _cosign_bundle: &[u8],
    _expected_identity: &str,
    _expected_issuer: &str,
) -> VerifyResult<VerifiedSigner> {
    Err(VerifyError::SignatureInvalid {
        reason: VERIFIER_DISABLED_REASON.to_string(),
    })
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

/// SHA-256 of a file, cached in a `<path>.sha256cache` sidecar that this host
/// has sealed. Returns the cached digest when the sidecar's seal verifies for
/// the file as it is now; otherwise hashes the file, writes a freshly sealed
/// sidecar (best-effort), and returns the digest.
///
/// Admission re-hashes the rootfs on every boot to bind the plan's image
/// digest (claim 8). For an immutable cached image that hundreds-of-MB hash is
/// identical every time, and re-reading it each boot dominates the boot. The
/// sidecar is a file next to the artifact, so anyone who can write the artifact
/// can write a sidecar; it is therefore sealed with an HMAC under a per-install
/// key that covers the file's inode, size, mtime and ctime
/// (see [`super::digest_cache`]). Editing the file, replacing it, or copying a
/// sidecar line from another file changes an input and the seal stops
/// verifying. A host that cannot read or create the key, or a platform without
/// inodes, never uses the cache and hashes every time. A read-only cache dir
/// likewise just means the next boot re-hashes.
pub fn sha256_file_cached(path: &Path) -> io::Result<String> {
    sha256_file_cached_report_source(path).map(|(hex, _)| hex)
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
pub fn sha256_file_cached_report_source(path: &Path) -> io::Result<(String, DigestSource)> {
    sha256_file_cached_with_key(path, super::digest_cache::process_key())
}

fn sha256_file_cached_with_key(
    path: &Path,
    key: Option<&super::digest_cache::CacheKey>,
) -> io::Result<(String, DigestSource)> {
    use super::digest_cache::FileIdentity;

    let read_started = std::time::SystemTime::now();
    let meta = fs::metadata(path)?;
    let size = meta.len();
    let sealed = key.zip(FileIdentity::of(&meta));

    let sidecar = sha256_cache_path(path);
    if let Some((key, identity)) = &sealed
        && let Ok(contents) = fs::read_to_string(&sidecar)
        && let Some(hex) = parse_sha256_sidecar(&contents, key, identity)
    {
        return Ok((hex, DigestSource::Sidecar));
    }

    let hex = sha256_file(path)?;
    if let Some(sealed) = &sealed {
        seal_if_unchanged_and_settled(path, sealed, &hex, read_started);
    }
    Ok((hex, DigestSource::Hashed(size)))
}

/// Seal `hex` as `path`'s digest when it is safe to: the file must be the one
/// that was hashed (its identity is unchanged since before the read) and must
/// have settled before the read, so a write in the same timestamp tick cannot
/// leave a seal that still verifies. Best-effort; a write failure only means
/// the next call hashes. Returns whether a sidecar was written.
fn seal_if_unchanged_and_settled(
    path: &Path,
    (key, identity): &(
        &super::digest_cache::CacheKey,
        super::digest_cache::FileIdentity,
    ),
    hex: &str,
    read_started: std::time::SystemTime,
) -> bool {
    use super::digest_cache::FileIdentity;

    fs::metadata(path).ok().and_then(|m| FileIdentity::of(&m)) == Some(*identity)
        && identity.settled(read_started, super::verified_digest::RACY_WINDOW)
        && write_sha256_sidecar(&sha256_cache_path(path), hex, &key.seal(identity, hex)).is_ok()
}

/// Seal `accepted` as `path`'s digest, only if the file still hashes to exactly
/// that value. For a caller that already verified `accepted` against an
/// authenticated expectation and wants later processes to reuse it: nothing it
/// seals is a digest that verification did not accept. Returns whether a
/// sidecar was written; `false` is not an error (no key, a file that has not
/// settled, an unwritable directory, or bytes that no longer match).
pub fn seal_digest_if_matches(path: &Path, accepted: &str) -> io::Result<bool> {
    seal_digest_if_matches_with_key(path, accepted, super::digest_cache::process_key())
}

fn seal_digest_if_matches_with_key(
    path: &Path,
    accepted: &str,
    key: Option<&super::digest_cache::CacheKey>,
) -> io::Result<bool> {
    use super::digest_cache::FileIdentity;

    let read_started = std::time::SystemTime::now();
    let Some(sealed) = key.zip(FileIdentity::of(&fs::metadata(path)?)) else {
        return Ok(false);
    };
    if sha256_file(path)? != accepted {
        return Ok(false);
    }
    Ok(seal_if_unchanged_and_settled(
        path,
        &sealed,
        accepted,
        read_started,
    ))
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

/// Parse a `"<hex> <seal>"` sidecar, returning the digest only when its seal
/// verifies for `identity` under `key`. An old unsealed line has the wrong shape
/// and is rejected, so it is re-hashed and replaced.
fn parse_sha256_sidecar(
    contents: &str,
    key: &super::digest_cache::CacheKey,
    identity: &super::digest_cache::FileIdentity,
) -> Option<String> {
    let mut it = contents.split_whitespace();
    let hex = it.next()?;
    let seal = it.next()?;
    if it.next().is_some() || hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    key.verify(identity, hex, seal).then(|| hex.to_string())
}

/// Write the sidecar atomically (temp + rename) so a concurrent boot never
/// reads a torn line. Best-effort; the caller ignores failure.
fn write_sha256_sidecar(sidecar: &Path, hex: &str, seal: &str) -> io::Result<()> {
    let mut tmp_os = sidecar.as_os_str().to_os_string();
    tmp_os.push(format!(".{}.tmp", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp_os);
    fs::write(&tmp, format!("{hex} {seal}\n"))?;
    fs::rename(&tmp, sidecar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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

    fn test_key(seed: u8) -> super::super::digest_cache::CacheKey {
        super::super::digest_cache::CacheKey::from_bytes([seed; 32])
    }

    /// Wait until a file written now would count as settled.
    fn settle() {
        std::thread::sleep(
            super::super::verified_digest::RACY_WINDOW + std::time::Duration::from_millis(60),
        );
    }

    #[test]
    fn a_digest_is_not_sealed_for_a_file_that_has_not_settled() {
        let dir = tempfile::tempdir().unwrap();
        let path = artifact(&dir, "fresh", b"just written");
        let key = test_key(1);
        let (_, source) = sha256_file_cached_with_key(&path, Some(&key)).unwrap();
        assert!(matches!(source, DigestSource::Hashed(_)));
        assert!(!sha256_cache_path(&path).exists(), "nothing was sealed");
    }

    #[cfg(unix)]
    #[test]
    fn a_slow_read_does_not_age_a_fresh_identity_into_a_seal() {
        use super::super::digest_cache::FileIdentity;
        use std::os::unix::fs::MetadataExt as _;
        use std::time::{Duration, UNIX_EPOCH};

        let dir = tempfile::tempdir().unwrap();
        let path = artifact(&dir, "slow-read", b"verified bytes");
        let meta = fs::metadata(&path).unwrap();
        let identity = FileIdentity::of(&meta).unwrap();
        let newest = (meta.mtime(), meta.mtime_nsec()).max((meta.ctime(), meta.ctime_nsec()));
        let stamped =
            UNIX_EPOCH + Duration::new(newest.0.try_into().unwrap(), newest.1.try_into().unwrap());
        let read_started = stamped + Duration::from_millis(100);
        let seal_at = read_started + Duration::from_millis(300);
        assert!(!identity.settled(read_started, super::super::verified_digest::RACY_WINDOW));
        assert!(identity.settled(seal_at, super::super::verified_digest::RACY_WINDOW));
        let key = test_key(1);
        let digest = sha256_file(&path).unwrap();
        assert!(!seal_if_unchanged_and_settled(
            &path,
            &(&key, identity),
            &digest,
            read_started,
        ));
        assert!(!sha256_cache_path(&path).exists());
    }

    #[test]
    fn a_settled_file_is_sealed_and_then_served_from_the_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let path = artifact(&dir, "settled", b"old enough");
        settle();
        let key = test_key(1);
        let (hex, first) = sha256_file_cached_with_key(&path, Some(&key)).unwrap();
        assert!(matches!(first, DigestSource::Hashed(_)));
        let (again, second) = sha256_file_cached_with_key(&path, Some(&key)).unwrap();
        assert_eq!((again, second), (hex, DigestSource::Sidecar));
    }

    #[test]
    fn only_the_accepted_digest_is_sealed() {
        let dir = tempfile::tempdir().unwrap();
        let path = artifact(&dir, "accepted", b"verified bytes");
        settle();
        let key = test_key(1);
        let accepted = sha256_file(&path).unwrap();

        let wrong = "0".repeat(64);
        assert!(!seal_digest_if_matches_with_key(&path, &wrong, Some(&key)).unwrap());
        assert!(
            !sha256_cache_path(&path).exists(),
            "a mismatch seals nothing"
        );

        assert!(seal_digest_if_matches_with_key(&path, &accepted, Some(&key)).unwrap());
        let (hex, source) = sha256_file_cached_with_key(&path, Some(&key)).unwrap();
        assert_eq!((hex, source), (accepted, DigestSource::Sidecar));
    }

    #[test]
    fn nothing_is_sealed_without_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = artifact(&dir, "keyless", b"bytes");
        settle();
        let accepted = sha256_file(&path).unwrap();
        assert!(!seal_digest_if_matches_with_key(&path, &accepted, None).unwrap());
        assert!(!sha256_cache_path(&path).exists());
    }

    /// A file in a fresh directory, so no other test shares its inode.
    fn artifact(dir: &tempfile::TempDir, name: &str, body: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, body).expect("write artifact");
        path
    }

    /// File times on some filesystems advance in coarse ticks, so a change made
    /// straight after another can carry the same ctime.
    fn cross_a_timestamp_tick() {
        std::thread::sleep(std::time::Duration::from_millis(30));
    }

    #[test]
    fn sha256_file_cached_matches_uncached_and_invalidates_on_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = test_key(1);
        let p = artifact(&dir, "blob", b"hello");
        settle();
        let sidecar = sha256_cache_path(&p);

        let direct = sha256_file(&p).expect("direct hash");
        // First cached call computes + writes the sidecar.
        assert_eq!(
            sha256_file_cached_with_key(&p, Some(&key))
                .expect("cached1")
                .0,
            direct
        );
        assert!(sidecar.exists(), "sidecar written");
        // Second call serves from the sidecar (same digest).
        assert_eq!(
            sha256_file_cached_with_key(&p, Some(&key))
                .expect("cached2")
                .0,
            direct
        );

        // Mutating the file invalidates the cache.
        cross_a_timestamp_tick();
        let mut f = fs::OpenOptions::new().append(true).open(&p).expect("open");
        f.write_all(b" world").expect("append");
        f.flush().expect("flush");
        drop(f);
        let direct2 = sha256_file(&p).expect("direct hash 2");
        assert_ne!(direct2, direct, "content changed");
        assert_eq!(
            sha256_file_cached_with_key(&p, Some(&key))
                .expect("cached3")
                .0,
            direct2,
            "stale digest must never be served after a content change"
        );
    }

    /// A cache hit must not read the artifact. The digest is correct either
    /// way, so without asserting the source directly a regression to hashing
    /// on every call would pass every other test in this module while costing
    /// a full re-read of the artifact on every launch.
    #[test]
    fn a_sidecar_hit_serves_the_digest_without_reading_the_artifact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = test_key(2);
        let body = b"the quick brown fox";
        let p = artifact(&dir, "blob", body);
        settle();

        let (miss, miss_source) = sha256_file_cached_with_key(&p, Some(&key)).expect("miss");
        assert_eq!(
            miss_source,
            DigestSource::Hashed(body.len() as u64),
            "a sidecar miss reads the whole artifact"
        );

        let (hit, hit_source) = sha256_file_cached_with_key(&p, Some(&key)).expect("hit");
        assert_eq!(hit, miss, "a hit serves the digest the miss computed");
        assert_eq!(
            hit_source,
            DigestSource::Sidecar,
            "a sidecar hit must not read the artifact"
        );

        // A rewrite must be read again rather than served from a stale sidecar.
        cross_a_timestamp_tick();
        let mut f = fs::OpenOptions::new().append(true).open(&p).expect("open");
        f.write_all(b" jumps").expect("append");
        drop(f);
        let (fresh, fresh_source) = sha256_file_cached_with_key(&p, Some(&key)).expect("after");
        assert_ne!(fresh, miss, "content changed, so the digest must change");
        assert!(
            matches!(fresh_source, DigestSource::Hashed(_)),
            "a rewritten artifact must be re-read, not served from a stale sidecar"
        );
    }

    /// Someone who can write the artifact edits it in place, keeps its size and
    /// puts its mtime back. Size and mtime alone would accept the old digest;
    /// the ctime that editing moves, which no user-space call can set, must not.
    #[test]
    fn an_in_place_edit_with_the_mtime_restored_is_not_served_the_old_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = test_key(3);
        let p = artifact(&dir, "rootfs", b"original image bytes");
        let original = sha256_file_cached_with_key(&p, Some(&key)).expect("seal").0;
        let mtime = fs::metadata(&p).expect("stat").modified().expect("mtime");

        cross_a_timestamp_tick();
        fs::write(&p, b"tampered image bytes").expect("same-size edit");
        fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .expect("open")
            .set_modified(mtime)
            .expect("restore mtime");

        let (served, source) = sha256_file_cached_with_key(&p, Some(&key)).expect("after edit");
        assert_ne!(
            served, original,
            "the edited file must not carry the old digest"
        );
        assert!(matches!(source, DigestSource::Hashed(_)), "got {source:?}");
    }

    /// A valid sidecar line is copied onto a different file made to have the
    /// same size and mtime. The line is sealed for the first file's inode and
    /// ctime, so it does not verify for the second.
    #[test]
    fn a_sidecar_copied_onto_another_file_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = test_key(4);
        let good = artifact(&dir, "good", b"trusted image bytes");
        settle();
        let trusted = sha256_file_cached_with_key(&good, Some(&key))
            .expect("seal")
            .0;
        let mtime = fs::metadata(&good)
            .expect("stat")
            .modified()
            .expect("mtime");

        cross_a_timestamp_tick();
        let evil = artifact(&dir, "evil", &vec![b'e'; b"trusted image bytes".len()]);
        assert_eq!(
            fs::metadata(&evil).expect("stat").len(),
            fs::metadata(&good).expect("stat").len()
        );
        fs::OpenOptions::new()
            .write(true)
            .open(&evil)
            .expect("open")
            .set_modified(mtime)
            .expect("match mtime");
        fs::copy(sha256_cache_path(&good), sha256_cache_path(&evil)).expect("copy sidecar");

        let (served, source) = sha256_file_cached_with_key(&evil, Some(&key)).expect("evil");
        assert_ne!(
            served, trusted,
            "another file must not inherit the sealed digest"
        );
        assert_eq!(served, sha256_file(&evil).expect("direct"));
        assert!(matches!(source, DigestSource::Hashed(_)), "got {source:?}");
    }

    #[test]
    fn a_forged_legacy_or_foreign_keyed_sidecar_is_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = test_key(5);
        let p = artifact(&dir, "blob", b"payload");
        let real = sha256_file(&p).expect("hash");
        let forged = "f".repeat(64);
        let meta = fs::metadata(&p).expect("stat");
        let size = meta.len();

        for (label, line) in [
            ("unsealed legacy line", format!("{forged} {size} 0\n")),
            ("guessed seal", format!("{forged} {}\n", "0".repeat(64))),
            ("digest only", format!("{forged}\n")),
        ] {
            fs::write(sha256_cache_path(&p), line).expect("plant sidecar");
            let (served, source) = sha256_file_cached_with_key(&p, Some(&key)).expect(label);
            assert_eq!(served, real, "{label}");
            assert!(
                matches!(source, DigestSource::Hashed(_)),
                "{label}: {source:?}"
            );
        }

        // A sidecar sealed under another host's key does not verify here.
        let other = test_key(6);
        sha256_file_cached_with_key(&p, Some(&other)).expect("sealed by another key");
        let (_, source) = sha256_file_cached_with_key(&p, Some(&key)).expect("under our key");
        assert!(matches!(source, DigestSource::Hashed(_)), "got {source:?}");
    }

    #[test]
    fn without_a_key_nothing_is_cached_and_every_call_hashes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = artifact(&dir, "blob", b"payload");
        for _ in 0..2 {
            let (_, source) = sha256_file_cached_with_key(&p, None).expect("hash");
            assert!(matches!(source, DigestSource::Hashed(_)), "got {source:?}");
        }
        assert!(
            !sha256_cache_path(&p).exists(),
            "no unsealed sidecar is written"
        );
    }

    #[test]
    fn parse_sha256_sidecar_rejects_malformed_lines() {
        let key = test_key(7);
        let dir = tempfile::tempdir().expect("tempdir");
        let p = artifact(&dir, "blob", b"x");
        let identity = super::super::digest_cache::FileIdentity::of(&fs::metadata(&p).unwrap())
            .expect("identity");
        let hex = "a".repeat(64);
        let seal = key.seal(&identity, &hex);
        assert_eq!(
            parse_sha256_sidecar(&format!("{hex} {seal}"), &key, &identity),
            Some(hex.clone())
        );
        assert_eq!(parse_sha256_sidecar("garbage", &key, &identity), None);
        assert_eq!(
            parse_sha256_sidecar(&format!("short {seal}"), &key, &identity),
            None
        );
        assert_eq!(
            parse_sha256_sidecar(&format!("{hex} {seal} extra"), &key, &identity),
            None
        );
        let non_hex = format!("{}g", "a".repeat(63));
        assert_eq!(
            parse_sha256_sidecar(
                &format!("{non_hex} {}", key.seal(&identity, &non_hex)),
                &key,
                &identity
            ),
            None,
            "a 64-character non-hex digest is rejected"
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

    /// A real release bundle, the same fixture the release-signature tests
    /// verify under an exact identity. Checked here under the issuer alone, the
    /// verifier must hand back the workflow identity the certificate carries —
    /// the value a pattern-matching caller compares, so a regression that
    /// returned the wrong field would let that caller trust the wrong signer.
    #[cfg(feature = "manifest-verify")]
    #[test]
    fn a_real_bundle_verified_under_its_issuer_names_its_signing_workflow() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../mvm-build/tests/fixtures/release-signature/v0.18.0-rc.1");
        let payload = std::fs::read(dir.join("builder-vm-aarch64-checksums-sha256.txt")).unwrap();
        let bundle =
            std::fs::read(dir.join("builder-vm-aarch64-checksums-sha256.txt.bundle")).unwrap();

        let signer = verify_signed_payload_signer(
            &payload,
            &bundle,
            crate::release_trust::RELEASE_OIDC_ISSUER,
        )
        .expect("the release workflow's own signature verifies under its issuer");
        assert_eq!(
            signer.identity,
            crate::release_trust::accepted_release_identities("0.18.0-rc.1")[0]
        );
        assert_eq!(signer.issuer, crate::release_trust::RELEASE_OIDC_ISSUER);

        let mut tampered = payload.clone();
        tampered.push(b'\n');
        verify_signed_payload_signer(
            &tampered,
            &bundle,
            crate::release_trust::RELEASE_OIDC_ISSUER,
        )
        .expect_err("a payload that is not the signed one must be refused");
        verify_signed_payload_signer(&payload, &bundle, "https://accounts.example.test")
            .expect_err("a signature is never accepted under a different issuer");
    }

    #[cfg(feature = "manifest-verify")]
    #[test]
    fn a_real_bundle_verifies_the_streamed_file_digest_without_loading_the_payload() {
        use sha2::{Digest, Sha256};

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../mvm-build/tests/fixtures/release-signature/v0.18.0-rc.1");
        let payload = std::fs::read(dir.join("builder-vm-aarch64-checksums-sha256.txt"))
            .expect("fixture payload");
        let bundle = std::fs::read(dir.join("builder-vm-aarch64-checksums-sha256.txt.bundle"))
            .expect("fixture bundle");
        let digest = hex::encode(Sha256::digest(&payload));
        let identity = &crate::release_trust::accepted_release_identities("0.18.0-rc.1")[0];
        verify_signed_sha256(
            &digest,
            &bundle,
            identity,
            crate::release_trust::RELEASE_OIDC_ISSUER,
        )
        .expect("real signed digest verifies");

        let wrong = hex::encode(Sha256::digest(b"changed payload"));
        verify_signed_sha256(
            &wrong,
            &bundle,
            identity,
            crate::release_trust::RELEASE_OIDC_ISSUER,
        )
        .expect_err("a different digest is refused");
        verify_signed_sha256(
            &digest,
            &bundle,
            "https://github.com/other/workflow@refs/heads/main",
            crate::release_trust::RELEASE_OIDC_ISSUER,
        )
        .expect_err("a different signer is refused");
    }

    #[test]
    fn malformed_digest_cannot_be_verified() {
        verify_signed_sha256("not-a-digest", b"bundle", "identity", "issuer")
            .expect_err("invalid SHA-256 syntax is refused");
    }

    #[cfg(not(feature = "manifest-verify"))]
    #[test]
    fn a_build_without_the_verifier_refuses_signer_extraction_too() {
        assert!(!keyless_verifier_available());
        let err = verify_signed_payload_signer(b"{}", b"bundle", "issuer")
            .expect_err("a non-verifying build must refuse");
        assert!(
            err.to_string()
                .contains("manifest-verify feature is disabled")
        );
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
