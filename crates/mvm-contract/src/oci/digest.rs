//! Content-digest verification for OCI bytes already in memory.
//!
//! This is the "verify" half of inspect-and-verify: given manifest bytes
//! and the digest they were pinned under, prove they still hash to it. No
//! registry, no filesystem, no async — so a browser can check an image it
//! fetched by any means at all.

use alloc::format;
use alloc::string::ToString;
use sha2::{Digest, Sha256};

use crate::oci::OciError;
use crate::verify::encode_hex32;

/// Verify that `bytes` hashes to `expected` (a `sha256:<hex>` string).
/// Used by callers that already have manifest bytes in hand (e.g. from a
/// cache) and want to assert content integrity without going through the
/// full fetcher.
///
/// Always fails closed. Returns [`OciError::DigestMismatch`] on content
/// drift, [`OciError::MalformedDigest`] if `expected` does not match
/// `sha256:<64 lowercase hex chars>`,
/// [`OciError::UnsupportedDigestAlgorithm`] for non-sha256 inputs.
pub fn verify_sha256_digest(bytes: &[u8], expected: &str) -> Result<(), OciError> {
    let (alg, hex_part) = expected.split_once(':').ok_or_else(|| {
        OciError::MalformedDigest(format!("missing algorithm prefix: {expected:?}"))
    })?;
    if alg != "sha256" {
        return Err(OciError::UnsupportedDigestAlgorithm(alg.to_string()));
    }
    if hex_part.len() != 64 {
        return Err(OciError::MalformedDigest(format!(
            "sha256 digest must be 64 hex chars, got {} in {expected:?}",
            hex_part.len()
        )));
    }
    if !hex_part
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(OciError::MalformedDigest(format!(
            "digest hex must be lowercase ascii: {expected:?}"
        )));
    }

    // `encode_hex32` is this crate's existing lowercase-hex encoder, used by
    // the audit verifier. Reused rather than pulling in `hex`, which the
    // browser bundle would otherwise carry for one call.
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let computed = format!("sha256:{}", encode_hex32(&digest));
    if computed != expected {
        return Err(OciError::DigestMismatch {
            expected: expected.to_string(),
            computed,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    const KNOWN_BYTES: &[u8] = b"hello mvm";
    // sha256("hello mvm") — kept as a constant so the test for
    // `known_digest_constant_is_self_consistent` flags any
    // accidental edit. Recompute via:
    //   printf 'hello mvm' | shasum -a 256
    const KNOWN_DIGEST: &str =
        "sha256:790aa64759a490e14bb0197b875b2d41d7ecea8d73fedcaea7eb88b6d59b691d";

    fn computed_digest(bytes: &[u8]) -> String {
        let d: [u8; 32] = Sha256::digest(bytes).into();
        format!("sha256:{}", encode_hex32(&d))
    }

    #[test]
    fn verify_digest_accepts_matching_content() {
        let digest = computed_digest(KNOWN_BYTES);
        verify_sha256_digest(KNOWN_BYTES, &digest).expect("matching content must verify");
    }

    #[test]
    fn verify_digest_rejects_tampered_content() {
        let digest = computed_digest(KNOWN_BYTES);
        let tampered: Vec<u8> = KNOWN_BYTES
            .iter()
            .copied()
            .chain(core::iter::once(b'!'))
            .collect();
        let err = verify_sha256_digest(&tampered, &digest).unwrap_err();
        match err {
            OciError::DigestMismatch { .. } => {}
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_digest_rejects_unsupported_algorithm() {
        let err = verify_sha256_digest(KNOWN_BYTES, "sha512:abc").unwrap_err();
        match err {
            OciError::UnsupportedDigestAlgorithm(alg) => assert_eq!(alg, "sha512"),
            other => panic!("expected UnsupportedDigestAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn verify_digest_rejects_missing_algorithm_prefix() {
        let err = verify_sha256_digest(KNOWN_BYTES, "abc").unwrap_err();
        assert!(matches!(err, OciError::MalformedDigest(_)), "got {err:?}");
    }

    #[test]
    fn verify_digest_rejects_wrong_hex_length() {
        let err = verify_sha256_digest(KNOWN_BYTES, "sha256:abc").unwrap_err();
        assert!(matches!(err, OciError::MalformedDigest(_)), "got {err:?}");
    }

    #[test]
    fn verify_digest_rejects_uppercase_hex() {
        // 64 uppercase hex chars — wrong-case rather than wrong-length.
        let upper = format!("sha256:{}", "A".repeat(64));
        let err = verify_sha256_digest(KNOWN_BYTES, &upper).unwrap_err();
        assert!(matches!(err, OciError::MalformedDigest(_)), "got {err:?}");
    }

    #[test]
    fn known_digest_constant_is_self_consistent() {
        // Guard against future edits to KNOWN_DIGEST breaking the
        // other tests silently. If this fires, recompute the
        // constant via:
        //   echo -n "hello mvm" | shasum -a 256
        let computed = computed_digest(KNOWN_BYTES);
        assert_eq!(computed, KNOWN_DIGEST);
    }
}
