//! Cosign-verify a downloaded release archive before anything reads it.
//!
//! The digest an installed binary checks an archive against comes from a
//! `.sha256` fetched over the same channel as the archive itself. That
//! authenticates the transport, not the publisher: whoever controls what the
//! base URL serves serves a matching pair. Since the archive becomes the
//! guest's runtime overlay or its SDK cdylib, "whoever controls that URL"
//! otherwise gets arbitrary code inside the sandbox.
//!
//! So every downloaded release archive is verified against the release
//! workflow's cosign-keyless signing identity before it is extracted. The
//! verification primitive is [`mvm_core::crypto::image_verify::verify_signed_payload`]
//! — an offline check against an embedded Sigstore trust root — and the trust
//! root is [`mvm_core::release_trust`], the same one a stock binary already uses
//! for its own release packs. Nothing new is trusted and no dependency is added.
//!
//! Fails closed: a missing bundle, an unparseable bundle, a signature from an
//! identity outside the release set, or a build that cannot verify at all each
//! refuse the install.

use std::path::Path;

use crate::runtime_overlay::RuntimeOverlayError;

/// Documented emergency-rotation escape: skip the signature rung when a
/// signing outage would otherwise strand every download. Never set in CI.
/// Sibling of `MVM_SKIP_HASH_VERIFY`, and deliberately a *separate* switch —
/// bypassing the publisher check is a strictly bigger concession than
/// bypassing the digest check, so one does not imply the other.
pub const SKIP_COSIGN_VERIFY_ENV: &str = "MVM_SKIP_COSIGN_VERIFY";

/// Suffix the release attaches beside each signed archive.
const BUNDLE_SUFFIX: &str = ".bundle";

/// Name of the signature bundle published beside `asset`.
///
/// One definition, so the release workflow's asset list and the downloader's
/// request cannot drift — a mismatch would be invisible until a real download
/// 404s. `tests/release_assets.rs` asserts the workflow publishes exactly this.
#[must_use]
pub fn bundle_asset_name(asset: &str) -> String {
    format!("{asset}{BUNDLE_SUFFIX}")
}

/// One archive to check, and where its signature lives.
///
/// A params struct rather than four positional arguments because three of them
/// are strings and transposing any two would silently verify the wrong thing.
#[derive(Debug, Clone, Copy)]
pub struct ReleaseSignatureRequest<'a> {
    /// Per-version release base URL the archive was fetched from.
    pub base_url: &'a str,
    /// The archive's published asset name, e.g. `runtime-overlay-aarch64.tar.gz`.
    pub asset: &'a str,
    /// Where the already-downloaded archive sits on disk.
    pub archive_path: &'a Path,
    /// Version whose signing identity is accepted. The release identity is
    /// tag-bound, so this pins *which* release may have signed the archive.
    pub version: &'a str,
    /// Which release train published the asset, and therefore which workflow
    /// identity may have signed it.
    pub train: ReleaseTrain,
}

/// The release train an asset was published on.
///
/// The two trains sign different artifact classes under different refs, and
/// `mvm_core::release_trust` keeps their identity sets deliberately disjoint so
/// a signature minted over a boot image cannot validate a CLI tarball or the
/// reverse. Making the caller name its train keeps that separation a decision
/// at the fetch site rather than an accident of which helper it reached for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReleaseTrain {
    /// `release.yml`, signing CLI tarballs under `refs/tags/v<version>`.
    #[default]
    Cli,
    /// `release-boot-image.yml`, signing images under
    /// `refs/tags/boot-image/v<version>`.
    BootImage,
}

/// Verify `request`'s archive against the release workflow's keyless signing
/// identity, fetching the Sigstore bundle published beside it.
///
/// Accepts if any identity in [`mvm_core::release_trust::accepted_release_identities`]
/// verifies the archive bytes under the release OIDC issuer. Refuses on a
/// missing bundle, an unparseable bundle, a signature from an identity outside
/// that set, or a build compiled without the verifier — there is no downgrade
/// to the digest-only posture this rung exists to replace.
///
/// Errors name the asset and never echo bundle or archive bytes, so the message
/// is safe to surface to an operator verbatim.
pub fn verify_release_archive_signature(
    request: &ReleaseSignatureRequest<'_>,
) -> Result<(), RuntimeOverlayError> {
    if std::env::var_os(SKIP_COSIGN_VERIFY_ENV).is_some() {
        tracing::warn!(
            asset = request.asset,
            "{SKIP_COSIGN_VERIFY_ENV} set — skipping release signature verification. \
             This is an emergency-rotation escape hatch; never set it in CI."
        );
        return Ok(());
    }

    let bundle = fetch_bundle(request)?;
    let archive = std::fs::read(request.archive_path)?;
    verify_against_release_identities(&archive, &bundle, request)
}

/// Download the archive's signature bundle. A release that published an archive
/// without one is refused here rather than treated as unsigned.
fn fetch_bundle(request: &ReleaseSignatureRequest<'_>) -> Result<Vec<u8>, RuntimeOverlayError> {
    let url = format!("{}/{}", request.base_url, bundle_asset_name(request.asset));
    let tmp = tempfile::NamedTempFile::new()?;
    crate::runtime_overlay::curl_download(&url, tmp.path()).map_err(|_| {
        RuntimeOverlayError::SignatureMissing {
            asset: request.asset.to_string(),
            bundle_url: url.clone(),
        }
    })?;
    Ok(std::fs::read(tmp.path())?)
}

fn verify_against_release_identities(
    archive: &[u8],
    bundle: &[u8],
    request: &ReleaseSignatureRequest<'_>,
) -> Result<(), RuntimeOverlayError> {
    let identities = match request.train {
        ReleaseTrain::Cli => mvm_core::release_trust::accepted_release_identities(request.version),
        ReleaseTrain::BootImage => {
            mvm_core::release_trust::accepted_boot_image_identities(request.version)
        }
    };
    verify_release_archive_bytes(
        archive,
        bundle,
        request.asset,
        &identities,
        mvm_core::release_trust::RELEASE_OIDC_ISSUER,
    )
}

/// Verify `archive` against `bundle` under any of `identities`, accepting on
/// the first that verifies.
///
/// The trust root is a parameter rather than baked in — the same shape
/// `mvm_core::packs::verify` takes a `KeylessTrust` — so a signer other than
/// the tagged release workflow can be checked without a second implementation.
/// Production always passes [`mvm_core::release_trust`]'s set; the
/// `verify-release-archive-signature` example passes an explicit identity so a
/// CI lane can round-trip a *real* cosign bundle signed under that lane's own
/// OIDC identity. That is the only way to prove the format the release
/// publishes is one this verifier can actually parse — offline fixtures cannot,
/// because a valid Sigstore signature needs Fulcio and Rekor.
///
/// The identity set is a list because the release trust root allows more than
/// one template; a rotation that adds one must not require a code change here.
pub fn verify_release_archive_bytes(
    archive: &[u8],
    bundle: &[u8],
    asset: &str,
    identities: &[String],
    issuer: &str,
) -> Result<(), RuntimeOverlayError> {
    let mut last_failure: Option<String> = None;

    for identity in identities {
        match mvm_core::crypto::image_verify::verify_signed_payload(
            archive, bundle, identity, issuer,
        ) {
            Ok(()) => {
                tracing::debug!(
                    asset,
                    identity = identity.as_str(),
                    "release archive signature verified"
                );
                return Ok(());
            }
            Err(error) => last_failure = Some(error.to_string()),
        }
    }

    Err(RuntimeOverlayError::SignatureInvalid {
        asset: asset.to_string(),
        reason: last_failure.unwrap_or_else(|| {
            "no release signing identity is configured for this version".to_string()
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    const FIXTURE_VERSION: &str = "9.9.9";
    const ASSET: &str = "runtime-overlay-aarch64.tar.gz";

    /// Stage a release directory holding `archive`, optionally beside a bundle.
    /// Returns the tempdir plus the `file://` base URL pointing at it.
    fn stage(archive: &[u8], bundle: Option<&[u8]>) -> (tempfile::TempDir, String) {
        let root = tempfile::tempdir().expect("release fixture root");
        let dir = root.path().join(format!("v{FIXTURE_VERSION}"));
        std::fs::create_dir_all(&dir).expect("create the release dir");
        std::fs::write(dir.join(ASSET), archive).expect("write the archive");
        if let Some(bytes) = bundle {
            std::fs::write(dir.join(format!("{ASSET}.bundle")), bytes).expect("write the bundle");
        }
        let base = format!("file://{}/v{FIXTURE_VERSION}", root.path().display());
        (root, base)
    }

    /// Write the archive where the downloader would have put it, then run the
    /// signature rung against the staged release.
    fn verify(base: &str, archive: &[u8]) -> Result<(), String> {
        let local = tempfile::tempdir().expect("local dir");
        let path = local.path().join(ASSET);
        std::fs::write(&path, archive).expect("write the local archive");
        verify_release_archive_signature(&ReleaseSignatureRequest {
            base_url: base,
            asset: ASSET,
            archive_path: &path,
            version: FIXTURE_VERSION,
            train: ReleaseTrain::Cli,
        })
        .map_err(|e| e.to_string())
    }

    #[test]
    fn a_missing_bundle_refuses_and_names_the_asset() {
        let mut env = TestEnv::new();
        env.remove("MVM_SKIP_COSIGN_VERIFY");
        let archive = b"archive-bytes";
        let (_root, base) = stage(archive, None);

        let err = verify(&base, archive).expect_err("an unsigned archive must be refused");

        assert!(
            err.contains(ASSET),
            "the refusal must name the asset: {err}"
        );
        assert!(
            err.contains("signature") || err.contains("bundle"),
            "the refusal must say what was missing: {err}"
        );
    }

    /// The documented emergency-rotation escape, and the only way an archive
    /// with no verifiable signature is ever admitted.
    #[test]
    fn the_documented_escape_hatch_admits() {
        let mut env = TestEnv::new();
        env.set("MVM_SKIP_COSIGN_VERIFY", "1");
        let archive = b"archive-bytes";
        let (_root, base) = stage(archive, None);

        verify(&base, archive).expect("the escape hatch must admit without a bundle");
    }

    /// A bundle that is present but not a Sigstore bundle must be refused, not
    /// treated as absent. Only meaningful when the verifier is actually
    /// compiled in — without `manifest-verify` every bundle fails identically,
    /// so the assertion could not tell a bad signature from a disabled
    /// verifier and would not be a witness.
    #[cfg(feature = "manifest-verify")]
    #[test]
    fn a_malformed_bundle_is_refused() {
        let mut env = TestEnv::new();
        env.remove("MVM_SKIP_COSIGN_VERIFY");
        let archive = b"archive-bytes";
        let (_root, base) = stage(archive, Some(b"{\"not\":\"a sigstore bundle\"}"));

        let err = verify(&base, archive).expect_err("a malformed bundle must be refused");

        assert!(err.contains(ASSET), "{err}");
    }

    /// A build that cannot verify must refuse rather than silently downgrade to
    /// the sha256-only posture this rung exists to replace.
    #[cfg(not(feature = "manifest-verify"))]
    #[test]
    fn a_build_that_cannot_verify_refuses_and_names_both_remedies() {
        let mut env = TestEnv::new();
        env.remove("MVM_SKIP_COSIGN_VERIFY");
        let archive = b"archive-bytes";
        let (_root, base) = stage(archive, Some(b"{\"not\":\"a sigstore bundle\"}"));

        let err = verify(&base, archive).expect_err("a non-verifying build must refuse");

        assert!(
            err.contains("manifest-verify"),
            "the refusal must name the feature that would fix it: {err}"
        );
        assert!(
            err.contains(SKIP_COSIGN_VERIFY_ENV),
            "the refusal must name the documented escape: {err}"
        );
    }

    #[test]
    fn the_refusal_carries_no_bundle_bytes() {
        let mut env = TestEnv::new();
        env.remove("MVM_SKIP_COSIGN_VERIFY");
        let archive = b"archive-bytes";
        let secret_looking = b"{\"canary\":\"SHOULD-NOT-APPEAR-IN-AN-ERROR\"}";
        let (_root, base) = stage(archive, Some(secret_looking));

        let err = verify(&base, archive).expect_err("a bogus bundle must be refused");

        assert!(
            !err.contains("SHOULD-NOT-APPEAR-IN-AN-ERROR"),
            "an error must not echo bundle contents: {err}"
        );
    }

    /// The identities the verifier accepts are the release workflow's, bound to
    /// the running version — not a wildcard and not a different workflow.
    #[test]
    fn accepted_identities_are_the_versioned_release_workflow() {
        let identities = mvm_core::release_trust::accepted_release_identities(FIXTURE_VERSION);
        assert!(!identities.is_empty(), "there must be a release identity");
        for identity in &identities {
            assert!(
                identity.contains("release.yml"),
                "only the release workflow signs release archives: {identity}"
            );
            assert!(
                identity.ends_with(&format!("refs/tags/v{FIXTURE_VERSION}")),
                "the identity must be pinned to this version's tag: {identity}"
            );
        }
    }
}
