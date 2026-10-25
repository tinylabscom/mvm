//! Read-only bundle verification for launch previews.

use std::path::Path;

use anyhow::Result;
use mvm_core::plan::FsTrustStore;
use mvm_core::plan::bundle::{
    BUNDLE_ORIGIN_LABEL, BundleOrigin, LOCAL_BUILD_ORIGIN, LocalBundleTrustStore,
    VerifiedBundleFile, bundle_origin, key_id_from_pubkey, verify_bundle_file,
};

pub fn verify_for_preview(
    path: &Path,
    release_trust: FsTrustStore,
) -> Result<(VerifiedBundleFile, BundleOrigin)> {
    let Some(host_key) = crate::bundle::existing_host_verifying_key()? else {
        let verified = verify_bundle_file(path, &release_trust)
            .map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))?;
        let origin = if verified
            .manifest
            .labels
            .get(BUNDLE_ORIGIN_LABEL)
            .is_some_and(|value| value == LOCAL_BUILD_ORIGIN)
        {
            BundleOrigin::Untrusted
        } else {
            BundleOrigin::ReleaseVerified
        };
        return Ok((verified, origin));
    };
    let host_key_id = key_id_from_pubkey(&host_key);
    let trust = LocalBundleTrustStore::new(release_trust, host_key_id.clone(), host_key);
    let verified = verify_bundle_file(path, &trust)
        .map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))?;
    let origin = bundle_origin(&verified.manifest, &host_key_id, trust.release());
    Ok((verified, origin))
}
