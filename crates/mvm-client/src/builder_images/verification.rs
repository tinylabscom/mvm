//! Shared legacy release-fixture support, compiled only for tests/test-support.
use anyhow::{Context, Result};

pub struct ChecksumManifest<'a> {
    pub base_url: &'a str,
    pub asset: &'a str,
    pub version: &'a str,
    pub train: mvm_build::release_signature::ReleaseTrain,
}

impl ChecksumManifest<'_> {
    pub fn url(&self) -> String {
        format!("{}/{}", self.base_url, self.asset)
    }
}

pub fn bump_verify_outcome(outcome: &str) {
    let metrics = mvm_core::observability::metrics::global();
    let counter = match outcome {
        "sig_invalid" => &metrics.dev_image_verify_sig_invalid,
        "digest_mismatch" => &metrics.dev_image_verify_digest_mismatch,
        "version_skew" => &metrics.dev_image_verify_version_skew,
        "revoked" => &metrics.dev_image_verify_revoked,
        "expired" => &metrics.dev_image_verify_expired,
        "network" => &metrics.dev_image_verify_network,
        _ => {
            tracing::warn!("bump_verify_outcome: unknown outcome '{outcome}'");
            return;
        }
    };
    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if outcome != "network" {
        let mvmctl_version = env!("CARGO_PKG_VERSION");
        mvm_core::audit_emit!(
            ImageVerifyFailed,
            "outcome={outcome} mvmctl_version={mvmctl_version}"
        );
    }
}

pub fn verify_artifact_hash(path: &str, name: &str, expected: Option<&String>) -> Result<()> {
    if std::env::var_os("MVM_SKIP_HASH_VERIFY").is_some() {
        tracing::warn!("MVM_SKIP_HASH_VERIFY set — skipping integrity check on {name}");
        return Ok(());
    }
    let expected =
        expected.with_context(|| format!("internal: no expected hash recorded for {name}"))?;
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open downloaded artifact at {path}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file
            .read(&mut buffer)
            .with_context(|| format!("Failed to hash downloaded artifact at {path}"))?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    let actual = hex::encode(digest.finalize());
    if actual != *expected {
        let _ = std::fs::remove_file(path);
        bump_verify_outcome("digest_mismatch");
        anyhow::bail!(
            "Integrity check failed for {name}.\n\
             expected sha256: {expected}\n\
             actual   sha256: {actual}\n\
             \n\
             The downloaded artifact does not match the published checksum.\n\
             Refusing to use it. Possible causes:\n\
             - mid-flight corruption (retry the download);\n\
             - mirror/CDN cache poisoning (open an issue);\n\
             - the release was re-uploaded and the manifest is stale.\n\
             ADR-002 §W5.1."
        );
    }
    Ok(())
}
