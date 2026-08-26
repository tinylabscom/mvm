//! `mvmctl pack download` — fetch a pack version into the cache without
//! changing which version is active (the one exception: the first version
//! recorded for a key becomes active, since none existed to preserve).
//!
//! Only the builder pack class has a release-fetch wired today (via the
//! builder VM bootstrap path's published-pack machinery); runtime/dev-image
//! packs have no publish/fetch story yet, so those refuse explicitly rather
//! than pretending to do something.

use anyhow::{Result, bail};

use mvm_core::packs::PackKind;

use super::PackKindArg;

pub(in crate::commands) fn run(kind: PackKindArg, version: Option<String>) -> Result<()> {
    match kind.to_pack_kind() {
        PackKind::Builder => {
            let promoted = builder::fetch_and_promote(version.as_deref())?;
            mvm_core::audit_emit!(
                PackCacheChange,
                "op=pack_download kind=builder version={}",
                promoted.release_version
            );
            crate::ui::success(&format!(
                "Downloaded and cached builder pack {} (release {}).",
                builder::short_hash(promoted.hash.as_str()),
                promoted.release_version,
            ));
            Ok(())
        }
        other => not_fetchable(other),
    }
}

/// Shared refusal for pack classes with no release-fetch wired yet. Explicit
/// and specific per class rather than a generic "not implemented" — a caller
/// should never wonder whether this is a bug or a known gap.
pub(in crate::commands) fn not_fetchable(kind: PackKind) -> Result<()> {
    let label = match kind {
        PackKind::Builder => "builder",
        PackKind::Runtime => "runtime",
        PackKind::ImageProject => "dev-image",
        PackKind::Extension => "extension",
    };
    bail!(
        "{label} pack download is not yet fetchable — {label} release-fetch is not wired \
         yet (only the builder pack has a publish/fetch path today)"
    );
}

/// The builder-pack fetch, isolated in its own module so the `not
/// all(release-artifact-bootstrap, builder-vm, manifest-verify)` fallback
/// stays a single, obviously-correct arm regardless of how the feature-gated
/// implementation evolves.
pub(in crate::commands) mod builder {
    use anyhow::Result;

    use mvm_core::packs::Sha256Hex;

    /// A builder pack this process just fetched and promoted (or, for
    /// `update`, is about to activate).
    pub(in crate::commands) struct PromotedBuilderPack {
        pub(in crate::commands) key: mvm_core::pack_cache::PackKey,
        pub(in crate::commands) hash: Sha256Hex,
        pub(in crate::commands) release_version: String,
    }

    pub(in crate::commands) fn short_hash(hash: &str) -> &str {
        &hash[..hash.len().min(12)]
    }

    #[cfg(all(
        feature = "release-artifact-bootstrap",
        feature = "builder-vm",
        feature = "manifest-verify"
    ))]
    pub(in crate::commands) fn fetch_and_promote(
        version: Option<&str>,
    ) -> Result<PromotedBuilderPack> {
        use anyhow::{Context, bail};

        use mvm_core::arch::GuestArch;
        use mvm_core::pack_cache::{
            PackKey, PackProvenanceInput, PackVerifyCtx, promote_and_record,
        };
        use mvm_core::packs::PackManifest;

        use crate::commands::env::builder_vm::bootstrap::attested_builder_pack::{
            fetch_release_builder_pack_staging, host_pack_verify_inputs, keyless_release_policy,
        };

        // The published-pack fetch always pulls the assets for *this build's
        // own* release version (the URL is derived from `CARGO_PKG_VERSION`).
        // An explicit `--version` is honored only when it names that same
        // release; pinning an arbitrary older/newer version isn't wired.
        let current = env!("CARGO_PKG_VERSION");
        if let Some(requested) = version {
            let normalized = requested.trim_start_matches('v');
            if normalized != current {
                bail!(
                    "only the current mvmctl release (v{current}) is fetchable today; \
                     pinning a different --version isn't wired yet"
                );
            }
        }

        let arch = GuestArch::host();
        let arch_str = match arch {
            GuestArch::X86_64 => "x86_64",
            GuestArch::Aarch64 => "aarch64",
        };
        let inputs = host_pack_verify_inputs(arch);
        let policy = keyless_release_policy(&inputs.policy);
        let keyless = mvm_core::release_trust::release_keyless_trust(current);
        let ctx = PackVerifyCtx::keyless(&policy, &keyless, &inputs.trust);

        let staging = fetch_release_builder_pack_staging(arch_str)
            .context("fetching the published builder pack")?;

        let manifest_path = staging.path().join("pack-manifest.json");
        let manifest_bytes = std::fs::read(&manifest_path).with_context(|| {
            format!(
                "reading staged builder pack manifest at {}",
                manifest_path.display()
            )
        })?;
        let manifest: PackManifest =
            serde_json::from_slice(&manifest_bytes).with_context(|| {
                format!(
                    "parsing staged builder pack manifest at {}",
                    manifest_path.display()
                )
            })?;

        let release_version = format!("v{current}");
        let prov = PackProvenanceInput {
            channel: manifest.trust.channel_identity.clone(),
            release_version: release_version.clone(),
            promoted_at_unix: now_unix(),
        };
        let key = PackKey {
            kind: manifest.kind.clone(),
            arch: manifest.target_arch,
            backend: inputs.policy.backend.clone(),
        };
        let promoted = promote_and_record(staging.path(), &manifest, &prov, &ctx)
            .context("verifying and promoting the downloaded builder pack")?;

        Ok(PromotedBuilderPack {
            key,
            hash: promoted.verified.pack_hash,
            release_version,
        })
    }

    #[cfg(all(
        feature = "release-artifact-bootstrap",
        feature = "builder-vm",
        feature = "manifest-verify"
    ))]
    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    #[cfg(not(all(
        feature = "release-artifact-bootstrap",
        feature = "builder-vm",
        feature = "manifest-verify"
    )))]
    pub(in crate::commands) fn fetch_and_promote(
        _version: Option<&str>,
    ) -> Result<PromotedBuilderPack> {
        anyhow::bail!(
            "builder pack download requires an mvmctl built with --features \
             user,release-artifact-bootstrap (end-user release binaries carry \
             this by default); this binary was built without it, so it cannot fetch a \
             published pack"
        );
    }
}

#[cfg(all(
    test,
    not(all(
        feature = "release-artifact-bootstrap",
        feature = "builder-vm",
        feature = "manifest-verify"
    ))
))]
mod tests {
    #[test]
    fn download_refusal_names_root_features_that_exist() {
        let error = match super::builder::fetch_and_promote(None) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("a build without the release feature must refuse"),
        };

        assert!(
            error.contains("--features user,release-artifact-bootstrap"),
            "the remediation must compile against the root package: {error}"
        );
        assert!(
            !error.contains("release-artifact-bootstrap,manifest-verify"),
            "the remediation must not name the removed root feature: {error}"
        );
    }
}
