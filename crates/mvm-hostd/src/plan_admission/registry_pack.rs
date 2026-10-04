//! Reverification of signed registry-pack identities at host admission.

use anyhow::{Context, Result};
use mvm_core::plan::{AssetKind, ExecutionPlan};

/// Re-open every pack identity under the host's current publisher trust and
/// lock state. A signed plan alone cannot establish that an installed payload
/// is still present, unmodified, and published by a trusted identity.
pub(super) fn verify_registry_pack_assets(plan: &ExecutionPlan) -> Result<()> {
    let packs = plan
        .asset_identities
        .iter()
        .filter(|identity| identity.kind == AssetKind::RegistryPack)
        .collect::<Vec<_>>();
    if packs.is_empty() {
        return Ok(());
    }
    let lock =
        mvm_core::registry_pack_store::load_pack_lockfile(&mvm_core::config::pack_lockfile_path())
            .context("loading registry pack lockfile for admission")?;
    let publisher = mvm_core::registry_pack_store::load_publisher_policy_or_official_default(
        &mvm_core::config::registry_pack_publisher_policy_path(),
    )
    .context("loading registry pack publisher trust for admission")?
    .policy;
    let cache = mvm_core::config::registry_pack_cache_dir();
    for identity in packs {
        let reference: mvm_core::registry_pack::PackReference = identity
            .name
            .parse()
            .context("invalid registry pack reference in signed plan")?;
        anyhow::ensure!(
            reference.version().is_some(),
            "registry pack identity in signed plan must name an exact version"
        );
        let (_, verified) = mvm_core::registry_pack_store::open_installed_registry_pack(
            &cache, &lock, &publisher, &reference,
        )
        .with_context(|| format!("verifying registry pack {reference} at admission"))?;
        anyhow::ensure!(
            verified.manifest_sha256().as_str() == identity.digest,
            "registry pack {reference} does not match its signed-plan digest"
        );
    }
    Ok(())
}
