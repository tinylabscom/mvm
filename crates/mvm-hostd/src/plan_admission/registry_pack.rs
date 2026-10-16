//! Reverification of signed registry-pack identities at host admission.

use anyhow::{Context, Result};
use mvm_core::plan::{AssetKind, ExecutionPlan};
use mvm_core::vm_backend::{BackendKind, VmStartConfig};

/// Ownership of the authenticated archive for a checked runtime selection.
/// The normal runtime lifecycle rechecks and owns payload snapshots before
/// backend effects, and retains their authenticated closure for the VM.
#[derive(Debug)]
pub struct PreparedBuiltPackRuntime {
    _manifest: mvm_build::guest_runtime::evidence::VerifiedRuntimeManifest,
}

impl PreparedBuiltPackRuntime {
    /// Recheck the actual selection immediately before dispatch. This cannot
    /// turn the earlier checked release into a source or alternate release.
    pub fn verify_config(&self, config: &VmStartConfig) -> Result<()> {
        let current = checked_release_runtime(config)?;
        anyhow::ensure!(
            current._manifest.archive_sha256() == self._manifest.archive_sha256(),
            "built pack runtime changed after its final admission check"
        );
        Ok(())
    }
}

/// One-use final image expectations copied from a genuinely admitted plan.
/// This cannot admit a plan, be deserialized, or authorize another launch.
pub struct BuiltPackBootCheck {
    plan: ExecutionPlan,
    plan_json: String,
    backend: BackendKind,
}

impl std::fmt::Debug for BuiltPackBootCheck {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BuiltPackBootCheck")
            .field("plan_id", &self.plan.plan_id)
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

impl super::AdmittedPlan {
    /// Carry only admitted image expectations across a preparation callback.
    /// No unsigned JSON is parsed, and the original admission remains the
    /// authority for grants, replay protection and the audit lifecycle.
    pub fn built_pack_boot_check(&self) -> Result<Option<BuiltPackBootCheck>> {
        if !self
            .plan()
            .asset_identities
            .iter()
            .any(|asset| asset.kind == AssetKind::RegistryPack)
        {
            return Ok(None);
        }
        Ok(Some(BuiltPackBootCheck {
            plan: self.plan().clone(),
            plan_json: serde_json::to_string(self.signed())?,
            backend: self
                .backend
                .context("pack boot handoff requires an admitted backend")?,
        }))
    }
}

impl BuiltPackBootCheck {
    /// Consume the expectations against the actual final configuration. Keep
    /// any returned runtime owner through the normal lifecycle handoff.
    pub fn prepare(
        self,
        config: &mut VmStartConfig,
        backend: BackendKind,
    ) -> Result<Option<PreparedBuiltPackRuntime>> {
        anyhow::ensure!(
            backend == self.backend,
            "registry pack backend differs from the admitted backend"
        );
        anyhow::ensure!(
            config.plan_json.as_deref() == Some(self.plan_json.as_str())
                && config.tenant_id.as_deref() == Some(self.plan.tenant.0.as_str()),
            "registry pack final configuration differs from its admitted plan"
        );
        verify_registry_pack_boot(&self.plan, config, backend)
    }
}

/// Check a final admitted image while the normal runtime lifecycle retains
/// payload snapshots and authenticated evidence for the VM lifetime.
pub fn prepare_built_pack_start(
    admitted: &super::AdmittedPlan,
    config: &mut VmStartConfig,
    backend: BackendKind,
) -> Result<Option<PreparedBuiltPackRuntime>> {
    match admitted.built_pack_boot_check()? {
        Some(check) => check.prepare(config, backend),
        None => Ok(None),
    }
}

pub(super) fn verify_runtime_at_dispatch(
    runtime: Option<&PreparedBuiltPackRuntime>,
    config: &VmStartConfig,
    admitted: &super::AdmittedPlan,
    emitter: Option<&crate::audit::emitter::AuditEmitter>,
) -> Result<()> {
    if let Some(runtime) = runtime {
        runtime.verify_config(config).inspect_err(|error| {
            if let Some(emitter) = emitter
                && let Err(audit_error) = emitter.emit_failed(
                    admitted.plan(),
                    "registry-pack-runtime",
                    &format!("{error:#}"),
                )
            {
                tracing::warn!(error = %audit_error, "audit emit_failed failed (non-fatal)");
            }
        })?;
    }
    Ok(())
}

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

/// Revalidate built workload bytes against the final configuration, not just
/// the pack identity admitted earlier. Source packs keep their existing path.
pub(super) fn verify_registry_pack_boot(
    plan: &ExecutionPlan,
    config: &mut VmStartConfig,
    backend: BackendKind,
) -> Result<Option<PreparedBuiltPackRuntime>> {
    use mvm_core::registry_pack::{PackPin, RegistryPackImage};
    use mvm_core::registry_pack_boot::BuiltPackBootContract;

    let mut built = false;
    for identity in plan
        .asset_identities
        .iter()
        .filter(|identity| identity.kind == AssetKind::RegistryPack)
    {
        let reference = identity
            .name
            .parse()
            .context("invalid registry pack reference at final boot verification")?;
        let pin = PackPin::new(
            reference,
            mvm_core::packs::Sha256Hex::new(&identity.digest)?,
        )?;
        let lock = mvm_core::registry_pack_store::load_pack_lockfile(
            &mvm_core::config::pack_lockfile_path(),
        )?;
        let publisher = mvm_core::registry_pack_store::load_publisher_policy_or_official_default(
            &mvm_core::config::registry_pack_publisher_policy_path(),
        )?
        .policy;
        let (_, verified) = mvm_core::registry_pack_store::open_installed_registry_pack(
            &mvm_core::config::registry_pack_cache_dir(),
            &lock,
            &publisher,
            pin.reference(),
        )?;
        anyhow::ensure!(
            verified.manifest_sha256() == pin.manifest_sha256(),
            "registry pack no longer matches the admitted pin at backend handoff"
        );
        if matches!(verified.manifest().image, Some(RegistryPackImage::Built(_))) {
            anyhow::ensure!(
                !built,
                "more than one admitted registry pack declares a built image"
            );
            built = true;
            let contract = BuiltPackBootContract::open_for_admission(
                &pin,
                &mvm_build::stage0_kernel::current_image_set_protocol_support(),
            )?;
            contract.verify_image_config(
                plan,
                config,
                mvm_core::arch::GuestArch::host(),
                backend,
            )?;
        }
    }
    if !built {
        return Ok(None);
    }
    checked_release_runtime(config).map(Some)
}

fn checked_release_runtime(config: &VmStartConfig) -> Result<PreparedBuiltPackRuntime> {
    anyhow::ensure!(
        !config
            .volumes
            .iter()
            .any(|volume| volume.guest == mvm_core::plan::SDK_SIDECAR_GUEST_PATH),
        "built registry images require signed SDK assembly evidence for SDK sidecar attachments"
    );
    let manifest = mvm_runtime::runtime_evidence::verify_release_runtime_for_launch(
        config,
        mvm_runtime::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
    )?;
    Ok(PreparedBuiltPackRuntime {
        _manifest: manifest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_runtime_refuses_unsigned_development_and_unbound_sdk() {
        let mut config = VmStartConfig {
            unsigned_runtime_development: true,
            ..Default::default()
        };
        assert!(checked_release_runtime(&config).is_err());
        config.unsigned_runtime_development = false;
        config.volumes.push(mvm_core::vm_backend::VmVolume {
            guest: mvm_core::plan::SDK_SIDECAR_GUEST_PATH.into(),
            ..Default::default()
        });
        assert!(
            checked_release_runtime(&config)
                .unwrap_err()
                .to_string()
                .contains("signed SDK assembly evidence")
        );
    }
}
