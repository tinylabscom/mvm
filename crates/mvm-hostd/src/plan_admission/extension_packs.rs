//! Optional extension packs bound by a signed plan: binding validation and exact
//! re-verification against the installed pack.

use anyhow::{Context, Result};
use mvm_core::pack_cache::{PackVerifyCtx, resolve_pack_digest};
use mvm_core::packs::{PackKind, Sha256Hex};
use mvm_core::plan::ExecutionPlan;
use sha2::{Digest, Sha256};

/// Re-verified host artifact behind one extension binding in the signed plan.
#[derive(Debug, Clone)]
pub struct AdmittedExtension {
    pub binding: mvm_contract::protocol::extension_pack::ExtensionPlanBinding,
    pub root: std::path::PathBuf,
}

/// Trust and revocation inputs for exact extension-pack re-verification.
pub struct ExtensionAdmissionContext<'a> {
    verify: &'a PackVerifyCtx<'a>,
    cache_root: Option<&'a std::path::Path>,
}

impl<'a> ExtensionAdmissionContext<'a> {
    /// Use the ordinary MVM pack cache.
    #[must_use]
    pub fn ambient(verify: &'a PackVerifyCtx<'a>) -> Self {
        Self {
            verify,
            cache_root: None,
        }
    }

    /// Use an explicit provider-owned pack cache.
    #[must_use]
    pub fn at(cache_root: &'a std::path::Path, verify: &'a PackVerifyCtx<'a>) -> Self {
        Self {
            verify,
            cache_root: Some(cache_root),
        }
    }

    fn resolve(
        &self,
        digest: &Sha256Hex,
    ) -> Result<Option<mvm_core::pack_cache::VerifiedPackRecord>> {
        match self.cache_root {
            Some(cache_root) => mvm_core::pack_cache::resolve_pack_digest_at(
                cache_root,
                PackKind::Extension,
                digest,
                self.verify,
            ),
            None => resolve_pack_digest(PackKind::Extension, digest, self.verify),
        }
        .map_err(Into::into)
    }
}

pub(super) fn validate_extension_bindings(plan: &ExecutionPlan) -> Result<()> {
    if !plan.extensions.is_empty() {
        let verbs = plan.agent_verbs.as_deref().unwrap_or_default();
        for required in ["run-extension", "cancel-extension"] {
            if !verbs.iter().any(|verb| verb.as_str() == required) {
                anyhow::bail!(
                    "signed plans with optional extensions must grant the {required} agent verb"
                );
            }
        }
    }
    let mut extension_ids = std::collections::HashSet::new();
    let mut pack_digests = std::collections::HashSet::new();
    let mut capabilities = std::collections::HashSet::new();
    for extension in &plan.extensions {
        extension
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid extension binding: {error}"))?;
        if extension.placement
            != mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload
        {
            anyhow::bail!(
                "extension placement isolated_controller is not executable by this MVM version"
            );
        }
        if !extension_ids.insert(extension.extension_id.clone()) {
            anyhow::bail!("duplicate extension identity in signed plan");
        }
        if !pack_digests.insert(extension.pack_digest) {
            anyhow::bail!("duplicate extension pack digest in signed plan");
        }
        for binding in &extension.capabilities {
            if !plan.services.contains(&binding.capability.service) {
                anyhow::bail!(
                    "extension capability service {} is not bound by the signed plan",
                    binding.capability.service
                );
            }
            if !capabilities.insert(binding.capability.clone()) {
                anyhow::bail!("duplicate extension capability in signed plan");
            }
        }
    }
    Ok(())
}

pub(super) fn verify_extension_packs(
    plan: &ExecutionPlan,
    context: Option<&ExtensionAdmissionContext<'_>>,
) -> Result<Vec<AdmittedExtension>> {
    if plan.extensions.is_empty() {
        return Ok(Vec::new());
    }
    let context = context.ok_or_else(|| {
        anyhow::anyhow!(
            "plan binds optional extensions but no extension verification context was provided"
        )
    })?;
    plan.extensions
        .iter()
        .map(|binding| {
            let digest = Sha256Hex::new(hex::encode(binding.pack_digest))
                .context("decoding extension pack digest")?;
            let digest_text = digest.as_str();
            let record = context
                .resolve(&digest)
                .with_context(|| format!("re-verifying extension pack {digest_text}"))?
                .ok_or_else(|| anyhow::anyhow!("extension pack {digest_text} is not installed"))?;
            let contract = record.manifest.extension.as_ref().ok_or_else(|| {
                anyhow::anyhow!("verified extension pack {digest_text} has no extension contract")
            })?;
            let contract_digest: [u8; 32] = Sha256::digest(
                serde_json::to_vec(contract).context("encoding extension contract")?,
            )
            .into();
            if !extension_binding_matches_contract(binding, contract, contract_digest) {
                anyhow::bail!("extension binding does not match verified pack {digest_text}");
            }
            let maximum: std::collections::HashSet<_> = contract
                .capabilities
                .iter()
                .map(mvm_contract::protocol::agent_capability::CapabilityDescriptor::binding)
                .collect();
            if binding
                .capabilities
                .iter()
                .any(|capability| !maximum.contains(capability))
            {
                anyhow::bail!("extension binding widens verified pack authority {digest_text}");
            }
            if !budgets_are_narrower(binding.budgets, contract.budgets) {
                anyhow::bail!("extension binding widens verified pack budgets {digest_text}");
            }
            let artifact = record.dir.root.join(&binding.artifact);
            if !artifact.is_file() {
                anyhow::bail!("verified extension artifact is missing from pack {digest_text}");
            }
            let artifact_size = std::fs::metadata(&artifact)
                .with_context(|| format!("inspecting extension artifact for {digest_text}"))?
                .len();
            if extension_artifact_exceeds_budget(artifact_size, binding.budgets.max_artifact_bytes)
            {
                anyhow::bail!(
                    "verified extension artifact exceeds admitted budget for {digest_text}"
                );
            }
            Ok(AdmittedExtension {
                binding: binding.clone(),
                root: record.dir.root,
            })
        })
        .collect()
}

pub(super) fn extension_binding_matches_contract(
    binding: &mvm_contract::protocol::extension_pack::ExtensionPlanBinding,
    contract: &mvm_contract::protocol::extension_pack::ExtensionPackContract,
    contract_digest: [u8; 32],
) -> bool {
    binding.extension_id == contract.extension_id
        && binding.version == contract.version
        && binding.contract_digest == contract_digest
        && binding.placement == contract.placement
        && binding.artifact == contract.artifact
        && binding.entrypoint == contract.entrypoint
}

pub(super) fn extension_artifact_exceeds_budget(artifact_size: u64, maximum_size: u64) -> bool {
    artifact_size > maximum_size
}

pub(super) fn budgets_are_narrower(
    admitted: mvm_contract::protocol::extension_pack::ExtensionBudgets,
    maximum: mvm_contract::protocol::extension_pack::ExtensionBudgets,
) -> bool {
    admitted.cpu_millis <= maximum.cpu_millis
        && admitted.memory_bytes <= maximum.memory_bytes
        && admitted.duration_ms <= maximum.duration_ms
        && admitted.max_steps <= maximum.max_steps
        && admitted.max_concurrency <= maximum.max_concurrency
        && admitted.max_payload_bytes <= maximum.max_payload_bytes
        && admitted.max_output_bytes <= maximum.max_output_bytes
        && admitted.max_artifact_bytes <= maximum.max_artifact_bytes
}
