//! Same-host custody for a selected development base; never release authority.

use anyhow::{Context, Result};
use mvm_core::plan::bundle::{ArtifactRole, BundleMember, VerifiedBundle, key_id_from_pubkey};
use mvm_core::plan::{ExecutionPlan, SignedExecutionPlan, Variant, verify_plan};

use super::{RunPosture, host_signer_id};

pub(super) fn verify(
    plan: &ExecutionPlan,
    signed: &SignedExecutionPlan,
    signer_id: &str,
    posture: &RunPosture<'_>,
    bundle: &VerifiedBundle,
) -> Result<()> {
    if !bundle
        .manifest
        .members
        .iter()
        .any(|member| matches!(member, BundleMember::LocalDevelopmentBaseProof(_)))
    {
        return Ok(());
    }
    anyhow::ensure!(
        posture.variant == Variant::Dev && signer_id == host_signer_id(),
        "local development base refuses production or externally signed plans"
    );
    let host = crate::audit::host_keypair::load_or_init()?;
    verify_plan(signed, &[(signer_id, &host.verifying)])
        .context("local development plan must be signed on this host")?;
    anyhow::ensure!(
        bundle.key_id == key_id_from_pubkey(&host.verifying),
        "local development bundle signer differs from this host"
    );
    let kernel = bundle
        .manifest
        .find_by_role(&ArtifactRole::Kernel)
        .context("local development kernel is missing")?;
    anyhow::ensure!(
        plan.environment
            .as_ref()
            .is_some_and(|environment| environment.kernel_sha256 == kernel.sha256),
        "local development kernel differs from signed plan environment"
    );
    Ok(())
}
