//! Producer-owned portable entrypoint preparation on the shared launch pipeline.

use super::{LaunchSource, PreparedEntrypoint, prepare_launch};
use anyhow::{Context, Result};
use mvm_core::vm_backend::VmStartConfig;

/// Prepare a producer-owned portable entrypoint through the shared launch pipeline.
///
/// The source callback must recheck and apply the producer's retained closure.
/// Hostd then verifies that exact release once, admits it once, applies the
/// admission-owned final config changes, and invokes the final-equivalence check.
/// The returned runtime evidence must remain alive through dispatch.
///
/// # Errors
/// Propagates source integrity, runtime verification, admission application, or
/// final-equivalence refusal before backend dispatch.
pub fn prepare_portable_entrypoint<A, B>(
    config: VmStartConfig,
    backend_kind: mvm_core::vm_backend::BackendKind,
    attach: impl FnOnce(
        &mut VmStartConfig,
    ) -> Result<
        std::sync::Arc<mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>,
    >,
    admit: impl FnOnce(
        &mut VmStartConfig,
        &mvm_runtime::runtime_evidence::VerifiedRuntimeSet,
    ) -> Result<A>,
    apply_admission: impl FnOnce(&mut VmStartConfig, A) -> Result<B>,
    verify_final: impl FnOnce(
        &VmStartConfig,
        &mvm_runtime::runtime_evidence::VerifiedRuntimeSet,
        &B,
    ) -> Result<()>,
) -> Result<PreparedEntrypoint<B>> {
    let prepared = prepare_launch(
        LaunchSource::PortableEntrypoint { backend_kind },
        config,
        |config| attach(config).map(Some),
        |config, verified_runtime| {
            let verified_runtime =
                verified_runtime.context("portable entrypoint runtime verification missing")?;
            admit(config, verified_runtime)
        },
    )?;
    let mut config = prepared.config;
    let admission = apply_admission(&mut config, prepared.admission)?;
    let verified_runtime = prepared
        .verified_runtime
        .as_deref()
        .context("portable entrypoint retained runtime verification missing")?;
    verify_final(&config, verified_runtime, &admission)?;
    Ok(PreparedEntrypoint {
        config,
        verified_runtime: prepared.verified_runtime,
        admission,
    })
}
