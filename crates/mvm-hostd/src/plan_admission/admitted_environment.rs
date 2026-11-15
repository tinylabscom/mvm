//! The kernel a plan pins, checked against the one a launch config supplies.

use anyhow::{Context, Result};
use mvm_core::plan::ExecutionPlan;

/// Refuse a boot whose kernel is not the one the plan pinned.
///
/// The image digest says what the workload *is*; it says nothing about what
/// confines it. The same signed image on a kernel built for a different job has
/// a different security posture — a kernel with `CONFIG_USER_NS` enabled lets
/// the guest become uid 0 in a user namespace, which the workload kernel is
/// built to prevent. Before the kernel was pinned, that substitution was
/// invisible: identical plan, identical image digest, and confinement decided
/// by whichever kernel the host happened to have cached.
///
/// Fail-closed in both directions. A plan that pins a kernel and a launch
/// config that supplies none is a refusal, not a pass — otherwise dropping the
/// kernel path would be a way to skip the check.
/// Takes the kernel path rather than the whole [`VmStartConfig`] so the two
/// admission seams can share one gate. `mvmctl` synthesizes and admits its plan
/// without ever building a `VmStartConfig`, so a config-shaped signature meant
/// the CLI — the seam that ships — could not call this at all.
pub fn enforce_admitted_environment(
    kernel_path: Option<&std::path::Path>,
    plan: &ExecutionPlan,
) -> Result<()> {
    let Some(environment) = plan.environment.as_ref() else {
        // No environment pinned. Plans predating the field, and backends that
        // boot their own bundled kernel, land here.
        return Ok(());
    };
    let Some(kernel_path) = kernel_path else {
        anyhow::bail!(
            "plan pins kernel {} but the launch config supplies no kernel path",
            environment.kernel_sha256
        );
    };
    let actual =
        mvm_core::crypto::image_verify::sha256_file_cached(kernel_path).with_context(|| {
            format!(
                "hashing kernel at {} for admitted-environment check",
                kernel_path.display()
            )
        })?;
    if actual != environment.kernel_sha256 {
        anyhow::bail!(
            "admitted-environment mismatch: plan pins kernel {} but {} hashes to {actual}",
            environment.kernel_sha256,
            kernel_path.display()
        );
    }
    Ok(())
}
