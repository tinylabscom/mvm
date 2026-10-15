//! Boot admission whose audit sync is left running beside the VMM boot.

use anyhow::Result;

use super::{AdmissionContext, AdmitPlanForBootParams, admit};

/// Where admission blocks on its audit sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AdmissionSync {
    /// Before admission returns: the context it hands back is durable.
    Inline,
    /// Not at all: the sync runs on its own thread and the caller waits for it
    /// before the workload runs.
    BesideBoot,
}

/// [`admit_plan_for_boot`](super::admit_plan_for_boot), with the admission's
/// audit sync left running instead of waited for.
///
/// Every refusal admission can make — image source, entrypoint, grants, host
/// budget, signing, verification, nonce, validity window, bundle posture,
/// policy — has been made, and every audit record written, before this
/// returns. What is still outstanding is the one `fdatasync` round that makes
/// those records survive a power loss. The returned [`AdmissionDurability`]
/// is that round: the caller may start the VMM beside it, and must not let the
/// workload run until it has waited for it successfully. Carrying it on
/// [`VmStartConfig::admission_durability`] is how a boot does that.
///
/// [`AdmissionDurability`]: mvm_core::admission_durability::AdmissionDurability
/// [`VmStartConfig::admission_durability`]: mvm_core::vm_backend::VmStartConfig::admission_durability
pub fn admit_plan_for_boot_syncing_beside_boot(
    p: AdmitPlanForBootParams<'_>,
) -> Result<(
    AdmissionContext,
    mvm_core::admission_durability::AdmissionDurability,
)> {
    let phase = mvm_runtime::ui::activity::start("Signing and admitting the execution plan");
    let admitted = admit(p, Vec::new(), AdmissionSync::BesideBoot)?;
    phase.finish();
    Ok(admitted)
}
