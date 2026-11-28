//! One launch's boot shape, resolved without starting a VM.

use anyhow::Result;
use mvm_core::vm_backend::VmStartConfig;
use mvm_runtime::backend::AnyBackend;

use super::TemplateAcceleration;
#[cfg(doc)]
use super::boot_transient_vm;

/// One launch's boot shape, resolved without starting a VM.
///
/// This is the whole of what a launch knows about itself before
/// [`boot_transient_vm`] runs: the backend it resolved against, a
/// [`VmStartConfig`] carrying the rootfs and its verity sidecars, the runtime
/// overlay and universal initramfs, the cmdline-bearing policy fields, and —
/// when the caller supplied an admission hook — the tenant and signed plan.
///
/// Producing one without booting is what lets the warm pool spawn a parent that
/// mirrors a real launch: `pool warm` resolves this, hands it to
/// `warm_to_target`, and the spawn derives the parent's boot shape and the
/// pool's compat key from the same value the launch will later be matched on.
pub struct ResolvedLaunch {
    /// The same one-use host hold returned by admission.
    pub host_budget: Option<std::sync::Arc<mvm_hostd::admission_budget::HostBudgetPermit>>,
    /// The backend the launch resolved against. Selected here rather than by
    /// the caller so a warm spawn and the run it serves cannot disagree about
    /// which backend's capabilities shaped the config.
    pub backend: AnyBackend,
    pub start_config: VmStartConfig,
    /// Exact signed release bytes owned until the lifecycle generation is bound.
    pub verified_runtime: Option<std::sync::Arc<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>>,
    /// Only admission may supply Dev posture for an opted-in mailbox.
    pub mailbox_posture: Option<mvm_hostd::plan_admission::MailboxLaunchPosture>,
    /// Opaque host-prepared owner for the admitted CLI cold alternative.
    pub cli_admission: Option<mvm_client::admission::CliAdmission>,
    /// Why this source cold-boots instead of using template acceleration.
    pub template_acceleration: TemplateAcceleration,
    /// Rootfs strategy the run-path tier gate selected — the value the run path
    /// records as `plan.boot_posture`.
    pub root_strategy: mvm_build::run_image::RootStrategy,
    /// The paused child reserved before admission, whose name this launch was
    /// admitted under.
    pub(crate) preloaded: Option<mvm_client::standby::PreloadedReservation>,
    /// Retained until normal runtime lifecycle binding has taken ownership.
    pub(super) _built_runtime: Option<mvm_hostd::plan_admission::PreparedBuiltPackRuntime>,
}

impl ResolvedLaunch {
    /// Consume a planless resolution into the opaque client warm-parent facade.
    pub(crate) fn into_warm_parent(self) -> Result<mvm_client::standby::PreparedWarmParent> {
        mvm_client::standby::PreparedWarmParent::from_resolved(
            self.backend,
            self.start_config,
            self.verified_runtime,
            self._built_runtime,
        )
    }
}
