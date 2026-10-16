//! Where a boot waits for the admission's audit sync.
//!
//! A launch may start its VMM while the admission's one `fdatasync` round is
//! still in flight, but nothing the plan authorizes may run until that sync
//! has succeeded. Where the wait happens depends on how the guest starts its
//! workload: a guest activated over vsock runs nothing until activation, so it
//! boots beside the sync and waits immediately before activating; a guest
//! without an activation step runs its workload as soon as it boots, so it
//! waits before the VMM starts.

use anyhow::Result;

use super::{ConsoleStreamer, RunningVm, VmStartConfig, vm_state_dir};

/// A guest that is not activated over vsock runs its workload as soon as it
/// boots, so it cannot boot beside the admission's audit sync: the sync must
/// finish before the VMM starts.
pub(super) fn wait_for_unactivated_boot(config: &VmStartConfig) -> Result<()> {
    if !crate::microvm::booted_with_universal_initramfs(config) {
        config.wait_for_admission_durability()?;
    }
    Ok(())
}

/// Activation is what lets workload code run, so it is where a boot that ran
/// beside the admission's audit sync waits for it. A sync that failed means
/// the admission cannot be shown afterwards: the guest is torn down
/// unactivated, having run nothing.
pub(super) fn wait_for_activation(
    config: &VmStartConfig,
    vm: &dyn RunningVm,
    streamer: &dyn ConsoleStreamer,
) -> Result<()> {
    if let Err(error) = config.wait_for_admission_durability() {
        abandon_unactivated(vm, &config.name, streamer);
        return Err(error);
    }
    Ok(())
}

/// The owning caller decides how to report/stop. A failed durability wait must
/// not reap helpers while the original native instance remains unconfirmed.
pub(super) fn wait_for_owned_activation(config: &VmStartConfig) -> Result<()> {
    config.wait_for_admission_durability()
}

/// Tear down a guest that booted but must never be activated.
///
/// Best-effort by necessity — the caller is already failing the launch —
/// but each step is logged rather than dropped, because a VMM left behind
/// here is a booted guest nobody owns.
fn abandon_unactivated(vm: &dyn RunningVm, name: &str, streamer: &dyn ConsoleStreamer) {
    if let Err(error) = vm.kill() {
        tracing::warn!(
            vm = %name,
            error = %format!("{error:#}"),
            "could not stop a guest refused activation"
        );
    }
    mvm_vmm::host::vm_helpers::reap_vm_host_helpers(&vm_state_dir(name), name);
    streamer.stop(name);
}
