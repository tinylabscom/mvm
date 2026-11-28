//! Where a boot waits for the admission's audit sync.
//!
//! A launch may start its VMM while the admission's one `fdatasync` round is
//! still in flight, and while its lifecycle lease and runtime generation are
//! being synced, but nothing the plan authorizes may run until both have
//! succeeded. Where the wait happens depends on how the guest starts its
//! workload: a guest activated over vsock runs nothing until activation, so it
//! boots beside the syncs and waits immediately before activating; a guest
//! without an activation step runs its workload as soon as it boots, so it
//! waits before the VMM starts.

use anyhow::Result;

use super::{ConsoleStreamer, RunningVm, VmStartConfig, vm_state_dir};
use crate::runtime_evidence::UnsyncedBind;

/// A guest that is not activated over vsock runs its workload as soon as it
/// boots, so it cannot boot beside the admission's audit sync or the bind's
/// syncs: both must finish before the VMM starts. Returns what is left to
/// sync beside the boot.
pub(super) fn wait_for_unactivated_boot(
    config: &VmStartConfig,
    unsynced: UnsyncedBind,
) -> Result<UnsyncedBind> {
    if crate::microvm::booted_with_universal_initramfs(config) {
        return Ok(unsynced);
    }
    config.wait_for_admission_durability()?;
    unsynced.sync_before_spawn()?;
    Ok(UnsyncedBind::default())
}

/// Activation is what lets workload code run, so it is where a boot that ran
/// beside the bind's syncs (`synced`) and the admission's audit sync waits
/// for them. A sync that failed means the launch's records cannot be shown
/// afterwards: the guest is torn down unactivated, having run nothing.
pub(super) fn wait_for_activation(
    config: &VmStartConfig,
    synced: Result<()>,
    vm: &dyn RunningVm,
    streamer: &dyn ConsoleStreamer,
) -> Result<()> {
    if let Err(error) = synced.and_then(|()| config.wait_for_admission_durability()) {
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
