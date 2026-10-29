//! One attempt to publish a paused machine's snapshot.
//!
//! Every failure is a `String` for the host, not an error for the run loop:
//! see `mvm_vmm::host::snapshot_publish` for why a refusal must not end the
//! machine.

use std::path::Path;

use super::guest_ram::GuestRam;
use super::hv_impl::HvfVcpu;
use super::snapshot::{
    HVF_SNAPSHOT_BACKEND_KIND, HvfVcpuState, capture_gic_device_state, encode_hvf_snapshot_frame,
    write_ram_image,
};
use crate::vmm::device_state::{SnapshotDeviceState, capture_device_states};

pub(super) struct SnapshotAttempt<'a> {
    pub vcpu: &'a HvfVcpu,
    pub devices: &'a [&'a dyn SnapshotDeviceState],
    /// Every CPU beyond the boot CPU, already parked, in CPU order.
    pub secondary_states: Vec<HvfVcpuState>,
    pub runtime_observer: Option<&'a mvm_vmm::runtime_artifacts::Observer>,
    pub guest_ram: &'a GuestRam,
    pub request: &'a Path,
    pub ram: &'a Path,
    pub frame: &'a Path,
}

impl SnapshotAttempt<'_> {
    /// The cheap, state-dependent captures come first: a device can refuse
    /// while host I/O is still draining, and a refusal must not cost a
    /// half-gigabyte RAM write per retry. RAM then goes whole, and the frame
    /// is renamed into place: the host takes the frame's appearance as the
    /// signal that both files are complete, so neither may be visible
    /// half-written.
    pub fn publish(self) -> Result<(), String> {
        let devices = capture_device_states(self.devices)
            .map_err(|error| format!("device state: {error}"))?;
        let gic = capture_gic_device_state().map_err(|error| format!("GIC state: {error:?}"))?;
        // Boot CPU first, then the rest in CPU order — the order a restore
        // hands them back out in.
        let mut vcpus = vec![
            self.vcpu
                .capture_state()
                .map_err(|error| format!("boot CPU state: {error:?}"))?,
        ];
        vcpus.extend(self.secondary_states);
        let artifacts = self
            .runtime_observer
            .map(|observer| observer.snapshot_payload())
            .transpose()
            .map_err(|error| format!("runtime evidence: {error}"))?
            .unwrap_or_default();
        let layout = write_ram_image(self.guest_ram, self.ram)
            .map_err(|error| format!("RAM image: {error}"))?;
        let frame = encode_hvf_snapshot_frame(
            HVF_SNAPSHOT_BACKEND_KIND,
            0,
            layout,
            &devices,
            &gic,
            &vcpus,
            &artifacts,
        )
        .map_err(|error| format!("frame encode: {error:?}"))?;
        mvm_core::util::atomic_io::atomic_write(self.frame, &frame)
            .map_err(|error| format!("frame write: {error}"))?;
        std::fs::remove_file(self.request).map_err(|error| format!("request cleanup: {error}"))
    }
}
