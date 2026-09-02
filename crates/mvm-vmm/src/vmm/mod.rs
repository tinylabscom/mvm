//! Portable, hypervisor-agnostic VMM device model.
//!
//! Guest memory access, the device tree (FDT), arm64 kernel-image loading, and
//! the virtio-mmio devices (PL011 console, block, entropy, vsock) live here with **no
//! hypervisor FFI** — so the same device model is driven by any backend's vCPU
//! run loop: HVF on macOS today, and KVM (Linux) / WHP (Windows) as they land.
//! A backend handles the platform-specific parts (create VM/vCPU, run, decode
//! the exit, raise a device's [`virtio::VirtioBlk::irq`] line its own way) and
//! delegates the MMIO/virtqueue/boot work to these types.
//!
//! This module compiles on every target; it is the "no VMM lock-in" seam.

use virtio_queue::{Queue as SplitQueue, QueueT};

pub(crate) mod agent_bridge;
pub mod device;
pub mod device_state;
pub(crate) mod host_dial_bridge;
// Promoted to the top-level backend-agnostic bridge module; re-exported at the
// old paths so the hvf run loop and cross-crate consumers keep working.
pub use crate::vsock_egress_bridge::egress_gate;
pub(crate) use crate::vsock_egress_bridge::substitution_bridge;
pub mod fdt;
pub mod guest_mem;
pub mod hv;
pub mod kernel_image;
pub mod run;

pub mod virtio;
pub mod virtio_rng;
pub mod vsock;
pub(crate) mod vsock_handlers;
mod vsock_io;
pub(crate) mod vsock_transport;

/// Maximum virtqueue size advertised to the guest via the `QueueNumMax`
/// register, shared by every virtio-mmio device in this module.
///
/// The split-virtqueue layout requires the driver-chosen queue size to be a
/// power of two not exceeding this maximum. See [`validated_queue_size`].
pub(crate) const QUEUE_SIZE_MAX: u32 = 256;

/// Validate a guest-programmed `QueueNum` into a usable ring size, or `None`
/// when the geometry is illegal.
///
/// A guest programs `QueueNum` as a raw 32-bit MMIO register, but the devices
/// index the ring with `slot % size` where `size` is a `u16`. A naive
/// `queue_num as u16` cast truncates, so a value whose low 16 bits are zero —
/// e.g. `0x1_0000` — is nonzero yet becomes `0`, and `slot % 0` divides by zero
/// and aborts the host process in a handful of register writes. Accepting only a
/// power-of-two size within the advertised maximum keeps every conformant guest
/// byte-identical (real ring sizes are always such) while making a zero (or
/// otherwise illegal) ring size unrepresentable in the service paths; an illegal
/// ring is simply left unserviced.
pub(crate) fn validated_queue_size(num: u32) -> Option<u16> {
    if num != 0 && num <= QUEUE_SIZE_MAX && num.is_power_of_two() {
        Some(num as u16)
    } else {
        None
    }
}

/// The guest-programmed split-virtqueue ring state a device hands to
/// [`build_split_queue`]: the three ring base addresses plus the device-owned
/// resume points in the available and used rings.
///
/// Grouped into one type because every virtio-mmio device in this module keeps
/// the same five values (block as flat fields, fs and vsock per queue) and they
/// only ever travel together.
#[derive(Clone, Copy)]
pub(crate) struct RingGeometry {
    pub(crate) desc: u64,
    pub(crate) avail: u64,
    pub(crate) used: u64,
    pub(crate) next_avail: u16,
    pub(crate) next_used: u16,
}

/// Build a validated `virtio-queue` split [`SplitQueue`] from a device's
/// guest-programmed ring geometry, shared by every virtio-mmio device here.
///
/// `qsz` is the already-validated ring size (a power of two ≤ [`QUEUE_SIZE_MAX`]
/// — see [`validated_queue_size`]); `next_avail` and `next_used` resume from the
/// device-owned cursors so both iteration and completion continue exactly where
/// the previous drain stopped. Neither cursor is ever recovered from guest RAM:
/// the used ring is guest-writable, so re-reading `used.idx` would let the guest
/// pick which slot the next completion overwrites.
/// Returns `None` if a ring address breaks virtio's alignment rules —
/// `set_*_address` silently keeps the prior value in that case, so we refuse to
/// service a geometry we could not faithfully program.
pub(crate) fn build_split_queue(ring: RingGeometry, qsz: u16) -> Option<SplitQueue> {
    let mut queue = SplitQueue::new(QUEUE_SIZE_MAX as u16).ok()?;
    queue.set_size(qsz);
    queue.set_ready(true);
    queue.set_desc_table_address(Some(ring.desc as u32), Some((ring.desc >> 32) as u32));
    queue.set_avail_ring_address(Some(ring.avail as u32), Some((ring.avail >> 32) as u32));
    queue.set_used_ring_address(Some(ring.used as u32), Some((ring.used >> 32) as u32));
    queue.set_next_avail(ring.next_avail);
    queue.set_next_used(ring.next_used);
    (queue.desc_table() == ring.desc
        && queue.avail_ring() == ring.avail
        && queue.used_ring() == ring.used)
        .then_some(queue)
}

#[cfg(test)]
mod tests {
    use super::validated_queue_size;

    #[test]
    fn accepts_power_of_two_sizes_within_the_maximum() {
        assert_eq!(validated_queue_size(1), Some(1));
        assert_eq!(validated_queue_size(2), Some(2));
        assert_eq!(validated_queue_size(128), Some(128));
        assert_eq!(validated_queue_size(256), Some(256));
    }

    #[test]
    fn rejects_zero_oversized_and_non_power_of_two_sizes() {
        assert_eq!(validated_queue_size(0), None);
        assert_eq!(validated_queue_size(3), None);
        assert_eq!(validated_queue_size(300), None);
        // A power of two, but above the advertised maximum.
        assert_eq!(validated_queue_size(512), None);
        // Nonzero, but the low 16 bits are zero — the truncation trap.
        assert_eq!(validated_queue_size(0x1_0000), None);
        assert_eq!(validated_queue_size(0xffff_0000), None);
        assert_eq!(validated_queue_size(u32::MAX), None);
    }
}
