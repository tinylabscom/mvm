//! Where each virtio-mmio device sits in guest-physical space, and its SPI.
//!
//! Every address here is baked into the device tree a guest boots against and
//! into the layout a saved snapshot was captured under, so moving one is a
//! compatibility change, not a tidy-up.

/// virtio-mmio device windows (above the GIC, below RAM) + their SPIs.
pub(super) const VIRTIO_MMIO_BASE: u64 = 0x0a00_0000;
pub(super) const VIRTIO_IRQ: u32 = 48;
pub(super) const VSOCK_MMIO_BASE: u64 = 0x0a00_0200;
pub(super) const VSOCK_IRQ: u32 = 49;
/// The first window where the deleted virtio-fs device used to live, above the
/// original six-disk band and vsock.
///
/// The HVF virtio-fs device is gone, so block devices may occupy this former
/// root-plus-share band. The constants stay because `RNG_MMIO_BASE` and
/// `RNG_IRQ` are computed *from* them: collapsing the band would silently move
/// the entropy device to a different address and SPI, changing both the device
/// tree a guest boots against and the layout a saved snapshot was captured
/// under.
pub(super) const FS_MMIO_BASE: u64 = VIRTIO_MMIO_BASE + 7 * MMIO_STRIDE;
pub(super) const FS_IRQ: u32 = 55;
/// Width of the former virtio-fs share band, retained to derive the stable
/// address and SPI that follow it.
pub(super) const MAX_VIRTIOFS_SHARES: usize = 8;
/// The entropy device keeps its address after the original
/// disk/vsock/virtio-fs layout, so its stable window cannot collide with a
/// device combination selected at runtime. Derived from the former band rather
/// than restated, so the fact that the entropy device sits *past* it is
/// expressed once. Same address as before: `VIRTIO_MMIO_BASE + 7*stride` +
/// `8*stride` + one slot = `base + 16*stride`.
pub(super) const RNG_MMIO_BASE: u64 = FS_MMIO_BASE + (MAX_VIRTIOFS_SHARES as u64 + 1) * MMIO_STRIDE;
pub(super) const RNG_IRQ: u32 = FS_IRQ + MAX_VIRTIOFS_SHARES as u32 + 1;
/// The free page reporting balloon takes the slot and SPI after the entropy
/// device, so adding it moved no existing device.
pub(super) const BALLOON_MMIO_BASE: u64 = RNG_MMIO_BASE + MMIO_STRIDE;
pub(super) const BALLOON_IRQ: u32 = RNG_IRQ + 1;
/// virtio-mmio window stride; each device occupies one 0x200 slot.
pub(super) const MMIO_STRIDE: u64 = 0x200;
/// Max virtio-blk devices (`/dev/vda`..). Six slots preceded the former
/// virtio-fs band; reclaiming its root slot plus eight share slots admits nine
/// more without moving the entropy device or any later snapshot-visible
/// address.
pub(super) const MAX_DISKS: usize = 6 + MAX_VIRTIOFS_SHARES + 1;

/// MMIO base + SPI for virtio-blk device `i` (`/dev/vda` = 0). Disk 0 keeps the
/// original single-disk window; disks 1+ sit *above* the vsock slot, so vsock's
/// address/IRQ stay fixed and the live-verified agent/egress path is untouched.
pub(super) fn disk_mmio(i: usize) -> (u64, u32) {
    if i == 0 {
        (VIRTIO_MMIO_BASE, VIRTIO_IRQ)
    } else {
        (
            VIRTIO_MMIO_BASE + (i as u64 + 1) * MMIO_STRIDE,
            VIRTIO_IRQ + i as u32 + 1,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balloon_slot_follows_the_entropy_device_without_overlap() {
        assert_eq!(BALLOON_MMIO_BASE, RNG_MMIO_BASE + MMIO_STRIDE);
        assert_eq!(BALLOON_IRQ, RNG_IRQ + 1);
        let mut windows: Vec<(u64, u32)> = (0..MAX_DISKS).map(disk_mmio).collect();
        windows.push((VSOCK_MMIO_BASE, VSOCK_IRQ));
        windows.push((RNG_MMIO_BASE, RNG_IRQ));
        for (base, irq) in windows {
            assert!(
                base + MMIO_STRIDE <= BALLOON_MMIO_BASE || base >= BALLOON_MMIO_BASE + MMIO_STRIDE,
                "window at {base:#x} overlaps the balloon"
            );
            assert_ne!(irq, BALLOON_IRQ);
        }
        // Device windows sit below RAM.
        const { assert!(BALLOON_MMIO_BASE + MMIO_STRIDE <= super::super::kernel_boot::RAM_BASE) };
    }

    #[test]
    fn disk_slots_reclaim_the_old_virtiofs_band_and_stop_before_entropy() {
        let (last_mmio, _) = disk_mmio(MAX_DISKS - 1);
        assert!(
            last_mmio + MMIO_STRIDE <= RNG_MMIO_BASE,
            "last disk must fit below the entropy device"
        );
        assert!(
            last_mmio >= FS_MMIO_BASE,
            "former virtio-fs slots are reused"
        );

        let (next_mmio, _) = disk_mmio(MAX_DISKS);
        assert_eq!(
            next_mmio, RNG_MMIO_BASE,
            "one more disk would collide with the entropy device"
        );
    }
}
