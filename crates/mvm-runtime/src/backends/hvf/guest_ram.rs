//! Guest physical RAM backed by a demand-zero anonymous mapping.
//!
//! Pages fault in on first guest access, so host residency follows the guest's
//! working set rather than its allocation. `MAP_ANON` pages are kernel-zeroed on
//! first fault, so the guest never observes stale host memory — the zero-init
//! guarantee the previous `alloc_zeroed` path provided is preserved without
//! touching (and thus resident-ing) every page up front.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::ptr::NonNull;

use super::{BootFault, HvfError};
use zeroize::Zeroize;

/// Apple-silicon hypervisor page size; `hv_vm_map` and `MAP_FIXED` sub-maps
/// must stay aligned to this boundary.
pub(crate) const HVF_PAGE_SIZE: usize = 16 * 1024;

/// An owned demand-zero region sized for guest RAM. `munmap`s on drop, so the
/// three hand-rolled free paths in the boot flow collapse into RAII.
pub struct GuestRam {
    ptr: NonNull<u8>,
    len: usize,
}

impl GuestRam {
    /// Map `len` bytes of demand-zero anonymous memory for use as guest RAM.
    pub fn new(len: usize) -> Result<Self, HvfError> {
        if len == 0 {
            return Err(HvfError::Alloc);
        }
        // SAFETY: null hint + fixed args; MAP_ANON gives a fresh, page-aligned,
        // demand-zero mapping. Never memset it — that would fault every page in
        // and defeat the whole point. Ownership is released via munmap in Drop.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(HvfError::Alloc);
        }
        let ptr = NonNull::new(raw.cast::<u8>()).ok_or(HvfError::Alloc)?;
        Ok(Self { ptr, len })
    }

    /// Base of the mapped region. Guest RAM is written and mapped through raw
    /// pointers, so a shared borrow hands out the mutable base directly.
    pub(crate) fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Length of the mapped region in bytes.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Return the number of resident bytes currently backing this mapping.
    ///
    /// The query is advisory and may change immediately after it returns, but
    /// it provides the measurement witness for demand-faulted guest RAM: an
    /// untouched anonymous region should occupy fewer resident pages than the
    /// same region after selected pages have been written.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub fn resident_bytes(&self) -> Result<usize, std::io::Error> {
        let (page_size, residency) = self.page_residency()?;
        residency
            .iter()
            .filter(|state| **state & 1 != 0)
            .count()
            .checked_mul(page_size)
            .ok_or_else(|| std::io::Error::other("resident byte count overflowed"))
    }

    /// Copy the complete RAM mapping into an owned snapshot section.
    pub fn snapshot_bytes(&self) -> Vec<u8> {
        // SAFETY: the mapping is live for `self`'s lifetime and covers exactly
        // `self.len` readable bytes.
        unsafe { std::slice::from_raw_parts(self.as_ptr().cast_const(), self.len).to_vec() }
    }

    /// Restore a complete RAM section into the existing mapping.
    pub fn restore_bytes(&mut self, bytes: &[u8]) -> Result<(), HvfError> {
        if bytes.len() != self.len {
            return Err(HvfError::SnapshotState("guest RAM length mismatch"));
        }
        // SAFETY: the exact length was checked; `ptr::copy` also permits an
        // overlapping source, so a caller may restore from an in-place view.
        unsafe {
            core::ptr::copy(bytes.as_ptr(), self.as_ptr(), self.len);
        }
        Ok(())
    }

    /// Overwrite resident pages in the mapping before it is released.
    ///
    /// This is intentionally separate from construction: demand-zero
    /// allocation must not fault in every page, while teardown must not leave
    /// guest runtime data in a host mapping that can be reused.
    fn zeroize_mapping(&mut self) {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Ok((page_size, residency)) = self.page_residency() {
            for (index, state) in residency.iter().enumerate() {
                if state & 1 == 0 {
                    continue;
                }
                let offset = index * page_size;
                let len = page_size.min(self.len - offset);
                // SAFETY: `offset` comes from the mapping's page count and
                // `len` is clipped to the exact mapping length.
                unsafe {
                    std::slice::from_raw_parts_mut(self.as_ptr().add(offset), len).zeroize();
                }
            }
        } else {
            self.zeroize_all();
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        self.zeroize_all();

        // Discard clean anonymous and private-COW pages after scrubbing the
        // resident pages. Anonymous pages will be zero-filled if faulted
        // again; private file-backed pages revert to their source file.
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        unsafe {
            let _ = libc::madvise(self.as_ptr().cast(), self.len, libc::MADV_DONTNEED);
        }
    }

    fn zeroize_all(&mut self) {
        // SAFETY: the mapping is live for `self`'s lifetime and covers exactly
        // `self.len` writable bytes. Private file-backed subranges remain
        // private, so scrubbing them cannot modify the snapshot file.
        unsafe {
            std::slice::from_raw_parts_mut(self.as_ptr(), self.len).zeroize();
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn page_residency(&self) -> Result<(usize, Vec<u8>), std::io::Error> {
        let raw_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page_size = usize::try_from(raw_page_size)
            .map_err(|_| std::io::Error::other("system page size is invalid"))?;
        if page_size == 0 {
            return Err(std::io::Error::other("system page size is zero"));
        }
        let page_count = self.len.div_ceil(page_size);
        let mut residency = vec![0_u8; page_count];
        // SAFETY: the mapping is live for `self`'s lifetime, `self.len` is its
        // exact mapped length, and `residency` has one byte per system page.
        let result = unsafe {
            libc::mincore(
                self.ptr.as_ptr().cast(),
                self.len,
                residency.as_mut_ptr().cast(),
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((page_size, residency))
    }

    /// Replace the complete RAM mapping with a private file-backed mapping.
    ///
    /// The file must be exactly the guest RAM size and page-aligned in length.
    /// Guest writes then use the kernel's private COW path, so a restored child
    /// starts from the parent's bytes without modifying the snapshot file.
    pub fn map_private_file(&mut self, path: &Path) -> Result<(), HvfError> {
        let file_len = File::open(path)
            .and_then(|file| file.metadata())
            .map_err(|e| HvfError::BadBoot(BootFault::KernelOpen(e.kind())))?
            .len();
        let file_len =
            usize::try_from(file_len).map_err(|_| HvfError::BadBoot(BootFault::Overflow))?;
        if file_len != self.len || !file_len.is_multiple_of(HVF_PAGE_SIZE) {
            return Err(HvfError::SnapshotState("snapshot RAM file length mismatch"));
        }
        self.map_private_file_at(0, path, file_len)
    }

    /// Copy bytes into the owned guest RAM mapping after checking bounds.
    pub(crate) fn copy_at(&mut self, offset: usize, bytes: &[u8]) -> Result<(), HvfError> {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.len)
        {
            return Err(HvfError::BadBoot(BootFault::KernelTooLarge {
                needed: offset.saturating_add(bytes.len()),
                available: self.len,
            }));
        }
        // SAFETY: destination bounds are checked above, and a borrowed slice
        // cannot overlap this owned mmap reservation.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.ptr.as_ptr().add(offset),
                bytes.len(),
            );
        }
        Ok(())
    }

    /// Replace a page-aligned subrange with a private COW file mapping.
    pub(crate) fn map_private_file_at(
        &mut self,
        offset: usize,
        path: &Path,
        len: usize,
    ) -> Result<(), HvfError> {
        let mapped_len = page_rounded_len(len)?;
        if !offset.is_multiple_of(HVF_PAGE_SIZE) {
            return Err(HvfError::BadBoot(BootFault::Misaligned { offset }));
        }
        if offset
            .checked_add(mapped_len)
            .is_none_or(|end| end > self.len)
        {
            return Err(HvfError::BadBoot(BootFault::KernelTooLarge {
                needed: offset.saturating_add(mapped_len),
                available: self.len,
            }));
        }
        let file =
            File::open(path).map_err(|e| HvfError::BadBoot(BootFault::KernelOpen(e.kind())))?;
        let dst = unsafe { self.ptr.as_ptr().add(offset) };
        // SAFETY: dst is page-aligned inside this owned reservation, and
        // mapped_len is page-rounded. MAP_FIXED intentionally replaces only the
        // kernel subrange; untouched guest RAM remains anonymous demand-zero.
        let mapped = unsafe {
            libc::mmap(
                dst.cast(),
                mapped_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_FIXED,
                file.as_raw_fd(),
                0,
            )
        };
        if mapped == libc::MAP_FAILED || mapped != dst.cast() {
            return Err(HvfError::Alloc);
        }
        Ok(())
    }
}

pub(crate) fn page_rounded_len(len: usize) -> Result<usize, HvfError> {
    if len == 0 {
        return Err(HvfError::BadBoot(BootFault::KernelEmpty));
    }
    len.checked_add(HVF_PAGE_SIZE - 1)
        .map(|n| n / HVF_PAGE_SIZE * HVF_PAGE_SIZE)
        .ok_or(HvfError::BadBoot(BootFault::Overflow))
}

impl Drop for GuestRam {
    fn drop(&mut self) {
        self.zeroize_mapping();
        // SAFETY: ptr/len come from a successful mmap in new() and are unmapped
        // exactly once, here.
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_length() {
        assert!(GuestRam::new(0).is_err());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn allocates_requested_size_page_aligned() {
        let ram = GuestRam::new(HVF_PAGE_SIZE * 4).expect("mmap");
        assert_eq!(ram.len(), HVF_PAGE_SIZE * 4);
        assert!(!ram.as_ptr().is_null());
        assert_eq!(
            ram.as_ptr() as usize % HVF_PAGE_SIZE,
            0,
            "region must be page-aligned"
        );
    }

    #[test]
    fn fresh_region_reads_as_zero() {
        let ram = GuestRam::new(HVF_PAGE_SIZE * 2).expect("mmap");
        // Sample a few offsets across the region; demand-zero guarantees 0.
        for off in [0usize, HVF_PAGE_SIZE, HVF_PAGE_SIZE * 2 - 1] {
            // SAFETY: off is within the mapped [0, len) range.
            let byte = unsafe { *ram.as_ptr().add(off) };
            assert_eq!(byte, 0, "offset {off} not zero-initialized");
        }
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn untouched_pages_are_not_resident_until_touched() {
        let ram = GuestRam::new(HVF_PAGE_SIZE * 8).expect("mmap");
        let before = ram.resident_bytes().expect("mincore before touch");
        for index in 0..4 {
            // SAFETY: each offset is the first byte of one page in the live
            // mapping, and volatile write makes the touch observable.
            unsafe {
                std::ptr::write_volatile(ram.as_ptr().add(index * HVF_PAGE_SIZE), 1);
            }
        }
        let after = ram.resident_bytes().expect("mincore after touch");
        assert!(after > before, "touching pages did not increase residency");
    }

    #[test]
    fn create_and_drop_many_does_not_exhaust_memory() {
        // Exercises the Drop/munmap path: leaking 64 MiB x 200 would OOM.
        for _ in 0..200 {
            let ram = GuestRam::new(64 * 1024 * 1024).expect("mmap");
            // SAFETY: base of a live mapping of at least one page.
            unsafe { *ram.as_ptr() = 1 }; // touch one page
        }
    }

    #[test]
    fn copy_at_checks_bounds() {
        let mut ram = GuestRam::new(HVF_PAGE_SIZE).expect("mmap");
        ram.copy_at(HVF_PAGE_SIZE - 4, b"tail").unwrap();
        assert!(ram.copy_at(HVF_PAGE_SIZE - 3, b"tail").is_err());
    }

    #[test]
    fn snapshot_bytes_roundtrip_mutated_pages() {
        let mut ram = GuestRam::new(HVF_PAGE_SIZE * 2).expect("mmap");
        ram.copy_at(0, b"before").unwrap();
        let snapshot = ram.snapshot_bytes();
        ram.copy_at(0, b"changed").unwrap();
        ram.restore_bytes(&snapshot).unwrap();
        assert_eq!(&ram.snapshot_bytes()[..6], b"before");
    }

    #[test]
    fn zeroize_mapping_clears_guest_runtime_bytes() {
        let mut ram = GuestRam::new(HVF_PAGE_SIZE * 2).expect("mmap");
        ram.copy_at(0, &[0xa5; HVF_PAGE_SIZE * 2]).unwrap();
        ram.zeroize_mapping();
        assert!(ram.snapshot_bytes().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn private_file_mapping_copies_on_guest_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ram.bin");
        let original = vec![0x41_u8; HVF_PAGE_SIZE * 2];
        std::fs::write(&path, &original).unwrap();

        let mut ram = GuestRam::new(original.len()).unwrap();
        ram.map_private_file(&path).unwrap();
        assert_eq!(ram.snapshot_bytes(), original);
        ram.copy_at(0, b"child").unwrap();
        assert_eq!(&ram.snapshot_bytes()[..5], b"child");
        ram.zeroize_mapping();
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn private_file_mapping_rejects_a_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ram.bin");
        std::fs::write(&path, vec![0_u8; HVF_PAGE_SIZE]).unwrap();
        let mut ram = GuestRam::new(HVF_PAGE_SIZE * 2).unwrap();
        assert!(matches!(
            ram.map_private_file(&path),
            Err(HvfError::SnapshotState("snapshot RAM file length mismatch"))
        ));
    }

    #[test]
    fn restore_bytes_rejects_a_different_ram_size() {
        let mut ram = GuestRam::new(HVF_PAGE_SIZE).expect("mmap");
        assert!(matches!(
            ram.restore_bytes(&[0u8; 4]),
            Err(HvfError::SnapshotState("guest RAM length mismatch"))
        ));
    }

    #[test]
    fn file_mapping_is_private_cow() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("Image");
        std::fs::write(&kernel, b"abcdefgh").unwrap();
        let mut ram = GuestRam::new(HVF_PAGE_SIZE * 2).unwrap();

        ram.copy_at(0, b"anon").unwrap();
        ram.map_private_file_at(HVF_PAGE_SIZE, &kernel, 8).unwrap();

        let mapped = unsafe { std::slice::from_raw_parts(ram.as_ptr().add(HVF_PAGE_SIZE), 8) };
        assert_eq!(mapped, b"abcdefgh");

        unsafe {
            *ram.as_ptr().add(HVF_PAGE_SIZE) = b'Z';
        }
        assert_eq!(std::fs::read(&kernel).unwrap(), b"abcdefgh");
        let mapped = unsafe { std::slice::from_raw_parts(ram.as_ptr().add(HVF_PAGE_SIZE), 8) };
        assert_eq!(mapped, b"Zbcdefgh");
    }

    #[test]
    fn file_mapping_rejects_unaligned_or_out_of_bounds_range() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("Image");
        std::fs::write(&kernel, b"abcdefgh").unwrap();
        let mut ram = GuestRam::new(HVF_PAGE_SIZE).unwrap();

        assert!(ram.map_private_file_at(1, &kernel, 8).is_err());
        assert!(ram.map_private_file_at(HVF_PAGE_SIZE, &kernel, 8).is_err());
    }
}
