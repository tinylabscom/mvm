//! Guest physical RAM backed by a demand-zero anonymous mapping.
//!
//! Pages fault in on first guest access, so host residency follows the guest's
//! working set rather than its allocation. `MAP_ANON` pages are kernel-zeroed on
//! first fault, so the guest never observes stale host memory — the zero-init
//! guarantee the previous `alloc_zeroed` path provided is preserved without
//! touching (and thus resident-ing) every page up front.

use std::ptr::NonNull;

use super::HvfError;

/// An owned demand-zero region sized for guest RAM. `munmap`s on drop, so the
/// three hand-rolled free paths in the boot flow collapse into RAII.
pub(crate) struct GuestRam {
    ptr: NonNull<u8>,
    len: usize,
}

impl GuestRam {
    /// Map `len` bytes of demand-zero anonymous memory for use as guest RAM.
    pub(crate) fn new(len: usize) -> Result<Self, HvfError> {
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
}

impl Drop for GuestRam {
    fn drop(&mut self) {
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

    const PAGE: usize = 16 * 1024; // Apple-silicon hypervisor page size

    #[test]
    fn rejects_zero_length() {
        assert!(GuestRam::new(0).is_err());
    }

    #[test]
    fn allocates_requested_size_page_aligned() {
        let ram = GuestRam::new(PAGE * 4).expect("mmap");
        assert_eq!(ram.len(), PAGE * 4);
        assert!(!ram.as_ptr().is_null());
        assert_eq!(
            ram.as_ptr() as usize % PAGE,
            0,
            "region must be page-aligned"
        );
    }

    #[test]
    fn fresh_region_reads_as_zero() {
        let ram = GuestRam::new(PAGE * 2).expect("mmap");
        // Sample a few offsets across the region; demand-zero guarantees 0.
        for off in [0usize, PAGE, PAGE * 2 - 1] {
            // SAFETY: off is within the mapped [0, len) range.
            let byte = unsafe { *ram.as_ptr().add(off) };
            assert_eq!(byte, 0, "offset {off} not zero-initialized");
        }
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
}
