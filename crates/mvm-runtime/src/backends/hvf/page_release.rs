//! HVF side of the free page reporting balloon: take a span out of the guest's
//! memory map, give its host pages back, and put it back.
//!
//! The span has to leave the guest's map first. Hypervisor.framework holds
//! every page it has mapped into a guest, so releasing a mapped page returns
//! nothing to the host.

use mvm_vmm::vmm::virtio_balloon::{GuestPageRelease, GuestSpan, PageReleaseError, RamRegion};

use super::guest_ram::HVF_PAGE_SIZE;
use super::sys::{HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE, HV_SUCCESS};
use super::sys::{hv_vm_map, hv_vm_unmap};

/// Returns spans of one contiguous guest RAM mapping to the host.
pub(crate) struct HvfPageRelease {
    host: *mut u8,
    gpa_base: u64,
    len: u64,
    regions: Vec<RamRegion>,
}

impl HvfPageRelease {
    /// # Safety
    ///
    /// `host` must be the start of `len` bytes of host memory that are mapped
    /// into the current VM at `gpa_base` with read, write and execute
    /// permission, and must stay mapped for this value's lifetime. `regions`
    /// must describe how that memory is backed.
    pub(crate) unsafe fn new(
        host: *mut u8,
        gpa_base: u64,
        len: usize,
        regions: Vec<RamRegion>,
    ) -> Self {
        Self {
            host,
            gpa_base,
            len: len as u64,
            regions,
        }
    }

    /// Host address of `span`, if it is granule-aligned and inside guest RAM.
    ///
    /// The device only passes spans it has already cut to RAM and aligned; this
    /// is the second check, because a wrong address here unmaps or discards
    /// memory the guest still uses.
    fn host_span(&self, span: GuestSpan) -> Result<*mut u8, PageReleaseError> {
        let granule = HVF_PAGE_SIZE as u64;
        let offset = span
            .gpa
            .checked_sub(self.gpa_base)
            .filter(|offset| {
                span.len != 0
                    && offset.is_multiple_of(granule)
                    && span.len.is_multiple_of(granule)
                    && offset
                        .checked_add(span.len)
                        .is_some_and(|end| end <= self.len)
            })
            .ok_or(PageReleaseError {
                code: i64::from(libc::EINVAL),
            })?;
        // SAFETY: `offset + span.len <= self.len`, so the result stays inside
        // the mapping `new` was given.
        Ok(unsafe { self.host.add(offset as usize) })
    }
}

impl GuestPageRelease for HvfPageRelease {
    fn granule(&self) -> u64 {
        HVF_PAGE_SIZE as u64
    }

    fn regions(&self) -> &[RamRegion] {
        &self.regions
    }

    fn resident(&self, span: GuestSpan) -> bool {
        self.host_span(span)
            .map_or(true, |host| any_page_resident(host, span.len as usize))
    }

    fn unmap(&mut self, span: GuestSpan) -> Result<(), PageReleaseError> {
        self.host_span(span)?;
        // SAFETY: FFI; the span lies inside the RAM mapping this VM holds.
        let rc = unsafe { hv_vm_unmap(span.gpa, span.len as usize) };
        hv_result(rc)
    }

    fn release(&mut self, span: GuestSpan) -> Result<(), PageReleaseError> {
        let host = self.host_span(span)?;
        release_host_pages(host, span.len as usize)
    }

    fn remap(&mut self, span: GuestSpan) -> Result<(), PageReleaseError> {
        let host = self.host_span(span)?;
        let flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
        // SAFETY: FFI; `host` addresses the same live host memory the span was
        // mapped from at boot, with the same permissions.
        let rc = unsafe { hv_vm_map(host.cast(), span.gpa, span.len as usize, flags) };
        hv_result(rc)
    }
}

/// Whether any page of `len` bytes at `host` is resident. Answers `true` when
/// residency cannot be read, so a failed query costs a release rather than
/// skipping one.
fn any_page_resident(host: *mut u8, len: usize) -> bool {
    // SAFETY: `sysconf` has no preconditions.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(0);
    if page == 0 {
        return true;
    }
    let mut residency = vec![0_u8; len.div_ceil(page)];
    // SAFETY: the range lies inside the live guest RAM mapping and
    // `residency` holds one byte per page of it.
    let rc = unsafe { libc::mincore(host.cast(), len, residency.as_mut_ptr().cast()) };
    rc != 0 || residency.iter().any(|state| state & 1 != 0)
}

fn hv_result(rc: i32) -> Result<(), PageReleaseError> {
    if rc == HV_SUCCESS {
        Ok(())
    } else {
        Err(PageReleaseError {
            code: i64::from(rc),
        })
    }
}

/// Give the host pages behind `len` bytes at `host` back to the operating
/// system by mapping fresh demand-zero memory over them.
///
/// Replacing the mapping frees the old pages at once, and the fresh pages are
/// charged to the process again as the guest touches them. Marking the pages
/// reusable (`MADV_FREE_REUSABLE`) was measured and rejected: it drops the
/// physical footprint immediately, but pages the guest later writes again are
/// never charged back, so a guest that refilled the memory it had freed
/// showed about 1.1 GiB less footprint than it was using — the process's
/// memory accounting would lie in the direction that hides pressure.
///
/// The guest reads zeros from the span afterwards. Free page reporting does
/// not promise the guest anything about a reported page's contents.
pub(crate) fn release_host_pages(host: *mut u8, len: usize) -> Result<(), PageReleaseError> {
    // SAFETY: callers pass a page-aligned range inside a live anonymous
    // mapping this process owns and that nothing maps into the guest right
    // now. `MAP_FIXED` replaces exactly that range; the owner's `munmap` of
    // the whole reservation still covers it.
    let mapped = unsafe {
        libc::mmap(
            host.cast(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    if mapped == host.cast() {
        Ok(())
    } else {
        Err(PageReleaseError {
            code: i64::from(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)),
        })
    }
}

#[cfg(test)]
mod tests {
    use mvm_vmm::vmm::virtio_balloon::RamBacking;

    use super::super::guest_ram::GuestRam;
    use super::*;

    const GPA: u64 = 0x8000_0000;

    fn releaser(ram: &GuestRam) -> HvfPageRelease {
        // SAFETY: nothing here calls into HVF; only `host_span` and the host
        // release are exercised, both against the live `ram` mapping.
        unsafe {
            HvfPageRelease::new(
                ram.as_ptr(),
                GPA,
                ram.len(),
                vec![RamRegion {
                    span: GuestSpan {
                        gpa: GPA,
                        len: ram.len() as u64,
                    },
                    backing: RamBacking::Anonymous,
                }],
            )
        }
    }

    #[test]
    fn host_span_accepts_only_aligned_spans_inside_ram() {
        let ram = GuestRam::new(HVF_PAGE_SIZE * 4).unwrap();
        let pages = releaser(&ram);
        let page = HVF_PAGE_SIZE as u64;
        let at = |gpa, len| pages.host_span(GuestSpan { gpa, len });

        assert_eq!(at(GPA, page).unwrap(), ram.as_ptr());
        assert_eq!(
            at(GPA + 3 * page, page).unwrap(),
            ram.as_ptr().wrapping_add(3 * HVF_PAGE_SIZE)
        );
        assert!(at(GPA - page, page).is_err(), "below RAM");
        assert!(at(GPA + 3 * page, 2 * page).is_err(), "runs past RAM");
        assert!(at(GPA + 1, page).is_err(), "misaligned start");
        assert!(at(GPA, page - 1).is_err(), "misaligned length");
        assert!(at(GPA, 0).is_err(), "empty");
        assert!(at(u64::MAX - page + 1, page).is_err(), "wraps");
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn residency_tracks_whether_the_guest_touched_the_span() {
        let mut ram = GuestRam::new(HVF_PAGE_SIZE * 4).unwrap();
        let pages = releaser(&ram);
        let first = GuestSpan {
            gpa: GPA,
            len: HVF_PAGE_SIZE as u64,
        };
        let rest = GuestSpan {
            gpa: GPA + HVF_PAGE_SIZE as u64,
            len: 3 * HVF_PAGE_SIZE as u64,
        };
        assert!(!pages.resident(first), "fresh anonymous memory");
        ram.copy_at(0, b"touched").unwrap();
        assert!(pages.resident(first));
        assert!(!pages.resident(rest));
    }

    #[test]
    fn release_refuses_a_span_outside_ram_before_touching_memory() {
        let ram = GuestRam::new(HVF_PAGE_SIZE).unwrap();
        let mut pages = releaser(&ram);
        let outside = GuestSpan {
            gpa: GPA + HVF_PAGE_SIZE as u64,
            len: HVF_PAGE_SIZE as u64,
        };
        assert!(pages.release(outside).is_err());
        assert!(pages.unmap(outside).is_err());
        assert!(pages.remap(outside).is_err());
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn a_released_span_drops_its_pages_and_leaves_its_neighbours() {
        let mut ram = GuestRam::new(HVF_PAGE_SIZE * 4).unwrap();
        ram.copy_at(0, &vec![0xa5; HVF_PAGE_SIZE * 4]).unwrap();
        let resident_before = ram.resident_bytes().unwrap();

        let mut pages = releaser(&ram);
        pages
            .release(GuestSpan {
                gpa: GPA + HVF_PAGE_SIZE as u64,
                len: 2 * HVF_PAGE_SIZE as u64,
            })
            .unwrap();

        let bytes = ram.snapshot_bytes();
        assert!(bytes[..HVF_PAGE_SIZE].iter().all(|b| *b == 0xa5));
        assert!(
            bytes[HVF_PAGE_SIZE..3 * HVF_PAGE_SIZE]
                .iter()
                .all(|b| *b == 0),
            "the released span reads as fresh memory"
        );
        assert!(bytes[3 * HVF_PAGE_SIZE..].iter().all(|b| *b == 0xa5));
        // Reading the released span faulted zero pages back in, so measure
        // residency on a fresh release instead of after the read.
        pages
            .release(GuestSpan {
                gpa: GPA,
                len: 4 * HVF_PAGE_SIZE as u64,
            })
            .unwrap();
        assert!(ram.resident_bytes().unwrap() < resident_before);

        // Still ordinary writable memory afterwards.
        ram.copy_at(HVF_PAGE_SIZE, b"after").unwrap();
        assert_eq!(
            &ram.snapshot_bytes()[HVF_PAGE_SIZE..HVF_PAGE_SIZE + 5],
            b"after"
        );
    }
}
