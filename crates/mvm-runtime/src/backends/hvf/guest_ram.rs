//! Guest physical RAM backed by a demand-zero anonymous mapping.
//!
//! Pages fault in on first guest access, so host residency follows the guest's
//! working set rather than its allocation. `MAP_ANON` pages are kernel-zeroed on
//! first fault, so the guest never observes stale host memory — the zero-init
//! guarantee the previous `alloc_zeroed` path provided is preserved without
//! touching (and thus resident-ing) every page up front.
//!
//! Parts of the reservation can instead be private copy-on-write mappings of a
//! file: the kernel image on a cold boot, and the whole of RAM on a restore.
//! Those ranges are recorded, because free-page reporting and teardown both
//! have to treat them differently: discarding a clean page of a private file
//! mapping makes it read back as the file's bytes, not as zeros, and zeroing
//! one copies it first.

use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::ptr::NonNull;

use super::snapshot::RamLayout;
use super::{BootFault, HvfError};
use mvm_vmm::vmm::virtio_balloon::{GuestSpan, RamBacking, RamRegion};
use std::ops::Range;
use zeroize::Zeroize;

/// Apple-silicon hypervisor page size; `hv_vm_map` and `MAP_FIXED` sub-maps
/// must stay aligned to this boundary.
pub(crate) const HVF_PAGE_SIZE: usize = 16 * 1024;

/// Chunk size [`GuestRam::write_to`] hands the writer, so a capture never
/// holds more than this much of guest memory outside the mapping.
const WRITE_CHUNK: usize = 8 * 1024 * 1024;

/// An owned demand-zero region sized for guest RAM. `munmap`s on drop, so the
/// three hand-rolled free paths in the boot flow collapse into RAII.
pub struct GuestRam {
    ptr: NonNull<u8>,
    len: usize,
    /// Byte ranges replaced by a private file mapping, in mapping order.
    file_backed: Vec<Range<usize>>,
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
        Ok(Self {
            ptr,
            len,
            file_backed: Vec::new(),
        })
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

    /// Guest RAM at `gpa_base`, split by how each part is backed on the host.
    pub(crate) fn backing_regions(&self, gpa_base: u64) -> Vec<RamRegion> {
        backing_layout(self.len, &self.file_backed)
            .into_iter()
            .map(|(range, backing)| RamRegion {
                span: GuestSpan {
                    gpa: gpa_base + range.start as u64,
                    len: (range.end - range.start) as u64,
                },
                backing,
            })
            .collect()
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

    /// Copy the complete RAM mapping into an owned buffer.
    #[cfg(test)]
    pub fn snapshot_bytes(&self) -> Vec<u8> {
        // SAFETY: the mapping is live for `self`'s lifetime and covers exactly
        // `self.len` readable bytes.
        unsafe { std::slice::from_raw_parts(self.as_ptr().cast_const(), self.len).to_vec() }
    }

    /// Write the current contents of guest RAM to `out`, in bounded chunks.
    ///
    /// Reads the mapping, so a page the guest wrote after being restored from a
    /// file is captured as the guest's bytes, not the file's. The caller must
    /// hold every vCPU out of the guest for the duration, as for any capture.
    pub fn write_to(&self, out: &mut impl Write) -> std::io::Result<()> {
        let mut offset = 0;
        while offset < self.len {
            let len = WRITE_CHUNK.min(self.len - offset);
            // SAFETY: `offset + len <= self.len`, and the mapping is live and
            // readable for `self`'s lifetime.
            let chunk = unsafe { std::slice::from_raw_parts(self.as_ptr().add(offset), len) };
            out.write_all(chunk)?;
            offset += len;
        }
        Ok(())
    }

    /// Map guest RAM copy-on-write from a restore image.
    ///
    /// `file` must be the verified private copy the restore was handed; the
    /// range `layout` names must cover the whole reservation and fit inside the
    /// file. The mapping has to exist before the reservation is registered with
    /// the hypervisor, which registers whatever backs the range at that time.
    pub fn map_snapshot_ram(&mut self, file: &File, layout: RamLayout) -> Result<(), HvfError> {
        if layout.len != self.len as u64 {
            return Err(HvfError::SnapshotState("snapshot RAM length mismatch"));
        }
        let end = layout
            .file_end()
            .map_err(|_| HvfError::SnapshotState("snapshot RAM range overflows"))?;
        let file_len = file
            .metadata()
            .map_err(|_| HvfError::SnapshotState("snapshot RAM file stat failed"))?
            .len();
        if file_len < end {
            return Err(HvfError::SnapshotState("snapshot RAM file is too short"));
        }
        self.map_private_fd_at(0, file, layout.file_offset, self.len)
    }

    /// Overwrite resident pages in the mapping before it is released.
    ///
    /// This is intentionally separate from construction: demand-zero
    /// allocation must not fault in every page, while teardown must not leave
    /// guest runtime data in a host mapping that can be reused.
    fn zeroize_mapping(&mut self) {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if !self.scrub_resident() {
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

    /// Zero every resident page that can hold guest data this process owns.
    ///
    /// Returns `false` when residency cannot be read, so the caller falls back
    /// to scrubbing everything.
    ///
    /// A clean page of a private file mapping is not scrubbed. It is the page
    /// cache's copy of bytes that are already on disk in the saved image, so
    /// overwriting it buys no secrecy — and writing to it would make the kernel
    /// copy it first, so scrubbing every clean page of a restored guest's RAM
    /// would allocate a second copy of the whole image just to zero it.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn scrub_resident(&mut self) -> bool {
        let Ok((page_size, residency)) = self.page_residency() else {
            return false;
        };
        let file_runs: Vec<_> = backing_layout(self.len, &self.file_backed)
            .into_iter()
            .filter(|(_, backing)| *backing == RamBacking::PrivateFile)
            .map(|(range, _)| range)
            .collect();
        for (index, state) in residency.iter().enumerate() {
            let offset = index * page_size;
            let len = page_size.min(self.len - offset);
            let file_backed = file_runs
                .iter()
                .any(|run| run.start <= offset && offset + len <= run.end);
            if !page_needs_scrub(*state, file_backed) {
                continue;
            }
            // SAFETY: `offset` comes from the mapping's page count and
            // `len` is clipped to the exact mapping length.
            unsafe {
                std::slice::from_raw_parts_mut(self.as_ptr().add(offset), len).zeroize();
            }
        }
        true
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
        let page_size = host_page_size()?;
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
        let file =
            File::open(path).map_err(|e| HvfError::BadBoot(BootFault::KernelOpen(e.kind())))?;
        self.map_private_fd_at(offset, &file, 0, len)
    }

    /// Replace `len` bytes at `offset` with a private COW mapping of `file`
    /// starting at `file_offset`.
    fn map_private_fd_at(
        &mut self,
        offset: usize,
        file: &File,
        file_offset: u64,
        len: usize,
    ) -> Result<(), HvfError> {
        let mapped_len = page_rounded_len(len)?;
        if !offset.is_multiple_of(HVF_PAGE_SIZE) {
            return Err(HvfError::BadBoot(BootFault::Misaligned { offset }));
        }
        if !file_offset.is_multiple_of(file_mapping_granule()? as u64) {
            return Err(HvfError::SnapshotState("file offset is not page-aligned"));
        }
        let file_offset = libc::off_t::try_from(file_offset)
            .map_err(|_| HvfError::BadBoot(BootFault::Overflow))?;
        if offset
            .checked_add(mapped_len)
            .is_none_or(|end| end > self.len)
        {
            return Err(HvfError::BadBoot(BootFault::KernelTooLarge {
                needed: offset.saturating_add(mapped_len),
                available: self.len,
            }));
        }
        // SAFETY: `offset + mapped_len <= self.len` was checked above, so the
        // pointer stays inside this owned reservation.
        let dst = unsafe { self.ptr.as_ptr().add(offset) };
        // SAFETY: `dst` is page-aligned inside this owned reservation, and
        // `mapped_len` is page-rounded and in bounds. MAP_FIXED replaces only
        // that subrange; the rest of guest RAM keeps its current backing. The
        // mapping is private, so guest writes never reach the file.
        let mapped = unsafe {
            libc::mmap(
                dst.cast(),
                mapped_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_FIXED,
                file.as_raw_fd(),
                file_offset,
            )
        };
        if mapped == libc::MAP_FAILED || mapped != dst.cast() {
            return Err(HvfError::Alloc);
        }
        self.file_backed.push(offset..offset + mapped_len);
        Ok(())
    }
}

/// `mincore` reports the page resident.
const MINCORE_INCORE: u8 = 0x1;
/// XNU `mincore`: this mapping holds its own copy of the page (a private
/// mapping's copy-on-write happened). Not exported by the `libc` crate.
#[cfg(target_os = "macos")]
const MINCORE_COPIED: u8 = 0x40;
/// XNU `mincore`: the page is anonymous memory. Not exported by `libc`.
#[cfg(target_os = "macos")]
const MINCORE_ANONYMOUS: u8 = 0x80;

/// Whether teardown has to zero a page with residency `state`.
///
/// Every resident anonymous page is scrubbed. A resident page of a private
/// file mapping is scrubbed only when this process holds its own copy of it —
/// the guest wrote it — because an unwritten one is the page cache's shared
/// copy of the saved image. Only XNU reports that distinction; elsewhere every
/// resident file-backed page is scrubbed, which is the safe answer.
fn page_needs_scrub(state: u8, file_backed: bool) -> bool {
    if state & MINCORE_INCORE == 0 {
        return false;
    }
    if !file_backed {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        state & (MINCORE_COPIED | MINCORE_ANONYMOUS) != 0
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}

/// The host's page size, which `mmap` requires every file offset to be a
/// multiple of: 16 KiB on Apple silicon, 4 KiB on most other hosts.
fn host_page_size() -> Result<usize, std::io::Error> {
    // SAFETY: `sysconf` has no preconditions; a negative result is an error.
    let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    match usize::try_from(raw) {
        Ok(0) => Err(std::io::Error::other("system page size is zero")),
        Ok(size) => Ok(size),
        Err(_) => Err(std::io::Error::other("system page size is invalid")),
    }
}

/// The alignment a file range must have to be mapped as guest RAM.
///
/// It is the hypervisor page, which the host page has to divide: a range
/// aligned to the hypervisor page is then aligned for `mmap` as well. A host
/// whose pages are larger than the hypervisor's cannot map a snapshot at all,
/// and is refused rather than handed a mapping that splits a host page.
pub(crate) fn file_mapping_granule() -> Result<usize, HvfError> {
    let host =
        host_page_size().map_err(|_| HvfError::SnapshotState("host page size is unavailable"))?;
    if !HVF_PAGE_SIZE.is_multiple_of(host) {
        return Err(HvfError::SnapshotState(
            "host page size does not divide the hypervisor page size",
        ));
    }
    Ok(HVF_PAGE_SIZE)
}

/// Split `0..len` into maximal runs of one backing, given the byte ranges that
/// were replaced by private file mappings (possibly overlapping, in any order).
fn backing_layout(len: usize, file_backed: &[Range<usize>]) -> Vec<(Range<usize>, RamBacking)> {
    let mut files: Vec<Range<usize>> = file_backed
        .iter()
        .map(|range| range.start.min(len)..range.end.min(len))
        .filter(|range| range.start < range.end)
        .collect();
    files.sort_by_key(|range| range.start);
    let mut layout: Vec<(Range<usize>, RamBacking)> = Vec::new();
    let mut cursor = 0;
    for file in files {
        if file.start > cursor {
            layout.push((cursor..file.start, RamBacking::Anonymous));
        }
        let start = file.start.max(cursor);
        if file.end > start {
            match layout.last_mut() {
                Some((last, RamBacking::PrivateFile)) if last.end == start => last.end = file.end,
                _ => layout.push((start..file.end, RamBacking::PrivateFile)),
            }
            cursor = file.end;
        }
    }
    if cursor < len {
        layout.push((cursor..len, RamBacking::Anonymous));
    }
    layout
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
    fn zeroize_mapping_clears_guest_runtime_bytes() {
        let mut ram = GuestRam::new(HVF_PAGE_SIZE * 2).expect("mmap");
        ram.copy_at(0, &[0xa5; HVF_PAGE_SIZE * 2]).unwrap();
        ram.zeroize_mapping();
        assert!(ram.snapshot_bytes().iter().all(|byte| *byte == 0));
    }

    /// Pages of `ram` this process holds its own copy of, per XNU `mincore`.
    #[cfg(target_os = "macos")]
    fn private_copies(ram: &GuestRam) -> usize {
        let (_, residency) = ram.page_residency().unwrap();
        residency
            .iter()
            .filter(|state| *state & (MINCORE_COPIED | MINCORE_ANONYMOUS) != 0)
            .count()
    }

    /// Teardown of a restored guest must not copy the saved image it never
    /// wrote. Every page of a clean file mapping is resident (the page cache
    /// holds it), and scrubbing those used to copy each one before zeroing it,
    /// doubling the process's memory at stop. The unwritten pages still read as
    /// the image afterwards, which is the proof they were left alone.
    #[cfg(target_os = "macos")]
    #[test]
    fn teardown_does_not_copy_a_clean_file_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let pages = 64;
        let image = vec![0x41_u8; HVF_PAGE_SIZE * pages];
        let file = ram_file(dir.path(), &image);
        let mut ram = GuestRam::new(image.len()).unwrap();
        ram.map_snapshot_ram(&file, RamLayout::whole_file(image.len()))
            .unwrap();
        // Bring every page into the page cache, the state a restore leaves
        // after hashing the image.
        assert_eq!(ram.snapshot_bytes(), image);
        assert_eq!(private_copies(&ram), 0);

        assert!(ram.scrub_resident());

        assert_eq!(
            private_copies(&ram),
            0,
            "scrubbing must not copy pages the guest never wrote"
        );
        assert_eq!(ram.snapshot_bytes(), image);
    }

    /// The pages a restored guest did write are its own data, and teardown
    /// still zeroes them; anonymous RAM keeps being scrubbed as before.
    #[cfg(target_os = "macos")]
    #[test]
    fn teardown_still_scrubs_pages_a_restored_guest_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let image = vec![0x41_u8; HVF_PAGE_SIZE * 8];
        let file = ram_file(dir.path(), &image);
        let mut ram = GuestRam::new(image.len()).unwrap();
        ram.map_snapshot_ram(&file, RamLayout::whole_file(image.len()))
            .unwrap();
        ram.copy_at(HVF_PAGE_SIZE * 2, b"guest secret").unwrap();
        ram.copy_at(HVF_PAGE_SIZE * 5, b"another").unwrap();
        assert!(private_copies(&ram) >= 2);

        assert!(ram.scrub_resident());

        let bytes = ram.snapshot_bytes();
        for (page, chunk) in bytes.chunks(HVF_PAGE_SIZE).enumerate() {
            if page == 2 || page == 5 {
                assert!(
                    chunk.iter().all(|b| *b == 0),
                    "written page {page} scrubbed"
                );
            } else {
                assert!(
                    chunk.iter().all(|b| *b == 0x41),
                    "clean page {page} untouched"
                );
            }
        }
    }

    #[test]
    fn a_page_is_scrubbed_only_when_it_can_hold_this_guests_data() {
        assert!(!page_needs_scrub(0, false), "not resident");
        assert!(!page_needs_scrub(0, true), "not resident");
        assert!(
            page_needs_scrub(MINCORE_INCORE, false),
            "resident anonymous"
        );
        #[cfg(target_os = "macos")]
        {
            assert!(!page_needs_scrub(MINCORE_INCORE, true), "clean file page");
            assert!(page_needs_scrub(MINCORE_INCORE | MINCORE_COPIED, true));
            assert!(page_needs_scrub(MINCORE_INCORE | MINCORE_ANONYMOUS, true));
        }
        #[cfg(not(target_os = "macos"))]
        assert!(
            page_needs_scrub(MINCORE_INCORE, true),
            "no way to tell; scrub"
        );
    }

    fn assert_all_anonymous(ram: &GuestRam, why: &str) {
        let regions = ram.backing_regions(0);
        assert_eq!(regions.len(), 1, "{why}: {regions:?}");
        assert_eq!(regions[0].backing, RamBacking::Anonymous, "{why}");
    }

    fn ram_file(dir: &Path, bytes: &[u8]) -> File {
        let path = dir.join("ram.bin");
        std::fs::write(&path, bytes).unwrap();
        File::open(path).unwrap()
    }

    #[test]
    fn a_snapshot_mapping_copies_on_guest_write_and_never_writes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let original = vec![0x41_u8; HVF_PAGE_SIZE * 2];
        let file = ram_file(dir.path(), &original);

        let mut ram = GuestRam::new(original.len()).unwrap();
        ram.map_snapshot_ram(&file, RamLayout::whole_file(original.len()))
            .unwrap();
        assert_eq!(ram.snapshot_bytes(), original);
        ram.copy_at(0, b"child").unwrap();
        assert_eq!(&ram.snapshot_bytes()[..5], b"child");
        ram.zeroize_mapping();
        assert_eq!(
            std::fs::read(dir.path().join("ram.bin")).unwrap(),
            original,
            "guest writes and teardown scrubbing must not reach the snapshot file"
        );
    }

    /// The granule a snapshot's RAM is aligned to is the hypervisor page, and
    /// the host page divides it, so an aligned range is also valid for `mmap`.
    /// On Apple silicon both are 16 KiB; a 4 KiB assumption would produce file
    /// offsets `mmap` rejects.
    #[test]
    fn the_file_mapping_granule_is_a_multiple_of_the_host_page() {
        let granule = file_mapping_granule().unwrap();
        let host = host_page_size().unwrap();
        assert_eq!(granule, HVF_PAGE_SIZE);
        assert!(granule.is_multiple_of(host), "{granule} vs host {host}");
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        assert_eq!(host, 16 * 1024, "Apple silicon hosts use 16 KiB pages");
    }

    /// A file offset aligned only to 4 KiB is refused before anything is
    /// mapped, and the reservation keeps its anonymous backing.
    #[test]
    fn a_file_offset_off_the_granule_is_refused_before_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let file = ram_file(dir.path(), &vec![0x42_u8; HVF_PAGE_SIZE * 3]);
        let mut ram = GuestRam::new(HVF_PAGE_SIZE * 2).unwrap();
        let layout = RamLayout {
            file_offset: 4096,
            ..RamLayout::whole_file(HVF_PAGE_SIZE * 2)
        };
        assert_eq!(
            ram.map_snapshot_ram(&file, layout),
            Err(HvfError::SnapshotState("file offset is not page-aligned"))
        );
        assert_all_anonymous(&ram, "nothing was mapped");
        assert!(ram.snapshot_bytes().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn a_snapshot_mapping_honours_a_page_aligned_file_offset() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = vec![0xee_u8; HVF_PAGE_SIZE];
        bytes.extend(vec![0x42_u8; HVF_PAGE_SIZE * 2]);
        let file = ram_file(dir.path(), &bytes);
        let layout = RamLayout {
            file_offset: HVF_PAGE_SIZE as u64,
            ..RamLayout::whole_file(HVF_PAGE_SIZE * 2)
        };

        let mut ram = GuestRam::new(HVF_PAGE_SIZE * 2).unwrap();
        ram.map_snapshot_ram(&file, layout).unwrap();
        assert!(ram.snapshot_bytes().iter().all(|byte| *byte == 0x42));
    }

    #[test]
    fn a_snapshot_mapping_refuses_a_wrong_length_or_a_short_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = ram_file(dir.path(), &vec![0_u8; HVF_PAGE_SIZE]);
        let mut ram = GuestRam::new(HVF_PAGE_SIZE * 2).unwrap();
        assert_eq!(
            ram.map_snapshot_ram(&file, RamLayout::whole_file(HVF_PAGE_SIZE)),
            Err(HvfError::SnapshotState("snapshot RAM length mismatch"))
        );
        assert_eq!(
            ram.map_snapshot_ram(&file, RamLayout::whole_file(HVF_PAGE_SIZE * 2)),
            Err(HvfError::SnapshotState("snapshot RAM file is too short"))
        );
        assert_all_anonymous(&ram, "nothing was mapped");
    }

    /// A capture of a restored guest carries what the guest holds now: its own
    /// writes where it made them, the snapshot's bytes everywhere else.
    #[test]
    fn write_to_captures_current_memory_not_the_file_it_was_restored_from() {
        let dir = tempfile::tempdir().unwrap();
        let original = vec![0x41_u8; HVF_PAGE_SIZE * 2];
        let file = ram_file(dir.path(), &original);
        let mut ram = GuestRam::new(original.len()).unwrap();
        ram.map_snapshot_ram(&file, RamLayout::whole_file(original.len()))
            .unwrap();
        ram.copy_at(HVF_PAGE_SIZE, b"after-restore").unwrap();

        let mut captured = Vec::new();
        ram.write_to(&mut captured).unwrap();

        let mut expected = original.clone();
        expected[HVF_PAGE_SIZE..HVF_PAGE_SIZE + 13].copy_from_slice(b"after-restore");
        assert_eq!(captured, expected);
    }

    #[test]
    fn write_to_streams_ram_larger_than_one_chunk() {
        let mut ram = GuestRam::new(WRITE_CHUNK + HVF_PAGE_SIZE).unwrap();
        ram.copy_at(WRITE_CHUNK, b"tail").unwrap();
        let mut captured = Vec::new();
        ram.write_to(&mut captured).unwrap();
        assert_eq!(captured.len(), WRITE_CHUNK + HVF_PAGE_SIZE);
        assert_eq!(&captured[WRITE_CHUNK..WRITE_CHUNK + 4], b"tail");
    }

    #[test]
    fn a_whole_ram_snapshot_mapping_replaces_earlier_file_ranges() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("Image");
        std::fs::write(&kernel, vec![7_u8; HVF_PAGE_SIZE]).unwrap();
        let file = ram_file(dir.path(), &vec![1_u8; HVF_PAGE_SIZE * 4]);
        let mut ram = GuestRam::new(HVF_PAGE_SIZE * 4).unwrap();
        ram.map_private_file_at(HVF_PAGE_SIZE, &kernel, HVF_PAGE_SIZE)
            .unwrap();
        ram.map_snapshot_ram(&file, RamLayout::whole_file(HVF_PAGE_SIZE * 4))
            .unwrap();
        let regions = ram.backing_regions(0);
        assert_eq!(regions.len(), 1, "{regions:?}");
        assert_eq!(regions[0].backing, RamBacking::PrivateFile);
        assert_eq!(regions[0].span.len, (HVF_PAGE_SIZE * 4) as u64);
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
    fn fresh_ram_is_one_anonymous_region() {
        let ram = GuestRam::new(HVF_PAGE_SIZE * 4).unwrap();
        assert_eq!(
            ram.backing_regions(0x8000_0000),
            vec![RamRegion {
                span: GuestSpan {
                    gpa: 0x8000_0000,
                    len: (HVF_PAGE_SIZE * 4) as u64,
                },
                backing: RamBacking::Anonymous,
            }]
        );
    }

    #[test]
    fn a_file_mapped_kernel_is_carved_out_of_anonymous_ram() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("Image");
        std::fs::write(&kernel, b"abcdefgh").unwrap();
        let mut ram = GuestRam::new(HVF_PAGE_SIZE * 4).unwrap();
        ram.map_private_file_at(HVF_PAGE_SIZE, &kernel, 8).unwrap();

        let page = HVF_PAGE_SIZE as u64;
        let region = |gpa, len, backing| RamRegion {
            span: GuestSpan { gpa, len },
            backing,
        };
        assert_eq!(
            ram.backing_regions(0),
            vec![
                region(0, page, RamBacking::Anonymous),
                region(page, page, RamBacking::PrivateFile),
                region(2 * page, 2 * page, RamBacking::Anonymous),
            ]
        );
    }

    #[test]
    fn a_whole_ram_snapshot_mapping_leaves_nothing_anonymous() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ram.bin");
        std::fs::write(&path, vec![0_u8; HVF_PAGE_SIZE * 2]).unwrap();
        let mut ram = GuestRam::new(HVF_PAGE_SIZE * 2).unwrap();
        let file = File::open(&path).unwrap();
        ram.map_snapshot_ram(&file, RamLayout::whole_file(HVF_PAGE_SIZE * 2))
            .unwrap();
        let regions = ram.backing_regions(0);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].backing, RamBacking::PrivateFile);
    }

    #[test]
    fn backing_layout_merges_overlapping_file_ranges_and_clips_to_ram() {
        use RamBacking::{Anonymous, PrivateFile};
        assert_eq!(backing_layout(10, &[]), vec![(0..10, Anonymous)]);
        assert_eq!(
            backing_layout(10, &[6..8, 2..4, 3..7]),
            vec![(0..2, Anonymous), (2..8, PrivateFile), (8..10, Anonymous)]
        );
        assert_eq!(
            backing_layout(10, &[8..20, 0..2]),
            vec![(0..2, PrivateFile), (2..8, Anonymous), (8..10, PrivateFile)]
        );
        assert_eq!(
            backing_layout(10, &[0..10, 4..6]),
            vec![(0..10, PrivateFile)]
        );
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
