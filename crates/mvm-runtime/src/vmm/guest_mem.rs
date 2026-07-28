//! Bounds-checked guest-physical memory access over the single mapped RAM
//! region, shared by the virtio devices for virtqueue + buffer DMA.
//!
//! Every read/write is gated by the same bounds check and then performed through
//! `vm-memory`'s [`VolatileSlice`] — the audited safe wrapper over a raw guest
//! pointer — rather than hand-rolled `ptr::copy_nonoverlapping`. The bounds gate
//! and the out-of-range semantics (read → zero-fill, write → no-op) are preserved
//! byte-for-byte, so callers are unaffected.
//!
//! Scalar/byte access goes through `VolatileSlice::new`, which imposes no
//! alignment constraint. Separately, [`GuestMem::guest_memory`] builds a real
//! [`GuestMemoryMmap`] over the same mapping via [`MmapRegion::build_raw`] so the
//! validated `virtio-queue` ring walk has a `GuestMemory` to iterate. `build_raw`
//! hard-requires a **page-aligned** pointer and creates a **non-owning** region
//! (`owned = false`), so vm-memory never unmaps the externally-owned HVF/KVM
//! mapping. Production RAM is page-aligned; the device unit tests allocate their
//! scratch RAM at page granularity (see `crate::test_support::page_aligned_ram`)
//! so the same construction works for prod and tests.

use vm_memory::{GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion, VolatileSlice};

/// A view onto guest RAM mapped at `base .. base+size` via host pointer `ram`.
#[derive(Clone, Copy)]
pub(super) struct GuestMem {
    ram: *mut u8,
    base: u64,
    size: usize,
}

// SAFETY: `GuestMem` is a raw view onto the single mapped guest-RAM region, which
// outlives every thread that touches it. The vsock device shares it between the
// vCPU thread and the dedicated host-I/O thread, but all access is serialized
// under the device's `Mutex<VsockShared>`, and the I/O thread is joined before the
// RAM is unmapped/freed (`VirtioVsock::shutdown` runs before `dealloc`). So the
// pointer is only ever dereferenced by one thread at a time and never dangles.
// This is the same externally-owned-mapping invariant `vm-memory` itself relies on
// for `MmapRegion`'s `unsafe impl Send`; routing accesses through `VolatileSlice`
// does not weaken it.
unsafe impl Send for GuestMem {}

impl GuestMem {
    /// # Safety
    /// `ram` must point to `size` bytes mapped as guest RAM at `base`, valid for
    /// as long as this `GuestMem` is used.
    pub(super) unsafe fn new(ram: *mut u8, base: u64, size: usize) -> Self {
        Self { ram, base, size }
    }

    /// Byte offset of `[gpa, gpa+len)` within the mapping, or `None` when the
    /// range starts below `base`, runs past `size`, or `gpa + len` overflows.
    fn offset(&self, gpa: u64, len: usize) -> Option<usize> {
        if gpa < self.base {
            return None;
        }
        let off = (gpa - self.base) as usize;
        if off.checked_add(len)? > self.size {
            return None;
        }
        Some(off)
    }

    /// Host pointer for a guest-physical range, bounds-checked against RAM.
    pub(super) fn host(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        // SAFETY: `off + len` are within the mapped region by `offset`'s checks.
        self.offset(gpa, len)
            .map(|off| unsafe { self.ram.add(off) })
    }

    /// Build a non-owning [`GuestMemoryMmap`] over this mapping so the audited
    /// `virtio-queue` `Queue`/`DescriptorChain` iterator can walk the ring with a
    /// real `GuestMemory`. Returns `None` when the backing pointer is not
    /// page-aligned (which [`MmapRegion::build_raw`] rejects) or the region is
    /// otherwise unrepresentable, in which case the caller services nothing —
    /// mirroring the existing "illegal geometry → left unserviced" early outs.
    pub(super) fn guest_memory(&self) -> Option<GuestMemoryMmap> {
        // SAFETY: `self.ram` addresses `self.size` bytes of guest RAM valid for as
        // long as this `GuestMem` is used (the `new` contract). `build_raw` takes
        // ownership of nothing — it constructs a region with `owned = false`, so
        // dropping the returned `GuestMemoryMmap` never unmaps the mapping the
        // hypervisor owns. The `prot`/`flags` are recorded metadata only; no mmap
        // syscall runs for a raw-pointer region.
        let region = unsafe {
            MmapRegion::build_raw(
                self.ram,
                self.size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            )
        }
        .ok()?;
        let region = GuestRegionMmap::new(region, GuestAddress(self.base))?;
        GuestMemoryMmap::from_regions(vec![region]).ok()
    }

    /// A [`VolatileSlice`] over an in-range `[gpa, gpa+len)`, or `None` when the
    /// range is out of bounds. Callers copy through the slice, so an out-of-range
    /// access yields no copy — reproducing the zero-fill/no-op semantics.
    fn slice(&self, gpa: u64, len: usize) -> Option<VolatileSlice<'_>> {
        let ptr = self.host(gpa, len)?;
        // SAFETY: `ptr` is valid for `len` bytes (bounds-checked by `host`) and
        // lives as long as the mapping. Every guest-RAM access in this module goes
        // through a `VolatileSlice`, honouring the volatile-only-access contract.
        Some(unsafe { VolatileSlice::new(ptr, len) })
    }

    fn rd<const N: usize>(&self, gpa: u64) -> [u8; N] {
        let mut b = [0u8; N];
        if let Some(vs) = self.slice(gpa, N) {
            // In range: copy all N bytes out. Out of range: `b` stays zero-filled.
            vs.copy_to(&mut b);
        }
        b
    }

    pub(super) fn rd_u16(&self, gpa: u64) -> u16 {
        u16::from_le_bytes(self.rd(gpa))
    }
    pub(super) fn rd_u32(&self, gpa: u64) -> u32 {
        u32::from_le_bytes(self.rd(gpa))
    }
    pub(super) fn rd_u64(&self, gpa: u64) -> u64 {
        u64::from_le_bytes(self.rd(gpa))
    }

    pub(super) fn wr_u8(&self, gpa: u64, v: u8) {
        if let Some(vs) = self.slice(gpa, 1) {
            vs.copy_from(&[v]);
        }
    }
    /// Store a 16-bit little-endian word. The last production writer of a bare
    /// guest word was the hand-rolled used-ring update; `virtio-queue` owns those
    /// writes now, so this survives as the fixture/oracle helper the device tests
    /// use to lay out rings and reproduce pre-migration completions.
    #[cfg(test)]
    pub(super) fn wr_u16(&self, gpa: u64, v: u16) {
        if let Some(vs) = self.slice(gpa, 2) {
            vs.copy_from(&v.to_le_bytes());
        }
    }

    /// Copy `bytes` into guest memory at `gpa` (truncated to what fits).
    pub(super) fn write_bytes(&self, gpa: u64, bytes: &[u8]) -> usize {
        match self.slice(gpa, bytes.len()) {
            Some(vs) => {
                vs.copy_from(bytes);
                bytes.len()
            }
            None => 0,
        }
    }

    /// Read `len` bytes from guest memory at `gpa`.
    pub(super) fn read_bytes(&self, gpa: u64, len: usize) -> Vec<u8> {
        match self.slice(gpa, len) {
            Some(vs) => {
                let mut v = vec![0u8; len];
                vs.copy_to(&mut v);
                v
            }
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GuestMem;

    const BASE: u64 = 0x4000_0000;
    const SIZE: usize = 256;

    /// Independent reference model of the documented `GuestMem` semantics: an
    /// in-range `[gpa, gpa+len)` reads/writes the exact bytes; any range starting
    /// below `base`, running past `size`, or whose `gpa + len` overflows reads as
    /// zero and writes as a no-op.
    struct RefMem {
        data: Vec<u8>,
        base: u64,
    }

    impl RefMem {
        fn offset(&self, gpa: u64, len: usize) -> Option<usize> {
            if gpa < self.base {
                return None;
            }
            let off = (gpa - self.base) as usize;
            if off.checked_add(len)? > self.data.len() {
                return None;
            }
            Some(off)
        }

        fn read_bytes(&self, gpa: u64, len: usize) -> Vec<u8> {
            match self.offset(gpa, len) {
                Some(off) => self.data[off..off + len].to_vec(),
                None => Vec::new(),
            }
        }

        fn rd<const N: usize>(&self, gpa: u64) -> [u8; N] {
            let mut b = [0u8; N];
            if let Some(off) = self.offset(gpa, N) {
                b.copy_from_slice(&self.data[off..off + N]);
            }
            b
        }

        fn write_bytes(&mut self, gpa: u64, bytes: &[u8]) -> usize {
            match self.offset(gpa, bytes.len()) {
                Some(off) => {
                    self.data[off..off + bytes.len()].copy_from_slice(bytes);
                    bytes.len()
                }
                None => 0,
            }
        }
    }

    /// The `(gpa, len)` matrix: below-base, in-range, straddling the end, exactly
    /// at the boundary, fully out-of-range, zero-length, and `gpa + len` overflow.
    fn cases() -> Vec<(u64, usize)> {
        let lens = [0usize, 1, 2, 4, 8, 16, 255, 256, 300];
        let gpas = [
            0,                      // far below base
            BASE - 2,               // just below base
            BASE - 1,               // one below base
            BASE,                   // start of RAM
            BASE + 1,               // in range
            BASE + 100,             // mid range
            BASE + 248,             // near end, straddles for len >= 8
            BASE + 254,             // straddles for len >= 2
            BASE + 255,             // last byte
            BASE + SIZE as u64,     // one past end (boundary)
            BASE + SIZE as u64 + 8, // fully out of range
            u64::MAX - 4,           // gpa + len overflows for len > 4
            u64::MAX,               // gpa + len overflows for any len > 0
        ];
        let mut out = Vec::new();
        for &g in &gpas {
            for &l in &lens {
                out.push((g, l));
            }
        }
        out
    }

    fn pattern(size: usize) -> Vec<u8> {
        // Deterministic, non-trivial content so little-endian reads are meaningful.
        (0..size)
            .map(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
            .collect()
    }

    #[test]
    fn reads_match_documented_semantics() {
        let mut ram = pattern(SIZE);
        let reference = RefMem {
            data: ram.clone(),
            base: BASE,
        };
        // SAFETY: `ram` is `SIZE` bytes and outlives `gm` within this test.
        let gm = unsafe { GuestMem::new(ram.as_mut_ptr(), BASE, SIZE) };

        for (gpa, len) in cases() {
            assert_eq!(
                gm.read_bytes(gpa, len),
                reference.read_bytes(gpa, len),
                "read_bytes mismatch at gpa={gpa:#x} len={len}"
            );
            assert_eq!(
                gm.rd_u16(gpa),
                u16::from_le_bytes(reference.rd(gpa)),
                "rd_u16 mismatch at gpa={gpa:#x}"
            );
            assert_eq!(
                gm.rd_u32(gpa),
                u32::from_le_bytes(reference.rd(gpa)),
                "rd_u32 mismatch at gpa={gpa:#x}"
            );
            assert_eq!(
                gm.rd_u64(gpa),
                u64::from_le_bytes(reference.rd(gpa)),
                "rd_u64 mismatch at gpa={gpa:#x}"
            );
        }
    }

    #[test]
    fn writes_match_documented_semantics() {
        // Each write case runs against a fresh zeroed buffer + mirror so an
        // out-of-range write leaves both untouched and an in-range write lands
        // byte-identically, then the whole buffer is compared to the mirror.
        for (gpa, len) in cases() {
            let payload: Vec<u8> = (0..len).map(|i| (i as u8) ^ 0xA5).collect();

            let mut ram = vec![0u8; SIZE];
            let mut reference = RefMem {
                data: vec![0u8; SIZE],
                base: BASE,
            };
            // SAFETY: `ram` is `SIZE` bytes and outlives `gm` within this loop body.
            let gm = unsafe { GuestMem::new(ram.as_mut_ptr(), BASE, SIZE) };

            let got = gm.write_bytes(gpa, &payload);
            let want = reference.write_bytes(gpa, &payload);
            assert_eq!(
                got, want,
                "write_bytes return mismatch at gpa={gpa:#x} len={len}"
            );
            assert_eq!(
                ram, reference.data,
                "RAM diverged after write at gpa={gpa:#x} len={len}"
            );
        }

        // wr_u8 / wr_u16 against the boundary and overflow cases.
        for &(gpa, _) in &cases() {
            let mut ram = vec![0u8; SIZE];
            let mut reference = RefMem {
                data: vec![0u8; SIZE],
                base: BASE,
            };
            // SAFETY: `ram` is `SIZE` bytes and outlives `gm` within this loop body.
            let gm = unsafe { GuestMem::new(ram.as_mut_ptr(), BASE, SIZE) };

            gm.wr_u8(gpa, 0x5C);
            reference.write_bytes(gpa, &[0x5C]);
            assert_eq!(ram, reference.data, "wr_u8 diverged at gpa={gpa:#x}");

            let mut ram2 = vec![0u8; SIZE];
            let mut reference2 = RefMem {
                data: vec![0u8; SIZE],
                base: BASE,
            };
            // SAFETY: `ram2` is `SIZE` bytes and outlives `gm2` within this loop body.
            let gm2 = unsafe { GuestMem::new(ram2.as_mut_ptr(), BASE, SIZE) };
            gm2.wr_u16(gpa, 0xBEEF);
            reference2.write_bytes(gpa, &0xBEEFu16.to_le_bytes());
            assert_eq!(ram2, reference2.data, "wr_u16 diverged at gpa={gpa:#x}");
        }
    }

    #[test]
    fn host_pointer_bounds_match_offset_check() {
        let mut ram = pattern(SIZE);
        // SAFETY: `ram` is `SIZE` bytes and outlives `gm` within this test.
        let gm = unsafe { GuestMem::new(ram.as_mut_ptr(), BASE, SIZE) };
        for (gpa, len) in cases() {
            let in_range = gm.host(gpa, len).is_some();
            let expected = gpa >= BASE
                && ((gpa - BASE) as usize)
                    .checked_add(len)
                    .is_some_and(|end| end <= SIZE);
            assert_eq!(
                in_range, expected,
                "host() bounds mismatch at gpa={gpa:#x} len={len}"
            );
        }
    }
}
