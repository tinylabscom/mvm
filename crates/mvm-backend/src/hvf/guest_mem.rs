//! Bounds-checked guest-physical memory access over the single mapped RAM
//! region, shared by the virtio devices for virtqueue + buffer DMA.

/// A view onto guest RAM mapped at `base .. base+size` via host pointer `ram`.
#[derive(Clone, Copy)]
pub(super) struct GuestMem {
    ram: *mut u8,
    base: u64,
    size: usize,
}

impl GuestMem {
    /// # Safety
    /// `ram` must point to `size` bytes mapped as guest RAM at `base`, valid for
    /// as long as this `GuestMem` is used.
    pub(super) unsafe fn new(ram: *mut u8, base: u64, size: usize) -> Self {
        Self { ram, base, size }
    }

    /// Host pointer for a guest-physical range, bounds-checked against RAM.
    pub(super) fn host(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        if gpa < self.base {
            return None;
        }
        let off = (gpa - self.base) as usize;
        if off.checked_add(len)? > self.size {
            return None;
        }
        // SAFETY: offset + len are within the mapped region by the checks above.
        Some(unsafe { self.ram.add(off) })
    }

    fn rd<const N: usize>(&self, gpa: u64) -> [u8; N] {
        let mut b = [0u8; N];
        if let Some(p) = self.host(gpa, N) {
            // SAFETY: `p` is valid for N bytes.
            unsafe { core::ptr::copy_nonoverlapping(p, b.as_mut_ptr(), N) };
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
        if let Some(p) = self.host(gpa, 1) {
            // SAFETY: `p` valid for 1 byte.
            unsafe { *p = v };
        }
    }
    pub(super) fn wr_u16(&self, gpa: u64, v: u16) {
        if let Some(p) = self.host(gpa, 2) {
            // SAFETY: `p` valid for 2 bytes.
            unsafe { core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), p, 2) };
        }
    }

    /// Copy `bytes` into guest memory at `gpa` (truncated to what fits).
    pub(super) fn write_bytes(&self, gpa: u64, bytes: &[u8]) -> usize {
        match self.host(gpa, bytes.len()) {
            Some(p) => {
                // SAFETY: `p` valid for bytes.len().
                unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len()) };
                bytes.len()
            }
            None => 0,
        }
    }

    /// Read `len` bytes from guest memory at `gpa`.
    pub(super) fn read_bytes(&self, gpa: u64, len: usize) -> Vec<u8> {
        match self.host(gpa, len) {
            Some(p) => {
                let mut v = vec![0u8; len];
                // SAFETY: `p` valid for len.
                unsafe { core::ptr::copy_nonoverlapping(p, v.as_mut_ptr(), len) };
                v
            }
            None => Vec::new(),
        }
    }
}
