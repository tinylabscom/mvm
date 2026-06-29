//! Minimal MMIO device model for the HVF console path.
//!
//! A guest access to an unmapped guest-physical address traps out of
//! `hv_vcpu_run` as a data abort; the run loop decodes the faulting access and
//! dispatches it here. Today that is just enough of a PL011 UART for a kernel's
//! `earlycon` to emit bytes — the first guest output beyond the boot proof.

/// A memory-mapped device occupying `[base, base+len)` in guest-physical space.
pub trait MmioDevice {
    fn base(&self) -> u64;
    fn region_len(&self) -> u64;
    fn contains(&self, addr: u64) -> bool {
        addr >= self.base() && addr < self.base() + self.region_len()
    }
    /// Handle a guest store of `value` (low `size` bytes) at `offset` from base.
    fn write(&mut self, offset: u64, value: u64, size: u8);
    /// Handle a guest load of `size` bytes at `offset` from base.
    fn read(&mut self, offset: u64, size: u8) -> u64;
}

/// ARM PL011 UART, cut down to what `earlycon=pl011` needs: writes to the data
/// register emit a byte; the flag register always reports "ready to transmit"
/// so the guest never spins waiting on us. Emitted bytes accumulate in `output`.
pub struct Pl011 {
    base: u64,
    pub output: Vec<u8>,
}

impl Pl011 {
    /// Register offsets (PL011 TRM).
    const DR: u64 = 0x00; // data register
    const FR: u64 = 0x18; // flag register
    /// Flag register bits we care about. TXFE set + BUSY/TXFF clear ⇒ the guest
    /// sees an idle, ready transmitter.
    const FR_TXFE: u64 = 1 << 7;

    /// PrimeCell/peripheral ID register block (0xFE0..0xFFC), 8 words.
    const PERIPH_ID0: u64 = 0xFE0;
    const PCELL_ID3: u64 = 0xFFC;
    /// PL011 identity: PeriphID 0x00041011, PrimeCell ID 0xB105F00D.
    const ID_REGS: [u64; 8] = [0x11, 0x10, 0x14, 0x00, 0x0D, 0xF0, 0x05, 0xB1];

    pub fn new(base: u64) -> Self {
        Self {
            base,
            output: Vec::new(),
        }
    }

    /// PL011 occupies a 4 KiB MMIO page.
    pub const LEN: u64 = 0x1000;
}

impl MmioDevice for Pl011 {
    fn base(&self) -> u64 {
        self.base
    }
    fn region_len(&self) -> u64 {
        Self::LEN
    }

    fn write(&mut self, offset: u64, value: u64, _size: u8) {
        if offset == Self::DR {
            self.output.push((value & 0xff) as u8);
        }
        // All other registers are write-ignored for earlycon's purposes.
    }

    fn read(&mut self, offset: u64, _size: u8) -> u64 {
        match offset {
            Self::FR => Self::FR_TXFE, // always ready to transmit
            // PrimeCell + peripheral ID registers, so the real `ttyAMA0` driver
            // (not just earlycon) recognizes us as a PL011 and attaches.
            // periphid 0x00041011, cellid 0xb105f00d.
            o if (Self::PERIPH_ID0..=Self::PCELL_ID3).contains(&o) => {
                Self::ID_REGS[((o - Self::PERIPH_ID0) / 4) as usize]
            }
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_register_writes_accumulate_as_bytes() {
        let mut uart = Pl011::new(0x0900_0000);
        for b in b"OK\n" {
            uart.write(Pl011::DR, u64::from(*b), 4);
        }
        assert_eq!(uart.output, b"OK\n");
    }

    #[test]
    fn flag_register_reports_transmitter_ready() {
        let mut uart = Pl011::new(0x0900_0000);
        assert_eq!(uart.read(Pl011::FR, 4) & Pl011::FR_TXFE, Pl011::FR_TXFE);
    }

    #[test]
    fn only_low_byte_of_a_wide_write_is_emitted() {
        let mut uart = Pl011::new(0x0900_0000);
        uart.write(Pl011::DR, 0xdead_be41, 4); // 'A'
        assert_eq!(uart.output, b"A");
    }

    #[test]
    fn contains_covers_the_mmio_page() {
        let uart = Pl011::new(0x0900_0000);
        assert!(uart.contains(0x0900_0000));
        assert!(uart.contains(0x0900_0fff));
        assert!(!uart.contains(0x0900_1000));
        assert!(!uart.contains(0x08ff_ffff));
    }
}
