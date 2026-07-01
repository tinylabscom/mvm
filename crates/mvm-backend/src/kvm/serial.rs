//! Minimal 16550 UART — the x86 console for the KVM run loop, cut down to what a
//! Linux `console=ttyS0` needs: writes to the transmit-holding register emit a
//! byte; the line-status register always reports "transmitter empty" so the guest
//! never blocks on us. A [`RunDevice`](crate::vmm::run::RunDevice) at PIO `0x3f8`.
//!
//! Polled TX is enough for kernel printk (the kernel's console writer busy-waits
//! on LSR). Interrupt-driven userspace tty TX would need the serial IRQ wired;
//! that is not modeled here (the spike used `/dev/kmsg` to surface a userspace
//! marker through the polled console).

use crate::vmm::run::RunDevice;

/// 8-port 16550 register block.
pub struct Serial16550 {
    base: u16,
    /// Bytes the guest transmitted.
    pub output: Vec<u8>,
}

impl Serial16550 {
    const THR: u64 = 0; // transmit holding register (write)
    const LSR: u64 = 5; // line status register (read)
    /// LSR: THRE (0x20) | TEMT (0x40) — always ready to accept a byte.
    const LSR_READY: u64 = 0x60;
    /// The 16550 occupies 8 consecutive ports.
    pub const LEN: u64 = 8;

    pub fn new(base: u16) -> Self {
        Self {
            base,
            output: Vec::new(),
        }
    }
}

impl RunDevice for Serial16550 {
    fn contains(&self, addr: u64) -> bool {
        addr >= u64::from(self.base) && addr < u64::from(self.base) + Self::LEN
    }
    fn base(&self) -> u64 {
        u64::from(self.base)
    }
    fn read(&mut self, offset: u64, _size: u8) -> u64 {
        if offset == Self::LSR {
            Self::LSR_READY
        } else {
            0
        }
    }
    fn write(&mut self, offset: u64, value: u64, _size: u8) -> Option<u32> {
        if offset == Self::THR {
            self.output.push((value & 0xff) as u8);
        }
        None // polled console: no interrupt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thr_writes_accumulate_as_bytes() {
        let mut s = Serial16550::new(0x3f8);
        for b in b"OK\n" {
            s.write(Serial16550::THR, u64::from(*b), 1);
        }
        assert_eq!(s.output, b"OK\n");
    }

    #[test]
    fn lsr_reports_transmitter_ready() {
        let mut s = Serial16550::new(0x3f8);
        assert_eq!(s.read(Serial16550::LSR, 1), Serial16550::LSR_READY);
    }

    #[test]
    fn contains_covers_the_eight_ports() {
        let s = Serial16550::new(0x3f8);
        assert!(s.contains(0x3f8));
        assert!(s.contains(0x3ff));
        assert!(!s.contains(0x400));
        assert!(!s.contains(0x3f7));
    }
}
