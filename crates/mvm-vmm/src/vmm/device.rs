//! Minimal MMIO device model for the guest console path.
//!
//! A guest access to an unmapped guest-physical address traps the vCPU as a data
//! abort; the backend's run loop decodes the faulting access and dispatches it
//! here. Today that is just enough of a PL011 UART for a kernel's `earlycon` to
//! emit bytes — the first guest output beyond the boot proof.

use std::io::Write;

use super::device_state::{
    DeviceKind, DeviceStateError, SnapshotDeviceState, StateReader, StateWriter,
};

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
///
/// A caller may also attach a sink with [`Pl011::stream_to`], in which case
/// every byte is additionally written through as the guest emits it. `output`
/// stays authoritative for the whole-run transcript; the sink is what makes a
/// guest that never finishes booting observable while it is still hung.
pub struct Pl011 {
    base: u64,
    pub output: Vec<u8>,
    stream: Option<ConsoleStream>,
}

/// Write-through tail for [`Pl011`], flushed a line at a time.
///
/// Line granularity is the whole point: a per-byte flush is a syscall per
/// character, and a flush only at drop is what left a hung guest's console
/// empty for the entire time anyone was looking at it.
struct ConsoleStream {
    sink: Box<dyn Write + Send>,
    pending: Vec<u8>,
    /// Set after the first failed write. A console log that cannot be written
    /// is a lost diagnostic, never a reason to fault the guest, so the device
    /// stops trying rather than retrying on every byte.
    failed: bool,
}

impl ConsoleStream {
    /// Flush threshold for a line that never ends. A guest that hangs
    /// mid-write still surfaces what it managed to emit.
    const MAX_PENDING: usize = 512;

    fn push(&mut self, byte: u8) {
        if self.failed {
            return;
        }
        self.pending.push(byte);
        if byte == b'\n' || self.pending.len() >= Self::MAX_PENDING {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.failed || self.pending.is_empty() {
            return;
        }
        if self.sink.write_all(&self.pending).is_err() || self.sink.flush().is_err() {
            self.failed = true;
            return;
        }
        self.pending.clear();
    }
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
            stream: None,
        }
    }

    /// Mirror guest output into `sink` as it arrives, in addition to `output`.
    ///
    /// The device never opens the sink itself: the caller owns where the
    /// transcript goes and, for the host console log, that it is opened
    /// write-only.
    pub fn stream_to(&mut self, sink: Box<dyn Write + Send>) {
        self.stream = Some(ConsoleStream {
            sink,
            pending: Vec::new(),
            failed: false,
        });
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
            let byte = (value & 0xff) as u8;
            self.output.push(byte);
            if let Some(stream) = self.stream.as_mut() {
                stream.push(byte);
            }
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

impl SnapshotDeviceState for Pl011 {
    fn device_kind(&self) -> DeviceKind {
        DeviceKind::Pl011
    }

    fn snapshot_state(&self) -> Result<Vec<u8>, DeviceStateError> {
        // The UART has no guest-visible mutable register state in this model.
        // Its output is a host transcript and must not be replayed into a child.
        Ok(StateWriter::new(1).finish())
    }

    fn restore_state(&mut self, bytes: &[u8]) -> Result<(), DeviceStateError> {
        let kind = DeviceKind::Pl011;
        let mut reader = StateReader::new(bytes);
        let version = reader.version(kind)?;
        if version != 1 {
            return Err(DeviceStateError::UnsupportedVersion(version));
        }
        reader.finish()?;
        self.output.clear();
        // Same reason the transcript is not replayed: a partial parent line
        // still sitting in the write-through buffer is the parent's output,
        // and must not appear in the child's console log. The sink itself
        // stays attached — it is the child's own log file.
        if let Some(stream) = self.stream.as_mut() {
            stream.pending.clear();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmm::device_state::SnapshotDeviceState;

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

    #[test]
    fn snapshot_state_does_not_replay_host_console_transcript() {
        let mut uart = Pl011::new(0x0900_0000);
        uart.output.extend_from_slice(b"parent output");
        let state = uart.snapshot_state().unwrap();
        uart.output.clear();
        uart.output.extend_from_slice(b"child output");
        uart.restore_state(&state).unwrap();
        assert!(uart.output.is_empty());
    }

    /// Writes a byte at a time into `uart`, as the guest does.
    fn emit(uart: &mut Pl011, bytes: &[u8]) {
        for b in bytes {
            uart.write(Pl011::DR, u64::from(*b), 4);
        }
    }

    fn streaming_uart(path: &std::path::Path) -> Pl011 {
        let mut uart = Pl011::new(0x0900_0000);
        uart.stream_to(Box::new(std::fs::File::create(path).expect("create sink")));
        uart
    }

    /// The property whose absence hid a boot failure: output is readable from
    /// the sink while the device is still live, not only once it is dropped.
    #[test]
    fn a_completed_line_reaches_the_sink_before_the_device_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console.log");
        let mut uart = streaming_uart(&path);

        emit(&mut uart, b"mvm-guest-init: switching to /init\n");

        // Deliberately no drop, no flush call: the guest is still running.
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"mvm-guest-init: switching to /init\n"
        );
    }

    /// A guest that hangs part-way through a line still surfaces it.
    #[test]
    fn an_unterminated_line_flushes_once_it_exceeds_the_pending_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console.log");
        let mut uart = streaming_uart(&path);

        emit(&mut uart, &vec![b'x'; ConsoleStream::MAX_PENDING - 1]);
        assert!(
            std::fs::read(&path).unwrap().is_empty(),
            "below the cap and with no newline, nothing needs to have been written yet"
        );

        emit(&mut uart, b"x");
        assert_eq!(
            std::fs::read(&path).unwrap().len(),
            ConsoleStream::MAX_PENDING,
            "reaching the cap must flush what is pending"
        );
    }

    /// Streaming is additive. The in-memory transcript is unchanged, so the
    /// exit-time consumers of it see exactly what they saw before.
    #[test]
    fn streaming_does_not_change_the_in_memory_transcript() {
        let dir = tempfile::tempdir().unwrap();
        let mut streamed = streaming_uart(&dir.path().join("console.log"));
        let mut plain = Pl011::new(0x0900_0000);

        for uart in [&mut streamed, &mut plain] {
            emit(uart, b"line one\nline two, unterminated");
        }

        assert_eq!(streamed.output, plain.output);
    }

    /// A sink that cannot be written must not fault the guest, and must not be
    /// retried on every subsequent byte.
    #[test]
    fn a_failing_sink_is_abandoned_rather_than_propagated() {
        struct Broken;
        impl std::io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("sink is gone"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut uart = Pl011::new(0x0900_0000);
        uart.stream_to(Box::new(Broken));
        emit(&mut uart, b"first\nsecond\n");

        assert_eq!(uart.output, b"first\nsecond\n", "the guest keeps emitting");
        assert!(
            uart.stream.as_ref().is_some_and(|s| s.failed),
            "the stream must latch failed rather than retry per byte"
        );
    }

    /// A restored child must not inherit a partial parent line through the
    /// write-through buffer, but keeps its own sink attached.
    #[test]
    fn restore_clears_pending_output_without_detaching_the_sink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console.log");
        let mut uart = streaming_uart(&path);

        emit(&mut uart, b"parent partial line");
        let state = uart.snapshot_state().unwrap();
        uart.restore_state(&state).unwrap();
        emit(&mut uart, b"child line\n");

        assert_eq!(std::fs::read(&path).unwrap(), b"child line\n");
    }
}
