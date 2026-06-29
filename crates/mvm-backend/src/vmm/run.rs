//! The unified vCPU run loop — one body for every backend.
//!
//! Drives a [`HypervisorVcpu`](super::hv::HypervisorVcpu) through the seam:
//! `step()` yields a *decoded* [`VcpuExit`], the loop dispatches `Mmio`/`Io`
//! accesses to a device list (matched by guest address / port), completes a read
//! via `complete_read`, and raises a device's IRQ line via the supplied
//! `set_irq`. Halt/cancel end the run; non-MMIO exceptions (arm64 PSCI/HVC — KVM
//! never produces these) go to a caller hook.
//!
//! Because HVF decodes its data-abort ESR into the same `Mmio` the kernel hands
//! KVM, this single loop serves both backends with no `cfg` and no per-backend
//! device dispatch.

use super::hv::{HypervisorVcpu, VcpuExit};

/// A guest device the run loop dispatches decoded accesses to. Matched by guest
/// address (MMIO) or port number (PIO) — the two spaces don't overlap within a
/// VM, so one list serves both.
pub trait RunDevice {
    /// True if `addr` (a guest-physical address, or a port for PIO) is this
    /// device's.
    fn contains(&self, addr: u64) -> bool;
    /// Base address/port, subtracted to form the register offset.
    fn base(&self) -> u64;
    /// Service a guest load of `size` bytes at `offset` from base.
    fn read(&mut self, offset: u64, size: u8) -> u64;
    /// Service a guest store; return `Some(irq)` to raise that interrupt line.
    fn write(&mut self, offset: u64, value: u64, size: u8) -> Option<u32>;
    /// Do pending host-side async work (e.g. drain a backing socket into the
    /// guest's rx queue) and return `Some(irq)` if the guest needs an interrupt.
    /// Called on every timer tick so host→guest delivery happens even when the
    /// guest isn't doing MMIO. Default: nothing to do.
    fn poll(&mut self) -> Option<u32> {
        None
    }
}

/// Whether the loop should keep running after a caller-handled exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunControl {
    Continue,
    Stop,
}

/// Why the run loop returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// The guest halted or requested shutdown ([`VcpuExit::Halt`]).
    Halt,
    /// Another thread forced the vCPU out ([`VcpuExit::Canceled`]) — e.g. a
    /// watchdog.
    Canceled,
    /// A caller hook (or an unmodeled exit) stopped the run.
    Stopped,
}

/// Dispatch one decoded access (MMIO or PIO, keyed by `addr`) to `devices`,
/// completing a read through `vcpu` and raising any triggered IRQ via `set_irq`.
fn dispatch<C, S>(
    vcpu: &C,
    set_irq: &S,
    devices: &mut [&mut dyn RunDevice],
    addr: u64,
    write: bool,
    size: u8,
    data: u64,
) -> Result<(), C::Error>
where
    C: HypervisorVcpu,
    S: Fn(u32, bool) -> Result<(), C::Error>,
{
    match devices.iter_mut().find(|d| d.contains(addr)) {
        Some(d) => {
            let offset = addr - d.base();
            if write {
                if let Some(irq) = d.write(offset, data, size) {
                    set_irq(irq, true)?;
                }
            } else {
                let v = d.read(offset, size);
                vcpu.complete_read(v)?;
            }
        }
        // Unmapped: reads-as-zero, writes-ignored, so the guest keeps going.
        None if !write => vcpu.complete_read(0)?,
        None => {}
    }
    Ok(())
}

/// Run `vcpu` until it halts/cancels or `on_exception` says stop.
///
/// - `set_irq(intid, level)` raises/lowers a device interrupt line (the backend's
///   `HypervisorVm::set_irq`).
/// - `devices` are matched by guest address (MMIO) / port (PIO).
/// - `on_exception(vcpu, syndrome, phys_addr)` handles a non-MMIO exception
///   (arm64 PSCI/HVC); return [`RunControl::Stop`] to end the run. x86 KVM never
///   reaches it (every exit is decoded).
/// - `should_stop()` disambiguates a forced exit ([`VcpuExit::Canceled`]): a real
///   stop (watchdog timeout / graceful stop) returns `true` and ends the run; a
///   `false` means the cancel was a *heartbeat wake* to let host-side async work
///   run (e.g. draining an egress socket into the guest's rx queue while the guest
///   is idle in WFI), so the loop polls devices and keeps going. Backends with no
///   async host I/O pass `|| true` (a cancel always stops).
pub fn run<C, S, X, Q>(
    vcpu: &C,
    set_irq: S,
    devices: &mut [&mut dyn RunDevice],
    mut on_exception: X,
    should_stop: Q,
) -> Result<RunOutcome, C::Error>
where
    C: HypervisorVcpu,
    S: Fn(u32, bool) -> Result<(), C::Error>,
    X: FnMut(&C, u64, u64) -> Result<RunControl, C::Error>,
    Q: Fn() -> bool,
{
    loop {
        match vcpu.step()? {
            VcpuExit::VTimer => {
                // Host→guest async work each timer tick (e.g. drain an egress
                // socket into the guest's rx queue), so delivery happens even
                // when the guest is idle in WFI rather than doing MMIO.
                for d in devices.iter_mut() {
                    if let Some(irq) = d.poll() {
                        set_irq(irq, true)?;
                    }
                }
            }
            VcpuExit::Canceled => {
                // A forced exit: either a real stop or a heartbeat wake. Poll
                // host-side async work either way (this is how an egress reply
                // reaches a guest blocked in WFI), then end only if a stop was
                // actually requested.
                for d in devices.iter_mut() {
                    if let Some(irq) = d.poll() {
                        set_irq(irq, true)?;
                    }
                }
                if should_stop() {
                    return Ok(RunOutcome::Canceled);
                }
            }
            VcpuExit::Halt => return Ok(RunOutcome::Halt),
            VcpuExit::Mmio {
                phys_addr,
                write,
                len,
                data,
            } => {
                dispatch(vcpu, &set_irq, devices, phys_addr, write, len, data)?;
            }
            VcpuExit::Io {
                port,
                write,
                size,
                data,
            } => {
                dispatch(
                    vcpu,
                    &set_irq,
                    devices,
                    u64::from(port),
                    write,
                    size,
                    u64::from(data),
                )?;
            }
            VcpuExit::Exception {
                syndrome,
                phys_addr,
            } => {
                if on_exception(vcpu, syndrome, phys_addr)? == RunControl::Stop {
                    return Ok(RunOutcome::Stopped);
                }
            }
            VcpuExit::Unknown(_) => return Ok(RunOutcome::Stopped),
        }
    }
}

// ---- RunDevice impls for the in-repo device model --------------------------

impl RunDevice for super::device::Pl011 {
    fn contains(&self, addr: u64) -> bool {
        super::device::MmioDevice::contains(self, addr)
    }
    fn base(&self) -> u64 {
        super::device::MmioDevice::base(self)
    }
    fn read(&mut self, offset: u64, size: u8) -> u64 {
        super::device::MmioDevice::read(self, offset, size)
    }
    fn write(&mut self, offset: u64, value: u64, size: u8) -> Option<u32> {
        super::device::MmioDevice::write(self, offset, value, size);
        None // PL011 has no interrupt in this model
    }
}

impl RunDevice for super::virtio::VirtioBlk {
    fn contains(&self, addr: u64) -> bool {
        self.contains(addr)
    }
    fn base(&self) -> u64 {
        self.base()
    }
    fn read(&mut self, offset: u64, _size: u8) -> u64 {
        (*self).read(offset)
    }
    fn write(&mut self, offset: u64, value: u64, _size: u8) -> Option<u32> {
        self.write(offset, value).then(|| self.irq())
    }
}

impl RunDevice for super::vsock::VirtioVsock {
    fn contains(&self, addr: u64) -> bool {
        self.contains(addr)
    }
    fn base(&self) -> u64 {
        self.base()
    }
    fn read(&mut self, offset: u64, _size: u8) -> u64 {
        (*self).read(offset)
    }
    fn write(&mut self, offset: u64, value: u64, _size: u8) -> Option<u32> {
        self.write(offset, value).then(|| self.irq())
    }
    fn poll(&mut self) -> Option<u32> {
        // Host→guest half of the egress proxy: drain admitted sockets into the rx
        // queue each timer tick.
        self.drain_egress()
    }
}

#[cfg(test)]
mod tests {
    use super::super::hv::{CoreReg, SysReg, VcpuHandle};
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    #[derive(Clone, Copy)]
    struct NopHandle;
    impl VcpuHandle for NopHandle {
        fn force_exit(_: &[Self]) {}
    }

    /// A vCPU that replays a scripted list of exits and records the values handed
    /// to `complete_read`.
    struct ScriptVcpu {
        script: RefCell<VecDeque<VcpuExit>>,
        reads: RefCell<Vec<u64>>,
    }
    impl ScriptVcpu {
        fn new(exits: Vec<VcpuExit>) -> Self {
            Self {
                script: RefCell::new(exits.into()),
                reads: RefCell::new(Vec::new()),
            }
        }
    }
    impl HypervisorVcpu for ScriptVcpu {
        type Error = ();
        type Handle = NopHandle;
        fn exit_token(&self) -> NopHandle {
            NopHandle
        }
        fn get_core(&self, _: CoreReg) -> Result<u64, ()> {
            Err(())
        }
        fn set_core(&self, _: CoreReg, _: u64) -> Result<(), ()> {
            Err(())
        }
        fn get_sys(&self, _: SysReg) -> Result<u64, ()> {
            Err(())
        }
        fn set_sys(&self, _: SysReg, _: u64) -> Result<(), ()> {
            Err(())
        }
        fn step(&self) -> Result<VcpuExit, ()> {
            // Out of script → Halt, so a test that forgets a terminator still ends.
            Ok(self
                .script
                .borrow_mut()
                .pop_front()
                .unwrap_or(VcpuExit::Halt))
        }
        fn complete_read(&self, value: u64) -> Result<(), ()> {
            self.reads.borrow_mut().push(value);
            Ok(())
        }
    }

    /// A device at `[base, base+0x100)` recording writes; reads return `cookie`,
    /// and a write to offset 0 requests `irq`.
    struct FakeDev {
        base: u64,
        irq: u32,
        cookie: u64,
        writes: Vec<(u64, u64)>,
    }
    impl RunDevice for FakeDev {
        fn contains(&self, addr: u64) -> bool {
            addr >= self.base && addr < self.base + 0x100
        }
        fn base(&self) -> u64 {
            self.base
        }
        fn read(&mut self, _offset: u64, _size: u8) -> u64 {
            self.cookie
        }
        fn write(&mut self, offset: u64, value: u64, _size: u8) -> Option<u32> {
            self.writes.push((offset, value));
            (offset == 0).then_some(self.irq)
        }
    }

    fn no_exceptions(_: &ScriptVcpu, _: u64, _: u64) -> Result<RunControl, ()> {
        Ok(RunControl::Stop)
    }

    /// A device whose `poll()` reports an interrupt exactly once — models an
    /// async host→guest delivery (e.g. an egress reply arriving) that the run loop
    /// must drain on a timer tick / heartbeat wake.
    struct PollDev {
        irq: u32,
        polls: u32,
        delivered: bool,
    }
    impl RunDevice for PollDev {
        fn contains(&self, _addr: u64) -> bool {
            false
        }
        fn base(&self) -> u64 {
            0
        }
        fn read(&mut self, _: u64, _: u8) -> u64 {
            0
        }
        fn write(&mut self, _: u64, _: u64, _: u8) -> Option<u32> {
            None
        }
        fn poll(&mut self) -> Option<u32> {
            self.polls += 1;
            if self.delivered {
                None
            } else {
                self.delivered = true;
                Some(self.irq)
            }
        }
    }

    /// A heartbeat wake (`Canceled` with `should_stop()==false`) polls devices,
    /// raises any reported IRQ, and keeps running — it must NOT end the run.
    #[test]
    fn canceled_with_no_stop_polls_then_continues() {
        // Two cancels (heartbeats) then the guest halts.
        let vcpu = ScriptVcpu::new(vec![VcpuExit::Canceled, VcpuExit::Canceled, VcpuExit::Halt]);
        let raised = RefCell::new(Vec::new());
        let mut dev = PollDev {
            irq: 7,
            polls: 0,
            delivered: false,
        };
        let mut devs: Vec<&mut dyn RunDevice> = vec![&mut dev];
        let out = run(
            &vcpu,
            |intid, level| {
                raised.borrow_mut().push((intid, level));
                Ok(())
            },
            &mut devs,
            no_exceptions,
            || false, // never a real stop → cancels are heartbeat wakes
        )
        .unwrap();
        assert_eq!(out, RunOutcome::Halt); // ran to the guest halt, not the cancel
        assert_eq!(*raised.borrow(), vec![(7u32, true)]); // delivered exactly once
        assert_eq!(dev.polls, 2); // polled on each heartbeat wake
    }

    /// A real stop (`Canceled` with `should_stop()==true`) still drains one final
    /// poll, then ends the run as `Canceled`.
    #[test]
    fn canceled_with_stop_polls_then_returns() {
        let vcpu = ScriptVcpu::new(vec![VcpuExit::Canceled]);
        let raised = RefCell::new(Vec::new());
        let mut dev = PollDev {
            irq: 9,
            polls: 0,
            delivered: false,
        };
        let mut devs: Vec<&mut dyn RunDevice> = vec![&mut dev];
        let out = run(
            &vcpu,
            |intid, level| {
                raised.borrow_mut().push((intid, level));
                Ok(())
            },
            &mut devs,
            no_exceptions,
            || true, // real stop
        )
        .unwrap();
        assert_eq!(out, RunOutcome::Canceled);
        assert_eq!(*raised.borrow(), vec![(9u32, true)]); // final drain still delivered
    }

    #[test]
    fn read_is_completed_with_the_device_value() {
        let vcpu = ScriptVcpu::new(vec![
            VcpuExit::Mmio {
                phys_addr: 0x1000,
                write: false,
                len: 4,
                data: 0,
            },
            VcpuExit::Halt,
        ]);
        let mut dev = FakeDev {
            base: 0x1000,
            irq: 7,
            cookie: 0xdead_beef,
            writes: vec![],
        };
        let mut devs: Vec<&mut dyn RunDevice> = vec![&mut dev];
        let out = run(&vcpu, |_, _| Ok(()), &mut devs, no_exceptions, || true).unwrap();
        assert_eq!(out, RunOutcome::Halt);
        assert_eq!(*vcpu.reads.borrow(), vec![0xdead_beef]);
    }

    #[test]
    fn write_reaches_the_device_at_the_right_offset() {
        let vcpu = ScriptVcpu::new(vec![
            VcpuExit::Mmio {
                phys_addr: 0x1010,
                write: true,
                len: 4,
                data: 0x55,
            },
            VcpuExit::Halt,
        ]);
        let mut dev = FakeDev {
            base: 0x1000,
            irq: 7,
            cookie: 0,
            writes: vec![],
        };
        let mut devs: Vec<&mut dyn RunDevice> = vec![&mut dev];
        run(&vcpu, |_, _| Ok(()), &mut devs, no_exceptions, || true).unwrap();
        assert_eq!(dev.writes, vec![(0x10, 0x55)]);
        assert!(
            vcpu.reads.borrow().is_empty(),
            "a write must not complete a read"
        );
    }

    #[test]
    fn a_write_that_triggers_an_irq_raises_the_line() {
        let vcpu = ScriptVcpu::new(vec![
            VcpuExit::Mmio {
                phys_addr: 0x1000,
                write: true,
                len: 4,
                data: 1,
            }, // offset 0 → irq
            VcpuExit::Halt,
        ]);
        let mut dev = FakeDev {
            base: 0x1000,
            irq: 42,
            cookie: 0,
            writes: vec![],
        };
        let mut devs: Vec<&mut dyn RunDevice> = vec![&mut dev];
        let raised = RefCell::new(Vec::new());
        run(
            &vcpu,
            |intid, level| {
                raised.borrow_mut().push((intid, level));
                Ok(())
            },
            &mut devs,
            no_exceptions,
            || true,
        )
        .unwrap();
        assert_eq!(*raised.borrow(), vec![(42u32, true)]);
    }

    #[test]
    fn pio_dispatches_by_port_and_unmapped_reads_as_zero() {
        let vcpu = ScriptVcpu::new(vec![
            VcpuExit::Io {
                port: 0x60,
                write: false,
                size: 1,
                data: 0,
            }, // device at 0x60
            VcpuExit::Mmio {
                phys_addr: 0x9999,
                write: false,
                len: 4,
                data: 0,
            }, // unmapped
            VcpuExit::Halt,
        ]);
        let mut dev = FakeDev {
            base: 0x60,
            irq: 1,
            cookie: 0xab,
            writes: vec![],
        };
        let mut devs: Vec<&mut dyn RunDevice> = vec![&mut dev];
        run(&vcpu, |_, _| Ok(()), &mut devs, no_exceptions, || true).unwrap();
        assert_eq!(*vcpu.reads.borrow(), vec![0xab, 0]); // device value, then RAZ
    }

    #[test]
    fn canceled_exit_ends_the_run() {
        let vcpu = ScriptVcpu::new(vec![VcpuExit::Canceled]);
        let mut devs: Vec<&mut dyn RunDevice> = vec![];
        let out = run(&vcpu, |_, _| Ok(()), &mut devs, no_exceptions, || true).unwrap();
        assert_eq!(out, RunOutcome::Canceled);
    }

    #[test]
    fn exception_hook_can_continue_then_stop() {
        let vcpu = ScriptVcpu::new(vec![
            VcpuExit::Exception {
                syndrome: 0x5a00_0000,
                phys_addr: 0,
            }, // HVC-like
            VcpuExit::Exception {
                syndrome: 0,
                phys_addr: 0,
            },
        ]);
        let mut devs: Vec<&mut dyn RunDevice> = vec![];
        let seen = RefCell::new(0u32);
        // Continue on the first exception, stop on the second.
        let out = run(
            &vcpu,
            |_, _| Ok(()),
            &mut devs,
            |_: &ScriptVcpu, _, _| {
                *seen.borrow_mut() += 1;
                Ok(if *seen.borrow() >= 2 {
                    RunControl::Stop
                } else {
                    RunControl::Continue
                })
            },
            || true,
        )
        .unwrap();
        assert_eq!(out, RunOutcome::Stopped);
        assert_eq!(*seen.borrow(), 2);
    }

    #[test]
    fn vtimer_is_ignored_and_the_loop_continues() {
        let vcpu = ScriptVcpu::new(vec![VcpuExit::VTimer, VcpuExit::VTimer, VcpuExit::Halt]);
        let mut devs: Vec<&mut dyn RunDevice> = vec![];
        let out = run(&vcpu, |_, _| Ok(()), &mut devs, no_exceptions, || true).unwrap();
        assert_eq!(out, RunOutcome::Halt);
    }
}
