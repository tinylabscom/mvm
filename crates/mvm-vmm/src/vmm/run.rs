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

use std::time::Duration;

use super::device_state::SnapshotDeviceState;
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

    /// Drop host-owned handles before a paused snapshot is serialized.
    ///
    /// Most devices have no host handles. The vsock device overrides this to
    /// stop its host-I/O owner and clear host bindings; those are recreated
    /// explicitly for a restored child.
    fn prepare_snapshot(&mut self) {}

    /// Expose deterministic device state to the pause snapshot hook.
    fn snapshot_device(&self) -> Option<&dyn SnapshotDeviceState> {
        None
    }

    /// Expose a mutable deterministic device-state target for restore.
    fn snapshot_device_mut(&mut self) -> Option<&mut dyn SnapshotDeviceState> {
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

/// Exclusive access to the device model, for as long as one access takes.
///
/// The run loop reaches devices only through this, so the same loop body serves
/// a machine with one vCPU and a machine with several. With one, the devices are
/// borrowed directly and nothing is locked. With several, every vCPU thread
/// shares one device model and the bus is what serialises them: the device
/// structs hold queue indices and raw pointers into guest RAM, and two CPUs
/// servicing a virtqueue at once would corrupt both.
///
/// Deliberately scoped to a single access rather than handed out as a guard. A
/// guard could be held across a sleep or a blocking read, and one vCPU parked in
/// the pause hold while holding the device model would freeze every other CPU
/// with it. Passing a closure makes the narrow hold the only thing expressible.
pub trait DeviceBus {
    /// Run `f` with exclusive access to every device.
    fn with_devices<R>(&self, f: impl FnOnce(&mut [&mut dyn RunDevice]) -> R) -> R;
}

/// The device model of a single-vCPU machine, borrowed by the one thread that
/// drives it.
///
/// A `RefCell` rather than a `Mutex`: there is no second thread to exclude, so
/// paying for an atomic on every MMIO exit would buy nothing. The borrow is
/// checked all the same, which is what catches a re-entrant `with_devices` —
/// a device whose handler dispatched back into the bus would deadlock a `Mutex`
/// silently and panics here instead.
pub struct SoleBus<'a, 'd> {
    devices: core::cell::RefCell<&'a mut [&'d mut dyn RunDevice]>,
}

impl<'a, 'd> SoleBus<'a, 'd> {
    /// Borrow `devices` for the run.
    pub fn new(devices: &'a mut [&'d mut dyn RunDevice]) -> Self {
        Self {
            devices: core::cell::RefCell::new(devices),
        }
    }
}

impl DeviceBus for SoleBus<'_, '_> {
    fn with_devices<R>(&self, f: impl FnOnce(&mut [&mut dyn RunDevice]) -> R) -> R {
        f(&mut self.devices.borrow_mut()[..])
    }
}

/// The device model of an SMP machine, shared by every vCPU thread.
///
/// One lock over all devices rather than one per device. MMIO exits are rare
/// next to the guest execution between them and each access is a register
/// read or a queue kick, so the contention a coarse lock costs is not
/// measurable — while the bugs a fine-grained one invites (two CPUs in two
/// devices reaching the same guest page) are not the kind that show up in
/// testing.
pub struct SharedBus<'a, 'd> {
    devices: std::sync::Mutex<&'a mut [&'d mut dyn RunDevice]>,
}

impl<'a, 'd> SharedBus<'a, 'd> {
    /// Share `devices` across the vCPU threads of one run.
    pub fn new(devices: &'a mut [&'d mut dyn RunDevice]) -> Self {
        Self {
            devices: std::sync::Mutex::new(devices),
        }
    }
}

impl DeviceBus for SharedBus<'_, '_> {
    fn with_devices<R>(&self, f: impl FnOnce(&mut [&mut dyn RunDevice]) -> R) -> R {
        // A poisoned device model cannot be reasoned about: a panic mid-access
        // leaves a virtqueue half-updated, and the guest has already been told
        // the descriptor was consumed. Take the inner value and let the caller
        // fail rather than resuming against state nothing has validated.
        let mut guard = self
            .devices
            .lock()
            .expect("device model poisoned by a panicking vCPU thread");
        f(&mut guard[..])
    }
}

// SAFETY: `RunDevice` implementors in this crate are not `Send` because they
// hold raw `*mut u8` pointers into guest RAM. Sharing them across the vCPU
// threads of one VM is sound for the reasons the pointer is sound at all:
//
// - The pointee is the single `hv_vm_map`ped guest RAM allocation, which
//   outlives every vCPU thread. The threads are scoped (`std::thread::scope`),
//   so they are joined before the mapping is torn down or the allocation freed.
// - Every access goes through `with_devices`, which holds the `Mutex`, so no
//   two threads touch a device — or the RAM it points into — concurrently.
// - The pointer is not thread-affine. It addresses a plain shared mapping, not
//   a thread-local or a handle bound to the thread that opened it, so reading
//   it from a different thread than the one that formed it is well defined.
//
// This is the same argument `GuestMem` makes one module over, for the same
// allocation.
unsafe impl Send for SharedBus<'_, '_> {}
// SAFETY: as above — `&SharedBus` grants access only through the `Mutex`, so
// sharing the reference is exactly as safe as sending the value.
unsafe impl Sync for SharedBus<'_, '_> {}

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
/// - `should_pause()` parks the vCPU without ending the run: when it returns
///   `true` (and no stop is pending) after a forced exit, the loop holds the vCPU
///   out of guest execution — polling once first, then sleeping — so guest RAM and
///   device state freeze in place until the pause clears (resume) or a stop
///   arrives. Backends with no pause primitive pass `|| false`.
///
/// The hooks the run loop consults. A struct rather than more positional
/// arguments: the loop already takes seven, and an eighth would trip the
/// argument-count lint this repo bans exceptions to.
pub struct RunHooks<C, X, Q, P, H, T>
where
    C: HypervisorVcpu,
    X: FnMut(&C, u64, u64) -> Result<RunControl, C::Error>,
    Q: Fn() -> bool,
    P: Fn() -> bool,
    H: FnMut(&C, &[&dyn SnapshotDeviceState]) -> Result<(), C::Error>,
    T: Fn() -> bool,
{
    pub on_exception: X,
    pub should_stop: Q,
    pub should_pause: P,
    pub on_pause: H,
    /// True while the vCPU must be held out of guest execution to stay inside
    /// its CPU quota. Polled like `should_pause`, but parks the vCPU without
    /// touching any snapshot machinery.
    pub should_throttle: T,
    pub _marker: std::marker::PhantomData<fn() -> C>,
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
/// - `should_pause()` parks the vCPU without ending the run: when it returns
///   `true` (and no stop is pending) after a forced exit, the loop holds the vCPU
///   out of guest execution — polling once first, then sleeping — so guest RAM and
///   device state freeze in place until the pause clears (resume) or a stop
///   arrives. Backends with no pause primitive pass `|| false`.
pub fn run<C, S, X, Q, P>(
    vcpu: &C,
    set_irq: S,
    devices: &mut [&mut dyn RunDevice],
    on_exception: X,
    should_stop: Q,
    should_pause: P,
) -> Result<RunOutcome, C::Error>
where
    C: HypervisorVcpu,
    S: Fn(u32, bool) -> Result<(), C::Error>,
    X: FnMut(&C, u64, u64) -> Result<RunControl, C::Error>,
    Q: Fn() -> bool,
    P: Fn() -> bool,
{
    run_with_pause_hook(
        vcpu,
        set_irq,
        devices,
        on_exception,
        should_stop,
        should_pause,
        |_, _| Ok(()),
    )
}

/// Run a vCPU and invoke `on_pause` while the vCPU is held outside guest
/// execution. The hook is called repeatedly until the pause request clears so
/// a host control plane can publish a snapshot asynchronously after the pause
/// acknowledgement arrives.
pub fn run_with_pause_hook<C, S, X, Q, P, H>(
    vcpu: &C,
    set_irq: S,
    devices: &mut [&mut dyn RunDevice],
    on_exception: X,
    should_stop: Q,
    should_pause: P,
    on_pause: H,
) -> Result<RunOutcome, C::Error>
where
    C: HypervisorVcpu,
    S: Fn(u32, bool) -> Result<(), C::Error>,
    X: FnMut(&C, u64, u64) -> Result<RunControl, C::Error>,
    Q: Fn() -> bool,
    P: Fn() -> bool,
    H: FnMut(&C, &[&dyn SnapshotDeviceState]) -> Result<(), C::Error>,
{
    run_with_hooks(
        vcpu,
        set_irq,
        devices,
        RunHooks {
            on_exception,
            should_stop,
            should_pause,
            on_pause,
            should_throttle: || false,
            _marker: std::marker::PhantomData,
        },
    )
}

/// Run a vCPU with the full hook set. This is the single implementation shared
/// by [`run`] and [`run_with_pause_hook`]; callers that need a throttle hold
/// supply a `should_throttle` predicate.
pub fn run_with_hooks<C, S, X, Q, P, H, T>(
    vcpu: &C,
    set_irq: S,
    devices: &mut [&mut dyn RunDevice],
    hooks: RunHooks<C, X, Q, P, H, T>,
) -> Result<RunOutcome, C::Error>
where
    C: HypervisorVcpu,
    S: Fn(u32, bool) -> Result<(), C::Error>,
    X: FnMut(&C, u64, u64) -> Result<RunControl, C::Error>,
    Q: Fn() -> bool,
    P: Fn() -> bool,
    H: FnMut(&C, &[&dyn SnapshotDeviceState]) -> Result<(), C::Error>,
    T: Fn() -> bool,
{
    run_on_bus(vcpu, set_irq, &SoleBus::new(devices), hooks)
}

/// Run one vCPU against a device model reached through `bus`.
///
/// The single loop body, shared by every backend and by every vCPU of an SMP
/// machine. It differs from [`run_with_hooks`] only in reaching devices through
/// the bus rather than owning them, which is what lets several threads drive it
/// at once.
///
/// Each device touch takes the bus for exactly that touch. The two hold loops
/// below — pause and throttle — sleep *outside* it: this vCPU is parked, and
/// keeping the device model to itself while it sleeps would park every other
/// vCPU behind it.
pub fn run_on_bus<C, S, B, X, Q, P, H, T>(
    vcpu: &C,
    set_irq: S,
    bus: &B,
    mut hooks: RunHooks<C, X, Q, P, H, T>,
) -> Result<RunOutcome, C::Error>
where
    C: HypervisorVcpu,
    S: Fn(u32, bool) -> Result<(), C::Error>,
    B: DeviceBus,
    X: FnMut(&C, u64, u64) -> Result<RunControl, C::Error>,
    Q: Fn() -> bool,
    P: Fn() -> bool,
    H: FnMut(&C, &[&dyn SnapshotDeviceState]) -> Result<(), C::Error>,
    T: Fn() -> bool,
{
    /// Poll every device once and raise whatever interrupts they ask for.
    fn poll_all<C, S, B>(bus: &B, set_irq: &S) -> Result<(), C::Error>
    where
        C: HypervisorVcpu,
        S: Fn(u32, bool) -> Result<(), C::Error>,
        B: DeviceBus,
    {
        // Collect under the bus, raise outside it: `set_irq` is the backend's
        // interrupt controller, and holding the device model across it would
        // widen the hold for no reason.
        let irqs = bus.with_devices(|devices| {
            devices
                .iter_mut()
                .filter_map(|d| d.poll())
                .collect::<Vec<_>>()
        });
        for irq in irqs {
            set_irq(irq, true)?;
        }
        Ok(())
    }

    let mut pause_prepared = false;
    loop {
        match vcpu.step()? {
            VcpuExit::VTimer => {
                // Host→guest async work each timer tick (e.g. drain an egress
                // socket into the guest's rx queue), so delivery happens even
                // when the guest is idle in WFI rather than doing MMIO.
                poll_all::<C, _, _>(bus, &set_irq)?;
            }
            VcpuExit::Canceled => {
                // A forced exit: either a real stop or a heartbeat wake. Poll
                // host-side async work either way (this is how an egress reply
                // reaches a guest blocked in WFI), then end only if a stop was
                // actually requested.
                poll_all::<C, _, _>(bus, &set_irq)?;
                if (hooks.should_stop)() {
                    return Ok(RunOutcome::Canceled);
                }
                // Pause hold: a pause request parks the vCPU here, out of guest
                // execution, so RAM and device state stay frozen until resume
                // clears the pause (or a stop arrives). The device poll above
                // already drained any in-flight host reply before we park.
                if (hooks.should_pause)() {
                    if !pause_prepared {
                        bus.with_devices(|devices| {
                            for device in devices.iter_mut() {
                                device.prepare_snapshot();
                            }
                        });
                        pause_prepared = true;
                    }
                    bus.with_devices(|devices| {
                        let snapshot_devices = devices
                            .iter()
                            .filter_map(|device| device.snapshot_device())
                            .collect::<Vec<_>>();
                        (hooks.on_pause)(vcpu, &snapshot_devices)
                    })?;
                } else {
                    pause_prepared = false;
                }
                while (hooks.should_pause)() && !(hooks.should_stop)() {
                    poll_all::<C, _, _>(bus, &set_irq)?;
                    bus.with_devices(|devices| {
                        let snapshot_devices = devices
                            .iter()
                            .filter_map(|device| device.snapshot_device())
                            .collect::<Vec<_>>();
                        (hooks.on_pause)(vcpu, &snapshot_devices)
                    })?;
                    std::thread::sleep(Duration::from_millis(1));
                }
                // Throttle hold: a throttle is not a pause. The vCPU is parked
                // to stay inside its CPU quota, and the guest's device state
                // must survive it untouched. Devices are still polled every
                // millisecond so host→guest I/O keeps flowing while the vCPU is
                // out of guest execution; nothing else from the pause path runs.
                while (hooks.should_throttle)() && !(hooks.should_stop)() && !(hooks.should_pause)()
                {
                    poll_all::<C, _, _>(bus, &set_irq)?;
                    std::thread::sleep(Duration::from_millis(1));
                }
                // A stop that arrived while we were throttled must still end the
                // run as Canceled, even if the next vCPU step would otherwise
                // return Halt.
                if (hooks.should_stop)() {
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
                bus.with_devices(|devices| {
                    dispatch(vcpu, &set_irq, devices, phys_addr, write, len, data)
                })?;
            }
            VcpuExit::Io {
                port,
                write,
                size,
                data,
            } => {
                bus.with_devices(|devices| {
                    dispatch(
                        vcpu,
                        &set_irq,
                        devices,
                        u64::from(port),
                        write,
                        size,
                        u64::from(data),
                    )
                })?;
            }
            VcpuExit::Exception {
                syndrome,
                phys_addr,
            } => {
                if (hooks.on_exception)(vcpu, syndrome, phys_addr)? == RunControl::Stop {
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
    fn snapshot_device(&self) -> Option<&dyn SnapshotDeviceState> {
        Some(self)
    }
    fn snapshot_device_mut(&mut self) -> Option<&mut dyn SnapshotDeviceState> {
        Some(self)
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
    fn snapshot_device(&self) -> Option<&dyn SnapshotDeviceState> {
        Some(self)
    }
    fn snapshot_device_mut(&mut self) -> Option<&mut dyn SnapshotDeviceState> {
        Some(self)
    }
}

impl RunDevice for super::virtio::VirtioFs {
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
    fn snapshot_device(&self) -> Option<&dyn SnapshotDeviceState> {
        Some(self)
    }
    fn snapshot_device_mut(&mut self) -> Option<&mut dyn SnapshotDeviceState> {
        Some(self)
    }
}

impl RunDevice for super::virtio_rng::VirtioRng {
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
    fn snapshot_device(&self) -> Option<&dyn SnapshotDeviceState> {
        Some(self)
    }
    fn snapshot_device_mut(&mut self) -> Option<&mut dyn SnapshotDeviceState> {
        Some(self)
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
        super::vsock::VirtioVsock::write(self, offset, value).then(|| self.irq())
    }
    fn poll(&mut self) -> Option<u32> {
        // Host→guest work: relay host-initiated agent streams and drain
        // egress-endpoint replies. On HVF the dedicated host-I/O thread
        // ([`super::vsock_io`]) drives this reliably off the vCPU exit path; this
        // run-loop path remains a fallback (e.g. KVM) and is a harmless no-op when
        // the I/O thread already serviced everything (both run under the lock).
        super::vsock::VirtioVsock::poll(self)
    }
    fn prepare_snapshot(&mut self) {
        super::vsock::VirtioVsock::prepare_snapshot(self);
    }
    fn snapshot_device(&self) -> Option<&dyn SnapshotDeviceState> {
        Some(self)
    }
    fn snapshot_device_mut(&mut self) -> Option<&mut dyn SnapshotDeviceState> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::super::hv::{CoreReg, SysReg, VcpuHandle};
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
            || false, // no pause
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
            || true,  // real stop
            || false, // no pause
        )
        .unwrap();
        assert_eq!(out, RunOutcome::Canceled);
        assert_eq!(*raised.borrow(), vec![(9u32, true)]); // final drain still delivered
    }

    #[test]
    fn canceled_with_pause_holds_until_resume_then_continues() {
        let vcpu = ScriptVcpu::new(vec![VcpuExit::Canceled, VcpuExit::Halt]);
        let mut devs: Vec<&mut dyn RunDevice> = vec![];
        let paused = Arc::new(AtomicBool::new(true));
        let paused_for_resume = Arc::clone(&paused);
        let resume = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(60));
            paused_for_resume.store(false, Ordering::SeqCst);
        });

        let started = std::time::Instant::now();
        let out = run(
            &vcpu,
            |_, _| Ok(()),
            &mut devs,
            no_exceptions,
            || false,
            || paused.load(Ordering::SeqCst),
        )
        .unwrap();
        resume.join().unwrap();

        assert_eq!(out, RunOutcome::Halt);
        assert!(
            started.elapsed() >= Duration::from_millis(40),
            "pause hold should keep the vCPU out of guest execution until resume"
        );
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
        let out = run(
            &vcpu,
            |_, _| Ok(()),
            &mut devs,
            no_exceptions,
            || true,
            || false,
        )
        .unwrap();
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
        run(
            &vcpu,
            |_, _| Ok(()),
            &mut devs,
            no_exceptions,
            || true,
            || false,
        )
        .unwrap();
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
            || false,
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
        run(
            &vcpu,
            |_, _| Ok(()),
            &mut devs,
            no_exceptions,
            || true,
            || false,
        )
        .unwrap();
        assert_eq!(*vcpu.reads.borrow(), vec![0xab, 0]); // device value, then RAZ
    }

    #[test]
    fn canceled_exit_ends_the_run() {
        let vcpu = ScriptVcpu::new(vec![VcpuExit::Canceled]);
        let mut devs: Vec<&mut dyn RunDevice> = vec![];
        let out = run(
            &vcpu,
            |_, _| Ok(()),
            &mut devs,
            no_exceptions,
            || true,
            || false,
        )
        .unwrap();
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
            || false,
        )
        .unwrap();
        assert_eq!(out, RunOutcome::Stopped);
        assert_eq!(*seen.borrow(), 2);
    }

    #[test]
    fn vtimer_is_ignored_and_the_loop_continues() {
        let vcpu = ScriptVcpu::new(vec![VcpuExit::VTimer, VcpuExit::VTimer, VcpuExit::Halt]);
        let mut devs: Vec<&mut dyn RunDevice> = vec![];
        let out = run(
            &vcpu,
            |_, _| Ok(()),
            &mut devs,
            no_exceptions,
            || true,
            || false,
        )
        .unwrap();
        assert_eq!(out, RunOutcome::Halt);
    }

    /// Regression for the host→guest poll-starvation bug: the dedicated vsock I/O
    /// thread must service a host connection even when the guest produces ONLY
    /// `Mmio` exits (no `VTimer`/`Canceled`, so the run loop's `poll()` fallback is
    /// never invoked). Before the fix, host servicing rode on `poll()` and was
    /// starved under MMIO load, so the agent connection was never accepted.
    #[test]
    fn vsock_io_thread_services_host_under_sustained_mmio() {
        use super::super::vsock::{IrqLine, VirtioVsock};
        use crate::test_support::error_chain_has_permission_denied;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountIrq(AtomicU32);
        impl IrqLine for CountIrq {
            fn signal(&self, _spi: u32) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Guest RAM for the device (freed only after the device — and its joined I/O
        // thread — drop at end of the test).
        let mut ram = vec![0u8; 0x10000];
        let base = 0x0a00_0200u64;
        // SAFETY: `ram` outlives `dev`; the device joins its I/O thread on drop
        // before `ram` is freed.
        let mut dev =
            unsafe { VirtioVsock::new(base, 49, ram.as_mut_ptr(), 0x4000_0000, ram.len()) };

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        if let Err(err) = dev.set_agent_socket(&sock) {
            if error_chain_has_permission_denied(&err) {
                eprintln!(
                    "skipping test: sandbox denied agent socket setup at {}: {err}",
                    sock.display()
                );
                return;
            }
            panic!("agent socket setup failed at {}: {err}", sock.display());
        }
        dev.start_io(Arc::new(CountIrq(AtomicU32::new(0))));

        // A host RPC client connects. No rx buffers are posted, so the framed
        // OP_REQUEST stays queued — observable via `queued_host_packets`.
        let _client = std::os::unix::net::UnixStream::connect(&sock).unwrap();

        // Drive the run loop with ONLY `Mmio` exits (reads of the vsock magic
        // register) then `Halt`. The `poll()` fallback fires only on
        // `VTimer`/`Canceled`, neither of which appears here.
        let mut script = Vec::new();
        for _ in 0..50 {
            script.push(VcpuExit::Mmio {
                phys_addr: base,
                write: false,
                len: 4,
                data: 0,
            });
        }
        script.push(VcpuExit::Halt);
        let vcpu = ScriptVcpu::new(script);
        {
            let mut devs: Vec<&mut dyn RunDevice> = vec![&mut dev];
            let out = run(
                &vcpu,
                |_, _| Ok(()),
                &mut devs,
                no_exceptions,
                || true,
                || false,
            )
            .unwrap();
            assert_eq!(out, RunOutcome::Halt);
        }

        // The I/O thread (readiness + 5 ms backstop) accepts the connection and
        // frames its OP_REQUEST entirely off the vCPU exit path.
        let mut serviced = false;
        for _ in 0..400 {
            if dev.queued_host_packets() > 0 {
                serviced = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            serviced,
            "the I/O thread must accept the host connection under pure-MMIO activity"
        );
    }

    /// A device that counts how many times the snapshot machinery touches it.
    struct SnapshotCountDev {
        prepare_count: RefCell<usize>,
    }

    impl SnapshotCountDev {
        fn new() -> Self {
            Self {
                prepare_count: RefCell::new(0),
            }
        }
        fn prepare_count(&self) -> usize {
            *self.prepare_count.borrow()
        }
    }

    impl RunDevice for SnapshotCountDev {
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
        fn prepare_snapshot(&mut self) {
            *self.prepare_count.borrow_mut() += 1;
        }
        fn snapshot_device(&self) -> Option<&dyn SnapshotDeviceState> {
            Some(self)
        }
    }

    impl SnapshotDeviceState for SnapshotCountDev {
        fn device_kind(&self) -> super::super::device_state::DeviceKind {
            super::super::device_state::DeviceKind::Unknown(99)
        }
        fn snapshot_state(&self) -> Result<Vec<u8>, super::super::device_state::DeviceStateError> {
            Ok(vec![0])
        }
        fn restore_state(
            &mut self,
            _bytes: &[u8],
        ) -> Result<(), super::super::device_state::DeviceStateError> {
            Ok(())
        }
    }

    /// A device that counts how many times `poll()` is called.
    struct PollCountDev {
        polls: RefCell<usize>,
    }

    impl PollCountDev {
        fn new() -> Self {
            Self {
                polls: RefCell::new(0),
            }
        }
        fn polls(&self) -> usize {
            *self.polls.borrow()
        }
    }

    impl RunDevice for PollCountDev {
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
            *self.polls.borrow_mut() += 1;
            None
        }
    }

    #[test]
    fn a_throttle_hold_parks_the_vcpu_until_it_clears() {
        let vcpu = ScriptVcpu::new(vec![VcpuExit::Canceled, VcpuExit::Halt]);
        let mut devs: Vec<&mut dyn RunDevice> = vec![];
        let throttle = Arc::new(AtomicBool::new(true));
        let throttle_for_clear = Arc::clone(&throttle);
        let clear = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(60));
            throttle_for_clear.store(false, Ordering::SeqCst);
        });

        let started = std::time::Instant::now();
        let out = run_with_hooks(
            &vcpu,
            |_, _| Ok(()),
            &mut devs,
            RunHooks {
                _marker: std::marker::PhantomData,
                on_exception: no_exceptions,
                should_stop: || false,
                should_pause: || false,
                on_pause: |_, _| Ok(()),
                should_throttle: || throttle.load(Ordering::SeqCst),
            },
        )
        .unwrap();
        clear.join().unwrap();

        assert_eq!(out, RunOutcome::Halt);
        assert!(
            started.elapsed() >= Duration::from_millis(40),
            "throttle hold should keep the vCPU out of guest execution until it clears"
        );
    }

    #[test]
    fn a_throttle_hold_never_prepares_a_snapshot() {
        let vcpu = ScriptVcpu::new(vec![VcpuExit::Canceled, VcpuExit::Halt]);
        let mut dev = SnapshotCountDev::new();
        let mut devs: Vec<&mut dyn RunDevice> = vec![&mut dev];
        let throttle = Arc::new(AtomicBool::new(true));
        let throttle_for_clear = Arc::clone(&throttle);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            throttle_for_clear.store(false, Ordering::SeqCst);
        });

        run_with_hooks(
            &vcpu,
            |_, _| Ok(()),
            &mut devs,
            RunHooks {
                _marker: std::marker::PhantomData,
                on_exception: no_exceptions,
                should_stop: || false,
                should_pause: || false,
                on_pause: |_, _| Ok(()),
                should_throttle: || throttle.load(Ordering::SeqCst),
            },
        )
        .unwrap();

        assert_eq!(
            dev.prepare_count(),
            0,
            "throttle hold must not prepare a snapshot"
        );

        // And a pause hold on the same device does prepare one.
        let vcpu2 = ScriptVcpu::new(vec![VcpuExit::Canceled, VcpuExit::Halt]);
        let mut dev2 = SnapshotCountDev::new();
        let mut devs2: Vec<&mut dyn RunDevice> = vec![&mut dev2];
        let paused = Arc::new(AtomicBool::new(true));
        let paused_for_resume = Arc::clone(&paused);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            paused_for_resume.store(false, Ordering::SeqCst);
        });
        run(
            &vcpu2,
            |_, _| Ok(()),
            &mut devs2,
            no_exceptions,
            || false,
            || paused.load(Ordering::SeqCst),
        )
        .unwrap();
        assert!(
            dev2.prepare_count() > 0,
            "pause hold must prepare a snapshot"
        );
    }

    #[test]
    fn a_throttle_hold_never_calls_the_pause_hook() {
        let vcpu = ScriptVcpu::new(vec![VcpuExit::Canceled, VcpuExit::Halt]);
        let mut devs: Vec<&mut dyn RunDevice> = vec![];
        let throttle = Arc::new(AtomicBool::new(true));
        let throttle_for_clear = Arc::clone(&throttle);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            throttle_for_clear.store(false, Ordering::SeqCst);
        });
        let pause_calls = Arc::new(AtomicUsize::new(0));
        let pause_calls_for_hook = Arc::clone(&pause_calls);

        run_with_hooks(
            &vcpu,
            |_, _| Ok(()),
            &mut devs,
            RunHooks {
                _marker: std::marker::PhantomData,
                on_exception: no_exceptions,
                should_stop: || false,
                should_pause: || false,
                on_pause: move |_, _| {
                    pause_calls_for_hook.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                should_throttle: || throttle.load(Ordering::SeqCst),
            },
        )
        .unwrap();

        assert_eq!(
            pause_calls.load(Ordering::SeqCst),
            0,
            "throttle hold must not call the pause hook"
        );
    }

    #[test]
    fn a_throttle_hold_keeps_polling_devices() {
        let vcpu = ScriptVcpu::new(vec![VcpuExit::Canceled, VcpuExit::Halt]);
        let mut dev = PollCountDev::new();
        let mut devs: Vec<&mut dyn RunDevice> = vec![&mut dev];
        let throttle = Arc::new(AtomicBool::new(true));
        let throttle_for_clear = Arc::clone(&throttle);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            throttle_for_clear.store(false, Ordering::SeqCst);
        });

        run_with_hooks(
            &vcpu,
            |_, _| Ok(()),
            &mut devs,
            RunHooks {
                _marker: std::marker::PhantomData,
                on_exception: no_exceptions,
                should_stop: || false,
                should_pause: || false,
                on_pause: |_, _| Ok(()),
                should_throttle: || throttle.load(Ordering::SeqCst),
            },
        )
        .unwrap();

        assert!(
            dev.polls() >= 10,
            "device poll count {} should rise during a throttle hold",
            dev.polls()
        );
    }

    #[test]
    fn a_stop_breaks_a_throttle_hold() {
        let vcpu = ScriptVcpu::new(vec![VcpuExit::Canceled, VcpuExit::Halt]);
        let mut devs: Vec<&mut dyn RunDevice> = vec![];
        let throttle = Arc::new(AtomicBool::new(true));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_set = Arc::clone(&stop);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            stop_for_set.store(true, Ordering::SeqCst);
        });

        let started = std::time::Instant::now();
        let out = run_with_hooks(
            &vcpu,
            |_, _| Ok(()),
            &mut devs,
            RunHooks {
                _marker: std::marker::PhantomData,
                on_exception: no_exceptions,
                should_stop: || stop.load(Ordering::SeqCst),
                should_pause: || false,
                on_pause: |_, _| Ok(()),
                should_throttle: || throttle.load(Ordering::SeqCst),
            },
        )
        .unwrap();

        assert_eq!(out, RunOutcome::Canceled);
        assert!(
            started.elapsed() >= Duration::from_millis(30),
            "stop should have held the throttle at least 30 ms"
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "stop should break the throttle hold promptly"
        );
    }

    #[test]
    fn a_pause_during_a_throttle_takes_precedence() {
        let vcpu = ScriptVcpu::new(vec![VcpuExit::Canceled, VcpuExit::Canceled, VcpuExit::Halt]);
        let mut dev = SnapshotCountDev::new();
        let mut devs: Vec<&mut dyn RunDevice> = vec![&mut dev];
        let throttle = Arc::new(AtomicBool::new(true));
        let pause = Arc::new(AtomicBool::new(false));
        let throttle_for_thread = Arc::clone(&throttle);
        let pause_for_thread = Arc::clone(&pause);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            throttle_for_thread.store(false, Ordering::SeqCst);
            pause_for_thread.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(30));
            pause_for_thread.store(false, Ordering::SeqCst);
        });
        let pause_calls = Arc::new(AtomicUsize::new(0));
        let pause_calls_for_hook = Arc::clone(&pause_calls);

        let started = std::time::Instant::now();
        let out = run_with_hooks(
            &vcpu,
            |_, _| Ok(()),
            &mut devs,
            RunHooks {
                _marker: std::marker::PhantomData,
                on_exception: no_exceptions,
                should_stop: || false,
                should_pause: || pause.load(Ordering::SeqCst),
                on_pause: move |_, _| {
                    pause_calls_for_hook.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                should_throttle: || throttle.load(Ordering::SeqCst),
            },
        )
        .unwrap();

        assert_eq!(out, RunOutcome::Halt);
        assert!(
            started.elapsed() >= Duration::from_millis(50),
            "pause hold should extend the park"
        );
        assert!(
            dev.prepare_count() > 0,
            "pause machinery must run when pause takes over"
        );
        assert!(
            pause_calls.load(Ordering::SeqCst) > 0,
            "pause hook must run when pause takes over"
        );
    }

    #[test]
    fn the_existing_entry_points_throttle_never() {
        let vcpu = ScriptVcpu::new(vec![VcpuExit::Canceled, VcpuExit::Halt]);
        let mut devs: Vec<&mut dyn RunDevice> = vec![];
        let paused = Arc::new(AtomicBool::new(true));
        let paused_for_resume = Arc::clone(&paused);
        let resume = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(60));
            paused_for_resume.store(false, Ordering::SeqCst);
        });

        let started = std::time::Instant::now();
        let out = run(
            &vcpu,
            |_, _| Ok(()),
            &mut devs,
            no_exceptions,
            || false,
            || paused.load(Ordering::SeqCst),
        )
        .unwrap();
        resume.join().unwrap();

        assert_eq!(out, RunOutcome::Halt);
        assert!(
            started.elapsed() >= Duration::from_millis(40),
            "run() must still honor pause"
        );
    }
}
