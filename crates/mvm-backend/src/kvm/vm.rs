//! KVM implementation of the portable hypervisor seam ([`crate::vmm::hv`]).
//!
//! `KvmVm` / `KvmVcpu` are thin wrappers over `kvm-ioctls`, binding the Linux
//! backend to the same `HypervisorVm`/`HypervisorVcpu` contract HVF implements.
//! The x86 boot register setup lives outside the (aarch64) register seam — see
//! [`KvmVm::boot_x86`], which applies [`x86_boot::BootRegs`] directly. Lifecycle,
//! mapping, IRQ, boot, exit decoding, and read-completion (`complete_read` fills
//! the `kvm_run` data buffer so the kernel finishes a load on re-entry) are all
//! wired here.

use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use kvm_bindings::{
    KVM_MAX_CPUID_ENTRIES, kvm_pit_config, kvm_segment, kvm_userspace_memory_region,
};
use kvm_ioctls::{Kvm, VcpuExit as KvmExit, VcpuFd, VmFd};

use super::serial::Serial16550;
use super::x86_boot;
use crate::vmm::egress_gate::EgressGate;
use crate::vmm::hv::{CoreReg, HypervisorVcpu, HypervisorVm, SysReg, VcpuExit, VcpuHandle};
use crate::vmm::run::{self, RunControl, RunDevice};
use crate::vmm::vsock::VirtioVsock;

/// virtio-mmio window for the guest's vsock device (above RAM, below the 4 GiB
/// PCI hole) and its IOAPIC GSI. The guest learns it from the kernel cmdline arg
/// [`vsock_mmio_cmdline_arg`]; the run loop dispatches MMIO here to [`VirtioVsock`].
pub const VSOCK_MMIO_BASE: u64 = 0xd000_0000;
pub const VSOCK_MMIO_LEN: u64 = 0x200;
pub const VSOCK_IRQ: u32 = 5;

/// Kernel cmdline fragment that tells the guest where the vsock virtio-mmio device
/// is (`virtio_mmio.device=<size>@<base>:<irq>`). The caller appends this to
/// `BootConfig.cmdline` so the guest binds `virtio_vsock` on the right window.
pub fn vsock_mmio_cmdline_arg() -> String {
    format!("virtio_mmio.device={VSOCK_MMIO_LEN:#x}@{VSOCK_MMIO_BASE:#x}:{VSOCK_IRQ}")
}

/// Outcome of an egress-enabled KVM boot.
#[derive(Debug, Default)]
pub struct KvmEgressResult {
    /// Bytes the guest emitted on the 16550 console.
    pub console: Vec<u8>,
    /// Workload exit code, if the guest reported one over the vsock workload-exit
    /// port (the transient run-to-exit signal).
    pub workload_exit_code: Option<i32>,
    /// Egress targets the vsock gateway refused (claim-10 default-deny).
    pub egress_denied: Vec<String>,
    /// Egress targets the vsock gateway admitted + connected.
    pub egress_allowed: Vec<String>,
}

/// Backend-native error.
#[derive(Debug)]
pub enum KvmError {
    Kvm(kvm_ioctls::Error),
    Boot(x86_boot::BootError),
    /// A seam method that does not apply to the x86_64 KVM backend (the aarch64
    /// register accessors; x86 boot regs are set via [`KvmVm::boot_x86`]).
    Unsupported(&'static str),
}

impl std::fmt::Display for KvmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KvmError::Kvm(e) => write!(f, "kvm: {e}"),
            KvmError::Boot(e) => write!(f, "boot: {e}"),
            KvmError::Unsupported(m) => write!(f, "unsupported on x86_64 KVM: {m}"),
        }
    }
}
impl std::error::Error for KvmError {}
impl From<kvm_ioctls::Error> for KvmError {
    fn from(e: kvm_ioctls::Error) -> Self {
        KvmError::Kvm(e)
    }
}
impl From<x86_boot::BootError> for KvmError {
    fn from(e: x86_boot::BootError) -> Self {
        KvmError::Boot(e)
    }
}

/// A KVM VM: owns `/dev/kvm` + the VM fd and its in-kernel irqchip + PIT.
pub struct KvmVm {
    kvm: Kvm,
    vm: VmFd,
    next_slot: AtomicU32,
    next_id: AtomicU64,
}

impl KvmVm {
    /// Load an x86_64 `bzImage` (+ optional initramfs) into `mem` and return a
    /// vCPU primed at the kernel's long-mode entry. `mem` must already be mapped
    /// via [`HypervisorVm::map_ram`] at gpa 0. x86-specific: the entry register
    /// state is applied directly, not through the aarch64 register seam.
    pub fn boot_x86(
        &self,
        mem: &mut [u8],
        cfg: &x86_boot::BootConfig,
    ) -> Result<KvmVcpu, KvmError> {
        let regs = x86_boot::setup_boot(mem, cfg)?;
        let vcpu = self.create_vcpu()?;
        vcpu.apply_boot_regs(&regs)?;
        Ok(vcpu)
    }

    /// Boot an x86_64 bzImage already loaded in `mem` (mapped at gpa 0 via
    /// [`HypervisorVm::map_ram`]) and drive it through the unified run loop
    /// ([`crate::vmm::run`]) with a 16550 console until it halts or `timeout`
    /// elapses, returning the console bytes. This is the *same* loop body the HVF
    /// backend uses — the x86 console is the only backend-specific piece.
    pub fn boot_to_console(
        &self,
        mem: &mut [u8],
        cfg: &x86_boot::BootConfig,
        timeout: Duration,
    ) -> Result<Vec<u8>, KvmError> {
        let vcpu = self.boot_x86(mem, cfg)?;

        // Watchdog: force the vCPU out of KVM_RUN after `timeout` via the seam's
        // cross-thread cancel (a booting kernel never returns on its own).
        let done = Arc::new(AtomicBool::new(false));
        let done_w = done.clone();
        let handle = vcpu.exit_token();
        let watchdog = std::thread::spawn(move || {
            let step = Duration::from_millis(50);
            let mut waited = Duration::ZERO;
            while waited < timeout {
                if done_w.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(step);
                waited += step;
            }
            KvmHandle::force_exit(&[handle]);
        });

        let mut serial = Serial16550::new(0x3f8);
        let outcome = {
            let mut devices: Vec<&mut dyn RunDevice> = vec![&mut serial];
            run::run(
                &vcpu,
                |intid, level| self.set_irq(intid, level),
                &mut devices,
                // x86 KVM decodes every exit; the exception hook is never reached.
                |_: &KvmVcpu, _, _| Ok(RunControl::Stop),
                // No async host I/O on this path yet → a forced exit always stops.
                || true,
            )
        };
        done.store(true, Ordering::Relaxed);
        let _ = watchdog.join();
        outcome?;
        Ok(serial.output)
    }

    /// Boot an x86_64 bzImage (loaded in `mem`) with the **vsock egress gateway**
    ///  — no guest NIC. The guest reaches the network only by opening a
    /// vsock stream to [`VSOCK_MMIO_BASE`]'s device on the egress port; the host
    /// decides each target against `gate` (claim-10) and proxies admitted flows.
    /// This is the same run loop + `EgressProxy` HVF uses; the KVM specifics are the
    /// virtio-mmio window + the SIGUSR1 heartbeat that breaks the in-kernel HLT so
    /// host→guest replies reach an idle guest. `stop` ends the run (timeout or a
    /// caller signal). The caller must append [`vsock_mmio_cmdline_arg`] to the
    /// kernel cmdline.
    pub fn boot_with_egress(
        &self,
        mem: &mut [u8],
        cfg: &x86_boot::BootConfig,
        timeout: Duration,
        gate: EgressGate,
        stop: &'static AtomicBool,
    ) -> Result<KvmEgressResult, KvmError> {
        let ram_ptr = mem.as_mut_ptr();
        let ram_len = mem.len();
        let vcpu = self.boot_x86(mem, cfg)?;

        // Watchdog + heartbeat: end the run on timeout/stop; between those, a
        // periodic force-exit breaks the guest's in-kernel HLT so the run loop can
        // poll host I/O (drain egress sockets into a guest idle in `recv`). The run
        // loop treats a forced exit (Canceled) as a stop only when `stop` is set.
        let done = Arc::new(AtomicBool::new(false));
        let done_w = done.clone();
        let egress_active = Arc::new(AtomicUsize::new(0));
        let egress_active_w = egress_active.clone();
        let handle = vcpu.exit_token();
        let watchdog = std::thread::spawn(move || {
            let step = Duration::from_millis(5);
            let mut waited = Duration::ZERO;
            loop {
                std::thread::sleep(step);
                if done_w.load(Ordering::Relaxed) {
                    return;
                }
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                waited += step;
                if waited >= timeout {
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
                if egress_active_w.load(Ordering::Relaxed) > 0 {
                    KvmHandle::force_exit(&[handle]);
                }
            }
            KvmHandle::force_exit(&[handle]);
        });

        let mut serial = Serial16550::new(0x3f8);
        // SAFETY: `ram_ptr`/`ram_len` is the guest RAM mapped at gpa 0 for this VM's
        // lifetime; the device shares it with the running guest (standard VMM
        // aliasing, as on HVF).
        let mut vsock =
            unsafe { VirtioVsock::new(VSOCK_MMIO_BASE, VSOCK_IRQ, ram_ptr, 0, ram_len) };
        vsock.capture_workload_exit(stop);
        vsock.set_egress_gate(gate);
        vsock.set_egress_activity(egress_active.clone());

        let outcome = {
            let mut devices: Vec<&mut dyn RunDevice> = vec![&mut serial, &mut vsock];
            run::run(
                &vcpu,
                |intid, level| self.set_irq(intid, level),
                &mut devices,
                |_: &KvmVcpu, _, _| Ok(RunControl::Stop),
                || stop.load(Ordering::Relaxed),
            )
        };
        done.store(true, Ordering::Relaxed);
        let _ = watchdog.join();
        outcome?;

        Ok(KvmEgressResult {
            console: serial.output,
            workload_exit_code: vsock.workload_exit_code,
            egress_denied: vsock.egress_denied().to_vec(),
            egress_allowed: vsock.egress_allowed().to_vec(),
        })
    }
}

fn seg(s: &x86_boot::Segment) -> kvm_segment {
    kvm_segment {
        base: s.base,
        limit: s.limit,
        selector: s.selector,
        type_: s.type_,
        present: s.present,
        dpl: s.dpl,
        db: s.db,
        s: s.s,
        l: s.l,
        g: s.g,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

/// A KVM vCPU. The fd is `RefCell`-wrapped so [`step`](HypervisorVcpu::step) can
/// take `&self` (vCPUs are thread-bound, so this is never contended).
pub struct KvmVcpu {
    fd: RefCell<VcpuFd>,
    pid: i32,
    tid: i32,
    /// Data buffer (into the `kvm_run` mmap) + width of a pending guest read that
    /// `step` surfaced; `complete_read` writes the value here before re-entry.
    pending_read: Cell<Option<(*mut u8, usize)>>,
}

impl KvmVcpu {
    /// Apply the long-mode entry register state (x86-specific boot path).
    pub fn apply_boot_regs(&self, r: &x86_boot::BootRegs) -> Result<(), KvmError> {
        let fd = self.fd.borrow_mut(); // kvm get/set_(s)regs take &self
        let mut sregs = fd.get_sregs()?;
        sregs.cr0 = r.cr0;
        sregs.cr3 = r.cr3;
        sregs.cr4 = r.cr4;
        sregs.efer = r.efer;
        sregs.gdt.base = r.gdt_base;
        sregs.gdt.limit = r.gdt_limit;
        let cs = seg(&r.cs);
        let ds = seg(&r.ds);
        sregs.cs = cs;
        sregs.ds = ds;
        sregs.es = ds;
        sregs.ss = ds;
        sregs.fs = ds;
        sregs.gs = ds;
        fd.set_sregs(&sregs)?;
        let mut regs = fd.get_regs()?;
        regs.rip = r.rip;
        regs.rsi = r.rsi;
        regs.rflags = r.rflags;
        fd.set_regs(&regs)?;
        Ok(())
    }
}

/// Cross-thread force-exit token: the (pid, tid) of the vCPU thread. `force_exit`
/// signals it so a blocked `KVM_RUN` returns `EINTR` → [`VcpuExit::Canceled`].
#[derive(Clone, Copy)]
pub struct KvmHandle {
    pid: i32,
    tid: i32,
}

impl VcpuHandle for KvmHandle {
    fn force_exit(handles: &[Self]) {
        for h in handles {
            // SAFETY: tgkill to a known thread with the run-interrupt signal.
            unsafe {
                libc::syscall(libc::SYS_tgkill, h.pid, h.tid, RUN_INTERRUPT_SIGNAL);
            }
        }
    }
}

/// Signal used to kick a vCPU out of `KVM_RUN` (no-op handler installed once).
const RUN_INTERRUPT_SIGNAL: i32 = libc::SIGUSR1;

extern "C" fn run_interrupt_handler(_: libc::c_int) {}

fn install_run_interrupt_handler() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: installs a no-op handler so the signal interrupts KVM_RUN
        // (EINTR) instead of terminating the process; no SA_RESTART.
        unsafe {
            let h = run_interrupt_handler as extern "C" fn(libc::c_int);
            libc::signal(RUN_INTERRUPT_SIGNAL, h as libc::sighandler_t);
        }
    });
}

impl HypervisorVcpu for KvmVcpu {
    type Error = KvmError;
    type Handle = KvmHandle;

    fn exit_token(&self) -> KvmHandle {
        KvmHandle {
            pid: self.pid,
            tid: self.tid,
        }
    }

    // The aarch64 register seam does not apply to x86_64; boot regs are set via
    // `KvmVm::boot_x86` / `apply_boot_regs`.
    fn get_core(&self, _reg: CoreReg) -> Result<u64, KvmError> {
        Err(KvmError::Unsupported("get_core (aarch64 reg) on x86_64"))
    }
    fn set_core(&self, _reg: CoreReg, _value: u64) -> Result<(), KvmError> {
        Err(KvmError::Unsupported("set_core (aarch64 reg) on x86_64"))
    }
    fn get_sys(&self, _reg: SysReg) -> Result<u64, KvmError> {
        Err(KvmError::Unsupported("get_sys (aarch64 reg) on x86_64"))
    }
    fn set_sys(&self, _reg: SysReg, _value: u64) -> Result<(), KvmError> {
        Err(KvmError::Unsupported("set_sys (aarch64 reg) on x86_64"))
    }

    fn step(&self) -> Result<VcpuExit, KvmError> {
        self.pending_read.set(None);
        let mut fd = self.fd.borrow_mut();
        match fd.run() {
            Ok(KvmExit::IoOut(port, data)) => Ok(VcpuExit::Io {
                port,
                write: true,
                size: data.len() as u8,
                data: le_u32(data),
            }),
            Ok(KvmExit::IoIn(port, data)) => {
                self.pending_read.set(Some((data.as_mut_ptr(), data.len())));
                Ok(VcpuExit::Io {
                    port,
                    write: false,
                    size: data.len() as u8,
                    data: 0,
                })
            }
            Ok(KvmExit::MmioWrite(addr, data)) => Ok(VcpuExit::Mmio {
                phys_addr: addr,
                write: true,
                len: data.len() as u8,
                data: le_u64(data),
            }),
            Ok(KvmExit::MmioRead(addr, data)) => {
                self.pending_read.set(Some((data.as_mut_ptr(), data.len())));
                Ok(VcpuExit::Mmio {
                    phys_addr: addr,
                    write: false,
                    len: data.len() as u8,
                    data: 0,
                })
            }
            Ok(KvmExit::Hlt) | Ok(KvmExit::Shutdown) => Ok(VcpuExit::Halt),
            Ok(other) => Ok(VcpuExit::Unknown(kvm_exit_code(&other))),
            Err(e) if e.errno() == libc::EINTR => Ok(VcpuExit::Canceled),
            Err(e) => Err(KvmError::Kvm(e)),
        }
    }

    fn complete_read(&self, value: u64) -> Result<(), KvmError> {
        if let Some((ptr, len)) = self.pending_read.take() {
            let bytes = value.to_le_bytes();
            let n = len.min(bytes.len());
            // SAFETY: ptr points into this vCPU's kvm_run mmap, valid until the
            // next run(); n <= 8 = the pending read width. Single-threaded vCPU,
            // no outstanding borrow of the kvm_run.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, n) };
        }
        Ok(())
    }
}

fn le_u32(d: &[u8]) -> u32 {
    let mut v = [0u8; 4];
    v[..d.len().min(4)].copy_from_slice(&d[..d.len().min(4)]);
    u32::from_le_bytes(v)
}
fn le_u64(d: &[u8]) -> u64 {
    let mut v = [0u8; 8];
    v[..d.len().min(8)].copy_from_slice(&d[..d.len().min(8)]);
    u64::from_le_bytes(v)
}
fn kvm_exit_code(_e: &KvmExit) -> u32 {
    u32::MAX // opaque; the run loop logs Unknown
}

impl HypervisorVm for KvmVm {
    type Error = KvmError;
    type Vcpu = KvmVcpu;

    fn create() -> Result<Self, KvmError> {
        install_run_interrupt_handler();
        let kvm = Kvm::new()?;
        let vm = kvm.create_vm()?;
        vm.set_tss_address(0xffff_b000)?;
        vm.create_irq_chip()?; // in-kernel LAPIC/IOAPIC/PIC
        vm.create_pit2(kvm_pit_config::default())?; // i8254 PIT: timer ticks
        Ok(KvmVm {
            kvm,
            vm,
            next_slot: AtomicU32::new(0),
            next_id: AtomicU64::new(0),
        })
    }

    unsafe fn map_ram(
        &self,
        host_ptr: *mut u8,
        gpa: u64,
        len: usize,
        _prot: u64,
    ) -> Result<(), KvmError> {
        let slot = self.next_slot.fetch_add(1, Ordering::Relaxed);
        let region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: gpa,
            memory_size: len as u64,
            userspace_addr: host_ptr as u64,
            flags: 0,
        };
        // SAFETY: caller upholds map_ram's contract on host_ptr/len for the VM's
        // lifetime; the region is well-formed.
        unsafe { self.vm.set_user_memory_region(region)? };
        Ok(())
    }

    fn create_vcpu(&self) -> Result<KvmVcpu, KvmError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let fd = self.vm.create_vcpu(id)?;
        let cpuid = self.kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
        fd.set_cpuid2(&cpuid)?;
        // SAFETY: plain getpid/gettid syscalls.
        let pid = unsafe { libc::getpid() };
        let tid = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
        Ok(KvmVcpu {
            fd: RefCell::new(fd),
            pid,
            tid,
            pending_read: Cell::new(None),
        })
    }

    fn set_irq(&self, intid: u32, level: bool) -> Result<(), KvmError> {
        if level {
            // x86 IOAPIC delivers on the low→high edge. The device model only ever
            // asserts (the run loop raises an IRQ when a device has work), and it
            // does not lower the line, so a second assert on an already-high line
            // produces no new edge — a later async notification (e.g. an egress
            // reply drained on a heartbeat tick, after the guest's recv has
            // blocked) would be lost. Pulse instead: assert then deassert, so every
            // notification is a fresh edge. The guest's own connect-time IRQ (raised
            // during its notify) is unaffected.
            self.vm.set_irq_line(intid, true)?;
            self.vm.set_irq_line(intid, false)?;
        } else {
            self.vm.set_irq_line(intid, false)?;
        }
        Ok(())
    }
}
