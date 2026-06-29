//! Boot a real arm64 Linux `Image` under HVF and capture earlycon output.
//!
//! Loads the kernel and a minimal DTB into guest RAM, sets the arm64 boot
//! registers (`x0`=DTB, `PC`=entry), and runs the vCPU with the console run
//! loop: PL011 MMIO is captured, PSCI HVCs are stubbed, unmodeled MMIO is
//! read-as-zero / write-ignore so the kernel keeps progressing, and a watchdog
//! thread forces the vCPU out after a timeout (a booting kernel never returns on
//! its own). The captured bytes are the kernel's earlycon output — proof that
//! real Linux boots and prints on this backend.
//!
//! Creates HVF's in-kernel GICv3 + arch timer so the kernel's IRQ subsystem
//! comes up: a real kernel boots through banner, PSCI, CPU-feature detection,
//! memory init, and into `init_IRQ`, driving the PL011 console the whole way.
//! Full boot-to-userspace additionally needs the GIC redistributor MMIO exposed
//! to the guest and a root filesystem (next slices).

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::HvfError;
use super::device::{MmioDevice, Pl011};
use super::sys::*;
use super::vcpu::{advance_pc, decode_data_abort, esr_ec, read_gp, write_gp};
use super::{fdt, kernel_image};

/// Guest RAM base (2 GiB, per the aarch64 Linux boot convention) and size
/// (512 MiB). The GIC + PL011 sit below RAM so their accesses fault out as MMIO.
const RAM_BASE: u64 = 0x8000_0000;
const RAM_SIZE: usize = 0x2000_0000;
const PAGE: usize = 16384;
/// Linux aarch64 loads/enters the kernel at RAM start + 0x80000.
const KERNEL_LOAD_OFFSET: u64 = 0x8_0000;
/// DTB reserved window at the top of RAM (matches `fdt::FDT_MAX_SIZE` budget).
const FDT_MAX_SIZE: u64 = 0x20_0000;
const UART_BASE: u64 = fdt::SERIAL_MMIO_BASE;

/// GIC ID-register offset (`PIDR2`) within a 64 KiB GIC frame, and the value
/// reporting GICv3 (ArchRev=3 in bits 7:4) — the one GIC register HVF's
/// in-kernel GIC does not emulate for us.
const GIC_PIDR2_OFFSET: u64 = 0xffe8;
const GICV3_PIDR2_ARCHREV: u64 = 0x30;

/// GIC MMIO window (distributor + redistributor), below RAM.
fn in_gic_range(addr: u64) -> bool {
    (fdt::GICV3_DIST_BASE..fdt::GICV3_REDIST_BASE + 0x10_0000).contains(&addr)
}

const PSCI_VERSION_FN: u64 = 0x8400_0000;
const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
const PSCI_NOT_SUPPORTED: u64 = (-1i64) as u64;

/// Outcome of a kernel boot attempt (with boot diagnostics).
#[derive(Debug, Clone, Default)]
pub struct KernelBootResult {
    /// Bytes the kernel emitted via the emulated PL011 (its earlycon output).
    pub console: Vec<u8>,
    /// Final vCPU exit reason.
    pub exit_reason: hv_exit_reason_t,
    /// PL011 data-register writes serviced.
    pub mmio_writes: usize,
    /// PSCI HVC calls serviced.
    pub hvc_calls: usize,
    /// True if the watchdog forced the run to stop (expected for a live boot).
    pub stopped_by_watchdog: bool,
    /// Total data-abort (MMIO) exits.
    pub data_aborts: usize,
    /// Synchronous exceptions other than HVC/data-abort.
    pub other_exceptions: usize,
    /// First distinct faulting MMIO addresses (capped).
    pub fault_addrs: Vec<u64>,
    /// PSCI function ids requested (capped).
    pub psci_fns: Vec<u64>,
    /// Distinct exception classes seen on the "other" path (capped).
    pub other_ecs: Vec<u32>,
    /// vCPU PC when the run ended.
    pub final_pc: u64,
}

/// Boot `image` (an arm64 `Image`) under HVF, returning what it printed within
/// `timeout`.
pub fn boot_kernel(image: &[u8], timeout: Duration) -> Result<KernelBootResult, HvfError> {
    // Validate it's an arm64 Image; we load at the fixed boot-protocol offset.
    let _hdr = kernel_image::parse(image).map_err(|_| HvfError::BadKernel)?;
    let load_off = KERNEL_LOAD_OFFSET as usize;
    let dtb_off = RAM_SIZE - FDT_MAX_SIZE as usize; // DTB window at top of RAM
    if load_off + image.len() > dtb_off {
        return Err(HvfError::BadKernel);
    }

    let layout = Layout::from_size_align(RAM_SIZE, PAGE).map_err(|_| HvfError::Alloc)?;
    // SAFETY: non-zero layout; null-checked; freed on every return path.
    let ram = unsafe { alloc_zeroed(layout) };
    if ram.is_null() {
        return Err(HvfError::Alloc);
    }

    let bootargs = std::env::var("MVM_HVF_BOOTARGS").unwrap_or_else(|_| {
        format!("earlycon=pl011,0x{UART_BASE:x} console=ttyAMA0 panic=-1 nokaslr loglevel=8")
    });
    let dtb = fdt::build_dtb(&bootargs, RAM_BASE, RAM_SIZE as u64);
    if dtb.len() > FDT_MAX_SIZE as usize {
        // SAFETY: same layout.
        unsafe { dealloc(ram, layout) };
        return Err(HvfError::BadKernel);
    }
    if let Ok(path) = std::env::var("MVM_HVF_DUMP_DTB") {
        let _ = std::fs::write(path, &dtb);
    }

    // SAFETY: `ram` owns RAM_SIZE writable bytes; both regions are bounds-checked
    // above to fit.
    unsafe {
        core::ptr::copy_nonoverlapping(image.as_ptr(), ram.add(load_off), image.len());
        core::ptr::copy_nonoverlapping(dtb.as_ptr(), ram.add(dtb_off), dtb.len());
    }

    let entry = RAM_BASE + KERNEL_LOAD_OFFSET;
    let dtb_addr = RAM_BASE + dtb_off as u64;

    // SAFETY: VM created before use and destroyed before `ram` is freed.
    let result = unsafe {
        let rc = hv_vm_create(core::ptr::null_mut());
        if rc != HV_SUCCESS {
            dealloc(ram, layout);
            return Err(HvfError::VmCreate(rc));
        }
        let r = run(ram, entry, dtb_addr, timeout);
        hv_vm_destroy();
        r
    };
    // SAFETY: same layout.
    unsafe { dealloc(ram, layout) };
    result
}

/// # Safety
/// Between `hv_vm_create`/`hv_vm_destroy`; `ram` holds RAM_SIZE bytes with the
/// kernel + DTB loaded.
unsafe fn run(
    ram: *mut u8,
    entry: u64,
    dtb_addr: u64,
    timeout: Duration,
) -> Result<KernelBootResult, HvfError> {
    unsafe {
        // In-kernel GICv3 — created after the VM, before any vCPU. Base
        // addresses must match the DTB's intc node, or the kernel's IRQ/timer
        // init hangs (no console).
        let gic_cfg = hv_gic_config_create();
        let grc = hv_gic_config_set_distributor_base(gic_cfg, fdt::GICV3_DIST_BASE);
        let grc = if grc == HV_SUCCESS {
            hv_gic_config_set_redistributor_base(gic_cfg, fdt::GICV3_REDIST_BASE)
        } else {
            grc
        };
        let grc = if grc == HV_SUCCESS {
            hv_gic_create(gic_cfg)
        } else {
            grc
        };
        if grc != HV_SUCCESS {
            return Err(HvfError::GicCreate(grc));
        }

        let flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
        let rc = hv_vm_map(ram.cast(), RAM_BASE, RAM_SIZE, flags);
        if rc != HV_SUCCESS {
            return Err(HvfError::Map(rc));
        }

        let mut vcpu: hv_vcpu_t = 0;
        let mut exit: *mut hv_vcpu_exit_t = core::ptr::null_mut();
        let rc = hv_vcpu_create(&mut vcpu, &mut exit, core::ptr::null_mut());
        if rc != HV_SUCCESS {
            return Err(HvfError::VcpuCreate(rc));
        }

        // arm64 boot protocol: x0=DTB, x1..x3=0, PC=entry, EL1h with DAIF masked.
        let ok = hv_vcpu_set_reg(vcpu, HV_REG_PC, entry) == HV_SUCCESS
            && hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0x3c5) == HV_SUCCESS
            && hv_vcpu_set_reg(vcpu, HV_REG_X0, dtb_addr) == HV_SUCCESS
            && hv_vcpu_set_reg(vcpu, HV_REG_X1, 0) == HV_SUCCESS
            && hv_vcpu_set_reg(vcpu, HV_REG_X2, 0) == HV_SUCCESS
            && hv_vcpu_set_reg(vcpu, HV_REG_X3, 0) == HV_SUCCESS;
        if !ok {
            hv_vcpu_destroy(vcpu);
            return Err(HvfError::SetReg(0));
        }

        // Watchdog: a booting kernel never exits on its own, so force the vCPU
        // out after `timeout`. The flag lets a clean early exit skip the wait.
        let done = Arc::new(AtomicBool::new(false));
        let done_w = done.clone();
        let vcpu_w = vcpu;
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
            let arr = [vcpu_w];
            // SAFETY: hv_vcpus_exit is the documented cross-thread cancel.
            hv_vcpus_exit(arr.as_ptr(), 1);
        });

        let mut uart = Pl011::new(UART_BASE);
        let mut r = KernelBootResult::default();
        let outcome = drive(vcpu, exit, &mut uart, &mut r);
        done.store(true, Ordering::Relaxed);
        let _ = watchdog.join();
        let mut pc = 0u64;
        hv_vcpu_get_reg(vcpu, HV_REG_PC, &mut pc);
        hv_vcpu_destroy(vcpu);

        outcome?;
        r.console = uart.output;
        r.final_pc = pc;
        r.stopped_by_watchdog = r.exit_reason == HV_EXIT_REASON_CANCELED;
        Ok(r)
    }
}

/// The kernel run loop, accumulating diagnostics into `r`.
///
/// # Safety
/// `vcpu`/`exit` come from a live `hv_vcpu_create` on this thread.
unsafe fn drive(
    vcpu: hv_vcpu_t,
    exit: *mut hv_vcpu_exit_t,
    uart: &mut Pl011,
    r: &mut KernelBootResult,
) -> Result<(), HvfError> {
    unsafe {
        loop {
            let rc = hv_vcpu_run(vcpu);
            if rc != HV_SUCCESS {
                return Err(HvfError::Run(rc));
            }
            let e = *exit;
            match e.reason {
                HV_EXIT_REASON_VTIMER_ACTIVATED => continue,
                HV_EXIT_REASON_CANCELED => {
                    r.exit_reason = e.reason;
                    return Ok(());
                }
                HV_EXIT_REASON_EXCEPTION => {}
                other => return Err(HvfError::UnexpectedExit(other)),
            }

            let esr = e.exception.syndrome;
            match esr_ec(esr) {
                EC_HVC_AARCH64 => {
                    r.hvc_calls += 1;
                    let fn_id = read_gp(vcpu, 0)?;
                    if r.psci_fns.len() < 16 && !r.psci_fns.contains(&fn_id) {
                        r.psci_fns.push(fn_id);
                    }
                    match fn_id {
                        PSCI_SYSTEM_OFF | PSCI_SYSTEM_RESET => {
                            r.exit_reason = e.reason;
                            return Ok(());
                        }
                        PSCI_VERSION_FN => write_gp(vcpu, 0, 0x1_0000)?, // PSCI v1.0
                        _ => write_gp(vcpu, 0, PSCI_NOT_SUPPORTED)?,
                    }
                    // HVC is a completed synchronous exception: HVF already
                    // points PC at the instruction after `hvc`. Do NOT advance
                    // again or we skip an instruction and corrupt the guest.
                }
                EC_DATA_ABORT_LOWER_EL => {
                    r.data_aborts += 1;
                    let da = decode_data_abort(esr);
                    let ipa = e.exception.physical_address;
                    if r.fault_addrs.len() < 16 && !r.fault_addrs.contains(&ipa) {
                        r.fault_addrs.push(ipa);
                    }
                    if !da.isv {
                        advance_pc(vcpu)?;
                        continue;
                    }
                    if uart.contains(ipa) {
                        let offset = ipa - uart.base();
                        if da.is_write {
                            let v = read_gp(vcpu, da.reg)?;
                            uart.write(offset, v, da.size);
                            r.mmio_writes += 1;
                        } else {
                            let v = uart.read(offset, da.size);
                            write_gp(vcpu, da.reg, v)?;
                        }
                    } else if !da.is_write {
                        // Unmodeled MMIO is read-as-zero, except the GIC PIDR2 ID
                        // register (offset 0xffe8): HVF's in-kernel GIC emulates
                        // the functional registers but not this ID register, and
                        // the driver needs ArchRev=3 to recognize the GICv3
                        // redistributor. Without it the driver derives a bad base
                        // and faults during IRQ setup.
                        let val = if in_gic_range(ipa) && ipa & 0xffff == GIC_PIDR2_OFFSET {
                            GICV3_PIDR2_ARCHREV
                        } else {
                            0
                        };
                        write_gp(vcpu, da.reg, val)?;
                    }
                    advance_pc(vcpu)?;
                }
                ec => {
                    r.other_exceptions += 1;
                    if r.other_ecs.len() < 16 && !r.other_ecs.contains(&ec) {
                        r.other_ecs.push(ec);
                    }
                    advance_pc(vcpu)?;
                }
            }
        }
    }
}
