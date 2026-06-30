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
//! Creates HVF's in-kernel GICv3 + arch timer and sets the vCPU's `MPIDR_EL1`
//! affinity to match the redistributor, so the kernel's interrupt + timer
//! subsystems come fully up: a real kernel boots all the way through driver and
//! filesystem init to `prepare_namespace`, driving the PL011 console throughout.
//! It then panics mounting the root fs because none is supplied — providing a
//! root filesystem (initramfs / virtio-blk) is the next slice.

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use super::HvfError;
use super::hv_impl::{HvfHandle, HvfVcpu};
use super::sys::*;
use super::vcpu::esr_ec;
use crate::vmm::device::Pl011;
use crate::vmm::hv::{CoreReg, HypervisorVcpu, SysReg, VcpuHandle};
use crate::vmm::run::{self, RunControl, RunDevice, RunOutcome};
use crate::vmm::virtio::VirtioBlk;
use crate::vmm::vsock::VirtioVsock;
use crate::vmm::{fdt, kernel_image};

/// Guest RAM base (2 GiB, per the aarch64 Linux boot convention) and size
/// (512 MiB). The GIC + PL011 sit below RAM so their accesses fault out as MMIO.
const RAM_BASE: u64 = 0x8000_0000;
const RAM_SIZE: usize = 0x2000_0000;
const PAGE: usize = 16384;
/// Linux aarch64 loads/enters the kernel at RAM start + 0x80000.
const KERNEL_LOAD_OFFSET: u64 = 0x8_0000;
/// DTB reserved window at the top of RAM (matches `fdt::FDT_MAX_SIZE` budget).
const FDT_MAX_SIZE: u64 = 0x20_0000;
/// initramfs load offset within RAM (256 MiB in — clear of the kernel, below the
/// DTB window).
const INITRD_OFFSET: u64 = 0x1000_0000;
const UART_BASE: u64 = fdt::SERIAL_MMIO_BASE;
/// virtio-mmio device windows (above the GIC, below RAM) + their SPIs.
const VIRTIO_MMIO_BASE: u64 = 0x0a00_0000;
const VIRTIO_IRQ: u32 = 48;
const VSOCK_MMIO_BASE: u64 = 0x0a00_0200;
const VSOCK_IRQ: u32 = 49;

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
    /// PSCI HVC calls serviced.
    pub hvc_calls: usize,
    /// True if the watchdog forced the run to stop (expected for a live boot).
    pub stopped_by_watchdog: bool,
    /// Synchronous exceptions other than HVC/data-abort.
    pub other_exceptions: usize,
    /// PSCI function ids requested (capped).
    pub psci_fns: Vec<u64>,
    /// Distinct exception classes seen on the "other" path (capped).
    pub other_ecs: Vec<u32>,
    /// vCPU PC when the run ended.
    pub final_pc: u64,
    /// Bytes the guest sent to the host over virtio-vsock.
    pub vsock_received: Vec<u8>,
    /// Workload exit code, if the guest reported one over the workload-exit vsock
    /// port (the transient run-to-exit signal). `None` for a run that ended by
    /// timeout/stop without a workload-exit report.
    pub workload_exit_code: Option<i32>,
    /// Egress targets the vsock gateway refused (claim-10 default-deny, ADR-100).
    pub egress_denied: Vec<String>,
    /// Egress targets the vsock gateway admitted + connected (ADR-100).
    pub egress_allowed: Vec<String>,
}

/// Kernel cmdline used when `MVM_HVF_BOOTARGS` is unset. Always wires the PL011
/// console (earlycon + `ttyAMA0`). When a virtio-blk disk is attached it is a
/// real mkGuest workload rootfs, so mount it and run the baked init —
/// `root=/dev/vda rw init=/init`, the same contract the Vz/firecracker backends
/// boot mkGuest images with. Disk-less boots (initramfs / freestanding payloads)
/// keep the bare console args.
fn default_bootargs(has_disk: bool) -> String {
    let mut args =
        format!("earlycon=pl011,0x{UART_BASE:x} console=ttyAMA0 panic=-1 nokaslr loglevel=8");
    if has_disk {
        args.push_str(" root=/dev/vda rw init=/init");
    }
    args
}

/// Boot `image` (an arm64 `Image`) under HVF, optionally with an `initramfs`
/// (cpio, gzip-or-raw), returning what it printed within `timeout`.
pub fn boot_kernel(
    image: &[u8],
    initramfs: Option<&[u8]>,
    disk: Option<&[u8]>,
    vsock: bool,
    timeout: Duration,
) -> Result<KernelBootResult, HvfError> {
    static NEVER_STOP: AtomicBool = AtomicBool::new(false);
    boot_kernel_impl(
        image,
        initramfs,
        disk,
        vsock,
        timeout,
        &NEVER_STOP,
        egress_gate_from_env(),
    )
}

/// Like [`boot_kernel`], but stops as soon as `stop` is set — a
/// persistent-until-stop VM — and drives egress through the caller-supplied
/// `egress` gateway (the supervisor builds it from the admitted plan's network
/// policy; ADR-100). The supervisor sets `stop` from a SIGTERM handler so
/// `HvfBackend::stop` ends the guest cleanly. `timeout` still caps the run.
pub fn boot_kernel_until(
    image: &[u8],
    initramfs: Option<&[u8]>,
    disk: Option<&[u8]>,
    vsock: bool,
    timeout: Duration,
    stop: &'static AtomicBool,
    egress: crate::vmm::egress_gate::EgressGate,
) -> Result<KernelBootResult, HvfError> {
    boot_kernel_impl(image, initramfs, disk, vsock, timeout, stop, egress)
}

fn boot_kernel_impl(
    image: &[u8],
    initramfs: Option<&[u8]>,
    disk: Option<&[u8]>,
    vsock: bool,
    timeout: Duration,
    stop: &'static AtomicBool,
    egress: crate::vmm::egress_gate::EgressGate,
) -> Result<KernelBootResult, HvfError> {
    // Validate it's an arm64 Image; we load at the fixed boot-protocol offset.
    let _hdr = kernel_image::parse(image).map_err(|_| HvfError::BadKernel)?;
    let load_off = KERNEL_LOAD_OFFSET as usize;
    let dtb_off = RAM_SIZE - FDT_MAX_SIZE as usize; // DTB window at top of RAM
    if load_off + image.len() > dtb_off {
        return Err(HvfError::BadKernel);
    }
    // Place initramfs at INITRD_OFFSET; must clear the kernel and the DTB window.
    let initrd_off = INITRD_OFFSET as usize;
    if let Some(rd) = initramfs
        && (initrd_off < load_off + image.len() || initrd_off + rd.len() > dtb_off)
    {
        return Err(HvfError::BadKernel);
    }

    let layout = Layout::from_size_align(RAM_SIZE, PAGE).map_err(|_| HvfError::Alloc)?;
    // SAFETY: non-zero layout; null-checked; freed on every return path.
    let ram = unsafe { alloc_zeroed(layout) };
    if ram.is_null() {
        return Err(HvfError::Alloc);
    }

    let bootargs =
        std::env::var("MVM_HVF_BOOTARGS").unwrap_or_else(|_| default_bootargs(disk.is_some()));
    let initrd_bounds = initramfs.map(|rd| {
        (
            RAM_BASE + INITRD_OFFSET,
            RAM_BASE + INITRD_OFFSET + rd.len() as u64,
        )
    });
    let mut virtio_nodes: Vec<(u64, u32)> = Vec::new();
    if disk.is_some() {
        virtio_nodes.push((VIRTIO_MMIO_BASE, VIRTIO_IRQ));
    }
    if vsock {
        virtio_nodes.push((VSOCK_MMIO_BASE, VSOCK_IRQ));
    }
    let dtb = fdt::build_dtb(
        &bootargs,
        RAM_BASE,
        RAM_SIZE as u64,
        initrd_bounds,
        &virtio_nodes,
    );
    if dtb.len() > FDT_MAX_SIZE as usize {
        // SAFETY: same layout.
        unsafe { dealloc(ram, layout) };
        return Err(HvfError::BadKernel);
    }
    if let Ok(path) = std::env::var("MVM_HVF_DUMP_DTB") {
        let _ = std::fs::write(path, &dtb);
    }

    // SAFETY: `ram` owns RAM_SIZE writable bytes; every region is bounds-checked
    // above to fit and not overlap.
    unsafe {
        core::ptr::copy_nonoverlapping(image.as_ptr(), ram.add(load_off), image.len());
        core::ptr::copy_nonoverlapping(dtb.as_ptr(), ram.add(dtb_off), dtb.len());
        if let Some(rd) = initramfs {
            core::ptr::copy_nonoverlapping(rd.as_ptr(), ram.add(initrd_off), rd.len());
        }
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
        let r = run(
            ram,
            entry,
            dtb_addr,
            RunInputs {
                disk,
                vsock,
                timeout,
                egress,
            },
            stop,
        );
        hv_vm_destroy();
        r
    };
    // SAFETY: same layout.
    unsafe { dealloc(ram, layout) };
    result
}

/// Build the egress gateway policy. Until the admitted plan's network policy is
/// threaded through (the productionized path), a dev hook
/// `MVM_HVF_EGRESS_ALLOW=<ip>:<port>` admits one TCP destination; otherwise the
/// gate is claim-10 default-deny (ADR-100).
fn egress_gate_from_env() -> crate::vmm::egress_gate::EgressGate {
    use crate::vmm::egress_gate::EgressGate;
    use mvm_core::policy::projection::{CanonicalEgress, CanonicalRule, Proto};

    let Ok(spec) = std::env::var("MVM_HVF_EGRESS_ALLOW") else {
        return EgressGate::default_deny();
    };
    match spec.parse::<std::net::SocketAddr>() {
        Ok(addr) => {
            let cidr = if addr.is_ipv4() {
                format!("{}/32", addr.ip())
            } else {
                format!("{}/128", addr.ip())
            };
            let rule = CanonicalRule {
                proto: Proto::Tcp,
                net: cidr.parse().expect("host cidr"),
                port_lo: addr.port(),
                port_hi: addr.port(),
            };
            EgressGate::new(CanonicalEgress::Rules(vec![rule]))
        }
        Err(_) => EgressGate::default_deny(),
    }
}

/// # Safety
/// Between `hv_vm_create`/`hv_vm_destroy`; `ram` holds RAM_SIZE bytes with the
/// kernel + DTB loaded.
/// Device + run inputs for [`run`], bundled to keep its argument count sane.
struct RunInputs<'a> {
    disk: Option<&'a [u8]>,
    vsock: bool,
    timeout: Duration,
    /// Host egress gateway policy (ADR-100).
    egress: crate::vmm::egress_gate::EgressGate,
}

unsafe fn run(
    ram: *mut u8,
    entry: u64,
    dtb_addr: u64,
    inputs: RunInputs,
    stop: &'static AtomicBool,
) -> Result<KernelBootResult, HvfError> {
    let RunInputs {
        disk,
        vsock,
        timeout,
        egress,
    } = inputs;
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

        let mut vcpu_id: hv_vcpu_t = 0;
        let mut exit: *mut hv_vcpu_exit_t = core::ptr::null_mut();
        let rc = hv_vcpu_create(&mut vcpu_id, &mut exit, core::ptr::null_mut());
        if rc != HV_SUCCESS {
            return Err(HvfError::VcpuCreate(rc));
        }
        // Wrap the raw vCPU in the seam type and drive it through the unified run
        // loop (crate::vmm::run) — the same body the KVM backend uses.
        let vcpu = HvfVcpu::from_raw(vcpu_id, exit);

        // MPIDR_EL1 affinity 0 must match FDT cpu@0 + the GIC redistributor frame
        // (else gic_populate_rdist walks off the region and faults). arm64 boot
        // protocol: x0=DTB, x1..x3=0, PC=entry, EL1h with DAIF masked.
        let setup = vcpu
            .set_sys(SysReg::MpidrEl1, 0)
            .and_then(|()| vcpu.set_core(CoreReg::Pc, entry))
            .and_then(|()| vcpu.set_core(CoreReg::Cpsr, 0x3c5))
            .and_then(|()| vcpu.set_core(CoreReg::X(0), dtb_addr))
            .and_then(|()| vcpu.set_core(CoreReg::X(1), 0))
            .and_then(|()| vcpu.set_core(CoreReg::X(2), 0))
            .and_then(|()| vcpu.set_core(CoreReg::X(3), 0));
        if let Err(e) = setup {
            hv_vcpu_destroy(vcpu_id);
            return Err(e);
        }

        // Watchdog + heartbeat: a booting kernel never exits on its own, so force
        // the vCPU out after `timeout` or as soon as `stop` is set (graceful stop).
        // Between those, a periodic force-exit acts as a heartbeat: it breaks the
        // guest out of WFI so the run loop can poll host-side async work (drain an
        // egress socket into a guest blocked in `recv` — ADR-100). The run loop
        // treats a forced exit as a stop only when `stop` is set, so a heartbeat
        // wake just polls and continues. On timeout we set `stop` first so the run
        // loop ends.
        let done = Arc::new(AtomicBool::new(false));
        let done_w = done.clone();
        // Open-egress-connection count, shared with the vsock device. The heartbeat
        // only fires while this is non-zero — a guest with no open egress socket has
        // no host push to wait for, so the host can idle instead of waking 200×/s.
        let egress_active = Arc::new(AtomicUsize::new(0));
        let egress_active_w = egress_active.clone();
        // Host agent listener path (host→guest RPC, GUEST_AGENT_PORT). When bound,
        // the heartbeat fires unconditionally so the run loop polls the listener +
        // services agent streams even while the guest is idle in WFI — an agent VM
        // exists to answer host RPC, so the wake is warranted. (A transient
        // run-to-exit VM leaves this unset and keeps the egress-gated heartbeat.)
        let agent_socket = std::env::var("MVM_HVF_AGENT_SOCKET").ok();
        let agent_bound = agent_socket.is_some();
        let handle = vcpu.exit_token();
        let watchdog = std::thread::spawn(move || {
            let step = Duration::from_millis(5);
            let mut waited = Duration::ZERO;
            loop {
                std::thread::sleep(step);
                if done_w.load(Ordering::Relaxed) {
                    return; // run already ended; don't poke a finishing vCPU
                }
                if stop.load(Ordering::Relaxed) {
                    break; // requested stop / workload-exit → final force-exit below
                }
                waited += step;
                if waited >= timeout {
                    stop.store(true, Ordering::Relaxed); // timeout → end the run
                    break;
                }
                // Heartbeat while an agent listener is bound (accept/serve RPC) or
                // there's host→guest egress to deliver.
                if agent_bound || egress_active_w.load(Ordering::Relaxed) > 0 {
                    HvfHandle::force_exit(&[handle]); // wake the run loop to poll
                }
            }
            HvfHandle::force_exit(&[handle]); // final wake → loop sees stop, returns
        });

        let mut uart = Pl011::new(UART_BASE);
        let mut virtio = disk.map(|d| {
            VirtioBlk::new(
                VIRTIO_MMIO_BASE,
                VIRTIO_IRQ,
                ram,
                RAM_BASE,
                RAM_SIZE,
                d.to_vec(),
            )
        });
        let mut vsock_dev =
            vsock.then(|| VirtioVsock::new(VSOCK_MMIO_BASE, VSOCK_IRQ, ram, RAM_BASE, RAM_SIZE));
        // Transient run-to-exit: a guest write of the exit code to the workload
        // exit port stops the run (and is captured below). Egress over vsock is
        // claim-10 default-deny until the plan's policy is threaded in (ADR-100).
        if let Some(v) = vsock_dev.as_mut() {
            v.capture_workload_exit(stop);
            v.set_egress_gate(egress);
            v.set_egress_activity(egress_active.clone());
            // Host→guest agent RPC (GUEST_AGENT_PORT): expose the listener so host
            // clients (`machine invoke`) reach the guest agent over vsock (ADR-100).
            if let Some(path) = &agent_socket {
                v.set_agent_activity(egress_active.clone());
                if let Err(e) = v.set_agent_socket(std::path::Path::new(path)) {
                    eprintln!("mvm-hvf: agent socket bind failed at {path}: {e}");
                }
            }
        }

        // Diagnostics gathered by the exception hook (HVC/PSCI + other traps).
        let mut hvc_calls = 0usize;
        let mut other_exceptions = 0usize;
        let mut psci_fns: Vec<u64> = Vec::new();
        let mut other_ecs: Vec<u32> = Vec::new();

        // Scope the device list so its mutable borrows end before we read the
        // device output below.
        let outcome = {
            let mut devices: Vec<&mut dyn RunDevice> = vec![&mut uart];
            if let Some(v) = virtio.as_mut() {
                devices.push(v);
            }
            if let Some(v) = vsock_dev.as_mut() {
                devices.push(v);
            }
            let set_irq = |intid: u32, level: bool| -> Result<(), HvfError> {
                // SAFETY: FFI to the process-global in-kernel GIC (nested in the
                // enclosing `unsafe` block).
                if hv_gic_set_spi(intid, level) == HV_SUCCESS {
                    Ok(())
                } else {
                    Err(HvfError::GicCreate(0))
                }
            };
            run::run(
                &vcpu,
                set_irq,
                &mut devices,
                |vc: &HvfVcpu, esr, _phys| {
                    if esr_ec(esr) == EC_HVC_AARCH64 {
                        hvc_calls += 1;
                        let fn_id = vc.get_core(CoreReg::X(0))?;
                        if psci_fns.len() < 16 && !psci_fns.contains(&fn_id) {
                            psci_fns.push(fn_id);
                        }
                        match fn_id {
                            PSCI_SYSTEM_OFF | PSCI_SYSTEM_RESET => return Ok(RunControl::Stop),
                            PSCI_VERSION_FN => vc.set_core(CoreReg::X(0), 0x1_0000)?, // PSCI v1.0
                            _ => vc.set_core(CoreReg::X(0), PSCI_NOT_SUPPORTED)?,
                        }
                        // HVC is completed: HVF already advanced PC. Do NOT advance.
                        Ok(RunControl::Continue)
                    } else {
                        let ec = esr_ec(esr);
                        other_exceptions += 1;
                        if other_ecs.len() < 16 && !other_ecs.contains(&ec) {
                            other_ecs.push(ec);
                        }
                        // Advance past the faulting instruction and keep going.
                        let pc = vc.get_core(CoreReg::Pc)?;
                        vc.set_core(CoreReg::Pc, pc + 4)?;
                        Ok(RunControl::Continue)
                    }
                },
                // A forced exit is a real stop only when `stop` is set (timeout or
                // graceful); otherwise it's a heartbeat wake so the run loop can drain
                // egress sockets into a guest blocked in WFI (ADR-100 async proxy).
                move || stop.load(Ordering::Relaxed),
            )?
        };

        done.store(true, Ordering::Relaxed);
        let _ = watchdog.join();
        let final_pc = vcpu.get_core(CoreReg::Pc).unwrap_or(0);
        hv_vcpu_destroy(vcpu_id);

        let mut r = KernelBootResult {
            console: uart.output,
            exit_reason: match outcome {
                RunOutcome::Canceled => HV_EXIT_REASON_CANCELED,
                _ => HV_EXIT_REASON_EXCEPTION,
            },
            hvc_calls,
            stopped_by_watchdog: outcome == RunOutcome::Canceled,
            other_exceptions,
            psci_fns,
            other_ecs,
            final_pc,
            ..Default::default()
        };
        if let Some(vs) = &vsock_dev {
            r.vsock_received = vs.received.clone();
            r.workload_exit_code = vs.workload_exit_code;
            r.egress_denied = vs.egress_denied().to_vec();
            r.egress_allowed = vs.egress_allowed().to_vec();
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bootargs_mounts_rootfs_when_disk_present() {
        // A virtio-blk disk is a real mkGuest workload rootfs: mount it and run
        // the baked init, matching the `root=/dev/vda rw init=/init` contract
        // the other backends boot mkGuest images with.
        let with = default_bootargs(true);
        assert!(
            with.contains("root=/dev/vda rw"),
            "real workload must mount the virtio-blk rootfs: {with}"
        );
        assert!(
            with.contains("init=/init"),
            "must run the mkGuest init: {with}"
        );
        assert!(with.contains("console=ttyAMA0"), "console wired: {with}");

        // Disk-less boots (initramfs / freestanding demos) keep the demo args.
        let without = default_bootargs(false);
        assert!(
            !without.contains("root="),
            "disk-less boot must not mount a root: {without}"
        );
        assert!(
            without.contains("console=ttyAMA0"),
            "console wired: {without}"
        );
    }
}
