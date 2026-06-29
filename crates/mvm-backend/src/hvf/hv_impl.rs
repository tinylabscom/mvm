//! HVF implementation of the portable hypervisor seam ([`crate::vmm::hv`]).
//!
//! Thin wrappers over [`super::sys`] that bind the HVF backend to the
//! `HypervisorVm`/`HypervisorVcpu` contract so the (forthcoming) generic run
//! loop can drive HVF and KVM identically. The existing `kernel_boot` run loop
//! still calls `sys` directly; it migrates onto this contract next.

use super::HvfError;
use super::sys::*;
use crate::vmm::fdt;
use crate::vmm::hv::{CoreReg, HypervisorVcpu, HypervisorVm, SysReg, VcpuExit, VcpuHandle, prot};

/// HVF VM handle. HVF's VM + in-kernel GIC are process-global, so this is a
/// zero-sized marker; `create` performs the global setup.
pub struct HvfVm;

/// A cross-thread token to force a vCPU out of `step()` (HVF `hv_vcpus_exit`).
#[derive(Clone, Copy)]
pub struct HvfHandle(hv_vcpu_t);

impl VcpuHandle for HvfHandle {
    fn force_exit(handles: &[Self]) {
        let ids: Vec<hv_vcpu_t> = handles.iter().map(|h| h.0).collect();
        // SAFETY: documented cross-thread cancel over valid vCPU ids.
        unsafe {
            let _ = hv_vcpus_exit(ids.as_ptr(), ids.len() as u32);
        }
    }
}

/// HVF vCPU: the handle + the kernel-owned exit struct pointer.
pub struct HvfVcpu {
    vcpu: hv_vcpu_t,
    exit: *mut hv_vcpu_exit_t,
}

fn core_id(reg: CoreReg) -> hv_reg_t {
    match reg {
        CoreReg::X(n) => HV_REG_X0 + u32::from(n),
        CoreReg::Pc => HV_REG_PC,
        CoreReg::Cpsr => HV_REG_CPSR,
    }
}

impl HypervisorVcpu for HvfVcpu {
    type Error = HvfError;
    type Handle = HvfHandle;

    fn exit_token(&self) -> HvfHandle {
        HvfHandle(self.vcpu)
    }

    fn get_core(&self, reg: CoreReg) -> Result<u64, HvfError> {
        let mut v = 0u64;
        // SAFETY: live vCPU; valid reg id.
        let rc = unsafe { hv_vcpu_get_reg(self.vcpu, core_id(reg), &mut v) };
        if rc != HV_SUCCESS {
            return Err(HvfError::GetReg(rc));
        }
        Ok(v)
    }

    fn set_core(&self, reg: CoreReg, value: u64) -> Result<(), HvfError> {
        // SAFETY: live vCPU; valid reg id.
        let rc = unsafe { hv_vcpu_set_reg(self.vcpu, core_id(reg), value) };
        if rc != HV_SUCCESS {
            return Err(HvfError::SetReg(rc));
        }
        Ok(())
    }

    fn get_sys(&self, _reg: SysReg) -> Result<u64, HvfError> {
        // Only MpidrEl1 is modeled; HVF exposes it via the sys-reg path.
        Err(HvfError::GetReg(0))
    }

    fn set_sys(&self, reg: SysReg, value: u64) -> Result<(), HvfError> {
        let SysReg::MpidrEl1 = reg;
        // SAFETY: live vCPU; valid sys-reg id.
        let rc = unsafe { hv_vcpu_set_sys_reg(self.vcpu, HV_SYS_REG_MPIDR_EL1, value) };
        if rc != HV_SUCCESS {
            return Err(HvfError::SetReg(rc));
        }
        Ok(())
    }

    fn step(&self) -> Result<VcpuExit, HvfError> {
        // SAFETY: live vCPU; `exit` is the kernel-owned struct for it.
        let e = unsafe {
            let rc = hv_vcpu_run(self.vcpu);
            if rc != HV_SUCCESS {
                return Err(HvfError::Run(rc));
            }
            *self.exit
        };
        Ok(match e.reason {
            HV_EXIT_REASON_VTIMER_ACTIVATED => VcpuExit::VTimer,
            HV_EXIT_REASON_CANCELED => VcpuExit::Canceled,
            // HVF surfaces the raw arm64 trap; the run loop decodes the ESR.
            HV_EXIT_REASON_EXCEPTION => VcpuExit::Exception {
                syndrome: e.exception.syndrome,
                phys_addr: e.exception.physical_address,
            },
            other => VcpuExit::Unknown(other),
        })
    }
}

impl HypervisorVm for HvfVm {
    type Error = HvfError;
    type Vcpu = HvfVcpu;

    fn create() -> Result<Self, HvfError> {
        // SAFETY: HVF VM + in-kernel GICv3 global setup; bases match the DTB.
        unsafe {
            let rc = hv_vm_create(core::ptr::null_mut());
            if rc != HV_SUCCESS {
                return Err(HvfError::VmCreate(rc));
            }
            let cfg = hv_gic_config_create();
            let mut grc = hv_gic_config_set_distributor_base(cfg, fdt::GICV3_DIST_BASE);
            if grc == HV_SUCCESS {
                grc = hv_gic_config_set_redistributor_base(cfg, fdt::GICV3_REDIST_BASE);
            }
            if grc == HV_SUCCESS {
                grc = hv_gic_create(cfg);
            }
            if grc != HV_SUCCESS {
                return Err(HvfError::GicCreate(grc));
            }
        }
        Ok(HvfVm)
    }

    unsafe fn map_ram(
        &self,
        host_ptr: *mut u8,
        gpa: u64,
        len: usize,
        prot: u64,
    ) -> Result<(), HvfError> {
        let mut flags = 0u64;
        if prot & prot::READ != 0 {
            flags |= HV_MEMORY_READ;
        }
        if prot & prot::WRITE != 0 {
            flags |= HV_MEMORY_WRITE;
        }
        if prot & prot::EXEC != 0 {
            flags |= HV_MEMORY_EXEC;
        }
        // SAFETY: caller upholds `map_ram`'s contract on `host_ptr`/`len`.
        let rc = unsafe { hv_vm_map(host_ptr.cast(), gpa, len, flags) };
        if rc != HV_SUCCESS {
            return Err(HvfError::Map(rc));
        }
        Ok(())
    }

    fn create_vcpu(&self) -> Result<HvfVcpu, HvfError> {
        let mut vcpu: hv_vcpu_t = 0;
        let mut exit: *mut hv_vcpu_exit_t = core::ptr::null_mut();
        // SAFETY: HVF vCPU creation on the calling thread.
        let rc = unsafe { hv_vcpu_create(&mut vcpu, &mut exit, core::ptr::null_mut()) };
        if rc != HV_SUCCESS {
            return Err(HvfError::VcpuCreate(rc));
        }
        Ok(HvfVcpu { vcpu, exit })
    }

    fn set_irq(&self, intid: u32, level: bool) -> Result<(), HvfError> {
        // SAFETY: FFI to the process-global in-kernel GIC.
        let rc = unsafe { hv_gic_set_spi(intid, level) };
        if rc != HV_SUCCESS {
            return Err(HvfError::GicCreate(rc));
        }
        Ok(())
    }
}
