//! HVF implementation of the portable hypervisor seam ([`crate::vmm::hv`]).
//!
//! Thin wrappers over [`super::sys`] that bind the HVF backend to the
//! `HypervisorVm`/`HypervisorVcpu` contract, so the generic run loop
//! ([`crate::vmm::run`]) drives HVF and KVM identically. `kernel_boot` boots a
//! live arm64 Linux guest through exactly this path.

use std::cell::Cell;

use super::HvfError;
use super::snapshot::{
    HvfVcpuState, SNAPSHOT_EXTRA_SYS_REGS, SNAPSHOT_GIC_ICC_REGS, SNAPSHOT_SYS_REGS,
    VCPU_SIMD_REGS, gic_icc_is_restorable,
};
use super::sys::*;
use super::vcpu::{advance_pc, decode_data_abort, esr_ec, read_gp, write_gp};
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

/// HVF vCPU: the handle + the kernel-owned exit struct pointer. `pending_read`
/// records the destination GP register + width of a load data abort that
/// `step` surfaced, so `complete_read` can write the value and advance PC.
pub struct HvfVcpu {
    vcpu: hv_vcpu_t,
    exit: *mut hv_vcpu_exit_t,
    pending_read: Cell<Option<(u8, u8)>>,
}

impl HvfVcpu {
    /// Wrap a raw vCPU created via `sys` (the kernel-boot path owns VM creation
    /// directly). The caller owns the vCPU's lifetime (`hv_vcpu_destroy`).
    pub(super) fn from_raw(vcpu: hv_vcpu_t, exit: *mut hv_vcpu_exit_t) -> Self {
        Self {
            vcpu,
            exit,
            pending_read: Cell::new(None),
        }
    }

    /// Capture the architecturally visible core registers exposed by HVF.
    pub fn capture_state(&self) -> Result<HvfVcpuState, HvfError> {
        let mut x = [0u64; 31];
        for (index, slot) in x.iter_mut().enumerate() {
            let register = u8::try_from(index)
                .map_err(|_| HvfError::SnapshotState("general-purpose register index"))?;
            *slot = self.get_core(CoreReg::X(register))?;
        }
        Ok(HvfVcpuState {
            x,
            pc: self.get_core(CoreReg::Pc)?,
            cpsr: self.get_core(CoreReg::Cpsr)?,
            sys: SNAPSHOT_SYS_REGS
                .iter()
                .map(|reg| self.get_sys(*reg))
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| HvfError::SnapshotState("system register state length"))?,
            extra_sys: SNAPSHOT_EXTRA_SYS_REGS
                .iter()
                .map(|reg| {
                    let mut value = 0u64;
                    // SAFETY: this vCPU is live and owned by this thread;
                    // `value` is a valid out-parameter.
                    let rc = unsafe { hv_vcpu_get_sys_reg(self.vcpu, *reg, &mut value) };
                    if rc == HV_SUCCESS {
                        Ok(value)
                    } else {
                        Err(HvfError::GetReg(rc))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| HvfError::SnapshotState("extra system register state length"))?,
            gic_icc: SNAPSHOT_GIC_ICC_REGS
                .iter()
                .map(|reg| {
                    let mut value = 0u64;
                    // SAFETY: this vCPU is live and owned by the calling thread;
                    // `value` is a valid out-parameter.
                    let rc = unsafe { hv_gic_get_icc_reg(self.vcpu, *reg, &mut value) };
                    if rc == HV_SUCCESS {
                        Ok(value)
                    } else {
                        Err(HvfError::GicCpuCapture {
                            reg: *reg,
                            status: rc,
                        })
                    }
                })
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| HvfError::SnapshotState("GIC CPU register state length"))?,
            fpcr: self.get_raw_reg(HV_REG_FPCR)?,
            fpsr: self.get_raw_reg(HV_REG_FPSR)?,
            simd: (0..VCPU_SIMD_REGS)
                .map(|index| self.get_simd(index))
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| HvfError::SnapshotState("SIMD register state length"))?,
        })
    }

    /// Restore the architecturally visible core registers exposed by HVF.
    pub fn restore_state(&self, state: &HvfVcpuState) -> Result<(), HvfError> {
        for (index, value) in state.x.iter().copied().enumerate() {
            let register = u8::try_from(index)
                .map_err(|_| HvfError::SnapshotState("general-purpose register index"))?;
            self.set_core(CoreReg::X(register), value)?;
        }
        self.set_core(CoreReg::Pc, state.pc)?;
        self.set_core(CoreReg::Cpsr, state.cpsr)?;
        for (reg, value) in SNAPSHOT_SYS_REGS.iter().zip(state.sys) {
            self.set_sys(*reg, value)?;
        }
        for (reg, value) in SNAPSHOT_EXTRA_SYS_REGS.iter().zip(state.extra_sys) {
            // SAFETY: this vCPU is live and owned by this thread.
            let rc = unsafe { hv_vcpu_set_sys_reg(self.vcpu, *reg, value) };
            if rc != HV_SUCCESS {
                return Err(HvfError::SetReg(rc));
            }
        }
        self.set_raw_reg(HV_REG_FPCR, state.fpcr)?;
        self.set_raw_reg(HV_REG_FPSR, state.fpsr)?;
        for (index, value) in state.simd.iter().copied().enumerate() {
            self.set_simd(index, value)?;
        }
        for (reg, value) in SNAPSHOT_GIC_ICC_REGS.iter().zip(state.gic_icc) {
            if !gic_icc_is_restorable(*reg) {
                continue;
            }
            // SAFETY: this vCPU is live and owned by the calling thread; the
            // opaque GIC device state has already been restored.
            let rc = unsafe { hv_gic_set_icc_reg(self.vcpu, *reg, value) };
            if rc != HV_SUCCESS {
                return Err(HvfError::GicCpuRestore {
                    reg: *reg,
                    status: rc,
                });
            }
        }
        Ok(())
    }

    fn get_raw_reg(&self, reg: hv_reg_t) -> Result<u64, HvfError> {
        let mut value = 0u64;
        // SAFETY: this vCPU is live and owned by this thread; `value` is a
        // valid out-parameter.
        let rc = unsafe { hv_vcpu_get_reg(self.vcpu, reg, &mut value) };
        if rc == HV_SUCCESS {
            Ok(value)
        } else {
            Err(HvfError::GetReg(rc))
        }
    }

    fn set_raw_reg(&self, reg: hv_reg_t, value: u64) -> Result<(), HvfError> {
        // SAFETY: this vCPU is live and owned by this thread.
        let rc = unsafe { hv_vcpu_set_reg(self.vcpu, reg, value) };
        if rc == HV_SUCCESS {
            Ok(())
        } else {
            Err(HvfError::SetReg(rc))
        }
    }

    fn get_simd(&self, index: usize) -> Result<[u8; 16], HvfError> {
        let reg =
            u32::try_from(index).map_err(|_| HvfError::SnapshotState("SIMD register index"))?;
        let mut value = [0u8; 16];
        // SAFETY: this vCPU is live and owned by this thread; `value` is a
        // writable 16-byte out-parameter for the framework's vector value.
        let rc = unsafe { hv_vcpu_get_simd_fp_reg(self.vcpu, reg, &mut value) };
        if rc != HV_SUCCESS {
            return Err(HvfError::GetReg(rc));
        }
        Ok(value)
    }

    fn set_simd(&self, index: usize, value: [u8; 16]) -> Result<(), HvfError> {
        let reg =
            u32::try_from(index).map_err(|_| HvfError::SnapshotState("SIMD register index"))?;
        // SAFETY: this vCPU is live and owned by this thread; the assembly
        // bridge synchronously loads all 16 bytes before tail-calling HVF.
        let rc = unsafe { mvm_hv_vcpu_set_simd_fp_reg(self.vcpu, reg, &value) };
        if rc == HV_SUCCESS {
            Ok(())
        } else {
            Err(HvfError::SetReg(rc))
        }
    }
}

/// Map a decoded data abort to the portable exit + (for a load) the destination
/// register/width to complete later. Pure; the store value is filled by `step`.
fn classify_data_abort(esr: u64, phys_addr: u64) -> (VcpuExit, Option<(u8, u8)>) {
    let da = decode_data_abort(esr);
    let exit = VcpuExit::Mmio {
        phys_addr,
        write: da.is_write,
        len: da.size,
        data: 0,
    };
    let pending = (!da.is_write).then_some((da.reg, da.size));
    (exit, pending)
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

    fn get_sys(&self, reg: SysReg) -> Result<u64, HvfError> {
        let mut value = 0u64;
        // SAFETY: live vCPU; valid system-register id.
        let rc = unsafe { hv_vcpu_get_sys_reg(self.vcpu, sys_id(reg), &mut value) };
        if rc != HV_SUCCESS {
            return Err(HvfError::GetReg(rc));
        }
        Ok(value)
    }

    fn set_sys(&self, reg: SysReg, value: u64) -> Result<(), HvfError> {
        // SAFETY: live vCPU; valid sys-reg id.
        let rc = unsafe { hv_vcpu_set_sys_reg(self.vcpu, sys_id(reg), value) };
        if rc != HV_SUCCESS {
            return Err(HvfError::SetReg(rc));
        }
        Ok(())
    }

    fn step(&self) -> Result<VcpuExit, HvfError> {
        loop {
            self.pending_read.set(None);
            // SAFETY: live vCPU; `exit` is the kernel-owned struct for it.
            let e = unsafe {
                let rc = hv_vcpu_run(self.vcpu);
                if rc != HV_SUCCESS {
                    return Err(HvfError::Run(rc));
                }
                *self.exit
            };
            match e.reason {
                HV_EXIT_REASON_VTIMER_ACTIVATED => return Ok(VcpuExit::VTimer),
                HV_EXIT_REASON_CANCELED => return Ok(VcpuExit::Canceled),
                HV_EXIT_REASON_EXCEPTION
                    if esr_ec(e.exception.syndrome) == EC_DATA_ABORT_LOWER_EL =>
                {
                    let esr = e.exception.syndrome;
                    let phys_addr = e.exception.physical_address;
                    let da = decode_data_abort(esr);
                    if !da.isv {
                        // No instruction syndrome to emulate the access (e.g. cache
                        // maintenance): skip it and re-enter.
                        // SAFETY: live vCPU.
                        unsafe { advance_pc(self.vcpu)? };
                        continue;
                    }
                    let (exit, pending) = classify_data_abort(esr, phys_addr);
                    self.pending_read.set(pending);
                    if pending.is_none() {
                        // Store: read the value out of the guest reg + advance PC
                        // now; the run loop applies `data` to the device model.
                        // SAFETY: live vCPU; reg from the decoded abort.
                        let data = unsafe { read_gp(self.vcpu, da.reg)? };
                        // SAFETY: live vCPU.
                        unsafe { advance_pc(self.vcpu)? };
                        return Ok(VcpuExit::Mmio {
                            phys_addr,
                            write: true,
                            len: da.size,
                            data,
                        });
                    }
                    return Ok(exit);
                }
                // Non-MMIO traps (HVC/PSCI, unknowns) stay raw for the caller hook.
                HV_EXIT_REASON_EXCEPTION => {
                    return Ok(VcpuExit::Exception {
                        syndrome: e.exception.syndrome,
                        phys_addr: e.exception.physical_address,
                    });
                }
                other => return Ok(VcpuExit::Unknown(other)),
            }
        }
    }

    fn complete_read(&self, value: u64) -> Result<(), HvfError> {
        if let Some((reg, _size)) = self.pending_read.take() {
            // SAFETY: live vCPU; reg from a decoded load data abort.
            unsafe {
                write_gp(self.vcpu, reg, value)?;
                advance_pc(self.vcpu)?;
            }
        }
        Ok(())
    }
}

fn sys_id(reg: SysReg) -> hv_sys_reg_t {
    match reg {
        SysReg::MpidrEl1 => HV_SYS_REG_MPIDR_EL1,
        SysReg::SctlrEl1 => HV_SYS_REG_SCTLR_EL1,
        SysReg::Ttbr0El1 => HV_SYS_REG_TTBR0_EL1,
        SysReg::Ttbr1El1 => HV_SYS_REG_TTBR1_EL1,
        SysReg::TcrEl1 => HV_SYS_REG_TCR_EL1,
        SysReg::MairEl1 => HV_SYS_REG_MAIR_EL1,
        SysReg::VbarEl1 => HV_SYS_REG_VBAR_EL1,
        SysReg::EsrEl1 => HV_SYS_REG_ESR_EL1,
        SysReg::FarEl1 => HV_SYS_REG_FAR_EL1,
        SysReg::ElrEl1 => HV_SYS_REG_ELR_EL1,
        SysReg::SpEl1 => HV_SYS_REG_SP_EL1,
        SysReg::SpsrEl1 => HV_SYS_REG_SPSR_EL1,
        SysReg::CntkctlEl1 => HV_SYS_REG_CNTKCTL_EL1,
        SysReg::CntvCtlEl0 => HV_SYS_REG_CNTV_CTL_EL0,
        SysReg::CntvCvalEl0 => HV_SYS_REG_CNTV_CVAL_EL0,
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
        Ok(HvfVcpu {
            vcpu,
            exit,
            pending_read: Cell::new(None),
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn da_esr(iss: u64) -> u64 {
        (u64::from(EC_DATA_ABORT_LOWER_EL) << 26) | iss
    }

    #[test]
    fn load_classifies_as_read_with_pending_dest() {
        // ISV, byte width (size field 0), load, destination X5.
        let esr = da_esr((1 << 24) | (5 << 16));
        let (exit, pending) = classify_data_abort(esr, 0x900_0000);
        assert_eq!(pending, Some((5, 1)));
        assert!(matches!(
            exit,
            VcpuExit::Mmio {
                phys_addr: 0x900_0000,
                write: false,
                len: 1,
                data: 0
            }
        ));
    }

    #[test]
    fn store_classifies_as_write_no_pending() {
        // ISV, word width (size field 2 -> 4 bytes), store, source X0.
        let esr = da_esr((1 << 24) | (2 << 22) | (1 << 6));
        let (exit, pending) = classify_data_abort(esr, 0x900_0000);
        assert_eq!(pending, None);
        assert!(matches!(
            exit,
            VcpuExit::Mmio {
                write: true,
                len: 4,
                ..
            }
        ));
    }
}
