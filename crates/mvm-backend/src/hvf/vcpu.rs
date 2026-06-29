//! Shared vCPU register access + ESR decode for the HVF run loops.
//!
//! Used by both the console smoke and the kernel boot loop so the
//! data-abort/MMIO decode and GP-register plumbing have one implementation.

use super::HvfError;
use super::sys::*;

/// Exception class field of an ESR value (bits 31:26).
pub(super) fn esr_ec(esr: u64) -> u32 {
    ((esr >> 26) & 0x3f) as u32
}

/// A decoded data-abort syndrome (ESR ISS for a GP-register load/store).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DataAbort {
    /// Instruction syndrome valid — required to emulate the access.
    pub isv: bool,
    /// Access width in bytes.
    pub size: u8,
    /// GP register index (X0..X30, or 31 = XZR/WZR).
    pub reg: u8,
    /// True for a store, false for a load.
    pub is_write: bool,
}

/// Decode the data-abort ISS fields used for MMIO emulation.
pub(super) fn decode_data_abort(esr: u64) -> DataAbort {
    DataAbort {
        isv: (esr >> 24) & 1 == 1,
        size: 1u8 << ((esr >> 22) & 3),
        reg: ((esr >> 16) & 0x1f) as u8,
        is_write: (esr >> 6) & 1 == 1,
    }
}

/// Read GP register `reg` (X0..X30); index 31 is XZR and reads as 0.
///
/// # Safety
/// `vcpu` must be a live handle.
pub(super) unsafe fn read_gp(vcpu: hv_vcpu_t, reg: u8) -> Result<u64, HvfError> {
    if u32::from(reg) > HV_REG_X30 {
        return Ok(0);
    }
    let mut v = 0u64;
    // SAFETY: HV_REG_X0 + reg is a valid GP register index for reg in 0..=30.
    let rc = unsafe { hv_vcpu_get_reg(vcpu, HV_REG_X0 + u32::from(reg), &mut v) };
    if rc != HV_SUCCESS {
        return Err(HvfError::GetReg(rc));
    }
    Ok(v)
}

/// Write GP register `reg` (X0..X30); index 31 is WZR/XZR and is discarded.
///
/// # Safety
/// `vcpu` must be a live handle.
pub(super) unsafe fn write_gp(vcpu: hv_vcpu_t, reg: u8, value: u64) -> Result<(), HvfError> {
    if u32::from(reg) > HV_REG_X30 {
        return Ok(());
    }
    // SAFETY: HV_REG_X0 + reg is a valid GP register index for reg in 0..=30.
    let rc = unsafe { hv_vcpu_set_reg(vcpu, HV_REG_X0 + u32::from(reg), value) };
    if rc != HV_SUCCESS {
        return Err(HvfError::SetReg(rc));
    }
    Ok(())
}

/// Advance PC past the faulting (4-byte) instruction.
///
/// # Safety
/// `vcpu` must be a live handle.
pub(super) unsafe fn advance_pc(vcpu: hv_vcpu_t) -> Result<(), HvfError> {
    let mut pc = 0u64;
    // SAFETY: HV_REG_PC is a valid register on a live vCPU.
    unsafe {
        if hv_vcpu_get_reg(vcpu, HV_REG_PC, &mut pc) != HV_SUCCESS {
            return Err(HvfError::GetReg(0));
        }
        if hv_vcpu_set_reg(vcpu, HV_REG_PC, pc + 4) != HV_SUCCESS {
            return Err(HvfError::SetReg(0));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esr_ec_extracts_exception_class() {
        assert_eq!(esr_ec(0x5a00_0000), EC_HVC_AARCH64);
        assert_eq!(
            esr_ec(u64::from(EC_DATA_ABORT_LOWER_EL) << 26),
            EC_DATA_ABORT_LOWER_EL
        );
    }

    #[test]
    fn decodes_a_32bit_store_to_x0() {
        let iss = (1 << 24) | (2 << 22) | (1 << 6);
        let da = decode_data_abort((u64::from(EC_DATA_ABORT_LOWER_EL) << 26) | iss);
        assert!(da.isv && da.is_write);
        assert_eq!(da.size, 4);
        assert_eq!(da.reg, 0);
    }

    #[test]
    fn decodes_a_byte_load_to_x5() {
        let da = decode_data_abort((1 << 24) | (5 << 16));
        assert!(da.isv && !da.is_write);
        assert_eq!(da.size, 1);
        assert_eq!(da.reg, 5);
    }
}
