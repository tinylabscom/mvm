//! Console boot proof: MMIO trap-and-emulate + an emulated PL011 UART.
//!
//! Adds the load-bearing capability a kernel boot needs: a guest store to an
//! unmapped address (a device register) traps `hv_vcpu_run` as a data abort, the
//! run loop decodes the faulting access from the ESR, dispatches it to the
//! [`Pl011`] model, advances PC past the instruction, and resumes. The guest
//! here is a hand-assembled stand-in that writes `"OK\n"` to the UART data
//! register exactly as a kernel's `earlycon=pl011` would, so a clean run proves
//! the host can drive a virtual console device for the guest.
//!
//! Loading a real Linux `Image` + DTB and letting the kernel itself drive this
//! UART is the next slice (it needs a kernel file); the device-model substrate
//! is what this proves.

use std::alloc::{Layout, alloc_zeroed, dealloc};

use super::HvfError;
use super::boot_smoke::{GUEST_RAM_SIZE, PAGE};
use super::device::{MmioDevice, Pl011};
use super::sys::*;

/// PL011 base, well above the 2 MiB of mapped guest RAM so accesses to it fault
/// out as MMIO rather than hitting backing memory.
const UART_BASE: u64 = 0x0900_0000;

/// Hand-assembled arm64 stand-in for a kernel's earlycon writes, from IPA 0:
/// ```text
///   movz x1, #0x0900, lsl #16   ; 0xD2A12001  x1 = UART_BASE (0x09000000)
///   movz x0, #'O'               ; 0xD28009E0
///   str  w0, [x1]               ; 0xB9000020  -> MMIO data abort
///   movz x0, #'K'               ; 0xD2800960
///   str  w0, [x1]               ; 0xB9000020
///   movz x0, #'\n'              ; 0xD2800140
///   str  w0, [x1]               ; 0xB9000020
///   hvc  #0                     ; 0xD4000002  -> done
/// ```
const PROGRAM: [u32; 8] = [
    0xD2A1_2001,
    0xD280_09E0,
    0xB900_0020,
    0xD280_0960,
    0xB900_0020,
    0xD280_0140,
    0xB900_0020,
    0xD400_0002,
];

/// What the guest emitted to the console, plus how the run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleProof {
    pub output: Vec<u8>,
    pub mmio_writes: usize,
    pub exit_reason: hv_exit_reason_t,
}

/// A decoded data-abort syndrome (ESR ISS for a GP-register load/store).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DataAbort {
    /// Instruction syndrome valid — required to emulate the access.
    isv: bool,
    /// Access width in bytes.
    size: u8,
    /// GP register index (X0..X30, or 31 = XZR/WZR).
    reg: u8,
    /// True for a store, false for a load.
    is_write: bool,
}

/// Exception class field of an ESR value.
fn esr_ec(esr: u64) -> u32 {
    ((esr >> 26) & 0x3f) as u32
}

/// Decode the data-abort ISS fields used for MMIO emulation.
fn decode_data_abort(esr: u64) -> DataAbort {
    DataAbort {
        isv: (esr >> 24) & 1 == 1,
        size: 1u8 << ((esr >> 22) & 3),
        reg: ((esr >> 16) & 0x1f) as u8,
        is_write: (esr >> 6) & 1 == 1,
    }
}

/// Run the console stand-in and return what it printed via the emulated UART.
pub fn console_smoke() -> Result<ConsoleProof, HvfError> {
    let layout = Layout::from_size_align(GUEST_RAM_SIZE, PAGE).map_err(|_| HvfError::Alloc)?;
    // SAFETY: non-zero layout; pointer null-checked and freed on every path.
    let ram = unsafe { alloc_zeroed(layout) };
    if ram.is_null() {
        return Err(HvfError::Alloc);
    }
    // SAFETY: `ram` owns GUEST_RAM_SIZE writable bytes; PROGRAM fits in page 0.
    unsafe {
        let prog =
            core::slice::from_raw_parts(PROGRAM.as_ptr().cast::<u8>(), size_of_val(&PROGRAM));
        core::ptr::copy_nonoverlapping(prog.as_ptr(), ram, prog.len());
    }

    // SAFETY: FFI into Hypervisor.framework; the VM is destroyed before `ram` is
    // freed and the vCPU is created/run/destroyed on this one thread.
    let result = unsafe {
        let rc = hv_vm_create(core::ptr::null_mut());
        if rc != HV_SUCCESS {
            dealloc(ram, layout);
            return Err(HvfError::VmCreate(rc));
        }
        let r = run_with_uart(ram);
        hv_vm_destroy();
        r
    };

    // SAFETY: same layout used for the allocation.
    unsafe { dealloc(ram, layout) };
    result
}

/// # Safety
/// Must run between `hv_vm_create`/`hv_vm_destroy`; `ram` is the guest RAM with
/// the program loaded at offset 0.
unsafe fn run_with_uart(ram: *mut u8) -> Result<ConsoleProof, HvfError> {
    unsafe {
        let flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
        let rc = hv_vm_map(ram.cast(), 0, GUEST_RAM_SIZE, flags);
        if rc != HV_SUCCESS {
            return Err(HvfError::Map(rc));
        }

        let mut vcpu: hv_vcpu_t = 0;
        let mut exit: *mut hv_vcpu_exit_t = core::ptr::null_mut();
        let rc = hv_vcpu_create(&mut vcpu, &mut exit, core::ptr::null_mut());
        if rc != HV_SUCCESS {
            return Err(HvfError::VcpuCreate(rc));
        }
        if hv_vcpu_set_reg(vcpu, HV_REG_PC, 0) != HV_SUCCESS
            || hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0x3c5) != HV_SUCCESS
        {
            hv_vcpu_destroy(vcpu);
            return Err(HvfError::SetReg(0));
        }

        let mut uart = Pl011::new(UART_BASE);
        let result = drive(vcpu, exit, &mut uart);
        hv_vcpu_destroy(vcpu);
        result.map(|(mmio_writes, exit_reason)| ConsoleProof {
            output: uart.output,
            mmio_writes,
            exit_reason,
        })
    }
}

/// The run loop: resume the vCPU, servicing MMIO faults against `uart`, until the
/// guest issues `hvc`. Returns `(mmio_write_count, final_exit_reason)`.
///
/// # Safety
/// `vcpu`/`exit` come from a live `hv_vcpu_create`; called on the owning thread.
unsafe fn drive(
    vcpu: hv_vcpu_t,
    exit: *mut hv_vcpu_exit_t,
    uart: &mut Pl011,
) -> Result<(usize, hv_exit_reason_t), HvfError> {
    unsafe {
        let mut mmio_writes = 0usize;
        loop {
            let rc = hv_vcpu_run(vcpu);
            if rc != HV_SUCCESS {
                return Err(HvfError::Run(rc));
            }
            let e = *exit;
            match e.reason {
                HV_EXIT_REASON_VTIMER_ACTIVATED => continue,
                HV_EXIT_REASON_EXCEPTION => {}
                other => return Err(HvfError::UnexpectedExit(other)),
            }

            let esr = e.exception.syndrome;
            match esr_ec(esr) {
                EC_HVC_AARCH64 => return Ok((mmio_writes, e.reason)),
                EC_DATA_ABORT_LOWER_EL => {
                    let da = decode_data_abort(esr);
                    if !da.isv {
                        return Err(HvfError::NoSyndrome);
                    }
                    let ipa = e.exception.physical_address;
                    if !uart.contains(ipa) {
                        return Err(HvfError::UnhandledMmio(ipa));
                    }
                    let offset = ipa - uart.base();
                    if da.is_write {
                        let value = read_gp(vcpu, da.reg)?;
                        uart.write(offset, value, da.size);
                        mmio_writes += 1;
                    } else {
                        let value = uart.read(offset, da.size);
                        write_gp(vcpu, da.reg, value)?;
                    }
                    advance_pc(vcpu)?;
                }
                ec => return Err(HvfError::UnexpectedException(ec)),
            }
        }
    }
}

/// Read GP register `reg` (X0..X30); index 31 is XZR and reads as 0.
///
/// # Safety
/// `vcpu` must be a live handle.
unsafe fn read_gp(vcpu: hv_vcpu_t, reg: u8) -> Result<u64, HvfError> {
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
unsafe fn write_gp(vcpu: hv_vcpu_t, reg: u8, value: u64) -> Result<(), HvfError> {
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

/// Advance PC past the faulting (4-byte) instruction so the guest resumes after
/// the emulated access instead of re-faulting on it.
///
/// # Safety
/// `vcpu` must be a live handle.
unsafe fn advance_pc(vcpu: hv_vcpu_t) -> Result<(), HvfError> {
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
        // syndrome=0x5a000000 (the boot proof's hvc): EC = 0x16.
        assert_eq!(esr_ec(0x5a00_0000), EC_HVC_AARCH64);
    }

    #[test]
    fn decodes_a_32bit_store_to_x0() {
        // ISV=1, SAS=2 (word, 4 bytes), SRT=0, WnR=1.
        let iss = (1 << 24) | (2 << 22) | (0 << 16) | (1 << 6);
        let esr = (u64::from(EC_DATA_ABORT_LOWER_EL) << 26) | iss;
        let da = decode_data_abort(esr);
        assert!(da.isv && da.is_write);
        assert_eq!(da.size, 4);
        assert_eq!(da.reg, 0);
    }

    #[test]
    fn decodes_a_byte_load_to_x5() {
        // ISV=1, SAS=0 (byte), SRT=5, WnR=0.
        let iss = (1 << 24) | (0 << 22) | (5 << 16);
        let da = decode_data_abort(iss);
        assert!(da.isv && !da.is_write);
        assert_eq!(da.size, 1);
        assert_eq!(da.reg, 5);
    }

    // Live run needs the hypervisor entitlement — run the hvf-console-smoke
    // example. Ignored here as the executable spec of the expected result.
    #[test]
    #[ignore = "needs com.apple.security.hypervisor entitlement; run the hvf-console-smoke example"]
    fn live_console_emits_ok() {
        let proof = console_smoke().expect("HVF console boot");
        assert_eq!(proof.output, b"OK\n");
        assert_eq!(proof.mmio_writes, 3);
        assert_eq!(proof.exit_reason, HV_EXIT_REASON_EXCEPTION);
    }
}
