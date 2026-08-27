//! Guest-RAM mapping + minimal vCPU boot — the load-bearing primitive a raw-HVF
//! backend is built on.
//!
//! Maps a block of host memory as guest RWX RAM, loads four arm64 instructions,
//! and runs the vCPU. The guest writes a magic value to a register **and** to a
//! mapped data page, then `hvc #0` traps back to the host. A clean run proves
//! the three things the backend depends on:
//!   1. code is fetched and executed from mapped RWX guest RAM,
//!   2. the guest can write to mapped RW guest RAM (host reads it back),
//!   3. guest register + exit state is observable from the host.
//!
//! Producing a real kernel/rootfs to boot is later backend work; this is the
//! hardware-level substrate that proves the path exists on this host.

use std::alloc::{Layout, alloc_zeroed, dealloc};

use super::sys::*;

/// 2 MiB of guest RAM (a multiple of the 16 KiB Apple-silicon page size).
pub(super) const GUEST_RAM_SIZE: usize = 0x20_0000;
/// Apple-silicon hypervisor page size; `hv_vm_map` requires page alignment.
pub(super) const PAGE: usize = 16384;
/// Where the guest stores its magic word (inside the mapped region).
const DATA_IPA: u64 = 0x1000;
/// The value the guest puts in `x0` and stores to `DATA_IPA`.
pub const MAGIC: u64 = 0x42;

/// Hand-assembled arm64, executed from IPA 0:
/// ```text
///   movz x0, #0x42        ; 0xD2800840
///   movz x1, #0x1000      ; 0xD2820001  (DATA_IPA)
///   str  x0, [x1]         ; 0xF9000020
///   hvc  #0               ; 0xD4000002  -> trap to host
/// ```
const PROGRAM: [u32; 4] = [0xD280_0840, 0xD282_0001, 0xF900_0020, 0xD400_0002];

/// What the guest left behind after a successful run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootProof {
    /// `x0` read back from the guest vCPU (expect [`MAGIC`]).
    pub x0: u64,
    /// The word the guest stored into mapped RAM at `DATA_IPA` (expect [`MAGIC`]).
    pub data_word: u64,
    /// The vCPU exit reason (expect [`HV_EXIT_REASON_EXCEPTION`] from the `hvc`).
    pub exit_reason: hv_exit_reason_t,
    /// ESR syndrome of the trapping exception.
    pub syndrome: u64,
}

/// Why an HVF boot could not be set up.
///
/// One variant per distinguishable cause. `BadKernel` used to be a single unit
/// variant returned from more than twenty places, so "the kernel file is
/// missing", "the kernel is empty", "the image does not fit in guest RAM" and
/// "too many disks were attached" all printed as the same four words, and the
/// operator had to read the source and guess which one they had.
///
/// [`HvfError`] is `Copy` — it is returned through the vCPU run loop — so this
/// carries an [`std::io::ErrorKind`] and sizes rather than a `PathBuf` and an
/// `io::Error`. That is enough to tell the causes apart; the path is known to
/// whoever supplied it and belongs where the error is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootFault {
    /// Opening or stat-ing the kernel image failed.
    KernelOpen(std::io::ErrorKind),
    /// Reading the kernel image header failed (short file, I/O error).
    KernelRead(std::io::ErrorKind),
    /// The image is zero bytes.
    KernelEmpty,
    /// The bytes are not a usable arm64 `Image` (bad magic or header).
    KernelNotArm64Image,
    /// The image does not fit the window it must load into.
    KernelTooLarge { needed: usize, available: usize },
    /// A load offset is not page-aligned.
    Misaligned { offset: usize },
    /// A length or address computation overflowed.
    Overflow,
    /// Guest RAM is too small to hold even the DTB window.
    GuestRamTooSmall { ram: usize, needed: usize },
    /// No gap between the kernel and the DTB window for the initramfs.
    InitrdNoRoom {
        kernel_end: usize,
        initrd_len: usize,
        dtb_offset: usize,
    },
    /// More disks than the device model has MMIO slots for.
    TooManyDisks { given: usize, max: usize },
    /// More virtiofs shares than the device model has MMIO slots for.
    TooManyFilesystems { given: usize, max: usize },
    /// The generated device tree exceeds its reserved window.
    DtbTooLarge { needed: usize, max: usize },
}

/// Failure points along the HVF boot path, each carrying the raw `hv_return_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvfError {
    Alloc,
    VmCreate(hv_return_t),
    Map(hv_return_t),
    VcpuCreate(hv_return_t),
    SetReg(hv_return_t),
    Run(hv_return_t),
    GetReg(hv_return_t),
    /// A data abort whose syndrome is not decodable (ISV=0) — can't emulate it.
    NoSyndrome,
    /// MMIO fault outside any modeled device's range.
    UnhandledMmio(u64),
    /// vCPU exited for a reason the loop doesn't handle.
    UnexpectedExit(hv_exit_reason_t),
    /// An exception with an unexpected class (ESR `EC`).
    UnexpectedException(u32),
    /// The boot could not be set up. Carries which check failed.
    BadBoot(BootFault),
    /// In-kernel GICv3 creation failed (needs macOS 15+).
    GicCreate(hv_return_t),
    /// A vCPU's GIC redistributor frame is not where the device tree told the
    /// guest it would be.
    ///
    /// Its own variant because the alternative is not a worse machine, it is a
    /// hang: the guest matches CPUs to redistributors during IRQ init, before
    /// the console exists, so the boot stops with nothing written anywhere.
    /// Naming the CPU and both addresses is the difference between a five-minute
    /// fix and a day of bisecting a silent failure.
    RedistributorMismatch {
        cpu: u32,
        expected: u64,
        actual: u64,
    },
    /// Serialized HVF state failed structural validation.
    SnapshotState(&'static str),
}

/// Whether this host can create an HVF VM right now: both the platform supports
/// it and the launching binary carries the `com.apple.security.hypervisor`
/// entitlement. Creates and immediately destroys a bare VM (no vCPU, no memory).
pub fn probe_available() -> bool {
    // SAFETY: hv_vm_create with NULL config is the documented availability probe;
    // it is balanced by hv_vm_destroy on success and creates nothing on failure.
    unsafe {
        if hv_vm_create(core::ptr::null_mut()) != HV_SUCCESS {
            return false;
        }
        hv_vm_destroy();
        true
    }
}

/// Map guest RAM, run the [`PROGRAM`], and report what the guest produced.
///
/// One VM per process is an HVF constraint, and the vCPU must be created and run
/// on the calling thread — both satisfied here (single VM, single thread).
pub fn boot_smoke() -> Result<BootProof, HvfError> {
    let layout = Layout::from_size_align(GUEST_RAM_SIZE, PAGE).map_err(|_| HvfError::Alloc)?;
    // SAFETY: layout is non-zero-sized; pointer is checked for null below and
    // freed with the same layout on every return path.
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

    // SAFETY: FFI into Hypervisor.framework; every handle is created before use
    // and torn down before the backing memory is freed.
    let result = unsafe { run_guest(ram) };

    // SAFETY: same layout used for the allocation.
    unsafe { dealloc(ram, layout) };
    result
}

/// The unsafe HVF body, factored out so `boot_smoke` always frees `ram`.
///
/// # Safety
/// `ram` must point to at least `GUEST_RAM_SIZE` writable, page-aligned bytes
/// with the program already loaded at offset 0.
unsafe fn run_guest(ram: *mut u8) -> Result<BootProof, HvfError> {
    unsafe {
        let rc = hv_vm_create(core::ptr::null_mut());
        if rc != HV_SUCCESS {
            return Err(HvfError::VmCreate(rc));
        }

        let proof = run_vcpu(ram);

        // Tear the VM down regardless of the vCPU outcome.
        hv_vm_destroy();
        proof
    }
}

/// # Safety
/// Must be called between `hv_vm_create` and `hv_vm_destroy`, with `ram` as in
/// [`run_guest`].
unsafe fn run_vcpu(ram: *mut u8) -> Result<BootProof, HvfError> {
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

        // PC at the start of the program; CPSR = EL1h with DAIF masked (0x3c5)
        // so a pending vtimer/IRQ can't preempt the four instructions.
        if hv_vcpu_set_reg(vcpu, HV_REG_PC, 0) != HV_SUCCESS
            || hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0x3c5) != HV_SUCCESS
        {
            hv_vcpu_destroy(vcpu);
            return Err(HvfError::SetReg(0));
        }

        // Run until a non-vtimer exit (the hvc trap).
        let (exit_reason, syndrome) = loop {
            let rc = hv_vcpu_run(vcpu);
            if rc != HV_SUCCESS {
                hv_vcpu_destroy(vcpu);
                return Err(HvfError::Run(rc));
            }
            let e = *exit;
            if e.reason == HV_EXIT_REASON_VTIMER_ACTIVATED {
                continue;
            }
            break (e.reason, e.exception.syndrome);
        };

        let mut x0 = 0u64;
        let rc = hv_vcpu_get_reg(vcpu, HV_REG_X0, &mut x0);
        hv_vcpu_destroy(vcpu);
        if rc != HV_SUCCESS {
            return Err(HvfError::GetReg(rc));
        }

        let data_word = core::ptr::read_unaligned(ram.add(DATA_IPA as usize).cast::<u64>());
        Ok(BootProof {
            x0,
            data_word,
            exit_reason,
            syndrome,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_encodings_are_stable() {
        // Guards the hand-assembled opcodes — the one bug-prone part that can be
        // checked without the hypervisor entitlement.
        assert_eq!(PROGRAM[0], 0xD280_0840, "movz x0,#0x42");
        assert_eq!(PROGRAM[1], 0xD282_0001, "movz x1,#0x1000");
        assert_eq!(PROGRAM[2], 0xF900_0020, "str x0,[x1]");
        assert_eq!(PROGRAM[3], 0xD400_0002, "hvc #0");
    }

    // The live boot requires the `com.apple.security.hypervisor` entitlement on
    // the test binary, which `cargo test` does not apply. Run it via the
    // codesigned `hvf-smoke` example instead. Kept here, ignored, as the
    // executable spec of the expected hardware result.
    #[test]
    #[ignore = "needs com.apple.security.hypervisor entitlement; run the hvf-smoke example"]
    fn live_boot_writes_magic_to_register_and_ram() {
        let proof = boot_smoke().expect("HVF boot");
        assert_eq!(proof.x0, MAGIC);
        assert_eq!(proof.data_word, MAGIC);
        assert_eq!(proof.exit_reason, HV_EXIT_REASON_EXCEPTION);
    }
}
