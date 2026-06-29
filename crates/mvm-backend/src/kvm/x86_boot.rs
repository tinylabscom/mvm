//! x86_64 Linux boot protocol — pure setup over a guest-RAM slice (gpa 0 ==
//! `mem[0]`), returning the register state to enter the kernel's 64-bit entry in
//! long mode. No hypervisor dependency, so it is unit-testable on any host; the
//! KVM backend writes the returned [`BootRegs`] onto the vCPU's SREGS/REGS and
//! runs. This is the spike recipe (`spikes/kvm-x86-boot/`) productionized.
//!
//! Reference: `Documentation/arch/x86/boot.rst` (the Linux boot protocol).

/// Guest-physical layout. Everything but the kernel/initrd lives below 1 MiB.
pub mod layout {
    /// Page-map level 4 (top of the 4-level walk).
    pub const PML4: u64 = 0x1000;
    /// Page-directory pointer table.
    pub const PDPT: u64 = 0x2000;
    /// Page directory (512 × 2 MiB = identity-maps the low 1 GiB).
    pub const PD: u64 = 0x3000;
    /// Global descriptor table (null, null, code64, data).
    pub const GDT: u64 = 0x4000;
    /// `struct boot_params` (the "zero page"), passed to the kernel via RSI.
    pub const BOOT_PARAMS: u64 = 0x1_0000;
    /// Kernel command line (NUL-terminated ASCII).
    pub const CMDLINE: u64 = 0x2_0000;
    /// Protected-mode kernel load address; the 64-bit entry is here + 0x200.
    pub const KERNEL: u64 = 0x10_0000;
}

// boot_params / setup_header field offsets within the zero page.
const BP_E820_ENTRIES: u64 = 0x1e8;
const BP_SETUP_HEADER: u64 = 0x1f1;
const HDR_SETUP_SECTS: usize = 0x1f1;
const HDR_TYPE_OF_LOADER: u64 = 0x210;
const HDR_LOADFLAGS: u64 = 0x211;
const HDR_RAMDISK_IMAGE: u64 = 0x218;
const HDR_RAMDISK_SIZE: u64 = 0x21c;
const HDR_CMD_LINE_PTR: u64 = 0x228;
const HDR_INIT_SIZE: usize = 0x260;
const SETUP_HEADER_END: u64 = 0x268;
const BP_E820_TABLE: u64 = 0x2d0;
const E820_ENTRY_STRIDE: u64 = 20; // packed { u64 addr; u64 size; u32 type; }
const E820_RAM: u32 = 1;

// Long-mode control regs applied on entry (proven in spikes/kvm-x86-boot).
const CR0_PE_PG: u64 = 0x8000_0001;
const CR4_PAE: u64 = 0x20;
const EFER_LME_LMA: u64 = 0x500;
const GDT_CODE64: u64 = 0x00af_9a00_0000_ffff;
const GDT_DATA: u64 = 0x00cf_9200_0000_ffff;
const BOOT_CS: u16 = 0x10; // GDT entry 2
const BOOT_DS: u16 = 0x18; // GDT entry 3

const PAGE: u64 = 0x1000;
/// The ramdisk load address is a 32-bit field capped at this protocol-safe
/// ceiling; placing it above truncates and the initramfs silently fails to load.
const INITRD_ADDR_CEILING: u64 = 0x8000_0000;

/// A segment register's portable state; the backend copies it onto its native
/// descriptor type (KVM `kvm_segment`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub type_: u8,
    pub dpl: u8,
    pub s: u8,
    pub present: u8,
    pub l: u8,
    pub db: u8,
    pub g: u8,
}

/// vCPU register state that enters the kernel in long mode. The backend applies
/// it to SREGS/REGS; DS/ES/SS/FS/GS all share [`BootRegs::ds`].
#[derive(Clone, Copy, Debug)]
pub struct BootRegs {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub gdt_base: u64,
    pub gdt_limit: u16,
    pub cs: Segment,
    pub ds: Segment,
    pub rip: u64,
    pub rsi: u64,
    pub rflags: u64,
}

/// Inputs to [`setup_boot`].
pub struct BootConfig<'a> {
    /// Total guest RAM (also `mem.len()`).
    pub mem_size: usize,
    /// Kernel command line (without the trailing NUL — added here).
    pub cmdline: &'a str,
    /// bzImage bytes (real-mode setup sectors + protected-mode kernel).
    pub bzimage: &'a [u8],
    /// Optional initramfs (cpio) the kernel unpacks as its initial rootfs.
    pub initrd: Option<&'a [u8]>,
}

/// Boot-setup failures — all are bad-input problems, never internal invariants.
#[derive(Debug, PartialEq, Eq)]
pub enum BootError {
    BzImageTooSmall { len: usize, need: usize },
    SetupSectorsOutOfRange { pm_offset: usize, len: usize },
    MemTooSmall { need: u64, have: usize },
    CmdlineTooLong { len: usize, max: u64 },
}

impl std::fmt::Display for BootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootError::BzImageTooSmall { len, need } => {
                write!(f, "bzImage too small: {len} bytes, need >= {need}")
            }
            BootError::SetupSectorsOutOfRange { pm_offset, len } => {
                write!(
                    f,
                    "setup sectors out of range: pm at +{pm_offset:#x} past end {len}"
                )
            }
            BootError::MemTooSmall { need, have } => {
                write!(f, "guest RAM too small: need {need:#x}, have {have:#x}")
            }
            BootError::CmdlineTooLong { len, max } => {
                write!(f, "cmdline too long: {len} bytes, max {max}")
            }
        }
    }
}

impl std::error::Error for BootError {}

/// Bounds-checked little-endian writer over guest RAM (gpa 0 == `mem[0]`).
struct GuestWriter<'a> {
    mem: &'a mut [u8],
}

impl GuestWriter<'_> {
    fn write(&mut self, gpa: u64, bytes: &[u8]) -> Result<(), BootError> {
        let start = gpa as usize;
        let end = start
            .checked_add(bytes.len())
            .filter(|&e| e <= self.mem.len())
            .ok_or(BootError::MemTooSmall {
                need: gpa + bytes.len() as u64,
                have: self.mem.len(),
            })?;
        self.mem[start..end].copy_from_slice(bytes);
        Ok(())
    }
    fn write_u8(&mut self, gpa: u64, v: u8) -> Result<(), BootError> {
        self.write(gpa, &[v])
    }
    fn write_u32(&mut self, gpa: u64, v: u32) -> Result<(), BootError> {
        self.write(gpa, &v.to_le_bytes())
    }
    fn write_u64(&mut self, gpa: u64, v: u64) -> Result<(), BootError> {
        self.write(gpa, &v.to_le_bytes())
    }
}

/// Choose the initramfs load address: highest page-aligned base that fits the
/// ramdisk while staying clear of the kernel's `[KERNEL, KERNEL + footprint)`
/// decompression window (a ramdisk inside it is clobbered during decompression).
fn initrd_load_addr(mem_size: u64, footprint: u64, len: u64) -> Result<u64, BootError> {
    let floor = (layout::KERNEL + footprint).next_multiple_of(PAGE);
    let top = mem_size.min(INITRD_ADDR_CEILING);
    match top.checked_sub(len).map(|a| a & !(PAGE - 1)) {
        Some(addr) if addr >= floor => Ok(addr),
        _ => Err(BootError::MemTooSmall {
            need: floor + len,
            have: mem_size as usize,
        }),
    }
}

/// Build the boot environment in `mem` and return the entry register state.
pub fn setup_boot(mem: &mut [u8], cfg: &BootConfig) -> Result<BootRegs, BootError> {
    use layout::*;
    debug_assert_eq!(
        mem.len(),
        cfg.mem_size,
        "mem slice must be exactly mem_size"
    );

    let bz = cfg.bzimage;
    if (bz.len() as u64) < SETUP_HEADER_END {
        return Err(BootError::BzImageTooSmall {
            len: bz.len(),
            need: SETUP_HEADER_END as usize,
        });
    }
    // setup_sects of 0 historically means 4.
    let setup_sects = if bz[HDR_SETUP_SECTS] == 0 {
        4
    } else {
        bz[HDR_SETUP_SECTS]
    };
    let pm_offset = (setup_sects as usize + 1) * 512;
    if pm_offset >= bz.len() {
        return Err(BootError::SetupSectorsOutOfRange {
            pm_offset,
            len: bz.len(),
        });
    }
    let pm_kernel = &bz[pm_offset..];

    let init_size =
        u32::from_le_bytes(bz[HDR_INIT_SIZE..HDR_INIT_SIZE + 4].try_into().unwrap()) as u64;
    let footprint = (pm_kernel.len() as u64).max(init_size);
    let mut high_water = KERNEL + pm_kernel.len() as u64;
    let initrd_addr = match cfg.initrd {
        Some(rd) => {
            let addr = initrd_load_addr(cfg.mem_size as u64, footprint, rd.len() as u64)?;
            high_water = high_water.max(addr + rd.len() as u64);
            Some(addr)
        }
        None => None,
    };
    if high_water > cfg.mem_size as u64 {
        return Err(BootError::MemTooSmall {
            need: high_water,
            have: cfg.mem_size,
        });
    }
    let cmdline_max = KERNEL - CMDLINE;
    if cfg.cmdline.len() as u64 + 1 > cmdline_max {
        return Err(BootError::CmdlineTooLong {
            len: cfg.cmdline.len(),
            max: cmdline_max,
        });
    }

    let mut w = GuestWriter { mem };

    // 1. Identity-map the low 1 GiB (PML4 -> PDPT -> PD, 2 MiB pages).
    w.write_u64(PML4, PDPT | 0x3)?;
    w.write_u64(PDPT, PD | 0x3)?;
    for i in 0..512u64 {
        w.write_u64(PD + i * 8, (i * 0x20_0000) | 0x83)?; // present|rw|ps
    }

    // 2. GDT: [0]=null, [1]=null, [2]=code64, [3]=data.
    w.write_u64(GDT, 0)?;
    w.write_u64(GDT + 8, 0)?;
    w.write_u64(GDT + 16, GDT_CODE64)?;
    w.write_u64(GDT + 24, GDT_DATA)?;

    // 3. boot_params: copy the setup header, then patch loader/cmdline/ramdisk.
    w.write(
        BOOT_PARAMS + BP_SETUP_HEADER,
        &bz[BP_SETUP_HEADER as usize..SETUP_HEADER_END as usize],
    )?;
    w.write_u8(BOOT_PARAMS + HDR_TYPE_OF_LOADER, 0xff)?;
    w.write_u8(
        BOOT_PARAMS + HDR_LOADFLAGS,
        bz[HDR_LOADFLAGS as usize] | 0x01,
    )?;
    match (cfg.initrd, initrd_addr) {
        (Some(rd), Some(addr)) => {
            w.write_u32(BOOT_PARAMS + HDR_RAMDISK_IMAGE, addr as u32)?;
            w.write_u32(BOOT_PARAMS + HDR_RAMDISK_SIZE, rd.len() as u32)?;
        }
        _ => {
            w.write_u32(BOOT_PARAMS + HDR_RAMDISK_IMAGE, 0)?;
            w.write_u32(BOOT_PARAMS + HDR_RAMDISK_SIZE, 0)?;
        }
    }
    w.write_u32(BOOT_PARAMS + HDR_CMD_LINE_PTR, CMDLINE as u32)?;

    // 4. Command line.
    w.write(CMDLINE, cfg.cmdline.as_bytes())?;
    w.write_u8(CMDLINE + cfg.cmdline.len() as u64, 0)?;

    // 5. e820: 0..640 KiB, then 1 MiB..end (a single entry trips the e801
    //    fallback -> only ~640 KiB usable -> alloc_low_pages panic).
    let mut e820 = |slot: u64, addr: u64, size: u64, typ: u32| -> Result<(), BootError> {
        let base = BOOT_PARAMS + BP_E820_TABLE + slot * E820_ENTRY_STRIDE;
        w.write_u64(base, addr)?;
        w.write_u64(base + 8, size)?;
        w.write_u32(base + 16, typ)
    };
    e820(0, 0, 0x9_fc00, E820_RAM)?;
    e820(1, KERNEL, cfg.mem_size as u64 - KERNEL, E820_RAM)?;
    w.write_u8(BOOT_PARAMS + BP_E820_ENTRIES, 2)?;

    // 6. Load the protected-mode kernel and the initramfs.
    w.write(KERNEL, pm_kernel)?;
    if let (Some(rd), Some(addr)) = (cfg.initrd, initrd_addr) {
        w.write(addr, rd)?;
    }

    // 7. Long-mode entry register state.
    let cs = Segment {
        selector: BOOT_CS,
        base: 0,
        limit: 0xf_ffff,
        type_: 0xb,
        dpl: 0,
        s: 1,
        present: 1,
        l: 1,
        db: 0,
        g: 1,
    };
    let ds = Segment {
        selector: BOOT_DS,
        base: 0,
        limit: 0xf_ffff,
        type_: 0x3,
        dpl: 0,
        s: 1,
        present: 1,
        l: 0,
        db: 1,
        g: 1,
    };
    Ok(BootRegs {
        cr0: CR0_PE_PG,
        cr3: PML4,
        cr4: CR4_PAE,
        efer: EFER_LME_LMA,
        gdt_base: GDT,
        gdt_limit: 0x1f, // 4 entries * 8 - 1
        cs,
        ds,
        rip: KERNEL + 0x200,
        rsi: BOOT_PARAMS,
        rflags: 2,
    })
}

#[cfg(test)]
mod tests {
    use super::layout::*;
    use super::*;

    /// A synthetic bzImage: 1 setup sector + a protected-mode body, with a valid
    /// setup header (setup_sects, init_size).
    fn fake_bzimage(pm_len: usize, init_size: u32) -> Vec<u8> {
        let mut bz = vec![0u8; 512 + pm_len];
        bz[HDR_SETUP_SECTS] = 0; // -> treated as 4 setup sects... but pm starts at (4+1)*512
        // use 0 setup_sects => 4; size the buffer so pm offset is valid
        bz.resize(5 * 512 + pm_len, 0);
        bz[HDR_LOADFLAGS as usize] = 0x10; // some image bits to preserve
        bz[HDR_INIT_SIZE..HDR_INIT_SIZE + 4].copy_from_slice(&init_size.to_le_bytes());
        // mark the pm body so we can assert it was copied
        for (i, b) in bz[5 * 512..].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        bz
    }

    fn rd_u64(mem: &[u8], gpa: u64) -> u64 {
        u64::from_le_bytes(mem[gpa as usize..gpa as usize + 8].try_into().unwrap())
    }
    fn rd_u32(mem: &[u8], gpa: u64) -> u32 {
        u32::from_le_bytes(mem[gpa as usize..gpa as usize + 4].try_into().unwrap())
    }

    #[test]
    fn page_tables_and_gdt_written() {
        let mut mem = vec![0u8; 512 << 20];
        let bz = fake_bzimage(4096, 0x10_0000);
        let cfg = BootConfig {
            mem_size: mem.len(),
            cmdline: "console=ttyS0",
            bzimage: &bz,
            initrd: None,
        };
        setup_boot(&mut mem, &cfg).unwrap();
        assert_eq!(rd_u64(&mem, PML4), PDPT | 0x3);
        assert_eq!(rd_u64(&mem, PDPT), PD | 0x3);
        assert_eq!(rd_u64(&mem, PD), 0x83); // entry 0: addr 0, present|rw|ps
        assert_eq!(rd_u64(&mem, PD + 8), 0x20_0000 | 0x83); // entry 1: 2 MiB
        assert_eq!(rd_u64(&mem, GDT + 16), GDT_CODE64);
        assert_eq!(rd_u64(&mem, GDT + 24), GDT_DATA);
    }

    #[test]
    fn e820_has_two_entries() {
        let mut mem = vec![0u8; 512 << 20];
        let bz = fake_bzimage(4096, 0x10_0000);
        let cfg = BootConfig {
            mem_size: mem.len(),
            cmdline: "x",
            bzimage: &bz,
            initrd: None,
        };
        setup_boot(&mut mem, &cfg).unwrap();
        assert_eq!(mem[(BOOT_PARAMS + BP_E820_ENTRIES) as usize], 2);
        // entry 0: 0..640 KiB
        assert_eq!(rd_u64(&mem, BOOT_PARAMS + BP_E820_TABLE), 0);
        assert_eq!(rd_u64(&mem, BOOT_PARAMS + BP_E820_TABLE + 8), 0x9_fc00);
        assert_eq!(rd_u32(&mem, BOOT_PARAMS + BP_E820_TABLE + 16), E820_RAM);
        // entry 1: 1 MiB..end
        let e1 = BOOT_PARAMS + BP_E820_TABLE + E820_ENTRY_STRIDE;
        assert_eq!(rd_u64(&mem, e1), KERNEL);
        assert_eq!(rd_u64(&mem, e1 + 8), mem.len() as u64 - KERNEL);
    }

    #[test]
    fn boot_regs_enter_long_mode_at_entry() {
        let mut mem = vec![0u8; 512 << 20];
        let bz = fake_bzimage(4096, 0x10_0000);
        let cfg = BootConfig {
            mem_size: mem.len(),
            cmdline: "x",
            bzimage: &bz,
            initrd: None,
        };
        let r = setup_boot(&mut mem, &cfg).unwrap();
        assert_eq!(r.cr0, CR0_PE_PG);
        assert_eq!(r.cr3, PML4);
        assert_eq!(r.cr4, CR4_PAE);
        assert_eq!(r.efer, EFER_LME_LMA);
        assert_eq!(r.rip, KERNEL + 0x200);
        assert_eq!(r.rsi, BOOT_PARAMS);
        assert_eq!(r.cs.l, 1); // 64-bit code
        assert_eq!(r.cs.selector, BOOT_CS);
        assert_eq!(r.ds.selector, BOOT_DS);
        // loader id patched; image loadflags preserved + LOADED_HIGH set
        assert_eq!(mem[(BOOT_PARAMS + HDR_TYPE_OF_LOADER) as usize], 0xff);
        assert_eq!(mem[(BOOT_PARAMS + HDR_LOADFLAGS) as usize], 0x11);
    }

    #[test]
    fn kernel_body_copied_to_1mib() {
        let mut mem = vec![0u8; 512 << 20];
        let bz = fake_bzimage(4096, 0x10_0000);
        let cfg = BootConfig {
            mem_size: mem.len(),
            cmdline: "x",
            bzimage: &bz,
            initrd: None,
        };
        setup_boot(&mut mem, &cfg).unwrap();
        // pm body starts at (4+1)*512 in the bzImage, byte value (i % 251)
        assert_eq!(mem[KERNEL as usize], 0);
        assert_eq!(mem[KERNEL as usize + 1], 1);
    }

    #[test]
    fn initrd_placed_top_down_clear_of_kernel() {
        let mut mem = vec![0u8; 512 << 20];
        let bz = fake_bzimage(4096, 0x10_0000);
        let rd = vec![0xabu8; 4096];
        let cfg = BootConfig {
            mem_size: mem.len(),
            cmdline: "x",
            bzimage: &bz,
            initrd: Some(&rd),
        };
        setup_boot(&mut mem, &cfg).unwrap();
        let addr = rd_u32(&mem, BOOT_PARAMS + HDR_RAMDISK_IMAGE) as u64;
        let size = rd_u32(&mem, BOOT_PARAMS + HDR_RAMDISK_SIZE) as u64;
        assert_eq!(size, rd.len() as u64);
        assert!(
            addr >= KERNEL + 0x10_0000,
            "initrd must clear the kernel footprint"
        );
        assert_eq!(addr & (PAGE - 1), 0, "page aligned");
        assert_eq!(mem[addr as usize], 0xab);
    }

    #[test]
    fn rejects_truncated_bzimage() {
        let mut mem = vec![0u8; 1 << 20];
        let bz = vec![0u8; 16];
        let cfg = BootConfig {
            mem_size: mem.len(),
            cmdline: "x",
            bzimage: &bz,
            initrd: None,
        };
        assert!(matches!(
            setup_boot(&mut mem, &cfg),
            Err(BootError::BzImageTooSmall { .. })
        ));
    }

    #[test]
    fn rejects_too_small_ram() {
        // RAM smaller than the kernel image end.
        let mut mem = vec![0u8; 2 << 20];
        let bz = fake_bzimage(8 << 20, 0x10_0000); // 8 MiB pm body > 2 MiB RAM
        let cfg = BootConfig {
            mem_size: mem.len(),
            cmdline: "x",
            bzimage: &bz,
            initrd: None,
        };
        assert!(matches!(
            setup_boot(&mut mem, &cfg),
            Err(BootError::MemTooSmall { .. })
        ));
    }
}
