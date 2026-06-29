//! Minimal flattened-device-tree (FDT/DTB) builder.
//!
//! Just enough to hand an arm64 Linux kernel a valid device tree: memory, one
//! CPU, PSCI (HVC), an arch timer, and `/chosen` bootargs carrying the
//! `earlycon` directive. All FDT integers are big-endian.

use std::collections::HashMap;

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_END: u32 = 9;
const FDT_VERSION: u32 = 17;
const FDT_LAST_COMP_VERSION: u32 = 16;

/// Incremental FDT writer: accumulates the structure + strings blocks, then
/// emits the full blob with header and (empty) memory-reservation map.
pub struct FdtBuilder {
    structure: Vec<u8>,
    strings: Vec<u8>,
    string_offsets: HashMap<String, u32>,
}

impl Default for FdtBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FdtBuilder {
    pub fn new() -> Self {
        Self {
            structure: Vec::new(),
            strings: Vec::new(),
            string_offsets: HashMap::new(),
        }
    }

    fn token(&mut self, t: u32) {
        self.structure.extend_from_slice(&t.to_be_bytes());
    }

    fn pad_struct(&mut self) {
        while !self.structure.len().is_multiple_of(4) {
            self.structure.push(0);
        }
    }

    fn intern(&mut self, name: &str) -> u32 {
        if let Some(&off) = self.string_offsets.get(name) {
            return off;
        }
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        self.string_offsets.insert(name.to_string(), off);
        off
    }

    pub fn begin_node(&mut self, name: &str) {
        self.token(FDT_BEGIN_NODE);
        self.structure.extend_from_slice(name.as_bytes());
        self.structure.push(0);
        self.pad_struct();
    }

    pub fn end_node(&mut self) {
        self.token(FDT_END_NODE);
    }

    fn prop_raw(&mut self, name: &str, value: &[u8]) {
        let nameoff = self.intern(name);
        self.token(FDT_PROP);
        self.structure
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.structure.extend_from_slice(&nameoff.to_be_bytes());
        self.structure.extend_from_slice(value);
        self.pad_struct();
    }

    pub fn prop_empty(&mut self, name: &str) {
        self.prop_raw(name, &[]);
    }

    pub fn prop_u32(&mut self, name: &str, v: u32) {
        self.prop_raw(name, &v.to_be_bytes());
    }

    pub fn prop_cells(&mut self, name: &str, cells: &[u32]) {
        let mut b = Vec::with_capacity(cells.len() * 4);
        for c in cells {
            b.extend_from_slice(&c.to_be_bytes());
        }
        self.prop_raw(name, &b);
    }

    pub fn prop_str(&mut self, name: &str, s: &str) {
        let mut b = s.as_bytes().to_vec();
        b.push(0);
        self.prop_raw(name, &b);
    }

    pub fn prop_strlist(&mut self, name: &str, list: &[&str]) {
        let mut b = Vec::new();
        for s in list {
            b.extend_from_slice(s.as_bytes());
            b.push(0);
        }
        self.prop_raw(name, &b);
    }

    /// Emit the complete DTB blob.
    pub fn finish(mut self) -> Vec<u8> {
        self.token(FDT_END);

        const HEADER_LEN: usize = 40; // 10 big-endian u32s
        let rsvmap = [0u8; 16]; // single terminating (address=0, size=0) entry
        let off_mem_rsvmap = HEADER_LEN;
        let off_dt_struct = off_mem_rsvmap + rsvmap.len();
        let size_dt_struct = self.structure.len();
        let off_dt_strings = off_dt_struct + size_dt_struct;
        let size_dt_strings = self.strings.len();
        let totalsize = off_dt_strings + size_dt_strings;

        let mut out = Vec::with_capacity(totalsize);
        for word in [
            FDT_MAGIC,
            totalsize as u32,
            off_dt_struct as u32,
            off_dt_strings as u32,
            off_mem_rsvmap as u32,
            FDT_VERSION,
            FDT_LAST_COMP_VERSION,
            0, // boot_cpuid_phys
            size_dt_strings as u32,
            size_dt_struct as u32,
        ] {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out.extend_from_slice(&rsvmap);
        out.extend_from_slice(&self.structure);
        out.extend_from_slice(&self.strings);
        out
    }
}

/// Addresses for the modeled aarch64 machine. Dictated by the Linux boot
/// expectations + what the run loop emulates; the DTB and the hypervisor setup
/// must agree on these.
pub const GICV3_DIST_BASE: u64 = 0x0800_0000;
pub const GICV3_DIST_SIZE: u64 = 0x0001_0000;
pub const GICV3_REDIST_BASE: u64 = 0x0808_0000;
pub const GICV3_REDIST_STRIDE: u64 = 0x0002_0000;
pub const SERIAL_MMIO_BASE: u64 = 0x0900_0000;
pub const SERIAL_MMIO_SIZE: u64 = 0x1000;
/// PL011 SPI interrupt id (absolute INTID; SPI offset = id - 32).
pub const SERIAL_IRQ: u32 = 33;

const GIC_PHANDLE: u32 = 1;
const CLOCK_PHANDLE: u32 = 2;
const FDT_IRQ_SPI: u32 = 0;
const FDT_IRQ_PPI: u32 = 1;
const IRQ_LEVEL_HI: u32 = 4;
/// Edge-rising required for virtio on HVF's in-kernel GIC: it auto-deasserts the
/// SPI on guest EOI, which only works with edge semantics.
const IRQ_EDGE_RISING: u32 = 1;

/// Build a device tree for an arm64 Linux guest: one CPU, GICv3, arch timer,
/// PL011 console (with IRQ + clock), PSCI over HVC, memory, and `/chosen`
/// bootargs. Enough for the kernel to set up its console and boot.
pub fn build_dtb(
    bootargs: &str,
    ram_base: u64,
    ram_size: u64,
    initrd: Option<(u64, u64)>,
    virtio: Option<(u64, u32)>,
) -> Vec<u8> {
    let reg_pair = |addr: u64, size: u64| {
        [
            (addr >> 32) as u32,
            addr as u32,
            (size >> 32) as u32,
            size as u32,
        ]
    };

    let mut f = FdtBuilder::new();
    f.begin_node(""); // root
    f.prop_str("compatible", "linux,dummy-virt");
    f.prop_u32("#address-cells", 2);
    f.prop_u32("#size-cells", 2);
    f.prop_u32("interrupt-parent", GIC_PHANDLE);

    f.begin_node("cpus");
    f.prop_u32("#address-cells", 2);
    f.prop_u32("#size-cells", 0);
    f.begin_node("cpu@0");
    f.prop_str("device_type", "cpu");
    f.prop_str("compatible", "arm,arm-v8");
    f.prop_cells("reg", &[0, 0]); // MPIDR affinity 0 (2 address cells)
    f.end_node();
    f.end_node();

    f.begin_node("memory");
    f.prop_str("device_type", "memory");
    f.prop_cells("reg", &reg_pair(ram_base, ram_size));
    f.end_node();

    f.begin_node("chosen");
    f.prop_str("bootargs", bootargs);
    f.prop_str("stdout-path", &format!("/pl011@{SERIAL_MMIO_BASE:x}"));
    if let Some((start, end)) = initrd {
        f.prop_cells("linux,initrd-start", &[(start >> 32) as u32, start as u32]);
        f.prop_cells("linux,initrd-end", &[(end >> 32) as u32, end as u32]);
    }
    f.end_node();

    f.begin_node(&format!("intc@{GICV3_DIST_BASE:x}"));
    f.prop_str("compatible", "arm,gic-v3");
    f.prop_empty("interrupt-controller");
    f.prop_u32("#interrupt-cells", 3);
    f.prop_u32("#address-cells", 2);
    f.prop_u32("#size-cells", 2);
    f.prop_u32("phandle", GIC_PHANDLE);
    let mut intc_reg = Vec::new();
    intc_reg.extend_from_slice(&reg_pair(GICV3_DIST_BASE, GICV3_DIST_SIZE));
    intc_reg.extend_from_slice(&reg_pair(GICV3_REDIST_BASE, GICV3_REDIST_STRIDE));
    f.prop_cells("reg", &intc_reg);
    f.end_node();

    f.begin_node("timer");
    f.prop_str("compatible", "arm,armv8-timer");
    f.prop_empty("always-on");
    f.prop_cells(
        "interrupts",
        &[
            FDT_IRQ_PPI,
            13,
            IRQ_LEVEL_HI, // secure
            FDT_IRQ_PPI,
            14,
            IRQ_LEVEL_HI, // non-secure
            FDT_IRQ_PPI,
            11,
            IRQ_LEVEL_HI, // virtual
            FDT_IRQ_PPI,
            10,
            IRQ_LEVEL_HI, // hypervisor
        ],
    );
    f.end_node();

    f.begin_node(&format!("pl011@{SERIAL_MMIO_BASE:x}"));
    f.prop_strlist("compatible", &["arm,pl011", "arm,primecell"]);
    f.prop_cells("reg", &reg_pair(SERIAL_MMIO_BASE, SERIAL_MMIO_SIZE));
    f.prop_cells("interrupts", &[FDT_IRQ_SPI, SERIAL_IRQ - 32, IRQ_LEVEL_HI]);
    f.prop_u32("clocks", CLOCK_PHANDLE);
    f.prop_str("clock-names", "apb_pclk");
    f.end_node();

    f.begin_node("apb-pclk");
    f.prop_str("compatible", "fixed-clock");
    f.prop_u32("#clock-cells", 0);
    f.prop_u32("clock-frequency", 24_000_000);
    f.prop_str("clock-output-names", "clk24mhz");
    f.prop_u32("phandle", CLOCK_PHANDLE);
    f.end_node();

    f.begin_node("psci");
    f.prop_str("compatible", "arm,psci-0.2");
    f.prop_str("method", "hvc");
    f.end_node();

    if let Some((base, irq)) = virtio {
        f.begin_node(&format!("virtio_mmio@{base:x}"));
        f.prop_str("compatible", "virtio,mmio");
        f.prop_cells("reg", &reg_pair(base, 0x200));
        f.prop_cells("interrupts", &[FDT_IRQ_SPI, irq - 32, IRQ_EDGE_RISING]);
        f.end_node();
    }

    f.end_node(); // root
    f.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be32(b: &[u8], at: usize) -> u32 {
        u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn header_is_well_formed() {
        let dtb = build_dtb(
            "earlycon=pl011,mmio32,0x9000000",
            0x4000_0000,
            0x2000_0000,
            None,
            None,
        );
        assert_eq!(be32(&dtb, 0), FDT_MAGIC);
        assert_eq!(be32(&dtb, 4) as usize, dtb.len(), "totalsize == blob len");
        assert_eq!(be32(&dtb, 20), FDT_VERSION);
        let off_struct = be32(&dtb, 8) as usize;
        // first struct token is BEGIN_NODE for the root.
        assert_eq!(be32(&dtb, off_struct), FDT_BEGIN_NODE);
        // blob ends with FDT_END.
        let off_strings = be32(&dtb, 12) as usize;
        assert_eq!(be32(&dtb, off_strings - 4), FDT_END);
    }

    #[test]
    fn carries_bootargs_and_memory_base() {
        let dtb = build_dtb(
            "earlycon=pl011,mmio32,0x9000000",
            0x4000_0000,
            0x2000_0000,
            None,
            None,
        );
        let needle = b"earlycon=pl011,mmio32,0x9000000";
        assert!(
            dtb.windows(needle.len()).any(|w| w == needle),
            "bootargs string present in blob"
        );
        for s in [
            &b"chosen\0"[..],
            b"arm,gic-v3\0",
            b"arm,pl011\0",
            b"arm,armv8-timer\0",
            b"arm,psci-0.2\0",
            b"fixed-clock\0",
        ] {
            assert!(
                dtb.windows(s.len()).any(|w| w == s),
                "DTB should contain {:?}",
                String::from_utf8_lossy(s)
            );
        }
    }

    #[test]
    fn initrd_props_present_only_when_supplied() {
        let without = build_dtb("x", 0x8000_0000, 0x2000_0000, None, None);
        assert!(!without.windows(18).any(|w| w == b"linux,initrd-start"));
        let with = build_dtb(
            "x",
            0x8000_0000,
            0x2000_0000,
            Some((0x9000_0000, 0x9000_0600)),
            None,
        );
        assert!(with.windows(18).any(|w| w == b"linux,initrd-start"));
        assert!(with.windows(16).any(|w| w == b"linux,initrd-end"));
    }

    #[test]
    fn struct_block_is_4_byte_aligned() {
        let dtb = build_dtb("x", 0x4000_0000, 0x1000_0000, None, None);
        assert!(be32(&dtb, 8).is_multiple_of(4), "off_dt_struct 4-aligned");
        assert!(be32(&dtb, 16).is_multiple_of(8), "off_mem_rsvmap 8-aligned");
    }
}
