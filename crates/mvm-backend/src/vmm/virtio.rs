//! Minimal virtio-mmio (modern / v2) transport + split virtqueue + block device.
//!
//! Enough of the virtio-blk device for a guest kernel to detect `/dev/vda`,
//! negotiate `VIRTIO_F_VERSION_1`, set up its single request queue, and read or
//! write sectors. Requests are serviced synchronously inside the guest's
//! `QueueNotify` MMIO exit: the queue is drained, the used ring updated, and the
//! backend raises the device's edge SPI so the guest's ISR completes the I/O.
//!
//! Guest-physical addresses in the virtqueue are translated against the single
//! mapped RAM region (`ram_base .. ram_base+ram_size`), bounds-checked.

use super::guest_mem::GuestMem;

const VIRTIO_MAGIC: u32 = 0x7472_6976; // "virt"
const VIRTIO_VERSION: u32 = 2;
const VIRTIO_ID_BLOCK: u32 = 2;
const VIRTIO_VENDOR: u32 = 0x4d56_4d76; // "vMVM"

// virtio-mmio register offsets (v2).
const R_MAGIC: u64 = 0x000;
const R_VERSION: u64 = 0x004;
const R_DEVICE_ID: u64 = 0x008;
const R_VENDOR_ID: u64 = 0x00c;
const R_DEVICE_FEATURES: u64 = 0x010;
const R_DEVICE_FEATURES_SEL: u64 = 0x014;
const R_DRIVER_FEATURES: u64 = 0x020;
const R_DRIVER_FEATURES_SEL: u64 = 0x024;
const R_QUEUE_SEL: u64 = 0x030;
const R_QUEUE_NUM_MAX: u64 = 0x034;
const R_QUEUE_NUM: u64 = 0x038;
const R_QUEUE_READY: u64 = 0x044;
const R_QUEUE_NOTIFY: u64 = 0x050;
const R_INTERRUPT_STATUS: u64 = 0x060;
const R_INTERRUPT_ACK: u64 = 0x064;
const R_STATUS: u64 = 0x070;
const R_QUEUE_DESC_LO: u64 = 0x080;
const R_QUEUE_DESC_HI: u64 = 0x084;
const R_QUEUE_DRIVER_LO: u64 = 0x090;
const R_QUEUE_DRIVER_HI: u64 = 0x094;
const R_QUEUE_DEVICE_LO: u64 = 0x0a0;
const R_QUEUE_DEVICE_HI: u64 = 0x0a4;
const R_CONFIG: u64 = 0x100; // block config: capacity (u64 sectors) at +0

const MMIO_LEN: u64 = 0x200;
const QUEUE_SIZE_MAX: u32 = 256;
const SECTOR: u64 = 512;

const VIRTQ_DESC_F_NEXT: u16 = 1;

const VIRTIO_BLK_T_IN: u32 = 0; // read
const VIRTIO_BLK_T_OUT: u32 = 1; // write
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;

/// A virtio-mmio block device backed by an in-memory disk.
pub struct VirtioBlk {
    base: u64,
    irq: u32,
    mem: GuestMem,
    disk: Vec<u8>,

    device_features_sel: u32,
    driver_features_sel: u32,
    status: u32,
    queue_num: u32,
    queue_ready: u32,
    desc: u64,
    avail: u64,
    used: u64,
    last_avail: u16,
    interrupt_status: u32,
}

impl VirtioBlk {
    /// # Safety
    /// `ram` must point to `ram_size` bytes mapped as guest RAM at `ram_base`,
    /// valid for the device's lifetime.
    pub unsafe fn new(
        base: u64,
        irq: u32,
        ram: *mut u8,
        ram_base: u64,
        ram_size: usize,
        disk: Vec<u8>,
    ) -> Self {
        Self {
            base,
            irq,
            // SAFETY: forwarded from this fn's contract.
            mem: unsafe { GuestMem::new(ram, ram_base, ram_size) },
            disk,
            device_features_sel: 0,
            driver_features_sel: 0,
            status: 0,
            queue_num: 0,
            queue_ready: 0,
            desc: 0,
            avail: 0,
            used: 0,
            last_avail: 0,
            interrupt_status: 0,
        }
    }

    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + MMIO_LEN
    }

    // Guest-memory access delegates to the shared bounds-checked view.
    fn host(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        self.mem.host(gpa, len)
    }
    fn rd_u16(&self, gpa: u64) -> u16 {
        self.mem.rd_u16(gpa)
    }
    fn rd_u32(&self, gpa: u64) -> u32 {
        self.mem.rd_u32(gpa)
    }
    fn rd_u64(&self, gpa: u64) -> u64 {
        self.mem.rd_u64(gpa)
    }
    fn wr_u16(&self, gpa: u64, v: u16) {
        self.mem.wr_u16(gpa, v)
    }
    fn wr_u8(&self, gpa: u64, v: u8) {
        self.mem.wr_u8(gpa, v)
    }

    /// Handle an MMIO read at `offset` from the device base.
    pub fn read(&self, offset: u64) -> u64 {
        u64::from(match offset {
            R_MAGIC => VIRTIO_MAGIC,
            R_VERSION => VIRTIO_VERSION,
            R_DEVICE_ID => VIRTIO_ID_BLOCK,
            R_VENDOR_ID => VIRTIO_VENDOR,
            // Only VIRTIO_F_VERSION_1 (feature bit 32) is offered.
            R_DEVICE_FEATURES if self.device_features_sel == 1 => 1,
            R_DEVICE_FEATURES => 0,
            R_QUEUE_NUM_MAX => QUEUE_SIZE_MAX,
            R_QUEUE_READY => self.queue_ready,
            R_INTERRUPT_STATUS => self.interrupt_status,
            R_STATUS => self.status,
            // block config: capacity in 512-byte sectors (u64 at +0/+4).
            R_CONFIG => (self.disk.len() as u64 / SECTOR) as u32,
            o if o == R_CONFIG + 4 => ((self.disk.len() as u64 / SECTOR) >> 32) as u32,
            _ => 0,
        })
    }

    /// Handle an MMIO write at `offset`. Returns `true` if the guest should be
    /// interrupted (a queue was serviced).
    pub fn write(&mut self, offset: u64, value: u64) -> bool {
        let v = value as u32;
        match offset {
            R_DEVICE_FEATURES_SEL => self.device_features_sel = v,
            R_DRIVER_FEATURES_SEL => self.driver_features_sel = v,
            R_DRIVER_FEATURES => {} // accept whatever the driver acks
            R_QUEUE_SEL => {}       // single queue (0)
            R_QUEUE_NUM => self.queue_num = v,
            R_QUEUE_READY => self.queue_ready = v,
            R_STATUS => self.status = v,
            R_INTERRUPT_ACK => self.interrupt_status &= !v,
            R_QUEUE_DESC_LO => self.desc = (self.desc & !0xffff_ffff) | u64::from(v),
            R_QUEUE_DESC_HI => self.desc = (self.desc & 0xffff_ffff) | (u64::from(v) << 32),
            R_QUEUE_DRIVER_LO => self.avail = (self.avail & !0xffff_ffff) | u64::from(v),
            R_QUEUE_DRIVER_HI => self.avail = (self.avail & 0xffff_ffff) | (u64::from(v) << 32),
            R_QUEUE_DEVICE_LO => self.used = (self.used & !0xffff_ffff) | u64::from(v),
            R_QUEUE_DEVICE_HI => self.used = (self.used & 0xffff_ffff) | (u64::from(v) << 32),
            R_QUEUE_NOTIFY => return self.process_queue(),
            _ => {}
        }
        false
    }

    /// Drain the available ring, servicing each block request. Returns whether
    /// any request completed (and thus the guest needs an interrupt).
    fn process_queue(&mut self) -> bool {
        if self.queue_ready == 0 || self.queue_num == 0 {
            return false;
        }
        let qsz = self.queue_num as u16;
        let avail_idx = self.rd_u16(self.avail + 2);
        let debug = std::env::var_os("MVM_HVF_VIRTIO_DEBUG").is_some();
        if debug {
            eprintln!(
                "virtio: notify qsz={qsz} ready={} avail_idx={avail_idx} last_avail={} desc={:#x} avail={:#x} used={:#x}",
                self.queue_ready, self.last_avail, self.desc, self.avail, self.used
            );
        }
        let mut serviced = false;
        while self.last_avail != avail_idx {
            let slot = self.last_avail % qsz;
            let head = self.rd_u16(self.avail + 4 + u64::from(slot) * 2);
            let written = self.service_request(head, qsz);
            if debug {
                eprintln!("virtio:   head={head} written={written}");
            }
            // used ring: {id u32, len u32} at used + 4 + (used_idx % qsz)*8
            let used_idx = self.rd_u16(self.used + 2);
            let slot = u64::from(used_idx % qsz);
            self.wr_u16(self.used + 4 + slot * 8, head); // id low 16 bits
            self.wr_u16(self.used + 6 + slot * 8, 0); // id high 16 bits
            self.wr_u16(self.used + 8 + slot * 8, written as u16);
            self.wr_u16(self.used + 10 + slot * 8, (written >> 16) as u16);
            self.wr_u16(self.used + 2, used_idx.wrapping_add(1));
            self.last_avail = self.last_avail.wrapping_add(1);
            serviced = true;
        }
        if serviced {
            self.interrupt_status |= 1; // used-buffer notification
        }
        serviced
    }

    /// Service one descriptor chain (a virtio-blk request). Returns bytes
    /// written into device-writable buffers (used-ring `len`).
    fn service_request(&mut self, head: u16, qsz: u16) -> u32 {
        // Descriptor: addr u64 @0, len u32 @8, flags u16 @12, next u16 @14.
        let desc_base = self.desc;
        let desc_at = |i: u16| desc_base + u64::from(i) * 16;
        let d0 = desc_at(head);
        let hdr_addr = self.rd_u64(d0);
        // request header: type u32 @0, reserved u32 @4, sector u64 @8.
        let req_type = self.rd_u32(hdr_addr);
        let mut sector = self.rd_u64(hdr_addr + 8);
        if std::env::var_os("MVM_HVF_VIRTIO_DEBUG").is_some() {
            eprintln!("virtio:   req hdr@{hdr_addr:#x} type={req_type} sector={sector}");
        }

        // Walk the rest of the chain: data descriptors then the 1-byte status.
        let mut idx = head;
        let mut flags = self.rd_u16(d0 + 12);
        let mut written: u32 = 0;
        let mut status_addr: Option<u64> = None;
        let mut guard = 0u32;
        while flags & VIRTQ_DESC_F_NEXT != 0 {
            let next = self.rd_u16(desc_at(idx) + 14);
            if next >= qsz {
                break;
            }
            // virtq_desc: addr u64 @0, len u32 @8, flags u16 @12, next u16 @14.
            let da = desc_at(next);
            let addr = self.rd_u64(da);
            let len = self.rd_u32(da + 8);
            let dflags = self.rd_u16(da + 12);
            if std::env::var_os("MVM_HVF_VIRTIO_DEBUG").is_some() {
                eprintln!("virtio:     desc[{next}] addr={addr:#x} len={len} flags={dflags:#x}");
            }
            if dflags & VIRTQ_DESC_F_NEXT == 0 {
                // last descriptor = status byte
                status_addr = Some(addr);
            } else {
                // data descriptor
                self.transfer(req_type, sector, addr, len, &mut written);
                sector += u64::from(len) / SECTOR;
            }
            idx = next;
            flags = dflags;
            guard += 1;
            if guard > qsz as u32 {
                break;
            }
        }
        let ok = matches!(req_type, VIRTIO_BLK_T_IN | VIRTIO_BLK_T_OUT);
        if let Some(s) = status_addr {
            self.wr_u8(
                s,
                if ok {
                    VIRTIO_BLK_S_OK
                } else {
                    VIRTIO_BLK_S_IOERR
                },
            );
            written += 1;
        }
        written
    }

    /// Copy one data descriptor between the disk and guest memory.
    fn transfer(&mut self, req_type: u32, sector: u64, addr: u64, len: u32, written: &mut u32) {
        let disk_off = (sector * SECTOR) as usize;
        let len = len as usize;
        match req_type {
            VIRTIO_BLK_T_IN => {
                if let Some(dst) = self.host(addr, len) {
                    for i in 0..len {
                        let b = self.disk.get(disk_off + i).copied().unwrap_or(0);
                        // SAFETY: dst valid for `len` bytes.
                        unsafe { *dst.add(i) = b };
                    }
                    *written += len as u32;
                }
            }
            VIRTIO_BLK_T_OUT => {
                if let Some(src) = self.host(addr, len) {
                    for i in 0..len {
                        // SAFETY: src valid for `len` bytes.
                        let b = unsafe { *src.add(i) };
                        if disk_off + i < self.disk.len() {
                            self.disk[disk_off + i] = b;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// The device's SPI INTID — the platform run loop raises it on completion
    /// (HVF: `hv_gic_set_spi`; KVM: `KVM_IRQ_LINE`; WHP: `WHvRequestInterrupt`).
    pub fn irq(&self) -> u32 {
        self.irq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(disk: Vec<u8>) -> VirtioBlk {
        let mut ram = vec![0u8; 0x10000];
        // SAFETY: ram lives for the test; leaked pointer is fine here.
        unsafe {
            VirtioBlk::new(
                0x0a00_0000,
                48,
                ram.as_mut_ptr(),
                0x4000_0000,
                ram.len(),
                disk,
            )
        }
    }

    #[test]
    fn transport_identity_registers() {
        let d = dev(vec![0u8; 4096]);
        assert_eq!(d.read(R_MAGIC) as u32, VIRTIO_MAGIC);
        assert_eq!(d.read(R_VERSION) as u32, VIRTIO_VERSION);
        assert_eq!(d.read(R_DEVICE_ID) as u32, VIRTIO_ID_BLOCK);
    }

    #[test]
    fn offers_version_1_feature_in_high_word() {
        let mut d = dev(vec![0u8; 4096]);
        d.write(R_DEVICE_FEATURES_SEL, 0);
        assert_eq!(d.read(R_DEVICE_FEATURES) as u32, 0);
        d.write(R_DEVICE_FEATURES_SEL, 1);
        assert_eq!(d.read(R_DEVICE_FEATURES) as u32, 1); // VIRTIO_F_VERSION_1 (bit 32)
    }

    #[test]
    fn capacity_reports_sector_count() {
        let d = dev(vec![0u8; 8192]); // 16 sectors
        assert_eq!(d.read(R_CONFIG) as u32, 16);
    }

    #[test]
    fn contains_covers_mmio_window() {
        let d = dev(vec![0u8; 512]);
        assert!(d.contains(0x0a00_0000));
        assert!(d.contains(0x0a00_01ff));
        assert!(!d.contains(0x0a00_0200));
    }

    #[test]
    fn interrupt_ack_clears_status() {
        let mut d = dev(vec![0u8; 512]);
        d.interrupt_status = 1;
        d.write(R_INTERRUPT_ACK, 1);
        assert_eq!(d.read(R_INTERRUPT_STATUS) as u32, 0);
    }

    #[test]
    fn services_a_block_read_through_the_split_virtqueue() {
        const BASE: u64 = 0x4000_0000;
        let mut ram = vec![0u8; 0x10000];
        let put = |ram: &mut [u8], gpa: u64, bytes: &[u8]| {
            let off = (gpa - BASE) as usize;
            ram[off..off + bytes.len()].copy_from_slice(bytes);
        };
        let get = |ram: &[u8], gpa: u64, len: usize| {
            let off = (gpa - BASE) as usize;
            ram[off..off + len].to_vec()
        };

        let (desc, avail, used) = (BASE + 0x1000, BASE + 0x2000, BASE + 0x3000);
        let (hdr, data, status) = (BASE + 0x4000, BASE + 0x5000, BASE + 0x6000);

        // Descriptor chain: header(RO,->1), data(WO,->2), status(WO). The `len`
        // field sits at desc offset 8 — the regression this test guards.
        let mk = |addr: u64, len: u32, flags: u16, next: u16| {
            let mut d = [0u8; 16];
            d[0..8].copy_from_slice(&addr.to_le_bytes());
            d[8..12].copy_from_slice(&len.to_le_bytes());
            d[12..14].copy_from_slice(&flags.to_le_bytes());
            d[14..16].copy_from_slice(&next.to_le_bytes());
            d
        };
        put(&mut ram, desc, &mk(hdr, 16, VIRTQ_DESC_F_NEXT, 1));
        put(
            &mut ram,
            desc + 16,
            &mk(data, 512, VIRTQ_DESC_F_NEXT | 2, 2),
        );
        put(&mut ram, desc + 32, &mk(status, 1, 2, 0));
        // avail: flags=0, idx=1, ring[0]=head desc 0.
        put(&mut ram, avail + 2, &1u16.to_le_bytes());
        put(&mut ram, avail + 4, &0u16.to_le_bytes());
        // request header: type=IN(read), sector=0.
        put(&mut ram, hdr, &VIRTIO_BLK_T_IN.to_le_bytes());
        put(&mut ram, hdr + 8, &0u64.to_le_bytes());

        let mut disk = vec![0u8; 4096];
        disk[..11].copy_from_slice(b"DISK-BYTES!");

        // SAFETY: ram outlives the device for the test.
        let mut d =
            unsafe { VirtioBlk::new(0x0a00_0000, 48, ram.as_mut_ptr(), BASE, ram.len(), disk) };
        d.write(R_QUEUE_NUM, 4);
        d.write(R_QUEUE_DESC_LO, desc & 0xffff_ffff);
        d.write(R_QUEUE_DRIVER_LO, avail & 0xffff_ffff);
        d.write(R_QUEUE_DEVICE_LO, used & 0xffff_ffff);
        d.write(R_QUEUE_READY, 1);

        assert!(d.write(R_QUEUE_NOTIFY, 0), "notify services the queue");
        // Data buffer received sector 0; status OK; used ring advanced.
        assert_eq!(&get(&ram, data, 11), b"DISK-BYTES!");
        assert_eq!(get(&ram, status, 1)[0], VIRTIO_BLK_S_OK);
        assert_eq!(
            u16::from_le_bytes([
                ram[(used - BASE) as usize + 2],
                ram[(used - BASE) as usize + 3]
            ]),
            1
        );
    }
}
