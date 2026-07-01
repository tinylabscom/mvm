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

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;

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
/// virtio-blk feature bit 5 (low feature word): the device is read-only. Offered
/// for a read-only backing so the guest mounts it `ro`; writes are also rejected
/// at the device (below), so RO is hypervisor-enforced, not guest-honour-system.
const VIRTIO_BLK_F_RO: u32 = 1 << 5;

/// Backing store for a virtio-blk device.
///
/// `Mem` keeps the whole image in host RAM — fine for tests and small ephemeral
/// disks, but writes don't persist past the VM. `File` serves the image with
/// `pread`/`pwrite` against the host file, so (a) a large disk (e.g. the builder's
/// nix-store) costs no host memory, and (b) writes persist to the file across
/// runs. A `read_only` file rejects guest writes at the device.
pub enum DiskImage {
    Mem(Vec<u8>),
    File {
        file: File,
        len: u64,
        read_only: bool,
    },
}

impl DiskImage {
    /// In-memory image (tests, small ephemeral disks).
    pub fn mem(bytes: Vec<u8>) -> Self {
        Self::Mem(bytes)
    }

    /// Open a file-backed image, read-write unless `read_only`. The capacity is
    /// the file's current length (images are pre-sized by the caller).
    pub fn open(path: &Path, read_only: bool) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(!read_only).open(path)?;
        let len = file.metadata()?.len();
        Ok(Self::File {
            file,
            len,
            read_only,
        })
    }

    /// Capacity in bytes.
    fn len(&self) -> u64 {
        match self {
            Self::Mem(v) => v.len() as u64,
            Self::File { len, .. } => *len,
        }
    }

    fn read_only(&self) -> bool {
        match self {
            Self::Mem(_) => false,
            Self::File { read_only, .. } => *read_only,
        }
    }

    /// Fill `buf` from the image at byte offset `off`, zero-filling any bytes past
    /// end-of-image (a guest read past capacity reads zeros, never host junk).
    fn read_at(&self, off: u64, buf: &mut [u8]) {
        buf.fill(0);
        match self {
            Self::Mem(v) => {
                let start = off.min(v.len() as u64) as usize;
                let n = buf.len().min(v.len() - start);
                buf[..n].copy_from_slice(&v[start..start + n]);
            }
            Self::File { file, len, .. } => {
                if off >= *len {
                    return;
                }
                let want = ((*len - off).min(buf.len() as u64)) as usize;
                let mut done = 0;
                while done < want {
                    match file.read_at(&mut buf[done..want], off + done as u64) {
                        Ok(0) => break,
                        Ok(n) => done += n,
                        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
            }
        }
    }

    /// Write `buf` to the image at byte offset `off`, clamped to capacity (the
    /// image is never grown). Returns `false` if the write is rejected (read-only)
    /// or the backing I/O fails — the caller reports `VIRTIO_BLK_S_IOERR`.
    fn write_at(&mut self, off: u64, buf: &[u8]) -> bool {
        match self {
            Self::Mem(v) => {
                if off >= v.len() as u64 {
                    return false;
                }
                let start = off as usize;
                let n = buf.len().min(v.len() - start);
                v[start..start + n].copy_from_slice(&buf[..n]);
                true
            }
            Self::File {
                read_only: true, ..
            } => false,
            Self::File { file, len, .. } => {
                if off >= *len {
                    return false;
                }
                let want = ((*len - off).min(buf.len() as u64)) as usize;
                let mut done = 0;
                while done < want {
                    match file.write_at(&buf[done..want], off + done as u64) {
                        Ok(0) => return false,
                        Ok(n) => done += n,
                        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => return false,
                    }
                }
                true
            }
        }
    }
}

/// A virtio-mmio block device backed by a [`DiskImage`].
pub struct VirtioBlk {
    base: u64,
    irq: u32,
    mem: GuestMem,
    disk: DiskImage,

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
        disk: DiskImage,
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
            // High word (bit 32): VIRTIO_F_VERSION_1. Low word: VIRTIO_BLK_F_RO
            // for a read-only backing (else no low-word features).
            R_DEVICE_FEATURES if self.device_features_sel == 1 => 1,
            R_DEVICE_FEATURES if self.disk.read_only() => VIRTIO_BLK_F_RO,
            R_DEVICE_FEATURES => 0,
            R_QUEUE_NUM_MAX => QUEUE_SIZE_MAX,
            R_QUEUE_READY => self.queue_ready,
            R_INTERRUPT_STATUS => self.interrupt_status,
            R_STATUS => self.status,
            // block config: capacity in 512-byte sectors (u64 at +0/+4).
            R_CONFIG => (self.disk.len() / SECTOR) as u32,
            o if o == R_CONFIG + 4 => ((self.disk.len() / SECTOR) >> 32) as u32,
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
        let mut io_ok = true;
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
                io_ok &= self.transfer(req_type, sector, addr, len, &mut written);
                sector += u64::from(len) / SECTOR;
            }
            idx = next;
            flags = dflags;
            guard += 1;
            if guard > qsz as u32 {
                break;
            }
        }
        let ok = io_ok && matches!(req_type, VIRTIO_BLK_T_IN | VIRTIO_BLK_T_OUT);
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

    /// Copy one data descriptor between the disk and guest memory. Returns whether
    /// the backing I/O succeeded — a write to a read-only disk (or a failed host
    /// write) returns `false`, which surfaces to the guest as `VIRTIO_BLK_S_IOERR`.
    fn transfer(
        &mut self,
        req_type: u32,
        sector: u64,
        addr: u64,
        len: u32,
        written: &mut u32,
    ) -> bool {
        let disk_off = sector * SECTOR;
        let len = len as usize;
        match req_type {
            VIRTIO_BLK_T_IN => {
                // `host()` returns a raw pointer (no live borrow), so reading the
                // backing into a scratch buffer and copying it in is borrow-clean.
                let Some(dst) = self.host(addr, len) else {
                    return true;
                };
                let mut tmp = vec![0u8; len];
                self.disk.read_at(disk_off, &mut tmp);
                // SAFETY: dst is valid for `len` bytes (bounds-checked by host()).
                unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), dst, len) };
                *written += len as u32;
                true
            }
            VIRTIO_BLK_T_OUT => {
                let Some(src) = self.host(addr, len) else {
                    return true;
                };
                let mut tmp = vec![0u8; len];
                // SAFETY: src is valid for `len` bytes (bounds-checked by host()).
                unsafe { core::ptr::copy_nonoverlapping(src, tmp.as_mut_ptr(), len) };
                self.disk.write_at(disk_off, &tmp)
            }
            _ => true,
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
                DiskImage::mem(disk),
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
        let mut d = unsafe {
            VirtioBlk::new(
                0x0a00_0000,
                48,
                ram.as_mut_ptr(),
                BASE,
                ram.len(),
                DiskImage::mem(disk),
            )
        };
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

    #[test]
    fn disk_image_mem_reads_writes_and_clamps_to_capacity() {
        let mut d = DiskImage::mem(vec![0u8; 32]);
        assert_eq!(d.len(), 32);
        assert!(!d.read_only());
        assert!(d.write_at(4, b"hello"));
        let mut buf = [0u8; 5];
        d.read_at(4, &mut buf);
        assert_eq!(&buf, b"hello");
        // A write starting past capacity is rejected; a read past EOF zero-fills.
        assert!(!d.write_at(64, b"x"));
        let mut z = [1u8; 4];
        d.read_at(30, &mut z);
        assert_eq!(z, [0, 0, 0, 0]);
    }

    #[test]
    fn disk_image_file_backed_read_zero_fills_past_eof() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"DISK-BYTES!").unwrap();
        f.flush().unwrap();
        let d = DiskImage::open(f.path(), true).unwrap();
        assert_eq!(d.len(), 11);
        assert!(d.read_only());
        let mut buf = [9u8; 16];
        d.read_at(0, &mut buf);
        assert_eq!(&buf[..11], b"DISK-BYTES!");
        assert_eq!(&buf[11..], &[0u8; 5]); // past EOF is zero, never host junk
    }

    #[test]
    fn disk_image_file_backed_write_persists_to_the_host_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().set_len(64).unwrap();
        let mut d = DiskImage::open(f.path(), false).unwrap();
        assert!(d.write_at(8, b"persist-me"));
        drop(d);
        // Re-read the file from scratch: the write reached the host file.
        let raw = std::fs::read(f.path()).unwrap();
        assert_eq!(&raw[8..18], b"persist-me");
    }

    #[test]
    fn disk_image_read_only_file_rejects_writes() {
        let f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().set_len(64).unwrap();
        let mut d = DiskImage::open(f.path(), true).unwrap();
        assert!(!d.write_at(0, b"nope"));
        let raw = std::fs::read(f.path()).unwrap();
        assert!(
            raw.iter().all(|&b| b == 0),
            "read-only file must be untouched"
        );
    }

    #[test]
    fn read_only_backing_offers_the_ro_feature_bit() {
        let mut ram = vec![0u8; 0x10000];
        let f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().set_len(512).unwrap();
        let img = DiskImage::open(f.path(), true).unwrap();
        // SAFETY: ram outlives the device for the test.
        let mut d = unsafe {
            VirtioBlk::new(
                0x0a00_0000,
                48,
                ram.as_mut_ptr(),
                0x4000_0000,
                ram.len(),
                img,
            )
        };
        // Low feature word advertises RO; high word still offers VERSION_1.
        d.write(R_DEVICE_FEATURES_SEL, 0);
        assert_eq!(d.read(R_DEVICE_FEATURES) as u32, VIRTIO_BLK_F_RO);
        d.write(R_DEVICE_FEATURES_SEL, 1);
        assert_eq!(d.read(R_DEVICE_FEATURES) as u32, 1);
        // A writable (mem) backing offers no low-word features.
        let mut w = dev(vec![0u8; 512]);
        w.write(R_DEVICE_FEATURES_SEL, 0);
        assert_eq!(w.read(R_DEVICE_FEATURES) as u32, 0);
    }
}
