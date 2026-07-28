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
use std::sync::OnceLock;

use virtio_queue::desc::split::Descriptor;
use virtio_queue::{QueueOwnedT, QueueT};

use super::guest_mem::GuestMem;
use super::{RingGeometry, build_split_queue};

/// Whether the per-descriptor virtio trace is enabled (`MVM_HVF_VIRTIO_DEBUG`).
/// Read from the environment once and cached — the request/descriptor hot path
/// must not take the process-global env lock per descriptor.
fn virtio_debug() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("MVM_HVF_VIRTIO_DEBUG").is_some())
}

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
const SECTOR: u64 = 512;

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
    next_used: u16,
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
            next_used: 0,
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
            R_QUEUE_NUM_MAX => super::QUEUE_SIZE_MAX,
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
            R_QUEUE_READY => {
                self.queue_ready = v;
                if v == 0 {
                    self.rewind_ring_cursors();
                }
            }
            R_STATUS => {
                self.status = v;
                if v == 0 {
                    self.rewind_ring_cursors();
                }
            }
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
        if self.queue_ready == 0 {
            return false;
        }
        // Keep the geometry gate ahead of the queue build: an illegal
        // guest-programmed `QueueNum` is left unserviced, and a legal size is also
        // what the validated ring accepts.
        let Some(qsz) = super::validated_queue_size(self.queue_num) else {
            return false;
        };
        // The validated ring walk needs a real `GuestMemory` built over the same
        // externally-owned RAM. If it can't be constructed (e.g. a non-page-aligned
        // mapping), service nothing — mirroring the illegal-geometry early out.
        let Some(mem) = self.mem.guest_memory() else {
            return false;
        };
        let Some(mut queue) = build_split_queue(self.ring(), qsz) else {
            return false;
        };

        let debug = virtio_debug();
        if debug {
            eprintln!(
                "virtio: notify qsz={qsz} ready={} avail_idx={} last_avail={} desc={:#x} avail={:#x} used={:#x}",
                self.queue_ready,
                self.rd_u16(self.avail + 2),
                self.last_avail,
                self.desc,
                self.avail,
                self.used
            );
        }

        let mut completed: Vec<(u16, u32)> = Vec::new();
        {
            // `DescriptorChain::next` seeds `ttl` from the validated queue size and
            // stops once `ttl == 0 || next_index >= queue_size`, so the chain walk
            // is bounded and range-checked — no hand-rolled counter, no missing
            // `next < qsz` guard.
            let Ok(avail) = queue.iter(&mem) else {
                return false;
            };
            for chain in avail {
                let head = chain.head_index();
                // virtio-blk splits a request across the chain by direction: the
                // device-readable run carries the request header (and, for a write,
                // the payload); the device-writable run carries the payload (for a
                // read) and the trailing status byte.
                let readable: Vec<Descriptor> = chain.clone().readable().collect();
                let writable: Vec<Descriptor> = chain.writable().collect();
                let written = self.service_request(&readable, &writable);
                if debug {
                    eprintln!("virtio:   head={head} written={written}");
                }
                completed.push((head, written));
            }
        }
        let serviced = !completed.is_empty();
        for (head, written) in completed {
            // `head` came from a validated avail-ring slot (`< qsz`); `add_used`
            // re-checks the bound and writes the same 8-byte used element + used
            // index the hand-rolled completion wrote.
            let _ = queue.add_used(&mem, head, written);
        }
        self.last_avail = queue.next_avail();
        self.next_used = queue.next_used();
        if serviced {
            self.interrupt_status |= 1; // used-buffer notification
        }
        serviced
    }

    /// This device's guest-programmed ring state, in the shape the shared
    /// [`build_split_queue`] consumes.
    fn ring(&self) -> RingGeometry {
        RingGeometry {
            desc: self.desc,
            avail: self.avail,
            used: self.used,
            next_avail: self.last_avail,
            next_used: self.next_used,
        }
    }

    /// Rewind both device-owned ring cursors to the start of a fresh ring.
    ///
    /// The cursors are zero at construction and are re-zeroed on exactly the two
    /// register writes by which a driver hands the device a newly-programmed
    /// ring: detaching the queue (`QueueReady` ← 0, after which the driver frees
    /// the ring and any later activation programs zeroed memory) and resetting
    /// the device (`Status` ← 0, after which the driver re-runs the whole
    /// initialization sequence). Every other register write leaves them alone, so
    /// a redundant `QueueReady` ← 1 on a live queue cannot rewind the device onto
    /// used slots the driver still owns.
    fn rewind_ring_cursors(&mut self) {
        self.last_avail = 0;
        self.next_used = 0;
    }

    /// Service one virtio-blk request, given its chain's device-readable and
    /// device-writable descriptors in chain order. The request header is the
    /// first readable descriptor, the 1-byte status is the last writable one, and
    /// every descriptor between them carries payload — readable for a write
    /// request, writable for a read. Returns bytes written into device-writable
    /// buffers (used-ring `len`).
    fn service_request(&mut self, readable: &[Descriptor], writable: &[Descriptor]) -> u32 {
        // request header: type u32 @0, reserved u32 @4, sector u64 @8.
        let Some(header) = readable.first() else {
            return 0;
        };
        let hdr_addr = header.addr().0;
        let req_type = self.rd_u32(hdr_addr);
        let mut sector = self.rd_u64(hdr_addr + 8);
        if virtio_debug() {
            eprintln!("virtio:   req hdr@{hdr_addr:#x} type={req_type} sector={sector}");
        }

        let (status_addr, writable_data) = match writable.split_last() {
            Some((status, data)) => (Some(status.addr().0), data),
            // No writable descriptor at all: no status to report, and nothing the
            // device may write into.
            None => (None, writable),
        };
        let mut written: u32 = 0;
        let mut io_ok = true;
        for desc in readable[1..].iter().chain(writable_data) {
            let (addr, len) = (desc.addr().0, desc.len());
            if virtio_debug() {
                eprintln!(
                    "virtio:     data addr={addr:#x} len={len} flags={:#x}",
                    desc.flags()
                );
            }
            io_ok &= self.transfer(req_type, sector, addr, len, &mut written);
            sector += u64::from(len) / SECTOR;
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

// ---- virtio-fs (read-only root) --------------------------------------------

const VIRTIO_ID_FS: u32 = 26;
// hiprio (queue 0) + one request queue (queue 1). `num_request_queues` = 1.
const FS_NUM_QUEUES: usize = 2;
// The tag the guest mounts: `mount -t virtiofs mvmroot /`.
const FS_TAG: &str = "mvmroot";

/// Per-queue virtqueue state (virtio-fs has multiple queues, unlike blk).
#[derive(Default, Clone, Copy)]
struct FsQueue {
    num: u32,
    ready: u32,
    desc: u64,
    avail: u64,
    used: u64,
    last_avail: u16,
    next_used: u16,
}

impl FsQueue {
    /// This queue's guest-programmed ring state, in the shape the shared
    /// [`build_split_queue`] consumes.
    fn ring(&self) -> RingGeometry {
        RingGeometry {
            desc: self.desc,
            avail: self.avail,
            used: self.used,
            next_avail: self.last_avail,
            next_used: self.next_used,
        }
    }

    /// Rewind both device-owned ring cursors to the start of a fresh ring, on the
    /// same two transitions as [`VirtioBlk::rewind_ring_cursors`]: this queue
    /// being detached (`QueueReady` ← 0) and the device being reset
    /// (`Status` ← 0).
    fn rewind_cursors(&mut self) {
        self.last_avail = 0;
        self.next_used = 0;
    }
}

/// virtio-fs MMIO device serving a read-only host directory to the guest as its
/// root. The virtqueue transport here mirrors [`VirtioBlk`]; the payload is FUSE,
/// handled by [`super::virtio_fs::FuseServer`].
pub struct VirtioFs {
    base: u64,
    irq: u32,
    mem: GuestMem,
    server: super::virtio_fs::FuseServer,
    device_features_sel: u32,
    status: u32,
    queue_sel: u32,
    queues: [FsQueue; FS_NUM_QUEUES],
    interrupt_status: u32,
    config: [u8; 40],
}

impl VirtioFs {
    /// # Safety
    /// `ram`/`ram_base`/`ram_size` must describe the mapped guest RAM region for
    /// the lifetime of this device (same contract as [`VirtioBlk::new`]).
    pub unsafe fn new(
        base: u64,
        irq: u32,
        ram: *mut u8,
        ram_base: u64,
        ram_size: usize,
        root: std::path::PathBuf,
    ) -> Self {
        let mut config = [0u8; 40];
        let tag = FS_TAG.as_bytes();
        config[..tag.len()].copy_from_slice(tag); // tag[36], NUL-padded
        config[36..40].copy_from_slice(&1u32.to_le_bytes()); // num_request_queues
        VirtioFs {
            base,
            irq,
            // SAFETY: forwarded from the caller's guest-RAM contract.
            mem: unsafe { GuestMem::new(ram, ram_base, ram_size) },
            server: super::virtio_fs::FuseServer::new(root),
            device_features_sel: 0,
            status: 0,
            queue_sel: 0,
            queues: [FsQueue::default(); FS_NUM_QUEUES],
            interrupt_status: 0,
            config,
        }
    }

    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + MMIO_LEN
    }
    pub fn irq(&self) -> u32 {
        self.irq
    }

    fn q(&self) -> &FsQueue {
        &self.queues[(self.queue_sel as usize).min(FS_NUM_QUEUES - 1)]
    }
    fn q_mut(&mut self) -> &mut FsQueue {
        &mut self.queues[(self.queue_sel as usize).min(FS_NUM_QUEUES - 1)]
    }

    pub fn read(&self, offset: u64) -> u64 {
        u64::from(match offset {
            R_MAGIC => VIRTIO_MAGIC,
            R_VERSION => VIRTIO_VERSION,
            R_DEVICE_ID => VIRTIO_ID_FS,
            R_VENDOR_ID => VIRTIO_VENDOR,
            // Only VIRTIO_F_VERSION_1 (high feature word); no low-word features.
            R_DEVICE_FEATURES if self.device_features_sel == 1 => 1,
            R_DEVICE_FEATURES => 0,
            R_QUEUE_NUM_MAX => super::QUEUE_SIZE_MAX,
            R_QUEUE_READY => self.q().ready,
            R_INTERRUPT_STATUS => self.interrupt_status,
            R_STATUS => self.status,
            o if (R_CONFIG..R_CONFIG + 40).contains(&o) => {
                let i = (o - R_CONFIG) as usize;
                let mut b = [0u8; 4];
                let n = (self.config.len() - i).min(4);
                b[..n].copy_from_slice(&self.config[i..i + n]);
                u32::from_le_bytes(b)
            }
            _ => 0,
        })
    }

    /// Handle an MMIO write. Returns `true` if a queue was serviced (interrupt).
    pub fn write(&mut self, offset: u64, value: u64) -> bool {
        let v = value as u32;
        match offset {
            R_DEVICE_FEATURES_SEL => self.device_features_sel = v,
            R_DRIVER_FEATURES_SEL | R_DRIVER_FEATURES => {}
            R_QUEUE_SEL => self.queue_sel = v,
            R_QUEUE_NUM => self.q_mut().num = v,
            R_QUEUE_READY => {
                let q = self.q_mut();
                q.ready = v;
                if v == 0 {
                    q.rewind_cursors();
                }
            }
            R_STATUS => {
                self.status = v;
                if v == 0 {
                    // A device reset returns every queue to its pre-init state, not
                    // just the one currently selected.
                    self.queues.iter_mut().for_each(FsQueue::rewind_cursors);
                }
            }
            R_INTERRUPT_ACK => self.interrupt_status &= !v,
            R_QUEUE_DESC_LO => {
                let d = self.q().desc;
                self.q_mut().desc = (d & !0xffff_ffff) | u64::from(v);
            }
            R_QUEUE_DESC_HI => {
                let d = self.q().desc;
                self.q_mut().desc = (d & 0xffff_ffff) | (u64::from(v) << 32);
            }
            R_QUEUE_DRIVER_LO => {
                let a = self.q().avail;
                self.q_mut().avail = (a & !0xffff_ffff) | u64::from(v);
            }
            R_QUEUE_DRIVER_HI => {
                let a = self.q().avail;
                self.q_mut().avail = (a & 0xffff_ffff) | (u64::from(v) << 32);
            }
            R_QUEUE_DEVICE_LO => {
                let u = self.q().used;
                self.q_mut().used = (u & !0xffff_ffff) | u64::from(v);
            }
            R_QUEUE_DEVICE_HI => {
                let u = self.q().used;
                self.q_mut().used = (u & 0xffff_ffff) | (u64::from(v) << 32);
            }
            R_QUEUE_NOTIFY => return self.process_queue(v as usize),
            _ => {}
        }
        false
    }

    fn process_queue(&mut self, qidx: usize) -> bool {
        if qidx >= FS_NUM_QUEUES {
            return false;
        }
        let q = self.queues[qidx];
        if q.ready == 0 {
            return false;
        }
        // Geometry gate first: an illegal guest-programmed `QueueNum` is left
        // unserviced, exactly as before the validated ring walk landed.
        let Some(qsz) = super::validated_queue_size(q.num) else {
            return false;
        };
        // The validated ring walk needs a real `GuestMemory` over the same
        // externally-owned RAM; if it can't be built (e.g. a non-page-aligned
        // mapping) service nothing, mirroring the illegal-geometry early out.
        let Some(mem) = self.mem.guest_memory() else {
            return false;
        };
        let Some(mut queue) = build_split_queue(q.ring(), qsz) else {
            return false;
        };

        let mut completed: Vec<(u16, u32)> = Vec::new();
        {
            // `DescriptorChain::next` seeds `ttl` from the validated queue size and
            // range-checks every `next` link, so the chain walk is bounded without a
            // hand-rolled counter.
            let Ok(avail) = queue.iter(&mem) else {
                return false;
            };
            for chain in avail {
                let head = chain.head_index();
                // The FUSE request is the chain's device-readable span (gathered in
                // chain order); the reply lands in its device-writable span.
                let mut req = Vec::new();
                for desc in chain.clone().readable() {
                    req.extend_from_slice(&self.mem.read_bytes(desc.addr().0, desc.len() as usize));
                }
                let writable: Vec<(u64, u32)> = chain
                    .writable()
                    .map(|desc| (desc.addr().0, desc.len()))
                    .collect();
                completed.push((head, self.service_request(&req, &writable)));
            }
        }
        let serviced = !completed.is_empty();
        for (head, written) in completed {
            // `head` came from a validated avail-ring slot (`< qsz`); `add_used`
            // re-checks the bound and writes the same 8-byte used element + used
            // index the hand-rolled completion wrote.
            let _ = queue.add_used(&mem, head, written);
        }
        self.queues[qidx].last_avail = queue.next_avail();
        self.queues[qidx].next_used = queue.next_used();
        if serviced {
            self.interrupt_status |= 1;
        }
        serviced
    }

    /// Dispatch the gathered FUSE request, then scatter the reply across the
    /// chain's device-writable descriptors in chain order. Returns bytes written
    /// into guest memory (the used-ring `len`).
    ///
    /// The scatter deliberately keeps its own loop rather than reusing the vsock
    /// transport's: an out-of-range writable descriptor here is skipped and the
    /// reply continues into the next one, whereas the vsock RX scatter stops.
    fn service_request(&mut self, req: &[u8], writable: &[(u64, u32)]) -> u32 {
        let reply = self.server.dispatch(req);
        let mut off = 0usize;
        let mut written = 0u32;
        for &(addr, len) in writable {
            if off >= reply.len() {
                break;
            }
            let n = (len as usize).min(reply.len() - off);
            let wrote = self.mem.write_bytes(addr, &reply[off..off + n]);
            written += wrote as u32;
            off += wrote;
        }
        written
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Split-descriptor flag bits, as a conformant guest programs them.
    const DESC_F_NEXT: u16 = 1;
    const DESC_F_WRITE: u16 = 2;

    /// Base guest-physical address of the scratch RAM the device fixtures map.
    const BLK_BASE: u64 = 0x4000_0000;
    /// Scratch RAM size for the fixtures: room for the rings plus every request
    /// buffer the differential layouts need.
    const RAM_SIZE: usize = 0x20000;

    /// Drive one FUSE INIT through the virtio-fs transport: build a virtqueue in
    /// a RAM buffer with a readable request descriptor + a writable reply
    /// descriptor, notify the request queue, and assert the reply landed (a
    /// success `fuse_out_header` with the negotiated major version). This
    /// exercises the descriptor gather/scatter + used-ring update end to end.
    #[test]
    fn fs_transport_drives_the_fuse_server_over_a_virtqueue() {
        let dir = tempfile::tempdir().unwrap();
        let mut fs = fs_dev(dir.path());

        // FUSE INIT request: fuse_in_header(40) + fuse_init_in(16).
        let fuse = fuse_request(FUSE_INIT, 1, 0, &init_body());
        fs.mem.write_bytes(0x4000, &fuse);

        // desc[0] readable → request @0x4000; desc[1] writable → reply @0x5000.
        write_desc(&fs.mem, 0x1000, 0x4000, fuse.len() as u32, DESC_F_NEXT, 1);
        write_desc(&fs.mem, 0x1010, 0x5000, 256, DESC_F_WRITE, 0);
        // avail ring @0x2000: idx=1, ring[0]=head 0.
        fs.mem.wr_u16(0x2002, 1);
        fs.mem.wr_u16(0x2004, 0);

        // Program the request queue (index 1) and notify.
        fs.write(R_QUEUE_SEL, 1);
        fs.write(R_QUEUE_NUM, 4);
        fs.write(R_QUEUE_DESC_LO, 0x1000);
        fs.write(R_QUEUE_DRIVER_LO, 0x2000);
        fs.write(R_QUEUE_DEVICE_LO, 0x3000);
        fs.write(R_QUEUE_READY, 1);
        let irq = fs.write(R_QUEUE_NOTIFY, 1);
        assert!(irq, "servicing a request must raise an interrupt");

        // used ring idx advanced to 1.
        assert_eq!(fs.mem.rd_u16(0x3002), 1);
        // Reply @0x5000: fuse_out_header len@0, error@4 == 0, major @16.
        assert_eq!(fs.mem.rd_u32(0x5004) as i32, 0, "INIT must succeed");
        assert_eq!(fs.mem.rd_u32(0x5010), 7, "negotiated FUSE major version");
    }

    /// A block device over freshly-allocated page-aligned scratch RAM. The
    /// virtqueue paths build a `GuestMemoryMmap` over this pointer, which rejects
    /// a non-page-aligned mapping, so the fixture RAM must match production's.
    fn blk_dev(disk: DiskImage) -> VirtioBlk {
        let ram = crate::test_support::page_aligned_ram(RAM_SIZE);
        // SAFETY: page-aligned, zeroed, leaked for the test process lifetime.
        unsafe { VirtioBlk::new(0x0a00_0000, 48, ram.as_mut_ptr(), BLK_BASE, ram.len(), disk) }
    }

    /// A virtio-fs device serving `root`, over page-aligned scratch RAM mapped at
    /// guest-physical 0 (the addresses the fs fixtures use).
    fn fs_dev(root: &Path) -> VirtioFs {
        let ram = crate::test_support::page_aligned_ram(RAM_SIZE);
        // SAFETY: page-aligned, zeroed, leaked for the test process lifetime.
        unsafe { VirtioFs::new(0, 5, ram.as_mut_ptr(), 0, ram.len(), root.to_path_buf()) }
    }

    /// Write one 16-byte split descriptor (addr u64 @0, len u32 @8, flags u16 @12,
    /// next u16 @14) at guest address `at`.
    fn write_desc(mem: &GuestMem, at: u64, addr: u64, len: u32, flags: u16, next: u16) {
        mem.write_bytes(at, &addr.to_le_bytes());
        mem.write_bytes(at + 8, &len.to_le_bytes());
        mem.wr_u16(at + 12, flags);
        mem.wr_u16(at + 14, next);
    }

    fn dev(disk: Vec<u8>) -> VirtioBlk {
        blk_dev(DiskImage::mem(disk))
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
        let (desc, avail, used) = (BLK_BASE + 0x1000, BLK_BASE + 0x2000, BLK_BASE + 0x3000);
        let (hdr, data, status) = (BLK_BASE + 0x4000, BLK_BASE + 0x5000, BLK_BASE + 0x6000);

        let mut disk = vec![0u8; 4096];
        disk[..11].copy_from_slice(b"DISK-BYTES!");
        let mut d = blk_dev(DiskImage::mem(disk));

        // Descriptor chain: header(RO,->1), data(WO,->2), status(WO). The `len`
        // field sits at desc offset 8 — the regression this test guards.
        write_desc(&d.mem, desc, hdr, 16, DESC_F_NEXT, 1);
        write_desc(&d.mem, desc + 16, data, 512, DESC_F_NEXT | DESC_F_WRITE, 2);
        write_desc(&d.mem, desc + 32, status, 1, DESC_F_WRITE, 0);
        // avail: flags=0, idx=1, ring[0]=head desc 0.
        d.mem.wr_u16(avail + 2, 1);
        d.mem.wr_u16(avail + 4, 0);
        // request header: type=IN(read), sector=0.
        d.mem.write_bytes(hdr, &VIRTIO_BLK_T_IN.to_le_bytes());
        d.mem.write_bytes(hdr + 8, &0u64.to_le_bytes());

        d.write(R_QUEUE_NUM, 4);
        d.write(R_QUEUE_DESC_LO, desc & 0xffff_ffff);
        d.write(R_QUEUE_DRIVER_LO, avail & 0xffff_ffff);
        d.write(R_QUEUE_DEVICE_LO, used & 0xffff_ffff);
        d.write(R_QUEUE_READY, 1);

        assert!(d.write(R_QUEUE_NOTIFY, 0), "notify services the queue");
        // Data buffer received sector 0; status OK; used ring advanced.
        assert_eq!(&d.mem.read_bytes(data, 11), b"DISK-BYTES!");
        assert_eq!(d.mem.read_bytes(status, 1)[0], VIRTIO_BLK_S_OK);
        assert_eq!(d.mem.rd_u16(used + 2), 1);
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
        let f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().set_len(512).unwrap();
        let mut d = blk_dev(DiskImage::open(f.path(), true).unwrap());
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

    /// Queue sizes a hostile guest can program that are illegal geometry: zero,
    /// values whose low 16 bits are zero (which truncate to a zero `u16`), and
    /// sizes above the advertised maximum or not a power of two.
    const ILLEGAL_QUEUE_SIZES: [u32; 6] = [0, 0x1_0000, 0x2_0000, 0xffff_0000, 300, 512];

    /// Program a virtio-blk request queue with raw `QueueNum` and an `avail_idx`
    /// of 1 (so the drain loop body, which indexes with `last % qsz`, runs), then
    /// notify. Returns whether the device signalled an interrupt (serviced the
    /// ring). Must never panic.
    fn blk_notify_with_queue_num(num: u32) -> bool {
        let mut d = blk_dev(DiskImage::mem(vec![0u8; 4096]));
        d.mem.wr_u16(BLK_BASE + 0x2002, 1);
        d.write(R_QUEUE_NUM, u64::from(num));
        d.write(R_QUEUE_DESC_LO, (BLK_BASE + 0x1000) & 0xffff_ffff);
        d.write(R_QUEUE_DRIVER_LO, (BLK_BASE + 0x2000) & 0xffff_ffff);
        d.write(R_QUEUE_DEVICE_LO, (BLK_BASE + 0x3000) & 0xffff_ffff);
        d.write(R_QUEUE_READY, 1);
        d.write(R_QUEUE_NOTIFY, 0)
    }

    #[test]
    fn virtio_blk_rejects_queue_size_that_truncates_to_zero() {
        assert!(!blk_notify_with_queue_num(0x1_0000));
    }

    #[test]
    fn virtio_blk_rejects_illegal_queue_geometry() {
        for num in ILLEGAL_QUEUE_SIZES {
            assert!(
                !blk_notify_with_queue_num(num),
                "blk queue size {num:#x} must not be serviced"
            );
        }
    }

    /// Program the virtio-fs request queue (index 1) with raw `QueueNum` and an
    /// `avail_idx` of 1, then notify. Returns whether an interrupt was signalled.
    /// Must never panic.
    fn fs_notify_with_queue_num(num: u32) -> bool {
        let dir = tempfile::tempdir().unwrap();
        let mut fs = fs_dev(dir.path());
        fs.mem.wr_u16(0x2002, 1);
        fs.write(R_QUEUE_SEL, 1);
        fs.write(R_QUEUE_NUM, u64::from(num));
        fs.write(R_QUEUE_DESC_LO, 0x1000);
        fs.write(R_QUEUE_DRIVER_LO, 0x2000);
        fs.write(R_QUEUE_DEVICE_LO, 0x3000);
        fs.write(R_QUEUE_READY, 1);
        fs.write(R_QUEUE_NOTIFY, 1)
    }

    #[test]
    fn virtio_fs_rejects_queue_size_that_truncates_to_zero() {
        assert!(!fs_notify_with_queue_num(0x1_0000));
    }

    #[test]
    fn virtio_fs_rejects_illegal_queue_geometry() {
        for num in ILLEGAL_QUEUE_SIZES {
            assert!(
                !fs_notify_with_queue_num(num),
                "fs queue size {num:#x} must not be serviced"
            );
        }
    }

    // ---- virtio-blk queue migration: differential equivalence ---------------

    /// One conformant virtio-blk request chain: a 16-byte device-readable
    /// request header, `data` payload descriptors of the given byte lengths
    /// (device-writable for a read request, device-readable for a write), and a
    /// trailing 1-byte device-writable status descriptor when `status` is set.
    #[derive(Clone)]
    struct BlkChain {
        req_type: u32,
        sector: u64,
        data: Vec<u32>,
        status: bool,
    }

    /// Deterministic, non-trivial disk contents so a read moves recognisable
    /// bytes and a write is visible against the surrounding pattern.
    fn blk_disk() -> DiskImage {
        DiskImage::mem(
            (0..8192usize)
                .map(|i| (i as u8).wrapping_mul(31).wrapping_add(11))
                .collect(),
        )
    }

    fn disk_bytes(d: &VirtioBlk) -> Vec<u8> {
        match &d.disk {
            DiskImage::Mem(v) => v.clone(),
            DiskImage::File { .. } => panic!("differential fixtures use in-memory disks"),
        }
    }

    /// Representative conformant block layouts for `qsz`: reads and writes,
    /// single and multi payload descriptors, a payload-less request, an unknown
    /// request type (status IOERR), a read past capacity, and a multi-chain
    /// batch — all within `qsz` descriptors and `qsz` chains.
    fn blk_layouts_for(qsz: u16) -> Vec<(&'static str, Vec<BlkChain>)> {
        let read = |sector, data: &[u32]| BlkChain {
            req_type: VIRTIO_BLK_T_IN,
            sector,
            data: data.to_vec(),
            status: true,
        };
        let write = |sector, data: &[u32]| BlkChain {
            req_type: VIRTIO_BLK_T_OUT,
            sector,
            data: data.to_vec(),
            status: true,
        };
        match qsz {
            // One descriptor fits: a header with neither payload nor status.
            1 => vec![(
                "header-only",
                vec![BlkChain {
                    req_type: VIRTIO_BLK_T_IN,
                    sector: 0,
                    data: Vec::new(),
                    status: false,
                }],
            )],
            // Two descriptors: header + status, or two header-only chains.
            2 => vec![
                ("read-no-payload", vec![read(0, &[])]),
                ("write-no-payload", vec![write(1, &[])]),
                (
                    "two-header-only-chains",
                    vec![
                        BlkChain {
                            req_type: VIRTIO_BLK_T_IN,
                            sector: 0,
                            data: Vec::new(),
                            status: false,
                        },
                        BlkChain {
                            req_type: VIRTIO_BLK_T_OUT,
                            sector: 3,
                            data: Vec::new(),
                            status: false,
                        },
                    ],
                ),
            ],
            _ => vec![
                ("read-single-payload", vec![read(0, &[512])]),
                ("write-single-payload", vec![write(2, &[512])]),
                ("read-multi-payload", vec![read(1, &[512, 512, 1024])]),
                ("write-multi-payload", vec![write(4, &[512, 512])]),
                ("read-bulk", vec![read(0, &[4096])]),
                // Sector far past the 8 KiB image: the read zero-fills.
                ("read-past-capacity", vec![read(4096, &[512])]),
                (
                    "unknown-request-type",
                    vec![BlkChain {
                        req_type: 7,
                        sector: 0,
                        data: Vec::new(),
                        status: true,
                    }],
                ),
                (
                    "mixed-batch",
                    vec![
                        read(0, &[512]),
                        write(6, &[512]),
                        read(2, &[512, 512]),
                        BlkChain {
                            req_type: 9,
                            sector: 1,
                            data: Vec::new(),
                            status: true,
                        },
                        write(8, &[1024]),
                    ],
                ),
            ],
        }
    }

    /// Lay `chains` out as a virtio-blk split virtqueue in `d`'s guest RAM,
    /// program the device's ring registers, and seed each request header (plus
    /// each write request's payload). The available index is left at zero — the
    /// caller publishes chains by raising it, one notify round at a time.
    /// Returns the (available ring, used ring) addresses.
    fn program_blk_queue(d: &mut VirtioBlk, qsz: u16, chains: &[BlkChain]) -> (u64, u64) {
        let desc = BLK_BASE + 0x1000;
        let avail = BLK_BASE + 0x4000;
        let used = BLK_BASE + 0x8000;
        let mut buf = BLK_BASE + 0xc000;
        let mut desc_idx: u16 = 0;
        for (chain_no, chain) in chains.iter().enumerate() {
            let head = desc_idx;
            // Descriptor plan: 16-byte header, payload buffers, optional status.
            let payload_flags = if chain.req_type == VIRTIO_BLK_T_IN {
                DESC_F_WRITE
            } else {
                0
            };
            let mut plan: Vec<(u32, u16)> = vec![(16, 0)];
            plan.extend(chain.data.iter().map(|&len| (len, payload_flags)));
            if chain.status {
                plan.push((1, DESC_F_WRITE));
            }
            for (slot, &(len, flags)) in plan.iter().enumerate() {
                assert!(
                    desc_idx < qsz,
                    "layout exceeds the {qsz}-entry descriptor table"
                );
                let last = slot + 1 == plan.len();
                write_desc(
                    &d.mem,
                    desc + u64::from(desc_idx) * 16,
                    buf,
                    len,
                    flags | if last { 0 } else { DESC_F_NEXT },
                    desc_idx + 1,
                );
                if slot == 0 {
                    // request header: type u32 @0, reserved u32 @4, sector u64 @8.
                    d.mem.write_bytes(buf, &chain.req_type.to_le_bytes());
                    d.mem.write_bytes(buf + 8, &chain.sector.to_le_bytes());
                } else if flags & DESC_F_WRITE == 0 {
                    // A write request's payload, distinct per chain.
                    let fill = vec![0xC0u8.wrapping_add(chain_no as u8); len as usize];
                    d.mem.write_bytes(buf, &fill);
                }
                // Keep buffers separated and 16-aligned; empty buffers still stride.
                buf += (u64::from(len).max(1) + 15) & !15;
                desc_idx += 1;
            }
            d.mem.wr_u16(avail + 4 + (chain_no as u64) * 2, head);
        }
        d.queue_num = u32::from(qsz);
        d.desc = desc;
        d.avail = avail;
        d.used = used;
        d.queue_ready = 1;
        (avail, used)
    }

    /// Notify boundaries for a layout: the available index published before each
    /// round. A multi-chain layout is drained over two notifies so the
    /// device-owned available and used cursors must survive between them.
    fn notify_rounds(chains: usize) -> Vec<u16> {
        if chains > 1 {
            vec![1, chains as u16]
        } else {
            vec![chains as u16]
        }
    }

    /// Faithful copy of the pre-migration hand-rolled virtio-blk drain loop and
    /// used-ring completion, kept as the differential oracle. The migrated
    /// `process_queue` must reproduce its guest-RAM writes, disk writes,
    /// used-ring bytes, used index, `last_avail`, and interrupt bit exactly.
    ///
    /// The oracle re-reads `used.idx` from guest RAM before every completion
    /// where the migrated path uses its own cursor. The two stay in lockstep for
    /// every layout here because each fixture starts from a zeroed used ring
    /// that no guest buffer aliases — exactly the conformant case. A fixture
    /// that pre-seeds a non-zero `used.idx`, or aims a device-writable buffer at
    /// the used ring, is expected to diverge; those cases are asserted as
    /// device-owned wins by the ring-cursor tests below.
    fn reference_blk_process_queue(d: &mut VirtioBlk) -> bool {
        if d.queue_ready == 0 {
            return false;
        }
        let Some(qsz) = super::super::validated_queue_size(d.queue_num) else {
            return false;
        };
        let avail_idx = d.rd_u16(d.avail + 2);
        let mut serviced = false;
        while d.last_avail != avail_idx {
            let slot = d.last_avail % qsz;
            let head = d.rd_u16(d.avail + 4 + u64::from(slot) * 2);
            let written = reference_blk_service_request(d, head, qsz);
            // used ring: {id u32, len u32} at used + 4 + (used_idx % qsz)*8.
            let used_idx = d.rd_u16(d.used + 2);
            let uslot = u64::from(used_idx % qsz);
            d.mem.wr_u16(d.used + 4 + uslot * 8, head);
            d.mem.wr_u16(d.used + 6 + uslot * 8, 0);
            d.mem.wr_u16(d.used + 8 + uslot * 8, written as u16);
            d.mem
                .wr_u16(d.used + 10 + uslot * 8, (written >> 16) as u16);
            d.mem.wr_u16(d.used + 2, used_idx.wrapping_add(1));
            d.last_avail = d.last_avail.wrapping_add(1);
            serviced = true;
        }
        if serviced {
            d.interrupt_status |= 1;
        }
        serviced
    }

    /// Faithful copy of the pre-migration positional chain walk: the head
    /// descriptor is the request header, a descriptor without `F_NEXT` is the
    /// status byte, everything between them is payload.
    fn reference_blk_service_request(d: &mut VirtioBlk, head: u16, qsz: u16) -> u32 {
        let desc_base = d.desc;
        let desc_at = |i: u16| desc_base + u64::from(i) * 16;
        let d0 = desc_at(head);
        let hdr_addr = d.rd_u64(d0);
        let req_type = d.rd_u32(hdr_addr);
        let mut sector = d.rd_u64(hdr_addr + 8);

        let mut idx = head;
        let mut flags = d.rd_u16(d0 + 12);
        let mut written: u32 = 0;
        let mut status_addr: Option<u64> = None;
        let mut io_ok = true;
        let mut guard = 0u32;
        while flags & DESC_F_NEXT != 0 {
            let next = d.rd_u16(desc_at(idx) + 14);
            if next >= qsz {
                break;
            }
            let da = desc_at(next);
            let addr = d.rd_u64(da);
            let len = d.rd_u32(da + 8);
            let dflags = d.rd_u16(da + 12);
            if dflags & DESC_F_NEXT == 0 {
                status_addr = Some(addr);
            } else {
                io_ok &= d.transfer(req_type, sector, addr, len, &mut written);
                sector += u64::from(len) / SECTOR;
            }
            idx = next;
            flags = dflags;
            guard += 1;
            if guard > u32::from(qsz) {
                break;
            }
        }
        let ok = io_ok && matches!(req_type, VIRTIO_BLK_T_IN | VIRTIO_BLK_T_OUT);
        if let Some(s) = status_addr {
            d.wr_u8(
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

    #[test]
    fn blk_process_queue_matches_reference_walk_byte_for_byte() {
        for qsz in [1u16, 2, 128, 256] {
            for (label, chains) in blk_layouts_for(qsz) {
                let what = format!("qsz={qsz} layout={label}");

                // The pre-migration oracle drives one RAM + disk image, the
                // migrated path a byte-identical pair, notify round for notify
                // round.
                let mut d_ref = blk_dev(blk_disk());
                let (avail, used) = program_blk_queue(&mut d_ref, qsz, &chains);
                let mut d_new = blk_dev(blk_disk());
                program_blk_queue(&mut d_new, qsz, &chains);

                for round in notify_rounds(chains.len()) {
                    d_ref.mem.wr_u16(avail + 2, round);
                    let ret_ref = reference_blk_process_queue(&mut d_ref);
                    d_new.mem.wr_u16(avail + 2, round);
                    let ret_new = d_new.process_queue();
                    assert_eq!(
                        ret_new, ret_ref,
                        "return value differs for {what} at avail_idx={round}"
                    );
                }
                assert_eq!(
                    d_new.mem.read_bytes(BLK_BASE, RAM_SIZE),
                    d_ref.mem.read_bytes(BLK_BASE, RAM_SIZE),
                    "guest RAM differs for {what}"
                );
                let used_len = 4 + usize::from(qsz) * 8;
                assert_eq!(
                    d_new.mem.read_bytes(used, used_len),
                    d_ref.mem.read_bytes(used, used_len),
                    "used-ring bytes differ for {what}"
                );
                assert_eq!(
                    d_new.rd_u16(used + 2),
                    d_ref.rd_u16(used + 2),
                    "used index differs for {what}"
                );
                assert_eq!(
                    d_new.last_avail, d_ref.last_avail,
                    "last_avail differs for {what}"
                );
                assert_eq!(
                    d_new.interrupt_status, d_ref.interrupt_status,
                    "interrupt_status differs for {what}"
                );
                assert_eq!(
                    disk_bytes(&d_new),
                    disk_bytes(&d_ref),
                    "disk image differs for {what}"
                );
            }
        }
    }

    /// A guest that aims a read's payload buffer at its own used ring cannot
    /// steer where the device records completions: the used index is device
    /// state now, not a value re-read from guest RAM per completion.
    #[test]
    fn blk_used_index_is_device_owned_within_a_drain() {
        let qsz = 8u16;
        let desc = BLK_BASE + 0x1000;
        let avail = BLK_BASE + 0x4000;
        let used = BLK_BASE + 0x8000;
        let scratch = BLK_BASE + 0xc000;

        // Two read chains. The first aims its 512-byte payload buffer straight at
        // the used ring, so servicing it overwrites the used index with disk bytes.
        let program = |d: &mut VirtioBlk| {
            write_desc(&d.mem, desc, scratch, 16, DESC_F_NEXT, 1);
            write_desc(&d.mem, desc + 16, used, 512, DESC_F_WRITE | DESC_F_NEXT, 2);
            write_desc(&d.mem, desc + 32, scratch + 0x100, 1, DESC_F_WRITE, 0);
            write_desc(&d.mem, desc + 48, scratch + 0x200, 16, DESC_F_NEXT, 4);
            write_desc(
                &d.mem,
                desc + 64,
                scratch + 0x400,
                512,
                DESC_F_WRITE | DESC_F_NEXT,
                5,
            );
            write_desc(&d.mem, desc + 80, scratch + 0x800, 1, DESC_F_WRITE, 0);
            // Both request headers read sector 0.
            d.mem.write_bytes(scratch, &VIRTIO_BLK_T_IN.to_le_bytes());
            d.mem
                .write_bytes(scratch + 0x200, &VIRTIO_BLK_T_IN.to_le_bytes());
            d.mem.wr_u16(avail + 4, 0);
            d.mem.wr_u16(avail + 6, 3);
            d.mem.wr_u16(avail + 2, 2);
            d.queue_num = u32::from(qsz);
            d.desc = desc;
            d.avail = avail;
            d.used = used;
            d.queue_ready = 1;
        };

        let mut d = blk_dev(blk_disk());
        program(&mut d);
        assert!(d.process_queue());
        // Completions landed at used slots 0 and 1, and the index counted exactly
        // the two chains — despite the guest's payload landing on top of it.
        assert_eq!(
            d.mem.rd_u16(used + 2),
            2,
            "used index counts the two chains"
        );
        assert_eq!(d.mem.rd_u32(used + 4), 0, "slot 0 records the first head");
        assert_eq!(
            d.mem.rd_u32(used + 8),
            513,
            "slot 0 records payload + status"
        );
        assert_eq!(d.mem.rd_u32(used + 12), 3, "slot 1 records the second head");
        assert_eq!(
            d.mem.rd_u32(used + 16),
            513,
            "slot 1 records payload + status"
        );
        assert_eq!(d.last_avail, 2);

        // The pre-migration walk re-read the index from guest RAM per completion,
        // so the same layout steered it wherever the disk bytes pointed.
        let mut d_ref = blk_dev(blk_disk());
        program(&mut d_ref);
        assert!(reference_blk_process_queue(&mut d_ref));
        assert_ne!(
            d_ref.mem.rd_u16(used + 2),
            2,
            "the hand-rolled walk was steerable — that is the behaviour being retired"
        );
    }

    // ---- device-owned ring cursors: cross-drain + lifecycle -----------------

    /// Two conformant single-payload read chains. Laid out by
    /// [`program_blk_queue`], chain 0 takes descriptors 0..3 (head 0) and
    /// chain 1 takes 3..6 (head 3).
    fn blk_two_read_chains() -> Vec<BlkChain> {
        (0..2)
            .map(|sector| BlkChain {
                req_type: VIRTIO_BLK_T_IN,
                sector,
                data: vec![512],
                status: true,
            })
            .collect()
    }

    /// A block device carrying [`blk_two_read_chains`], drained once — so both
    /// device-owned cursors sit at 1 with one chain still unpublished. Returns
    /// the device and its (available ring, used ring) addresses.
    fn blk_drained_once(qsz: u16) -> (VirtioBlk, u64, u64) {
        let mut d = blk_dev(blk_disk());
        let (avail, used) = program_blk_queue(&mut d, qsz, &blk_two_read_chains());
        d.mem.wr_u16(avail + 2, 1);
        assert!(d.process_queue(), "first drain services one chain");
        (d, avail, used)
    }

    /// The used cursor is device state **across** drains, not just within one:
    /// the device never recovers it from the guest-writable used ring. A guest
    /// that rewrites `used.idx` between two notifies cannot make the next
    /// completion overwrite a record it has not consumed.
    #[test]
    fn blk_used_index_is_device_owned_across_drains() {
        let qsz = 8u16;
        let (mut d, avail, used) = blk_drained_once(qsz);
        assert_eq!(d.mem.rd_u16(used + 2), 1, "first drain published index 1");
        assert_eq!(d.mem.rd_u32(used + 4), 0, "slot 0 records the first head");

        // Between drains the guest scribbles its own value into `used.idx`,
        // aiming the next completion back at slot 0.
        d.mem.wr_u16(used + 2, 0);

        d.mem.wr_u16(avail + 2, 2);
        assert!(d.process_queue(), "second drain services the second chain");
        assert_eq!(
            d.mem.rd_u16(used + 2),
            2,
            "the device republished its own count, not the guest's"
        );
        assert_eq!(
            d.mem.rd_u32(used + 4),
            0,
            "slot 0 still holds the first completion"
        );
        assert_eq!(
            d.mem.rd_u32(used + 12),
            3,
            "the second completion landed at the device's next slot"
        );
        assert_eq!(d.next_used, 2, "device cursor counted both completions");

        // The pre-migration walk re-read the index from guest RAM per
        // completion, so the same scribble steered its second completion on top
        // of the first.
        let mut d_ref = blk_dev(blk_disk());
        program_blk_queue(&mut d_ref, qsz, &blk_two_read_chains());
        d_ref.mem.wr_u16(avail + 2, 1);
        assert!(reference_blk_process_queue(&mut d_ref));
        d_ref.mem.wr_u16(used + 2, 0);
        d_ref.mem.wr_u16(avail + 2, 2);
        assert!(reference_blk_process_queue(&mut d_ref));
        assert_eq!(
            d_ref.mem.rd_u16(used + 2),
            1,
            "the retired walk followed the guest's index"
        );
        assert_eq!(
            d_ref.mem.rd_u32(used + 4),
            3,
            "and overwrote slot 0 with the second head"
        );
    }

    #[test]
    fn blk_queue_ready_zero_rewinds_the_ring_cursors() {
        let (mut d, avail, used) = blk_drained_once(8);
        assert_eq!(
            (d.last_avail, d.next_used),
            (1, 1),
            "one chain consumed and completed"
        );

        d.write(R_QUEUE_READY, 0);
        assert_eq!(d.queue_ready, 0);
        assert_eq!(
            (d.last_avail, d.next_used),
            (0, 0),
            "detaching the queue rewinds both cursors"
        );

        // The driver reactivates with a freshly-zeroed ring: the first chain is
        // serviced again and its completion lands at used slot 0.
        d.mem.wr_u16(used + 2, 0);
        d.mem.wr_u16(avail + 2, 0);
        d.write(R_QUEUE_READY, 1);
        d.mem.wr_u16(avail + 2, 1);
        assert!(d.process_queue());
        assert_eq!(d.mem.rd_u16(used + 2), 1, "completion published at index 1");
        assert_eq!(d.mem.rd_u32(used + 4), 0, "and recorded at slot 0");
    }

    #[test]
    fn blk_device_reset_rewinds_the_ring_cursors() {
        let (mut d, _avail, _used) = blk_drained_once(8);
        assert_eq!((d.last_avail, d.next_used), (1, 1));

        // A driver walking the status bits up to DRIVER_OK must not be rewound.
        d.write(R_STATUS, 0xf);
        assert_eq!(
            (d.last_avail, d.next_used),
            (1, 1),
            "a non-zero status write leaves the cursors alone"
        );

        d.write(R_STATUS, 0);
        assert_eq!(
            (d.last_avail, d.next_used),
            (0, 0),
            "a device reset rewinds both cursors"
        );
    }

    #[test]
    fn blk_redundant_queue_ready_write_does_not_rewind_a_live_ring() {
        let (mut d, avail, used) = blk_drained_once(8);

        d.write(R_QUEUE_READY, 1);
        assert_eq!(
            (d.last_avail, d.next_used),
            (1, 1),
            "re-arming an already-ready queue must not rewind it"
        );

        // The next drain resumes at the second chain and the device's next slot.
        d.mem.wr_u16(avail + 2, 2);
        assert!(d.process_queue());
        assert_eq!(d.mem.rd_u16(used + 2), 2);
        assert_eq!(
            d.mem.rd_u32(used + 12),
            3,
            "slot 1 records the second chain's head"
        );
    }

    // ---- virtio-fs queue migration: differential equivalence ----------------

    const FUSE_LOOKUP: u32 = 1;
    const FUSE_GETATTR: u32 = 3;
    const FUSE_STATFS: u32 = 17;
    const FUSE_INIT: u32 = 26;
    /// An opcode the server does not implement: the reply is a bare error header.
    const FUSE_UNSUPPORTED: u32 = 0x7fff;
    /// Wire size of `fuse_in_header`.
    const FUSE_IN_HEADER_LEN: usize = 40;

    /// Build a FUSE request: `fuse_in_header` (len, opcode, unique, nodeid, uid,
    /// gid, pid, padding) followed by the opcode body.
    fn fuse_request(opcode: u32, unique: u64, nodeid: u64, body: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&((FUSE_IN_HEADER_LEN + body.len()) as u32).to_le_bytes());
        b.extend_from_slice(&opcode.to_le_bytes());
        b.extend_from_slice(&unique.to_le_bytes());
        b.extend_from_slice(&nodeid.to_le_bytes());
        b.extend_from_slice(&[0u8; 16]); // uid, gid, pid, padding
        b.extend_from_slice(body);
        b
    }

    /// `fuse_init_in`: major, minor, max_readahead, flags.
    fn init_body() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&7u32.to_le_bytes());
        b.extend_from_slice(&31u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b
    }

    /// One virtio-fs chain: the FUSE request bytes split across device-readable
    /// descriptors, then the device-writable reply-buffer capacities.
    #[derive(Clone)]
    struct FsChain {
        req: Vec<Vec<u8>>,
        reply: Vec<u32>,
    }

    /// Split `req` after `at` bytes into two device-readable descriptors.
    fn split_at(req: &[u8], at: usize) -> Vec<Vec<u8>> {
        vec![req[..at].to_vec(), req[at..].to_vec()]
    }

    /// Representative virtio-fs layouts for `qsz`: a whole request in one
    /// descriptor, a request split mid-header and after the header, a reply
    /// scattered across several writable buffers, a reply buffer too small for
    /// the reply, a chain with no writable descriptor at all, and a multi-chain
    /// batch of different opcodes.
    fn fs_layouts_for(qsz: u16) -> Vec<(&'static str, Vec<FsChain>)> {
        let init = fuse_request(FUSE_INIT, 1, 0, &init_body());
        let getattr = fuse_request(FUSE_GETATTR, 2, 1, &[0u8; 16]);
        let lookup = fuse_request(FUSE_LOOKUP, 3, 1, b"hello.txt\0");
        let statfs = fuse_request(FUSE_STATFS, 4, 1, &[]);
        let unsupported = fuse_request(FUSE_UNSUPPORTED, 5, 1, &[]);
        match qsz {
            // One descriptor: request only, so the reply has nowhere to land.
            1 => vec![(
                "request-without-reply-buffer",
                vec![FsChain {
                    req: vec![init.clone()],
                    reply: Vec::new(),
                }],
            )],
            2 => vec![
                (
                    "init",
                    vec![FsChain {
                        req: vec![init.clone()],
                        reply: vec![256],
                    }],
                ),
                (
                    "reply-buffer-too-small",
                    vec![FsChain {
                        req: vec![init.clone()],
                        reply: vec![8],
                    }],
                ),
            ],
            _ => vec![
                (
                    "request-split-after-header",
                    vec![FsChain {
                        req: split_at(&init, FUSE_IN_HEADER_LEN),
                        reply: vec![256],
                    }],
                ),
                (
                    "request-split-mid-header",
                    vec![FsChain {
                        req: split_at(&init, 12),
                        reply: vec![256],
                    }],
                ),
                (
                    "reply-scattered",
                    vec![FsChain {
                        req: vec![init.clone()],
                        reply: vec![16, 24, 240],
                    }],
                ),
                (
                    "reply-truncated-across-buffers",
                    vec![FsChain {
                        req: vec![init.clone()],
                        reply: vec![8, 8],
                    }],
                ),
                (
                    "opcode-batch",
                    vec![
                        FsChain {
                            req: vec![init.clone()],
                            reply: vec![256],
                        },
                        FsChain {
                            req: vec![getattr],
                            reply: vec![256],
                        },
                        FsChain {
                            req: split_at(&lookup, FUSE_IN_HEADER_LEN),
                            reply: vec![64, 192],
                        },
                        FsChain {
                            req: vec![statfs],
                            reply: vec![256],
                        },
                        FsChain {
                            req: vec![unsupported],
                            reply: vec![256],
                        },
                        FsChain {
                            req: vec![init],
                            reply: Vec::new(),
                        },
                    ],
                ),
            ],
        }
    }

    /// Lay `chains` out as a virtio-fs split virtqueue in `fs`'s guest RAM,
    /// program request queue `qidx`, and seed each request buffer. The available
    /// index is left at zero — the caller publishes chains by raising it, one
    /// notify round at a time. Returns the (available ring, used ring) addresses.
    fn program_fs_queue(
        fs: &mut VirtioFs,
        qidx: usize,
        qsz: u16,
        chains: &[FsChain],
    ) -> (u64, u64) {
        let desc = 0x1000u64;
        let avail = 0x4000u64;
        let used = 0x8000u64;
        let mut buf = 0xc000u64;
        let mut desc_idx: u16 = 0;
        for (chain_no, chain) in chains.iter().enumerate() {
            let head = desc_idx;
            let total = chain.req.len() + chain.reply.len();
            for slot in 0..total {
                assert!(
                    desc_idx < qsz,
                    "layout exceeds the {qsz}-entry descriptor table"
                );
                let (len, flags) = match chain.req.get(slot) {
                    Some(seg) => {
                        fs.mem.write_bytes(buf, seg);
                        (seg.len() as u32, 0)
                    }
                    None => (chain.reply[slot - chain.req.len()], DESC_F_WRITE),
                };
                let last = slot + 1 == total;
                write_desc(
                    &fs.mem,
                    desc + u64::from(desc_idx) * 16,
                    buf,
                    len,
                    flags | if last { 0 } else { DESC_F_NEXT },
                    desc_idx + 1,
                );
                // Keep buffers separated and 16-aligned; empty buffers still stride.
                buf += (u64::from(len).max(1) + 15) & !15;
                desc_idx += 1;
            }
            fs.mem.wr_u16(avail + 4 + (chain_no as u64) * 2, head);
        }
        fs.queues[qidx] = FsQueue {
            num: u32::from(qsz),
            ready: 1,
            desc,
            avail,
            used,
            last_avail: 0,
            next_used: 0,
        };
        (avail, used)
    }

    /// Faithful copy of the pre-migration hand-rolled virtio-fs drain loop and
    /// used-ring completion, kept as the differential oracle. Byte-identity with
    /// the migrated path holds under the same precondition as the block oracle:
    /// a zeroed, un-aliased used ring.
    fn reference_fs_process_queue(fs: &mut VirtioFs, qidx: usize) -> bool {
        if qidx >= FS_NUM_QUEUES {
            return false;
        }
        let q = fs.queues[qidx];
        if q.ready == 0 {
            return false;
        }
        let Some(qsz) = super::super::validated_queue_size(q.num) else {
            return false;
        };
        let avail_idx = fs.mem.rd_u16(q.avail + 2);
        let mut last_avail = q.last_avail;
        let mut serviced = false;
        while last_avail != avail_idx {
            let slot = last_avail % qsz;
            let head = fs.mem.rd_u16(q.avail + 4 + u64::from(slot) * 2);
            let written = reference_fs_service_request(fs, &q, head, qsz);
            let used_idx = fs.mem.rd_u16(q.used + 2);
            let uslot = u64::from(used_idx % qsz);
            fs.mem.wr_u16(q.used + 4 + uslot * 8, head);
            fs.mem.wr_u16(q.used + 6 + uslot * 8, 0);
            fs.mem.wr_u16(q.used + 8 + uslot * 8, written as u16);
            fs.mem
                .wr_u16(q.used + 10 + uslot * 8, (written >> 16) as u16);
            fs.mem.wr_u16(q.used + 2, used_idx.wrapping_add(1));
            last_avail = last_avail.wrapping_add(1);
            serviced = true;
        }
        fs.queues[qidx].last_avail = last_avail;
        if serviced {
            fs.interrupt_status |= 1;
        }
        serviced
    }

    /// Faithful copy of the pre-migration hand-rolled gather/dispatch/scatter.
    fn reference_fs_service_request(fs: &mut VirtioFs, q: &FsQueue, head: u16, qsz: u16) -> u32 {
        let desc_at = |i: u16| q.desc + u64::from(i) * 16;
        let mut req = Vec::new();
        let mut writable: Vec<(u64, u32)> = Vec::new();
        let mut idx = head;
        let mut guard = 0u32;
        loop {
            let da = desc_at(idx);
            let addr = fs.mem.rd_u64(da);
            let len = fs.mem.rd_u32(da + 8);
            let flags = fs.mem.rd_u16(da + 12);
            if flags & DESC_F_WRITE != 0 {
                writable.push((addr, len));
            } else {
                req.extend_from_slice(&fs.mem.read_bytes(addr, len as usize));
            }
            guard += 1;
            if flags & DESC_F_NEXT == 0 || guard > u32::from(qsz) {
                break;
            }
            let next = fs.mem.rd_u16(da + 14);
            if next >= qsz {
                break;
            }
            idx = next;
        }
        let reply = fs.server.dispatch(&req);
        let mut off = 0usize;
        let mut written = 0u32;
        for (addr, len) in writable {
            if off >= reply.len() {
                break;
            }
            let n = (len as usize).min(reply.len() - off);
            let wrote = fs.mem.write_bytes(addr, &reply[off..off + n]);
            written += wrote as u32;
            off += wrote;
        }
        written
    }

    #[test]
    fn fs_process_queue_matches_reference_walk_byte_for_byte() {
        // One shared read-only tree, so both devices' FUSE servers see identical
        // inodes and identical replies.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), b"virtio-fs payload").unwrap();
        const QIDX: usize = 1; // the request queue

        for qsz in [1u16, 2, 128, 256] {
            for (label, chains) in fs_layouts_for(qsz) {
                let what = format!("qsz={qsz} layout={label}");

                let mut fs_ref = fs_dev(dir.path());
                let (avail, used) = program_fs_queue(&mut fs_ref, QIDX, qsz, &chains);
                let mut fs_new = fs_dev(dir.path());
                program_fs_queue(&mut fs_new, QIDX, qsz, &chains);

                for round in notify_rounds(chains.len()) {
                    fs_ref.mem.wr_u16(avail + 2, round);
                    let ret_ref = reference_fs_process_queue(&mut fs_ref, QIDX);
                    fs_new.mem.wr_u16(avail + 2, round);
                    let ret_new = fs_new.process_queue(QIDX);
                    assert_eq!(
                        ret_new, ret_ref,
                        "return value differs for {what} at avail_idx={round}"
                    );
                }
                assert_eq!(
                    fs_new.mem.read_bytes(0, RAM_SIZE),
                    fs_ref.mem.read_bytes(0, RAM_SIZE),
                    "guest RAM differs for {what}"
                );
                let used_len = 4 + usize::from(qsz) * 8;
                assert_eq!(
                    fs_new.mem.read_bytes(used, used_len),
                    fs_ref.mem.read_bytes(used, used_len),
                    "used-ring bytes differ for {what}"
                );
                assert_eq!(
                    fs_new.mem.rd_u16(used + 2),
                    fs_ref.mem.rd_u16(used + 2),
                    "used index differs for {what}"
                );
                assert_eq!(
                    fs_new.queues[QIDX].last_avail, fs_ref.queues[QIDX].last_avail,
                    "last_avail differs for {what}"
                );
                assert_eq!(
                    fs_new.interrupt_status, fs_ref.interrupt_status,
                    "interrupt_status differs for {what}"
                );
            }
        }
    }

    /// The virtio-fs request queue (queue 0 is hiprio).
    const FS_REQ_QIDX: usize = 1;

    /// Two conformant FUSE INIT chains, each a request descriptor plus a reply
    /// buffer. Chain 0 takes descriptors 0..2 (head 0), chain 1 takes 2..4
    /// (head 2).
    fn fs_two_init_chains() -> Vec<FsChain> {
        let init = fuse_request(FUSE_INIT, 1, 0, &init_body());
        vec![
            FsChain {
                req: vec![init.clone()],
                reply: vec![256],
            },
            FsChain {
                req: vec![init],
                reply: vec![256],
            },
        ]
    }

    /// A virtio-fs device carrying [`fs_two_init_chains`] on its request queue,
    /// drained once — so both device-owned cursors sit at 1 with one chain still
    /// unpublished. Returns the device and its (available ring, used ring)
    /// addresses.
    fn fs_drained_once(root: &Path, qsz: u16) -> (VirtioFs, u64, u64) {
        let mut fs = fs_dev(root);
        let (avail, used) = program_fs_queue(&mut fs, FS_REQ_QIDX, qsz, &fs_two_init_chains());
        fs.mem.wr_u16(avail + 2, 1);
        assert!(
            fs.process_queue(FS_REQ_QIDX),
            "first drain services one chain"
        );
        (fs, avail, used)
    }

    /// Select the request queue, so the `QueueNum`/`QueueReady`/address register
    /// writes that follow apply to it.
    fn fs_select_request_queue(fs: &mut VirtioFs) {
        fs.write(R_QUEUE_SEL, FS_REQ_QIDX as u64);
    }

    /// Cross-drain witness: a guest that rewrites `used.idx` between two
    /// notifies cannot steer where the fs device records its next completion.
    #[test]
    fn fs_used_index_is_device_owned_across_drains() {
        let dir = tempfile::tempdir().unwrap();
        let qsz = 8u16;
        let (mut fs, avail, used) = fs_drained_once(dir.path(), qsz);
        assert_eq!(fs.mem.rd_u16(used + 2), 1, "first drain published index 1");
        assert_eq!(fs.mem.rd_u32(used + 4), 0, "slot 0 records the first head");

        fs.mem.wr_u16(used + 2, 0);

        fs.mem.wr_u16(avail + 2, 2);
        assert!(fs.process_queue(FS_REQ_QIDX));
        assert_eq!(
            fs.mem.rd_u16(used + 2),
            2,
            "the device republished its own count, not the guest's"
        );
        assert_eq!(
            fs.mem.rd_u32(used + 4),
            0,
            "slot 0 still holds the first completion"
        );
        assert_eq!(
            fs.mem.rd_u32(used + 12),
            2,
            "the second completion landed at the device's next slot"
        );
        assert_eq!(fs.queues[FS_REQ_QIDX].next_used, 2);

        // The pre-migration walk re-read the index per completion, so the same
        // scribble steered its second completion on top of the first.
        let mut fs_ref = fs_dev(dir.path());
        program_fs_queue(&mut fs_ref, FS_REQ_QIDX, qsz, &fs_two_init_chains());
        fs_ref.mem.wr_u16(avail + 2, 1);
        assert!(reference_fs_process_queue(&mut fs_ref, FS_REQ_QIDX));
        fs_ref.mem.wr_u16(used + 2, 0);
        fs_ref.mem.wr_u16(avail + 2, 2);
        assert!(reference_fs_process_queue(&mut fs_ref, FS_REQ_QIDX));
        assert_eq!(
            fs_ref.mem.rd_u16(used + 2),
            1,
            "the retired walk followed the guest's index"
        );
        assert_eq!(
            fs_ref.mem.rd_u32(used + 4),
            2,
            "and overwrote slot 0 with the second head"
        );
    }

    #[test]
    fn fs_queue_ready_zero_rewinds_the_ring_cursors() {
        let dir = tempfile::tempdir().unwrap();
        let (mut fs, avail, used) = fs_drained_once(dir.path(), 8);
        let cursors = |fs: &VirtioFs| {
            (
                fs.queues[FS_REQ_QIDX].last_avail,
                fs.queues[FS_REQ_QIDX].next_used,
            )
        };
        assert_eq!(cursors(&fs), (1, 1), "one chain consumed and completed");

        fs_select_request_queue(&mut fs);
        fs.write(R_QUEUE_READY, 0);
        assert_eq!(fs.queues[FS_REQ_QIDX].ready, 0);
        assert_eq!(
            cursors(&fs),
            (0, 0),
            "detaching the queue rewinds both cursors"
        );

        fs.mem.wr_u16(used + 2, 0);
        fs.mem.wr_u16(avail + 2, 0);
        fs.write(R_QUEUE_READY, 1);
        fs.mem.wr_u16(avail + 2, 1);
        assert!(fs.process_queue(FS_REQ_QIDX));
        assert_eq!(
            fs.mem.rd_u16(used + 2),
            1,
            "completion published at index 1"
        );
        assert_eq!(fs.mem.rd_u32(used + 4), 0, "and recorded at slot 0");
    }

    #[test]
    fn fs_device_reset_rewinds_every_queues_ring_cursors() {
        let dir = tempfile::tempdir().unwrap();
        let (mut fs, _avail, _used) = fs_drained_once(dir.path(), 8);
        // The hiprio queue is never notified by these fixtures; give it cursors
        // of its own so the reset is observed across the whole device.
        fs.queues[0].last_avail = 5;
        fs.queues[0].next_used = 5;

        fs.write(R_STATUS, 0xf);
        assert_eq!(
            (fs.queues[FS_REQ_QIDX].last_avail, fs.queues[0].next_used),
            (1, 5),
            "a non-zero status write leaves the cursors alone"
        );

        fs.write(R_STATUS, 0);
        for (qidx, q) in fs.queues.iter().enumerate() {
            assert_eq!(
                (q.last_avail, q.next_used),
                (0, 0),
                "queue {qidx} not rewound by the device reset"
            );
        }
    }

    #[test]
    fn fs_redundant_queue_ready_write_does_not_rewind_a_live_ring() {
        let dir = tempfile::tempdir().unwrap();
        let (mut fs, avail, used) = fs_drained_once(dir.path(), 8);

        fs_select_request_queue(&mut fs);
        fs.write(R_QUEUE_READY, 1);
        assert_eq!(
            (
                fs.queues[FS_REQ_QIDX].last_avail,
                fs.queues[FS_REQ_QIDX].next_used
            ),
            (1, 1),
            "re-arming an already-ready queue must not rewind it"
        );

        fs.mem.wr_u16(avail + 2, 2);
        assert!(fs.process_queue(FS_REQ_QIDX));
        assert_eq!(fs.mem.rd_u16(used + 2), 2);
        assert_eq!(
            fs.mem.rd_u32(used + 12),
            2,
            "slot 1 records the second chain's head"
        );
    }
}
