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

use super::device_state::{
    DeviceKind, DeviceStateError, SnapshotDeviceState, StateReader, StateWriter,
};
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
const VIRTIO_BLK_T_FLUSH: u32 = 4; // flush the write-back cache
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
/// virtio-blk feature bit 5 (low feature word): the device is read-only. Offered
/// for a read-only backing so the guest mounts it `ro`; writes are also rejected
/// at the device (below), so RO is hypervisor-enforced, not guest-honour-system.
const VIRTIO_BLK_F_RO: u32 = 1 << 5;
/// virtio-blk feature bit 9 (low feature word): the device honours
/// `VIRTIO_BLK_T_FLUSH`. Offered for every writable backing. Without it the
/// guest is entitled to assume a completed write is already durable and never
/// issues a barrier, so ext4's journal ordering rests on an assumption nothing
/// enforces — and a host that dies with dirty page cache loses the filesystem.
const VIRTIO_BLK_F_FLUSH: u32 = 1 << 9;

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

    /// Force everything written so far to stable storage. A RAM-backed or
    /// read-only image has nothing to push, so it succeeds trivially.
    ///
    /// `sync_data` rather than `sync_all`: the guest filesystem's consistency
    /// depends on its own bytes reaching the disk, not on the host's metadata
    /// for a file whose length never changes.
    fn flush(&mut self) -> bool {
        match self {
            Self::Mem(_) => true,
            Self::File {
                read_only: true, ..
            } => true,
            Self::File { file, .. } => file.sync_data().is_ok(),
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
            // for a read-only backing, which takes no writes and so has nothing
            // to flush; VIRTIO_BLK_F_FLUSH for a writable one.
            R_DEVICE_FEATURES if self.device_features_sel == 1 => 1,
            R_DEVICE_FEATURES if self.disk.read_only() => VIRTIO_BLK_F_RO,
            R_DEVICE_FEATURES => VIRTIO_BLK_F_FLUSH,
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
        // A flush carries no data descriptors, so it is serviced here rather
        // than in `transfer`.
        let flushed = req_type != VIRTIO_BLK_T_FLUSH || self.disk.flush();
        let ok = io_ok
            && flushed
            && matches!(
                req_type,
                VIRTIO_BLK_T_IN | VIRTIO_BLK_T_OUT | VIRTIO_BLK_T_FLUSH
            );
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

impl SnapshotDeviceState for VirtioBlk {
    fn device_kind(&self) -> DeviceKind {
        DeviceKind::VirtioBlk
    }

    fn snapshot_state(&self) -> Result<Vec<u8>, DeviceStateError> {
        let mut writer = StateWriter::new(1);
        writer.u32(self.device_features_sel);
        writer.u32(self.driver_features_sel);
        writer.u32(self.status);
        writer.u32(self.queue_num);
        writer.u32(self.queue_ready);
        writer.u64(self.desc);
        writer.u64(self.avail);
        writer.u64(self.used);
        writer.u16(self.last_avail);
        writer.u16(self.next_used);
        writer.u32(self.interrupt_status);
        Ok(writer.finish())
    }

    fn restore_state(&mut self, bytes: &[u8]) -> Result<(), DeviceStateError> {
        let kind = DeviceKind::VirtioBlk;
        let mut reader = StateReader::new(bytes);
        let version = reader.version(kind)?;
        if version != 1 {
            return Err(DeviceStateError::UnsupportedVersion(version));
        }
        let device_features_sel = reader.u32(kind, "device_features_sel")?;
        let driver_features_sel = reader.u32(kind, "driver_features_sel")?;
        let status = reader.u32(kind, "status")?;
        let queue_num = reader.u32(kind, "queue_num")?;
        let queue_ready = reader.u32(kind, "queue_ready")?;
        let desc = reader.u64(kind, "desc")?;
        let avail = reader.u64(kind, "avail")?;
        let used = reader.u64(kind, "used")?;
        let last_avail = reader.u16(kind, "last_avail")?;
        let next_used = reader.u16(kind, "next_used")?;
        let interrupt_status = reader.u32(kind, "interrupt_status")?;
        reader.finish()?;

        if device_features_sel > 1 {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "device_features_sel",
            });
        }
        if driver_features_sel > 1 {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "driver_features_sel",
            });
        }
        if queue_ready > 1 {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "queue_ready",
            });
        }
        if queue_num != 0 && super::validated_queue_size(queue_num).is_none() {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "queue_num",
            });
        }

        self.device_features_sel = device_features_sel;
        self.driver_features_sel = driver_features_sel;
        self.status = status;
        self.queue_num = queue_num;
        self.queue_ready = queue_ready;
        self.desc = desc;
        self.avail = avail;
        self.used = used;
        self.last_avail = last_avail;
        self.next_used = next_used;
        self.interrupt_status = interrupt_status;
        Ok(())
    }
}

// ---- virtio-fs (read-only root) --------------------------------------------

// hiprio (queue 0) + one request queue (queue 1). `num_request_queues` = 1.
// The tag the guest mounts: `mount -t virtiofs mvmroot /`.

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

    /// A block device over freshly-allocated page-aligned scratch RAM. The
    /// virtqueue paths build a `GuestMemoryMmap` over this pointer, which rejects
    /// a non-page-aligned mapping, so the fixture RAM must match production's.
    fn blk_dev(disk: DiskImage) -> VirtioBlk {
        let ram = crate::test_support::page_aligned_ram(RAM_SIZE);
        // SAFETY: page-aligned, zeroed, leaked for the test process lifetime.
        unsafe { VirtioBlk::new(0x0a00_0000, 48, ram.as_mut_ptr(), BLK_BASE, ram.len(), disk) }
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
        // Writable, so the low word carries FLUSH.
        assert_eq!(d.read(R_DEVICE_FEATURES) as u32, VIRTIO_BLK_F_FLUSH);
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
    fn a_writable_backing_offers_the_flush_feature_bit() {
        // Without this bit the guest never issues a barrier, because it is
        // entitled to treat a completed write as already durable.
        let f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().set_len(512).unwrap();
        let mut d = blk_dev(DiskImage::open(f.path(), false).unwrap());
        d.write(R_DEVICE_FEATURES_SEL, 0);
        assert_eq!(
            d.read(R_DEVICE_FEATURES) as u32 & VIRTIO_BLK_F_FLUSH,
            VIRTIO_BLK_F_FLUSH
        );
    }

    #[test]
    fn a_read_only_backing_does_not_offer_flush() {
        // It takes no writes, so it has nothing to push.
        let f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().set_len(512).unwrap();
        let mut d = blk_dev(DiskImage::open(f.path(), true).unwrap());
        d.write(R_DEVICE_FEATURES_SEL, 0);
        assert_eq!(d.read(R_DEVICE_FEATURES) as u32 & VIRTIO_BLK_F_FLUSH, 0);
    }

    #[test]
    fn flushing_a_writable_file_succeeds() {
        let f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().set_len(512).unwrap();
        let mut d = DiskImage::open(f.path(), false).unwrap();
        assert!(d.write_at(0, b"durable"));
        assert!(d.flush(), "a writable backing must be able to sync");
        assert_eq!(&std::fs::read(f.path()).unwrap()[..7], b"durable");
    }

    #[test]
    fn flushing_a_read_only_or_ram_backing_is_a_no_op_that_succeeds() {
        let f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().set_len(512).unwrap();
        assert!(DiskImage::open(f.path(), true).unwrap().flush());
        assert!(DiskImage::mem(vec![0u8; 512]).flush());
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
        // A writable backing offers FLUSH instead, so the guest can force its
        // journal to stable storage.
        let mut w = dev(vec![0u8; 512]);
        w.write(R_DEVICE_FEATURES_SEL, 0);
        assert_eq!(w.read(R_DEVICE_FEATURES) as u32, VIRTIO_BLK_F_FLUSH);
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
                // A flush is header + status by definition: it carries no data.
                (
                    "flush",
                    vec![BlkChain {
                        req_type: VIRTIO_BLK_T_FLUSH,
                        sector: 0,
                        data: Vec::new(),
                        status: true,
                    }],
                ),
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
        let flushed = req_type != VIRTIO_BLK_T_FLUSH || d.disk.flush();
        let ok = io_ok
            && flushed
            && matches!(
                req_type,
                VIRTIO_BLK_T_IN | VIRTIO_BLK_T_OUT | VIRTIO_BLK_T_FLUSH
            );
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
    fn a_flush_request_is_acknowledged_not_refused() {
        // Absolute, not differential: the reference walk mirrors production, so
        // only a concrete status byte proves a flush is actually honoured.
        // Before FLUSH support this returned VIRTIO_BLK_S_IOERR, and ext4 reads
        // a failed barrier as disk failure.
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(4096).unwrap();
        let mut d = blk_dev(DiskImage::open(file.path(), false).unwrap());

        let chains = vec![BlkChain {
            req_type: VIRTIO_BLK_T_FLUSH,
            sector: 0,
            data: Vec::new(),
            status: true,
        }];
        let (avail, _used) = program_blk_queue(&mut d, 2, &chains);
        d.mem.wr_u16(avail + 2, 1);
        assert!(d.process_queue(), "the flush chain must be consumed");

        // Descriptor 1 is the status byte; descriptor 0 is the request header.
        let status_addr = d.rd_u64(BLK_BASE + 0x1000 + 16);
        assert_eq!(d.mem.read_bytes(status_addr, 1)[0], VIRTIO_BLK_S_OK);
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

    #[test]
    fn blk_device_state_roundtrips_control_plane_without_backing_disk() {
        let mut source = blk_dev(DiskImage::mem(vec![0u8; 4096]));
        source.device_features_sel = 1;
        source.driver_features_sel = 1;
        source.status = 7;
        source.queue_num = 8;
        source.queue_ready = 1;
        source.desc = BLK_BASE + 0x1000;
        source.avail = BLK_BASE + 0x2000;
        source.used = BLK_BASE + 0x3000;
        source.last_avail = 9;
        source.next_used = 11;
        source.interrupt_status = 1;
        let state = source.snapshot_state().unwrap();

        let mut target = blk_dev(DiskImage::mem(vec![0u8; 4096]));
        target.restore_state(&state).unwrap();
        assert_eq!(target.device_features_sel, 1);
        assert_eq!(target.driver_features_sel, 1);
        assert_eq!(target.status, 7);
        assert_eq!(target.queue_num, 8);
        assert_eq!(target.queue_ready, 1);
        assert_eq!(
            (target.desc, target.avail, target.used),
            (BLK_BASE + 0x1000, BLK_BASE + 0x2000, BLK_BASE + 0x3000)
        );
        assert_eq!((target.last_avail, target.next_used), (9, 11));
        assert_eq!(target.interrupt_status, 1);
    }

    #[test]
    fn blk_device_state_rejects_an_illegal_queue_size_before_mutation() {
        let mut source = blk_dev(DiskImage::mem(vec![0u8; 4096]));
        source.queue_num = 8;
        let mut state = source.snapshot_state().unwrap();
        state[14..18].copy_from_slice(&3u32.to_le_bytes());

        let mut target = blk_dev(DiskImage::mem(vec![0u8; 4096]));
        assert!(matches!(
            target.restore_state(&state),
            Err(DeviceStateError::InvalidValue {
                kind: DeviceKind::VirtioBlk,
                field: "queue_num"
            })
        ));
        assert_eq!(target.queue_num, 0);
    }
}
