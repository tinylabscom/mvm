//! Portable virtio-balloon device that only accepts free page reports.
//!
//! The guest kernel reports blocks of memory it has freed; the device hands
//! the backing host pages back to the host operating system and then returns
//! the report. The guest may read anything from a reported block afterwards —
//! free page reporting without page poisoning promises it nothing — and in
//! practice reads zeros. The device never asks the guest to inflate (`num_pages` stays
//! zero), so the inflate and deflate queues exist only because the virtio
//! queue numbering requires them.
//!
//! Releasing a page that is mapped into the guest is not enough: the
//! hypervisor holds every range it has mapped, so host advice alone frees
//! nothing. Each releasable span is therefore unmapped from the guest, released
//! on the host, and mapped again — all before the report is acknowledged. The
//! remap cannot be deferred to the next guest fault: two vCPUs faulting on the
//! same span race to remap it, and a fault on an unmapped RAM address is
//! indistinguishable from a device access.
//!
//! The host-side mechanics sit behind [`GuestPageRelease`], so the queue logic
//! here is exercised by unit tests without a hypervisor.

use virtio_queue::{QueueOwnedT, QueueT};

use super::device_state::{
    DeviceKind, DeviceStateError, SnapshotDeviceState, StateReader, StateWriter,
};
use super::guest_mem::GuestMem;
use super::{QueueState, build_split_queue};

const VIRTIO_MAGIC: u32 = 0x7472_6976;
const VIRTIO_VERSION: u32 = 2;
const VIRTIO_ID_BALLOON: u32 = 5;
const VIRTIO_VENDOR: u32 = 0x4d56_4d76;

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
const R_CONFIG_GENERATION: u64 = 0x0fc;
/// `struct virtio_balloon_config`: `num_pages` then `actual`, both le32.
const R_CONFIG_NUM_PAGES: u64 = 0x100;
const R_CONFIG_ACTUAL: u64 = 0x104;

const MMIO_LEN: u64 = 0x200;

/// Feature bits from the virtio-balloon specification. Only the two this
/// device offers, plus the two that shift the reporting queue's index, are
/// named.
pub const F_STATS_VQ: u64 = 1 << 1;
pub const F_DEFLATE_ON_OOM: u64 = 1 << 2;
pub const F_FREE_PAGE_HINT: u64 = 1 << 3;
pub const F_PAGE_REPORTING: u64 = 1 << 5;
/// `VIRTIO_F_VERSION_1`, required of every modern virtio-mmio device.
pub const F_VERSION_1: u64 = 1 << 32;

/// Everything this device offers. Nothing that would add a statistics or
/// hinting queue, so the reporting queue is always index 2 here.
pub const OFFERED_FEATURES: u64 = F_VERSION_1 | F_DEFLATE_ON_OOM | F_PAGE_REPORTING;

const INFLATE_QUEUE: usize = 0;
const DEFLATE_QUEUE: usize = 1;
/// Most queues this device can have: inflate, deflate, reporting.
const MAX_QUEUES: usize = 3;

/// Index of the free page reporting queue under `features`, or `None` when
/// reporting was not negotiated.
///
/// The specification lists five queues — inflate, deflate, stats, free page
/// hint, reporting — but a queue exists only when its feature is negotiated,
/// and the driver numbers the ones that exist consecutively. So reporting is
/// index 2 without the stats and hint features, and moves up one for each of
/// them that is present.
pub fn reporting_queue_index(features: u64) -> Option<usize> {
    if features & F_PAGE_REPORTING == 0 {
        return None;
    }
    let mut index = 2;
    if features & F_STATS_VQ != 0 {
        index += 1;
    }
    if features & F_FREE_PAGE_HINT != 0 {
        index += 1;
    }
    Some(index)
}

/// Number of queues that exist under `features`: inflate and deflate always,
/// then one per optional queue feature.
pub fn queue_count(features: u64) -> usize {
    let optional = [F_STATS_VQ, F_FREE_PAGE_HINT, F_PAGE_REPORTING];
    2 + optional.iter().filter(|bit| features & **bit != 0).count()
}

/// A half-open span of guest-physical address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestSpan {
    pub gpa: u64,
    pub len: u64,
}

impl GuestSpan {
    /// Exclusive end, or `None` if the span wraps the address space.
    fn end(self) -> Option<u64> {
        self.gpa.checked_add(self.len)
    }
}

/// How a span of guest RAM is backed on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RamBacking {
    /// Demand-zero anonymous memory. Releasing it drops the host pages; the
    /// guest reads zeros if it touches the span again.
    Anonymous,
    /// A private copy-on-write mapping of a file (a kernel image, or a
    /// restored guest's RAM, mapped from that restore's own private clone of
    /// the snapshot). Never released: the pages the guest has not written are
    /// the file's page cache, so dropping them frees nothing the host can keep.
    ///
    /// Known limit: nothing reclaims the pages the guest *did* write either.
    /// Those are private anonymous copies, but releasing one here would make
    /// the span read back as the file's bytes rather than zeros, and no
    /// component owns that mapping's lifecycle to remap it safely. So a
    /// restored guest's freed memory is not returned to the host until the
    /// guest stops.
    PrivateFile,
}

/// One contiguous piece of guest RAM with a single host backing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamRegion {
    pub span: GuestSpan,
    pub backing: RamBacking,
}

/// Why a host-side step of a release failed. Carries the backend's native
/// return code for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageReleaseError {
    pub code: i64,
}

/// The host side of returning guest pages: how guest RAM is laid out, and the
/// three steps that release a span of it.
///
/// The device calls the steps in a fixed order for every span —
/// [`unmap`](Self::unmap), [`release`](Self::release), [`remap`](Self::remap)
/// — and acknowledges the report only after the last of them. Every span it
/// passes lies inside one [`RamBacking::Anonymous`] region from
/// [`regions`](Self::regions) and is aligned to [`granule`](Self::granule).
pub trait GuestPageRelease {
    /// Host page size the hypervisor maps at; spans are shrunk to it.
    fn granule(&self) -> u64;
    /// Guest RAM, split by host backing.
    fn regions(&self) -> &[RamRegion];
    /// Whether any host page behind the span is resident. A span the guest
    /// never touched has nothing to give back, and a freshly booted guest
    /// reports nearly all of its memory, so this keeps boot from paying three
    /// hypervisor calls per block for no reclaim. When unsure, answer `true`.
    fn resident(&self, span: GuestSpan) -> bool;
    /// Remove the span from the guest's memory map.
    fn unmap(&mut self, span: GuestSpan) -> Result<(), PageReleaseError>;
    /// Tell the host the span's pages are free.
    fn release(&mut self, span: GuestSpan) -> Result<(), PageReleaseError>;
    /// Put the span back into the guest's memory map.
    fn remap(&mut self, span: GuestSpan) -> Result<(), PageReleaseError>;
}

/// The spans of `reported` that can be released: each reported range cut to
/// the anonymous regions it overlaps, shrunk inward to `granule`, and merged
/// where adjacent within one region.
///
/// Empty, wrapping, and out-of-bounds ranges contribute nothing, as do the
/// parts of a range that fall in a private file mapping or between regions.
pub fn releasable_spans(
    reported: &[GuestSpan],
    regions: &[RamRegion],
    granule: u64,
) -> Vec<GuestSpan> {
    if granule == 0 || !granule.is_power_of_two() {
        return Vec::new();
    }
    let mut spans = Vec::new();
    for region in regions
        .iter()
        .filter(|region| region.backing == RamBacking::Anonymous)
    {
        let Some(region_end) = region.span.end() else {
            continue;
        };
        let mut pieces: Vec<GuestSpan> = reported
            .iter()
            .filter_map(|range| {
                let end = range.end()?.min(region_end);
                let start = range.gpa.max(region.span.gpa);
                let start = start.checked_next_multiple_of(granule)?;
                let end = end - end % granule;
                (start < end).then(|| GuestSpan {
                    gpa: start,
                    len: end - start,
                })
            })
            .collect();
        pieces.sort_by_key(|span| span.gpa);
        spans.extend(merge_adjacent(pieces));
    }
    spans
}

/// Merge sorted spans that touch or overlap. A guest may report the same block
/// twice; releasing it once is enough.
fn merge_adjacent(sorted: Vec<GuestSpan>) -> Vec<GuestSpan> {
    let mut merged: Vec<GuestSpan> = Vec::with_capacity(sorted.len());
    for span in sorted {
        if let Some(last) = merged.last_mut() {
            let last_end = last.gpa + last.len;
            if span.gpa <= last_end {
                last.len = last_end.max(span.gpa + span.len) - last.gpa;
                continue;
            }
        }
        merged.push(span);
    }
    merged
}

/// Outcome of releasing the spans of one report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportOutcome {
    /// Every span is mapped into the guest again; the report may be returned.
    Settled,
    /// A span could not be remapped. The guest must not get the report back:
    /// its pages stay withheld from the guest allocator, which is the only
    /// way to keep the guest off an address that no longer has memory behind
    /// it.
    Unmapped,
}

/// A virtio-mmio balloon that returns freed guest memory to the host.
pub struct VirtioBalloon {
    base: u64,
    irq: u32,
    mem: GuestMem,
    pages: Box<dyn GuestPageRelease>,
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: u64,
    status: u32,
    queue_sel: u32,
    queues: [QueueState; MAX_QUEUES],
    interrupt_status: u32,
    /// The guest's `actual` config field. Stored and read back, never acted on:
    /// this device never asks for pages.
    actual: u32,
    /// Set once a span could not be remapped. From then on no queue is
    /// serviced, so nothing the guest reports can reach a hole in its RAM.
    unmapped: bool,
}

impl VirtioBalloon {
    /// Create a device over externally owned guest RAM.
    ///
    /// # Safety
    ///
    /// `ram` must point to `ram_size` bytes mapped as guest RAM at `ram_base`,
    /// and that mapping must remain valid for this device's lifetime.
    pub unsafe fn new(
        base: u64,
        irq: u32,
        ram: *mut u8,
        ram_base: u64,
        ram_size: usize,
        pages: Box<dyn GuestPageRelease>,
    ) -> Self {
        // SAFETY: forwarded from this function's contract.
        let mem = unsafe { GuestMem::new(ram, ram_base, ram_size) };
        Self::with_memory(base, irq, mem, pages)
    }

    fn with_memory(base: u64, irq: u32, mem: GuestMem, pages: Box<dyn GuestPageRelease>) -> Self {
        Self {
            base,
            irq,
            mem,
            pages,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: 0,
            status: 0,
            queue_sel: 0,
            queues: [QueueState::default(); MAX_QUEUES],
            interrupt_status: 0,
            actual: 0,
            unmapped: false,
        }
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn irq(&self) -> u32 {
        self.irq
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + MMIO_LEN
    }

    /// Features both sides agreed on. A driver cannot enable a bit the device
    /// never offered.
    fn negotiated(&self) -> u64 {
        self.driver_features & OFFERED_FEATURES
    }

    /// The selected queue, if it exists under the negotiated features.
    fn selected(&self) -> Option<usize> {
        let index = usize::try_from(self.queue_sel).ok()?;
        (index < queue_count(self.negotiated()).min(MAX_QUEUES)).then_some(index)
    }

    /// Handle a virtio-mmio register read.
    pub fn read(&self, offset: u64) -> u64 {
        let page = |features: u64, sel: u32| match sel {
            0 => features as u32,
            1 => (features >> 32) as u32,
            _ => 0,
        };
        u64::from(match offset {
            R_MAGIC => VIRTIO_MAGIC,
            R_VERSION => VIRTIO_VERSION,
            R_DEVICE_ID => VIRTIO_ID_BALLOON,
            R_VENDOR_ID => VIRTIO_VENDOR,
            R_DEVICE_FEATURES => page(OFFERED_FEATURES, self.device_features_sel),
            // A queue that does not exist reports a maximum size of zero,
            // which is how the driver learns it is absent.
            R_QUEUE_NUM_MAX if self.selected().is_some() => super::QUEUE_SIZE_MAX,
            R_QUEUE_READY => self.selected().map_or(0, |index| self.queues[index].ready),
            R_INTERRUPT_STATUS => self.interrupt_status,
            R_STATUS => self.status,
            R_CONFIG_GENERATION => 0,
            R_CONFIG_NUM_PAGES => 0,
            R_CONFIG_ACTUAL => self.actual,
            _ => 0,
        })
    }

    /// Handle a virtio-mmio register write. Returns `true` when an interrupt
    /// should be raised because at least one buffer was returned.
    pub fn write(&mut self, offset: u64, value: u64) -> bool {
        let value = value as u32;
        match offset {
            R_DEVICE_FEATURES_SEL => self.device_features_sel = value,
            R_DRIVER_FEATURES_SEL => self.driver_features_sel = value,
            R_DRIVER_FEATURES => self.set_driver_features(value),
            R_QUEUE_SEL => self.queue_sel = value,
            R_STATUS => {
                self.status = value;
                if value == 0 {
                    self.reset();
                }
            }
            R_INTERRUPT_ACK => self.interrupt_status &= !value,
            R_CONFIG_ACTUAL => self.actual = value,
            R_QUEUE_NOTIFY => return self.notify(value),
            _ => self.write_queue_register(offset, value),
        }
        false
    }

    fn set_driver_features(&mut self, value: u32) {
        let value = u64::from(value);
        self.driver_features = match self.driver_features_sel {
            0 => (self.driver_features & !0xffff_ffff) | value,
            1 => (self.driver_features & 0xffff_ffff) | (value << 32),
            _ => self.driver_features,
        };
    }

    fn write_queue_register(&mut self, offset: u64, value: u32) {
        let Some(index) = self.selected() else {
            return;
        };
        let queue = &mut self.queues[index];
        match offset {
            R_QUEUE_NUM => queue.num = value,
            R_QUEUE_READY => {
                queue.ready = value;
                if value == 0 {
                    queue.rewind_cursors();
                }
            }
            R_QUEUE_DESC_LO => set_lo(&mut queue.desc, value),
            R_QUEUE_DESC_HI => set_hi(&mut queue.desc, value),
            R_QUEUE_DRIVER_LO => set_lo(&mut queue.avail, value),
            R_QUEUE_DRIVER_HI => set_hi(&mut queue.avail, value),
            R_QUEUE_DEVICE_LO => set_lo(&mut queue.used, value),
            R_QUEUE_DEVICE_HI => set_hi(&mut queue.used, value),
            _ => {}
        }
    }

    /// A device reset returns every queue and the negotiated features to their
    /// pre-initialization state.
    fn reset(&mut self) {
        self.queues = [QueueState::default(); MAX_QUEUES];
        self.driver_features = 0;
        self.driver_features_sel = 0;
        self.device_features_sel = 0;
        self.queue_sel = 0;
        self.interrupt_status = 0;
        self.actual = 0;
    }

    fn notify(&mut self, queue: u32) -> bool {
        if self.unmapped {
            return false;
        }
        let Ok(index) = usize::try_from(queue) else {
            return false;
        };
        if index >= queue_count(self.negotiated()).min(MAX_QUEUES) {
            return false;
        }
        if Some(index) == reporting_queue_index(self.negotiated()) {
            self.service_reports(index)
        } else if index == INFLATE_QUEUE || index == DEFLATE_QUEUE {
            // Never requested, so there is nothing to act on. Returned rather
            // than ignored so a driver that posts anyway does not wait forever.
            self.return_unread(index)
        } else {
            false
        }
    }

    /// Return every available buffer on `index` without acting on it.
    fn return_unread(&mut self, index: usize) -> bool {
        self.drain(index, |_, _| true)
    }

    /// Release the memory in every available report, returning each report
    /// only once its memory is mapped into the guest again.
    fn service_reports(&mut self, index: usize) -> bool {
        self.drain(index, |pages, reported| {
            release_report(pages, reported) == ReportOutcome::Settled
        })
    }

    /// Walk the available ring of queue `index`, hand each chain's buffers to
    /// `settle`, and return to the guest every chain `settle` accepts. Stops
    /// servicing the device at the first chain it refuses.
    fn drain(
        &mut self,
        index: usize,
        mut settle: impl FnMut(&mut dyn GuestPageRelease, &[GuestSpan]) -> bool,
    ) -> bool {
        let state = self.queues[index];
        if state.ready == 0 {
            return false;
        }
        let Some(size) = super::validated_queue_size(state.num) else {
            return false;
        };
        let Some(mem) = self.mem.guest_memory() else {
            return false;
        };
        let Some(mut queue) = build_split_queue(state.ring(), size) else {
            return false;
        };

        let mut chains = Vec::new();
        {
            let Ok(available) = queue.iter(&mem) else {
                return false;
            };
            for chain in available {
                let head = chain.head_index();
                let buffers: Vec<GuestSpan> = chain
                    .map(|descriptor| GuestSpan {
                        gpa: descriptor.addr().0,
                        len: u64::from(descriptor.len()),
                    })
                    .collect();
                chains.push((head, buffers));
            }
        }

        let mut returned = false;
        for (head, buffers) in chains {
            if !settle(self.pages.as_mut(), &buffers) {
                self.unmapped = true;
                break;
            }
            // Nothing is written into a report, so the used length is zero.
            if queue.add_used(&mem, head, 0).is_ok() {
                returned = true;
            }
        }
        self.queues[index].last_avail = queue.next_avail();
        self.queues[index].next_used = queue.next_used();
        if returned {
            self.interrupt_status |= 1;
        }
        returned
    }
}

/// Release every releasable span of one report, in the order the hypervisor
/// requires.
fn release_report(pages: &mut dyn GuestPageRelease, reported: &[GuestSpan]) -> ReportOutcome {
    let spans = releasable_spans(reported, pages.regions(), pages.granule());
    for span in spans {
        if release_span(pages, span) == ReportOutcome::Unmapped {
            return ReportOutcome::Unmapped;
        }
    }
    ReportOutcome::Settled
}

/// Unmap, release, and remap one span.
///
/// A span with no resident host pages is skipped outright. A failed unmap leaves the span mapped and untouched, so it is skipped. A
/// failed release leaves the pages resident, which is wasteful but correct, so
/// the span is still remapped. A remap is retried once; if it still fails the
/// span has no memory behind it and the report must not be returned.
fn release_span(pages: &mut dyn GuestPageRelease, span: GuestSpan) -> ReportOutcome {
    if !pages.resident(span) || pages.unmap(span).is_err() {
        return ReportOutcome::Settled;
    }
    let _ = pages.release(span);
    if pages.remap(span).is_ok() || pages.remap(span).is_ok() {
        ReportOutcome::Settled
    } else {
        ReportOutcome::Unmapped
    }
}

impl SnapshotDeviceState for VirtioBalloon {
    fn device_kind(&self) -> DeviceKind {
        DeviceKind::VirtioBalloon
    }

    fn snapshot_state(&self) -> Result<Vec<u8>, DeviceStateError> {
        let mut writer = StateWriter::new(1);
        writer.u32(self.device_features_sel);
        writer.u32(self.driver_features_sel);
        writer.u64(self.driver_features);
        writer.u32(self.status);
        writer.u32(self.queue_sel);
        writer.u32(self.interrupt_status);
        writer.u32(self.actual);
        for queue in &self.queues {
            writer.u32(queue.num);
            writer.u32(queue.ready);
            writer.u64(queue.desc);
            writer.u64(queue.avail);
            writer.u64(queue.used);
            writer.u16(queue.last_avail);
            writer.u16(queue.next_used);
        }
        Ok(writer.finish())
    }

    fn restore_state(&mut self, bytes: &[u8]) -> Result<(), DeviceStateError> {
        let kind = DeviceKind::VirtioBalloon;
        let mut reader = StateReader::new(bytes);
        let version = reader.version(kind)?;
        if version != 1 {
            return Err(DeviceStateError::UnsupportedVersion(version));
        }
        let device_features_sel = reader.u32(kind, "device_features_sel")?;
        let driver_features_sel = reader.u32(kind, "driver_features_sel")?;
        let driver_features = reader.u64(kind, "driver_features")?;
        let status = reader.u32(kind, "status")?;
        let queue_sel = reader.u32(kind, "queue_sel")?;
        let interrupt_status = reader.u32(kind, "interrupt_status")?;
        let actual = reader.u32(kind, "actual")?;
        let mut queues = [QueueState::default(); MAX_QUEUES];
        for queue in &mut queues {
            *queue = QueueState {
                num: reader.u32(kind, "queue_num")?,
                ready: reader.u32(kind, "queue_ready")?,
                desc: reader.u64(kind, "queue_desc")?,
                avail: reader.u64(kind, "queue_avail")?,
                used: reader.u64(kind, "queue_used")?,
                last_avail: reader.u16(kind, "queue_last_avail")?,
                next_used: reader.u16(kind, "queue_next_used")?,
            };
        }
        reader.finish()?;

        let invalid = |field| DeviceStateError::InvalidValue { kind, field };
        if device_features_sel > 1 {
            return Err(invalid("device_features_sel"));
        }
        if driver_features_sel > 1 {
            return Err(invalid("driver_features_sel"));
        }
        if driver_features & !OFFERED_FEATURES != 0 {
            return Err(invalid("driver_features"));
        }
        if usize::try_from(queue_sel).map_or(true, |index| index >= MAX_QUEUES) {
            return Err(invalid("queue_sel"));
        }
        for queue in &queues {
            if queue.ready > 1 {
                return Err(invalid("queue_ready"));
            }
            if queue.num != 0 && super::validated_queue_size(queue.num).is_none() {
                return Err(invalid("queue_num"));
            }
        }

        self.device_features_sel = device_features_sel;
        self.driver_features_sel = driver_features_sel;
        self.driver_features = driver_features;
        self.status = status;
        self.queue_sel = queue_sel;
        self.interrupt_status = interrupt_status;
        self.actual = actual;
        self.queues = queues;
        Ok(())
    }
}

fn set_lo(word: &mut u64, value: u32) {
    *word = (*word & 0xffff_ffff_0000_0000) | u64::from(value);
}

fn set_hi(word: &mut u64, value: u32) {
    *word = (*word & 0x0000_0000_ffff_ffff) | (u64::from(value) << 32);
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    const RAM_BASE: u64 = 0x4000_0000;
    const RAM_SIZE: usize = 0x20_0000;
    const DEVICE_BASE: u64 = 0x0a00_2200;
    const IRQ: u32 = 65;
    const DESC: u64 = RAM_BASE + 0x1000;
    const AVAIL: u64 = RAM_BASE + 0x2000;
    const USED: u64 = RAM_BASE + 0x3000;
    const DESC_F_NEXT: u16 = 1;
    const DESC_F_WRITE: u16 = 2;
    const GRANULE: u64 = 0x4000;
    /// Reported blocks live well above the rings, in a guest-physical window
    /// the fake treats as RAM without the test having to allocate it.
    const REPORT_BASE: u64 = 0x8000_0000;
    const BLOCK: u64 = 0x20_0000;

    /// One step the device asked the host to take.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Step {
        Unmap(GuestSpan),
        Release(GuestSpan),
        Remap(GuestSpan),
    }

    /// Records every host step, and lets a test fail a chosen one.
    #[derive(Default)]
    struct Journal {
        steps: Vec<Step>,
        fail_unmap: bool,
        fail_release: bool,
        /// Spans the fake reports as never touched.
        untouched: Vec<GuestSpan>,
        remap_failures: usize,
    }

    struct FakePages {
        regions: Vec<RamRegion>,
        journal: Rc<RefCell<Journal>>,
    }

    impl GuestPageRelease for FakePages {
        fn granule(&self) -> u64 {
            GRANULE
        }
        fn regions(&self) -> &[RamRegion] {
            &self.regions
        }
        fn resident(&self, span: GuestSpan) -> bool {
            !self.journal.borrow().untouched.contains(&span)
        }
        fn unmap(&mut self, span: GuestSpan) -> Result<(), PageReleaseError> {
            let mut journal = self.journal.borrow_mut();
            journal.steps.push(Step::Unmap(span));
            if journal.fail_unmap {
                return Err(PageReleaseError { code: -1 });
            }
            Ok(())
        }
        fn release(&mut self, span: GuestSpan) -> Result<(), PageReleaseError> {
            let mut journal = self.journal.borrow_mut();
            journal.steps.push(Step::Release(span));
            if journal.fail_release {
                return Err(PageReleaseError { code: -2 });
            }
            Ok(())
        }
        fn remap(&mut self, span: GuestSpan) -> Result<(), PageReleaseError> {
            let mut journal = self.journal.borrow_mut();
            journal.steps.push(Step::Remap(span));
            if journal.remap_failures > 0 {
                journal.remap_failures -= 1;
                return Err(PageReleaseError { code: -3 });
            }
            Ok(())
        }
    }

    fn span(gpa: u64, len: u64) -> GuestSpan {
        GuestSpan { gpa, len }
    }

    fn anonymous(gpa: u64, len: u64) -> RamRegion {
        RamRegion {
            span: span(gpa, len),
            backing: RamBacking::Anonymous,
        }
    }

    fn file(gpa: u64, len: u64) -> RamRegion {
        RamRegion {
            span: span(gpa, len),
            backing: RamBacking::PrivateFile,
        }
    }

    /// The layout most tests use: 1 GiB of anonymous RAM at `REPORT_BASE`.
    fn default_regions() -> Vec<RamRegion> {
        vec![anonymous(REPORT_BASE, 0x4000_0000)]
    }

    fn device(regions: Vec<RamRegion>) -> (VirtioBalloon, Rc<RefCell<Journal>>) {
        let journal = Rc::new(RefCell::new(Journal::default()));
        let pages = FakePages {
            regions,
            journal: Rc::clone(&journal),
        };
        let ram = crate::test_support::page_aligned_ram(RAM_SIZE);
        // SAFETY: the page-aligned leaked allocation remains valid for the test
        // process lifetime and is mapped at RAM_BASE in the device view.
        let mem = unsafe { GuestMem::new(ram.as_mut_ptr(), RAM_BASE, ram.len()) };
        (
            VirtioBalloon::with_memory(DEVICE_BASE, IRQ, mem, Box::new(pages)),
            journal,
        )
    }

    fn negotiate(device: &mut VirtioBalloon, features: u64) {
        device.write(R_DRIVER_FEATURES_SEL, 0);
        device.write(R_DRIVER_FEATURES, features & 0xffff_ffff);
        device.write(R_DRIVER_FEATURES_SEL, 1);
        device.write(R_DRIVER_FEATURES, features >> 32);
    }

    fn write_descriptor(device: &VirtioBalloon, index: u16, buffer: GuestSpan, next: Option<u16>) {
        let at = DESC + u64::from(index) * 16;
        let flags = DESC_F_WRITE | if next.is_some() { DESC_F_NEXT } else { 0 };
        let len = u32::try_from(buffer.len).expect("test buffers fit a descriptor");
        device.mem.write_bytes(at, &buffer.gpa.to_le_bytes());
        device.mem.write_bytes(at + 8, &len.to_le_bytes());
        device.mem.write_bytes(at + 12, &flags.to_le_bytes());
        device
            .mem
            .write_bytes(at + 14, &next.unwrap_or(0).to_le_bytes());
    }

    /// Program queue `index` and make one chain per entry of `chains`
    /// available on it, each chain one descriptor per buffer.
    fn post(device: &mut VirtioBalloon, index: u32, chains: &[&[GuestSpan]]) {
        let mut slot = 0u16;
        for (position, chain) in chains.iter().enumerate() {
            device.mem.wr_u16(AVAIL + 4 + 2 * position as u64, slot);
            for (offset, buffer) in chain.iter().enumerate() {
                let is_last = offset + 1 == chain.len();
                let next = (!is_last).then_some(slot + 1);
                write_descriptor(device, slot, *buffer, next);
                slot += 1;
            }
        }
        device.mem.wr_u16(AVAIL + 2, chains.len() as u16);
        device.write(R_QUEUE_SEL, u64::from(index));
        device.write(R_QUEUE_NUM, 64);
        device.write(R_QUEUE_DESC_LO, DESC);
        device.write(R_QUEUE_DRIVER_LO, AVAIL);
        device.write(R_QUEUE_DEVICE_LO, USED);
        device.write(R_QUEUE_READY, 1);
    }

    /// A device with reporting negotiated and `chains` posted on the reporting
    /// queue.
    fn reporting(
        regions: Vec<RamRegion>,
        chains: &[&[GuestSpan]],
    ) -> (VirtioBalloon, Rc<RefCell<Journal>>) {
        let (mut device, journal) = device(regions);
        negotiate(&mut device, OFFERED_FEATURES);
        post(&mut device, 2, chains);
        (device, journal)
    }

    fn used_count(device: &VirtioBalloon) -> u16 {
        device.mem.rd_u16(USED + 2)
    }

    fn steps(journal: &Rc<RefCell<Journal>>) -> Vec<Step> {
        journal.borrow().steps.clone()
    }

    #[test]
    fn identifies_as_a_modern_balloon_offering_only_reporting_and_deflate_on_oom() {
        let (mut device, _) = device(default_regions());
        assert_eq!(device.read(R_MAGIC), u64::from(VIRTIO_MAGIC));
        assert_eq!(device.read(R_VERSION), u64::from(VIRTIO_VERSION));
        assert_eq!(device.read(R_DEVICE_ID), u64::from(VIRTIO_ID_BALLOON));
        assert_eq!(
            device.read(R_DEVICE_FEATURES),
            F_DEFLATE_ON_OOM | F_PAGE_REPORTING
        );
        device.write(R_DEVICE_FEATURES_SEL, 1);
        assert_eq!(device.read(R_DEVICE_FEATURES), 1, "VERSION_1 is bit 32");
        assert_eq!(device.read(R_CONFIG_NUM_PAGES), 0, "never asks for pages");
    }

    #[test]
    fn reporting_queue_index_follows_the_negotiated_optional_queues() {
        assert_eq!(reporting_queue_index(0), None);
        assert_eq!(reporting_queue_index(F_DEFLATE_ON_OOM), None);
        assert_eq!(reporting_queue_index(F_PAGE_REPORTING), Some(2));
        assert_eq!(reporting_queue_index(OFFERED_FEATURES), Some(2));
        assert_eq!(
            reporting_queue_index(F_PAGE_REPORTING | F_STATS_VQ),
            Some(3)
        );
        assert_eq!(
            reporting_queue_index(F_PAGE_REPORTING | F_FREE_PAGE_HINT),
            Some(3)
        );
        assert_eq!(
            reporting_queue_index(F_PAGE_REPORTING | F_STATS_VQ | F_FREE_PAGE_HINT),
            Some(4)
        );
        assert_eq!(queue_count(0), 2);
        assert_eq!(queue_count(OFFERED_FEATURES), 3);
        assert_eq!(
            queue_count(F_STATS_VQ | F_FREE_PAGE_HINT | F_PAGE_REPORTING),
            5
        );
    }

    #[test]
    fn the_reporting_queue_exists_only_once_reporting_is_negotiated() {
        let (mut device, _) = device(default_regions());
        device.write(R_QUEUE_SEL, 2);
        assert_eq!(device.read(R_QUEUE_NUM_MAX), 0, "absent before negotiation");
        device.write(R_QUEUE_SEL, 1);
        assert_eq!(
            device.read(R_QUEUE_NUM_MAX),
            u64::from(super::super::QUEUE_SIZE_MAX)
        );

        negotiate(&mut device, OFFERED_FEATURES);
        device.write(R_QUEUE_SEL, 2);
        assert_eq!(
            device.read(R_QUEUE_NUM_MAX),
            u64::from(super::super::QUEUE_SIZE_MAX)
        );
        device.write(R_QUEUE_SEL, 3);
        assert_eq!(device.read(R_QUEUE_NUM_MAX), 0, "no stats or hint queue");
    }

    #[test]
    fn a_driver_cannot_negotiate_a_feature_that_was_not_offered() {
        let (mut device, journal) = device(default_regions());
        // Stats would move reporting to index 3. The device never offered it,
        // so reporting stays at 2 and queue 3 stays absent.
        negotiate(&mut device, OFFERED_FEATURES | F_STATS_VQ);
        device.write(R_QUEUE_SEL, 3);
        assert_eq!(device.read(R_QUEUE_NUM_MAX), 0);
        post(&mut device, 2, &[&[span(REPORT_BASE, BLOCK)]]);
        assert!(device.write(R_QUEUE_NOTIFY, 2));
        assert_eq!(steps(&journal).len(), 3);
    }

    #[test]
    fn a_report_is_unmapped_released_and_remapped_before_it_is_returned() {
        let block = span(REPORT_BASE, BLOCK);
        let (mut device, journal) = reporting(default_regions(), &[&[block]]);

        assert!(device.write(R_QUEUE_NOTIFY, 2));

        assert_eq!(
            steps(&journal),
            vec![Step::Unmap(block), Step::Release(block), Step::Remap(block)]
        );
        assert_eq!(used_count(&device), 1, "returned after the remap");
        assert_eq!(device.mem.rd_u32(USED + 4), 0, "head of the only chain");
        assert_eq!(
            device.mem.rd_u32(USED + 8),
            0,
            "nothing written into a report"
        );
        assert_eq!(device.read(R_INTERRUPT_STATUS), 1);
    }

    #[test]
    fn every_buffer_of_a_chain_is_released_before_the_chain_is_returned() {
        let first = span(REPORT_BASE, BLOCK);
        let second = span(REPORT_BASE + 4 * BLOCK, BLOCK);
        let (mut device, journal) = reporting(default_regions(), &[&[first, second]]);

        assert!(device.write(R_QUEUE_NOTIFY, 2));

        assert_eq!(
            steps(&journal),
            vec![
                Step::Unmap(first),
                Step::Release(first),
                Step::Remap(first),
                Step::Unmap(second),
                Step::Release(second),
                Step::Remap(second),
            ]
        );
        assert_eq!(used_count(&device), 1);
    }

    #[test]
    fn adjacent_buffers_are_released_as_one_span() {
        let (mut device, journal) = reporting(
            default_regions(),
            &[&[
                span(REPORT_BASE + BLOCK, BLOCK),
                span(REPORT_BASE, BLOCK),
                span(REPORT_BASE, BLOCK),
            ]],
        );
        assert!(device.write(R_QUEUE_NOTIFY, 2));
        let merged = span(REPORT_BASE, 2 * BLOCK);
        assert_eq!(
            steps(&journal),
            vec![
                Step::Unmap(merged),
                Step::Release(merged),
                Step::Remap(merged)
            ]
        );
    }

    #[test]
    fn misaligned_ranges_shrink_inward_to_the_host_granule() {
        let reported = span(REPORT_BASE + 0x1000, 3 * GRANULE);
        let spans = releasable_spans(&[reported], &default_regions(), GRANULE);
        assert_eq!(spans, vec![span(REPORT_BASE + GRANULE, 2 * GRANULE)]);

        // Smaller than a granule once aligned: nothing to release, but the
        // report is still returned.
        let tiny = span(REPORT_BASE + 0x1000, GRANULE);
        let (mut device, journal) = reporting(default_regions(), &[&[tiny]]);
        assert!(device.write(R_QUEUE_NOTIFY, 2));
        assert!(steps(&journal).is_empty());
        assert_eq!(used_count(&device), 1);
    }

    #[test]
    fn out_of_bounds_ranges_release_only_the_part_inside_ram() {
        let regions = vec![anonymous(REPORT_BASE, 4 * BLOCK)];
        let below = span(REPORT_BASE - BLOCK, 2 * BLOCK);
        let above = span(REPORT_BASE + 3 * BLOCK, 2 * BLOCK);
        let outside = span(REPORT_BASE + 8 * BLOCK, BLOCK);
        assert_eq!(
            releasable_spans(&[below, above, outside], &regions, GRANULE),
            vec![
                span(REPORT_BASE, BLOCK),
                span(REPORT_BASE + 3 * BLOCK, BLOCK)
            ]
        );

        let (mut device, journal) = reporting(regions, &[&[outside]]);
        assert!(device.write(R_QUEUE_NOTIFY, 2));
        assert!(steps(&journal).is_empty());
        assert_eq!(
            used_count(&device),
            1,
            "returned even though nothing was freed"
        );
    }

    #[test]
    fn a_range_that_wraps_the_address_space_is_ignored() {
        let wrapping = span(u64::MAX - GRANULE + 1, 2 * GRANULE);
        let regions = vec![anonymous(0, u64::MAX)];
        assert!(releasable_spans(&[wrapping], &regions, GRANULE).is_empty());
    }

    #[test]
    fn zero_length_ranges_release_nothing() {
        let (mut device, journal) = reporting(default_regions(), &[&[span(REPORT_BASE, 0)]]);
        assert!(device.write(R_QUEUE_NOTIFY, 2));
        assert!(steps(&journal).is_empty());
        assert_eq!(used_count(&device), 1);
    }

    #[test]
    fn a_range_straddling_two_regions_is_released_per_region() {
        // Two anonymous regions that are adjacent in guest-physical space but
        // need not be adjacent on the host, so they must never share a span.
        let regions = vec![
            anonymous(REPORT_BASE, 2 * BLOCK),
            anonymous(REPORT_BASE + 2 * BLOCK, 2 * BLOCK),
        ];
        let straddling = span(REPORT_BASE + BLOCK, 2 * BLOCK);
        assert_eq!(
            releasable_spans(&[straddling], &regions, GRANULE),
            vec![
                span(REPORT_BASE + BLOCK, BLOCK),
                span(REPORT_BASE + 2 * BLOCK, BLOCK)
            ]
        );
    }

    #[test]
    fn private_file_mappings_are_skipped_and_the_report_still_returned() {
        let regions = vec![
            anonymous(REPORT_BASE, BLOCK),
            file(REPORT_BASE + BLOCK, BLOCK),
            anonymous(REPORT_BASE + 2 * BLOCK, BLOCK),
        ];
        let straddling = span(REPORT_BASE, 3 * BLOCK);
        let (mut device, journal) = reporting(regions, &[&[straddling]]);

        assert!(device.write(R_QUEUE_NOTIFY, 2));

        let first = span(REPORT_BASE, BLOCK);
        let last = span(REPORT_BASE + 2 * BLOCK, BLOCK);
        assert_eq!(
            steps(&journal),
            vec![
                Step::Unmap(first),
                Step::Release(first),
                Step::Remap(first),
                Step::Unmap(last),
                Step::Release(last),
                Step::Remap(last),
            ],
            "the file-backed block in the middle is never touched"
        );
        assert_eq!(used_count(&device), 1);
    }

    #[test]
    fn a_report_entirely_in_a_file_mapping_is_returned_untouched() {
        let regions = vec![file(REPORT_BASE, 4 * BLOCK)];
        let (mut device, journal) = reporting(regions, &[&[span(REPORT_BASE, BLOCK)]]);
        assert!(device.write(R_QUEUE_NOTIFY, 2));
        assert!(steps(&journal).is_empty());
        assert_eq!(used_count(&device), 1);
    }

    #[test]
    fn a_span_with_nothing_resident_is_returned_without_touching_the_hypervisor() {
        let untouched = span(REPORT_BASE, BLOCK);
        let touched = span(REPORT_BASE + 2 * BLOCK, BLOCK);
        let (mut device, journal) = reporting(default_regions(), &[&[untouched, touched]]);
        journal.borrow_mut().untouched.push(untouched);

        assert!(device.write(R_QUEUE_NOTIFY, 2));

        assert_eq!(
            steps(&journal),
            vec![
                Step::Unmap(touched),
                Step::Release(touched),
                Step::Remap(touched)
            ]
        );
        assert_eq!(used_count(&device), 1);
    }

    #[test]
    fn a_failed_unmap_skips_the_span_and_still_returns_the_report() {
        let block = span(REPORT_BASE, BLOCK);
        let (mut device, journal) = reporting(default_regions(), &[&[block]]);
        journal.borrow_mut().fail_unmap = true;

        assert!(device.write(R_QUEUE_NOTIFY, 2));

        assert_eq!(steps(&journal), vec![Step::Unmap(block)]);
        assert_eq!(used_count(&device), 1);
    }

    #[test]
    fn a_failed_release_still_remaps_before_returning() {
        let block = span(REPORT_BASE, BLOCK);
        let (mut device, journal) = reporting(default_regions(), &[&[block]]);
        journal.borrow_mut().fail_release = true;

        assert!(device.write(R_QUEUE_NOTIFY, 2));

        assert_eq!(
            steps(&journal),
            vec![Step::Unmap(block), Step::Release(block), Step::Remap(block)]
        );
        assert_eq!(used_count(&device), 1);
    }

    #[test]
    fn a_remap_is_retried_once() {
        let block = span(REPORT_BASE, BLOCK);
        let (mut device, journal) = reporting(default_regions(), &[&[block]]);
        journal.borrow_mut().remap_failures = 1;

        assert!(device.write(R_QUEUE_NOTIFY, 2));

        assert_eq!(
            steps(&journal),
            vec![
                Step::Unmap(block),
                Step::Release(block),
                Step::Remap(block),
                Step::Remap(block)
            ]
        );
        assert_eq!(used_count(&device), 1);
    }

    #[test]
    fn a_span_that_cannot_be_remapped_is_never_returned_and_stops_the_device() {
        let first = span(REPORT_BASE, BLOCK);
        let second = span(REPORT_BASE + 4 * BLOCK, BLOCK);
        let (mut device, journal) = reporting(default_regions(), &[&[first], &[second]]);
        journal.borrow_mut().remap_failures = 2;

        assert!(!device.write(R_QUEUE_NOTIFY, 2));

        assert_eq!(
            used_count(&device),
            0,
            "a report over a hole must not be returned"
        );
        assert!(
            !steps(&journal).contains(&Step::Unmap(second)),
            "the device stops at the first span it could not remap"
        );
        assert_eq!(device.read(R_INTERRUPT_STATUS), 0);

        // Later reports are left alone too.
        let before = steps(&journal).len();
        assert!(!device.write(R_QUEUE_NOTIFY, 2));
        assert_eq!(steps(&journal).len(), before);
    }

    #[test]
    fn several_reports_are_returned_in_order() {
        let first = span(REPORT_BASE, BLOCK);
        let second = span(REPORT_BASE + 2 * BLOCK, BLOCK);
        let (mut device, journal) = reporting(default_regions(), &[&[first], &[second]]);

        assert!(device.write(R_QUEUE_NOTIFY, 2));

        assert_eq!(steps(&journal).len(), 6);
        assert_eq!(used_count(&device), 2);
        assert_eq!(device.mem.rd_u32(USED + 4), 0, "first chain's head");
        assert_eq!(device.mem.rd_u32(USED + 12), 1, "second chain's head");
    }

    #[test]
    fn inflate_and_deflate_buffers_are_returned_without_releasing_anything() {
        for queue in [INFLATE_QUEUE, DEFLATE_QUEUE] {
            let (mut device, journal) = device(default_regions());
            negotiate(&mut device, OFFERED_FEATURES);
            post(&mut device, queue as u32, &[&[span(RAM_BASE + 0x8000, 64)]]);
            assert!(device.write(R_QUEUE_NOTIFY, queue as u64));
            assert!(steps(&journal).is_empty());
            assert_eq!(used_count(&device), 1);
        }
    }

    #[test]
    fn a_report_on_an_unnegotiated_reporting_queue_is_not_serviced() {
        let (mut device, journal) = device(default_regions());
        negotiate(&mut device, F_VERSION_1);
        post(&mut device, 2, &[&[span(REPORT_BASE, BLOCK)]]);
        assert!(!device.write(R_QUEUE_NOTIFY, 2));
        assert!(steps(&journal).is_empty());
        assert_eq!(used_count(&device), 0);
    }

    #[test]
    fn illegal_queue_geometry_is_not_serviced() {
        let (mut device, journal) = reporting(default_regions(), &[&[span(REPORT_BASE, BLOCK)]]);
        device.write(R_QUEUE_NUM, 0x1_0000);
        assert!(!device.write(R_QUEUE_NOTIFY, 2));
        assert!(steps(&journal).is_empty());
    }

    #[test]
    fn the_guest_actual_field_reads_back_and_reset_clears_it() {
        let (mut device, _) = device(default_regions());
        device.write(R_CONFIG_ACTUAL, 7);
        assert_eq!(device.read(R_CONFIG_ACTUAL), 7);
        device.write(R_STATUS, 0);
        assert_eq!(device.read(R_CONFIG_ACTUAL), 0);
    }

    #[test]
    fn reset_rewinds_every_queue_and_forgets_negotiation() {
        let (mut device, _) = reporting(default_regions(), &[&[span(REPORT_BASE, BLOCK)]]);
        assert!(device.write(R_QUEUE_NOTIFY, 2));
        assert_eq!(device.queues[2].last_avail, 1);

        device.write(R_STATUS, 0);

        assert!(
            device
                .queues
                .iter()
                .all(|queue| *queue == QueueState::default())
        );
        assert_eq!(device.negotiated(), 0);
    }

    #[test]
    fn device_state_round_trips() {
        let (mut source, _) = reporting(default_regions(), &[&[span(REPORT_BASE, BLOCK)]]);
        assert!(source.write(R_QUEUE_NOTIFY, 2));
        source.write(R_CONFIG_ACTUAL, 3);
        source.write(R_STATUS, 0xf);
        let state = source.snapshot_state().unwrap();

        let (mut target, journal) = device(default_regions());
        target.restore_state(&state).unwrap();

        assert_eq!(target.snapshot_state().unwrap(), state);
        assert_eq!(target.negotiated(), OFFERED_FEATURES);
        assert_eq!(target.queues, source.queues);
        assert_eq!(target.read(R_CONFIG_ACTUAL), 3);
        assert_eq!(target.read(R_STATUS), 0xf);
        assert_eq!(target.read(R_INTERRUPT_STATUS), 1);
        assert!(steps(&journal).is_empty(), "restore touches no host pages");
    }

    #[test]
    fn a_restored_device_continues_from_the_saved_cursors() {
        let first = span(REPORT_BASE, BLOCK);
        let (mut source, _) = reporting(default_regions(), &[&[first]]);
        assert!(source.write(R_QUEUE_NOTIFY, 2));
        let state = source.snapshot_state().unwrap();

        // The child shares the parent's RAM image, so its rings are where the
        // parent left them. Post a second report after the first.
        let (mut child, journal) = device(default_regions());
        child.mem = source.mem;
        child.restore_state(&state).unwrap();
        let second = span(REPORT_BASE + 2 * BLOCK, BLOCK);
        write_descriptor(&child, 1, second, None);
        child.mem.wr_u16(AVAIL + 6, 1);
        child.mem.wr_u16(AVAIL + 2, 2);

        assert!(child.write(R_QUEUE_NOTIFY, 2));

        assert_eq!(
            steps(&journal),
            vec![
                Step::Unmap(second),
                Step::Release(second),
                Step::Remap(second)
            ],
            "the first report is not released again"
        );
        assert_eq!(used_count(&child), 2);
    }

    #[test]
    fn restore_rejects_state_the_device_could_not_have_produced() {
        let (source, _) = device(default_regions());
        let good = source.snapshot_state().unwrap();
        let (mut target, _) = device(default_regions());

        // Header (magic, version) is 2 bytes; driver_features follows the two
        // selector words.
        let mut foreign_feature = good.clone();
        foreign_feature[10..18].copy_from_slice(&F_STATS_VQ.to_le_bytes());
        assert!(matches!(
            target.restore_state(&foreign_feature),
            Err(DeviceStateError::InvalidValue {
                field: "driver_features",
                ..
            })
        ));

        let mut bad_queue_sel = good.clone();
        bad_queue_sel[22..26].copy_from_slice(&3u32.to_le_bytes());
        assert!(matches!(
            target.restore_state(&bad_queue_sel),
            Err(DeviceStateError::InvalidValue {
                field: "queue_sel",
                ..
            })
        ));

        let mut truncated = good.clone();
        truncated.pop();
        assert!(target.restore_state(&truncated).is_err());

        let mut trailing = good;
        trailing.push(0);
        assert!(target.restore_state(&trailing).is_err());
    }
}
