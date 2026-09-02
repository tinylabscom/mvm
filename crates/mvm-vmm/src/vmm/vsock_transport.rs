use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use virtio_queue::{Queue as SplitQueue, QueueOwnedT, QueueT};
use virtio_vsock::packet::{PKT_HEADER_SIZE, VsockPacket};

use super::RingGeometry;
use super::guest_mem::GuestMem;

pub(crate) const VIRTIO_MAGIC: u32 = 0x7472_6976;
pub(crate) const VIRTIO_VERSION: u32 = 2;
pub(crate) const VIRTIO_ID_VSOCK: u32 = 19;
pub(crate) const VIRTIO_VENDOR: u32 = 0x4d56_4d76;

pub(crate) const NUM_QUEUES: usize = 3;
const RX: usize = 0;
const TX: usize = 1;

/// Wire size of a virtio-vsock stream packet header. Anchored to the audited
/// `virtio-vsock` header layout so the device's buffer/descriptor sizing math and
/// the typed header parse/format share one source of truth (both are 44 bytes).
pub(crate) const HDR_LEN: usize = PKT_HEADER_SIZE;
pub(crate) const HOST_CID: u64 = 2;
pub(crate) const GUEST_CID: u64 = 3;
pub(crate) const HOST_BUF_ALLOC: u32 = 256 * 1024;
/// Maximum number of guest-selected vsock stream identities tracked by one
/// device. A guest can choose the source port, so this is a host resource
/// boundary rather than a protocol limit.
pub(crate) const MAX_CONNECTIONS: usize = 256;
pub(crate) const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) const OP_REQUEST: u16 = 1;
pub(crate) const OP_RESPONSE: u16 = 2;
pub(crate) const OP_RST: u16 = 3;
pub(crate) const OP_SHUTDOWN: u16 = 4;
pub(crate) const OP_RW: u16 = 5;
pub(crate) const OP_CREDIT_UPDATE: u16 = 6;
pub(crate) const OP_CREDIT_REQUEST: u16 = 7;
pub(crate) const TYPE_STREAM: u16 = 1;

#[derive(Default, Clone, Copy)]
pub(crate) struct Queue {
    pub(crate) num: u32,
    pub(crate) ready: u32,
    pub(crate) desc: u64,
    pub(crate) avail: u64,
    pub(crate) used: u64,
    pub(crate) last_avail: u16,
    pub(crate) next_used: u16,
}

impl Queue {
    /// Rewind both device-owned ring cursors to the start of a fresh ring, on the
    /// same two transitions the block and fs devices use: this queue being
    /// detached (`QueueReady` ← 0) and the device being reset (`Status` ← 0).
    fn rewind_cursors(&mut self) {
        self.last_avail = 0;
        self.next_used = 0;
    }
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VsockHdr {
    pub(crate) src_cid: u64,
    pub(crate) dst_cid: u64,
    pub(crate) src_port: u32,
    pub(crate) dst_port: u32,
    pub(crate) len: u32,
    pub(crate) typ: u16,
    pub(crate) op: u16,
    pub(crate) flags: u32,
    pub(crate) buf_alloc: u32,
    pub(crate) fwd_cnt: u32,
}

impl VsockHdr {
    /// Serialize into the 44-byte little-endian wire header through the audited
    /// `virtio-vsock` typed packet, whose `Le64`/`Le32`/`Le16` field setters land
    /// each field at the spec offset — byte-identical to a hand-rolled LE encode.
    pub(crate) fn to_bytes(self) -> [u8; HDR_LEN] {
        let mut bytes = [0u8; HDR_LEN];
        // SAFETY: `bytes` is a live 44-byte stack buffer that outlives `pkt`. The
        // `VolatileSlice` `pkt` wraps over it is the only other alias, and every
        // access is single-threaded: the field setters write through the slice,
        // then the plain read of `bytes` at return observes those writes. This
        // satisfies `VsockPacket::new`'s "buffer alive for the wrapper's lifetime,
        // volatile-only access" contract.
        let mut pkt = unsafe { VsockPacket::new(&mut bytes, None) }.expect("44-byte header buffer");
        pkt.set_src_cid(self.src_cid)
            .set_dst_cid(self.dst_cid)
            .set_src_port(self.src_port)
            .set_dst_port(self.dst_port)
            .set_len(self.len)
            .set_type(self.typ)
            .set_op(self.op)
            .set_flags(self.flags)
            .set_buf_alloc(self.buf_alloc)
            .set_fwd_cnt(self.fwd_cnt);
        bytes
    }

    /// Parse a 44-byte little-endian wire header through the audited
    /// `virtio-vsock` typed packet. `set_header_from_raw` reparses the bytes into
    /// the typed `PacketHeader`; the accessors return each field host-endian,
    /// byte-identical to a hand-rolled LE decode. Panics on a short input, exactly
    /// as the previous fixed-offset decode did.
    pub(crate) fn from_bytes(b: &[u8]) -> Self {
        let mut scratch = [0u8; HDR_LEN];
        // SAFETY: `scratch` outlives `pkt`; the wrapping `VolatileSlice` is the only
        // other alias and all access is single-threaded, honouring the same
        // "buffer alive, volatile-only" contract as `to_bytes`.
        let mut pkt =
            unsafe { VsockPacket::new(&mut scratch, None) }.expect("44-byte header buffer");
        pkt.set_header_from_raw(&b[..HDR_LEN])
            .expect("44-byte header slice");
        Self {
            src_cid: pkt.src_cid(),
            dst_cid: pkt.dst_cid(),
            src_port: pkt.src_port(),
            dst_port: pkt.dst_port(),
            len: pkt.len(),
            typ: pkt.type_(),
            op: pkt.op(),
            flags: pkt.flags(),
            buf_alloc: pkt.buf_alloc(),
            fwd_cnt: pkt.fwd_cnt(),
        }
    }
}

pub(crate) enum RegisterWrite {
    None,
    Notify(u32),
}

pub(crate) struct VsockTransportCore {
    mem: GuestMem,
    pub(crate) device_features_sel: u32,
    pub(crate) status: u32,
    pub(crate) queue_sel: u32,
    pub(crate) queues: [Queue; NUM_QUEUES],
    pub(crate) interrupt_status: u32,
    pub(crate) recv_cnt: HashMap<VsockConnectionKey, RecvCredit>,
    pub(crate) pending_rx: VecDeque<(VsockHdr, Vec<u8>)>,
    tx_credit: HashMap<VsockConnectionKey, TxCredit>,
    /// Guest ports whose streams are exempt from idle eviction. Evicting one
    /// sends the guest an `OP_RST`, which tears down a stream that is merely
    /// quiet — and a request/response control channel is quiet for exactly as
    /// long as the operation it is waiting on.
    long_lived: std::collections::HashSet<u32>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct VsockConnectionKey {
    pub(crate) host_port: u32,
    pub(crate) guest_port: u32,
}

pub(crate) struct RecvCredit {
    bytes: u32,
    last_activity: Instant,
}

pub(crate) struct TxCredit {
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
    tx_cnt: u32,
    last_activity: Instant,
}

impl VsockTransportCore {
    /// # Safety
    /// `ram` must point to `ram_size` bytes mapped as guest RAM at `ram_base`.
    pub(crate) unsafe fn new(ram: *mut u8, ram_base: u64, ram_size: usize) -> Self {
        Self {
            // SAFETY: forwarded from this fn's contract.
            mem: unsafe { GuestMem::new(ram, ram_base, ram_size) },
            device_features_sel: 0,
            status: 0,
            queue_sel: 0,
            queues: [Queue::default(); NUM_QUEUES],
            interrupt_status: 0,
            recv_cnt: HashMap::new(),
            pending_rx: VecDeque::new(),
            tx_credit: HashMap::new(),
            long_lived: std::collections::HashSet::new(),
        }
    }

    pub(crate) fn read(&self, offset: u64, r_config: u64) -> u64 {
        u64::from(match offset {
            0x000 => VIRTIO_MAGIC,
            0x004 => VIRTIO_VERSION,
            0x008 => VIRTIO_ID_VSOCK,
            0x00c => VIRTIO_VENDOR,
            0x010 if self.device_features_sel == 1 => 1,
            0x010 => 0,
            0x034 => super::QUEUE_SIZE_MAX,
            0x044 => self.cur().ready,
            0x060 => self.interrupt_status,
            0x070 => self.status,
            o if o == r_config => GUEST_CID as u32,
            o if o == r_config + 4 => (GUEST_CID >> 32) as u32,
            _ => 0,
        })
    }

    pub(crate) fn write_register(&mut self, offset: u64, value: u64) -> RegisterWrite {
        let v = value as u32;
        match offset {
            0x014 => self.device_features_sel = v,
            0x024 | 0x020 => {}
            0x030 => self.queue_sel = v,
            0x038 => self.cur_mut().num = v,
            0x044 => {
                let q = self.cur_mut();
                q.ready = v;
                if v == 0 {
                    q.rewind_cursors();
                }
            }
            0x070 => {
                self.status = v;
                if v == 0 {
                    // A device reset returns every queue to its pre-init state, not
                    // just the one currently selected.
                    self.queues.iter_mut().for_each(Queue::rewind_cursors);
                }
            }
            0x064 => self.interrupt_status &= !v,
            0x080 => set_lo(&mut self.cur_mut().desc, v),
            0x084 => set_hi(&mut self.cur_mut().desc, v),
            0x090 => set_lo(&mut self.cur_mut().avail, v),
            0x094 => set_hi(&mut self.cur_mut().avail, v),
            0x0a0 => set_lo(&mut self.cur_mut().used, v),
            0x0a4 => set_hi(&mut self.cur_mut().used, v),
            0x050 => return RegisterWrite::Notify(v),
            _ => {}
        }
        RegisterWrite::None
    }

    pub(crate) fn take_tx_packets(&mut self) -> Vec<(VsockHdr, Vec<u8>)> {
        let q = self.queues[TX];
        if q.ready == 0 {
            return Vec::new();
        }
        // Keep the existing geometry gate ahead of the queue build: an illegal
        // guest-programmed `QueueNum` is left unserviced exactly as before, and a
        // valid size is also what the validated `Queue` accepts.
        let Some(qsz) = super::validated_queue_size(q.num) else {
            return Vec::new();
        };
        // The `virtio-queue` walk needs a real `GuestMemory` built over the same
        // externally-owned RAM. If it can't be constructed (e.g. a non-page-aligned
        // mapping), service nothing — mirroring the illegal-geometry early outs.
        let Some(mem) = self.mem.guest_memory() else {
            return Vec::new();
        };
        let Some(mut queue) = build_split_queue(&q, qsz) else {
            return Vec::new();
        };

        let mut packets = Vec::new();
        let mut completed = Vec::new();
        {
            // `DescriptorChain::next` seeds `ttl` from the validated queue size and
            // stops once `ttl == 0 || next_index >= queue_size`, so the chain walk
            // is bounded and range-checked — no hand-rolled counter, no missing
            // `next < qsz` guard.
            let Ok(avail) = queue.iter(&mem) else {
                return Vec::new();
            };
            for chain in avail {
                let head = chain.head_index();
                let mut buf = Vec::new();
                for desc in chain.readable() {
                    // Gather buffer bytes through the same bounds-checked `GuestMem`
                    // (out-of-range → zero bytes), byte-identical to the old walk.
                    buf.extend_from_slice(&self.mem.read_bytes(desc.addr().0, desc.len() as usize));
                }
                if buf.len() >= HDR_LEN {
                    let hdr = VsockHdr::from_bytes(&buf[..HDR_LEN]);
                    packets.push((hdr, buf[HDR_LEN..].to_vec()));
                }
                completed.push(head);
            }
        }
        for head in completed {
            // `head` came from a validated avail-ring slot (`< qsz`); `add_used`
            // re-checks the bound and writes the same 8-byte used element + used
            // index the old `complete(TX, head, 0, qsz)` wrote.
            let _ = queue.add_used(&mem, head, 0);
            self.interrupt_status |= 1;
        }
        self.queues[TX].last_avail = queue.next_avail();
        self.queues[TX].next_used = queue.next_used();
        packets
    }

    pub(crate) fn try_add_recv(&mut self, inbound: &VsockHdr, n: u32) -> bool {
        self.try_add_recv_at(inbound, n, Instant::now())
    }

    fn try_add_recv_at(&mut self, inbound: &VsockHdr, n: u32, now: Instant) -> bool {
        let key = VsockConnectionKey {
            host_port: inbound.dst_port,
            guest_port: inbound.src_port,
        };
        if !self.recv_cnt.contains_key(&key) && self.recv_cnt.len() >= MAX_CONNECTIONS {
            return false;
        }
        let entry = self.recv_cnt.entry(key).or_insert(RecvCredit {
            bytes: 0,
            last_activity: now,
        });
        entry.bytes = entry.bytes.saturating_add(n);
        entry.last_activity = now;
        true
    }

    pub(crate) fn set_long_lived_ports(&mut self, ports: impl IntoIterator<Item = u32>) {
        self.long_lived = ports.into_iter().collect();
    }

    pub(crate) fn evict_idle_connections(&mut self) -> Vec<VsockConnectionKey> {
        self.evict_idle_connections_at(Instant::now())
    }

    fn evict_idle_connections_at(&mut self, now: Instant) -> Vec<VsockConnectionKey> {
        let mut latest_activity =
            HashMap::with_capacity(self.recv_cnt.len() + self.tx_credit.len());
        for (key, credit) in &self.recv_cnt {
            latest_activity.insert(*key, credit.last_activity);
        }
        for (key, credit) in &self.tx_credit {
            latest_activity
                .entry(*key)
                .and_modify(|activity| *activity = (*activity).max(credit.last_activity))
                .or_insert(credit.last_activity);
        }

        let mut expired: Vec<_> = latest_activity
            .into_iter()
            .filter_map(|(key, activity)| {
                (!self.long_lived.contains(&key.guest_port)
                    && now.saturating_duration_since(activity) >= CONNECTION_IDLE_TIMEOUT)
                    .then_some(key)
            })
            .collect();
        expired.sort_unstable_by_key(|key| (key.host_port, key.guest_port));
        for key in &expired {
            self.recv_cnt.remove(key);
            self.tx_credit.remove(key);
        }
        expired
    }

    pub(crate) fn remove_recv(&mut self, host_port: u32, guest_port: u32) {
        self.recv_cnt.remove(&VsockConnectionKey {
            host_port,
            guest_port,
        });
    }

    /// Record the receive window advertised by the guest on an incoming packet.
    /// Every virtio-vsock stream header carries the peer's current `buf_alloc`
    /// and cumulative `fwd_cnt`, so refreshing this state before dispatch keeps
    /// host-to-guest writes inside the guest's actual buffer capacity.
    pub(crate) fn record_tx_credit(&mut self, inbound: &VsockHdr) -> bool {
        self.record_tx_credit_at(inbound, Instant::now())
    }

    fn record_tx_credit_at(&mut self, inbound: &VsockHdr, now: Instant) -> bool {
        let key = VsockConnectionKey {
            host_port: inbound.dst_port,
            guest_port: inbound.src_port,
        };
        if !self.tx_credit.contains_key(&key) && self.tx_credit.len() >= MAX_CONNECTIONS {
            return false;
        }
        let entry = self.tx_credit.entry(key).or_insert(TxCredit {
            peer_buf_alloc: inbound.buf_alloc,
            peer_fwd_cnt: inbound.fwd_cnt,
            tx_cnt: 0,
            last_activity: now,
        });
        entry.peer_buf_alloc = inbound.buf_alloc;
        entry.peer_fwd_cnt = inbound.fwd_cnt;
        entry.last_activity = now;
        true
    }

    pub(crate) fn tx_credit_available(&self, host_port: u32, guest_port: u32) -> u32 {
        self.tx_credit
            .get(&VsockConnectionKey {
                host_port,
                guest_port,
            })
            .map(|credit| {
                credit
                    .peer_buf_alloc
                    .saturating_sub(credit.tx_cnt.wrapping_sub(credit.peer_fwd_cnt))
            })
            .unwrap_or(0)
    }

    pub(crate) fn consume_tx_credit(&mut self, host_port: u32, guest_port: u32, n: u32) {
        if let Some(credit) = self.tx_credit.get_mut(&VsockConnectionKey {
            host_port,
            guest_port,
        }) {
            credit.tx_cnt = credit.tx_cnt.wrapping_add(n);
            credit.last_activity = Instant::now();
        }
    }

    pub(crate) fn remove_tx_credit(&mut self, host_port: u32, guest_port: u32) {
        self.tx_credit.remove(&VsockConnectionKey {
            host_port,
            guest_port,
        });
    }

    pub(crate) fn clear_tx_credit(&mut self) {
        self.tx_credit.clear();
    }

    pub(crate) fn has_tx_credit(&self) -> bool {
        !self.tx_credit.is_empty()
    }

    pub(crate) fn queue_host_packet(
        &mut self,
        src_port: u32,
        dst_port: u32,
        op: u16,
        payload: &[u8],
    ) {
        let hdr = VsockHdr {
            src_cid: HOST_CID,
            dst_cid: GUEST_CID,
            src_port,
            dst_port,
            len: payload.len() as u32,
            typ: TYPE_STREAM,
            op,
            flags: 0,
            buf_alloc: HOST_BUF_ALLOC,
            fwd_cnt: self.fwd_cnt_for(src_port, dst_port),
        };
        self.pending_rx.push_back((hdr, payload.to_vec()));
    }

    pub(crate) fn queue_reply(&mut self, inbound: &VsockHdr, op: u16, payload: &[u8]) {
        let reply = VsockHdr {
            src_cid: HOST_CID,
            dst_cid: GUEST_CID,
            src_port: inbound.dst_port,
            dst_port: inbound.src_port,
            len: payload.len() as u32,
            typ: TYPE_STREAM,
            op,
            flags: 0,
            buf_alloc: HOST_BUF_ALLOC,
            fwd_cnt: self.fwd_cnt_for(inbound.dst_port, inbound.src_port),
        };
        self.pending_rx.push_back((reply, payload.to_vec()));
    }

    pub(crate) fn flush_rx(&mut self) -> bool {
        let q = self.queues[RX];
        if q.ready == 0 || self.pending_rx.is_empty() {
            return false;
        }
        let Some(qsz) = super::validated_queue_size(q.num) else {
            return false;
        };
        // The `virtio-queue` walk needs a real `GuestMemory` over the same
        // externally-owned RAM; if it can't be built (e.g. a non-page-aligned
        // mapping) service nothing, mirroring the illegal-geometry early outs.
        let Some(mem) = self.mem.guest_memory() else {
            return false;
        };
        let Some(mut queue) = build_split_queue(&q, qsz) else {
            return false;
        };

        let mut completed = Vec::new();
        let mut delivered = false;
        {
            let Ok(mut avail) = queue.iter(&mem) else {
                return false;
            };
            while !self.pending_rx.is_empty() {
                let Some(chain) = avail.next() else {
                    break;
                };
                let head = chain.head_index();
                // The RX buffer is the chain's writable span. `virtio-queue` yields
                // only descriptors flagged device-writable and range-checks each
                // `next` link, so a chain offering no writable room delivers
                // nothing — the packet is left queued rather than silently dropped.
                let dsts: Vec<(u64, usize)> = chain
                    .writable()
                    .map(|desc| (desc.addr().0, desc.len() as usize))
                    .collect();
                let cap: usize = dsts.iter().map(|(_, len)| len).sum();
                let (hdr, payload) = self
                    .pending_rx
                    .pop_front()
                    .expect("loop guard checked non-empty");
                let payload_cap = match cap.checked_sub(HDR_LEN) {
                    Some(payload_cap) if payload_cap > 0 || payload.is_empty() => payload_cap,
                    _ => {
                        // No usable RX buffer: leave the packet queued and un-consume
                        // the avail entry so the used ring is not advanced for a
                        // packet the guest never received.
                        self.pending_rx.push_front((hdr, payload));
                        avail.go_to_previous_position();
                        break;
                    }
                };
                let send_len = payload.len().min(payload_cap);
                let mut framed = hdr;
                framed.len = send_len as u32;
                let mut bytes = framed.to_bytes().to_vec();
                bytes.extend_from_slice(&payload[..send_len]);
                if scatter_write(&self.mem, &dsts, &bytes) == 0 {
                    // Out-of-range RX descriptor addr: nothing was delivered. Leave
                    // the packet queued and un-consume the avail entry instead of
                    // advancing the used ring (mirrors the too-small-buffer path).
                    self.pending_rx.push_front((hdr, payload));
                    avail.go_to_previous_position();
                    break;
                }
                completed.push((head, bytes.len() as u32));
                let remainder = &payload[send_len..];
                if !remainder.is_empty() {
                    self.pending_rx.push_front((framed, remainder.to_vec()));
                }
                delivered = true;
            }
        }
        for (head, written) in completed {
            // `head` came from a validated avail-ring slot (`< qsz`); `add_used`
            // re-checks the bound and writes the same 8-byte used element + used
            // index the old `complete(RX, head, written, qsz)` wrote.
            let _ = queue.add_used(&mem, head, written);
            self.interrupt_status |= 1;
        }
        self.queues[RX].last_avail = queue.next_avail();
        self.queues[RX].next_used = queue.next_used();
        delivered
    }
    fn cur(&self) -> &Queue {
        &self.queues[(self.queue_sel as usize).min(NUM_QUEUES - 1)]
    }

    fn cur_mut(&mut self) -> &mut Queue {
        let i = (self.queue_sel as usize).min(NUM_QUEUES - 1);
        &mut self.queues[i]
    }

    fn fwd_cnt_for(&self, host_port: u32, guest_port: u32) -> u32 {
        self.recv_cnt
            .get(&VsockConnectionKey {
                host_port,
                guest_port,
            })
            .map(|credit| credit.bytes)
            .unwrap_or(0)
    }
}

/// Scatter `bytes` across the writable descriptors `dsts` (in chain order),
/// returning the total number of bytes landed in guest RAM. Each descriptor
/// write is bounds-checked by [`GuestMem`]; an out-of-range descriptor buffer
/// lands nothing and stops the scatter, so a fully out-of-range chain returns 0
/// and the caller treats the packet as undelivered.
fn scatter_write(mem: &GuestMem, dsts: &[(u64, usize)], bytes: &[u8]) -> usize {
    let mut written = 0usize;
    for &(addr, len) in dsts {
        if written >= bytes.len() {
            break;
        }
        let take = len.min(bytes.len() - written);
        let n = mem.write_bytes(addr, &bytes[written..written + take]);
        written += n;
        if n < take {
            break;
        }
    }
    written
}

/// Adapt this device's per-queue ring state to the module-shared
/// [`super::build_split_queue`] (used by the TX drain and the RX delivery).
fn build_split_queue(q: &Queue, qsz: u16) -> Option<SplitQueue> {
    super::build_split_queue(
        RingGeometry {
            desc: q.desc,
            avail: q.avail,
            used: q.used,
            next_avail: q.last_avail,
            next_used: q.next_used,
        },
        qsz,
    )
}

fn set_lo(v: &mut u64, lo: u32) {
    *v = (*v & !0xffff_ffff) | u64::from(lo);
}

fn set_hi(v: &mut u64, hi: u32) {
    *v = (*v & 0xffff_ffff) | (u64::from(hi) << 32);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport() -> VsockTransportCore {
        transport_with_ram(0x1000)
    }

    fn transport_with_ram(size: usize) -> VsockTransportCore {
        let ram = crate::test_support::page_aligned_ram(size);
        // SAFETY: page-aligned, zeroed, leaked for the test process lifetime.
        unsafe { VsockTransportCore::new(ram.as_mut_ptr(), 0x4000_0000, ram.len()) }
    }

    fn configure_rx_buffers(core: &mut VsockTransportCore, caps: &[usize]) -> Vec<u64> {
        let base = 0x4000_0000;
        let desc = base + 0x100;
        let avail = base + 0x200;
        let used = base + 0x300;
        let mut buffers = Vec::new();
        core.queues[RX] = Queue {
            num: caps.len() as u32,
            ready: 1,
            desc,
            avail,
            used,
            last_avail: 0,
            next_used: 0,
        };
        core.mem.wr_u16(avail + 2, caps.len() as u16);
        for (index, cap) in caps.iter().enumerate() {
            let buf = base + 0x400 + (index as u64 * 0x100);
            buffers.push(buf);
            let desc_addr = desc + (index as u64 * 16);
            core.mem.write_bytes(desc_addr, &buf.to_le_bytes());
            core.mem
                .write_bytes(desc_addr + 8, &(*cap as u32).to_le_bytes());
            // RX buffers are device-writable; a conformant guest sets F_WRITE so the
            // writable-descriptor walk yields them.
            core.mem.wr_u16(desc_addr + 12, DESC_F_WRITE);
            core.mem
                .wr_u16(avail + 4 + (index as u64 * 2), index as u16);
        }
        buffers
    }

    // ---- virtio-vsock typed header parse/format: byte-identity oracle -------

    /// Byte-for-byte copy of the pre-migration hand-rolled 44-byte little-endian
    /// header encode, kept as the differential oracle. The `virtio-vsock`-backed
    /// `VsockHdr::to_bytes` must reproduce its bytes exactly.
    fn reference_hdr_to_bytes(h: VsockHdr) -> [u8; HDR_LEN] {
        let mut b = [0u8; HDR_LEN];
        b[0..8].copy_from_slice(&h.src_cid.to_le_bytes());
        b[8..16].copy_from_slice(&h.dst_cid.to_le_bytes());
        b[16..20].copy_from_slice(&h.src_port.to_le_bytes());
        b[20..24].copy_from_slice(&h.dst_port.to_le_bytes());
        b[24..28].copy_from_slice(&h.len.to_le_bytes());
        b[28..30].copy_from_slice(&h.typ.to_le_bytes());
        b[30..32].copy_from_slice(&h.op.to_le_bytes());
        b[32..36].copy_from_slice(&h.flags.to_le_bytes());
        b[36..40].copy_from_slice(&h.buf_alloc.to_le_bytes());
        b[40..44].copy_from_slice(&h.fwd_cnt.to_le_bytes());
        b
    }

    /// Byte-for-byte copy of the pre-migration hand-rolled fixed-offset decode.
    fn reference_hdr_from_bytes(b: &[u8]) -> VsockHdr {
        let u64a = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().expect("hdr u64"));
        let u32a = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().expect("hdr u32"));
        let u16a = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().expect("hdr u16"));
        VsockHdr {
            src_cid: u64a(0),
            dst_cid: u64a(8),
            src_port: u32a(16),
            dst_port: u32a(20),
            len: u32a(24),
            typ: u16a(28),
            op: u16a(30),
            flags: u32a(32),
            buf_alloc: u32a(36),
            fwd_cnt: u32a(40),
        }
    }

    /// Every op the device dispatches, plus `0` and `u16::MAX` as out-of-range
    /// wire values a hostile guest can still frame.
    const ALL_OPS: [u16; 9] = [
        0,
        OP_REQUEST,
        OP_RESPONSE,
        OP_RST,
        OP_SHUTDOWN,
        OP_RW,
        OP_CREDIT_UPDATE,
        OP_CREDIT_REQUEST,
        u16::MAX,
    ];

    #[test]
    fn hdr_framing_is_byte_identical_to_the_reference_over_all_ops_and_boundaries() {
        // Boundary values for the wide fields: min, a mid value, and the type max.
        let cids = [0u64, HOST_CID, GUEST_CID, u64::MAX];
        let ports = [0u32, 1234, u32::MAX];
        let lens = [0u32, 1, u32::MAX];
        let buf_allocs = [0u32, HOST_BUF_ALLOC, u32::MAX];
        let fwd_cnts = [0u32, 7, u32::MAX];
        // Both virtio-vsock shutdown flag bits, independently and together.
        let flags = [0u32, 1, 2, 3];
        let types = [0u16, TYPE_STREAM];

        for &op in &ALL_OPS {
            for &flag in &flags {
                for &typ in &types {
                    for (i, &src_cid) in cids.iter().enumerate() {
                        // Index-pair the boundary arrays so the matrix stays
                        // representative without exploding combinatorially: each
                        // op × flag × type is exercised against the min / mid / max
                        // field sets, and every boundary value appears.
                        let h = VsockHdr {
                            src_cid,
                            dst_cid: cids[cids.len() - 1 - i],
                            src_port: ports[i % ports.len()],
                            dst_port: ports[(i + 1) % ports.len()],
                            len: lens[i % lens.len()],
                            typ,
                            op,
                            flags: flag,
                            buf_alloc: buf_allocs[i % buf_allocs.len()],
                            fwd_cnt: fwd_cnts[i % fwd_cnts.len()],
                        };

                        // 1. Framing is byte-identical to the hand-rolled encode.
                        let framed = h.to_bytes();
                        assert_eq!(
                            framed,
                            reference_hdr_to_bytes(h),
                            "framing differs for {h:?}"
                        );

                        // 2. Parse recovers every field identically to the
                        //    hand-rolled decode and round-trips to the original.
                        let parsed = VsockHdr::from_bytes(&framed);
                        assert_eq!(
                            parsed,
                            reference_hdr_from_bytes(&framed),
                            "parse differs for {h:?}"
                        );
                        assert_eq!(parsed, h, "round-trip lost a field for {h:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn flush_rx_splits_large_stream_payload_across_guest_buffers() {
        let mut core = transport();
        let buffers = configure_rx_buffers(&mut core, &[HDR_LEN + 6, HDR_LEN + 4]);
        let hdr = VsockHdr {
            src_cid: HOST_CID,
            dst_cid: GUEST_CID,
            src_port: mvm_agentd::vsock::EGRESS_PORT,
            dst_port: 1500,
            len: 10,
            typ: TYPE_STREAM,
            op: OP_RW,
            flags: 0,
            buf_alloc: HOST_BUF_ALLOC,
            fwd_cnt: 12,
        };
        core.pending_rx.push_back((hdr, b"abcdefghij".to_vec()));

        assert!(core.flush_rx());
        assert!(core.pending_rx.is_empty());

        let first = core.mem.read_bytes(buffers[0], HDR_LEN + 6);
        let first_hdr = VsockHdr::from_bytes(&first[..HDR_LEN]);
        assert_eq!(first_hdr.op, OP_RW);
        assert_eq!(first_hdr.len, 6);
        assert_eq!(&first[HDR_LEN..], b"abcdef");

        let second = core.mem.read_bytes(buffers[1], HDR_LEN + 4);
        let second_hdr = VsockHdr::from_bytes(&second[..HDR_LEN]);
        assert_eq!(second_hdr.op, OP_RW);
        assert_eq!(second_hdr.len, 4);
        assert_eq!(&second[HDR_LEN..], b"ghij");
    }

    /// Program a drainable ring (`RX` or `TX`) whose `avail_idx` is one past
    /// `last_avail`, so the drain loop body — where the ring is indexed with
    /// `last % qsz` — is entered. `num` is the raw guest-programmed `QueueNum`.
    fn program_ring(core: &mut VsockTransportCore, slot: usize, num: u32) {
        let base = 0x4000_0000;
        core.queues[slot] = Queue {
            num,
            ready: 1,
            desc: base + 0x100,
            avail: base + 0x200,
            used: base + 0x300,
            last_avail: 0,
            next_used: 0,
        };
        core.mem.wr_u16(base + 0x200 + 2, 1);
    }

    /// Queue sizes a hostile guest can program that are illegal geometry: zero,
    /// values whose low 16 bits are zero (which truncate to a zero `u16`), and
    /// sizes that are above the advertised maximum or not a power of two.
    const ILLEGAL_QUEUE_SIZES: [u32; 6] = [0, 0x1_0000, 0x2_0000, 0xffff_0000, 300, 512];

    #[test]
    fn take_tx_packets_rejects_queue_size_that_truncates_to_zero() {
        let mut core = transport();
        program_ring(&mut core, TX, 0x1_0000);
        assert!(core.take_tx_packets().is_empty());
    }

    #[test]
    fn take_tx_packets_rejects_illegal_queue_geometry() {
        for num in ILLEGAL_QUEUE_SIZES {
            let mut core = transport();
            program_ring(&mut core, TX, num);
            assert!(
                core.take_tx_packets().is_empty(),
                "TX queue size {num:#x} must not be serviced"
            );
        }
    }

    #[test]
    fn flush_rx_rejects_queue_size_that_truncates_to_zero() {
        let mut core = transport();
        program_ring(&mut core, RX, 0x1_0000);
        core.queue_host_packet(1, 2, OP_RW, b"x");
        assert!(!core.flush_rx());
        assert_eq!(core.pending_rx.len(), 1, "packet stays queued, not dropped");
    }

    #[test]
    fn flush_rx_rejects_illegal_queue_geometry() {
        for num in ILLEGAL_QUEUE_SIZES {
            let mut core = transport();
            program_ring(&mut core, RX, num);
            core.queue_host_packet(1, 2, OP_RW, b"x");
            assert!(
                !core.flush_rx(),
                "RX queue size {num:#x} must not be serviced"
            );
            assert_eq!(core.pending_rx.len(), 1);
        }
    }

    #[test]
    fn flush_rx_leaves_packet_queued_on_out_of_range_rx_descriptor() {
        let mut core = transport();
        let base = 0x4000_0000;
        let desc = base + 0x100;
        let avail = base + 0x200;
        let used = base + 0x300;
        core.queues[RX] = Queue {
            num: 1,
            ready: 1,
            desc,
            avail,
            used,
            last_avail: 0,
            next_used: 0,
        };
        core.mem.wr_u16(avail + 2, 1);
        core.mem.wr_u16(avail + 4, 0); // ring[0] = head 0
        // Head descriptor addr points past the mapped RAM region; the capacity is
        // large enough to pass the buffer-size check, so the write is attempted and
        // delivers 0 bytes.
        let bogus = base + 0x1_0000;
        core.mem.write_bytes(desc, &bogus.to_le_bytes());
        core.mem
            .write_bytes(desc + 8, &((HDR_LEN + 8) as u32).to_le_bytes());
        core.mem.wr_u16(desc + 12, DESC_F_WRITE);
        core.queue_host_packet(1, 2, OP_RW, b"payload!");

        assert!(!core.flush_rx(), "bogus addr delivers nothing");
        assert_eq!(core.pending_rx.len(), 1, "packet left queued, not dropped");
        assert_eq!(core.mem.rd_u16(used + 2), 0, "used ring not advanced");

        // Repointing the descriptor at valid RAM delivers the same packet and now
        // advances the used ring.
        let good = base + 0x400;
        core.mem.write_bytes(desc, &good.to_le_bytes());
        assert!(core.flush_rx());
        assert!(core.pending_rx.is_empty());
        assert_eq!(core.mem.rd_u16(used + 2), 1, "valid path advances used");
    }

    #[test]
    fn recv_credit_table_rejects_new_connection_ids_at_the_cap() {
        let mut core = transport();
        for guest_port in 0..MAX_CONNECTIONS as u32 {
            let hdr = VsockHdr {
                dst_port: 9000,
                src_port: guest_port,
                ..Default::default()
            };
            assert!(core.try_add_recv(&hdr, 1));
        }

        let new_connection = VsockHdr {
            dst_port: 9000,
            src_port: MAX_CONNECTIONS as u32,
            ..Default::default()
        };
        assert!(!core.try_add_recv(&new_connection, 1));
        assert_eq!(core.recv_cnt.len(), MAX_CONNECTIONS);

        // A normal close frees the slot, allowing a new stream to make progress.
        core.remove_recv(9000, 0);
        assert!(core.try_add_recv(&new_connection, 1));
        assert_eq!(core.recv_cnt.len(), MAX_CONNECTIONS);
    }

    #[test]
    fn recv_credit_for_existing_connection_remains_available_at_the_cap() {
        let mut core = transport();
        let existing = VsockHdr {
            dst_port: 9000,
            src_port: 7,
            ..Default::default()
        };
        assert!(core.try_add_recv(&existing, 1));
        for guest_port in 8..(MAX_CONNECTIONS as u32 + 7) {
            let hdr = VsockHdr {
                dst_port: 9000,
                src_port: guest_port,
                ..Default::default()
            };
            assert!(core.try_add_recv(&hdr, 1));
        }
        assert_eq!(core.recv_cnt.len(), MAX_CONNECTIONS);
        assert!(core.try_add_recv(&existing, 1));
    }

    #[test]
    fn idle_recv_credit_is_evicted_and_releases_identity() {
        let mut core = transport();
        let now = Instant::now();
        let hdr = VsockHdr {
            dst_port: 9000,
            src_port: 7,
            ..Default::default()
        };
        core.try_add_recv_at(
            &hdr,
            1,
            now - CONNECTION_IDLE_TIMEOUT - Duration::from_secs(1),
        );

        assert_eq!(
            core.evict_idle_connections_at(now),
            vec![VsockConnectionKey {
                host_port: 9000,
                guest_port: 7,
            }]
        );
        assert!(core.recv_cnt.is_empty());
    }

    #[test]
    fn unknown_transmit_credit_fails_closed() {
        let core = transport();
        assert_eq!(core.tx_credit_available(9000, 7), 0);
    }

    #[test]
    fn transmit_credit_stops_at_the_window_and_resumes_on_forward_progress() {
        let mut core = transport();
        let mut header = VsockHdr {
            dst_port: 9000,
            src_port: 7,
            buf_alloc: 64,
            ..Default::default()
        };
        assert!(core.record_tx_credit(&header));
        assert_eq!(core.tx_credit_available(9000, 7), 64);

        core.consume_tx_credit(9000, 7, 64);
        assert_eq!(core.tx_credit_available(9000, 7), 0);

        header.fwd_cnt = 64;
        assert!(core.record_tx_credit(&header));
        assert_eq!(core.tx_credit_available(9000, 7), 64);
    }

    #[test]
    fn transmit_credit_counters_wrap_without_reopening_the_window_early() {
        let mut core = transport();
        let key = VsockConnectionKey {
            host_port: 9000,
            guest_port: 7,
        };
        core.tx_credit.insert(
            key,
            TxCredit {
                peer_buf_alloc: 64,
                peer_fwd_cnt: u32::MAX - 31,
                tx_cnt: u32::MAX - 31,
                last_activity: Instant::now(),
            },
        );

        core.consume_tx_credit(9000, 7, 64);
        assert_eq!(core.tx_credit_available(9000, 7), 0);

        assert!(core.record_tx_credit(&VsockHdr {
            dst_port: 9000,
            src_port: 7,
            buf_alloc: 64,
            fwd_cnt: 32,
            ..Default::default()
        }));
        assert_eq!(core.tx_credit_available(9000, 7), 64);
    }

    #[test]
    fn transmit_credit_table_refuses_new_connections_at_the_cap() {
        let mut core = transport();
        for guest_port in 0..MAX_CONNECTIONS as u32 {
            assert!(core.record_tx_credit(&VsockHdr {
                dst_port: 9000,
                src_port: guest_port,
                buf_alloc: 64,
                ..Default::default()
            }));
        }

        let refused_port = MAX_CONNECTIONS as u32;
        assert!(!core.record_tx_credit(&VsockHdr {
            dst_port: 9000,
            src_port: refused_port,
            buf_alloc: u32::MAX,
            ..Default::default()
        }));
        assert_eq!(core.tx_credit_available(9000, refused_port), 0);
        assert_eq!(core.tx_credit.len(), MAX_CONNECTIONS);
    }

    /// The transport is the *second* layer that can reclaim a quiet stream, and
    /// it does so by sending the guest an `OP_RST`. Exempting a port in the
    /// host-dial bridge alone still let this one tear the stream down — which
    /// is exactly what severed a builder dispatch across a `nix build`.
    #[test]
    fn a_long_lived_guest_port_is_not_evicted_for_being_idle() {
        let mut core = transport();
        let now = Instant::now();
        let header = VsockHdr {
            dst_port: 9000,
            src_port: 21_471,
            buf_alloc: 64,
            ..Default::default()
        };
        core.set_long_lived_ports([21_471]);
        assert!(core.record_tx_credit_at(
            &header,
            now - CONNECTION_IDLE_TIMEOUT - Duration::from_secs(1)
        ));

        assert!(
            core.evict_idle_connections_at(now).is_empty(),
            "a long-lived control port must not be reset for being quiet"
        );
    }

    #[test]
    fn idle_transmit_credit_is_evicted_and_releases_identity() {
        let mut core = transport();
        let now = Instant::now();
        let header = VsockHdr {
            dst_port: 9000,
            src_port: 7,
            buf_alloc: 64,
            ..Default::default()
        };
        assert!(core.record_tx_credit_at(
            &header,
            now - CONNECTION_IDLE_TIMEOUT - Duration::from_secs(1)
        ));

        assert_eq!(
            core.evict_idle_connections_at(now),
            vec![VsockConnectionKey {
                host_port: 9000,
                guest_port: 7,
            }]
        );
        assert!(core.tx_credit.is_empty());
    }

    #[test]
    fn transmit_progress_keeps_download_connection_alive_past_receive_idle_timeout() {
        let mut core = transport();
        let opened_at = Instant::now();
        let mut header = VsockHdr {
            dst_port: 9000,
            src_port: 7,
            buf_alloc: 64,
            ..Default::default()
        };
        assert!(core.try_add_recv_at(&header, 1, opened_at));
        assert!(core.record_tx_credit_at(&header, opened_at));

        let download_active_at = opened_at + CONNECTION_IDLE_TIMEOUT + Duration::from_secs(1);
        header.fwd_cnt = 64;
        assert!(core.record_tx_credit_at(&header, download_active_at));

        assert!(
            core.evict_idle_connections_at(download_active_at)
                .is_empty(),
            "fresh transmit progress must keep the whole connection alive"
        );
        assert_eq!(core.recv_cnt.len(), 1);
        assert_eq!(core.tx_credit.len(), 1);

        let wholly_idle_at = download_active_at + CONNECTION_IDLE_TIMEOUT + Duration::from_secs(1);
        assert_eq!(
            core.evict_idle_connections_at(wholly_idle_at),
            vec![VsockConnectionKey {
                host_port: 9000,
                guest_port: 7,
            }]
        );
        assert!(core.recv_cnt.is_empty());
        assert!(core.tx_credit.is_empty());
    }

    // ---- TX virtio-queue migration: differential equivalence ----------------

    const DESC_F_NEXT: u16 = 1;
    const DESC_F_WRITE: u16 = 2;

    /// One guest→host TX descriptor chain: its bytes split across N buffers.
    type Chain = Vec<Vec<u8>>;

    fn tx_hdr(src_port: u32, len: u32) -> VsockHdr {
        VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port,
            dst_port: 2000,
            len,
            typ: TYPE_STREAM,
            op: OP_RW,
            flags: 0,
            buf_alloc: HOST_BUF_ALLOC,
            fwd_cnt: 7,
        }
    }

    /// Single-descriptor chain: 44-byte header + payload, contiguous.
    fn single_chain(src_port: u32, payload: &[u8]) -> Chain {
        let mut seg = tx_hdr(src_port, payload.len() as u32).to_bytes().to_vec();
        seg.extend_from_slice(payload);
        vec![seg]
    }

    /// Header in one descriptor, payload in the next (multi-descriptor chain).
    fn split_chain(src_port: u32, payload: &[u8]) -> Chain {
        vec![
            tx_hdr(src_port, payload.len() as u32).to_bytes().to_vec(),
            payload.to_vec(),
        ]
    }

    /// Header split across a descriptor boundary (first 40 bytes, then the rest):
    /// exercises byte gathering across descriptors, mid-header.
    fn boundary_chain(src_port: u32, payload: &[u8]) -> Chain {
        let mut full = tx_hdr(src_port, payload.len() as u32).to_bytes().to_vec();
        full.extend_from_slice(payload);
        let tail = full.split_off(40);
        vec![full, tail]
    }

    /// A chain whose gathered bytes are shorter than a header: no packet emitted,
    /// but the head is still completed on the used ring.
    fn short_chain() -> Chain {
        vec![vec![0x11; 20]]
    }

    /// Representative TX layouts for `qsz`: single + multi-descriptor chains,
    /// empty + full payloads, a mid-header boundary split, and a dropped-short
    /// chain — all within `qsz` descriptors/chains.
    fn layouts_for(qsz: u16) -> Vec<(&'static str, Vec<Chain>)> {
        match qsz {
            1 => vec![
                ("single-full", vec![single_chain(1000, b"abcdef")]),
                ("single-empty", vec![single_chain(1001, b"")]),
            ],
            2 => vec![
                ("split-hdr-payload", vec![split_chain(1000, b"hello123")]),
                ("boundary", vec![boundary_chain(1000, b"xyz")]),
            ],
            _ => vec![
                (
                    "mixed",
                    vec![
                        single_chain(1000, b"first payload"),
                        split_chain(1001, b"second-body"),
                        single_chain(1002, b""),
                        boundary_chain(1003, b"cross-boundary-data"),
                        short_chain(),
                    ],
                ),
                ("bulk", vec![single_chain(2000, &[0xAB; 100])]),
            ],
        }
    }

    /// Lay `chains` out as a TX split-virtqueue in `core`'s RAM at `base`, program
    /// `core.queues[TX]`, and return the used-ring address. Descriptors are
    /// assigned sequentially; each chain links its segments with F_NEXT.
    fn program_tx_queue(
        core: &mut VsockTransportCore,
        base: u64,
        qsz: u16,
        chains: &[Chain],
    ) -> u64 {
        let desc = base + 0x1000;
        let avail = base + 0x4000;
        let used = base + 0x5000;
        let buf_base = base + 0x6000;
        core.queues[TX] = Queue {
            num: u32::from(qsz),
            ready: 1,
            desc,
            avail,
            used,
            last_avail: 0,
            next_used: 0,
        };
        let mut desc_idx: u16 = 0;
        let mut buf_off: u64 = 0;
        for (chain_no, chain) in chains.iter().enumerate() {
            let head = desc_idx;
            for (seg_no, seg) in chain.iter().enumerate() {
                let da = desc + u64::from(desc_idx) * 16;
                let addr = buf_base + buf_off;
                core.mem.write_bytes(da, &addr.to_le_bytes());
                core.mem
                    .write_bytes(da + 8, &(seg.len() as u32).to_le_bytes());
                let last = seg_no + 1 == chain.len();
                core.mem.wr_u16(da + 12, if last { 0 } else { DESC_F_NEXT });
                core.mem
                    .wr_u16(da + 14, if last { 0 } else { desc_idx + 1 });
                core.mem.write_bytes(addr, seg);
                // Keep buffers separated and 16-aligned; empty segments still stride.
                buf_off += (seg.len().max(1) as u64 + 15) & !15;
                desc_idx += 1;
            }
            core.mem.wr_u16(avail + 4 + (chain_no as u64) * 2, head);
        }
        core.mem.wr_u16(avail + 2, chains.len() as u16);
        used
    }

    /// Faithful copy of the pre-migration hand-rolled TX walk (drain loop +
    /// `read_chain` + `complete`), kept as the differential oracle. The migrated
    /// `take_tx_packets` must reproduce its packets and used-ring writes exactly.
    fn reference_take_tx_packets(
        core: &VsockTransportCore,
        qsz: u16,
    ) -> (Vec<(VsockHdr, Vec<u8>)>, u16, bool) {
        let mem = &core.mem;
        let q = core.queues[TX];
        let avail_idx = mem.rd_u16(q.avail + 2);
        let mut last = q.last_avail;
        let mut packets = Vec::new();
        let mut interrupt = false;
        while last != avail_idx {
            let slot = last % qsz;
            let head = mem.rd_u16(q.avail + 4 + u64::from(slot) * 2);
            let buf = reference_read_chain(core, q.desc, head, qsz);
            if buf.len() >= HDR_LEN {
                let hdr = VsockHdr::from_bytes(&buf[..HDR_LEN]);
                packets.push((hdr, buf[HDR_LEN..].to_vec()));
            }
            reference_complete(core, q.used, head, 0, qsz);
            interrupt = true;
            last = last.wrapping_add(1);
        }
        (packets, last, interrupt)
    }

    fn reference_read_chain(core: &VsockTransportCore, desc: u64, head: u16, qsz: u16) -> Vec<u8> {
        let mem = &core.mem;
        let mut out = Vec::new();
        let mut idx = head;
        let mut guard = 0u32;
        loop {
            let da = desc + u64::from(idx) * 16;
            let addr = mem.rd_u64(da);
            let len = mem.rd_u32(da + 8) as usize;
            let flags = mem.rd_u16(da + 12);
            out.extend_from_slice(&mem.read_bytes(addr, len));
            guard += 1;
            if flags & DESC_F_NEXT == 0 || guard > u32::from(qsz) {
                break;
            }
            let next = mem.rd_u16(da + 14);
            if next >= qsz {
                break;
            }
            idx = next;
        }
        out
    }

    /// The pre-migration completion, shared by the TX and RX oracles: it
    /// recovers the used index from guest RAM where the migrated path uses the
    /// device-owned cursor. The two agree for every fixture here because each
    /// starts from a zeroed used ring that no guest buffer aliases — the
    /// conformant case. Divergence under a scribbled index is asserted as a
    /// device-owned win by the ring-cursor tests below.
    fn reference_complete(core: &VsockTransportCore, used: u64, head: u16, written: u32, qsz: u16) {
        let mem = &core.mem;
        let used_idx = mem.rd_u16(used + 2);
        let slot = u64::from(used_idx % qsz);
        mem.wr_u16(used + 4 + slot * 8, head);
        mem.wr_u16(used + 6 + slot * 8, 0);
        mem.wr_u16(used + 8 + slot * 8, written as u16);
        mem.wr_u16(used + 10 + slot * 8, (written >> 16) as u16);
        mem.wr_u16(used + 2, used_idx.wrapping_add(1));
    }

    #[test]
    fn take_tx_packets_matches_reference_walk_byte_for_byte() {
        let base = 0x4000_0000u64;
        for qsz in [1u16, 2, 128, 256] {
            for (label, chains) in layouts_for(qsz) {
                // Run the pre-migration oracle over one RAM image...
                let mut core_ref = transport_with_ram(0x10000);
                let used = program_tx_queue(&mut core_ref, base, qsz, &chains);
                let (packets_ref, last_ref, int_ref) = reference_take_tx_packets(&core_ref, qsz);

                // ...and the migrated path over a byte-identical RAM image.
                let mut core_new = transport_with_ram(0x10000);
                program_tx_queue(&mut core_new, base, qsz, &chains);
                let packets_new = core_new.take_tx_packets();

                assert_eq!(
                    packets_new, packets_ref,
                    "packet list differs for qsz={qsz} layout={label}"
                );
                assert_eq!(
                    core_new.queues[TX].last_avail, last_ref,
                    "last_avail differs for qsz={qsz} layout={label}"
                );
                assert_eq!(
                    core_new.interrupt_status & 1,
                    u32::from(int_ref),
                    "interrupt_status differs for qsz={qsz} layout={label}"
                );
                let used_len = 4 + usize::from(qsz) * 8;
                assert_eq!(
                    core_new.mem.read_bytes(used, used_len),
                    core_ref.mem.read_bytes(used, used_len),
                    "used-ring bytes differ for qsz={qsz} layout={label}"
                );
            }
        }
    }

    #[test]
    fn take_tx_packets_bounds_a_cyclic_descriptor_chain() {
        let base = 0x4000_0000u64;
        let qsz = 4u16;
        let mut core = transport_with_ram(0x10000);
        let desc = base + 0x1000;
        let avail = base + 0x4000;
        let used = base + 0x5000;
        let buf = base + 0x6000;
        core.queues[TX] = Queue {
            num: u32::from(qsz),
            ready: 1,
            desc,
            avail,
            used,
            last_avail: 0,
            next_used: 0,
        };
        // 0 -> 1 -> 0 -> 1 -> ... with F_NEXT set on both: a cycle a 65535-hop
        // hand-rolled walk would have followed.
        for (idx, next) in [(0u16, 1u16), (1, 0)] {
            let da = desc + u64::from(idx) * 16;
            core.mem.write_bytes(da, &buf.to_le_bytes());
            core.mem.write_bytes(da + 8, &64u32.to_le_bytes());
            core.mem.wr_u16(da + 12, DESC_F_NEXT);
            core.mem.wr_u16(da + 14, next);
        }
        core.mem.write_bytes(buf, &[0xAA; 64]);
        core.mem.wr_u16(avail + 4, 0);
        core.mem.wr_u16(avail + 2, 1);

        let packets = core.take_tx_packets();
        // `ttl` seeded from the queue size caps the walk at `qsz` hops, so at most
        // `qsz * 64` bytes are gathered — bounded, no panic, no runaway allocation.
        assert!(packets.len() <= 1);
        if let Some((_, payload)) = packets.first() {
            assert!(payload.len() <= usize::from(qsz) * 64);
        }
        assert_eq!(core.mem.rd_u16(used + 2), 1, "head completed exactly once");
        assert_eq!(core.queues[TX].last_avail, 1);
    }

    #[test]
    fn take_tx_packets_stops_at_out_of_range_next_index() {
        let base = 0x4000_0000u64;
        let qsz = 4u16;
        let mut core = transport_with_ram(0x10000);
        let desc = base + 0x1000;
        let avail = base + 0x4000;
        let used = base + 0x5000;
        let buf = base + 0x6000;
        core.queues[TX] = Queue {
            num: u32::from(qsz),
            ready: 1,
            desc,
            avail,
            used,
            last_avail: 0,
            next_used: 0,
        };
        // Head descriptor claims a `next` index past the ring; the validated walk
        // must stop after the head rather than follow the out-of-range link (the
        // missing `next < qsz` bound the hand-rolled walk lacked).
        core.mem.write_bytes(desc, &buf.to_le_bytes());
        core.mem
            .write_bytes(desc + 8, &((HDR_LEN + 6) as u32).to_le_bytes());
        core.mem.wr_u16(desc + 12, DESC_F_NEXT);
        core.mem.wr_u16(desc + 14, 99);
        core.mem.write_bytes(buf, &[0xCD; HDR_LEN + 6]);
        core.mem.wr_u16(avail + 4, 0);
        core.mem.wr_u16(avail + 2, 1);

        let packets = core.take_tx_packets();
        assert_eq!(packets.len(), 1);
        assert_eq!(
            packets[0].1.len(),
            6,
            "only the head descriptor was gathered"
        );
        assert_eq!(core.mem.rd_u16(used + 2), 1);
    }

    // ---- RX virtio-queue migration: differential equivalence ----------------

    fn rx_hdr(dst_port: u32) -> VsockHdr {
        VsockHdr {
            src_cid: HOST_CID,
            dst_cid: GUEST_CID,
            src_port: mvm_agentd::vsock::EGRESS_PORT,
            dst_port,
            len: 0,
            typ: TYPE_STREAM,
            op: OP_RW,
            flags: 0,
            buf_alloc: HOST_BUF_ALLOC,
            fwd_cnt: 3,
        }
    }

    /// Faithful copy of the pre-migration hand-rolled RX delivery (`flush_rx` +
    /// `complete`), kept as the differential oracle. It reads the head descriptor
    /// directly and advances a locally-tracked `last_avail`; the migrated
    /// `flush_rx` must reproduce its delivered bytes, used-ring writes, residual
    /// `pending_rx`, `last_avail`, and interrupt bit exactly.
    fn reference_flush_rx(core: &mut VsockTransportCore) -> bool {
        let q = core.queues[RX];
        if q.ready == 0 || core.pending_rx.is_empty() {
            return false;
        }
        let Some(qsz) = super::super::validated_queue_size(q.num) else {
            return false;
        };
        let mut last = q.last_avail;
        let mut delivered = false;
        while !core.pending_rx.is_empty() {
            let avail_idx = core.mem.rd_u16(q.avail + 2);
            if last == avail_idx {
                break;
            }
            let (hdr, payload) = core
                .pending_rx
                .pop_front()
                .expect("loop guard checked non-empty");
            let slot = last % qsz;
            let head = core.mem.rd_u16(q.avail + 4 + u64::from(slot) * 2);
            let da = q.desc + u64::from(head) * 16;
            let addr = core.mem.rd_u64(da);
            let cap = core.mem.rd_u32(da + 8) as usize;
            let payload_cap = match cap.checked_sub(HDR_LEN) {
                Some(payload_cap) if payload_cap > 0 || payload.is_empty() => payload_cap,
                _ => {
                    core.pending_rx.push_front((hdr, payload));
                    break;
                }
            };
            let send_len = payload.len().min(payload_cap);
            let mut framed = hdr;
            framed.len = send_len as u32;
            let mut bytes = framed.to_bytes().to_vec();
            bytes.extend_from_slice(&payload[..send_len]);
            if core.mem.write_bytes(addr, &bytes) == 0 {
                core.pending_rx.push_front((hdr, payload));
                break;
            }
            reference_complete(core, q.used, head, bytes.len() as u32, qsz);
            core.interrupt_status |= 1;
            let remainder = &payload[send_len..];
            if !remainder.is_empty() {
                core.pending_rx.push_front((framed, remainder.to_vec()));
            }
            last = last.wrapping_add(1);
            delivered = true;
        }
        core.queues[RX].last_avail = last;
        delivered
    }

    /// Assert the migrated `flush_rx` is observationally identical to the oracle
    /// over `caps` guest RX buffers and `packets` queued for delivery: same return
    /// value, delivered buffer bytes, used-ring bytes, residual `pending_rx`,
    /// `last_avail`, and interrupt bit.
    fn assert_rx_matches_reference(label: &str, caps: &[usize], packets: &[(VsockHdr, Vec<u8>)]) {
        let mut core_ref = transport();
        let buffers_ref = configure_rx_buffers(&mut core_ref, caps);
        for pkt in packets {
            core_ref.pending_rx.push_back(pkt.clone());
        }
        let used = core_ref.queues[RX].used;
        let ret_ref = reference_flush_rx(&mut core_ref);

        let mut core_new = transport();
        let buffers_new = configure_rx_buffers(&mut core_new, caps);
        for pkt in packets {
            core_new.pending_rx.push_back(pkt.clone());
        }
        let ret_new = core_new.flush_rx();

        assert_eq!(ret_new, ret_ref, "return value differs for {label}");
        assert_eq!(
            buffers_new, buffers_ref,
            "buffer layout differs for {label}"
        );
        for (i, (&buf, &cap)) in buffers_ref.iter().zip(caps).enumerate() {
            assert_eq!(
                core_new.mem.read_bytes(buf, cap),
                core_ref.mem.read_bytes(buf, cap),
                "buffer {i} bytes differ for {label}"
            );
        }
        let used_len = 4 + caps.len() * 8;
        assert_eq!(
            core_new.mem.read_bytes(used, used_len),
            core_ref.mem.read_bytes(used, used_len),
            "used-ring bytes differ for {label}"
        );
        assert_eq!(
            core_new.pending_rx, core_ref.pending_rx,
            "pending_rx residue differs for {label}"
        );
        assert_eq!(
            core_new.queues[RX].last_avail, core_ref.queues[RX].last_avail,
            "last_avail differs for {label}"
        );
        assert_eq!(
            core_new.interrupt_status & 1,
            core_ref.interrupt_status & 1,
            "interrupt bit differs for {label}"
        );
    }

    #[test]
    fn flush_rx_matches_reference_walk_byte_for_byte() {
        // Single buffer, roomy: whole payload delivered in one RX buffer.
        assert_rx_matches_reference(
            "single-buffer",
            &[HDR_LEN + 16],
            &[(rx_hdr(1500), b"hello".to_vec())],
        );
        // Multi-buffer split: a 10-byte payload spans two smaller RX buffers
        // (6 + 4) — the byte-identical case from the retained split test.
        assert_rx_matches_reference(
            "multi-buffer-split",
            &[HDR_LEN + 6, HDR_LEN + 4],
            &[(rx_hdr(1500), b"abcdefghij".to_vec())],
        );
        // Header-only buffer with an empty payload: delivered (0-length data ok).
        assert_rx_matches_reference("empty-payload", &[HDR_LEN], &[(rx_hdr(1500), Vec::new())]);
        // Buffer too small for even one payload byte: packet stays queued, used
        // ring not advanced.
        assert_rx_matches_reference("too-small", &[HDR_LEN], &[(rx_hdr(1500), b"xyz".to_vec())]);
        // Two packets into two buffers: both delivered in order.
        assert_rx_matches_reference(
            "two-packets",
            &[HDR_LEN + 8, HDR_LEN + 8],
            &[
                (rx_hdr(1500), b"one".to_vec()),
                (rx_hdr(1600), b"two".to_vec()),
            ],
        );
        // More packets than buffers: first delivered, second left queued.
        assert_rx_matches_reference(
            "packets-exceed-buffers",
            &[HDR_LEN + 8],
            &[
                (rx_hdr(1500), b"aaa".to_vec()),
                (rx_hdr(1600), b"bbb".to_vec()),
            ],
        );
        // Payload larger than a single buffer but only one buffer available: the
        // buffer is filled, the remainder re-framed and left queued.
        assert_rx_matches_reference(
            "partial-fill-remainder-queued",
            &[HDR_LEN + 4],
            &[(rx_hdr(1500), b"abcdefgh".to_vec())],
        );
    }

    #[test]
    fn flush_rx_matches_reference_on_bogus_rx_descriptor() {
        // A single RX buffer whose descriptor addr points past mapped RAM. The
        // migrated writable-descriptor path and the oracle must agree: nothing is
        // delivered, the packet stays queued, and the used ring is not advanced.
        let program = |core: &mut VsockTransportCore| {
            let base = 0x4000_0000;
            let desc = base + 0x100;
            let avail = base + 0x200;
            let used = base + 0x300;
            core.queues[RX] = Queue {
                num: 1,
                ready: 1,
                desc,
                avail,
                used,
                last_avail: 0,
                next_used: 0,
            };
            core.mem.wr_u16(avail + 2, 1);
            core.mem.wr_u16(avail + 4, 0);
            let bogus = base + 0x1_0000;
            core.mem.write_bytes(desc, &bogus.to_le_bytes());
            core.mem
                .write_bytes(desc + 8, &((HDR_LEN + 8) as u32).to_le_bytes());
            core.mem.wr_u16(desc + 12, DESC_F_WRITE);
            core.queue_host_packet(1, 2, OP_RW, b"payload!");
        };

        let mut core_ref = transport();
        program(&mut core_ref);
        let ret_ref = reference_flush_rx(&mut core_ref);

        let mut core_new = transport();
        program(&mut core_new);
        let ret_new = core_new.flush_rx();

        assert_eq!(ret_new, ret_ref);
        assert!(!ret_new, "bogus addr delivers nothing");
        assert_eq!(core_new.pending_rx, core_ref.pending_rx);
        assert_eq!(core_new.pending_rx.len(), 1, "packet left queued");
        let used = core_new.queues[RX].used;
        assert_eq!(core_new.mem.rd_u16(used + 2), core_ref.mem.rd_u16(used + 2));
        assert_eq!(core_new.mem.rd_u16(used + 2), 0, "used ring not advanced");
        assert_eq!(
            core_new.queues[RX].last_avail, core_ref.queues[RX].last_avail,
            "last_avail not advanced past the un-consumed entry"
        );
        assert_eq!(core_new.queues[RX].last_avail, 0);
    }

    // ---- device-owned ring cursors: cross-drain + lifecycle -----------------

    /// MMIO register offsets the lifecycle tests drive, named for readability
    /// (the device's `write_register` matches on the raw offsets).
    const R_QUEUE_SEL: u64 = 0x030;
    const R_QUEUE_READY: u64 = 0x044;
    const R_STATUS: u64 = 0x070;

    /// A transport with two single-descriptor TX chains programmed, drained once
    /// — so both device-owned TX cursors sit at 1 with one chain unpublished.
    /// Returns the core and its (available ring, used ring) addresses.
    fn tx_drained_once(qsz: u16) -> (VsockTransportCore, u64, u64) {
        let base = 0x4000_0000u64;
        let chains = vec![single_chain(1000, b"first"), single_chain(1001, b"second")];
        let mut core = transport_with_ram(0x10000);
        let used = program_tx_queue(&mut core, base, qsz, &chains);
        let avail = base + 0x4000;
        core.mem.wr_u16(avail + 2, 1);
        assert_eq!(
            core.take_tx_packets().len(),
            1,
            "first drain takes one packet"
        );
        (core, avail, used)
    }

    /// Read the selected queue's cursors as a pair.
    fn cursors(core: &VsockTransportCore, slot: usize) -> (u16, u16) {
        (core.queues[slot].last_avail, core.queues[slot].next_used)
    }

    /// Cross-drain witness: a guest that rewrites `used.idx` between two TX
    /// notifies cannot steer where the device records its next completion.
    #[test]
    fn take_tx_packets_used_index_is_device_owned_across_drains() {
        let (mut core, avail, used) = tx_drained_once(4);
        assert_eq!(
            core.mem.rd_u16(used + 2),
            1,
            "first drain published index 1"
        );
        assert_eq!(
            core.mem.rd_u32(used + 4),
            0,
            "slot 0 records the first head"
        );

        // Between drains the guest scribbles its own value into `used.idx`.
        core.mem.wr_u16(used + 2, 0);

        core.mem.wr_u16(avail + 2, 2);
        assert_eq!(core.take_tx_packets().len(), 1);
        assert_eq!(
            core.mem.rd_u16(used + 2),
            2,
            "the device republished its own count, not the guest's"
        );
        assert_eq!(
            core.mem.rd_u32(used + 4),
            0,
            "slot 0 still holds the first completion"
        );
        assert_eq!(
            core.mem.rd_u32(used + 12),
            1,
            "the second completion landed at the device's next slot"
        );
        assert_eq!(cursors(&core, TX), (2, 2));

        // The pre-migration walk re-read the index per completion, so the same
        // scribble steered its second completion on top of the first.
        let (core_ref, avail_ref, used_ref) = tx_drained_once(4);
        core_ref.mem.wr_u16(used_ref + 2, 0);
        core_ref.mem.wr_u16(avail_ref + 2, 2);
        let (_, _, interrupted) = reference_take_tx_packets(&core_ref, 4);
        assert!(interrupted);
        assert_eq!(
            core_ref.mem.rd_u16(used_ref + 2),
            1,
            "the retired walk followed the guest's index"
        );
        assert_eq!(
            core_ref.mem.rd_u32(used_ref + 4),
            1,
            "and overwrote slot 0 with the second head"
        );
    }

    #[test]
    fn queue_ready_zero_rewinds_the_ring_cursors() {
        let (mut core, avail, used) = tx_drained_once(4);
        assert_eq!(
            cursors(&core, TX),
            (1, 1),
            "one chain consumed and completed"
        );

        core.write_register(R_QUEUE_SEL, TX as u64);
        core.write_register(R_QUEUE_READY, 0);
        assert_eq!(core.queues[TX].ready, 0);
        assert_eq!(
            cursors(&core, TX),
            (0, 0),
            "detaching the queue rewinds both cursors"
        );

        // The driver reactivates with a freshly-zeroed ring: the first chain is
        // taken again and its completion lands at used slot 0.
        core.mem.wr_u16(used + 2, 0);
        core.mem.wr_u16(avail + 2, 0);
        core.write_register(R_QUEUE_READY, 1);
        core.mem.wr_u16(avail + 2, 1);
        assert_eq!(core.take_tx_packets().len(), 1);
        assert_eq!(
            core.mem.rd_u16(used + 2),
            1,
            "completion published at index 1"
        );
        assert_eq!(core.mem.rd_u32(used + 4), 0, "and recorded at slot 0");
    }

    #[test]
    fn device_reset_rewinds_every_queues_ring_cursors() {
        let (mut core, _avail, _used) = tx_drained_once(4);
        // The RX queue is not exercised by the TX fixture; give it cursors of its
        // own so the reset is observed across the whole device.
        core.queues[RX].last_avail = 5;
        core.queues[RX].next_used = 5;

        core.write_register(R_STATUS, 0xf);
        assert_eq!(
            (core.queues[TX].last_avail, core.queues[RX].next_used),
            (1, 5),
            "a non-zero status write leaves the cursors alone"
        );

        core.write_register(R_STATUS, 0);
        for slot in 0..NUM_QUEUES {
            assert_eq!(
                cursors(&core, slot),
                (0, 0),
                "queue {slot} not rewound by the device reset"
            );
        }
    }

    #[test]
    fn redundant_queue_ready_write_does_not_rewind_a_live_ring() {
        let (mut core, avail, used) = tx_drained_once(4);

        core.write_register(R_QUEUE_SEL, TX as u64);
        core.write_register(R_QUEUE_READY, 1);
        assert_eq!(
            cursors(&core, TX),
            (1, 1),
            "re-arming an already-ready queue must not rewind it"
        );

        core.mem.wr_u16(avail + 2, 2);
        assert_eq!(core.take_tx_packets().len(), 1);
        assert_eq!(core.mem.rd_u16(used + 2), 2);
        assert_eq!(
            core.mem.rd_u32(used + 12),
            1,
            "slot 1 records the second chain's head"
        );
    }
}
