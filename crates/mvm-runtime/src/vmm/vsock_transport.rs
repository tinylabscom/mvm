use std::collections::HashMap;

use super::guest_mem::GuestMem;

pub(crate) const VIRTIO_MAGIC: u32 = 0x7472_6976;
pub(crate) const VIRTIO_VERSION: u32 = 2;
pub(crate) const VIRTIO_ID_VSOCK: u32 = 19;
pub(crate) const VIRTIO_VENDOR: u32 = 0x4d56_4d76;

pub(crate) const QUEUE_SIZE_MAX: u32 = 256;
pub(crate) const NUM_QUEUES: usize = 3;
const RX: usize = 0;
const TX: usize = 1;

const VIRTQ_DESC_F_NEXT: u16 = 1;

pub(crate) const HDR_LEN: usize = 44;
pub(crate) const HOST_CID: u64 = 2;
pub(crate) const GUEST_CID: u64 = 3;
pub(crate) const HOST_BUF_ALLOC: u32 = 256 * 1024;

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
}

#[derive(Default, Clone, Copy, Debug)]
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
    pub(crate) fn to_bytes(self) -> [u8; HDR_LEN] {
        let mut b = [0u8; HDR_LEN];
        b[0..8].copy_from_slice(&self.src_cid.to_le_bytes());
        b[8..16].copy_from_slice(&self.dst_cid.to_le_bytes());
        b[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        b[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        b[24..28].copy_from_slice(&self.len.to_le_bytes());
        b[28..30].copy_from_slice(&self.typ.to_le_bytes());
        b[30..32].copy_from_slice(&self.op.to_le_bytes());
        b[32..36].copy_from_slice(&self.flags.to_le_bytes());
        b[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        b[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        b
    }

    pub(crate) fn from_bytes(b: &[u8]) -> Self {
        let u64a = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().expect("hdr u64"));
        let u32a = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().expect("hdr u32"));
        let u16a = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().expect("hdr u16"));
        Self {
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
    pub(crate) recv_cnt: HashMap<(u32, u32), u32>,
    pub(crate) pending_rx: Vec<(VsockHdr, Vec<u8>)>,
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
            pending_rx: Vec::new(),
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
            0x034 => QUEUE_SIZE_MAX,
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
            0x044 => self.cur_mut().ready = v,
            0x070 => self.status = v,
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
        if q.ready == 0 || q.num == 0 {
            return Vec::new();
        }
        let qsz = q.num as u16;
        let avail_idx = self.mem.rd_u16(q.avail + 2);
        let mut last = q.last_avail;
        let mut packets = Vec::new();
        while last != avail_idx {
            let slot = last % qsz;
            let head = self.mem.rd_u16(q.avail + 4 + u64::from(slot) * 2);
            let buf = self.read_chain(q.desc, head, qsz);
            if buf.len() >= HDR_LEN {
                let hdr = VsockHdr::from_bytes(&buf[..HDR_LEN]);
                packets.push((hdr, buf[HDR_LEN..].to_vec()));
            }
            self.complete(TX, head, 0);
            last = last.wrapping_add(1);
        }
        self.queues[TX].last_avail = last;
        packets
    }

    pub(crate) fn add_recv(&mut self, inbound: &VsockHdr, n: u32) {
        let entry = self
            .recv_cnt
            .entry((inbound.dst_port, inbound.src_port))
            .or_default();
        *entry = entry.wrapping_add(n);
    }

    pub(crate) fn remove_recv(&mut self, host_port: u32, guest_port: u32) {
        self.recv_cnt.remove(&(host_port, guest_port));
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
        self.pending_rx.push((hdr, payload.to_vec()));
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
        self.pending_rx.push((reply, payload.to_vec()));
    }

    pub(crate) fn flush_rx(&mut self) -> bool {
        let q = self.queues[RX];
        if q.ready == 0 || q.num == 0 || self.pending_rx.is_empty() {
            return false;
        }
        let qsz = q.num as u16;
        let mut last = q.last_avail;
        let mut delivered = false;
        while !self.pending_rx.is_empty() {
            let avail_idx = self.mem.rd_u16(q.avail + 2);
            if last == avail_idx {
                break;
            }
            let (mut hdr, payload) = self.pending_rx.remove(0);
            let slot = last % qsz;
            let head = self.mem.rd_u16(q.avail + 4 + u64::from(slot) * 2);
            let da = q.desc + u64::from(head) * 16;
            let addr = self.mem.rd_u64(da);
            let cap = self.mem.rd_u32(da + 8) as usize;
            let payload_cap = match cap.checked_sub(HDR_LEN) {
                Some(payload_cap) if payload_cap > 0 || payload.is_empty() => payload_cap,
                _ => {
                    self.pending_rx.insert(0, (hdr, payload));
                    break;
                }
            };
            let send_len = payload.len().min(payload_cap);
            let remainder = payload[send_len..].to_vec();
            hdr.len = send_len as u32;
            let mut bytes = hdr.to_bytes().to_vec();
            bytes.extend_from_slice(&payload[..send_len]);
            self.mem.write_bytes(addr, &bytes);
            self.complete(RX, head, bytes.len() as u32);
            if !remainder.is_empty() {
                self.pending_rx.insert(0, (hdr, remainder));
            }
            last = last.wrapping_add(1);
            delivered = true;
        }
        self.queues[RX].last_avail = last;
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
            .get(&(host_port, guest_port))
            .copied()
            .unwrap_or(0)
    }

    fn read_chain(&self, desc: u64, head: u16, qsz: u16) -> Vec<u8> {
        let mut out = Vec::new();
        let mut idx = head;
        let mut guard = 0u32;
        loop {
            let da = desc + u64::from(idx) * 16;
            let addr = self.mem.rd_u64(da);
            let len = self.mem.rd_u32(da + 8) as usize;
            let flags = self.mem.rd_u16(da + 12);
            out.extend_from_slice(&self.mem.read_bytes(addr, len));
            guard += 1;
            if flags & VIRTQ_DESC_F_NEXT == 0 || guard > u32::from(qsz) {
                break;
            }
            idx = self.mem.rd_u16(da + 14);
        }
        out
    }

    fn complete(&mut self, q: usize, head: u16, written: u32) {
        let used = self.queues[q].used;
        let qsz = self.queues[q].num as u16;
        let used_idx = self.mem.rd_u16(used + 2);
        let slot = u64::from(used_idx % qsz);
        self.mem.wr_u16(used + 4 + slot * 8, head);
        self.mem.wr_u16(used + 6 + slot * 8, 0);
        self.mem.wr_u16(used + 8 + slot * 8, written as u16);
        self.mem
            .wr_u16(used + 10 + slot * 8, (written >> 16) as u16);
        self.mem.wr_u16(used + 2, used_idx.wrapping_add(1));
        self.interrupt_status |= 1;
    }
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
        let ram = vec![0u8; 0x1000].leak();
        // SAFETY: leaked for the test.
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
        };
        core.mem.wr_u16(avail + 2, caps.len() as u16);
        for (index, cap) in caps.iter().enumerate() {
            let buf = base + 0x400 + (index as u64 * 0x100);
            buffers.push(buf);
            let desc_addr = desc + (index as u64 * 16);
            core.mem.write_bytes(desc_addr, &buf.to_le_bytes());
            core.mem
                .write_bytes(desc_addr + 8, &(*cap as u32).to_le_bytes());
            core.mem
                .wr_u16(avail + 4 + (index as u64 * 2), index as u16);
        }
        buffers
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
        core.pending_rx.push((hdr, b"abcdefghij".to_vec()));

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
}
