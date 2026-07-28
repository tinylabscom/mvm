// Fuzz the virtio-vsock device's virtqueue geometry + descriptor-table walk.
//
// The guest programs queue size, the descriptor/avail/used ring base addresses,
// and the descriptor table itself through untrusted MMIO writes and guest RAM.
// A hostile geometry (a `QueueNum` whose low 16 bits are zero, so it is nonzero
// yet truncates to a zero modulus) or a hostile descriptor chain (cyclic `next`
// links, oversized lengths) must not panic the host VMM process or drive it into
// an unbounded allocation — both are guest-triggerable host DoS.
//
// This target feeds a random RAM image (the descriptor/avail/used rings live in
// it) plus a random register-programming sequence into the transport and asserts
// the run completes with no panic. Termination and bounded allocation are
// structural: the validated-geometry gate leaves an illegal ring unserviced, and
// the descriptor walk's live-descriptor budget caps a chain at the (validated,
// <= 256) queue size regardless of cyclic links. The scratch RAM, avail-index,
// descriptor count, and payloads are all bounded so no single input can force a
// large-but-"legal" allocation that would mask the property under test.

#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use mvm_runtime::vmm::vsock::FuzzTransportDriver;

// Guest RAM image size. Small on purpose: it bounds every read the transport can
// make (out-of-range reads zero-fill), so the accumulated descriptor-walk buffer
// stays a small multiple of this even for the most hostile chain.
const RAM_SIZE: usize = 0x8000;
const RAM_BASE: u64 = 0;

// Fixed in-RAM layout the harness programs the rings at. Kept within RAM so the
// transport actually walks the fuzz-authored tables (out-of-RAM bases would just
// read zeros and service nothing).
const DESC_OFF: u64 = 0x0000; // 256 descriptors * 16 bytes = 0x1000
const AVAIL_OFF: u64 = 0x1000;
const USED_OFF: u64 = 0x1400;
const BUF_OFF: usize = 0x2000; // remainder: buffers descriptors can point at

// Register offsets in the virtio-mmio window (see `VsockTransportCore::write_register`).
const R_QUEUE_SEL: u64 = 0x030;
const R_QUEUE_NUM: u64 = 0x038;
const R_QUEUE_READY: u64 = 0x044;
const R_DESC_LO: u64 = 0x080;
const R_DESC_HI: u64 = 0x084;
const R_AVAIL_LO: u64 = 0x090;
const R_AVAIL_HI: u64 = 0x094;
const R_USED_LO: u64 = 0x0a0;
const R_USED_HI: u64 = 0x0a4;

const QUEUE_RX: u64 = 0;
const QUEUE_TX: u64 = 1;

// Bounds that keep any single input's work (and thus allocation) finite while
// still reaching both the divide-by-zero arms and the descriptor-chain walk.
const MAX_DESC: usize = 256; // one full descriptor table
const MAX_AVAIL: usize = 16; // avail-ring entries serviced per notify
const MAX_PKTS: usize = 32; // pre-queued host->guest packets
const MAX_PAYLOAD: usize = 512;
const MAX_REGS: usize = 64; // free-form extra register writes

struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

struct HostPkt {
    src_port: u32,
    dst_port: u32,
    op: u16,
    payload: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    // A short/empty input just exercises the empty-ring early-outs; that is fine.
    let _ = drive(Unstructured::new(data));
});

fn drive(mut u: Unstructured) -> arbitrary::Result<()> {
    // ---- parse the whole input up front (nothing here touches guest RAM) ----
    let queue_num: u32 = u.arbitrary()?;

    let ndesc = u.int_in_range(0..=MAX_DESC)?;
    let mut descs = Vec::with_capacity(ndesc);
    for _ in 0..ndesc {
        descs.push(Desc {
            addr: u.arbitrary()?,
            len: u.arbitrary()?,
            flags: u.arbitrary()?,
            next: u.arbitrary()?,
        });
    }

    let navail = u.int_in_range(0..=MAX_AVAIL)?;
    let mut heads = Vec::with_capacity(navail);
    for _ in 0..navail {
        heads.push(u.arbitrary::<u16>()?);
    }

    let npkt = u.int_in_range(0..=MAX_PKTS)?;
    let mut pkts = Vec::with_capacity(npkt);
    for _ in 0..npkt {
        let src_port = u.arbitrary()?;
        let dst_port = u.arbitrary()?;
        let op = u.arbitrary()?;
        let plen = u.int_in_range(0..=MAX_PAYLOAD.min(u.len()))?;
        let payload = u.bytes(plen)?.to_vec();
        pkts.push(HostPkt {
            src_port,
            dst_port,
            op,
            payload,
        });
    }

    let nreg = u.int_in_range(0..=MAX_REGS)?;
    let mut regs = Vec::with_capacity(nreg);
    for _ in 0..nreg {
        regs.push((u.arbitrary::<u16>()?, u.arbitrary::<u64>()?));
    }

    // Remaining bytes seed the buffer region descriptors can point at.
    let seed = u.take_rest();

    // ---- lay out guest RAM (must complete before the transport holds the ptr) ----
    let mut ram = vec![0u8; RAM_SIZE];
    let seed_len = seed.len().min(RAM_SIZE - BUF_OFF);
    ram[BUF_OFF..BUF_OFF + seed_len].copy_from_slice(&seed[..seed_len]);
    write_descriptors(&mut ram, &descs);
    write_avail_ring(&mut ram, &heads);

    // ---- construct the transport over the laid-out RAM and drive it ----
    // SAFETY: `ram` is a live, unmoved, writable allocation of `RAM_SIZE` bytes
    // that outlives `drv`; nothing else aliases it once the driver holds the ptr.
    let mut drv = unsafe { FuzzTransportDriver::new(ram.as_mut_ptr(), RAM_BASE, RAM_SIZE) };

    for p in &pkts {
        drv.queue_host_packet(p.src_port, p.dst_port, p.op, &p.payload);
    }

    // Program both workload queues with the (possibly hostile) geometry so every
    // run drives `QueueNum` into both the TX (`take_tx_packets`) and RX
    // (`flush_rx`) service paths, plus the descriptor walk.
    program_queue(&mut drv, QUEUE_RX, queue_num);
    program_queue(&mut drv, QUEUE_TX, queue_num);

    // Free-form register writes exercise the rest of the register decode. The
    // ring-base and queue-size registers are excluded: re-pointing a base out of
    // the bounded scratch layout could aim the avail index at a large in-RAM
    // value and drive the (accepted, u16-bounded) per-notify slot count into a
    // huge allocation that is neither the panic nor the single-chain class this
    // target guards.
    for (offset, value) in &regs {
        let off = u64::from(*offset);
        if is_ring_geometry_register(off) {
            continue;
        }
        drv.write_register(off, *value);
    }

    // Service both queues (a notify to queue 1 runs TX then RX).
    drv.notify(QUEUE_TX as u32);
    drv.notify(QUEUE_RX as u32);

    // The only host-retained buffer is the pending-RX queue; RX servicing must
    // drain (never grow) it, so it stays bounded by what we pre-queued.
    assert!(
        drv.pending_rx_len() <= pkts.len(),
        "pending_rx grew during servicing: {} > {}",
        drv.pending_rx_len(),
        pkts.len()
    );

    Ok(())
}

fn write_descriptors(ram: &mut [u8], descs: &[Desc]) {
    for (i, d) in descs.iter().take(MAX_DESC).enumerate() {
        let da = DESC_OFF as usize + i * 16;
        ram[da..da + 8].copy_from_slice(&d.addr.to_le_bytes());
        ram[da + 8..da + 12].copy_from_slice(&d.len.to_le_bytes());
        ram[da + 12..da + 14].copy_from_slice(&d.flags.to_le_bytes());
        ram[da + 14..da + 16].copy_from_slice(&d.next.to_le_bytes());
    }
}

fn write_avail_ring(ram: &mut [u8], heads: &[u16]) {
    let n = heads.len().min(MAX_AVAIL);
    let base = AVAIL_OFF as usize;
    // avail.idx at +2 — set one past the last serviced slot so the drain loop
    // runs (and, under a hostile size, reaches the modulus).
    ram[base + 2..base + 4].copy_from_slice(&(n as u16).to_le_bytes());
    for (i, head) in heads.iter().take(n).enumerate() {
        let ao = base + 4 + i * 2;
        ram[ao..ao + 2].copy_from_slice(&head.to_le_bytes());
    }
}

fn program_queue(drv: &mut FuzzTransportDriver, sel: u64, queue_num: u32) {
    drv.write_register(R_QUEUE_SEL, sel);
    drv.write_register(R_QUEUE_NUM, u64::from(queue_num));
    drv.write_register(R_DESC_LO, DESC_OFF & 0xffff_ffff);
    drv.write_register(R_DESC_HI, DESC_OFF >> 32);
    drv.write_register(R_AVAIL_LO, AVAIL_OFF & 0xffff_ffff);
    drv.write_register(R_AVAIL_HI, AVAIL_OFF >> 32);
    drv.write_register(R_USED_LO, USED_OFF & 0xffff_ffff);
    drv.write_register(R_USED_HI, USED_OFF >> 32);
    drv.write_register(R_QUEUE_READY, 1);
}

fn is_ring_geometry_register(offset: u64) -> bool {
    matches!(
        offset,
        R_QUEUE_NUM | R_DESC_LO | R_DESC_HI | R_AVAIL_LO | R_AVAIL_HI | R_USED_LO | R_USED_HI
    )
}
