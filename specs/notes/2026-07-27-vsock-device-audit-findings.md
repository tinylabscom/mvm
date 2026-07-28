# virtio-vsock device audit — findings (2026-07-27)

Read-only security audit of the hand-rolled virtio-vsock device in the in-house
(HVF/KVM) VMM. Scope: `crates/mvm-runtime/src/vmm/vsock.rs`,
`vmm/vsock_handlers/mod.rs`, `vmm/vsock_transport.rs`, `vmm/vsock_io.rs`,
`vmm/guest_mem.rs`, `vmm/virtio.rs`, plus the bridge implementations
(`vmm/agent_bridge.rs`, `vmm/console_bridge.rs`,
`vsock_egress_bridge/substitution_bridge.rs`) and the run-loop / hypervisor seam
(`vmm/run.rs`, `vmm/hv.rs`, `vmm/device.rs`).

The vsock device is the highest-risk trust boundary in the vsock-only security
model: guest-programmed virtqueue geometry, descriptor addresses/lengths/flags,
packet-header fields, and per-connection credit all cross from an untrusted
guest into host code.

**Threat-model note.** One guest = one workload = (effectively) one VMM process.
So a guest crashing or OOMing *its own* VMM is primarily a self-DoS. The findings
below are ranked with that in mind, but note that (a) a hostile-guest *panic* is
materially worse than a clean guest halt — it can tear the host process down
abruptly mid-flight (audit-log flush, endpoint sockets, temp state), and (b) the
per-VM substitution/broker endpoint is a *shared host* process that a guest can
drive into resource exhaustion (F2), which reaches beyond the single VM.

---

## URGENT — guest-triggerable divide-by-zero panic in the virtqueue ring walk (VMM DoS)

**This is a live, trivially-reachable crash from a handful of guest MMIO register
writes. It affects all three virtio devices (vsock, blk, fs) from one root
cause, and it should reprioritize the hardening track toward adopting a validated
queue primitive first.**

### F1 — unvalidated `queue_num` truncated to `u16` is used as a modulus → panic

Severity: **High** (availability; guest → host-process panic). Not memory
corruption — see "Overall verdict".

Untrusted-input path: the guest programs the queue size through the virtio-mmio
`QueueNum` register. `write_register` stores it verbatim, with no clamp against
the advertised maximum:

- `vsock_transport.rs:147` — `0x038 => self.cur_mut().num = v,` (`v` is the raw
  guest `u32`; no validation).
- `vsock_transport.rs:131` — the `QueueNumMax` read returns `QUEUE_SIZE_MAX`
  (256), but that is advisory; nothing enforces it on the write side.

The size is then narrowed with a truncating cast and used as a divisor:

- `take_tx_packets` — `vsock_transport.rs:168` `let qsz = q.num as u16;` then
  `vsock_transport.rs:173` `let slot = last % qsz;`.
- `flush_rx` — `vsock_transport.rs:242` / `:251`.
- `complete` — `vsock_transport.rs:317` `let qsz = self.queues[q].num as u16;`
  then `:319` `let slot = u64::from(used_idx % qsz);`.

The early guards only reject `q.num == 0` (`vsock_transport.rs:165`, `:239`), not
a *nonzero* `u32` whose low 16 bits are zero. Set `queue_num = 0x1_0000` (65536,
or any multiple of it): `q.num == 0` is false, but `q.num as u16 == 0`, so
`last % qsz` is `n % 0` → **integer divide-by-zero panic**.

Concrete failure scenario (fully guest-driven, no host cooperation):
1. Guest selects the TX queue, writes `QueueNum = 0x1_0000`, `QueueReady = 1`,
   programs `desc/avail/used` base addresses, and writes an avail-ring index
   (`avail + 2`) different from `last_avail`.
2. Guest writes `QueueNotify = 1`.
3. vCPU MMIO exit → `run::dispatch` (`run.rs:78`) → `VirtioVsock::write`
   (`vsock.rs:289`) → `on_notify(1)` (`vsock.rs:110`) → `take_tx_packets` →
   `last % qsz` with `qsz == 0` → panic on the vCPU thread.

An even cheaper trigger goes through `flush_rx`: any handled `OP_REQUEST` queues a
reply into `pending_rx` (`vsock.rs:129`), so with `RX` `queue_num = 0x1_0000` the
next `on_notify` reaches `flush_rx`'s `last % qsz` (`vsock_transport.rs:251`) and
panics.

Impact: the panic unwinds the vCPU thread (the device code runs in Rust *after*
`hv.step()` returns — `run.rs:128` — so it does not unwind across the HVF FFI
boundary, i.e. not UB). But it kills the vCPU thread → the guest is dead, and the
`Mutex<VsockShared>` is poisoned (tolerated everywhere via
`unwrap_or_else(|e| e.into_inner())`, e.g. `vsock.rs:188`). Under a
`panic = "abort"` profile the whole VMM process aborts. Either way this is a
guest-controlled crash of host code, reachable in ~5 register writes.

Sibling instances of the identical root cause (same fix eliminates all):
- `VirtioBlk::process_queue` — `virtio.rs:286` (`R_QUEUE_NUM => queue_num = v`),
  `virtio.rs:308` (`qsz = self.queue_num as u16`), `virtio.rs:319`
  (`slot = self.last_avail % qsz`) and the used-ring slot at `:327`.
- `VirtioFs::process_queue` — `virtio.rs:569`, `virtio.rs:611`, `virtio.rs:616`,
  `virtio.rs:621`.

Would an audited rust-vmm primitive eliminate the class? **Yes, entirely.**
`virtio-queue`'s `Queue` validates the negotiated size (rejects zero, sizes above
`max_size`, and non-power-of-two sizes) before the ring is usable, and its
`DescriptorChain` iterator derives its live-descriptor budget from that validated
size. A `queue_num` of 65536 is simply un-representable as an active queue, so the
`% qsz` divide-by-zero cannot arise. This is the single strongest argument for the
migration and motivates the first hardening slice.

---

## High / medium findings

### F2 — unbounded host state and host FDs keyed by the guest-chosen `src_port` (resource-exhaustion DoS)

Severity: **Medium-High** (availability; reaches the shared endpoint host
process). Untrusted-input path: the guest fully controls `src_port` on every TX
packet, and the device keys per-connection host state on it with no cap and only
explicit-`OP_SHUTDOWN` eviction.

- Credit map: `recv_cnt: HashMap<(u32,u32), u32>` grows one entry per distinct
  `(dst_port, src_port)` via `add_recv` (`vsock_transport.rs:187-193`), removed
  only on `OP_SHUTDOWN` (`vsock.rs:139-142`, `mod.rs:311`, `:357`). A guest that
  streams `OP_RW` from a walking `src_port` (up to 2^32 values) without ever
  sending `OP_SHUTDOWN` grows the map without bound.
- Worse — real host file descriptors: the egress/broker `StreamRelayHandler`
  opens a **new** `UnixStream` to the per-VM endpoint on the first frame of each
  distinct `conn_id` (= guest `src_port`):
  `substitution_bridge.rs:110-128` (`relay_guest_bytes` → `UnixStream::connect`),
  stored in `conns` with no ceiling, plus a parallel `headers` map in the handler
  (`mod.rs:321`, `:345`). Spraying distinct `src_port`s opens unbounded host
  sockets → host FD exhaustion against the shared substitution/broker endpoint.

Concrete scenario: guest sends N single-byte `OP_RW` frames on the egress port,
each with a fresh `src_port`, never shutting down. The device opens N host
`UnixStream`s and retains N `recv_cnt`/`headers` entries. N is bounded only by the
per-process FD limit / host memory, not by any device policy.

rust-vmm relevance: this is connection-tracking *policy*, not something
`virtio-queue`/`vm-memory` fix directly. The remedy is a typed per-device
connection table with a max-concurrent-streams cap (reject/`OP_RST` past the cap)
and idle-eviction; sequence it in the hardening plan alongside the queue work.

### F3 — descriptor-chain amplification: no `next` bound, cyclic chains, oversized `qsz` (memory-amplification DoS)

Severity: **Medium** (availability). Untrusted-input path: guest-authored
descriptor table walked by `read_chain`.

`read_chain` (`vsock_transport.rs:296-313`) follows the chain via
`idx = self.mem.rd_u16(da + 14)` (`:310`) with **no `next < qsz` bounds check** —
the only stop conditions are `F_NEXT` clear or the iteration counter
`guard > qsz` (`:307`). Because `qsz = q.num as u16` can be as large as 65535
(F1), and `next` may point back into the same descriptor (a cycle), a guest can
build a 65535-long chain whose descriptors each carry a large `len`. Each hop does
`out.extend_from_slice(&self.mem.read_bytes(addr, len))` (`:305`); `read_bytes`
bounds-checks `len` against the region (so `len ≤ ram_size` — `guest_mem.rs:86`),
but the accumulated `out` Vec can reach ~`65535 × ram_size` → allocation blow-up /
OOM.

Notably, the sibling block/fs walkers *do* guard this: `virtio.rs:366`
(`if next >= qsz { break; }`) and `virtio.rs:662`. The vsock `read_chain` omits
the equivalent check.

rust-vmm relevance: `virtio-queue`'s `DescriptorChain::next` returns `None` once
`ttl == 0 || next_index >= queue_size` and decrements a `ttl` seeded from the
*validated* queue size — verified from crate source. With a validated `max_size`
of 256 this caps a chain at 256 descriptors and rejects any out-of-range `next`,
eliminating both the cycle and the oversized-`qsz` amplification.

### F4 — used-ring index re-read from guest RAM instead of device-owned state (used-ring integrity / correctness)

Severity: **Low** (correctness; no host-memory unsafety). Untrusted-input path:
the guest can write the used-ring index in its own RAM.

`complete` reads the used index back out of guest memory each time
(`vsock_transport.rs:318` `let used_idx = self.mem.rd_u16(used + 2);`) and writes
`used_idx + 1` (`:325`). The used index is *device-owned* state in virtio; sourcing
it from guest-writable memory lets a guest rewind or steer where used entries land
(`slot = used_idx % qsz`, then writes at `used + 4 + slot*8` — all bounds-checked,
so confined to the guest's own RAM). Same pattern in `virtio.rs:326`/`:332` and
`virtio.rs:620`/`:627`. Not exploitable for host-memory corruption, but it lets the
guest corrupt its own completion stream and defeats the point of a device-side
index. `virtio-queue` keeps `next_used` in device state (`Queue::add_used`), which
is the correct model.

### F5 — RX delivery ignores descriptor writability / chaining and can silently drop packets (correctness)

Severity: **Low** (correctness / data-loss; not unsafe). `flush_rx`
(`vsock_transport.rs:237-278`) uses only the *head* descriptor
(`da = q.desc + head*16`, `:253`), reads `addr` and `cap`, and never checks
`VIRTQ_DESC_F_WRITE` nor follows a multi-descriptor RX buffer. If the guest posts
an RX descriptor whose `addr` is out of range, `write_bytes` returns 0
(`guest_mem.rs:74-83`) yet `complete` still advances the used ring (`:269`) — the
host believes it delivered a packet the guest never received. The too-small-buffer
case *is* handled (re-insert at `:256-262`), but the bogus-`addr` case is not.
`virtio-queue`'s writable-descriptor iterator (`DescriptorChainRwIter`) plus a
proper "no writable buffer available → leave queued" path fixes this.

### F6 — O(n) `Vec::remove(0)` / `insert(0, …)` on the RX hot path (perf)

Severity: **Low** (perf, guest-influenceable via backpressure). `flush_rx` does
`self.pending_rx.remove(0)` (`:250`) and `insert(0, …)` (`:259`, `:271`) — each an
O(n) shift of a `Vec`. Under many queued packets (which a guest can induce by
withholding RX buffers) this is O(n²) per flush. A `VecDeque` (or the deferred
`OP_RW` re-frame handled by `virtio-queue`'s own iteration) removes it.

### F7 — per-packet / per-descriptor `std::env::var_os` in hot paths (perf)

Severity: **Low**. `agent_dbg` (`mod.rs:517`), the bridges' `dbg_log`
(`agent_bridge.rs:216`, `console_bridge.rs:249`), and the virtio-blk debug taps
(`virtio.rs:310`, `:353`, `:374`) call `std::env::var_os(...)` on every
packet/descriptor. Env access takes a process-global lock; on the per-packet path
it should be read once and cached (e.g. a `OnceLock<bool>`).

---

## Areas reviewed and found sound (evidence)

These are called out deliberately so the hardening work does not "fix" things that
are already correct.

- **Guest-memory access is uniformly bounds-checked; no unchecked pointer/offset
  arithmetic.** Every guest-RAM read/write funnels through `GuestMem`
  (`guest_mem.rs`). `host(gpa, len)` rejects `gpa < base`, computes the offset,
  and rejects `off.checked_add(len)? > size` before returning a pointer
  (`guest_mem.rs:29-39`) — `checked_add` closes the overflow path, and an
  out-of-range access returns `None` (reads zero-fill, writes no-op). `rd_*`,
  `wr_*`, `read_bytes`, `write_bytes` all go through it. This is why F1/F3 are
  *panics/OOM* and not memory-corruption: the device is memory-safe by
  construction on the guest-RAM boundary.
- **Header vs. payload length lies are handled.** Every consumer clamps to the
  real payload: `let n = (hdr.len as usize).min(payload.len())` at `vsock.rs:131`,
  `mod.rs:304`, `:342`, `:413`, `:488`. A lying `hdr.len` cannot over-read.
- **Fixed-width header parse cannot panic on short input.** `VsockHdr::from_bytes`
  uses `try_into().expect(...)` (`vsock_transport.rs:71-87`) but is only ever
  called on an exactly-`HDR_LEN` slice, guarded by `if buf.len() >= HDR_LEN`
  (`vsock_transport.rs:176`). The exit-code parse is guarded by `payload.len() >= 4`
  (`mod.rs:80`).
- **Descriptor-index reads are bounds-checked even when unbounded by `qsz`.**
  `head`/`next`/`idx` are `u16`, and `desc + idx*16` is always run through the
  checked `GuestMem`, so an out-of-table index reads zeros rather than host memory.
- **vCPU/host-I/O concurrency is correctly serialized.** All guest-RAM and
  virtqueue access happens under `Mutex<VsockShared>`; the dedicated I/O thread
  and the vCPU thread both take it (`vsock.rs:187`, `vsock_io.rs:107-122`), and the
  I/O thread is joined before guest RAM is freed (`vsock_io.rs:56-62`, documented
  at `guest_mem.rs:12-18`). No data race on guest memory or the rings.
- **Egress fails closed.** With no endpoint configured, `relay_guest_bytes`
  returns `Refused` and the stream is `OP_RST`-reset
  (`substitution_bridge.rs:115-117`, `mod.rs:348-351`) — consistent with the
  default-deny egress claim.

Two items in scope that are **not applicable** as the code stands:
- **Snapshot/restore.** This device implements no snapshot serialization in scope
  (no state `get`/`set`). The live connection state (`recv_cnt`, `pending_rx`,
  `conns`, `headers`, `last_avail`) is purely in-memory. If device snapshotting is
  added later, that state must be captured/restored — and `virtio-queue`'s
  `QueueState` (`state()`/`set_state()`) would make the ring half of that
  correct-by-construction. No defect today; a forward note.
- **IRQ delivery / wakeup races.** `interrupt_status` is maintained under the lock;
  the I/O thread raises the SPI *after* releasing the lock (`vsock_io.rs:119-125`),
  and missed edges are covered by the timer/heartbeat `poll()` fallback
  (`run.rs:129-159`) plus `notify_io()` on every MMIO write (`vsock.rs:291`). No
  concrete lost-notification or double-delivery bug was found; the edge-vs-level
  coalescing is subtle enough to be worth preserving byte-for-byte across any
  migration (call it out as a regression risk, not a current defect).

---

## Overall verdict

The device is **memory-safe by construction** on the untrusted-guest boundary:
because every guest-RAM access is routed through the bounds-checked `GuestMem`,
and every header/payload length is clamped to the real buffer, I found **no
host-memory-corruption bug** reachable from guest bytes — no OOB read/write, no
unchecked cast into a pointer, no over-read from a lying length.

It is **not robust against a hostile guest on availability**. It trusts
guest-programmed queue geometry and connection identifiers, which yields a
trivially-reachable panic (F1), a descriptor-amplification OOM (F3), and unbounded
host-resource growth against a shared endpoint (F2). These are precisely the
classes that audited rust-vmm primitives remove wholesale: `virtio-queue`'s
validated `Queue` + `ttl`/bounds-guarded `DescriptorChain` kill F1, F3, and F4;
`vm-memory`'s checked `GuestMemory` is the audited equivalent of the (already
sound) `GuestMem`; `virtio-vsock`'s typed `VsockPacket` replaces the hand-rolled
44-byte header parse. F2 and F5–F7 are device-policy/quality items the migration
should carry alongside.

**Recommended first hardening slice:** land a validated queue-geometry gate that
rejects `queue_num == 0`, `> QUEUE_SIZE_MAX`, and non-power-of-two before the ring
is serviced (a safe no-op / non-service for hostile input, byte-for-byte identical
for every conformant Linux guest, which always negotiates a power-of-two size
≤ 256). This is a tiny, isolated, unit-testable change that removes the URGENT
panic across vsock + blk + fs immediately, and it is the natural on-ramp to
replacing the hand-rolled ring walk with `virtio-queue`'s `Queue` (which subsumes
the same validation). Details and sequencing in the companion hardening plan.
