# virtio-vsock device hardening — staged adoption of audited rust-vmm primitives (2026-07-27)

Companion to `2026-07-27-vsock-device-audit-findings.md`. Goal: replace the
hand-rolled virtqueue/guest-memory/packet code in the in-house VMM's virtio-vsock
device with audited rust-vmm primitives, **behavior-preserving**, in bounded
individually-reviewable slices, each gated by an equivalence test that proves
unchanged behavior for conformant guests and safe rejection of the hostile input
the audit found.

This plan is scoped to the vsock device but is written so the same primitives
land once and are reused by the block/fs devices (they share `GuestMem` and the
same divide-by-zero root cause — F1).

## Primitives (verified from primary sources, 2026-07-27)

All three are rust-vmm crates under the `rust-vmm/vm-virtio` and
`rust-vmm/vm-memory` repos, permissively licensed (Apache-2.0 / BSD-3-Clause).

- **`virtio-queue` 0.18.0** — split-virtqueue `Queue`, `Descriptor`,
  `DescriptorChain`, and the `DescriptorChainRwIter` readable/writable
  abstraction. Depends on `vm-memory ^0.18`. Verified from the crate source that
  `DescriptorChain::next` returns `None` once `ttl == 0 || next_index >=
  queue_size` and seeds/decrements `ttl` from the queue size — i.e. it structurally
  prevents both descriptor loops and out-of-range `next` indices (kills F3), and
  the validated `Queue` size makes a zero/oversized `qsz` un-representable (kills
  F1). `Queue::add_used` keeps the used index in device state (kills F4).
- **`vm-memory` 0.18.0** — `GuestMemory`/`GuestMemoryMmap`, `GuestAddress`, the
  `Bytes` trait (`read_obj`/`write_obj`/`read_slice`/`write_slice`), and
  `VolatileSlice` (a safe wrapper over raw guest pointers). This is the audited
  equivalent of the in-repo `GuestMem`. It can wrap an externally-owned mapping
  via `MmapRegion`'s raw-pointer constructor, which is required here because the
  RAM pointer is owned by the HVF/KVM mapping, not allocated by vm-memory.
- **`virtio-vsock` 0.12.0** — `VsockPacket`, parsed from a TX/RX descriptor chain
  (stream sockets only), header + optional data represented as `VolatileSlice`s.
  Replaces the hand-rolled 44-byte `VsockHdr::from_bytes/to_bytes` and `HDR_LEN`.
  Tracks the 0.18 `vm-memory`/`virtio-queue` line (ADR-033 realigned the note's
  original 0.11 pin, which pulled duplicate `vm-memory`/`virtio-queue` majors).

**Oracle, not a dependency:** a sibling in-house virtio-vsock reference
implementation (the "arcbox" oracle named in the tasking) is used only to
cross-check semantics during migration. It is **not** taken as a dependency
pending its own audit; do not add it to `Cargo.toml`.

## Cross-cutting constraints (must hold for every slice)

- **Closure budget + supply chain.** The repo gates default-binary crate count and
  audits every dependency (`deny.toml`, the `deny`/`audit` CI jobs, ADR-002
  "limit dependencies"). These three crates must land **only** on the host VMM
  path (`mvm-runtime`'s `vmm`/`hvf`), never in the sealed guest agent
  (`mvm-agentd` stays tokio/dep-free), `mvm-core` (no async), or the embedded
  cross-compiled host-vm bins. Concretely, before merging Slice 1: capture
  `cargo tree -p mvm-runtime -e no-dev` and the default-binary crate-count metric,
  add the exact crate + transitive additions to the `deny.toml` allowlist, and get
  maintainer sign-off on the closure delta. `vm-memory` pulls a small tree
  (`libc`, `thiserror`); `virtio-queue` adds `log`; `virtio-vsock` adds only those
  two. Feature-gate them (e.g. a `vmm-rustvmm-queue` feature) if the count needs to
  stay off by default during migration.
- **HVF must not regress.** (a) *Startup latency* — per-VM device construction must
  stay cheap; `Queue::new(max_size)` and wrapping the existing mapping in a
  `GuestRegionMmap` are O(1), no allocation of guest RAM. (b) *IRQ behavior* — do
  not touch the `IrqLine`/SPI edge semantics or the `poll()`/heartbeat fallback;
  the queue crate does not raise interrupts, so keep the existing
  `interrupt_status |= 1` + `set_irq`/`signal` exactly as-is. (c) *Snapshots* — the
  device does not snapshot today; if/when it does, prefer `virtio-queue`'s
  `QueueState` over re-deriving ring state. (d) *Cross-platform builds* — these
  deps are host-side and std-only; verify `just check-linux` (zigbuild
  x86_64/aarch64-gnu) stays green and that the `aarch64-unknown-linux-musl`
  embedded host-vm bins (which do not touch this code) are unaffected.
- **Behavior preservation is the acceptance bar.** For a conformant guest (Linux
  always negotiates a power-of-two queue size ≤ the advertised max, posts a header
  descriptor + data descriptors, etc.) every slice must produce byte-identical
  used-ring updates and byte-identical extracted TX packets / delivered RX bytes.
  The only *intended* behavior change is that the hostile inputs from F1/F3 stop
  panicking/OOMing and instead fail closed (no service, or `OP_RST`).

## Equivalence-test methodology (used by every slice)

Each slice ships a test that builds a virtqueue in a scratch RAM buffer (the
existing tests already do this — see `vsock_transport.rs::configure_rx_buffers`
and `virtio.rs::services_a_block_read_through_the_split_virtqueue`) and asserts the
new path is observationally identical to the old one:

1. **Golden replay.** Program a representative queue (sizes 1, 2, 128, 256; single
   and multi-descriptor chains; empty and full payloads; split RX payloads as in
   `flush_rx_splits_large_stream_payload_across_guest_buffers`). Capture used-ring
   bytes + extracted packets from the *current* code as golden vectors; assert the
   new code reproduces them exactly.
2. **Differential during migration.** While both implementations coexist (behind a
   feature), run both over the same RAM image in one test and `assert_eq!` their
   outputs — the strongest proof of equivalence.
3. **Hostile-input regression.** Assert the specific audit triggers now fail
   closed: `queue_num = 0x1_0000` (F1) services nothing / no panic; a cyclic
   65535-hop chain (F3) is capped and does not allocate unboundedly.

## Slices

### Slice 1 — validated queue-geometry gate (kills the URGENT F1; no new deps yet)

Smallest possible change that removes the panic. Introduce a
`ValidatedQueueSize`/`QueueGeometry` newtype (make illegal states
unrepresentable) constructed at `QueueReady`/notify time that rejects
`num == 0`, `num > QUEUE_SIZE_MAX`, and non-power-of-two `num`. The service paths
(`take_tx_packets`, `flush_rx`, `complete`, and the `virtio.rs` block/fs
equivalents) consult the validated size; an invalid geometry services nothing,
exactly mirroring the existing `if q.ready == 0 || q.num == 0 { return }` early
outs. No behavior change for any conformant guest.

- Removes: F1 across vsock + blk + fs; caps F3's `qsz` at 256 as a side effect.
- Tests: golden replay for sizes {1,2,128,256}; regression asserting
  `queue_num ∈ {0, 0x1_0000, 3, 257}` services nothing and does not panic.
- Deps/closure impact: none. This slice is deliberately dependency-free so the
  URGENT fix is not blocked on the closure-budget review.
- Reviewable in isolation; strictly additive validation.

### Slice 2 — adopt `vm-memory` behind the `GuestMem` seam

Replace the internals of `GuestMem` (`guest_mem.rs`) with `vm-memory`: wrap the
externally-owned RAM mapping in a `GuestRegionMmap`/`GuestMemoryMmap` built from
the raw pointer + size, and route `rd_*`/`wr_*`/`read_bytes`/`write_bytes` through
`read_obj`/`write_obj`/`VolatileSlice`. Keep the public method surface and the
current *semantics* (out-of-range read → zero-fill, write → no-op) so callers are
untouched; the `unsafe impl Send` + "joined before RAM freed" invariant
(`guest_mem.rs:12-18`) is preserved and re-documented against vm-memory's model.

- Removes: the last hand-rolled `unsafe` pointer arithmetic on the guest boundary
  (already sound — this is defense-in-depth + shrinks the audited surface).
- Tests: property test over random `(gpa, len)` pairs asserting the vm-memory-backed
  `GuestMem` returns identical results (including the zero-fill/no-op edge
  behavior) to the current one.
- Do this before the queue swap so the queue slice can hand `virtio-queue` a real
  `GuestMemory` rather than a bespoke shim.

### Slice 3 — `virtio-queue` for the vsock TX path

Replace `take_tx_packets` + `read_chain` (`vsock_transport.rs:163-185`, `:296-313`)
with `Queue::iter(mem)` yielding `DescriptorChain`s, gathering readable descriptors
into the TX buffer. The `ttl`/`next_index` guard subsumes the hand-rolled `guard`
counter and adds the missing `next < queue_size` bound (kills F3 on TX).

- Tests: differential test — same avail-ring + descriptor table through both the
  old `take_tx_packets` and the `virtio-queue` iterator; `assert_eq!` on the
  `(VsockHdr, payload)` list. Cyclic/oversized-chain regression.

### Slice 4 — `virtio-queue` for the vsock RX path

Replace `flush_rx` + `complete` (`vsock_transport.rs:237-278`, `:315-327`) with
`DescriptorChainRwIter` (writable descriptors) + `Queue::add_used`. This also fixes
F4 (used index becomes device-owned) and F5 (writable-descriptor validation +
proper "no RX buffer → leave queued" instead of silent drop) and lets the deferred
`OP_RW` re-frame drop the O(n) `Vec::remove(0)` (F6, switch `pending_rx` to
`VecDeque`).

- Tests: golden replay of `flush_rx_splits_large_stream_payload_across_guest_buffers`
  (byte-identical split across guest buffers); regression for bogus-`addr` RX
  descriptor now leaving the packet queued rather than advancing used.

### Slice 5 — `virtio-vsock` typed packet parse/format

Replace `VsockHdr::{from_bytes,to_bytes}` + `HDR_LEN` (`vsock_transport.rs:41-88`)
with `virtio-vsock`'s `VsockPacket`. Cross-check field-for-field against the
sibling reference implementation (oracle only). Keep the device's op-dispatch
(`handle_packet`, the handler registry) unchanged — only the wire parse/format is
swapped.

- Tests: round-trip a matrix of headers (all ops, boundary `len`/`buf_alloc`/
  `fwd_cnt`) and assert byte-identical framing vs the current `to_bytes`.

### Slice 6 — connection-table caps (F2; not a rust-vmm primitive)

Independent of the queue work: give the per-device connection state
(`recv_cnt`, the bridges' `conns`/`headers`) a typed table with a
max-concurrent-streams ceiling and idle eviction. Past the cap, refuse with
`OP_RST` instead of opening another host `UnixStream` / map entry. This closes the
shared-endpoint FD-exhaustion path.

- Tests: assert that N distinct `src_port`s past the cap yield `OP_RST` and open no
  further host sockets; assert `OP_SHUTDOWN`/idle frees slots.

## Fuzzing (extend the existing harness)

The repo already fuzzes `GuestRequest`, `AuthenticatedFrame`, and the host-side
`SupervisorConfig` (frozen fuzz lane, pinned nightly, workspace-excluded). Add,
using the same lane conventions:

- **Virtqueue-geometry + descriptor-table fuzzer** — feed a random RAM image plus a
  random register-programming sequence into `VsockTransportCore` (drive
  `write_register` + `on_notify`) and assert no panic / no unbounded allocation.
  This target reproduces F1 and F3 and becomes the regression guard for Slices 1,
  3, 4. Land it **before** Slice 1 so it demonstrably catches the divide-by-zero,
  then goes green after the fix.
- **Differential queue fuzzer** — during Slices 3–4, fuzz a RAM image through both
  the hand-rolled and `virtio-queue` paths and assert identical output; retire it
  once the old path is deleted.
- **Packet-parse fuzzer** — fuzz `VsockHdr::from_bytes` / `VsockPacket` on arbitrary
  ≥`HDR_LEN` byte strings (Slice 5), asserting parse never panics and round-trips.

## Sequencing summary

1. Slice 1 (validated geometry) + the geometry fuzzer — removes the URGENT panic,
   no deps, unblocked by closure review.
2. Closure-budget + `deny.toml` review; land `vm-memory` (Slice 2).
3. `virtio-queue` TX then RX (Slices 3–4) behind differential tests.
4. `virtio-vsock` packet parse (Slice 5).
5. Connection-table caps (Slice 6), independent, schedulable anytime after Slice 1.

Each slice is independently revertible and leaves the tree green. The block and fs
devices reuse the Slice 1 gate and the Slice 2 `vm-memory` seam directly, and can
follow the same TX/RX queue migration once the vsock path proves the pattern.

## Sources

- [virtio-queue on crates.io](https://crates.io/crates/virtio-queue) /
  [docs.rs](https://docs.rs/virtio-queue) — 0.18.0.
- [rust-vmm/vm-virtio `virtio-queue` chain iterator source](https://raw.githubusercontent.com/rust-vmm/vm-virtio/main/virtio-queue/src/chain.rs)
  — `ttl` + `next_index >= queue_size` guard.
- [vm-memory on docs.rs](https://docs.rs/crate/vm-memory/latest) — 0.18.0.
- [virtio-vsock on crates.io](https://crates.io/crates/virtio-vsock) /
  [docs.rs](https://docs.rs/virtio-vsock) — 0.12.0 (`VsockPacket`).
- [rust-vmm/vm-virtio](https://github.com/rust-vmm/vm-virtio).
