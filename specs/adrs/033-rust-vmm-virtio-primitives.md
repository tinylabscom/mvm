# ADR-033: Audited rust-vmm primitives for the in-house VMM's virtio devices

## Status

Accepted, and **fully landed** on the vsock device. This ADR is the gate:
it records the decision to adopt three rust-vmm crates on the host VMM
path and the supply-chain sign-off that adoption requires. Acceptance
landed with Slice 2 (`vm-memory` behind the `GuestMem` seam); Slices 3–4
adopted `virtio-queue` for the vsock TX then RX ring walk; Slice 5 adopted
`virtio-vsock`'s typed packet for the 44-byte header parse/format
(`VsockHdr::{to_bytes,from_bytes}` now frame through `VsockPacket`, and
`HDR_LEN` is anchored to `PKT_HEADER_SIZE`). The migration is now complete:
F1/F3/F4 are eliminated by construction, and F5's writable-descriptor
validation / "no RX buffer → leave queued" handling (Slice 4) is preserved
unchanged by the header swap — the packet round-trips byte-identically to
the hand-rolled encode/decode across every op and boundary value. The
staged implementation lives in
`specs/notes/2026-07-27-vsock-device-hardening-plan.md`; the audit that
motivates it in `specs/notes/2026-07-27-vsock-device-audit-findings.md`.
The block/fs device migrations (which reuse the same `vm-memory` seam and
`Queue` gate) remain out of scope here.

## Context

The in-house VMM (the HVF path on macOS 26+ Apple Silicon, the KVM path
on Linux — the "no VMM lock-in" device model in `mvm-runtime`'s `vmm`
module) hand-rolls its virtio-mmio stack: the split-virtqueue ring walk,
the guest-memory boundary (`vmm/guest_mem.rs`), and the 44-byte
virtio-vsock header parse (`vmm/vsock_transport.rs`). In the vsock-only
security model this device is the top trust boundary — guest-programmed
queue geometry, descriptor addresses/lengths/flags, packet-header fields,
and per-connection credit all cross from an untrusted guest into host
code (ADR-001; the vsock-only auditable data plane invariant).

A read-only audit of that surface reached a specific verdict: the device
is **memory-safe by construction** — every guest-RAM access funnels
through the bounds-checked `GuestMem`, and every header/payload length is
clamped to the real buffer, so no host-memory-corruption bug is reachable
from guest bytes — but it is **not availability-robust against a hostile
guest**. Three finding classes follow from trusting guest-programmed ring
state:

- **F1 (fixed, URGENT).** An unvalidated `queue_num` (the raw guest `u32`
  from the virtio-mmio `QueueNum` register) is truncated to `u16` and used
  as a modulus. `queue_num = 0x1_0000` passes the `num == 0` guard yet
  narrows to `0`, so `last % qsz` is a guest-triggerable divide-by-zero
  panic — reachable in ~5 register writes, across all three virtio devices
  (vsock, blk, fs) from one root cause. Slice 1 of the plan closes this
  dependency-free with a validated `QueueGeometry` newtype; this ADR does
  not block that urgent fix.
- **F3.** The vsock `read_chain` follows the descriptor chain with **no
  `next < qsz` bound** and only a loop counter as a stop condition. With an
  oversized `qsz` (F1) and a cyclic `next`, a guest builds a 65535-hop
  chain that amplifies into an unbounded `Vec` allocation → OOM. The
  sibling block/fs walkers already guard this; the vsock path does not.
- **F4.** The used-ring index is re-read from guest-writable RAM each
  completion instead of being device-owned, letting a guest rewind or
  steer where used entries land (confined to its own RAM, so not host
  unsafety — a correctness defect). Closed in two steps: within a drain by
  the `virtio-queue` adoption below, and across drains by the ring-cursor
  ownership decision that follows it.

The through-line: **hand-rolled virtqueue and guest-memory code re-derives,
per device, invariants that a validated queue primitive enforces once.**
F1/F3/F4 are three faces of the same untrusted-ring-geometry problem, and
the block/fs devices carry the same code shape. The audit's own verdict is
that these are "precisely the classes that audited rust-vmm primitives
remove wholesale."

## Decision

**Adopt three rust-vmm crates on the host VMM path, and only there:**

- **`vm-memory`** (0.18 line) — `GuestMemory`/`GuestMemoryMmap`, the
  checked `Bytes` trait, and `VolatileSlice`. The audited equivalent of
  the in-repo `GuestMem`; wraps the externally-owned HVF/KVM RAM mapping
  via `MmapRegion`'s raw-pointer constructor (the RAM is owned by the
  hypervisor mapping, not allocated by vm-memory).
- **`virtio-queue`** (0.18 line) — the validated `Queue` plus the
  `ttl`/bounds-guarded `DescriptorChain` iterator. `Queue` rejects a
  zero, oversized, or non-power-of-two negotiated size before the ring is
  usable, and `DescriptorChain::next` returns `None` once
  `ttl == 0 || next_index >= queue_size`, seeding `ttl` from the validated
  size. This makes `queue_num = 0x1_0000` un-representable (kills F1),
  caps and range-checks the chain walk (kills F3), and keeps `next_used`
  in device state (kills F4).
- **`virtio-vsock`** — the typed `VsockPacket`, replacing the hand-rolled
  `VsockHdr::{from_bytes,to_bytes}` + `HDR_LEN`.

### Boundary — host VMM path only, never the sealed guest or `no_std` core

These crates land **only** in `mvm-runtime`'s `vmm` device model (driven
by the cfg-gated `hvf` and `kvm` backends). They are host-side, std-only
code that sits behind the `VmBackend` seam, consistent with the standing
"isolate VMM specifics behind the trait, never lock into one VMM" rule.

They are forbidden in:

- **`mvm-agentd`** (the in-guest agent), whose default closure stays
  tokio-free and dependency-lean — the sealed-agent posture behind
  claims 4 and 15.
- **`mvm-core`** and **`mvm-protocol`** — the `no_std`/`wasm32`
  foundation, which carries no async and no host-VMM code.
- **The embedded cross-compiled host-vm bins** (`mvm-host-vm-init`,
  `mvm-egress-proxy`), built static `aarch64-unknown-linux-musl` in
  `mvm-build`; they do not touch this code and must stay unaffected.

### Feature-gated during migration; behavior-preserving; staged

The migration is behavior-preserving and lands in the plan's bounded,
individually-revertible slices — Slice 2 (`vm-memory` behind the
`GuestMem` seam), Slices 3–4 (`virtio-queue` for the vsock TX then RX
path), Slice 5 (`virtio-vsock` typed packet). Each slice ships an
equivalence test (golden replay + a differential test running both
implementations over one RAM image + a hostile-input regression) so a
conformant Linux guest sees byte-identical used-ring updates and extracted
packets; the only intended behavior change is that F1/F3 hostile inputs
fail closed instead of panicking/OOMing. F2 (connection-table caps) and
F5–F7 are device-policy/quality items carried alongside, not rust-vmm
primitives.

Gate the crates behind a Cargo feature (e.g. `vmm-rustvmm-queue`) for the
duration of the migration, so the default-binary closure delta stays
**zero** while both paths coexist and the differential tests run. Flip the
feature on by default — and delete the hand-rolled path — only once
Slice 5 lands and the old code is dead. This decouples the closure-budget
step below from every intermediate slice.

### Used-index ownership across drains, and ring-cursor lifecycle

The initial migration closed F4 only *within* a drain: each device still
seeded the per-drain `Queue`'s `next_used` from `used.idx` in guest RAM,
to keep the used entries byte-identical to the retired hand-rolled walk.
That left the index guest-recoverable between drains. It is now **device
state across drains**, exactly as `next_avail` already was: every device
carries a `next_used` sibling to its `last_avail`, feeds both into the
shared `RingGeometry` that `build_split_queue` programs, and writes both
back from `Queue::{next_avail,next_used}` after the drain. No device reads
`used.idx` from guest memory on any path. For a conformant guest this is
byte-identical — Linux zeroes the used ring before setting `QueueReady`
and never writes `used.idx` afterward, so the seed being removed only ever
read back what the device itself last wrote.

**Cursor lifecycle.** Both cursors are zero at device construction and are
re-zeroed on exactly the two register writes by which a driver hands the
device a freshly-programmed ring:

1. `QueueReady ← 0` — the driver detaching that queue. It then frees the
   ring, and any later activation programs newly-allocated (zeroed)
   memory, so the next drain must start at slot 0. Only the selected queue
   is rewound.
2. `Status ← 0` — a device reset. The driver re-runs the whole
   initialization sequence afterwards, so **every** queue is rewound.

Every other register write leaves the cursors alone. In particular a
redundant `QueueReady ← 1` on an already-ready queue is a no-op: making
activation rather than deactivation the trigger would let a mid-stream
write rewind the device onto used slots the driver still owns — a worse
defect than the one F4 describes. Zeroing on the 0-write covers both
orderings, since after it any subsequent activation already sits at zero.

The same lifecycle now applies to `last_avail`, which until this change
was zeroed only at construction and never on queue teardown or device
reset; the two cursors move together by construction rather than by
convention. Each of the three devices carries a cross-drain witness (a
scribbled `used.idx` between two drains does not move the next completion)
plus tests for both rewind transitions and for the redundant-activation
no-op.

## Supply chain and closure (ADR-002 / ADR-031 compliance)

Every workspace dependency clears the supply-chain bar — `cargo-deny`
(`deny.toml`) + `cargo-audit`, ADR-001 §W5.2 — and the repo holds the
limit-dependencies line (ADR-031; ADR-002's "audit in-house rather than
vet a third-party surface" posture). This is the crux of the sign-off, so
the closure delta was **measured**, not estimated.

Metric: distinct `crate@version` in
`cargo tree -p mvmctl --target x86_64-unknown-linux-gnu -e no-dev`
(the default-binary graph on the CI closure target), with cargo's `(*)`
"subtree already printed" re-print markers collapsed. Baseline: **267**
crates.

Two resolutions were measured:

- **Plan pins (`vm-memory 0.18`, `virtio-queue 0.18`, `virtio-vsock 0.11`):
  274 crates (+7).** New crates: `virtio-bindings 0.2.7`,
  `virtio-queue 0.17.0`, `virtio-queue 0.18.0`, `virtio-vsock 0.11.0`,
  `vm-memory 0.17.2`, `vm-memory 0.18.0`, `vmm-sys-util 0.15.0`. The catch:
  `virtio-vsock 0.11` requires `virtio-queue ^0.17` → `vm-memory ^0.17`, so
  **both** the 0.17 and 0.18 majors of `virtio-queue` and `vm-memory`
  resolve into the graph. Combined with `vmm-sys-util` (see below), that is
  **three** duplicate-major families, each of which trips `deny.toml`'s
  `multiple-versions = "deny"` ban.
- **Realigned to `virtio-vsock 0.12` (which tracks the 0.18
  `vm-memory`/`virtio-queue` line): 272 crates (+5).** New crates:
  `virtio-bindings 0.2.7`, `virtio-queue 0.18.0`, `virtio-vsock 0.12.0`,
  `vm-memory 0.18.0`, `vmm-sys-util 0.15.0`. Single 0.18 major of both
  `vm-memory` and `virtio-queue`; the two-major conflict disappears.

**Take `virtio-vsock 0.12`, not the note's `0.11`.** The three crates then
share one `vm-memory`/`virtio-queue` major and the default-binary delta is
**+5 crates** (267 → 272). The note's `0.11` pin predates checking the
transitive `virtio-queue`/`vm-memory` requirement; realigning is a
strictly better resolution and is the version this ADR adopts. The plan
note should be corrected to `0.12` before Slice 5.

**One residual duplicate major, unavoidable today: `vmm-sys-util`.** The
Linux KVM backend already pins `vmm-sys-util 0.12.1` transitively through
`kvm-bindings 0.11` / `kvm-ioctls 0.21`; the rust-vmm virtio crates bring
`vmm-sys-util 0.15.0`. Because cargo-deny evaluates the graph across all
targets, this 0.12/0.15 pair trips `multiple-versions = "deny"` on the
Linux target regardless of the `virtio-vsock` version. It cannot be
collapsed without `kvm-bindings`/`kvm-ioctls` tracking `vmm-sys-util 0.15`.

`deny.toml` edits required at land time:

- `[licenses].allow` — **no change.** All five new crates are
  Apache-2.0 / BSD-3-Clause (`virtio-bindings` BSD-3-Clause OR Apache-2.0;
  `virtio-queue` Apache-2.0 AND BSD-3-Clause; `virtio-vsock` and
  `vm-memory` Apache-2.0 OR BSD-3-Clause; `vmm-sys-util` BSD-3-Clause),
  all already in the allowlist.
- `[sources]` — **no change.** All resolve from crates.io.
- `[bans].skip` — **one recorded entry, `vmm-sys-util`**, for the KVM /
  rust-vmm major split above, sitting alongside the existing
  syscall-layer skips with a stated reason and a "shrink when
  `kvm-bindings` bumps" note. Taking `virtio-vsock 0.11` instead would
  force **three** skip entries (`vm-memory`, `virtio-queue`,
  `vmm-sys-util`) — running two majors of the very primitives being
  adopted to audit once — which is exactly the outcome the realignment
  avoids and a reason not to.
- `[advisories]` — no known RustSec advisory against these crates at
  measurement time; the `deny`/`audit` jobs re-check on every PR and are
  the live gate, not this prose.

This is a small, permissively-licensed, actively-maintained addition on
the host path only, and it *removes* audited surface (the hand-rolled ring
walk and header parse) once the migration completes. It clears the
ADR-031 bar: a real problem the in-tree primitive cannot solve (an
availability class the hand-rolled code re-introduces per device),
weighed against the CI-enforced closure/dep invariants, with the exact
cost measured and the one unavoidable skip named.

## HVF no-regress constraints

The migration must not regress the HVF path:

- **Startup latency — O(1) device construction.** `Queue::new(max_size)`
  and wrapping the existing HVF/KVM mapping in a `GuestRegionMmap` are
  O(1) with no allocation of guest RAM; per-VM device construction stays
  as cheap as today. No warm-path or boot-latency budget moves.
- **IRQ / SPI semantics untouched.** `virtio-queue` raises no interrupts.
  Keep the existing `interrupt_status |= 1` + `set_irq`/`signal` edge
  handling, the I/O thread's raise-after-unlock ordering, and the
  `poll()`/heartbeat fallback exactly as-is. The edge-vs-level coalescing
  is subtle and audited-sound; preserve it byte-for-byte and treat any
  change as a regression, not a cleanup.
- **Snapshots.** The device serializes no state today (live connection
  state is in-memory only). If device snapshotting is added later, prefer
  `virtio-queue`'s `QueueState` (`state()`/`set_state()`) over
  re-deriving ring state — correct-by-construction for the ring half.
- **Cross-platform builds.** These deps are host-side and std-only.
  `just check-linux` (zigbuild `x86_64`/`aarch64-unknown-linux-gnu`) must
  stay green, and the `aarch64-unknown-linux-musl` embedded host-vm bins
  — which do not touch this code — must stay unaffected.

## Alternatives considered

- **Keep hand-rolled, add validation only (Slice 1, no deps).** Endorsed
  as the urgent first step and shipped dependency-free — it removes the F1
  panic across vsock/blk/fs immediately. Rejected as the *endpoint*: F3's
  chain walk, F4's used-ring ownership, F5's writable-descriptor handling,
  and the block/fs devices all re-derive ring invariants that a validated
  `Queue` enforces once. Hand-rolling them again is the drift this repo's
  reuse-first rule exists to prevent.
- **The sibling in-house virtio-vsock reference ("arcbox" oracle) as a
  dependency.** Refused. It is used only to cross-check `VsockPacket`
  field semantics during Slice 5; it is not itself audited and never
  enters `Cargo.toml`.
- **`virtio-vsock 0.11` as pinned in the note.** Rejected in favor of
  `0.12` for the duplicate-major reason measured above.
- **Vendor / fork the crates.** Rejected — it forfeits the "audited
  upstream, tracked by advisory-db" property that is the whole point, and
  adds maintenance load, against the ADR-031 posture.

## Consequences

**Positive.** F1, F3, and F4 are eliminated by construction across vsock,
blk, and fs from a single validated primitive; the guest-memory boundary
moves onto the audited `vm-memory`; the hand-rolled ring walk and 44-byte
header parse leave the hand-audited surface. Block/fs reuse the same
`vm-memory` seam and `Queue` gate directly. A queue-geometry/descriptor
fuzz target (landed before Slice 1) and a differential queue fuzzer
(Slices 3–4) extend the existing frozen fuzz lane.

**Negative.** +5 distinct crates on the default binary and one recorded
`deny.toml` `vmm-sys-util` skip until `kvm-bindings` catches up; a second
std-only dependency family to watch in the advisory gate; the migration
must carry byte-identical behavior, which the per-slice golden-replay and
differential tests enforce.

**Security claims.** No numbered ADR-001 claim changes. This hardens the
availability robustness of the vsock trust boundary that underpins the
vsock-only data-plane invariant; whether an availability-robustness
property is promoted to a numbered claim is a separate maintainer
decision, out of scope here.

## Out of scope

F2 connection-table caps (a typed per-device connection table with a
max-concurrent-streams ceiling and idle eviction — device policy, not a
rust-vmm primitive; plan Slice 6); the block/fs device migrations that
follow the vsock pattern; and device snapshot serialization. Each is a
decision for the workstream that owns it.
