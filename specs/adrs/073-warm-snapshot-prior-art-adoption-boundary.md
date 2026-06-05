# ADR-072 — Warm-snapshot prior art: adoption boundary

**Status:** Proposed
**Date:** 2026-06-05
**Numbering:** 072 is next-after-highest in `specs/adrs/` (main tops at 071).
`xtask check-spec-numbers` (a Lint gate) hard-fails on a duplicate integer prefix —
re-confirm 072 is free against open PRs before merge and renumber if taken.

## Context

A wider prior-art sweep of the macOS fast-boot microVM space turned up a
**pooled OCI-microVM runtime** — a single-crate Rust library that runs any
OCI/Docker image as a hardware-isolated microVM, production-ready on Apple
Silicon. (Referred to obliquely per the repo naming policy
[[feedback_no_competitor_names_anywhere]]; trait disambiguation lives in auto-memory
`reference_objc2_vz_external_references`. It is a *commercial* sandbox product,
not an OSS research sibling like the one Plan 157 cites — hence the oblique handling.)

It is the closest external proof point yet for the warm-path cluster mvm is
building (Plan 140 snapshot/restore productionization, Plan 148 fork-fanout,
Plan 157 warmed-parent recipes, Plan 152/159 Rust-native VZ). Its measured
numbers — ~10–50 ms boot, sub-100 ms cold snapshot restore on Apple Silicon —
are the bar mvm's warm path is reaching for. So it is worth a deliberate record
of **what we take from it and what we refuse**, because its fastest paths are
built on tradeoffs mvm's security posture forbids.

Defining traits (by which the oblique reference is keyed):

- **HVF-direct.** Binds Hypervisor.framework directly (`applevisor-sys`), a layer
  *below* both mvm's Vz (Virtualization.framework) and libkrun paths. That
  low-level control over guest memory is what buys the CoW snapshot/restore speed.
- **Page-cache-baked warm snapshots.** A `with_warmup` bake runs the workload once
  during image build and captures a snapshot whose **guest page cache is already
  populated**; a tag (`with_warmup_tag`) invalidates stale bakes. New workers start
  warm, not merely booted — the restored guest does not pay cold page-fault cost on
  first access to its working set.
- **CoW restore as the boot primitive.** An `Image` *is* a baked snapshot; restore
  maps it copy-on-write, so memory overhead per restored VM stays low.
- **Auto-scaling pool with cross-cycle reuse.** A pool (`min`/`max`/`idle_timeout`)
  hands out workers; `restore_on_release(false)` ("skip-restore") drops a released
  worker straight back to idle **without** restoring snapshot state, keeping the
  guest page cache hot across cycles (~7× on rustc-class jobs). Safe *only* because
  the workloads it targets overwrite their own outputs.
- **TSI networking.** AF_INET TCP/UDP is handled transparently by the host TSI
  socket family; AF_NETLINK, raw sockets, multicast, TUN/TAP, and ICMP are
  unsupported.
- Bundled guest kernel + init shim, extracted at build/runtime — the same shape as
  mvm's libkrunfw `extract_bundled_kernel()` and embedded `stage0-init` (ADR-071).

This ADR is clean-room: it records *design-level* learnings from public docs, not
copied code. The runtime is Apache-2.0; nothing here vendors or links it
([[feedback_replace_over_workaround]], [[feedback_limit_dependencies]] — inspiration,
never a dependency, exactly as Plan 152/159 treat the VZ references).

## Decision

Four sub-decisions. Two adopt, two refuse.

### 1. Adopt — page-cache priming at freeze time

Fold a page-cache-priming step into the existing warm-path producer/consumer, not
a new mechanism: when Plan 157's freeze takes the memory snapshot at the ready
point, prime the guest page cache (touch the declared working set) so the snapshot
captures a warm cache, and let Plan 140's restore inherit that warmth. This is a
*refinement of the freeze step*, distinct from Plan 157's existing warmup (which
primes **disk** state — `initdb` output into a warm overlay). Page-cache priming
primes **memory** — the same files paged in — so the first post-restore access
does not fault from disk.

It composes cleanly with the three-layer warm-parent model (immutable verity rootfs
+ sealed warm overlay + memory snapshot): page-cache warmth is a *property of the
memory-snapshot layer*, captured once at freeze, costing nothing at child boot.
Tracked as a Plan 157 deferred follow-up; it sequences behind the same memory-
snapshot substrate (Plan 123 Phase C / Plan 140) the rest of the freeze leg needs.

**Why adopt:** it is the one mechanism here that is pure upside under mvm's model —
it makes a *signed, sealed, single-workload* snapshot boot faster without touching
isolation, provenance, or the audit chain. The warmth lives in the snapshot the
freeze already produces and admits.

### 2. Adopt (as a data point, no direction change) — HVF-direct as a reference for the Rust-native VZ path

The runtime's HVF-direct design demonstrates that driving the hypervisor a layer
below Virtualization.framework is viable and is where its snapshot/restore speed
comes from. Record this as a reference data point for Plan 152's Rust-native VZ
supervisor — **not** a direction change. mvm stays on Virtualization.framework: the
entitled-TCB-as-a-tiny-separate-process invariant, the entitlement model, and the
maintenance cost of an HVF-direct VMM all argue against dropping to raw HVF
(ADR-056, Plan 152 Decision). The honest tradeoff — VZ.framework gives less control
over guest memory, which is exactly the lever fast CoW restore wants — belongs in
Plan 152/140's design notes, not in a backend rewrite.

### 3. Refuse — cross-workload guest reuse (skip-restore / pooled hot cache)

The runtime's fastest path (`restore_on_release(false)`) **reuses a dirty guest
across workloads** — page cache, and any other in-memory state, survive from one job
to the next. That directly violates two standing mvm invariants:

- **One guest = one workload** (ADR-002 §"Out of scope" — multi-tenant guests are
  explicitly not in the threat model). A reused guest is a multi-workload guest.
- **Per-run admission + audit** (claim 8 / ADR-041): every workload boots from a
  freshly synthesized, signed `ExecutionPlan` and emits `plan.admitted` /
  `plan.launched` to the chain. A worker pulled hot from a pool with prior in-memory
  state has no fresh admission and carries un-attested residue across the audit
  boundary.

mvm's warm path is the *opposite* shape: fork/restore N **fresh** children from one
*paused* base (Plan 148), each getting fresh per-instance identity (IP, instance-id,
secrets disk, nonce) and post-resume hygiene — entropy reseed, clock resync, VMGenID
(Plan 140 gaps #2/#3, Plan 122 D). The runtime's pool is the anti-pattern that
machinery exists to prevent. We adopt warm *snapshots*; we refuse warm *guests*.

The single place reuse is even conceivable is the **dev-tier builder VM** — a
different security tier where the hardened workload claims do not apply
([[feedback_dev_vm_vs_prod_security_tiers]]). Even there it is out of scope for this
ADR: builder-VM warm reuse, if ever pursued, gets its own plan with its own
threat-model note. It is **never** available to workload microVMs.

### 4. Refuse — TSI networking (already decided; cited as supporting evidence)

The runtime routes guest network I/O through the host TSI socket family. mvm removed
TSI entirely (ADR-058 §W6.A amendment / Plan 102 W6.A / Plan 142): TSI bypasses
virtio-net, violating the claim-10 no-bypass invariant — every byte leaving a guest
must traverse the auditable gvproxy/passt bridge. This ADR does **not** reopen that;
it cites the runtime's own documented TSI limitation list (AF_NETLINK, raw sockets,
multicast, TUN/TAP, ICMP all unsupported) as **independent supporting evidence** for
the cost mvm already chose to pay by going virtio-net. The limitation list is a
witness, not a reconsideration.

## Out of scope (named)

Adjacent surfaces this ADR deliberately does not own, named so readers do not expect
them here:

- **Pool orchestration policy** — warm-pool sizing, wake-time admission, fan-out
  count. Fleet concern; lives in mvmd (`../mvmd/specs/plans/53-warm-pool-ms-restore.md`)
  and Plan 148 / 159 WS-1.
- **The warmed-parent producer lifecycle** — declarative warmup contract, ready
  probe, freeze, provenance. Owned by Plan 157; this ADR only adds the page-cache
  follow-up to it.
- **Restore correctness gaps** — seccomp-on-restore, entropy reseed, clock resync,
  wake admission. Owned by Plan 140.
- **The Rust-native VZ supervisor migration** — drop-Swift, objc2-virtualization,
  in-process payload tap. Owned by Plan 152; HVF-direct is a data point for it, not
  a deliverable here.
- **Builder-VM warm reuse** — the one dev-tier place cross-cycle reuse is
  conceivable; needs its own plan + threat-model note if ever pursued.

## Consequences

- Plan 157 gains a deferred follow-up (page-cache priming at freeze); no schema or
  code change lands from this ADR — it is a design record plus a tracked follow-up.
- The oblique reference is added to the auto-memory disambiguation key
  (`reference_objc2_vz_external_references`) so future sessions can decode "the
  pooled OCI-microVM runtime" without a name reaching repo text or memory.
- No claim changes. This is a prior-art/adoption-boundary ADR, not a security-claim
  ADR; the ADR-002 numbered table is untouched.

## References

- [ADR-002](002-microvm-security-posture.md) — security posture; one-guest-one-workload, claim numbering
- [ADR-041](041-signed-audited-execution-plans.md) — claim 8, signed/audited `ExecutionPlan` (per-run admission)
- [ADR-056](056-vz-backend.md) — Vz backend (why we stay on Virtualization.framework)
- [ADR-058](058-claim-10-bytes-leaving-trust-boundary.md) §W6.A — no-bypass invariant, TSI removed
- [ADR-071](071-stage0-bootstrap-trust-model.md) — bundled-kernel/embedded-init extraction shape
- [Plan 140](../plans/140-snapshot-restore-productionization.md) — restore productionization (inherits page-cache warmth)
- [Plan 148](../plans/148-microvm-fork-fanout-and-branch.md) — fork-fanout of fresh children from a paused base
- [Plan 152](../plans/152-rust-native-vz-and-init-lifecycle-parity.md) — Rust-native VZ supervisor (HVF-direct data point)
- [Plan 157](../plans/157-warmed-parent-recipes.md) — warmed-parent producer (page-cache follow-up lands here)
- [Plan 159](../plans/159-vz-inspired-macos-dx.md) — vz-inspired macOS DX (warm path WS-1)
