# Fast-start & density design — warm snapshot-fork within the vsock-only invariants

Date: 2026-07-26. Status: design agreed, pending spec review.

## Goal

Make mvm the default choice for running untrusted workloads by driving
start-up latency and memory density to the fastest achievable point *within*
the standing security invariants — not by adopting the no-OS / no-kernel
micro-isolation model of the sub-millisecond function-sandbox tier. mvm keeps
a full Linux guest (its whole value: run any unmodified OCI image, verified
boot, netfilter-grade egress, a real audit and secret-substitution chain), and
competes on being *fast enough that latency stops being the deciding factor*
while staying provably isolated.

Target shape: warm snapshot-fork pools + page-cache priming + density, across
Firecracker, the in-house HVF VMM, and libkrun. Realistic warm-start target is
tens of milliseconds, versus today's unoptimized cold boot.

## Where this sits relative to existing work

This is not greenfield. Two documents already scope most of the substrate:

- `specs/plans/255-vsock-first-snapshot-egress-adoption.md` (Draft) — the
  snapshot-first storage model, warm pool of paused clean parents, fork
  identity hygiene, egress enrichment, OCI template path. It is the substrate
  plan and stays so.
- `specs/adrs/025-warm-snapshot-prior-art-adoption-boundary.md` (Proposed) —
  the adopt/refuse boundary: adopt page-cache priming confined to the sealed
  rootfs; refuse warm-*guest* reuse; refuse host-socket networking.

Neither covers three things this design adds:

1. The Firecracker memory-snapshot restore path is **hard-disabled today**
   (`crates/mvm-runtime/src/microvm/snapshot.rs` bails on every restore entry
   point) because restoring a VMM can reintroduce the retired NIC and break
   the vsock-only / claim-10 boundary. Plan 255 assumes restore works; it does
   not. Re-enabling it safely is the load-bearing engineering task.
2. Backend sequencing, concrete latency/density SLOs gated in CI, and the
   density mechanisms (boot-time balloon, confined same-page sharing).
3. The competitive-positioning deliverables (reproducible benchmark + the
   security/compatibility comparison) that make "default choice" evidence-
   backed rather than asserted.

## Decisions (agreed)

- **Approach:** fastest *within* the invariants. No warm-guest reuse, no no-OS
  tier, no threat-model change. The sanctioned fast path is a warm memory
  snapshot forked into a fresh, signed, admitted identity.
- **Backend order:** Firecracker first (most mature snapshot tech, live-
  validatable on the KVM box), then the in-house HVF VMM (the strategic
  destination, vsock-pure so the no-NIC invariant is free), then libkrun (via
  its existing pool wiring).
- **Success = engineering + positioning.** Land the warm-start/density work
  behind CI-gated SLOs, and publish a reproducible benchmark plus a
  security-claim / workload-compatibility comparison against the no-OS tier.

## The invariant-safe fast path (technical crux)

FC restore is disabled because a restored full-VMM snapshot can reintroduce a
NIC → un-audited egress. The unlock is that the tree is already converging
every workload to NIC-less/vsock-only (plans 255/258). Therefore:

1. **Snapshot only vsock-only device models.** A device model with no NIC at
   freeze time cannot reintroduce one on restore. Re-enable restore behind a
   verified "restored device model contains no NIC" invariant, checked at
   restore, not only at capture.
2. **Snapshot-fork with fresh identity.** Each forked child boots a freshly
   synthesized, signed, admitted execution plan (new nonce, boot id,
   generation id, per-instance secrets disposition) — never the parent's. The
   existing warm-attach path already re-verifies the signed plan, so this
   slots in.
3. **Page-cache priming at freeze**, confined to the read-only verity-sealed
   rootfs (per ADR-025), so the restored child skips cold page-fault cost on
   its working set with no shared mutable/secret state.
4. **Warm pool = clean paused parents.** A parent is a factory, never a
   workload; on release the child is destroyed and a fresh parent replenished.

## Backends

Shared, backend-agnostic core (already partly built): the `CheckpointStore`,
the `VmFull` snapshot class (today reserved), the warm pool + `WarmLease`, the
memory accountant, identity-scrub-on-fork. Wired into the `VmBackend` trait so
all three backends inherit it (only libkrun implements the pool today).

- **Firecracker (lead, on the KVM box).** Un-bail `microvm/snapshot.rs` behind
  the no-NIC-on-restore invariant; land `create_snapshot` / `load_snapshot`
  behind the existing `SnapshotIO` trait seam; page-cache priming; **first
  published warm-start number.**
- **In-house HVF VMM.** Prerequisite: it needs a root filesystem (virtio-blk /
  initramfs — today it panics with no root fs) before snapshot is meaningful.
  Then native snapshot-fork; vsock-pure by construction, so the no-NIC
  invariant costs nothing.
- **libkrun.** Adopt the same seam through its existing standby-pool wiring.

## Density

- Boot-time balloon: commit `mem_initial_mib` at boot instead of the full cap
  (mechanism already present), inflate on demand under the existing
  Inflate/Hold/Deflate policy.
- CoW page sharing across a fork family is intrinsic (children share the
  parent's pages copy-on-write) and same-image, so it is the primary density
  lever and carries no cross-tenant exposure.
- Host-wide same-page merging (KSM) is **constrained, not adopted wholesale** —
  see security surface 6 below.
- Keep the memory accountant charging *measured* CoW resident, not the
  configured cap, so density accounting reflects reality.
- The minimal all-built-in kernel (`optimizeForSize`) already exists and stays
  the guest baseline.

## Security surfaces opened or widened by this work

Warm snapshot-fork adds attack surface that cold boot does not have. Each item
below is stated with its failure mode, the mitigation, and the claim or
witness that must cover it. Items marked NEW need a new CI witness; the rest
extend an existing claim into the restore path.

1. **Snapshot integrity — restore executes attacker-influenced memory.**
   A tampered memory image yields arbitrary guest register/memory state on
   restore, potentially forging an already-admitted state. Mitigation: gate
   every restore on the existing HMAC seal (`instance_snapshot.rs`
   integrity.json + snapshot_hmac), fail closed on mismatch; add AES-GCM
   confidentiality (currently absent) so snapshots-at-rest do not leak guest
   memory. Extends claim 8 into the restore path. NEW witness: restore refuses
   a byte-flipped snapshot.

2. **NIC reintroduction on restore — vsock-only / claim-10 bypass.** The reason
   restore is disabled today. Mitigation: snapshot only NIC-less device models;
   verify no NIC in the *restored* device model, refuse otherwise. Claim 10.
   NEW witness: restore of a snapshot whose device model carries a NIC is
   refused.

3. **Fork identity confusion / plan replay.** A child inheriting the parent's
   nonce/keys/audit position could replay a prior admission or carry a stale
   validity window. Mitigation: fresh signed+admitted plan per fork; nonce
   replay store; monotonic snapshot epoch enforced at restore to refuse
   rollback; fork lineage anchored to the chain-signed audit log so a fork
   fails closed on an un-audited or tampered parent. Claim 8 + existing
   checkpoint-lineage anchoring.

4. **Cross-fork residue.** The parent's memory is CoW-shared into every child;
   anything in the snapshotted parent RAM or primed cache is present in all
   children. Mitigation: snapshot only *clean pre-workload* parents (captured
   before any workload admission); priming confined to the read-only verity
   rootfs; per-instance mutable volumes never shared; secrets never enter guest
   memory (host-side substitution). ADR-001 one-guest-one-workload +
   secrets-never-in-guest; claim 13. NEW witness: a parent snapshot captured
   after a workload ran is refused for forking.

5. **Page-cache priming vs verified boot.** If primed content is not the
   verity-sealed rootfs, restore serves unverified pages. Mitigation: prime
   strictly from the dm-verity sealed read-only root; a declared working set
   resolving outside it is rejected; the restored rootfs stays verity-backed.
   Claim 3.

6. **Same-page merging (KSM) as a cross-VM side channel.** NEW boundary
   decision (absent from ADR-025). Host-wide KSM merges identical pages across
   VMs; a write to a merged page faults measurably slower — a memory-
   deduplication timing side channel (cross-VM disclosure, Rowhammer
   amplification). Mitigation: confine same-page sharing to a single fork
   family / same image (intrinsic CoW), never merge across tenants or distinct
   workload images. Recorded as a new "Constrain" decision in ADR-025.

7. **Snapshot at rest — disclosure and rollback.** Snapshots hold full guest
   memory; a local reader gets disclosure, and a rollback swap to an older
   snapshot could resurrect revoked credentials or known-vuln state.
   Mitigation: `~/.mvm` 0700 (existing W1.5); HMAC seal + AES-GCM
   confidentiality; monotonic epoch anti-rollback enforced at restore.

8. **Warm-pool control channel is untrusted.** A local attacker reaching the
   pool control UDS could try to claim or redirect a standby. Mitigation: pool
   dir + sockets mode 0700; the warm-attach path re-verifies the signed
   execution plan (already implemented) — the control UDS is explicitly not a
   trusted channel.

9. **Confinement re-application on restore.** A restored VMM that skips
   re-applying seccomp / jailer / per-service uid would come up less confined
   than a cold boot. Mitigation: treat restore as equivalent to boot for
   confinement — re-apply seccomp, jailer, and uid hardening on every restore.
   Claim 1. (ADR-025 lists seccomp-on-restore as an open restore-correctness
   gap; this closes it.)

10. **Host TCB growth in the snapshot-load path.** New snapshot-load code parses
    untrusted snapshot files. Mitigation: a cargo-fuzz target on the snapshot
    header/metadata parser (sibling to the existing SupervisorConfig fuzz);
    `#[serde(deny_unknown_fields)]` on every snapshot type. NEW fuzz witness.

11. **Density DoS via balloon (availability only).** A guest resisting balloon
    inflation under host pressure could starve the host. Mitigation: the
    existing balloon policy plus the host memory budget and spawn-concurrency
    gate cap oversubscription. No confidentiality impact.

Net: surfaces 1, 2, 4, 6, and 10 need new CI witnesses; the rest extend claims
3, 8, 10, 13, and W1.x into the restore path. None of them requires relaxing an
existing claim — the fast path is gated *harder* than cold boot, not softer.

## SLOs (design targets, tuned on the KVM box)

- Warm start p50 ≤ ~30 ms, p99 ≤ ~50 ms, measured through the existing
  `phase_timing` harness (`MVM_PHASE_TIMING=1`), versus the current
  unoptimized cold boot.
- Density: guests-per-GB via the memory accountant's measured resident, on a
  representative same-image fork family.
- These are starting targets; ratchet them from real measurement.

## Positioning (the "default choice" evidence)

- Reproducible benchmark harness, runnable on the KVM box, reporting warm start
  vs mvm's own cold-boot baseline and honestly placing both against the no-OS
  tier (no apples-to-oranges).
- A comparison doc: the machine-checked security claims + workload
  compatibility (any unmodified OCI image) matrix vs the no-OS tier. This is
  where mvm's already-built moat becomes visible. The no-OS tier is referred to
  obliquely throughout — no product proper noun in any committed file.

## Plan of record (artifacts to write)

1. **ADR-025 → Accepted**, plus a new "Constrain — same-page merging confined
   to a fork family" decision (surface 6) and a pointer to the security-surface
   enumeration.
2. **Plan 255 → Active**, minimal edits: add the FC-restore re-enable +
   no-NIC-on-restore task (the crux Plan 255 currently omits), and a cross-
   reference to Plan 265 for sequencing / SLOs / security surfaces.
3. **New Plan 265 — "Fast-start SLO, backend sequencing & competitive
   positioning."** Owns backend sequencing (FC → HVF → libkrun), the SLO CI
   gates, the density workstream, the security-surfaces section (mapping each
   surface to its claim/witness/fuzz), the benchmark harness, and the
   comparison doc. References Plan 255 for the substrate and ADR-025 for the
   boundary.

## Non-goals

- No warm-guest reuse; no no-OS / no-kernel tier; no Wasm micro-tier (unless a
  real use case later pulls for it).
- No relaxation of any existing security claim.
- No NIC/TAP/bridge or host-socket data plane; vsock stays the sole boundary.
- No product proper noun for the no-OS competitor in any committed file or
  commit message.
