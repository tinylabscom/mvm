# Plan 157 — Warmed parent recipes (forkd-inspired)

> Number 157 is the next free integer (`main` tops out at 156: 156 binary-size-reduction,
> 155 portable-runnable-artifacts, 154 cloud-hypervisor-tier1-parity). `xtask
> check-spec-numbers` is a Lint gate — re-confirm 157 is still free against open PRs +
> `main` before merge and renumber if taken.

## Context

[forkd](https://github.com/deeplethe/forkd) is the closest public sibling to mvm
(Firecracker microVMs, Rust, agent sandboxing, an explicit security posture). Its
`recipes/` directory ships **rootfs recipes** — a per-environment `build.sh` plus a
shared `scripts/build-rootfs.sh` — that turn a public OCI image into a **pre-warmed
parent**. `recipes/postgres-fixture` is the canonical one: it runs `initdb`, starts
the postmaster, emits a line-JSON ready handshake, then idles; `forkd snapshot`
freezes that primed state and `forkd fork -n` fans out children that get a
ready-to-query DB in ~10 ms instead of ~2 s.

Two findings from reviewing those recipes set the scope of this plan.

**1. The rootfs *mechanism* is not worth adopting — mvm already has the secure
equivalent.** forkd's `scripts/build-rootfs.sh` is `docker pull` → `docker export | tar`
→ `mkfs.ext4 -d` on the host. That collides head-on with two standing mvm invariants:
no Docker/containers anywhere near the image path, and ext4 is never materialized on
the host (it runs in the builder VM — ADR-050). mvm already converts OCI → ext4 with
`mvm_oci::unpack::unpack_layer` + `mvm_build::oci_to_rootfs::materialize_to_ext4` +
`seal_with_verity`, pure-Rust, in the builder VM, with cosign + provenance + audit
(claim 14, `specs/claims/claim-10-oci-image-provenance.md`). **Rebuilding that against
forkd's shell pipeline is an explicit non-goal** — it would regress integrity.

**2. forkd bakes warm state *into a writable rootfs*; mvm structurally can't — and
that exposes a real gap.** mvm's workload rootfs is read-only, dm-verity'd, and
provenance-pinned (claims 3 / 14). Mutable warm state — an initialized `initdb` data
dir, a running postmaster, primed caches — cannot live inside a verity rootfs without
throwing away the verity tree and the provenance chain. So a "warmed parent" in mvm
necessarily decomposes into **three** layers where forkd has one:

| Layer | Holds | mvm home | Status |
|---|---|---|---|
| Immutable rootfs | binaries (postgres, python) | verity ext4 via OCI-materialize / Nix `mkGuest` | **already built** |
| Warm **disk** state | `initdb` output, primed dirs | overlay (`FsOverlayManager`) / volume | substrate exists, no warm-lifecycle |
| Warm **memory** state | running postmaster, primed caches, imported modules | memory snapshot | Plan 123 C2 / Plan 140 |

The base image and the snapshot/fork substrate are covered: OCI-materialize is done;
Plan 123 Phase C builds the Firecracker UFFD/NBD/hugepages fast-resume substrate;
Plan 140 closes the four restore-correctness gaps; and **Plan 148** consumes "one
warmed, paused base snapshot" and fans out N children. **What nothing specs is the
producer of that warmed base** — the declarative warmup → ready → freeze lifecycle,
the catalog fields to author it, and the provenance for the warmed artifact. Plan 148
assumes the warm base exists; **Plan 157 is how it comes to exist.**

This earns its own plan rather than a sub-bullet in 123 or 148: it adds user-facing
surface (a verb to prime and freeze a forkable parent), a catalog schema bump, a
warmup executor with a ready-probe, and a provenance chain for the warmed artifact —
and it is the consumer-facing counterpart that Plan 148's primitive needs to be
useful.

**Second prior-art point (oblique): page-cache warmth, not just disk warmth.** A
*commercial* macOS fast-boot sibling — the **pooled OCI-microVM runtime** (referred
to obliquely per [[feedback_no_competitor_names_anywhere]]; trait key in auto-memory
`reference_objc2_vz_external_references`; design boundary recorded in
[ADR-073](../adrs/073-warm-snapshot-prior-art-adoption-boundary.md)) — bakes a warm
snapshot by running the workload *once during the bake* and capturing a snapshot
whose **guest page cache is already populated**. That is a distinct lever from this
plan's warmup, which primes **disk** state (`initdb` output into a warm overlay). Its
hot-pool reuse model (a released worker kept dirty across cycles) is **refused** under
mvm's one-guest-one-workload + claim-8 posture (ADR-073 §3); only the page-cache-at-
freeze idea is adopted, as a Phase C follow-up below. The other thing it validates is
that this whole warm-path direction is achievable on Apple Silicon (it hits ~10–50 ms
boot, sub-100 ms cold restore) — we just have to reach it without surrendering the
verity/provenance/audit chain.

**Core decision, stated up front: mvm does not warm the rootfs.** A warmed parent is
an immutable verity rootfs (already built) + a sealed warm overlay/volume (disk) + a
memory snapshot (RAM). forkd's "bake into one writable rootfs" model is rejected as a
verity/provenance regression.

**Prereqs / sequencing.** The disk-warm legs (Phases A, B, and the libkrun disk-only
arm of D) reuse OCI-materialize + the overlay manager and need no memory snapshot, so
they can land first. The **memory-snapshot leg** (Phase C's RAM freeze, and the
full-warm arm of D) sequences **after Plan 123 Phase C + Plan 140**. Do not start
before Plan 120 `core_demo_e2e` is green (mirrors Plan 148's prereq note).

## Phase A — Declarative warmup contract (catalog + plan schema)

The capability: a catalog entry can declare *how to warm itself* and *how to know it
is ready*, so warming is data, not a bespoke script per image.

### Task A1: `WarmupSpec` on the catalog entry

`CatalogEntry` (`crates/mvm-core/src/catalog.rs`) gains an optional warmup
declaration; the `Catalog` envelope's `schema_version` bumps 1 → 2 (it lives on
`Catalog`, not the entry).

```rust
#[serde(default)]
pub warmup: Option<WarmupSpec>,

pub struct WarmupSpec {
    /// Command run *inside the guest* to prime the image (e.g. initdb + start postmaster).
    pub command: String,
    /// How the guest signals "primed" so the freeze point can be taken.
    pub ready_signal: ReadySignal,
    /// Fail-closed bound on warmup; on timeout the staging VM is destroyed, nothing sealed.
    pub timeout_secs: u32,
}

pub enum ReadySignal {
    /// Line-JSON `{"event":"ready"}` over the existing guest-agent vsock (primary).
    VsockHandshake,
    /// SIGUSR1 ready-barrier (Plan 123 C2 substrate).
    Sigusr1,
    /// Guest touches a marker path; host polls it over the existing share.
    FileMark { path: String },
}
```

**Files:** `crates/mvm-core/src/catalog.rs`.

- [ ] **Step 1:** Failing test — a `Catalog` JSON with `schema_version: 2` and an
      entry carrying `warmup` round-trips; an entry without `warmup` still
      deserializes (back-compat default `None`); an unknown field inside `WarmupSpec`
      is rejected (`#[serde(deny_unknown_fields)]`, W4.1).
- [ ] **Step 2:** Add `WarmupSpec` / `ReadySignal`, the `warmup` field, bump
      `default_schema_version` → 2, keep `search()` unaffected. Commit.

### Task A2: mirror the warm-state split into the `ExecutionPlan`

A warmed parent must be an admitted, signed artifact (claim 8 path), not an ad-hoc
image. Carry the warmup declaration and the three-layer disposition through the typed
`ExecutionPlan` so synthesis + signing cover it.

**Files:** `crates/mvm-core/src/protocol/` (plan types), the `synthesize_plan` path.

- [ ] **Step 1:** Failing test — synthesizing a plan for a `warmup`-bearing entry
      carries the warmup command + ready signal into the signed plan; verify rejects a
      tampered warmup field.
- [ ] **Step 2:** Thread `WarmupSpec` into plan synthesis + verification. Commit.

## Phase B — Warmup executor + ready-probe lifecycle

The capability: boot the base image into a short-lived *staging* instance, run the
warmup inside the guest, and block until it reports ready — host-observable, bounded,
fail-closed.

### Task B1: staging boot with a read-write warm overlay

Boot the verity base with a **read-write** warm overlay attached (the disk layer that
will hold `initdb` output), distinct from the per-workload runtime overlay.

**Files:** `crates/mvm/src/vm/instance/lifecycle.rs` (staging boot), `crates/mvm/src/vm/overlay.rs`.

- [ ] **Step 1:** Failing test — staging boot attaches a writable overlay; writes from
      the warmup land in that overlay, not the rootfs (rootfs stays `ro`/verity).
- [ ] **Step 2:** Add a `stage_for_warmup` entry that reuses the existing boot path
      with the overlay mounted rw. Commit.

### Task B2: run warmup in-guest + ready handshake

Run `warmup.command` *inside the guest* (consistent with the "shell scripts run inside
the Linux VM" decision — never on the host), then wait on `ready_signal` with the
`timeout_secs` bound, destroying the staging VM and sealing nothing on timeout.

**Files:** `crates/mvm-guest/` (run warmup + emit `{"event":"ready"}` line-JSON over
vsock), `crates/mvm/src/vm/instance/lifecycle.rs` (host-side wait + timeout).

- [ ] **Step 1:** Failing test — guest runs the command and emits the ready handshake;
      host transitions to ready. Negative: a warmup that never signals trips the
      timeout, the staging VM is destroyed, and no artifact is sealed (fail-closed).
- [ ] **Step 2:** Implement the in-guest runner + host-side bounded wait. Commit.

### Task B3: make `InstanceReadiness::ServicesStarting` updatable

`InstanceReadiness::ServicesStarting { pending }`
(`crates/mvm-core/src/domain/instance.rs:191`) is write-once today — it is set but
never drained as services report healthy. Wire the ready handshake to drain `pending`
so warmup readiness is observable through the existing readiness machinery.

**Files:** `crates/mvm-core/src/domain/instance.rs`, `crates/mvm/src/vm/name_registry.rs`.

- [ ] **Step 1:** Failing test — `set_readiness` drains a named service from `pending`
      on its ready signal; the VM reaches `AgentReady`/clear-pending only when the
      list empties.
- [ ] **Step 2:** Add the drain transition + registry update. Commit.

## Phase C — Freeze + export as a forkable parent

The capability: at the ready point, capture the warm parent and publish it as a
catalog/registry entry that Plan 148 Phase A fan-out consumes directly.

### Task C1: freeze (seal warm overlay + memory snapshot)

On ready, quiesce and capture both warm layers: seal the warm overlay/volume as the
parent's CoW base (hash-locked like a deps volume — claim 11 style), and take the
**memory snapshot** via the Plan 140 / 123 C2 substrate. On a `snapshots == false`
backend, capture disk only (see Phase D).

**Files:** `crates/mvm/src/vm/instance/snapshot.rs`, `crates/mvm/src/vm/overlay.rs`
(seal path).

- [ ] **Step 1:** Failing test — freeze produces a sealed, hash-locked warm overlay +
      (where supported) a memory snapshot; a byte-flip on the sealed overlay is
      rejected at consume time (`verify_sealed_volume`-style).
- [ ] **Step 2:** Implement quiesce → seal overlay → snapshot memory. Commit.

### Task C2: `mvmctl image warm` verb + provenance

A new verb materializes the base (reusing OCI-materialize / Nix `mkGuest` — **not**
re-implementing it), runs Phases B–C, and emits a catalog/registry entry tagged as a
**forkable parent**. The warmed artifact carries its own provenance: base image
digest, the warmup command, and the sealed output digests, recorded in the
chain-signed audit log so the parent holds no un-attested mutable state.

**Files:** `crates/mvm-cli/src/commands/image.rs` (verb),
`crates/mvm-cli/src/commands/vm/audit_chain.rs` (`AuditEmitter` warmed-parent entry,
mirroring `emit_oci_provenance`).

- [ ] **Step 1:** Failing test (`tests/cli.rs`) — `mvmctl image warm <entry>` help +
      argument parsing; a dry-run emits a provenance record carrying base digest +
      warmup command + sealed output digest; `mvmctl audit verify` accepts the chain
      and rejects a tampered warmed-parent entry.
- [ ] **Step 2:** Wire the verb end-to-end through Phases B–C + provenance emit. Commit.

## Phase D — Per-backend disposition + honest degradation

A warmed parent means different things per backend; surface the difference, never
silently degrade (matches Plan 148 / 123 posture).

| Backend | `caps.snapshots` | Warmed parent = |
|---|---|---|
| Firecracker / cloud-hypervisor | `true` | full warm: memory snapshot + sealed CoW overlay → feeds Plan 148 Phase A |
| Vz (macOS 26+) | `true` | save/restore-based warm parent (no live branch) |
| libkrun / apple-container | `false` | **disk-only**: sealed warm overlay, memory is a cold boot |

**Files:** `crates/mvm-core/src/protocol/vm_backend.rs` (`snapshot_capability()`),
`crates/mvm-cli/src/commands/` (`doctor` reporting).

- [ ] **Step 1:** Failing test — `image warm` on a `snapshots == false` backend
      produces a disk-only forkable parent and reports it as such; `doctor` shows the
      per-backend warmed-parent disposition.
- [ ] **Step 2:** Implement the per-backend branch + honest `doctor` line. Commit.

## Security posture

- The warmed parent is a signed, admitted artifact (claim 8) — synthesized + verified
  through the plan path, never an ad-hoc image.
- The warm overlay/volume is sealed and hash-locked (claim 11 style); the freeze step
  re-admits; a tampered warm layer is rejected before any child boots.
- Forked children still get fresh per-instance identity (IP, instance-id, secrets
  disk, nonce) and post-resume hygiene (entropy reseed, clock resync, VMGenID) per
  Plans 148 / 140 — Plan 157 only produces the base, it does not relax child isolation.
- **Dev vs prod tiers:** dev warmed parents (for `mvmctl dev` fast iteration) need not
  be verity-hardened; **prod** warmed parents must seal + sign (the standing
  dev-VM-vs-prod-runtime tier split).

## Out of scope

- Fan-out count, when/how many children, and the speculative-execution + judge pattern
  — orchestration policy lives in mvmd + Plan 148, not here.
- Live BRANCH of a *running* parent — Plan 148 Phase B (a measured go/no-go, not a
  commitment).
- Rebuilding the OCI → ext4 rootfs builder — already exists (`unpack_layer` +
  `materialize_to_ext4` + `seal_with_verity`); explicitly **not** adopting forkd's
  `scripts/build-rootfs.sh`.

## Candidate recipes (target menu)

Expressed as mvm catalog entries with a `WarmupSpec`, drawn from forkd's recipe set:
`postgres-fixture` (initdb + postmaster), `jupyter-kernel`, `node`, `code-interpreter`,
`python-numpy`. Note forkd's own recipes are thin — `python-numpy` has *no* warmup
(just `apt install python3-numpy`); only `postgres-fixture` truly warms — so this is a
**target list, not a borrowed design**. `postgres-fixture` is the natural first
recipe (it exercises the full disk + memory freeze).

## Deferred follow-ups

- [ ] **Page-cache priming at freeze (ADR-073 §1).** Extend Task C1's freeze so the
      memory snapshot captures a *warm guest page cache*, not just a quiesced one:
      before taking the snapshot, touch the entry's declared working set (a new
      optional `WarmupSpec` field, e.g. `prime_paths` / a prime command) so the
      restored child does not pay cold page-fault cost on first access. This is a
      property of the **memory-snapshot layer** (distinct from the disk warm overlay
      Phase B already produces) and only applies on `caps.snapshots == true` backends
      (FC/CH/Vz); on `snapshots == false` it is a silent no-op (the parent is
      disk-only anyway, Phase D). Sequences behind the same memory-snapshot substrate
      as Task C1 (Plan 123 Phase C / Plan 140). Plan 140's restore inherits the
      warmth for free. Borrowed *design-level only* from the pooled OCI-microVM
      runtime's `with_warmup` (ADR-073) — no code adopted, and its hot-pool reuse is
      explicitly **not** taken. **Scope (ADR-073 §1):** `prime_paths` resolves inside
      the immutable verity'd **root volume** only — never mounted data/app-dep volumes,
      never secrets (which never live in a volume anyway; claims 12/13). The primed
      cache is shared across every fork, so priming mutable/sensitive state would leak
      it (claim 1 / 11); the freeze step rejects a working set that escapes the rootfs.

## Success criteria

- [ ] `Catalog` schema 2 round-trips with and without `warmup`; unknown fields rejected.
- [ ] `mvmctl image warm postgres-fixture` produces a forkable parent: sealed warm
      overlay + (FC/CH) memory snapshot, with a verifiable provenance entry.
- [ ] Warmup timeout fails closed — staging VM destroyed, nothing sealed.
- [ ] A `snapshots == false` backend yields an honest disk-only parent; `doctor`
      reports the disposition.
- [ ] A Plan 148 Phase A fan-out consumes a 157-produced parent unchanged (integration
      seam, once 148 lands).
