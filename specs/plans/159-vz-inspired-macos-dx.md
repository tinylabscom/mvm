# Plan 159 — vz-inspired strong macOS VZ support (DX + feature clone)

> **Status (2026-06-04):** Scoped, not started. **Depends on Plan 152**
> (Rust-native `objc2` VZ supervisor) — the DX surface here assumes the
> supervisor is the unit we extend, and several workstreams need its
> snapshot/control primitives. Sequence after Plan 152 WS-B lands (which
> is itself gated on Plan 120 green).
>
> **Numbering:** renumbered 153 → **159** at close-out (153 collided with
> committed `153-cli-command-group-modularization.md`); 159 was free at
> write time (main tops at 161, PR #589 holds 162). Re-confirm before
> merge — the `check-spec-numbers` Lint gate hard-fails on a duplicate.
>
> **Overlaps existing plans — this plan owns only the additive slice, and
> cross-references the rest (do not duplicate):** the warm path (WS-1) is
> the *infra* warm pool (pre-spawned supervisor+moat+booted blank VM) and
> sits alongside **Plan 157** (`warmed-parent-recipes` — warm *app/memory
> state* + freeze) and **Plan 123 C**; checkpoints/fork (WS-2) build on
> **Plan 148** (fork-fanout) + **Plan 140** (snapshot productionization);
> nested-virt overlaps **Plan 147**. Where a neighbor already owns the
> primitive, WS-* here is the DX/UX layer on top, not a reimplementation.
>
> **Naming:** the inspiration project is referred to obliquely ("the
> multi-crate Rust-native VZ runtime" / "the DX reference") per repo
> naming policy. Oblique-reference key is in auto-memory
> (`reference_objc2_vz_external_references`).

## Context

We want the **best-possible Apple `Virtualization.framework` (VZ)
support** on macOS. A wider prior-art review (recorded in Plan 152) found
a multi-crate Rust-native VZ runtime whose **UX/DX is its strongest
asset** — a snappy "create, snapshot, exec in seconds" experience on
Apple Silicon. We will **clone the good parts in our own Rust**, treating
it strictly as **inspiration, never a dependency** (`feedback_replace_over_workaround`,
`feedback_limit_dependencies`), and **not** by adopting Apple's Swift
`Containerization` framework (that option was considered and declined —
it re-introduces Swift and a large framework dep right as Plan 152
removes Swift; we clone in Rust instead).

What we already have (exploration, 2026-06-04): our `apple_container`
backend is **100% Rust via `objc2`** (`crates/mvm-backend/src/
apple_container.rs` + `providers/apple_container/macos.rs`) — boot, run,
PTY-over-vsock console, exec via the guest agent (vsock port 5252), and
**per-instance APFS copy-on-write rootfs cloning** all work today (Tier 2,
ADR-002). The gaps are **DX and stateful-isolation features**, not the VZ
plumbing:

- `capabilities()` reports `pause_resume=false`, `snapshots=false` — no
  checkpoint/restore/fork on the runtime tier (the VZ API supports it;
  the supervisor already has `saveMachineStateToURL`).
- No warm path: every `dev up` / `run` boots cold; no standby daemon
  (Plan 118 standby pool / Plan 93 warm-pool are unbuilt for macOS).
- Codesign/entitlement repair is internal-only (`ensure_signed()`); no
  user-facing self-sign for source-checkout users.
- Acquisition (builder VM / dev image) is hash-verified (claim 6) but not
  resumable and doesn't frame the one-time cost.
- CLI `--json` coverage and verb vocabulary are uneven.

The security spine is non-negotiable: every DX feature here lands
**without** regressing claims 1–14, without SSH, and without breaking
hermetic-Nix (ADR-046). Snapshots bind to the existing snapshot
crypto/audit spine.

## Workstreams

Ordered by leverage. Each is independently shippable on top of the
Plan 152 supervisor.

### WS-1 — Warm runtime path: the latency story (highest leverage)

Goal: make `mvmctl up` / `run` feel **instant** by having a VM warm
before the user asks — the DX reference's resident-daemon effect —
**without** collapsing our per-VM supervisor + process-moat into one
daemon. The reference runs a single long-lived daemon that *reuses* VMs;
we **cannot** reuse a VM across workloads (single-tenant-for-lifetime,
claims 3/8). So our pool holds **unassigned, pristine slots that are
consumed and destroyed**, not a recycled daemon.

**What "warm" buys (tiered).** Cold `up` pays: (1) spawn + cosign-verify
the supervisor + moat subprocesses (broker/host-signer/audit-signer),
seccomp/setpriv/cgroup setup; (2) VMM create + kernel load + device
setup; (3) guest boot → init → agent-ready; (4) per-workload admission
(synthesize + sign the `ExecutionPlan`, verify, first audit entry);
(5) attach the workload rootfs (APFS-CoW). Steps (1)–(3) are
**workload-agnostic** when the base image is shared and are most of the
latency; (4) is per-workload but cheap once the signer is warm; (5) is
already fast. We pre-pay (1)–(3); (4)–(5) stay at claim time.

**Architecture — a thin standby pool of per-VM stacks, not a mega-daemon.**
- A small **pool manager** maintains N *unassigned* warm slots. Each slot
  is a complete per-VM stack: supervisor + moat subprocesses
  (cosign-verified, seccomp'd) + a booted VM on the **dm-verity'd base
  image** (claim 3) with the agent up and **idle** — no workload code has
  run. Per-VM isolation + process moat unchanged; the pool just holds
  them pre-assembled.
- **Claim:** `up` takes a slot, runs admission for THIS workload (sign the
  plan via the already-warm `host-signer`, emit the first audit entry via
  the warm `audit-signer`), CoW-attaches the admitted workload layer over
  the base, starts the entrypoint. The slot **leaves the pool permanently**.
- **Single-tenant (Plan 93 invariant):** a claimed slot is bound to one
  workload and **destroyed at workload end — never returned to the pool**.
  The pool refills asynchronously with fresh slots. A warm slot is
  pristine (verified base, idle agent) until claimed, so nothing crosses
  between workloads.

**Tiered warmth (handles heterogeneous images).** A pre-booted slot only
helps workloads sharing its base (dev shell, function workloads on the
common base). For arbitrary `--flake` / OCI images:
- Tier A (base match) → full warm slot → instant.
- Tier B (different rootfs/kernel) → reuse a *partially* warm slot:
  process moat pre-spawned + cosign-verified + VMM host state prepped, but
  a fresh guest boot on the workload image. Skips (1) and part of (2).
- Tier C → cold fallback. Always available; pool exhaustion or an
  unsupported backend degrades to cold (logged, never a hard failure).

**Pool manager lifecycle (invisible, but no permanent idle daemon).**
Autostarts on first use, **idle-evicts to zero** after a TTL of no
activity (the reference keeps its daemon resident; we self-evict so we
don't hold an always-on process + idle VMs against our posture), re-warms
on next use. Small N (default 1–2), hard resource ceiling.

**Security posture (keyless launcher — not a new trust boundary).** A
resident pool manager is acceptable because it holds **no keys and never
sees a workload's plan or secrets**: warm slots are pristine (verified
base, idle agent, no workload code), the per-VM host/audit signers hold
their keys per-VM, and per-workload admission + signing happen at
**claim** inside the per-VM moat — not in the manager. So it is a
launcher/bookkeeper — the same architectural-not-trust boundary as Plan
104 T6. The one genuinely new surface is the post-spawn `configure` RPC
(tracked in Plan 104): it must carry the *same supervisor-signed config*
as today's stdin path, be **accepted exactly once**, and be verified
before acceptance — no weakening of H-L3.6 config-signing. Warm slots are
**verified-base-only** and **single-use** (destroyed after claim, never
recycled); a hard count ceiling + idle-evict bound resource/DoS
exposure. Net: no new keys at rest, no new cross-workload data path, one
new authenticated control RPC.

**Coupling to Plan 104 (must coordinate).** The moat subprocesses today
take a *signed config on stdin at spawn* (workload `ExecutionPlan.services`
bindings + agent profile + session key — Plan 104 §Subprocess lifecycle).
To pre-spawn before the workload is known we must defer that: pre-spawn
generically through cosign-verify + seccomp, then **inject the signed
workload config at claim** over the supervisor↔subprocess UDS (a small
Plan 104 lifecycle change: stdin-config → post-spawn "configure" RPC).
This amortizes the expensive cosign-verify/seccomp step. **WS-1 is
sequenced strictly after Plan 104**, which now tracks this `configure`
RPC as a deferred item; it is a dependency to land there, not a free win.

- [ ] Pool ownership (RESOLVED 2026-06-04): **route through mvmd when it
      manages this host** — mvmd is already a resident daemon and owns
      fleet warm pools (Plan 93/118), so the managed case adds **no new
      daemon**; for **standalone dev** (no mvmd) a small **local
      idle-evicting pool manager** fills the same role. `up`
      **auto-detects**: mvmd-managed → request a slot from mvmd; else
      local pool; else cold. Warm-vs-cold and the A/B/C tier are
      auto-selected, always with transparent cold fallback (the user never
      picks). Resident-process posture accepted (keyless launcher — see
      Security posture above).
- [ ] Build the pool on Plan 118 / Plan 93's mechanism — don't duplicate;
      WS-1 is the UX + tiered-warmth + claim layer on top.
- [ ] Pre-warm a slot: supervisor + moat (cosign-verified, seccomp'd) +
      booted verified-base VM + idle agent. Assert the base is the
      dm-verity image (claim 3).
- [ ] Claim path: take slot → admit THIS plan (warm host/audit signers) →
      CoW-attach workload layer → start. Slot leaves the pool permanently;
      single-tenant; destroy at end; refill async.
- [ ] Resolve the Plan 104 subprocess-config coupling (post-spawn
      configure RPC) so the moat can be pre-spawned.
- [ ] Tier B/C fallback + cold-path degradation that never hard-fails;
      log the tier hit.
- [ ] Invisible UX: autostart, idle-evict to zero, `MVM_WARM_POOL=0`
      opt-out, `mvmctl dev status` / `doctor` reporting (depth, RAM held,
      tier hit-rate). Publish cold-vs-warm latency (Plan 127 rig).

**Invariants (do not regress):** single-tenant per VM; warm VMs run only
the verified-boot base until claimed; per-workload admission + signing +
audit still happen at claim, in the same per-VM moat (claims 3/8/12/13).
The warm path changes *when* the stack is assembled, never *what* gates a
workload.

### WS-2 — Checkpoint / restore / fork DX for the VZ runtime

Clone the reference's **tiered, fail-closed checkpoint model** and bring
snapshots to the `apple_container` runtime tier (currently
`snapshots=false`).

- [x] Two classes, fail-closed (no silent degradation): `fs_quick`
      (default) backed by our existing **APFS CoW** rootfs clone (fast,
      filesystem-only) — **landed PR1**; `vm_full` backed by
      `saveMachineStateToURL` / `restoreMachineStateFromURL` (memory state,
      macOS 14+) — **landed PR2**. Rejects `vm_full` with a hard error when
      the backend can't honor it. `snapshot save`/`snapshot restore` retired.
- [x] `restore_checkpoint` — same-identity resume from `vm_full` state;
      re-hashes blobs, records `checkpoint.restored` audit entry.
- [x] `vm_full` **fork arm** — new-identity restore (rewrite config,
      fresh audit lineage, `checkpoint.forked` entry). First-class **fork**:
      branch a new sandbox lineage from a checkpoint (`fork <ckpt> [--new-id]`),
      reusing the per-instance CoW clone we already do.
- [ ] `checkpoint diff <a> <b>` — versioned diff between two checkpoints
      (the reference's `diff` verb), for inspecting what a fork changed.
      **(PR3)**
- [x] `--tag` to pin a checkpoint against GC; untagged ones follow cache
      retention (`cache prune` already exists — extend it).
- [x] Flip `apple_container` `capabilities()` to advertise the supported
      classes; wire `mvmctl pause/resume` + a `snapshot`/`checkpoint`
      verb to the VZ path (today `pause.rs::snapshot_io_for` is
      Firecracker-only).
- [x] Bind every checkpoint to the snapshot crypto/audit spine (Plan 97
      E / 140) — a checkpoint is signed + recorded, like a Firecracker
      snapshot. Do not ship an unaudited fork primitive.

### WS-3 — `mvmctl sign` — user-facing entitlement/codesign repair

The DX reference exposes a one-command `self-sign` that re-signs the
binary with `com.apple.security.virtualization`, with an entitlements
lookup chain + temp-file fallback. We do this internally
(`ensure_signed()`); a user-facing command is a big friction-killer for
source-checkout / `cargo install` macOS users.

- [ ] `mvmctl sign` (near `doctor`): re-sign `mvmctl` and the
      `mvm-vm-host` supervisor bin(s) with the right entitlements via the
      existing `ensure_signed()` harness; print signed paths + verify.
- [ ] `mvmctl doctor` reports signing status and suggests `mvmctl sign`
      when an entitlement is missing (it already probes the backend).
- [ ] Keep auto-sign on the normal path; `sign` is the explicit repair.

### WS-4 — Acquisition DX: honest cost, local-first, resumable

Borrow the reference's acquisition ergonomics for our builder-VM / dev
image bootstrap **without** touching the hermetic-Nix contract (the
artifacts are still locally built per ADR-046; this is only about how
**published prebuilts** are fetched at release-install time).

- [ ] Honest one-time-cost framing: when a first-run download is
      unavoidable, print the payoff inline ("one-time — subsequent runs
      restore from a warm supervisor in seconds").
- [ ] Local-first resolution chain (flag → installed path → cache → CDN)
      where applicable to `download_dev_image`.
- [ ] Resumable downloads (HTTP Range + a `download-state.json`) layered
      under the existing SHA-256 verification (claim 6 — never weaken the
      hash gate or `MVM_SKIP_HASH_VERIFY` posture).

### WS-5 — CLI ergonomics: consistent `--json` + verb parity

- [ ] Audit `crates/mvm-cli/src/commands/` for `--json` coverage; add it
      everywhere a machine-readable shape is useful (inspect/list/status).
- [ ] Verb-vocabulary consistency pass (list/inspect/rm/logs/exec)
      across vm/image/network surfaces. Polish, not new capability.
- [ ] Resume ergonomics: `-c/--continue` (re-attach the most recent
      sandbox), `-r/--resume <id>`, and `--ephemeral` (auto-clean when
      safe) — the reference's session-continuity flags.
- [ ] Streamed `exec`: confirm `mvmctl exec` streams stdout/stderr/exit
      in source order (the reference's `StreamExecOutput`), not just
      capture-then-return.

### WS-6 — Decision-gated (notes only; each needs sign-off before work)

These are headline reference features that **conflict with current
invariants**; capture them so the decision is explicit, don't start them.

- [ ] **macOS guests** (`VZMacOSBootLoader` / IPSW). The reference's big
      differentiator — full macOS VMs. For us this is a **threat-model +
      scope expansion** away from headless-Linux workloads (ADR-001) and
      would need its own ADR (acquisition, signing, what the security
      claims even mean for a macOS guest). **Needs an ADR before any
      work.**
- [ ] **Project `init` + config file** (toolchain autodetect → a project
      config, the reference's `vz init`/`vz.json`). Nice DX but cuts
      against our hermetic-Nix `--flake` model (ADR-046) — same tension
      as the gap-analysis `--rootfs` quick-import. Decide vs `--flake`
      first.
- [ ] **OCI / Compose-style verb surface.** The reference exposes
      docker-style `pull/run/ps/...` + a Compose `stack`. We have
      `mvm-oci` (signed-provenance ingest) and are single-workload by
      design. A multi-service `stack` is an orchestration concept that
      lives in **mvmd**, not mvmctl (`feedback_prod_gate_lives_in_mvmd`).
      Decide the boundary before cloning any compose UX.

## vz DX/UX parity checklist

Every DX/UX feature from the reference, mapped to its disposition — so
coverage is auditable and nothing falls through. "exists" = we already
have it; "WS-n" = owned by a workstream above; a plan number = owned
elsewhere; "candidate" = not yet owned, decision needed.

| Reference DX/UX feature | Disposition |
|---|---|
| Resident warm daemon → "instant" feel | **WS-1** (warm pool; mvmd-routed, idle-evicting local manager) |
| `run` / `run -i` one-shot in project VM | exists (`mvmctl up`/`run`/`console`) + **WS-5** polish |
| No-SSH vsock `exec` | exists (guest agent, vsock 5252) |
| Streamed `exec` (stdout/stderr/exit in order) | **WS-5** (confirm streaming) |
| Interactive `attach` / shell | exists (`mvmctl console`, PTY-over-vsock) |
| `checkpoint create/restore/fork`, tiered `fs_quick`/`vm_full` | **WS-2** |
| `checkpoint diff` (versioned) | **WS-2** |
| `--tag` pin against GC | **WS-2** |
| `self-sign` entitlement repair | **WS-3** (`mvmctl sign`) |
| `--json` everywhere + docker-style verb parity | **WS-5** |
| `-c/--continue` / `-r/--resume` / `--ephemeral` | **WS-5** (resume ergonomics) |
| Honest one-time-cost + local-first + resumable downloads | **WS-4** |
| Install one-liner (`curl \| sh`) for CLI/agent | **WS-4** (release-install path) |
| Reach host services (`host.*.internal`) | **Plan 104** — brokered `host.fetch.v1`/`host.endpoint.v1` (not raw NAT) |
| Published ~1s boot metric | **Plan 127** bench (WS-1 publishes warm-vs-cold) |
| Background-daemon `logs` | **WS-1** (`dev status`/`doctor` + logs) |
| `init` project autodetect → config file | **WS-6** (decision-gated vs hermetic-Nix `--flake`) |
| macOS guests (IPSW / `VZMacOSBootLoader`) | **WS-6** (decision-gated; needs ADR) |
| OCI / Compose `stack` | **WS-6** + `mvm-oci` for images; multi-service `stack` is mvmd's domain |
| **Signed patch / binary-delta image distribution** (`vm patch create-delta`/`apply-delta`) | **candidate — not yet owned.** Overlaps `mvm-oci` provenance + Plan 155 (portable artifacts) / 156 (binary size). Decide whether to route there or spec separately before claiming DX parity. |

The only **uncaptured** item is signed patch/delta image distribution
(last row). Everything else is either already in mvm, owned by a
workstream here, or owned by a named neighbor plan.

## Non-goals

- Any reviewed project as a **dependency** — inspiration only; we clone
  in our own Rust.
- Adopting Apple's Swift `Containerization` framework (declined — keeps
  us on the Rust-`objc2` path Plan 152 commits to).
- SSH into guests; in-guest agent injection (claim / ADR-001).
- Regressing any of claims 1–14; shipping an **unaudited** snapshot/fork
  primitive (WS-2 binds to the audit spine).
- Weakening the claim-6 hash gate for the resumable-download DX (WS-4).
- Multi-service orchestration in mvmctl (that is mvmd's domain).

## Verification

Per-workstream, on the local Vz dev host (isolate with
`MVM_CACHE_DIR`/`MVM_DATA_DIR`; `project_dev_host_runs_builder_via_vz`):

1. **WS-1:** measure cold vs warm `dev up` / `run`; assert the warm path
   is materially faster and that a warmed VM is never reused across
   tenants. Publish the number (Plan 127 rig).
2. **WS-2:** `fs_quick` checkpoint → fork → run in the fork; `vm_full`
   save → restore round-trip; assert `vm_full` hard-fails on an
   unsupported backend; assert every checkpoint is signed + appears in
   the audit chain (`mvmctl audit verify`).
3. **WS-3:** on a fresh source checkout, `mvmctl sign` makes a
   previously-unsigned binary boot a VZ VM; `doctor` flips to OK.
4. **WS-4:** interrupt + resume a dev-image download; assert byte-correct
   result still passes the SHA-256 gate.
5. `cargo nextest run --workspace`, `cargo test --workspace --doc`,
   `rustup run nightly cargo fmt --all -- --check`, `cargo clippy
   --workspace -- -D warnings`. `mvm-backend` test bins can be macOS-
   codesign-SIGKILL'd locally — lean on Linux CI
   (`reference_mvm_backend_test_binary_macos_codesign_sigkill`).

Never run `core_demo_e2e` unbounded
(`feedback_never_run_core_demo_e2e_unbounded`).

## References

- `specs/plans/152-rust-native-vz-and-init-lifecycle-parity.md` — the
  Rust supervisor this plan extends; its *Findings* hold the prior-art
  table.
- `specs/plans/93-...` (Apple Container warm-pool, sub-200ms launch) and
  `specs/plans/118-...` (standby pool) — WS-1's existing homes.
- `specs/plans/97-vz-backend.md` (Phase E snapshots) + `specs/plans/140-...`
  (snapshot save/restore) — WS-2's audit-bound snapshot spine.
- `specs/plans/127-...` (bench) — WS-1's published latency number.
- `specs/research/on-device-vz-sandbox-gap-analysis.md` — the
  product/feature surface this plan operationalizes.
- `crates/mvm-backend/src/apple_container.rs` +
  `providers/apple_container/macos.rs` — the Rust/objc2 runtime tier WS-1
  and WS-2 extend (APFS CoW, vsock proxy, `capabilities()`).
- `crates/mvm-cli/src/commands/` — WS-3/WS-4/WS-5 edit sites.
- ADR-001 (headless / Firecracker-only philosophy), ADR-002 (claims +
  tier matrix), ADR-046 (hermetic Nix) — the guardrails WS-6 decisions
  test against.
- Oblique-reference key: auto-memory
  `reference_objc2_vz_external_references`.
