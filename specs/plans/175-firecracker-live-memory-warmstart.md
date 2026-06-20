# Plan 175 — Firecracker live-memory warm-start (Plan 123 C2 carve-out)

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **This work is live-KVM-gated** — it cannot be verified on a macOS dev host; land each task on Linux CI / a Lima Firecracker VM.

**Goal:** Finish the one warm-start tier that is real, valuable, and still unbuilt: Firecracker **live-memory fast-resume** (~1s, VMGenID-reseeded). Plan 123 Phase C delivered the honest capability matrix (C1) and the libkrun disk-only path + the fail-closed `warm_start` seam (C4, #741). What remains is the Firecracker live-memory recipe (C2) and the user-facing verb that drives it. This plan carves that out of Plan 123 so it stays tracked rather than dissolving into "deferred (gated)".

**Parent:** Plan 123 Phase C (`specs/plans/123-network-storage-warmstart.md` §"Phase C", Tasks C2 + the C4 CLI/RPC follow-up). Vz save/restore (was C3) is **owned by Plan 152 WS-C** — out of scope here; cross-referenced only.

**Why a separate plan:** Plan 123's network + storage thrust is done and its top-line reads 🟢; its two gated warm-start tiers risk being read as "shipped". A focused plan keeps the live-memory work visible, sized, and honestly gated.

## What already landed (the seam this builds on)

Do **not** rebuild these — verify-who-calls before extending:

- **C1 — capability tier.** `SnapshotCapability {LiveMemory,SaveRestore,DiskOnly,Unsupported}` + `VmBackend::snapshot_capability()` (`crates/mvm-core/src/protocol/vm_backend.rs`); Firecracker = `LiveMemory`.
- **C4 — warm-start operation seam (#741).** Typed `WarmStartError` (ADR-053 recovery hint), `SnapshotCapability::{label,satisfies}` (the fail-closed tier gate), and the `VmBackend::warm_start(config, requested)` default that returns `Unsupported` on an over-request and `Failed("not wired")` when the tier admits but no backend impl exists. **Firecracker still rides that `Failed` default** — Task 4 below replaces it. doctor surfaces the matrix + the Linux NBD/HugeTLB substrate probe.
- **PostRestore sender (#734).** `mvm::vm::instance_snapshot::signal_post_restore` + `VsockPostRestoreSignal` route `GuestRequest::PostRestore` to the guest through `vsock_transport::for_vm`; an unacknowledged signal fails closed. **Today `GuestRequest::PostRestore` carries no payload** (`crates/mvm-guest/src/vsock.rs:194`).
- **VMGenID substrate (Plan 122 D).** Host mint `mvm_core::crypto::vmgenid::fresh_generation_token` → `GenerationToken`; guest reseed `mvm_guest::genid::GenIdReseeder::on_genid` (wraps the pure `GenIdState` change-detector + `reseed_kernel_csprng`). `crates/mvm-guest/src/genid.rs:11` states outright that **delivery — the host sending the token over vsock — is the missing piece.** That is Task 1.
- **Snapshot store.** `instance_snapshot.rs`'s `FirecrackerIO` (`vmstate.bin` / `mem.bin` create/load over the FC API socket) + `pause_and_seal` / `verify_and_resume` (integrity-sealed, replay-checked, optionally encrypted).

## Gating & verification environment

Every task here needs a **live KVM** Firecracker VM — none of it verifies on a macOS dev host. Recipe (per the repo's standing Linux-verification pattern):

- Cross-build the test binary on the Mac: `cargo-zigbuild test --target aarch64-unknown-linux-gnu.2.31 --no-run` (`PATH="$HOME/.cargo/bin:$PATH"`).
- Copy into the running `rvproxy-firecracker-lima` VM; run under `sudo env <FLAGS> ./<bin> <filter>`.
- Gate the live tests behind an env flag (e.g. `MVM_LIVE_KVM=1`), mirroring `MVM_LIVE_LUKS=1` — unit-buildable everywhere, executed only where KVM exists.

---

## Task 1: VMGenID delivery on resume (the next real increment)

The smallest end-to-end win: make a resume actually rotate the guest CSPRNG, so two clones of one snapshot don't generate identical secrets. The host has the token mint and the sender; the guest has the reseeder; only the wire payload is missing.

**Files:** `crates/mvm-guest/src/vsock.rs` (`GuestRequest::PostRestore`, `GuestResponse::PostRestoreAck`), `crates/mvm/src/vm/instance_snapshot.rs` (`signal_post_restore` / `VsockPostRestoreSignal`), the guest PostRestore handler.

- [x] **Step 1 (RED, unit, no KVM):** Failing test that a `PostRestore` carrying a `GenerationToken` round-trips the wire (`serde` + `deny_unknown_fields`), and that the guest handler feeds the delivered token to `GenIdReseeder::on_genid` and returns `PostRestoreAck { success, reseeded }` reflecting the change-detect outcome. A repeated identical token is a no-op (`reseeded = false`); a changed token reseeds (`reseeded = true`). The pure `GenIdState` logic already has coverage — this tests the *delivery + dispatch*, mockable without a guest. **DONE** — `genid::tests::{post_restore_zero_token_is_no_rotation,two_clones_of_one_snapshot_rotate_to_distinct_state}` + `vsock::tests::{post_restore_token_roundtrips_and_defaults_to_zero,post_restore_ack_carries_reseeded_flag}`.
- [x] **Step 2:** Add a `token: [u8; GENID_BYTES]` (or `GenerationToken`) field to `GuestRequest::PostRestore`; thread it from `signal_post_restore` (host mints via `fresh_generation_token(content_hash)` at resume) into `VsockPostRestoreSignal`; call `GenIdReseeder::on_genid` in the guest handler before the existing remount/restart work. Keep the no-token-needed callers (template restore) honest: either a distinct request or a documented zero token that the reseeder treats as "no rotation". **DONE** — struct-variant `PostRestore { token }` (`#[serde(default)]` zero = no-rotation), `PostRestoreAck { reseeded }`, process-resident `GenIdReseeder` static + zero-aware `on_post_restore_token` dispatch; both host senders (`VsockPostRestoreSignal`, `post_restore_at`) mint per-resume; `mvmctl resume` surfaces "VMGenID rotated".
- [ ] **Step 3 (live-KVM gated):** Snapshot → restore round-trip on the Lima FC VM; assert the guest's `/dev/urandom` draw **differs** across two restores of the same snapshot (the claim that matters), and that `PostRestoreAck.reseeded == true`. Entropy-source note: 122 D stirs `/dev/urandom`; if Plan 140 gap #2 swaps to virtio-rng + `RNDADDENTROPY`, `GenIdReseeder` isolates the source from the change-detection, so either composes. **GATED — rides Task 4's FC restore driver** (needs a real snapshot→restore of an mvm guest agent over vsock; the host/unit delivery + dispatch is proven above).

## Task 2: UFFD / NBD / hugepages fast-resume substrate

ADR-066 §7 — the ~1s resume recipe. This is the heavy systems work; commit per sub-piece, each with its own live-KVM test.

- [ ] **Step 1 — diff/layered snapshots.** One read-only golden memory base + a COW per-VM delta, reusing Phase B3's `SnapshotUpper` (storage half already shipped). Snapshot artifacts stay content-addressed + signed (122 Phase C). Test: a delta restore reproduces guest state without copying the full base.
      - **Chaining note (from the sibling's diff-snapshot design):** Firecracker clears the dirty bitmap on *every* `snapshot/create`, so a second Diff taken from an evolving source only captures pages dirtied since the first — applying it onto the boot-state base would drop everything dirtied before snapshot 1. The clean fix is **not** a separate per-source shadow file: each completed snapshot's `mem.bin` is, by construction, the source's full memory at that point, i.e. exactly the base the next Diff layers onto. Track `last_snapshot_mem_path` and diff against it; fall back (with a warning) to the golden base if an intermediate snapshot was pruned. This keeps repeated re-snapshots of one warming/branching source O(dirty pages) without maintaining shadow state. Content-addressing already dedups the shared base pages across the chain.
- [ ] **Step 2 — `userfaultfd` page-fault handler.** Stream guest pages on demand from a content-addressed memfile instead of a full `mem.bin` load. **Evaluate the `userfaultfd` crate vs. raw `libc` ioctls under the dep budget** (memory: limit deps; prefer the workspace's existing primitives). Test: a resumed guest faults pages lazily and runs correctly.
- [ ] **Step 3 — NBD-served rootfs + 2 MB hugepages.** Serve the rootfs over NBD (the doctor substrate probe already checks the module is loaded) and back the memfile with hugepages (doctor checks the HugeTLB reservation). Test: resume succeeds with both wired; doctor's substrate lines reflect the live host.

## Task 3: SIGUSR1 "primed" ready-barrier

A workload signals it has finished warming (caches, JITs, model load); the host snapshots **at that point** for a deterministic warm base, so every resume starts past cold-start.

- [ ] **Step 1 (RED):** Test the barrier protocol — the host waits for the workload's "primed" signal before invoking `pause_and_seal`, and times out / fails closed if it never arrives (no half-warmed snapshot).
- [ ] **Step 2:** Wire SIGUSR1 (or the vsock equivalent — pick the one that doesn't require a new guest privilege) from a primed workload to the host snapshot trigger. Commit.

## Task 4: `warm_start` CLI/RPC wiring (replaces the `Failed` default for Firecracker)

The user-facing verb that drives all of the above. Until this lands, `warm_start` is reachable only as a trait method with no caller — Firecracker rides the C4 `Failed("not wired")` default.

**Files:** `crates/mvm-backend/src/backend.rs` (`FirecrackerBackend::warm_start` override), the `mvmctl resume` / warm-start command (`crates/mvm-cli/src/commands/`), the snapshot RPC surface.

- [x] **Step 1:** Implement `FirecrackerBackend::warm_start` — gate via `SnapshotCapability::LiveMemory.satisfies(requested)` (reuse the C4 helper; no new gate), then drive Task 1–3 (mint token → `FirecrackerIO::load_snapshot` / UFFD restore → `signal_post_restore` with the token → ready-barrier). Map failures to `WarmStartError::Failed`. **DONE** — `microvm::warm_restore_instance(name, token)` (integrity-verify → `PUT /snapshot/load` resume_vm → wait-for-agent → `post_restore_at(token)`); `FirecrackerBackend::warm_start` does the C4 gate + mint + restore. Full-mem-load (the basic tier); UFFD substrate (Task 2) layers under the same seam later.
- [x] **Step 2:** Wire a user-facing verb (extend `mvmctl resume`, or a `--warm` flag) that calls `AnyBackend::warm_start`. A live-memory request on libkrun already returns the typed `Unsupported` with a recovery hint (C4) — confirm the CLI surfaces it cleanly. **DONE** — `mvmctl vm resume --warm` routes through `AnyBackend::warm_start`; unit test asserts libkrun refuses live-memory with the typed cold-boot hint.
- [~] **Step 3 (live-KVM gated):** End-to-end — cold-boot a workload, snapshot, `warm_start`, and `examples/agent_ping` the resumed instance (the validation the C4 prompt wanted but couldn't reach without a caller). Assert sub-2s resume and a reseeded CSPRNG. **IN PROGRESS on the live FC box.** Pre-req bug found + fixed: `pause.rs::firecracker_socket` (and the new warm path) looked for `runtime/firecracker.socket`, a path nothing in the tree creates — the real control socket is `{vm_dir}/fc.socket` (every other FC op uses it), so `vm pause`/`resume` could never find a live VM. Both now use `fc.socket`.

## Out of scope

- **Vz save/restore** — Plan 152 WS-C owns it (`saveMachineState`/`restoreMachineState`, macOS 26+). Cross-ref only; do not touch `crates/mvm-vm-host` / `crates/mvm-backend/src/vz.rs` / the Swift→objc2 supervisor.
- **libkrun warm-start** — done (disk-only, #741). No live-memory path exists for libkrun by design.
- **Reflink clone** for `SnapshotUpper::materialize_image` (APFS `clonefile` / Linux `FICLONE`) — a separate Plan 123 C4 follow-up; the disk-only path works with a plain copy today.
- **The faster Vz diff-snapshot** (UFFD-equivalent on macOS) — its own investigation (Plan 123 deferred follow-up).

## Acceptance

- [ ] A Firecracker snapshot + restore rotates the VMGenID and reseeds the guest CSPRNG (Task 1), proven on live KVM.
- [ ] Resume streams memory via UFFD from a content-addressed, signed memfile with an NBD rootfs + hugepages, ~1s warm (Task 2).
- [ ] A SIGUSR1 "primed" ready-barrier produces a deterministic warm base (Task 3).
- [ ] `mvmctl` exposes a warm-start verb that drives the Firecracker live-memory path and `agent_ping` confirms the resumed guest; an over-request on a disk-only backend still returns the typed `Unsupported` (Task 4).
- [ ] All unit layers green on host tiers + the gated live-KVM lane; clippy + fmt clean. `xtask check-claim-catalog` stays green (claim 8 audit + claim 3 verified-boot re-verification on the resume path — a snapshot must not bypass admission/verity).

## Self-review

- **Honesty:** this is the one *gated* warm-start tier worth building; the disk-only (libkrun) and matrix (doctor) halves already shipped, and Vz is owned elsewhere. No task claims a macOS-verifiable result.
- **Reuse-first:** Task 1 wires three pieces that already exist (sender #734, token mint 122 D, reseeder 122 D) — only the wire payload is new. Task 4 reuses the C4 gate helper and `WarmStartError`, not a parallel one.
- **Deps:** the only candidate new dep is `userfaultfd` (Task 2 Step 2), explicitly weighed against raw `libc` ioctls under the dep budget.
- **Security:** a resumed VM must not skip claim-8 admission or claim-3 verity re-verification (snapshot artifacts are hash-pinned + signed, 122 C); the acceptance gate names it.
