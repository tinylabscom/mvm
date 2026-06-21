# Plan 206 — Firecracker warm-start UFFD substrate + primed-barrier wiring (Plan 175 T2/T3-Step2 carve-out)

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **This work is live-KVM-gated** — it cannot be verified on a macOS dev host; land each task on Linux CI / a live-KVM Firecracker box.

**Goal:** Finish the two pieces carved out of Plan 175 when its *core* live-memory warm-start shipped: the **UFFD / NBD / hugepages fast-resume substrate** (the ~1s, scale-with-working-set recipe) and the **live wiring of the "primed" ready-barrier** (the host-side protocol already landed). Plan 175 delivered, merged, and live-proved the capability — cold-boot → `vm pause` (seal) → `vm resume --warm` (fresh-FC `/snapshot/load`, reseeded) works end to end on real Firecracker. What remains is **performance** (UFFD makes resume O(working-set) instead of O(full-mem)) and a **determinism nicety** (snapshot at a workload-signalled warm point).

**Parent:** Plan 175 (`specs/plans/175-firecracker-live-memory-warmstart.md`) Tasks 2 + 3-Step-2. Plan 175 was itself a Plan 123 C2 carve-out; this continues that "keep gated work visible, sized, honestly gated" pattern (mirrors how Plans 126/159 rehomed their heavy tails).

**Why a separate plan:** Plan 175's core is done and merged (#1150 / #1155 / #1165). Its remaining tail is large, live-KVM-gated systems work whose payoff is conditional (UFFD matters for multi-GB VMs; the primed barrier matters for warm-pool determinism). Tracking it here keeps it visible and sized rather than holding Plan 175 open or — worse — marking Plan 175 complete while the tail is unbuilt.

## What already landed (Plan 175 — the seam this builds on)

Do **not** rebuild these:

- **Live-memory warm-start, end-to-end (#1155).** `microvm::warm_restore_instance(name, token)`: integrity-verify the sealed snapshot → stop the paused FC → `start_vm_firecracker` (fresh blank VMM, clears stale `fc.socket`/`runtime/v.sock`) → `PUT /snapshot/load` (`mem_backend`, `resume_vm`) → best-effort VMGenID token delivery. `FirecrackerBackend::warm_start` = C4 tier-gate + mint + restore. `mvmctl vm resume --warm` drives it; libkrun → typed `Unsupported`. **Full-`mem.bin` load is the current tier** — this plan adds the UFFD lazy-paging tier under the same seam.
- **VMGenID delivery (#1150).** `GuestRequest::PostRestore { token }` + `GenIdReseeder::on_post_restore_token`; both host senders mint per-resume.
- **Primed-barrier *protocol* (#1165).** `await_primed_barrier(source, timeout)` + the `PrimedSignalSource` trait in `mvm::vm::instance_snapshot` — fail-closed, unit-tested. The **production `PrimedSignalSource` (guest→host vsock signal) + `vm pause` integration + live verify is Task 2 below.**
- **Control-socket fix.** `vm pause`/`resume` + the warm path use `{vm_dir}/fc.socket` (the path `start_vm_firecracker` actually creates), not the phantom `runtime/firecracker.socket`.

## Gating & verification environment

Every task here needs a **live KVM** Firecracker VM — none of it verifies on a macOS dev host. The Plan 175 recipe stands: build `mvmctl` natively on the live-KVM box (or cross-build + copy), boot a stay-alive workload (`--builder qemu up --flake examples/sleeper --hypervisor firecracker`), and gate the live tests behind an env flag (e.g. `MVM_LIVE_KVM=1`), unit-buildable everywhere, executed only where KVM exists.

---

## Task 1: UFFD / NBD / hugepages fast-resume substrate

ADR-066 §7 — the ~1s resume recipe. The heavy systems work; commit per sub-piece, each with its own live-KVM test. (Verbatim from Plan 175 Task 2 — unchanged scope.)

- [ ] **Step 1 — diff/layered snapshots.** One read-only golden memory base + a COW per-VM delta, reusing Phase B3's `SnapshotUpper` (storage half already shipped). Snapshot artifacts stay content-addressed + signed (122 Phase C). Test: a delta restore reproduces guest state without copying the full base.
      - **Chaining note:** Firecracker clears the dirty bitmap on *every* `snapshot/create`, so a second Diff taken from an evolving source only captures pages dirtied since the first. Track `last_snapshot_mem_path` and diff against it (each completed snapshot's `mem.bin` *is* the source's full memory at that point); fall back (with a warning) to the golden base if an intermediate snapshot was pruned. Content-addressing dedups the shared base pages across the chain.
- [ ] **Step 2 — `userfaultfd` page-fault handler.** Stream guest pages on demand from a content-addressed memfile instead of a full `mem.bin` load. **Evaluate the `userfaultfd` crate vs. raw `libc` ioctls under the dep budget** (prefer existing workspace primitives). Test: a resumed guest faults pages lazily and runs correctly. This is what turns the merged full-`mem.bin` load into the ~1s, O(working-set) resume.
- [ ] **Step 3 — NBD-served rootfs + 2 MB hugepages.** Serve the rootfs over NBD (`mvmctl doctor`'s substrate probe already checks the module is loaded) and back the memfile with hugepages (doctor checks the HugeTLB reservation). Test: resume succeeds with both wired; doctor's substrate lines reflect the live host.

## Task 2: Primed-barrier live wiring (Plan 175 T3 Step 2)

The host-side barrier policy (`await_primed_barrier`, fail-closed) already landed (#1165). This wires the real signal source + the pause integration.

- [x] **Step 1:** Implement the production `PrimedSignalSource` — the guest workload signals "primed" (caches/JITs/model load done) and the guest agent forwards it to the host over vsock (no new guest privilege; reuse the existing agent vsock surface, not a host-delivered SIGUSR1). Unit-test the source against a mock guest. **DONE (host + unit-tested):** new `GuestRequest::PrimedStatus` → `GuestResponse::PrimedStatusReport { primed }` RPC mirrors `ProbeStatus`; the workload asserts primed by creating `PRIMED_MARKER_PATH` (`/run/mvm/primed`, a no-privilege tmpfs write) and the agent reports its presence (`workload_is_primed_at`). Host-side `VsockPrimedSignalSource` polls that RPC over `vsock_transport::for_vm`; the poll *policy* (`wait_for_primed_polling`) is unit-tested with a fake probe (the mock guest), the per-poll vsock I/O is the thin shell (live-gated, mirrors `VsockPostRestoreSignal`). Wire serde + `deny_unknown_fields` + marker + interpret tests green.
- [x] **Step 2:** Gate the warm-snapshot path (`mvmctl vm pause` with an opt-in `--primed-barrier`/timeout, or the warm-pool seal trigger) on `await_primed_barrier` before `pause_and_seal`. Fail closed on timeout (no half-warmed snapshot). **DONE:** `vm pause --primed-barrier [--primed-timeout <secs>=120]` constructs `VsockPrimedSignalSource` and calls `await_primed_barrier` before `pause_and_seal`; the `?` propagates a timeout so no half-warmed snapshot is sealed. The hermetic `mock` hypervisor (no live agent) is never gated. Opt-in gating decision (`primed_barrier_timeout`) unit-tested.
- [ ] **Step 3 (live-KVM gated):** A workload that signals primed after warmup → host seals at that point → `vm resume --warm` starts past cold-start; a workload that never signals → the seal times out and refuses.

## Task 3: warm-start token-delivery polish (small, from the Plan 175 live capture)

The merged warm path restores correctly, but the VMGenID token delivery is best-effort and **raced the 30 s agent-ready window in every Plan 175 live run** — the restored guest agent reliably re-accepts ~30–35 s post-restore, just outside the window, so the reseed silently no-ops with a warn.

- [~] **Step 1 — investigate the ~30 s post-restore agent-ready latency.** Why does the restored agent take ~30 s to accept a host vsock connection (CONNECT 5252 → OK) when the VMM resumed in ~0.5 s? (Snapshot-captured listener state? clock/timer catch-up? service re-init?) Fix the root cause if cheap; otherwise widen `warm_restore_instance`'s agent-ready wait to cover the observed latency so the token reliably lands. **PARTIAL (fallback landed):** the agent-ready wait is widened to 60 s (`WARM_AGENT_READY_POLL_ATTEMPTS = 120 × 500 ms`, was 30 s), covering the observed ~30–35 s tail with margin, with a budget regression test. The root-cause investigation needs a live KVM resume and stays gated.
- [x] **Step 2 — make the verb honest.** `run_warm_start` prints "VMGenID rotated" unconditionally; surface the actual `PostRestoreAck.reseeded` (thread it back through `post_restore_at` → `warm_restore_instance`) so the message reflects whether the guest actually reseeded. **DONE:** `post_restore_at` now returns `PostRestoreReply { acknowledged, reseeded }`; `warm_restore_instance` returns a typed `ReseedStatus` (`Rotated` / `NotRotated` / `Undelivered` / `NotApplicable`, classified by the pure `classify_reseed`); `VmBackend::warm_start` returns `WarmStartOutcome { id, reseed }`; and `run_warm_start` prints `reseed.resume_summary()` so the line reflects the real outcome instead of asserting a rotation. libkrun's disk-only warm-start reports `NotApplicable`. Pure helpers unit-tested across all four crates.
- [ ] **Step 3 (live-KVM gated):** capture a live `vm resume --warm` where `reseeded == true` and two clones of one snapshot draw divergent `/dev/urandom` (the Plan 175 T1-Step3 claim, needs a dev/exec image).

## Out of scope

- The merged Plan 175 core (full-`mem.bin` warm-start, VMGenID delivery, barrier protocol). Don't rebuild.
- Vz save/restore (Plan 152 WS-C), libkrun warm-start (disk-only, #741), reflink clone (123 C4 follow-up).

## Acceptance

- [ ] Resume streams memory via UFFD from a content-addressed, signed memfile with an NBD rootfs + hugepages, ~1s warm regardless of VM size (Task 1), proven on live KVM.
- [ ] A workload-signalled "primed" barrier produces a deterministic warm base, fail-closed on no-signal (Task 2), proven on live KVM.
- [ ] All unit layers green on host tiers + the gated live-KVM lane; clippy + fmt clean. `xtask check-claim-catalog` stays green (a warm resume must not bypass claim-8 admission or claim-3 verity re-verification).

## Self-review

- **Honesty:** this is the *performance + determinism* tail of Plan 175; the capability already ships. No task claims a macOS-verifiable result, and the UFFD payoff (multi-GB VMs) is stated as conditional.
- **Reuse-first:** Task 1 Step 1 reuses `SnapshotUpper`; Task 2 reuses the merged `await_primed_barrier`/`PrimedSignalSource` and the agent vsock surface.
- **Deps:** the only candidate new dep is `userfaultfd` (Task 1 Step 2), explicitly weighed against raw `libc` ioctls under the dep budget.
- **Security:** a UFFD/diff resume must still pass claim-8 admission + claim-3 verity re-verification (snapshot artifacts hash-pinned + signed, 122 C); the acceptance gate names it.
