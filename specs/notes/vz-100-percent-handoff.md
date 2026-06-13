# Vz (Apple Virtualization.framework) — 100% support + close-out handoff

**Date:** 2026-06-13
**Status:** handoff prompt for a fresh session
**Goal:** confirm and complete 100% Vz support — the full user stack, live-proven on
this macOS-26 Apple-Silicon host — then formally close the VZ backend effort.

This is a verification-and-closeout mission, **not** a greenfield build. Most of the
stack already works and is live-proven — do NOT redo it. The job is to (a) prove the
FULL chain composes on `--hypervisor vz`, (b) close the genuinely-open gaps, (c)
reconcile each Sprint 55 / Plan 97 success criterion to current (post-Swift,
post-convergence) reality and mark it met or precisely blocked.

Copy the block below into a fresh session.

---

```
GOAL: Confirm and complete 100% Vz (Apple Virtualization.framework) support — the full
user stack, end-to-end, live-proven on this macOS-26 Apple-Silicon host — then formally
close the VZ backend effort (Sprint 55 / Plan 97 + its DX descendants). "Done" means:
every layer the libkrun/Firecracker path supports also works on `--hypervisor vz`,
demonstrated on real hardware, with the success criteria reconciled to the post-Swift,
post-convergence reality.

This is a verification-and-closeout mission, not a greenfield build. Most of the stack
already works and is live-proven — do NOT redo it. Your job is to (a) prove the FULL
chain composes on vz, (b) close the genuinely-open gaps, (c) reconcile each Sprint 55 /
Plan 97 success criterion to current reality and mark it met or precisely blocked.

STEP 0 — Sync + read the ground truth (do this first, don't work from memory):
  - `git fetch origin main && git -C <main checkout> merge --ff-only origin/main`
  - Read these REFACTOR-STATUS.md detail blocks: PLAN 152, 159, 189, 118, 123, 177, 183.
  - Read SPRINT.md Sprint 55 (success criteria + "Security claims under Vz" + "Live Vz
    validation" + Non-goals) and `specs/plans/97-vz-backend.md` (§"Can we still make all
    nine ADR-002 security claims?" + §"Security considerations" checkboxes).
  - Read `specs/plans/183-...-dns.md` §"deferred follow-ups".

ALREADY DONE on vz (live-proven — do NOT rebuild; verify-only if at all):
  - Build->admit->boot->run: `up --hypervisor vz` admits a claim-8 plan, boots the workload,
    guest agent reachable on vsock (sleeper fixture). Builder VM (libkrun + vz) fetches
    and builds (Plan 183).
  - Checkpoint/fork/warm: vm_full + fs_quick capture, `checkpoint diff`, native
    pause/resume; two-copy `fork --boot` (admitted child); INSTANT memory fork of a
    RUNNING parent (0.91s, claim-8 admitted, gvproxy-only invariant); saved-standby warm
    pool (`pool warm`->claim->self-replenish; compat reuses admission sha).
  - Rust-native VZ supervisor (Plan 152 WS-A/B/E; Swift deleted). objc2, not vfkit.

THE FULL-STACK ACCEPTANCE (the headline — run this entire chain LIVE on vz, one session,
isolated env, and capture each leg's evidence). Several legs are unproven on vz today:
  1. `dev up --builder vz` (the AVF builder path) -> builds the dev image; `dev down`.
  2. `build compile` an example with deps -> sealed app-deps volume (claim 11) — confirm
     it works when the build runs through the vz builder, not just libkrun.
  3. `up --flake <app> --hypervisor vz` -> admitted, boots, agent up.
  4. SECRETS/EGRESS ON VZ (Plan 129 — validated on QEMU, NOT yet confirmed on vz):
     `secret set` -> `up`/`invoke` on vz with substitution -> host-side endpoint injects
     the real credential, guest sees only the placeholder (claim 13); deny-by-default
     egress + the :80/:443 terminator + audit recorder all active on the vz launch
     (claim 10/16). This is the biggest unproven full-stack leg — prove it end-to-end on
     vz or pinpoint exactly where the vz launch path diverges from QEMU/FC.
  5. AUDIT: `trust audit verify` passes on the vz workload's chain; tamper -> nonzero exit.
  6. `doctor` reports claims 1,2,3 green on a vz-backed workload microVM (Sprint 55
     criterion) — confirm live.

OPEN ITEMS to audit and close (grouped; confirm current status against the docs first —
some may already be closed):
  A. Plan 152 WS-C/D + deferred robustness:
     - WS-C "fork primitive" — likely already satisfied by #700 snapshot/restore + Plan
       159 `fork --boot`; CONFIRM and close it, or state what's missing.
     - WS-D nested KVM (/dev/kvm in guest) — check whether this is in-scope for "full
       stack" or a separate capability; Sprint 55 claims no nested path is required.
       Decide + record.
     - Deferred robustness (from #772): exit-listener 2nd-conn, control-verb
       single-flight, `validateSaveRestore` hard-gate for Restore, VzIngest/mvm-vz-drainer
       dead-code sweep. Triage: close the cheap/correctness ones, defer the rest with a note.
  B. Plan 123 C3 (Vz save/restore, macOS 26+) — "owned by Plan 152 WS-C". vm_full
     save/restore is DONE (Plan 159 WS-2). Reconcile: is C3 effectively met? Tick or
     explain the gap.
  C. Sprint 55 Phase C (vz BUILDER artifact parity): "MVM_BUILDER_BACKEND=vz produces a
     rootfs whose hash matches the libkrun-built equivalent." NOTE: ext4 builds are
     NON-DETERMINISTIC (different bytes every build), so byte-hash equality is likely
     unmeetable as written. Re-interpret to FUNCTIONAL parity (same nix derivation / same
     boot+agent behavior) and confirm `MVM_BUILDER_BACKEND=vz mvmctl build` works live,
     or record why the criterion is retired/amended. Update the criterion text.
  D. Sprint 55 Phase B (>=30% cold-boot wall-time win vs nested libkrun->FC): measure it
     live, or retire/amend if the comparison is no longer meaningful post-convergence.
  E. Claim 5 (Vz config fuzz): the Swift JSONDecoder/Rust-equivalence criterion is OBSOLETE
     (Swift deleted, Plan 152). `crates/mvm-build/fuzz/fuzz_targets/fuzz_supervisor_config.rs`
     already fuzzes the Rust SupervisorConfig parser. Confirm it covers the current vz
     config surface and amend the criterion to the post-Swift reality.
  F. Plan 183 follow-ups still open: persistent VzPersistentBuilderVm runs `network:None`
     (wire gvproxy when it leaves scaffold status); `doctor` line surfacing in-builder
     egress posture + last builder net-bootstrap outcome; the warm-pool concurrent-
     overshoot pool-dir flock (`warm_to_target` read->spawn). Close the small ones.

DO NOT DUPLICATE (parallel session owns these — coordinate on file boundaries, don't edit
their files): Plan 189 WS-1 save/restore verbs, WS-2 cached fast-boot default (live
acceptance), WS-3 --json remainder, WS-4 base pinning — all in
`crates/mvm-cli/src/commands/env/dev.rs`, `dev_vz.rs`, `up.rs` (boot-decision layer) +
the fingerprint helpers (Plan 195). If a full-stack gap forces a change there, ping the
189 owner first. Plan 159 "WS-5 D verb renames / curl|sh installer / signed delta-image"
and Plan 118 "Firecracker standby pool" are NOT vz and are out of scope for "100% vz".

CLOSURE DELIVERABLE: a clear verdict — either "Vz is 100%: full-stack chain green on
hardware, every Sprint 55/Plan 97 criterion met-or-amended, here's the evidence" and flip
Sprint 55 to COMPLETE + tick Plan 97; OR a precise, short list of what blocks closure and
why (with the failing leg's logs). No hand-waving.

STANDING CONSTRAINTS:
  - subagent-driven-development for every implementation slice; two-stage review; live-
    validate on THIS macOS-26 Vz Mac. Keep REFACTOR-STATUS.md + SPRINT.md current in the
    same change (append-only; second-to-merge rebases; the top "Last updated" line is the
    conflict hotspot — union both sides' clauses).
  - No plan/PR/ADR refs in code comments (lint-gated). No Co-Authored-By trailer. Always
    work in a git worktree, never the main checkout. Reuse-first.

LIVE-ENV GOTCHAS (saves ~20 min each):
  - Build mvmctl + `mvm-vm-host --bin mvm-vz-supervisor` (+ `--bin mvm-libkrun-supervisor
    --features libkrun-sys`); pin `MVM_VZ_SUPERVISOR_PATH`. Homebrew rustc shadows rustup
    -> `export PATH="$HOME/.cargo/bin:$PATH"` for all cargo (else clippy E0514 / use a fresh
    CARGO_TARGET_DIR).
  - ext4 flake builds are NON-DETERMINISTIC: every `up --flake` -> a different image sha.
    For warm-pool / claim tests, warm AND claim from the SAME fixed artifact — use the
    cached default-microvm image (`pool warm` no --rootfs + `up` no --flake), which is
    stable. The kept test env `/tmp/mvm-mf-{data,cache}` already holds that cached image +
    promoted builder cache (saves ~15 min rebuild).
  - Warm claims need the gateway-bridge path: `MVM_GATEWAY_BRIDGE=1`, and the drainer needs
    `~/.mvm/observers/allowlist.toml` (mode 0600, `schema_version = 1`).
  - Vz supervisor self-signs via `mvm_backend::codesign::ensure_signed()` (no tools/build.sh).
  - NEVER run e2e unbounded: background + gtimeout + stdio-to-file + reap. Long-lived child
    supervisors inherit the shell pipe (a `tail` may look hung while the run already finished
    — check the .pid/console, not the tail).
```

---

## Source: where the open items came from (audited 2026-06-13 against `origin/main`)

- **Secrets/egress on vz (full-stack leg 4)** — REFACTOR-STATUS PLAN 129 records the
  clean-room e2e as GREEN on **QEMU** (and FC bringup), not vz. The terminator + vsock
  endpoint are backend-generic, so this is expected to work, but it is **not yet
  live-confirmed on the vz launch path**. Highest-value unproven leg.
- **Vz builder artifact parity (Phase C)** — no confirmation in the rollup that
  `MVM_BUILDER_BACKEND=vz` produces a matching artifact; and the literal "hash matches"
  criterion collides with ext4 non-determinism. Needs live confirmation + criterion
  amendment.
- **Claim 5** — `crates/mvm-build/fuzz/fuzz_targets/fuzz_supervisor_config.rs` exists and
  fuzzes the Rust `SupervisorConfig` parser; the Swift-equivalence half of the original
  criterion is obsolete (Swift deleted in Plan 152).
- **Plan 152 WS-C/D + #772 deferred robustness**, **Plan 123 C3**, **Plan 183 deferred
  follow-ups** (persistent-builder `network:None`, doctor egress-posture line, warm-pool
  flock) — all open per their detail blocks.
- **Parallel session owns Plan 189** (DX-parity: save/restore verbs, cached fast-boot,
  --json remainder, base pinning) — coordinate on the boot-decision file boundaries
  (`dev.rs`/`dev_vz.rs`/`up.rs`), do not duplicate.
