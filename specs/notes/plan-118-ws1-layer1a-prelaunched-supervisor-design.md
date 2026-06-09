# Design — WS-1 Layer 1a: prelaunched libkrun supervisor (base/attach split)

> **Status (2026-06-09): Implemented (1a)** — PR #748 (`feat/plan-118-ws1-layer1a`).
> First sub-project of Plan 159 WS-1 (warm pool). Implements **Plan 118 PR-10b's
> supervisor primitive** (`specs/plans/118-supervisor-standby-pool-and-live-bench.md`)
> — the security-sensitive core — as its own PR: the base/attach config split, the
> prelaunched control-UDS flow with the mandatory attach-time plan re-verify, the
> `fuzz_attach_message` target, the (a)–(e) rejection ladder, and a `libkrun-live`
> refusal integration. The pool + `up` claim + bench delta (**1b**) build on this.
> Implementation plan: `specs/notes/plan-118-ws1-layer1a-implementation-plan.md`.

## Goal

Add a **prelaunched** mode to `mvm-libkrun-supervisor`: it does all
workload-*independent* setup at spawn (codesign re-exec, dylib load, `KrunContext`
creation, kernel-image load) and then **blocks on a control UDS, holding no rootfs
and no plan, before `start_enter`**. On an **attach** message it validates, merges
the workload config, re-verifies the signed `ExecutionPlan`, and only *then* calls
`start_enter`. This is the primitive a warm-pool standby is built from (1b).

**Scope:** the supervisor primitive only. **No pool, no `up` integration, no
`warm_pool_size`** — those are 1b. 1a is exercised by a test driver that sends an
attach to a prelaunched supervisor.

## Why (and why it's safe)

`krun_start_enter` boots-and-`exit()`s the calling process, so a standby cannot be
a booted VM awaiting a rootfs (`reference_libkrun_gotchas`). A prelaunched
supervisor is the only libkrun-feasible warm primitive. It hides the
supervisor-setup latency (spawn + codesign + `KrunContext`/kernel-load), **not** the
guest boot (which is gated on the rootfs at attach).

**Load-bearing security invariant:** the supervisor **independently re-verifies the
signed `ExecutionPlan`** (Ed25519 signature + G4 time window + nonce-replay) before
`start_enter` — the *same* gate `run_with_bridge` performs today. The control UDS is
not an admission bypass: a same-uid attacker cannot boot a forged/unsigned workload
without the host plan-signing key (claim 8; no new key introduced). Required
mitigations (core, not optional):

- **Replay across standbys** → a **per-supervisor binding nonce** (in `BaseConfig`,
  unique per spawn) must be **echoed** in the attach; an attach minted for standby A
  is rejected by standby B (whose fresh nonce ledger never saw the plan nonce).
  Combined with **one-shot attach** (a standby accepts exactly one attach, then boots
  or dies — no reject-and-wait loop) and the plan's G4 window, cross-standby replay is
  closed.
- **DoS** → per-connection attach timeout; an abandoned connect must not wedge the
  standby (bounded by 1b's pool size).
- **Idle entitled process** → liveness/TTL is a 1b concern (reaper + `cache prune`);
  1a just exits cleanly on attach-timeout.

Channel hardening: control UDS mode `0700`, parent dir `0700` (matches the W1.2
vsock-proxy posture); the binding nonce also appears in the socket path.

## Changes

### 1. Config split — `crates/deps/libkrun-sys/src/lib.rs` (`SupervisorConfig` at :1293)

- **`SupervisorBaseConfig`** — workload-*independent*: kernel path, vsock wiring,
  control-UDS path, **binding nonce** (`[u8; 32]`/hex). Drives `KrunContext` creation.
- **`SupervisorAttachConfig`** — workload-*specific*: `plan_json`, `bundle_json`,
  `rootfs_path`, `tenant_id`, audit paths, the **echoed binding nonce**. The workload
  subset of today's `SupervisorConfig`.
- A `SupervisorConfig::from_base_and_attach(base, attach) -> Result<SupervisorConfig>`
  merge (validates the echoed nonce == base nonce) so the existing `run_with_bridge`
  path is reused verbatim after attach.
- Both `#[serde(deny_unknown_fields)]`. The non-pool path is **unchanged** — it still
  decodes a whole `SupervisorConfig` on stdin and never opens a control UDS.

### 2. Prelaunched flow — `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs`

`main()` today: `ensure_signed()` → read `SupervisorConfig` on stdin (:101) →
`run_legacy`/`run_with_bridge`. Add a **prelaunched** arm selected when stdin carries
a `SupervisorBaseConfig` (a tagged enum `SupervisorStdin { Whole(SupervisorConfig),
Base(SupervisorBaseConfig) }`, `deny_unknown_fields`, so the legacy path is
untouched):

1. `ensure_signed()` (codesign re-exec) + dylib load + `KrunContext` creation from the
   base (the expensive workload-independent setup) — *before* blocking.
2. Bind the control UDS (`0700`, in a `0700` dir, nonce in the path); accept **one**
   connection with a per-connection timeout.
3. Read the `SupervisorAttachConfig` (length-prefixed JSON, `deny_unknown_fields`).
4. Verify: echoed binding nonce == base nonce; then **add** a plan re-verify on this
   path. ⚠️ The cold path **deliberately skips** re-verify (`mvm-libkrun-supervisor.rs:204-217`:
   the host admitted + the stdin pipe is a private parent→child channel, trusted under
   ADR-002 — extract, don't re-verify). The warm path's control UDS is **same-uid-reachable**,
   so it is *not* a trusted private channel: the supervisor MUST `mvm_core::plan::verify_plan`
   (Ed25519 signature, against the host-signer **public** key derived from `signing_key_path`)
   + the **G4 validity window** + **nonce-replay**, mirroring `mvm-hostd::supervisor::aggregate`'s
   gate. This is the load-bearing invariant — Plan 118 named it but it is NOT yet implemented
   (the cold path's extract-only is why). Reuse `verify_plan` + the aggregate G4/nonce logic;
   do not fork a second verifier.
5. Merge base+attach → `SupervisorConfig`; hand to the existing `run_with_bridge`
   (which `start_enter`s). One-shot: any verification failure or timeout exits
   non-zero **without** `start_enter`.

### 3. Attach trust-boundary fuzz + tests

- `fuzz_attach_message.rs` (sibling to `fuzz_supervisor_config`) — the attach struct
  is the only attacker-reachable-post-spawn surface; fuzz its decoder for panic-freedom.
- Negative-path tests (each asserts **`start_enter` is never reached**): (a) wrong
  binding nonce; (b) a second attach on the same standby; (c) unsigned plan; (d)
  expired/out-of-window plan (G4); (e) replayed nonce. Extract the verify+merge step as
  a **pure function** (`base + attach bytes → Result<SupervisorConfig>`) so these are
  unit-testable without a VM (no `start_enter`).

## Out of scope (1b — the pool, separate PR)

`warm_pool_size` / `--warm-pool-size`; `SupervisorStandbyPool` under `~/.mvm/pool/<id>/`;
`up` claim + cold-boot fallback; base-compat (kernel match); reaper + `cache prune` TTL;
replenish-on-use; the bench delta. **Open 1b decisions (deferred):** fill trigger
(lean: explicit `mvmctl pool warm [N]` + claim-if-available, no auto-refill daemon in
v1); base compatibility (v1 standbys pre-load the default kernel; non-default → cold-boot).

## Testing

- Unit: the pure verify+merge function (the (a)–(e) rejection ladder + the happy merge).
- `cargo fuzz` attach decoder (panic-free on arbitrary bytes).
- `libkrun-live`-gated integration (dev host): spawn a prelaunched supervisor with a
  `BaseConfig`, send a valid attach for an admitted plan, assert the guest boots +
  agent reachable; assert a wrong-nonce attach is refused with no boot.
- Gates: `cargo clippy --workspace -- -D warnings`, `cargo nextest run --workspace -E
  'not package(mvm-backend)'`, `cargo test --workspace --doc`, nightly `fmt --all --check`.
- Claim posture: the prelaunched path runs the **same** plan re-verify as
  `run_with_bridge`; no claim-8 weakening. The `mvm-libkrun-supervisor` bin is
  feature-gated (`libkrun-sys`) + must be rebuilt explicitly
  (`reference_libkrun_supervisor_separate_binary_rebuild`).

## References

- `specs/plans/118-supervisor-standby-pool-and-live-bench.md` PR-10b — authoritative design.
- `specs/plans/159-vz-inspired-macos-dx.md` WS-1 — the warm-pool parent.
- `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs` — the bin (legacy + bridge paths).
- `crates/deps/libkrun-sys/src/lib.rs:1293` — `SupervisorConfig` (+ the existing re-verify in `run_with_bridge`).
- `reference_libkrun_gotchas` — `start_enter` exits the process (one supervisor per VM).
