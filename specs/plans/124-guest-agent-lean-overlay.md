# Plan 124 — Guest agent: lean-Rust v2 + universal + runtime overlay

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the guest agent small, universal, and sealed. Cut its heavy deps (`tokio`→`polling`, `serde_json`→hand-rolled framing, `rtnetlink`→`linux-raw-sys`, drop `async-trait`) — the real dep reduction in the rewrite. Run the *same* `mvm-guest-agent` in every VM type (builder/dev included). Ship it from the verity-sealed runtime overlay (ADR-051). Generate the **SDKs** (data/IR types + the RPC client surface, in every language) from one schema so they can't drift from each other or the core, and hand the runtime config to the guest on a read-only device before vsock is up.

**Architecture:** The agent (`crates/mvm-guest`: `mvm-guest-agent.rs` + `vsock`/`worker_pool`/`netinit`/`fs_rpc`/`process_rpc`/…) is feature-complete but heavy. This plan keeps its behavior and shrinks its closure. **Reality check (2026-06-05, verified against the worktree):** the agent's request-serving path is *already* synchronous — `worker_pool.rs`, `vsock.rs`, and `mvm-guest-agent.rs` use `std::thread` + `Mutex`/`Condvar`, with no `tokio` and no `async`. The *only* async surface in the crate is `netinit`'s `rtnetlink` installer, which is the sole reason `tokio` + `async-trait` enter the closure (both `cfg(target_os = "linux")`-gated; `Cargo.toml` attributes them to Plan 74 W2, not the pool). So there are **two** real weight centers, not three: `netinit`'s async netlink (`tokio` + `async-trait` + `rtnetlink` + `netlink-packet-route` — Task A3) and `vsock`'s `serde_json` framing (Task A2). There is no async runtime to remove from `worker_pool`; A1 is therefore a **lock-in gate**, not a rewrite, and `polling` is *not* added (it would be a net dep increase with nothing to remove). Recommended order: **A1 (gate) → A3 (the tokio cut) → A2 (serde_json) → A4 (measure)**. The universal-agent invariant (ADR-066 §6) and the verity overlay (ADR-051) already exist as designs; this wires them. **Claim 4 (no `do_exec` in prod) and claim 5 (vsock framing fuzzed) are invariants this plan must preserve** — the dev/builder tier runs the `dev-shell`-featured agent (with `do_exec`), prod workloads run the no-exec build, and the new hand-rolled framing keeps its fuzz target.

**Tech Stack:** Rust (`mvm-guest`), `linux-raw-sys` (raw netlink), the verity initramfs (`mvm-verity-init`), a protocol-codegen step (build script or `xtask`). Net **removes** ~25–35 crates; adds only `linux-raw-sys` (small, no_std-friendly). (`polling` was in the original sketch for a "tokio worker pool" that does not exist — the pool is already synchronous `std::thread`; dropped.)

**Prereqs:** 121 (the `mvm-guest` home, the `mvm-host-vm-init` → `mvm-build` bin). The universal-agent invariant is ADR-066 §6; the overlay is ADR-051.

**Measurement:** every dep-cut task records `cargo tree -p mvm-guest -e no-dev | wc -l` before/after, and the prod-agent binary size. This is the workstream where the dep-graph actually shrinks (ADR-066 §9: the consolidation delivers ~0; the lean agent delivers the win).

---

## Phase A — the lean dep cut

### Task A1: runtime-free lock-in gate (was: `tokio` → `polling` in `worker_pool`)

**Premise corrected 2026-06-05.** The worker pool is *already* synchronous — `worker_pool.rs` is `std::thread` + `Mutex`/`Condvar` with zero `tokio`/`async`; `vsock.rs` and `mvm-guest-agent.rs` likewise. There is no tokio worker pool to convert and `polling` buys nothing. A1 instead delivers the **gate that locks in the property A3 achieves**: `mvm-guest`'s non-dev closure pulls no async runtime. It is RED today (the async stack is present via `netinit`'s rtnetlink) and flips GREEN when A3 lands.

**Files:** `xtask/src/check_guest_agent_runtime_free.rs` (new), `xtask/src/main.rs`; `.github/workflows/ci.yml` (lane added in the A3 commit, where it goes green).

- [x] **Step 1:** Baseline recorded — `cargo tree -p mvm-guest -e no-dev` = **203 crates** (host target); the async stack (`tokio`/`rtnetlink`/`async-trait`/`netlink-packet-route`) is `cfg(linux)`-gated, so it only surfaces under `--target aarch64-unknown-linux-musl`.
- [x] **Step 2:** `xtask check-guest-agent-runtime-free` mirrors `check-core-runtime-free`: `cargo tree -p mvm-guest -e no-dev --prefix none --locked --target aarch64-unknown-linux-musl`, fails if `{tokio, async-trait, rtnetlink, netlink-packet-route}` appear. Parser unit tests green; the live gate is **RED now** (exit 1, all four present) — the real failing test A3 drives to green.
- [ ] **Step 3 (lands with A3):** wire the gate into `ci.yml` in the same commit that makes it pass (no knowingly-red required check in the tree). Coordinate with 128.

### Task A2: `serde_json` → hand-rolled framing in `vsock`

ADR-066 §9. The wire format is a small fixed set of typed messages; a hand-rolled length-delimited codec removes `serde_json` from the guest. **Claim 5: the fuzz target moves with it, not away.**

**Files:** `crates/mvm-guest/src/vsock.rs`; `crates/mvm-guest/fuzz/` (the `GuestRequest`/`AuthenticatedFrame` targets).

- [ ] **Step 1:** Failing tests — every `GuestRequest`/response round-trips through the new codec byte-for-byte; a truncated/oversized/garbage frame is rejected (the fuzz corpus cases as unit tests); `deny_unknown_fields` semantics preserved (unknown tag → reject).
- [ ] **Step 2:** Implement the codec (tag byte + length-prefixed fields; the existing `AuthenticatedFrame` envelope stays). Repoint the two fuzz harnesses at the new codec — claim 5 must keep covering the parser.
- [ ] **Step 3:** Drop `serde_json` from `mvm-guest` if no other module needs it (`integrations`/`runtime_config` may — keep only where load-bearing). `cargo tree` delta. Commit.

### Task A3: `rtnetlink` → `linux-raw-sys` in `netinit`

`netinit` configures the guest's interface/routes via `rtnetlink` (async, pulls tokio). Raw netlink over `linux-raw-sys` is a few dozen lines and no_std-friendly.

**Files:** `crates/mvm-guest/src/netinit.rs`, `bin/mvm-guest-netinit.rs`.

- [ ] **Step 1:** Failing test (gated, needs netns) — netinit brings the interface up + sets the route, asserted via `/proc/net` or a netns probe, with no `rtnetlink`/`tokio`. Also: make `RouteInstaller` a *synchronous* trait (drop `#[async_trait]`) so removing rtnetlink also removes `tokio` + `async-trait`. The cross-platform trait + install-loop + `MockInstaller` tests run on a macOS dev host; the raw-netlink installer itself is `cfg(target_os = "linux")` and rides Linux CI.
- [ ] **Step 2:** Hand-roll the `RTM_NEWADDR`/`RTM_NEWROUTE` messages over a raw `AF_NETLINK` socket (`linux-raw-sys`). Keep the `NetworkMandatoryDeny` audit marker (claim 10). Drop `tokio` (dep + dev-dep), `async-trait`, `rtnetlink`, `netlink-packet-route` from `Cargo.toml`.
- [ ] **Step 3:** The A1 gate (`check-guest-agent-runtime-free`) now passes — add its lane to `ci.yml` in this commit. Commit.

### Task A4: confirm the cut

- [ ] **Step 1:** `cargo tree -p mvm-guest -e no-dev | wc -l` total delta recorded (target ~25–35 crates removed); prod-agent binary size before/after. `prod-agent-no-exec` (claim 4) still green — assert `do_exec` absent without `dev-shell`. Commit a `docs/investigations/` note with the numbers (don't silently claim the reduction — show it).

## Phase B — universal agent (every VM type)

### Task B1: `mvm-host-vm-init` forks `mvm-guest-agent`

ADR-066 §6. The builder/dev VM bakes the agent (via mkGuest) but PID 1 (`mvm-host-vm-init`, now a `mvm-build` bin) never forks it. Make it fork the agent under setpriv, exactly as the workload `/init` does.

**Files:** `crates/mvm-build/src/bin/mvm-host-vm-init.rs` (post-121).

- [ ] **Step 1:** Failing test — `mvm-host-vm-init` startup spawns `mvm-guest-agent` under setpriv to the agent uid (assert the child is launched + reachable on vsock 5252 in a gated boot test). The dev/builder tier runs the `dev-shell` agent (with `do_exec` — a dev-tier VM, ADR-002 tier matrix).
- [ ] **Step 2:** Fork it alongside the builder protocol + the PTY console; the agent and the build path coexist (mkGuest's workload `/init` already does both). Commit.

### Task B2: `xtask check-guest-agent-in-all-images`

The enforcement gate from ADR-066 §6.

- [ ] **Step 1:** Failing test — the lint fails when a bootable image's launch path omits the agent. Enumerate the images (mkGuest workload, builder-vm, dev) and assert each forks `mvm-guest-agent`.
- [ ] **Step 2:** Implement the `xtask` check; wire into `ci.yml` (coordinate with 128). Commit.

## Phase C — runtime overlay (ADR-051)

### Task C1: the verity-sealed agent overlay

ADR-051 — the agent (+ netinit/seccomp-apply) ship from a shared verity-sealed `/mvm/runtime` overlay, not baked per-image. mkGuest's `/init` already prefers `/mvm/runtime/agent` over the baked copy.

**Files:** `nix/images/runtime-overlay/` (the overlay build); `mvm-verity-init` (the bind-mount before switch_root).

- [ ] **Step 1:** Failing test — a workload microVM with the overlay attached runs the agent *from the overlay* (assert the running agent's path is `/mvm/runtime/agent`), and a tampered overlay fails the dm-verity roothash (claim 3 lineage).
- [ ] **Step 2:** Build the overlay with the lean agent (Phase A) + seccomp-apply + netinit; `mvm-verity-init` bind-mounts it at `/mvm/runtime` before switch_root. The prod overlay carries the no-`do_exec` agent. Commit.

## Phase D — spec-first, autogenerated SDKs (no drift)

Owner requirement: the SDKs are **generated from one schema**, not hand-maintained, so Python / TS / Rust can't drift from each other or from the core. The foundation exists — the IR types derive `JsonSchema` and `mvm-ir/src/bin/emit_schema.rs` emits the schema; the host↔guest protocol gets the same. Generate, in every language: the **IR / data types** *and* the **RPC client method surface** (one host↔guest RPC → one generated client method) — **including the broker services** (`host.audit.v1`, `host.time.v1`, `host.cost.v1`), which are host↔guest RPCs the workload calls; 125 exposes them ergonomically. The idiomatic veneer (the `Sandbox` mode-switching, the decorator AST hooks, the typed helpers — plan 125) stays hand-written *over* the generated core; it's small and carries no wire contract, so it can't drift the protocol.

### Task D1: the schema + the generator

**Files:** the IR JSON Schema (`emit_schema`) + a host↔guest `protocol.schema` (single source of truth); `xtask gen-sdk`; generated outputs under `sdks/{python,typescript}/_generated/` + the guest agent's generated request enum.

- [ ] **Step 1:** Failing test — `xtask gen-sdk` produces the Python + TS type modules + RPC client stubs from the schema; a round-trip test (generated client ↔ generated agent types) passes; a **no-drift CI check** asserts the committed `sdks/*/_generated/` matches a fresh run (128 wires it into `ci.yml`).
- [ ] **Step 2:** Implement the generator: schema → Python (pydantic / dataclasses) + TS (interfaces) + the RPC method surface in each + the Rust agent request enum. Generated code is committed (reviewable) and gated.
- [ ] **Step 3:** Replace the hand-maintained `vsock` request enum + the SDK client type/RPC stubs with the generated ones; the 125 veneer now sits over `sdks/*/_generated/`. Commit.

## Phase E — config-on-a-device init handoff

### Task E1: signed runtime config as a read-only device

ADR-066 §"survey" — deliver the signed-plan-derived runtime config to the guest as a read-only JSON device (composes with dm-verity), read at init **before** vsock is up, instead of negotiating it over vsock.

**Files:** `crates/mvm-guest/src/runtime_config.rs`, `entrypoint.rs`; the backend's device attach.

- [ ] **Step 1:** Failing test — the guest reads its runtime config from the config device at init (before any vsock round-trip) and refuses to boot if the device is missing/unsigned (the config is derived from the signed `ExecutionPlan`, claim 8).
- [ ] **Step 2:** Attach the config as a read-only virtio-blk device (host side); `runtime_config.rs` reads + verifies it pre-vsock. Removes a vsock round-trip from the boot path (helps §7 boot budget). Commit.

## Acceptance

- [ ] `mvm-guest` sheds `tokio` + `async-trait` + `serde_json` (guest) + `rtnetlink`; `cargo tree -p mvm-guest -e no-dev` is ~25–35 crates lighter, recorded in a `docs/investigations/` note; prod-agent binary smaller.
- [ ] Claim 4 (`prod-agent-no-exec`) and claim 5 (vsock fuzz, repointed) stay green; claim 10's netinit audit marker preserved.
- [ ] The same `mvm-guest-agent` runs in builder/dev (forked by `mvm-host-vm-init`) and workload VMs; `check-guest-agent-in-all-images` enforces it.
- [ ] The agent runs from the verity-sealed `/mvm/runtime` overlay; a tampered overlay fails the roothash.
- [ ] The SDK data/IR types + the RPC client surface (Python/TS/Rust) are generated from one schema (`xtask gen-sdk` → `sdks/*/_generated/`) with a no-drift CI check; the 125 veneer sits over the generated core.
- [ ] Runtime config arrives on a read-only device, verified pre-vsock; missing/unsigned refuses boot.
- [ ] `cargo test --workspace` + clippy + fmt green.

### deferred follow-ups

- [ ] Apply the same lean treatment to `mvm-builder-agent` if it shares the heavy deps.
- [ ] `no_std` the agent core (a stretch once tokio/serde_json are gone).

## Self-review

- **Spec coverage (brief 124):** lean dep cut tokio/serde_json/rtnetlink (Phase A), universal agent across VM types (Phase B — wires the ADR-066 §6 invariant + its gate), verity overlay (Phase C, ADR-051), spec-first **autogenerated SDKs** (Phase D — types + RPC surface from one schema, all languages, no-drift), config-on-device init (Phase E). All five present.
- **Invariants preserved:** claim 4 (no prod `do_exec`) checked in A4/B1; claim 5 (fuzz) repointed not dropped in A2; claim 3 (verity) in C1; claim 10 (netinit audit) in A3.
- **Deps:** a *net negative* — removes ~25–35, adds two small crates (`polling`, `linux-raw-sys`); the delta is measured and written down, not asserted.
- **Voice:** comments mark the non-obvious (why polling suffices for an I/O-bound agent, why the fuzz target moves with the codec, why config-on-device removes a round-trip), not the calls.
