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
- [x] **Step 3 (landed with A3):** the gate is wired into `ci.yml` in the A3 commit — the same commit that flips it green, so no knowingly-red required check ever sat in the tree.

### Task A2: `serde_json` → hand-rolled framing in `vsock` — **NOT VIABLE AS WRITTEN (deferred 2026-06-05)**

ADR-066 §9 wanted a hand-rolled length-delimited codec to "remove `serde_json` from the guest." **Verified against the worktree: A2 cannot remove `serde_json` from `mvm-guest`'s tree, so its dep-graph benefit is zero.** Two findings:

1. **`serde_json` is a *transitive* dep via `mvm-core`** — `cargo tree -i serde_json` shows `serde_json → mvm-core → mvm-guest`. `mvm-core` uses it load-bearingly (signed `ExecutionPlan`/bundle/policy/audit JSON), so it stays in `mvm-guest`'s closure no matter what the guest crate does. Hand-rolling the vsock codec removes **0 crates**.
2. **`serde_json` is load-bearing in 7 guest modules + 3 bins** (non-test): `vsock`, `worker_protocol`, `integrations`, `probes`, `runtime_config`, `runner/config`, `builder_agent`, plus the agent/builder-agent/netinit bins. Even a full guest-wide de-serde would still leave it in the tree via (1).

**Cost/benefit:** hand-rolling encode/decode for `GuestRequest` (~35 variants) + `GuestResponse` + the `AuthenticatedFrame` envelope, re-implementing serde's `deny_unknown_fields` by hand, and **repointing the claim-5 fuzz targets onto a bespoke parser** — i.e. trading battle-tested serde for hand-written parsing on the security-critical host↔guest boundary claim 5 protects — buys **nothing** in the dep graph and *enlarges* the hand-written attack surface. Net-negative.

**Decision:** deferred. Genuinely shedding `serde_json` from the guest closure is gated on de-serde'ing **`mvm-core`** (a separate, cross-cutting effort, and dubious — `mvm-core` serializes signed plans as JSON by design). Revisit only if/when that lands. The lean-agent win this plan promised is delivered by A1+A3 (the `tokio`/`async-trait`/`rtnetlink` cut); `serde_json` was never removable here.

**Files (if ever revived):** `crates/mvm-guest/src/vsock.rs`; `crates/mvm-guest/fuzz/`.

### Task A3: `rtnetlink` → `linux-raw-sys` in `netinit`

`netinit` installs blackhole routes via `rtnetlink` (async, pulls tokio). Raw netlink over a synchronous `AF_NETLINK` socket is a few dozen lines.

**Dep deviation (2026-06-05):** the brief said add `linux-raw-sys`. Done **dep-free instead** — the rtnetlink constants are frozen kernel UAPI, so they're inlined (cross-platform, in a `#[cfg(any(target_os = "linux", test))] mod wire`) and the socket syscalls use `libc` (already a dep). Net deps added: **0** (vs +1); removed: 4. `constants_match_libc` (a `cfg(linux)` test) pins each inlined constant to `libc`'s value on CI.

**Scope note:** the current `netinit` only installs `RTM_NEWROUTE` blackholes (the `MANDATORY_DENY_RANGES` floor); it never did `RTM_NEWADDR`/interface-up. A3 is a faithful port of *that* surface — no new interface-config behaviour.

**Files:** `crates/mvm-guest/src/netinit.rs`, `bin/mvm-guest-netinit.rs`, `Cargo.toml`.

- [x] **Step 1:** `RouteInstaller` is now a *synchronous* trait (dropped `#[async_trait]`); `install_mandatory_deny` + `MockInstaller` + the six former `#[tokio::test]`s are sync and green on macOS. TDD RED→GREEN landed on the risky new bit — `encode_blackhole_route_v4` (pure netlink-message byte layout), pinned by `encode_blackhole_route_v4_produces_exact_netlink_bytes` + `…_carries_prefix_and_addr`. The live netns route test stays gated for Linux CI.
- [x] **Step 2:** `RawNetlinkInstaller` (`cfg(linux)`) opens/binds a `NETLINK_ROUTE` socket and does a blocking `sendto`+`recv` ACK (EEXIST → idempotent Ok), keeping the `REPORT_MARKER` audit path (claim 10). Dropped `tokio` (dep + dev-dep), `async-trait`, `rtnetlink`, `netlink-packet-route` — Cargo.lock shed ~20 crates.
- [x] **Step 3:** A1 gate (`check-guest-agent-runtime-free`) is GREEN; its lane is wired into `ci.yml` in this commit.

### Task A4: confirm the cut

- [x] **Step 1:** Delta recorded in [`docs/investigations/plan-124-lean-agent-dep-cut.md`](../../docs/investigations/plan-124-lean-agent-dep-cut.md): `mvm-guest`'s Linux no-dev closure went **126 → 99 unique crates (−27, 0 added)** — the whole `tokio`/`futures`/`netlink` ecosystem, right in the ~25–35 target. (The async stack was `cfg(linux)`-gated, so the cut only shows on the guest's real target, not the host.) Claim 4 (`prod-agent-no-exec`) untouched — A3 never touched the agent bin or `do_exec` (empty diff); claim 5 untouched (A2 deferred, vsock + fuzz unchanged); claim 10's `REPORT_MARKER` audit path preserved.

## Phase B — universal agent (every VM type)

### Task B1: `mvm-host-vm-init` forks `mvm-guest-agent`

ADR-066 §6. The builder/dev VM bakes the agent (via mkGuest) but PID 1 (`mvm-host-vm-init`, now a `mvm-build` bin) never forks it. Make it fork the agent under setpriv, exactly as the workload `/init` does.

**Files:** `crates/mvm-build/src/bin/mvm-host-vm-init.rs` (post-121).

Agent uid is **990** (CLAUDE.md's "901" is stale — the live `nix/lib/mk-guest.nix` workload fork uses 990); vsock port 5252; binary at `/mvm/runtime/agent` (verity overlay, ADR-051) or `/usr/local/bin/mvm-guest-agent` (baked), same preference order the workload `/init` probes.

- [x] **Step 1:** TDD'd the testable core (cross-platform, runs on macOS): `agent_spawn_command` builds the exact workload-`/init` setpriv argv (`setpriv --reuid=990 --regid=990 --clear-groups --no-new-privs -- <agent>`); `resolve_agent_binary` prefers the overlay path then the baked copy, `None` (agent-less, non-fatal) when neither. 4 tests, RED→GREEN. (The live "reachable on vsock 5252" boot assertion stays gated for a real builder-VM boot — CI / KVM host.)
- [x] **Step 2:** `fork_guest_agent()` (in `mod linux`) resolves the binary via a real `[ -x ]` (`libc::access` X_OK), spawns it under setpriv with `pre_exec` → `setsid` (new session, like the workload `/init`'s `setsid`), and is called from `run()` **after the egress lockdown, before the dispatch loop** — non-fatal, so a missing agent never wedges PID 1. The agent coexists with the builder dispatch protocol (the fork is a detached background child; PID 1 continues to the loop). The builder/dev tier already bakes the `dev-shell` agent (`entrypoint.shell = "/bin/sh"` → `withDevShell = true`), so no agent-build change is needed. **Verified:** 111 macOS bin tests green; `cargo zigbuild --target aarch64-unknown-linux-musl` produces a static ELF with `fork_guest_agent`/`is_executable` compiled+linked (the `cfg(linux)` path builds for the real guest target).

### Task B2: `xtask check-guest-agent-in-all-images`

The enforcement gate from ADR-066 §6.

- [x] **Step 1:** `launcher_forks_agent` + unit tests (`present_marker_passes`, `missing_marker_is_flagged`, `every_declared_launcher_has_a_distinct_marker`) — the lint fails when a launcher drops its agent-fork marker. The two distinct **launch mechanisms** are enumerated (not three — "dev" rides one of these): mkGuest `/init` (`nix/lib/mk-guest.nix`, marker `MVM_AGENT_BIN`) for workload + dev-shell images, and `mvm-host-vm-init` (marker `fork_guest_agent`) for the builder VM's PID 1.
- [x] **Step 2:** `xtask check-guest-agent-in-all-images` implemented (source-grep tripwire, sibling of `check-claim-catalog`/`check-guest-agent-runtime-free`); wired into the `ci.yml` Lint job. Live gate GREEN now that B1 added the builder-VM fork. Commit.

## Phase C — runtime overlay (ADR-051)

### Task C1: the verity-sealed agent overlay

ADR-051 — the agent (+ netinit/seccomp-apply) ship from a shared verity-sealed `/mvm/runtime` overlay, not baked per-image. mkGuest's `/init` already prefers `/mvm/runtime/agent` over the baked copy.

**Premise corrected (2026-06-06): C1's build + bind-mount are already done (landed under Plan 74 W1.4b).** Verified against the worktree:
- The overlay **flake is real** (`nix/images/runtime-overlay/flake.nix`, 339 lines): stages `mvm-guest-agent` + `mvm-seccomp-apply` + `mvm-guest-netinit` + `mvm-runner`, runs `mkfs.ext4` + `veritysetup format`, emits `overlay.ext4`/`overlay.verity`/`overlay.roothash`/`VERSION`, `withDevShell = false` (the prod no-`do_exec` agent — C1 Step 2's requirement).
- **`mvm-verity-init` already bind-mounts before switch_root**: it parses `mvm.runtime_roothash=`, sets up a second dm-verity target, mounts it RO at `/sysroot/mvm/runtime`, *then* pivots (`crates/mvm-guest/src/bin/mvm-verity-init.rs`, fully unit-tested).
- The **Firecracker attach is wired** (`/dev/vdc`+`/dev/vdd`, cmdline roothash threading); the host-side resolver (`mvm-build/src/runtime_overlay.rs`) is built.

So Steps 1–2 as written are **done**. What this slice fixes + guards:

- [x] **Version-pin fix + regression gate.** The flake's `overlayVersion` was **stale at `0.14.0`** vs the workspace `0.16.1` — a *fail-closed* bug (the resolver refuses an overlay whose `VERSION` ≠ the running mvmctl, so the overlay would silently never load). Bumped to `0.16.1`, and added `xtask check-runtime-overlay-version` (RED on the mismatch → GREEN after the bump) wired into the `ci.yml` Lint job so the lock-step pin can't drift again. Parsers unit-tested.

### deferred follow-ups (C1 — the real unbuilt leg, KVM-gated)

- [x] **Wire the resolver into the boot path (the code — 2a).** `attach_runtime_overlay` (`up.rs`) calls `RuntimeOverlayResolver::resolve` and populates `VmStartConfig.runtime_overlay_{path,verity_path,roothash}`, wired at all three workload-boot sites (direct-boot, main cold-boot, watch re-boot). **Backend-gated to Firecracker** (the only backend that attaches it; libkrun/Vz/apple-container/docker skip) and **non-fatal** — `resolve()` is a pure cache probe (no build/download/nix, macOS-safe), so a cold cache or non-verity dev rootfs leaves the fields `None` and the VM boots legacy. 3 unit tests (firecracker+cached populates; non-firecracker skips; cold-cache no-op) via a tempdir-seeded resolver. *Not* edited: `start.rs` (backend-blind) / `exec.rs` template-restore (predates admission, off the up/run overlay surface).
  - [ ] **Live boot validation (2b) — KVM-gated.** Seed the overlay into the cache (build the runtime-overlay flake → `install_overlay_into_cache`) and `mvmctl up` a verity workload on Firecracker; assert the agent runs from `/mvm/runtime/agent` and a tampered overlay panics the kernel on the dm-verity roothash (claim 3 lineage). Needs a real verity-enabled Firecracker/KVM boot — the Hetzner Debian-12/KVM box, not the macOS dev host.
- [ ] **libkrun + Vz overlay attach** — currently absent; the dm-verity/initramfs model doesn't map cleanly to libkrun's in-process path, so it needs its own design (likely its own plan).
- [ ] Optionally stage ADR-051's `certs/` dir into the overlay (not yet present).

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

- [x] `mvm-guest` sheds `tokio` + `async-trait` + `rtnetlink` (and the `futures`/`netlink` ecosystems they dragged in) — **−27 unique crates** on the Linux closure (126 → 99), recorded in [`docs/investigations/plan-124-lean-agent-dep-cut.md`](../../docs/investigations/plan-124-lean-agent-dep-cut.md). **`serde_json` is NOT shed** (A2): it enters transitively via `mvm-core`, so it's unremovable from the guest tree — deferred, see Task A2.
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
