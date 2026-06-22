# Plan 211 — Fold the external-VMM bridge sidecars into one `mvm-bridge` (libkrun stays merged)

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:executing-plans to
> implement this plan task-by-task, and superpowers:test-driven-development for
> every task — the unified stdin contract and each endpoint variant get a failing
> test first. Steps use checkbox (`- [ ]`) syntax for tracking. **Do not change
> `spawn_bridge_thread` enforcement behavior** — this is a topology refactor, not a
> policy change; claim-10/12/13 witnesses must stay byte-for-byte green throughout.

**Goal:** Fold the two external-VMM bridge sidecars (`mvm-firecracker-bridge`,
`mvm-vz-drainer`) into one shared `mvm-bridge` binary, and point the Firecracker
+ vz backends at it (ADR-094). **`mvm-libkrun-supervisor` keeps its merged
in-process bridge** — Task 3 (splitting it) was descoped on an intrinsic libkrun
constraint (see below). Net: 4 per-VM host bins → 3.

**Design:** ADR-094 (`specs/adrs/094-vm-host-process-model-convergence.md`). Read
it first — it is the contract. Locked rules:

- The split model is the natural fit for the **external-VMM** backends (FC, vz);
  they already use it. Do **not** try to make FC/vz merged, and do **not** try
  to split libkrun (it creates the bridge fds internally + `_exit()`s on guest
  shutdown — see ADR-094 "Why libkrun stays merged").
- One `mvm-bridge` binary; one `BridgeConfigJson` with an **endpoint-kind
  discriminant**; `mvm-jailer-lite` confinement through one cfg-gated codepath
  where the OS supports it (Linux `Passt`); passt-hash verify only on the passt
  endpoint, before confinement.
- `spawn_bridge_thread`, `BridgeConfig`, `BridgeEndpoints`, and the admission /
  signed-plan path are **unchanged**. This plan moves *who spawns what* (FC + vz
  spawn the shared bin instead of per-backend bins), not *what the bridge
  enforces*.
- FC + vz teardown stays the explicit `AttachedBridgeGuard` /
  `AttachedDrainerGuard` fail-closed kill they already use.

**Key anchors (verify before editing):**

- `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs` — **unchanged** (Task 3
  descoped): keeps `run_with_bridge` (the merged in-process bridge) +
  `run_legacy`. Listed only so reviewers know it is deliberately left alone.
- `crates/mvm-vm-host/src/bin/mvm-bridge.rs` — the shared sidecar (Task 2). FC +
  vz will spawn this instead of the per-backend bins.
- `crates/mvm-vm-host/src/bin/mvm-firecracker-bridge.rs` — to delete; its shape
  (stdin → `verify_passt_hash` → `confine_self` → `BridgeEndpoints::Passt`) is
  already reproduced in `mvm-bridge`.
- `crates/mvm-vm-host/src/bin/mvm-vz-drainer.rs` — to delete; its `VzIngest`
  shape is reproduced in `mvm-bridge`.
- `crates/mvm-vm-host/src/bridge::parse` (`BridgeConfigJson`, endpoint
  discriminant) + `firecracker_bridge::parse` (`decode_plan_json`,
  `verify_passt_hash`, `PasstHashesFile`) — the unified contract + reused
  helpers; the fuzz lane drives the parser.
- `mvm_hostd::supervisor::gateway_bridge` (`BridgeConfig`, `BridgeEndpoints`,
  `spawn_bridge_thread`) and `mvm_hostd::jailer` (`ConfinementSpec`,
  `confine_self`) — the shared core, unchanged.
- `crates/mvm-backend/src/microvm.rs` — `spawn_fc_bridge`, the RAII
  `AttachedBridgeGuard`, `MVM_FC_BRIDGE_PATH` resolution, socketpair
  fd-inheritance — **repoint at `mvm-bridge` with the unified config**.
- `crates/mvm-backend/src/vz.rs` — `AttachedDrainerGuard` (vz sidecar spawn) —
  **repoint at `mvm-bridge` with the `VzIngest` config**.
- `crates/mvm-backend/src/libkrun.rs` — `start` / `resolve_supervisor_path`
  **unchanged** (libkrun keeps the merged supervisor).
- `crates/mvm-vm-host/Cargo.toml` — `[[bin]]` declarations to edit.
- `crates/mvm-cli/build.rs` / packaging / `.github/workflows/architecture.yml`
  + the bridge fuzz lane — reference updates.

**Out of scope:** dropping Firecracker / any libkrun-only decision (separate
call); changing egress/DNS/L4 policy behavior; the supervisor-distribution
packaging fix (tracked separately, though this plan reduces its surface).

---

## Implementation status & resume context (as of 2026-06-21)

> **Update 2026-06-22:** Task 4 is **done and live-verified on both legs** (vz on
> macOS 26; FC on a Hetzner KVM box) — see the Task 4 section below. The detailed
> snapshot under this heading is the original pre-Task-4 record; the open
> decisions there are resolved (FC is live-testable via the Hetzner box; this is
> one stacked branch/PR; #1252 kept as-is). Remaining: Task 5 (packaging/embed +
> fuzz repoint + cosmetic ref sweep + architecture.yml/doctor) and Task 6's
> deeper egress regressions.

**Branches / PRs**

- **PR #1252** = branch `feat/plan-209-task1-unified-bridge-config` — carries the
  specs + **Task 1 + Task 2**. CI was red on `check-no-spec-refs-in-comments`
  (plan/ADR citations in source comments) → fixed (commit `15cd64e3`), pushed,
  `MERGEABLE`. **Note:** this PR still has the *original* ADR-094 ("split all
  backends / thin libkrun launcher"). The descope amendment lives on the Task 4
  branch below, so #1252 would merge ADR v1 and the Task 4 PR supersedes it with
  v2 — unless we cherry-pick the descope doc-commit into #1252 first (open
  decision — see below).
- **Task 4 work** = branch `feat/plan-209-task4-fold-sidecars` (stacked on
  #1252). Currently contains only the **descope amendment** (ADR-094 + this plan
  + REFACTOR-STATUS rewritten; commit `a66b86da`). No Task 4 code yet.

**Done**

- Task 1 (unified `bridge::parse` contract) + Task 2 (`mvm-bridge` binary). 43
  tests; fmt/clippy/spec-ref gates green.
- Task 3 **descoped** (libkrun stays merged) — see ADR-094 "Why libkrun stays
  merged". `msb_krun` checked and rejected (same `_exit()` behavior).

**Not done — remaining Task 4 work (mechanical but wide; both spawn sites read
and understood):**

- **vz leg** — `mvm-backend::vz::spawn_vz_drainer` (`crates/mvm-backend/src/vz.rs`
  ~L2317–2375). Reshape `drainer_cfg` JSON → unified `BridgeConfigJson`: **add
  `keys_dir`** (= `data_dir.join("keys")`; the old drainer omitted it),
  `endpoint: {vz_ingest: {events_socket_path}}`, omit `network_policy_json` (old
  drainer hardcoded `network_policy: None`). Resolve `mvm-bridge` (env
  `MVM_BRIDGE_PATH`) instead of `mvm-vz-drainer`. *Compiles on macOS; live test
  needs macOS 26 (now available after this upgrade).*
- **FC leg** — `mvm-backend::microvm::spawn_fc_bridge`
  (`crates/mvm-backend/src/microvm.rs` ~L2933–3015, `#[cfg(target_os="linux")]`).
  Reshape `bridge_cfg` JSON: move `passt_path` + `passt_hashes_path` into
  `endpoint: {passt: {passt_path, passt_hashes_path, gateway_fd_raw,
  supervisor_fd_raw}}`; **add `network_policy_json` = serialized
  `NetworkPolicy::unrestricted()`** (the old `mvm-firecracker-bridge` hardcoded
  this internally so the passt bridge defers to the nftables moat — must now be
  producer-supplied). Resolve `mvm-bridge`. ***Linux-only: NOT compiled on a
  macOS host — only CI verifies it.*** Leave the socketpair + `pre_exec` dup2 +
  `AttachedBridgeGuard` exactly as-is.
- **Byte-equivalence safety net** (cross-platform, runs on macOS): a test that
  builds the exact JSON each producer now emits (Passt + VzIngest) and asserts it
  deserializes into the unified `BridgeConfigJson` with the right endpoint +
  fields. This is the main guard for the FC leg we can't compile here.
- **Delete the two old bins** + their `[[bin]]` entries
  (`crates/mvm-vm-host/src/bin/mvm-firecracker-bridge.rs`, `mvm-vz-drainer.rs`,
  `crates/mvm-vm-host/Cargo.toml`). **Deletion fallout to handle in the same
  change** (found via grep): `crates/mvm-cli/src/commands/vm/up.rs` (references a
  bin name), `crates/mvm-vm-host/fuzz/` targets + `.github/workflows/security.yml`
  bridge-fuzz lane (L387), and jailer doc/comments (`mvm-hostd/src/jailer/*`).
  Keep `firecracker_bridge::parse` (the `decode_plan_json`/`verify_passt_hash`/
  `PasstHashesFile` helpers + the now-bin-less `BridgeConfigJson`, which stays
  `pub` so no dead-code warning) — the unified `bridge::parse` re-exports from it.
- Consider splitting Task 4 into **4a** (wire FC+vz + byte-equiv tests, *keep*
  old bins) and **4b** (delete bins + fuzz/CI/up.rs cleanup) so the risky
  deletion is isolated + revertible.

**Then:** Task 5 (fuzz/CI/docs/architecture.yml/doctor) and Task 6 (verification —
vz now live-testable on macOS 26; FC still KVM-gated).

**Open decisions for the user**

1. **#1252 ADR coordination:** merge #1252 as-is (ADR v1, superseded by Task 4
   PR) **or** cherry-pick the descope doc-commit (`a66b86da`) into #1252 so it
   merges correct in one shot?
2. **FC verification basis:** OK to land the FC egress-path change CI-checked +
   live-KVM-gated only (no KVM host available to us)?
3. Task 4 as one PR or split 4a/4b?

---

## Task 1: Unified `BridgeConfigJson` + endpoint-kind discriminant (contract first) — ✅ DONE

- [x] New module `mvm_vm_host::bridge::parse` defines a single `BridgeConfigJson`
      carrying an `endpoint: BridgeEndpointKind` enum (`Passt { passt_path,
      passt_hashes_path, gateway_fd_raw, supervisor_fd_raw }`, `VzIngest {
      events_socket_path }`, `LibkrunGvproxy { gvproxy_socket_path,
      supervisor_listen_path }`); `keys_dir` is a common field (threaded for
      every kind now, including vz). `#[serde(deny_unknown_fields)]` on the outer
      struct + the enum. **Externally tagged** (not internally), because
      `deny_unknown_fields` is not honoured on internally-tagged enums — fail-closed
      parsing is the security contract. Additive: old bins/configs untouched.
- [x] `decode_plan_json` / `verify_passt_hash` / `PasstHashesFile` re-exported
      verbatim from `firecracker_bridge::parse`; the fuzz target keeps compiling
      against the same code.
- [x] 10 tests: per-variant roundtrip (serialize→deserialize identity),
      `deny_unknown_fields` at top level + within a variant, unknown/missing
      endpoint kind refused, `bundle_json` default+carry, re-export resolves.
      `cargo test -p mvm-vm-host` + fmt + clippy green.

## Task 2: `mvm-bridge` binary — fold the two sidecars into one — ✅ DONE

> Confinement is **Linux-only** (`confine_self` = Landlock+seccomp; the macOS
> stub hard-errors). The unified binary is **cross-platform** (Linux `Passt`;
> macOS `VzIngest`/`LibkrunGvproxy`), so confinement is cfg-gated per arm — not a
> whole-binary Linux gate like the old `mvm-firecracker-bridge`. Network policy
> is **not** derivable from endpoint kind (`Passt` serves both FC, which defers
> to nftables → `unrestricted`, *and* libkrun-on-Linux, which enforces in the
> bridge), so the producer supplies it via a `network_policy_json` config field.

- [x] Extend `bridge::parse::BridgeConfigJson` with `network_policy_json:
      Option<String>` (`#[serde(default)]`) — the producer's egress-policy
      intent, decoded into `Option<NetworkPolicy>` for `BridgeConfig`. Keeps the
      sidecar policy-agnostic.
- [x] Added `crates/mvm-vm-host/src/bin/mvm-bridge.rs`: reads `BridgeConfigJson`
      from stdin → `check_endpoint_platform` (refuses `Passt` off Linux) →
      `verify_passt_hash` *before* `confine_self` (Passt, Linux) →
      `confine_for_endpoint` (Linux; firecracker_bridge spec for Passt) → decode
      plan/bundle/network_policy → `FileAuditSigner` → observer chain
      (`leaf_caps_for`: payload-tap for Passt/gvproxy, flow-only for VzIngest) →
      `BridgeConfig` → `build_endpoints` (Linux-only `unsafe` fd reconstruction
      for Passt) → `spawn_bridge_thread` → park. macOS arms unconfined. The
      `LibkrunGvproxy`-on-Linux confinement spec is deferred to Task 3 (refuses
      rather than ship unconfined) since no producer emits it until libkrun moves
      onto the sidecar.
- [x] Declared `[[bin]] mvm-bridge` in `crates/mvm-vm-host/Cargo.toml` (no
      whole-binary cfg gate; per-arm gating inside). Old two bins left in place.
- [x] Tests (4 in-bin + 3 in-lib): `leaf_caps_for` payload-tap mapping,
      `endpoint_label` stability, `check_endpoint_platform` matches host
      (`Passt` ⇔ Linux), `build_endpoints` maps the path-based variants,
      `network_policy_json` default+roundtrip. `cargo test -p mvm-vm-host` + fmt
      + clippy green. (Live confinement + relay + Passt fd reconstruction are
      exercised on-host in Task 6 / the Linux-gated leg.)

## Task 3: ~~Thin `mvm-libkrun-supervisor` + backend-spawned sidecar~~ — DESCOPED

> **Abandoned on an intrinsic libkrun constraint** (see ADR-094 "Why libkrun
> stays merged"). libkrun creates the bridge fds *inside* the supervisor
> (`run_supervisor_with_bridge` → `configure_with_gateway_for_bridge`) and
> `_exit()`s on guest shutdown, so the backend cannot feed it fds (as it does
> for the external `firecracker`/vz VMMs) and a destructor-based sidecar reaper
> never runs. Splitting would need a C-library restructure + per-platform
> `PR_SET_PDEATHSIG`/`kqueue NOTE_EXIT` reaping for no benefit the merged model
> doesn't already provide (running libkrun out-of-process to absorb `_exit()` is
> exactly what the per-VM supervisor already is). Confirmed against the
> `msb_krun` binding, which documents the same `_exit()` behavior.
>
> **`mvm-libkrun-supervisor` keeps its merged in-process bridge unchanged.** The
> "4 bins → 3" reduction is achieved entirely by Task 4 (folding the two
> external-VMM sidecars). The libkrun in-process bridge keeps calling the shared
> `spawn_bridge_thread`, so the enforcement logic stays one implementation.

## Task 4: Move FC + vz onto `mvm-bridge`; delete the old sidecars — ✅ DONE

- [x] **4a** — `mvm-backend::microvm::spawn_fc_bridge` (Passt) and
      `mvm-backend::vz::spawn_vz_drainer` (VzIngest) now emit the unified
      `BridgeConfigJson` and spawn `mvm-bridge`. The resolvers + env override
      unified to `MVM_BRIDGE_PATH`; the vz source-checkout helper build +
      `VZ_HELPER_BINARIES` build `mvm-bridge`. FC adds `network_policy_json =
      unrestricted` (defer to nftables); vz adds `keys_dir` + omits the policy.
      2 cross-platform golden tests mirror each producer's JSON.
- [x] **4b** — deleted `mvm-firecracker-bridge.rs` + `mvm-vz-drainer.rs` + their
      `[[bin]]` entries; updated the crate description + `lib.rs` doc to the
      3-bin topology. `firecracker_bridge::parse` kept (helpers re-exported by
      `bridge::parse`; fuzz lane still drives it).
- [x] **Live verification (both legs):**
      - vz on **macOS 26**: `machine run --image alpine` boots via vz, spawns
        `mvm-bridge` (VzIngest) + `mvm-vz-supervisor`, prints output, and reaps
        cleanly (no `mvm-vz-drainer`, no orphans).
      - FC on a **Hetzner x86_64 KVM box**: built clean on Linux (confirms the
        `cfg(linux)` FC producer compiles); with `MVM_GATEWAY_BRIDGE=1` the log
        shows `spawning mvm-bridge with inherited socketpair fds … gateway_fd=3
        supervisor_fd=4` then `starting mvm-bridge … endpoint="passt"` — i.e.
        the FC backend spawns `mvm-bridge`, which parses the unified config and
        selects Passt; the FC VM boots. (The FC Passt-bridge lane is opt-in via
        `MVM_GATEWAY_BRIDGE` and **pre-Task-4** is not wired end-to-end —
        confinement/observer-path gap + watchdog hard-fail; that is orthogonal
        to this swap. Default FC egress is the unconditional nftables moat.)
- [→] Packaging/release-artifact + `cargo build.rs` embed updates to ship
      `mvm-bridge` in place of the two old bins → **Task 5** (CI/packaging).
- [→] mock-backend lifecycle test for spawn/reap + grep gate for deleted names
      → **Task 5**.

## Task 5: CI, fuzz, docs, claim integrity

- [ ] Repoint the bridge fuzz lane (`firecracker-bridge-fuzz`) at the unified
      parser; rename to `bridge-config-fuzz` if appropriate. One parser, one
      fuzz target.
- [ ] Update `.github/workflows/architecture.yml` substrate-server inventory and
      `crates/mvm-vm-host/Cargo.toml` `[package.metadata.mvm.architecture]` to
      describe the three-bin topology.
- [ ] Update `mvmctl doctor` if it enumerates per-VM host bins; update any
      contributor/reference docs that name `mvm-firecracker-bridge` /
      `mvm-vz-drainer`.
- [ ] Confirm `xtask check-claim-catalog`, `xtask check-handler-*`, and the
      claim-10/12/13 witnesses stay green — this plan introduces no new claim and
      must not weaken an existing one. No catalog edits expected.
- [ ] `just ci` green (fmt --all, nextest, doctests, clippy -D warnings).

## Task 6: Verification (FC = live-KVM gated; vz = macOS-26 gated)

- [ ] libkrun path **unchanged** (Task 3 descoped): `machine run --image alpine
      -- echo hi` on a libkrun host still boots through the merged supervisor.
      This is a regression check, not new behavior.
- [ ] vz path (macOS-26 Apple Silicon gated): `machine run --image alpine` boots
      with `mvm-bridge` (VzIngest) as the drainer instead of `mvm-vz-drainer`;
      `--net` still resolves + connects allow-listed hosts and sink-holes the
      rest (claim-10 egress unchanged); the sidecar is reaped on teardown.
- [ ] Firecracker path (live-KVM gated; unverifiable on a macOS dev host): FC VM
      boots with `mvm-bridge` (Passt) as its sidecar instead of
      `mvm-firecracker-bridge`; default-deny + allow-list egress regression
      holds. Gated until run on a KVM host.

---

## Risks / notes

- **No behavior drift in `spawn_bridge_thread`.** If a claim-10/12/13 witness
  moves at all, stop — the refactor changed enforcement, which is out of scope.
- **The Passt/VzIngest configs `mvm-bridge` receives must match byte-for-byte
  what the old bins received** (same fds, paths, audit substrate, network
  policy). The only intended change is the binary name + the unified wrapper
  shape. Diff the produced JSON against the old producers.
- **Sequencing:** Tasks 1→2 are additive (old bins still present). Task 4 flips
  the FC + vz callers to `mvm-bridge` and deletes the two old bins; keep them
  until the grep gate is green to allow a clean revert. libkrun is never touched.
