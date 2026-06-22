# Plan 209 — Per-VM host-process model convergence (one shared `mvm-bridge`, thin libkrun launcher)

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:executing-plans to
> implement this plan task-by-task, and superpowers:test-driven-development for
> every task — the unified stdin contract and each endpoint variant get a failing
> test first. Steps use checkbox (`- [ ]`) syntax for tracking. **Do not change
> `spawn_bridge_thread` enforcement behavior** — this is a topology refactor, not a
> policy change; claim-10/12/13 witnesses must stay byte-for-byte green throughout.

**Goal:** Converge every workload backend on the split *VMM-process + thin shared
bridge sidecar* model (ADR-093). Fold `mvm-firecracker-bridge` + `mvm-vz-drainer`
into one `mvm-bridge` binary, and strip the bridge out of
`mvm-libkrun-supervisor` so it is a thin krun launcher whose backend spawns the
shared sidecar — exactly as Firecracker/vz already do.

**Design:** ADR-093 (`specs/adrs/093-vm-host-process-model-convergence.md`). Read
it first — it is the contract. Locked rules:

- The split model is the only common denominator (FC/vz VMMs cannot be
  in-process). Converge *toward* it; never try to merge FC/vz like libkrun.
- One `mvm-bridge` binary; one `BridgeConfigJson` with an **endpoint-kind
  discriminant**; **uniform** `mvm-jailer-lite` confinement for every endpoint
  (closes the current vz-drainer gap); passt-hash verify only on the passt
  endpoint, before confinement.
- `spawn_bridge_thread`, `BridgeConfig`, `BridgeEndpoints`, and the admission /
  signed-plan path are **unchanged**. This plan moves *who spawns what*, not
  *what the bridge enforces*.
- Teardown is the explicit `AttachedBridgeGuard` fail-closed kill, uniformly —
  no reliance on libkrun `exit()` to reap a thread.

**Key anchors (verify before editing):**

- `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs` — `run_with_bridge`
  (≈L332–566, the bridge half to remove), `run_legacy` (L320), main dispatch
  (L97–216), the `krun_start_enter` launch to keep.
- `crates/mvm-vm-host/src/bin/mvm-firecracker-bridge.rs` — sidecar shape:
  stdin read → `verify_passt_hash` → `confine_self` → `BridgeEndpoints::Passt`
  → `spawn_bridge_thread`.
- `crates/mvm-vm-host/src/bin/mvm-vz-drainer.rs` — sidecar shape with
  `BridgeEndpoints::VzIngest`; **no** jailer-lite today.
- `crates/mvm-vm-host/src/lib.rs` + `firecracker_bridge::parse`
  (`BridgeConfigJson`, `decode_plan_json`, `verify_passt_hash`,
  `PasstHashesFile`) — the parser surface the fuzz lane drives.
- `mvm_hostd::supervisor::gateway_bridge` (`BridgeConfig`, `BridgeEndpoints`,
  `spawn_bridge_thread`) and `mvm_hostd::jailer` (`ConfinementSpec`,
  `confine_self`) — the shared core, unchanged.
- `crates/mvm-backend/src/microvm.rs` — `spawn_fc_bridge`, the RAII
  `AttachedBridgeGuard`, `MVM_FC_BRIDGE_PATH` resolution, socketpair
  fd-inheritance (the pattern libkrun adopts).
- `crates/mvm-backend/src/vz.rs` — `AttachedDrainerGuard` (vz sidecar spawn).
- `crates/mvm-backend/src/libkrun.rs` — `start` (currently spawns the
  merged supervisor), `resolve_supervisor_path`.
- `crates/mvm-vm-host/Cargo.toml` — `[[bin]]` declarations to edit.
- `crates/mvm-cli/build.rs` / packaging / `.github/workflows/architecture.yml`
  + the bridge fuzz lane — reference updates.

**Out of scope:** dropping Firecracker / any libkrun-only decision (separate
call); changing egress/DNS/L4 policy behavior; the supervisor-distribution
packaging fix (tracked separately, though this plan reduces its surface).

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

## Task 2: `mvm-bridge` binary — fold the two sidecars into one

- [ ] Add `crates/mvm-vm-host/src/bin/mvm-bridge.rs`: read `BridgeConfigJson`
      from stdin → (passt only) `verify_passt_hash` *before* confinement →
      `confine_self` **for every endpoint kind** (closes the vz-drainer gap) →
      decode plan/bundle/network_policy → build `BridgeConfig` → build the
      `BridgeEndpoints` variant from the discriminant → `spawn_bridge_thread` →
      `catch_unwind → exit(1)` fail-closed wrapper (preserve today's semantics).
- [ ] Self-gate non-Linux to a stub `main()` (mirror the current
      `mvm-firecracker-bridge` cfg pattern) so non-Linux workspace builds stay
      green; vz endpoint path gated appropriately.
- [ ] Declare `[[bin]] mvm-bridge` in `crates/mvm-vm-host/Cargo.toml`. Leave the
      old two bins in place *for now* (deleted in Task 4 once callers move).
- [ ] Tests: per-endpoint dispatch selects the right `BridgeEndpoints` variant;
      confinement is applied on the vz path (regression for the gap); passt-hash
      mismatch refuses before confinement.

## Task 3: Thin `mvm-libkrun-supervisor` + backend-spawned sidecar (the crux)

- [ ] Strip the bridge half out of `run_with_bridge`: the supervisor parses the
      `SupervisorConfig`, builds the `KrunContext`, and calls
      `krun_start_enter` — nothing else. Collapse `run_legacy` + `run_with_bridge`
      into one launch path. Delete the `BridgeFds → BridgeEndpoints` factory
      closure and the concurrent bridge-thread spawn.
- [ ] In `mvm-backend::libkrun::start`, create the gateway socketpair, give one
      end to the krun net device (the fd the supervisor previously wired
      in-process), and spawn `mvm-bridge` with the other end via fd-inheritance —
      reusing/generalizing `spawn_fc_bridge`'s RAII `AttachedBridgeGuard` and the
      `MVM_*_BRIDGE_PATH` → adjacent-to-exe → PATH resolver. Guard reaps the
      sidecar on early return / panic / VM teardown.
- [ ] Generalize the bridge-path resolver + guard so libkrun, FC, and vz share
      one helper (one env override name, e.g. `MVM_BRIDGE_PATH`, plus the
      legacy `MVM_FC_BRIDGE_PATH`/supervisor-path fallbacks for compat).
- [ ] Tests: unit-test the socketpair setup + guard teardown (kill-on-drop);
      assert the thin supervisor no longer references `spawn_bridge_thread`; an
      `xtask`/grep gate that the libkrun supervisor links no bridge symbol.

## Task 4: Move FC + vz onto `mvm-bridge`; delete the old sidecars

- [ ] Point `mvm-backend::microvm::spawn_fc_bridge` and the vz
      `AttachedDrainerGuard` spawn at `mvm-bridge` with the unified
      `BridgeConfigJson` (Passt / VzIngest discriminant) instead of the
      per-backend bins.
- [ ] Delete `crates/mvm-vm-host/src/bin/mvm-firecracker-bridge.rs` and
      `mvm-vz-drainer.rs` and their `[[bin]]` entries; remove dead re-exports.
- [ ] Update `crates/mvm-cli/build.rs` / any embed/packaging manifest and the
      release-artifact list to ship `mvm-bridge` in place of the two old bins.
- [ ] Tests: FC + vz lifecycle (mock backend where live KVM/Vz is unavailable)
      spawn and reap `mvm-bridge`; no reference to the deleted bin names remains
      (grep gate).

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

## Task 6: Verification (dev-host bootable; FC live-KVM gated)

- [ ] On this macOS dev host (libkrun + vz): `machine run --image alpine --
      echo hi` boots through the thin libkrun supervisor + spawned `mvm-bridge`
      sidecar; `ps` shows the two-process topology (launcher + bridge); the
      sidecar is reaped on teardown (no orphan — also addresses the
      orphaned-supervisor leak observed during diagnosis). Capture the session.
- [ ] `machine run --net --image alpine` still resolves + connects allow-listed
      hosts and sink-holes the rest (claim-10 egress unchanged) on libkrun/vz.
- [ ] Firecracker path (live-KVM-gated; unverifiable on a macOS dev host):
      FC VM boots with `mvm-bridge` as its sidecar; default-deny + allow-list
      egress regression holds. Mark this acceptance line gated until run on a
      KVM host.

---

## Risks / notes

- **fd-passing is the highest-risk step** (Task 3). De-risk by mirroring
  `spawn_fc_bridge`'s socketpair + inherited-fd encoding exactly; the FC path is
  the working reference.
- **No behavior drift in `spawn_bridge_thread`.** If a claim-10/12/13 witness
  moves at all, stop — the refactor changed enforcement, which is out of scope.
- **Sequencing:** Tasks 1→2 are additive (old bins still present), so they can
  land and bake before Task 3/4 flip callers and delete the old bins. Keep the
  old bins until Task 4's grep gate is green to allow a clean revert.
