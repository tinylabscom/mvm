# Plan 305 — Delete the dead guest-NIC gateway stack

**Status: IN PROGRESS**
**Supersedes:** the confinement-first framing this plan opened with (see
"History" below)
**Related:** plan 303 WS6, ADR-003, ADR-014 claim 10, `xtask
check-vsock-only-egress`

## Why

Workload egress converged on vsock. Every workload backend boots with a
virtio-vsock device and no net device, and egress leaves the guest only over
the per-VM substitution endpoint. The guest-NIC gateway stack that predates
that convergence — passt, gvproxy, the native/rvproxy gateway, the `mvm-bridge`
sidecar, and the observer packet pipeline they feed — is still in the tree but
no longer reachable.

This is not an inference from the docs. It is what the code says:

- `crates/mvm-build/src/libkrun_builder.rs:154` — *"The active transport is now
  direct vsock on every backend. `MVM_NETWORKING` is retained only as a
  compatibility knob so stale shells produce a warning instead of silently
  reopening legacy guest-NIC code paths."* The env var is read only to log
  `"MVM_NETWORKING is ignored; libkrun networking is now direct-vsock only"`.
- `crates/mvm-hostd/src/bin/mvm-libkrun-supervisor.rs:470` — *"Historical
  native-gateway hook: this now stays inert because the active libkrun
  transport is direct-vsock only."*
- `should_use_bridge_route()` (same file, ~252) returns **false** for
  `Tsi | VsockDirect`, and those are the only modes anything produces.
- `ConfigBuilder::with_passt` has **zero** non-test callers. The only
  construction of `NetworkingMode::Passt` in the tree is inside a `#[test]`.
- `with_native_gateway_config` is called only from inside a block already
  guarded on `cfg.krun.networking` *being* `NativeGateway`, which nothing sets.
- `run_packet_pipeline`'s only non-test callers are `gateway_bridge/passt.rs`
  and `gateway_bridge/native_gateway.rs`.

So the whole subtree is unreachable, and it is not inert weight: it is a second
egress model sitting next to the real one, with its own policy surface, its own
audit path, and its own confinement spec. `xtask check-vsock-only-egress`
exists precisely to keep gateway tokens off workload paths — deleting the
gateway makes that gate trivially true instead of continuously defended.

## Two live findings this surfaced

1. **The only CI lane exercising Landlock + seccomp confinement cannot run.**
   `.github/workflows/ci-full.yml` invokes `cargo test -p mvm-jailer-lite`.
   That crate was absorbed into `mvm-hostd` and no longer exists as a
   workspace member, so the step fails to resolve its package. The lane is
   `workflow_dispatch`-only, which is why nobody noticed. The tests themselves
   are fine — run on a live Landlock kernel (6.8, `landlock` in
   `/sys/kernel/security/lsm`) both pass.
2. **`ConfinementSpec::firecracker_bridge` hard-requires `/usr/bin/passt` to
   exist**, because Landlock's `PathFd::new` opens every allowlisted path. On a
   box without passt the property tests fail with `landlock path missing`. That
   is a spec pinned to a binary the runtime no longer launches.

## Workstreams

### WS1 — Fix the broken confinement lane

Independent of the deletion and worth landing first: a gate that cannot run is
worse than no gate, because the row in the ledger says it is covered.

- [x] `-p mvm-jailer-lite` → `-p mvm-hostd` in `ci-full.yml`, and correct the
      stale `crates/mvm-jailer-lite/...` paths in the lane comments and job name
- [x] xtask gate: every `-p <pkg>` in a workflow names a real workspace member,
      so the next crate consolidation cannot silently orphan a lane. Live over
      121 `-p` references across 20 workflow files

Writing the gate turned up three more defects in the same file, all of the
same shape — `ci-full.yml` is `workflow_dispatch`-only, so nothing it says is
ever contradicted by a run:

- [x] **The Landlock probe skipped itself on working kernels.** It gated on
      `[ -d /sys/kernel/security/landlock ]`. That directory does not exist on
      the live 6.8 box, which nonetheless carries `landlock` in
      `/sys/kernel/security/lsm` and passes both property tests. Now probes the
      LSM list, which is the kernel's own answer.
- [x] **`cargo test -p mvm-host-vm-init`** in the Firecracker boot-smoke lane.
      That is a `[[bin]]` of `mvm-build`, not a package, so the lane could not
      resolve it either. Now `-p mvm-build --bin mvm-host-vm-init`.
- [x] **A paths filter on `crates/mvm-host-vm-init/**`**, a directory absorbed
      into `mvm-build`. A trigger that cannot match never fires, so edits to
      the builder VM's PID 1 silently stopped gating the builder-vm lane.

Verified on the live Linux box: with the corrected command, both property
tests pass under an enforcing Landlock (`landlock_denies_paths_outside_ruleset`,
`seccomp_allows_listed_denies_unlisted`).

One caveat found while doing it, feeding WS2: the tests only pass there because
`passt` was installed. `ConfinementSpec::firecracker_bridge` lists the passt
binary as a Landlock-readable path, and `PathFd::new` opens every path in the
ruleset — so the spec cannot be built on a host without a binary the runtime
never launches.

### WS2 — Delete the gateway stack

Staged so each step compiles and the test suite stays green.

- [ ] `NetworkingMode::{Passt, NativeGateway}` and their builder setters
- [ ] `libkrun-sys`: `bridge.rs`, `run_supervisor_with_bridge`,
      `native_gateway.rs`, passt spawn in `start.rs`/`supervisor.rs`
- [ ] `mvm-hostd`: `gateway_bridge/{passt,native_gateway,native_gateway_live}.rs`,
      `supervisor/network/rvproxy_*.rs`, and whatever of `gateway_bridge/` is
      left with no live caller
- [ ] `mvm-bridge` sidecar bin + `src/bridge/`, and its `ConfinementSpec` +
      `BRIDGE_SYSCALLS` if nothing else uses them
- [ ] `run_with_bridge` / `should_use_bridge_route` in the libkrun supervisor
- [ ] `MVM_NETWORKING` and `MVM_GATEWAY_BIN`
- [ ] The observer packet pipeline (`supervisor/network/pipeline.rs`) **only if**
      the compiler confirms no live caller survives — it is shared with the
      scan/substitution stages, so this one gets checked, not assumed

Anything whose deletion the compiler resists gets reported, not forced.

### WS3 — Correct the docs the deletion falsifies

- [ ] CLAUDE.md "Host dependencies (macOS)" still instructs `brew install
      slp/krun/gvproxy` and documents an `MVM_NETWORKING` per-OS default table
      that `libkrun_builder.rs:193` contradicts
- [ ] ADR-003 and any claim-5/claim-10 prose that describes the gateway parsers
      as a live surface

### WS4 — Then confine the signer roles

The original plan-305 scope, deferred behind the deletion because it is a
smaller surface afterwards: `mvm-host-signer`, `mvm-audit-signer`,
`mvm-signer-helper`, `mvm-broker` still run unconfined while `mvm-bridge` —
about to be deleted — is one of only two bins that call `confine_self`.

Blocked on: `mvmctl seccomp-audit` traces only the main thread, and all four
roles build `tokio::runtime::Builder::new_multi_thread()`, so any allowlist it
produces today is incomplete by construction and the failure mode is SIGSYS
under load. Extend the tracer with `PTRACE_O_TRACECLONE` first.

- [ ] Extend `seccomp-audit` to follow clones/threads
- [ ] Derive the four allowlists on the live Linux box
- [ ] One PR per role

## History

This plan opened as "confine the four unconfined moat roles". That framing
survived until the gateway stack was examined and found inert: confining
`mvm-bridge`'s peers is worth less than deleting the model `mvm-bridge` exists
to serve. The confinement work is preserved as WS4 rather than dropped.

## Validation

The live Linux box (kernel 6.8, Landlock active, `/dev/kvm`) is the target for
anything kernel-dependent. Both confinement property tests already pass there.
