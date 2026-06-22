# ADR-094 — Fold the external-VMM bridge sidecars into one `mvm-bridge`; keep libkrun merged

**Status:** Accepted
**Amends:** [ADR-002](002-microvm-security-posture.md) (per-backend tier matrix — the external-VMM backends share one bridge-sidecar process) and [ADR-083](083-workload-backend-type-bar.md) (the shared egress/audit funnel gains a single, shared transport process for FC + vz instead of two near-identical ones).
**Preserves:** every numbered claim — in particular claim 10 (default-deny egress), claim 12 (binding-gated host services), and claim 13 (no raw secret over the broker channel), all of which ride the gateway bridge. The `spawn_bridge_thread` enforcement core is unchanged; signed-plan admission ([ADR-041](041-signed-audited-execution-plans.md)) is untouched.
**Relates:** does **not** drop Firecracker or pick a single VMM — it is the topology cleanup that should land *before* any future libkrun-only / backend-consolidation decision, and is independently valuable if that decision is never taken.

## Context

`mvm` runs every microVM behind a per-VM host process (one per guest, by
design — the libkrun `krun_start_enter` `exit()` semantics forbid an
in-process registry). Today those host processes come in **four** binaries
that all funnel into the same enforcement core,
`mvm_hostd::supervisor::gateway_bridge::spawn_bridge_thread`, but wrap it in
**two different process models**:

- **Split model** — `mvm-firecracker-bridge` and `mvm-vz-drainer`. The VMM is
  a *separate* process (the upstream `firecracker` binary; the
  `mvm-vz-supervisor`), and the bridge is a **thin sidecar** that reads a JSON
  config on stdin → decodes the `ExecutionPlan` → builds a `BridgeConfig` + a
  `BridgeEndpoints` variant → calls `spawn_bridge_thread`. Both sidecars are
  spawned *from the backend* with an RAII teardown guard and socketpair
  fd-inheritance (`mvm-backend::microvm::spawn_fc_bridge` +
  `AttachedBridgeGuard`; `mvm-backend::vz` + `AttachedDrainerGuard`).
- **Merged model** — `mvm-libkrun-supervisor`. One process does **both** the
  VMM (`krun_start_enter`, in-process via the `libkrun-sys` FFI) **and** the
  bridge (`spawn_bridge_thread` on a concurrent thread, "reaped by `exit()` on
  guest shutdown" —
  `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs::run_with_bridge`).

The cost of the divergence:

- **The two split sidecars are ~90% identical** — same stdin contract (the
  source comments already note "the bridge's stdin contract is identical to
  `mvm-vz-drainer`'s and `mvm-libkrun-supervisor`'s"), same plan decode, same
  `spawn_bridge_thread` hand-off. They differ only in the `BridgeEndpoints`
  variant (`Passt` vs `VzIngest`) and confinement. Two binaries, two stdin
  parsers, two fuzz surfaces, for one contract.
- **Confinement is wired per-binary, not per-platform.** `mvm-firecracker-bridge`
  applies `mvm-jailer-lite` confinement (`confine_self`, seccomp + Landlock) and
  verifies the pinned passt hash; `mvm-vz-drainer` applies neither. That
  asymmetry is *mostly* a platform fact, not a pure duplication bug:
  `confine_self` is **Linux-only** — on macOS it is a stub that returns
  `SeccompUnavailable` (there is no Landlock/seccomp to apply), and the vz
  drainer only ever runs on macOS. So the consolidation does **not** newly
  confine the macOS paths (it cannot). What it *does* fix is that confinement
  becomes a single cfg-gated codepath applied uniformly to every endpoint the
  OS *can* confine (the Linux `Passt` path), instead of being open-coded in one
  bin and absent from the other — removing the duplication and the risk that a
  future Linux endpoint silently ships unconfined.
- **The libkrun supervisor carries a `BridgeFds → BridgeEndpoints` factory
  closure + a concurrent-thread-reaped-by-VMM-`exit()` dance** — which exists
  because libkrun's in-process VMM requires it (see "Why libkrun stays merged"
  under the decision). The two external-VMM sidecars carry neither.

The forcing observation: **the two external-VMM sidecars are interchangeable and
the libkrun supervisor is not.** Firecracker's VMM is an external binary and
vz's is the `mvm-vz-supervisor` process — both already use the split model
(external VMM + a thin bridge sidecar spawned by the backend), and their
sidecars differ only in endpoint variant + confinement. They fold into one
`mvm-bridge`. libkrun's VMM is an in-process library that creates the bridge fds
itself and `_exit()`s on guest shutdown, so it cannot be fed by the backend the
way an external VMM can; its merged supervisor stays. (The original proposal to
split libkrun too was abandoned on this constraint — see the decision.)

## Decision

Converge the **external-VMM backends (Firecracker, vz) on one shared
`mvm-bridge` sidecar binary**, and **keep libkrun's merged supervisor as-is**.

1. **Fold `mvm-firecracker-bridge` + `mvm-vz-drainer` into a single
   `mvm-bridge` binary.** It takes a unified `BridgeConfigJson` carrying an
   **endpoint-kind discriminant**, applies `mvm-jailer-lite` confinement
   through **one cfg-gated codepath** wherever the OS supports it (the Linux
   `Passt` endpoint; macOS `VzIngest` runs unconfined because macOS has no
   Landlock/seccomp — unchanged from today), verifies the passt hash on the
   passt endpoint only, builds the matching `BridgeEndpoints` variant, and calls
   the unchanged `spawn_bridge_thread`. The stdin contract — already identical
   in practice — is written and fuzzed once. The Firecracker backend
   (`mvm-backend::microvm::spawn_fc_bridge`) and the vz backend
   (`mvm-backend::vz`, `AttachedDrainerGuard`) spawn `mvm-bridge` with the RAII
   teardown guard + fd/path passing they already use.

2. **`mvm-libkrun-supervisor` keeps its merged in-process bridge.** The
   supervisor's `run_with_bridge` is unchanged: it calls
   `run_supervisor_with_bridge`, whose factory closure builds the bridge in the
   same process and `spawn_bridge_thread`s it.

### Why libkrun stays merged (constraint discovered during implementation)

The original proposal was to strip the bridge out of libkrun too and have the
backend spawn the sidecar, mirroring Firecracker. Implementation showed that is
not achievable without restructuring the C library, for two intrinsic reasons:

- **libkrun creates the bridge fds itself, inside the supervisor.**
  `run_supervisor_with_bridge` runs `configure_with_gateway_for_bridge` (which
  spawns passt/gvproxy and builds the socketpair *in the supervisor process*),
  then hands the `BridgeFds` to a factory closure, then `start_enter`s. Unlike
  Firecracker — where the *backend* creates the socketpair and passes fds to an
  external VMM — the fds do not exist until libkrun makes them, and only the
  supervisor holds them. The backend cannot create or pass them.
- **`krun_start_enter` calls `_exit()` on guest shutdown, skipping all Rust
  destructors.** That is the very reason the merged model exists (exit() reaps
  the bridge *thread* for free). Moving the bridge to a *process* means an
  `AttachedBridgeGuard` in the supervisor never runs, so the sidecar would leak;
  reaping would need per-platform `PR_SET_PDEATHSIG` (Linux) / `kqueue
  NOTE_EXIT` (macOS) self-termination glue.

Both are properties of **libkrun the VMM**, not our binding — confirmed against
an alternate binding (`msb_krun`), which documents the same `_exit()` behavior.
Running libkrun out-of-process to absorb the `exit()` is *exactly what the
per-VM supervisor already is*; the merged model is the architecture libkrun's
design implies, not a workaround. Forcing a split would add spawn + fd-passing +
per-platform reaping glue for no benefit libkrun doesn't already have.

The resulting per-VM topology:

```text
external-VMM backends            in-process VMM backend
[ firecracker | vz-supervisor ]  [ mvm-libkrun-supervisor ]
        +                              (merged: VMM + bridge
[ shared mvm-bridge sidecar ]           thread in one process)
```

Binaries still go from four (`mvm-libkrun-supervisor`, `mvm-vz-supervisor`,
`mvm-vz-drainer`, `mvm-firecracker-bridge`) to three (`mvm-libkrun-supervisor`,
`mvm-vz-supervisor`, `mvm-bridge`) — the reduction comes entirely from folding
the two external-VMM sidecars; the libkrun supervisor is untouched.

## Consequences

- **One bridge sidecar for the external-VMM backends.** FC + vz share a single
  binary with a single stdin parser; the `firecracker-bridge-fuzz` and
  supervisor-config fuzz surfaces converge. The libkrun in-process bridge keeps
  calling the same shared `spawn_bridge_thread` core, so the enforcement logic
  (claim 10/12/13) is still one implementation — `mvm-bridge` and the libkrun
  factory are two thin callers of it.
- **Confinement is one cfg-gated codepath in the sidecar, not per-bin
  open-coding.** Wherever the OS supports it (the Linux `Passt` endpoint) the
  sidecar applies `confine_self` uniformly. This does **not** newly confine the
  macOS `VzIngest` path — macOS has no Landlock/seccomp, so it runs unconfined
  exactly as the vz drainer did; the win is removing the duplication.
- **The merged-model concurrency stays only in libkrun, where it is the natural
  fit.** The FC/vz sidecars never had the factory-closure / thread-reaped-by-
  `exit()` shape; libkrun keeps it because its in-process VMM requires it.
- **No new process for libkrun.** libkrun keeps one process per VM (the merged
  supervisor); only FC + vz run the separate sidecar (which they already did).
- **Distribution simplifies for the external-VMM backends.** One shared
  `mvm-bridge` travels instead of two backend-specific sidecars; libkrun ships
  its supervisor as before.
- **`LibkrunGvproxy` endpoint reserved but unused.** The unified
  `BridgeConfigJson` carries a `LibkrunGvproxy` variant for completeness; no
  producer emits it while libkrun stays merged. Kept (and tested) so the
  contract is whole if libkrun is ever split upstream.

## Alternatives considered

- **Split libkrun too (the original proposal): thin krun launcher + a
  backend-spawned sidecar, mirroring Firecracker.** Rejected on an intrinsic
  libkrun constraint discovered in implementation (detailed under "Why libkrun
  stays merged"): libkrun creates the bridge fds *inside* the supervisor and
  `_exit()`s on guest shutdown, so the backend cannot feed it fds and a
  destructor-based sidecar reaper never runs. Achieving it would need a C-library
  restructure + per-platform `PDEATHSIG`/`kqueue` reaping glue for no benefit
  the merged model doesn't already provide. An alternate binding (`msb_krun`)
  was checked and documents the same `_exit()` behavior — it is a property of the
  VMM, not the binding.
- **Make Firecracker/vz adopt libkrun's merged model instead.** Rejected:
  impossible. FC's VMM is an external process; vz's is the objc2 supervisor.
  Neither can be linked in-process.
- **Leave the topology as-is; share only a library, not the binary.** A
  half-measure: it keeps two near-identical sidecar bins and two stdin parsers
  to fuzz. The duplication this ADR targets is precisely that per-binary
  plumbing, not the already-shared `spawn_bridge_thread` core.

Implementation is sequenced in Plan 211
(`specs/plans/211-vm-host-process-model-convergence.md`).
