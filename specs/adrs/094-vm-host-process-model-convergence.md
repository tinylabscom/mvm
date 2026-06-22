# ADR-094 — Converge per-VM host processes on the split VMM + shared bridge sidecar model

**Status:** Proposed
**Amends:** [ADR-002](002-microvm-security-posture.md) (per-backend tier matrix — the per-VM host-process topology becomes uniform across workload backends) and [ADR-083](083-workload-backend-type-bar.md) (the shared egress/audit funnel gains a single, shared transport process instead of three near-identical ones).
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
- **The libkrun supervisor carries the trickiest code in the tree** — the
  `BridgeFds → BridgeEndpoints` factory closure and the
  concurrent-thread-reaped-by-VMM-`exit()` dance — which exists *only* because
  libkrun *can* host the bridge in-process, not because it must.

The forcing observation: **the split model is the only model achievable for
every backend.** Firecracker's VMM is an external binary that cannot be linked
in-process; vz's VMM is the `mvm-vz-supervisor` process. Neither can ever adopt
the merged model. libkrun merged only because it is a library — and the
`exit()`-reaps-the-thread convenience it buys is exactly what the split model
already replaces with an explicit `AttachedBridgeGuard`. So there is one common
denominator, and it is *split*.

## Decision

Converge all workload backends on the **split model with one shared bridge
sidecar binary**. Two moves:

1. **Fold `mvm-firecracker-bridge` + `mvm-vz-drainer` into a single
   `mvm-bridge` binary.** It takes a unified `BridgeConfigJson` carrying an
   **endpoint-kind discriminant**, applies `mvm-jailer-lite` confinement
   through **one cfg-gated codepath** wherever the OS supports it (the Linux
   `Passt` endpoint; macOS `VzIngest`/`LibkrunGvproxy` run unconfined because
   macOS has no Landlock/seccomp — unchanged from today), verifies the passt
   hash on the passt endpoint only, builds the matching `BridgeEndpoints`
   variant, and calls the unchanged `spawn_bridge_thread`. The stdin contract —
   already identical in practice — is written and fuzzed once.

2. **Strip the bridge out of `mvm-libkrun-supervisor`.** The supervisor
   becomes a **thin krun launcher** (parse config → build `KrunContext` →
   `krun_start_enter`); `run_legacy`/`run_with_bridge` collapse into one path.
   The libkrun *backend* (`mvm-backend::libkrun::start`) spawns the shared
   `mvm-bridge` sidecar alongside it with an `AttachedBridgeGuard` and
   socketpair fd-inheritance — byte-for-byte the pattern `spawn_fc_bridge`
   already uses.

The resulting per-VM topology is uniform across every workload backend:

```text
[ thin VMM launcher ]   +   [ shared mvm-bridge sidecar ]
  krun-launch / firecracker / vz        one binary, one stdin contract,
                                        one (cfg-gated) confinement path
```

Binaries go from four (`mvm-libkrun-supervisor`, `mvm-vz-supervisor`,
`mvm-vz-drainer`, `mvm-firecracker-bridge`) to three
(`mvm-libkrun-supervisor` — much thinner, `mvm-vz-supervisor`, `mvm-bridge`).

## Consequences

- **One enforcement transport to harden, fuzz, and audit.** The egress/audit
  bridge sidecar is a single binary with a single stdin parser; the
  `firecracker-bridge-fuzz` and the supervisor-config fuzz surfaces converge.
  Claim 10/12/13 enforcement is exercised through one code path, not three.
- **Confinement becomes one cfg-gated codepath, not per-bin open-coding.**
  Wherever the OS supports it (the Linux `Passt` endpoint) the single sidecar
  applies `confine_self` uniformly, so a future Linux endpoint can't silently
  ship unconfined. This does **not** newly confine the macOS paths (vz /
  libkrun-on-macOS) — macOS has no Landlock/seccomp, so `confine_self` is a
  hard-erroring stub there and those paths run unconfined exactly as today; the
  win is removing the duplication, not adding a macOS sandbox.
- **The trickiest concurrency code is deleted.** No more factory closure, no
  more thread-reaped-by-`exit()`; teardown is the explicit, uniform
  `AttachedBridgeGuard` fail-closed kill that FC/vz already use.
- **+1 small process per libkrun/vz VM.** The bridge becomes its own process
  instead of an in-supervisor thread. Measured cost is a few MB RSS, flat
  regardless of guest `--memory` (per-VM footprint is dominated by guest RAM);
  it is the same process count FC already pays. Net memory at fleet density is
  unchanged in practice.
- **fd-passing is the real migration work** (see Plan 211). The gateway fds
  the libkrun supervisor sets up in-process must be handed to the sidecar via a
  socketpair — exactly the `gateway_fd_raw` / `supervisor_fd_raw` inheritance
  the FC path already encodes.
- **Distribution simplifies.** The packaging gap tracked elsewhere (shipping
  per-VM host binaries adjacent to `mvmctl`) shrinks: one shared `mvm-bridge`
  travels for all backends instead of two backend-specific sidecars.

## Alternatives considered

- **Make Firecracker/vz adopt the merged model.** Rejected: impossible. FC's
  VMM is an external process; vz's is the Swift/objc2 supervisor. Neither can
  be linked in-process, so the merged model cannot be a common denominator.
- **Leave the topology as-is; share only a library, not the binary.** A
  half-measure: it keeps two sidecar bins, two stdin parsers to fuzz, the
  vz confinement gap, and the libkrun merged-path concurrency. The duplication
  this ADR targets is precisely the per-binary plumbing, not the already-shared
  `spawn_bridge_thread` core.
- **Keep `mvm-libkrun-supervisor` merged; only fold the two sidecars.**
  Captures the smaller win but leaves libkrun as a permanent outlier with the
  riskiest code and a non-uniform teardown story. Deferred-rejected: the
  thin-launcher split is the larger and more durable simplification, and it is
  what makes the topology genuinely uniform.

Implementation is sequenced in Plan 211
(`specs/plans/211-vm-host-process-model-convergence.md`).
