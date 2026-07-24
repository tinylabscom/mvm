# Plan 258 — Uniform vsock-egress convergence: remaining followups

**Status:** COMPLETE for the microVM workload backends; F5.2 removed the dead Model-A
smoltcp-L3 stack after Firecracker, libkrun, and HVF converged on the runner seam.

**Goal:** every workload backend runs through the one
`WorkloadRunner<VmmDriver, EndpointSpawner, BrokerRegistrar>` seam, so claim-10
(default-deny egress) and claims 12/13 (secret substitution) are enforced in a
single place every backend must traverse — structural, not per-backend
convention that drifts. A `VmmDriver` exposes only boot/attach + vsock, no NIC
surface, so "no routable guest NIC" is a property of the type, not a habit.

## Seam (already in `crates/mvm-runtime/src/`)

- `driver/traits.rs` — `VmmDriver` (name/capabilities/boot/attach) +
  `RunningVm::vsock_connect`. No NIC surface.
- `workload_runner/runner.rs` — `WorkloadRunner<D,S,B>` (impls `VmBackend` +
  `WorkloadBackend`): the one egress endpoint (`RealEndpointSpawner`, Uds →
  `substitution-endpoint.sock`), the broker (`RealBrokerRegistrar`, claims
  12/13), the shared kernel cmdline, and the admission gates (overlay contract +
  runtime_meta) lifted so every driver behind it inherits them.
- Drivers: `HvfDriver`, `LibkrunDriver`, and `FcDriver`.

## Done

- **libkrun — merged (#1766).** `AnyBackend::Libkrun` retyped onto
  `WorkloadRunner<LibkrunDriver, RealEndpointSpawner, RealBrokerRegistrar>` —
  libkrun's sole production path (`--hypervisor libkrun` and `auto_select`).
  The verity cmdline base now routes through the driver seam (`console=hvc0`,
  not the hardcoded HVF pl011 UART that silently 0-byte-booted libkrun guests);
  the driver reuses the shared host kernel-prep (`libkrun_kernel_for_host` +
  `with_kernel_format`) instead of forking it. BDD verified-boot contracts
  landed on `bdd/uniform-vsock-egress`.
  - **Live Linux/KVM egress witness — PASS** (Hetzner box, native x86_64,
    `/dev/kvm`): boots, agent reachable (`listening on vsock port 5252`), no
    routable NIC (`SIOCGIFFLAGS eth0: No such device`), egress endpoint spawned
    with the guest egress port pinned to `substitution-endpoint.sock` (not the
    derived path), and default-deny blocks a guest outbound fetch.
- **HVF** routes via `HvfDriver`.
- Runner enrichment landed ahead of the flip: backend-metadata dispatch, shared
  cmdline, broker/claims-12/13 lift, user volumes.

## Followups

- [ ] **F1 — transient `machine run --hypervisor X` silently ignored.**
  `MachineRunArgs::into_run_args()` builds a `RunArgs` with no `hypervisor`
  field, so a transient run drops the flag and takes the default backend; only
  the persistent `-d` form and `MVM_HYPERVISOR` honor it. Thread `--hypervisor`
  through the transient path, or reject it when it cannot be honored. Confirmed
  live on the Hetzner box (nonsense backend names produced identical output;
  `--hypervisor libkrun` ran Firecracker).

- [x] **F2 — OCI+overlay+verity `/dev/vdb` device-ordering panic (raw libkrun
  path) — DORMANT, folds into F4.** Raw `LibkrunBackend::start`'s verity disk
  layout points `mvm.data=/dev/vdb` at the verity *hash* sidecar, so
  `mvm-verity-init` panicked (`ext4 superblock magic mismatch`) before the agent
  on pre-flip `main`. Post-flip this branch is **unreachable**: no production
  path constructs raw `LibkrunBackend` (the `AnyBackend::Libkrun` enum is the
  runner, which maps `/dev/vda`=rootfs correctly — proven live); the sole
  remaining caller of raw `start` is the `bench_probe` benchmark, whose
  `VmStartConfig` sets no `verity_path`/`roothash`, so `libkrun_verity_enabled`
  is false and it never takes the verity branch. No fix warranted — the buggy
  branch is removed with raw `start` in F4.

- [x] **F3 — `FcDriver`.** Converge Firecracker onto the runner, same pattern as
  `LibkrunDriver`: a `VmmSpec` → Firecracker driver, no guest NIC, egress via
  the endpoint. Retype `AnyBackend::Firecracker`. Reuse the vsock transport +
  no-NIC/token cmdline work already validated for the Firecracker Model-B egress
  path. Larger piece — suited to parallel subagents.

- [x] **F4 — `check-uniform-vsock-egress` gate.** xtask lint asserting every
  workload backend IS a `WorkloadRunner<_, RealEndpointSpawner, _>` and no
  egress wiring exists outside `RealEndpointSpawner` (the gate is the claim; it
  fails until convergence completes). Land it green once F3 is in; add
  driver-dispatched `kind()` + catalog rows. Retire the raw per-backend egress
  wiring (libkrun `spawn_libkrun_egress_endpoint`, FC `egress_bridge`) and the
  raw `start` paths once nothing else calls them.

- [x] **F5 — WS-NET endgame.** Once Firecracker egresses through the endpoint
  (Model B), delete the smoltcp-L3 stack (guest-netd + network-tunnel worker),
  and make HVF fail closed on the endpoint. This removes the second egress model
  entirely — one path off the guest, machine-checked by F4.

## Tracked follow-ups

- **Firecracker raw-launch cleanup:** the old direct flake, lifecycle, standby,
  and snapshot entry points were still able to describe or restore TAP-backed
  guests even though normal workload selection had moved to the runner. They
  now fail closed, and the runtime bridge/TAP provider, NIC configuration,
  network image setup, and raw Firecracker workload claim are removed. The
  runner-backed path is the only Firecracker workload launch path.
- **NIC-less OCI loopback / forward-proxy gap:** `mvm-oci-init` currently brings
  up guest `lo` only when `mvm.vsock_egress=1`. A default-deny OCI boot can
  therefore leave `127.0.0.1:18080` unavailable to the substitution forward
  proxy. Make OCI init bring up loopback unconditionally; this is backend-
  agnostic and outside F5.2.
- **F4.2 raw libkrun cleanup:** migrate `bench_probe` off raw
  `LibkrunBackend::start`, then delete that raw entry point and
  `spawn_libkrun_egress_endpoint_if_needed`.

The F5.2 light default-deny witness passed on 2026-07-24 UTC for local HVF
and native-KVM Firecracker/libkrun. Each guest exposed only `lo`, failed DNS
resolution for `example.com`, and printed `EXIT=1`.

## Validation

A live-KVM egress witness per backend gates each merge — host tests do not boot
a guest, and the libkrun flip's 0-byte-console defect was invisible to every one
of them. The witness must observe: boot + reachable agent, no routable guest
NIC, the egress port pinned to `substitution-endpoint.sock`, and a default-deny
block of a real guest outbound attempt. The positive contrast (`--network-allow`
→ the fetch flows through the host endpoint) is an optional strengthener.
