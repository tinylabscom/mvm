# Plan 258 — Uniform vsock-egress convergence: remaining followups

**Status:** libkrun converged + live-witnessed; Firecracker and the machine-checked gate remain.

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
- Drivers: `HvfDriver`, `LibkrunDriver`. `FcDriver` is the gap.

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
- **HVF** already routes via `HvfDriver` (opt-in runner selector).
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

- [ ] **F2 — OCI+overlay+verity `/dev/vdb` device-ordering panic (raw libkrun
  path).** Raw `LibkrunBackend::start`'s verity disk layout points
  `mvm.data=/dev/vdb` at the verity *hash* sidecar, so `mvm-verity-init` panics
  (`ext4 superblock magic mismatch: expected 0xef53, got 0x0000`) before the
  agent. Pre-existing on `main`; the runner path already maps `/dev/vda`=rootfs
  correctly (proven live). Either fix the raw path's slot ordering or confirm
  raw `start` is unreachable once the enum no longer routes through it (a live
  benchmark still calls it — see F4).

- [ ] **F3 — `FcDriver`.** Converge Firecracker onto the runner, same pattern as
  `LibkrunDriver`: a `VmmSpec` → Firecracker driver, no guest NIC, egress via
  the endpoint. Retype `AnyBackend::Firecracker`. Reuse the vsock transport +
  no-NIC/token cmdline work already validated for the Firecracker Model-B egress
  path. Larger piece — suited to parallel subagents.

- [ ] **F4 — `check-uniform-vsock-egress` gate.** xtask lint asserting every
  workload backend IS a `WorkloadRunner<_, RealEndpointSpawner, _>` and no
  egress wiring exists outside `RealEndpointSpawner` (the gate is the claim; it
  fails until convergence completes). Land it green once F3 is in; add
  driver-dispatched `kind()` + catalog rows. Retire the raw per-backend egress
  wiring (libkrun `spawn_libkrun_egress_endpoint`, FC `egress_bridge`) and the
  raw `start` paths once nothing else calls them.

- [ ] **F5 — WS-NET endgame.** Once Firecracker egresses through the endpoint
  (Model B), delete the smoltcp-L3 stack (guest-netd + network-tunnel worker),
  and make HVF fail closed on the endpoint. This removes the second egress model
  entirely — one path off the guest, machine-checked by F4.

## Validation

A live-KVM egress witness per backend gates each merge — host tests do not boot
a guest, and the libkrun flip's 0-byte-console defect was invisible to every one
of them. The witness must observe: boot + reachable agent, no routable guest
NIC, the egress port pinned to `substitution-endpoint.sock`, and a default-deny
block of a real guest outbound attempt. The positive contrast (`--network-allow`
→ the fetch flows through the host endpoint) is an optional strengthener.
