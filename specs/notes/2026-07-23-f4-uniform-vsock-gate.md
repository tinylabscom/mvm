# F4 — machine-checked gate + raw-path retirement: design & scoping

**Context:** F3 merged (#1779) — `AnyBackend::Firecracker` and `::Libkrun` are now
`WorkloadRunner<Driver, RealEndpointSpawner, RealBrokerRegistrar>`. F4 lands the machine-checked
gate that locks that convergence in, and deletes the one now-dead raw-boot entry point. No backend
egress behavior changes, so **no live witness is needed** — F4 is a lint + a zero-caller deletion.

Reframed by scouting: F4 is smaller than plan 258 implied.

## Already done (no F4 work)
- `kind()` is already driver-dispatched (`WorkloadRunner::kind()` → `self.driver.kind()` → identity
  backend). Catalog rows already point Firecracker/libkrun at the runner constructors.

## Most "retire raw paths" can't happen — the fleet path holds them live
`run_from_build` / `run_from_prestarted_build` / `run_configured_firecracker` / FC
`egress_bridge.{spawn_egress_endpoint,install_egress_redirect}` / `egress_redirect.rs` stay — held
by the hostd-supervisor admitted-plan launcher (`mvm-hostd/src/supervisor/backend.rs`) + the FC
standby-claim helper. The `FirecrackerBackend`/`LibkrunBackend` structs + their non-`start`
`VmBackend` surface stay (driver identity delegates, catalog, standby, bench).

Genuinely deletable now: `AnyBackend::start_firecracker` (backend.rs — zero callers workspace-wide,
still drives the raw NIC/TAP path). `spawn_libkrun_egress_endpoint_if_needed` is dead on the CLI
path but only removable after `bench_probe` migrates off raw `LibkrunBackend::start` (deferred F4.2).

## The gate — `xtask check-uniform-vsock-egress` (grep-based, mirrors `check_vsock_only_egress`)
- **Assertion A — converged CLI workload variants ARE runners.** Assert the `backend.rs` aliases
  `FcRunner`/`LibkrunRunner` are `WorkloadRunner<_, RealEndpointSpawner, RealBrokerRegistrar>`, and
  the enum arms bind them (`Firecracker(FcRunner)`, `Libkrun(LibkrunRunner)`) — a revert to
  `Firecracker(FirecrackerBackend)` must trip the gate.
- **Assertion B — no egress-endpoint wiring on the workload CLI surface outside
  `RealEndpointSpawner`.** GUARD the driver files (`driver/*.rs`) and forbid the raw egress-spawn
  tokens (`spawn_substitution_endpoint`, `EndpointTransport::{Uds,Vsock}`, `spawn_egress_endpoint`,
  `install_egress_redirect`, `spawn_libkrun_egress_endpoint_if_needed`), whitelisting
  `workload_runner/runner.rs` (the one legal `RealEndpointSpawner`). Exempt the builder role, the
  hostd supervisor, the raw libkrun/FC paths, the endpoint definition/binary, and bench — they
  legitimately construct endpoints and are outside the converged CLI scope.

**The gate is incremental (a decision, owner-approved).** It cannot assert "every workload backend
is a runner": raw `AnyBackend::Hvf` is still the macOS-26 `auto_select` default (`HvfRunner` is
opt-in), and `Wasm` is `is_workload` but raw. So the gate locks Firecracker + libkrun and
**exempts raw Hvf + Wasm** — the exemption list is the remaining-convergence ledger. It shrinks to
zero when HVF converges in **F5** (which already scopes "HVF fail-closed on the endpoint" and needs
its own live HVF witness on the Mac). The gate's exemption of raw Hvf is removed there.

## Slices
- **F4.1** — the `check-uniform-vsock-egress` xtask lint (Assertions A+B, raw-Hvf/Wasm exemption
  documented in the lint) wired into the CI Lint job, plus deleting the dead
  `AnyBackend::start_firecracker`. Host-testable; the gate must PASS on the current tree and FAIL on
  a regression (demonstrate the deliberate failure).
- **F4.2 (deferred)** — migrate `bench_probe` off raw `LibkrunBackend::start`, then delete raw
  `LibkrunBackend::start` + `spawn_libkrun_egress_endpoint_if_needed`. Not required for the gate.

## Deferred (tracked from the F3 final review)
- Fold `AnyBackend::start_firecracker` deletion into F4.1 (done here).
- Detached-`-d` FC exit-capture asymmetry with libkrun's supervisor.
- Investigate the tail `EAGAIN frame-read` on a transient run whose exec'd command outlives the
  response (reviewed as benign).
- Correct the stale `doctor/warm_start.rs` prose about "Firecracker's live-memory path".
