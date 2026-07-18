# 14 — facade slice: pause / resume (instance snapshot)

**Status: DESIGN.** Builds on [13-mvm-client-facade.md](13-mvm-client-facade.md)
(scope boundary + contract-faithfulness rule). This is the third migration slice
and the first that grows the `MvmClient` trait with a genuinely rich subsystem.

## What `mvmctl pause` / `resume` do today (`crates/mvm-cli/src/commands/vm/pause.rs`, 462 lines)

**pause:**
1. Optional **primed barrier** — wait for the workload's `/run/mvm/primed` signal
   over vsock (`await_primed_barrier`); fails closed on timeout so no half-warmed
   snapshot is sealed. Skipped for `mock` (no guest agent).
2. `snapshot_io_for(hypervisor)` → `FirecrackerIO` (the running VM's live FC UDS
   socket) or, for `--hypervisor mock`, `CannedIO` (deterministic stub bytes) so
   the live-test audit path runs without a real FC socket.
3. `pause_and_seal(name, &io)` — quiesce, write `vmstate.bin`+`mem.bin` to
   `~/.mvm/instances/<vm>/snapshot/`, seal the epoch-bound HMAC envelope; returns a
   sidecar (`epoch`, `vmstate_len`, `mem_len`).
4. Write the `fc.paused` pid marker (FC keeps its pid alive across pause, so
   liveness alone can't tell paused from running).
5. Registry `set_paused(true)` + save.
6. `audit_emit!(WorkloadSleep, …)`; print the success line.

**resume:**
- `--warm`: `backend.warm_start(config, SnapshotCapability::LiveMemory)` — mint a
  fresh VMGenID, load+resume, reseed; **fails closed with a typed recovery hint**
  on a disk-only backend (libkrun). Clears `fc.paused`, registry `set_paused(false)`
  + `touch_last_active`, `audit_emit!(WorkloadWake)`.
- plain: `verify_and_resume(name, &io)` — **verifies the envelope, refusing replayed
  older snapshots (the security property)** — then clears `fc.paused`, registry
  `set_paused(false)` + `touch_last_active`, mints a generation token, sends the
  host-side **PostRestore** signal (guest maps it to SIGUSR1 → remount config/secret
  drives, restart services; skipped for `mock`), `audit_emit!(WorkloadWake)`.

## The facade boundary (the load-bearing decisions)

1. **`SnapshotIO` stays host-local, never on the trait.** `FirecrackerIO` wraps a
   live FC UDS socket; it cannot cross a REST boundary. So the new trait methods
   do NOT take a `SnapshotIO` — `LocalBackend` constructs the right one internally
   from its configured backend + the VM's live socket. The security-relevant call
   (`verify_and_resume`, which refuses replayed snapshots) stays exactly where it
   is inside the `instance_snapshot` module; the facade just calls it, preserving
   the property unchanged.

2. **`--hypervisor` maps onto `LocalBackend` construction, not a method arg.** The
   CLI flag today selects the snapshot transport (`mock` → `CannedIO`). In the
   facade model the client already carries a backend (`LocalBackend::new()` /
   `with_hypervisor(name)`). So `mvmctl pause --hypervisor mock` becomes
   `LocalBackend::with_hypervisor("mock")` + `pause_machine(...)`, and the impl
   picks `CannedIO` when its backend is the mock, `FirecrackerIO` otherwise. The
   test affordance (hermetic `WorkloadSleep`/`WorkloadWake` coverage) is preserved
   without a transport arg on the contract.

3. **Trait growth (REST-satisfiable opts + outcome):**
   ```
   async fn pause_machine(&self, id: &MachineId, opts: PauseOpts) -> Result<PauseOutcome>;
   async fn resume_machine(&self, id: &MachineId, opts: ResumeOpts) -> Result<()>;

   struct PauseOpts   { primed_barrier: bool, primed_timeout_secs: u64 }   // serde, defaults
   struct PauseOutcome{ epoch: u64, vmstate_len: u64, mem_len: u64 }        // for the CLI line + audit
   struct ResumeOpts  { warm: bool }
   ```
   All plain serde data — a remote `GatewayBackend` can carry them over REST. No
   `SnapshotIO`, no host paths, no `VmStatus` in a signature.

4. **Every one of the four `MvmClient` impls grows** (compiler-caught):
   - `LocalBackend` — the real implementation: primed-barrier, `snapshot_io_for`
     (from `self.backend`), `pause_and_seal` / `verify_and_resume`, the `fc.paused`
     marker, registry `set_paused` + `touch_last_active`, the warm-start dispatch,
     the VMGenID mint + PostRestore signal. All the `mvm_runtime::{vm::instance_snapshot,
     microvm, vm::name_registry, backend}` reaches move DOWN here.
   - `MockBackend` (`mvm-core::client::mock`) — a minimal in-memory paused-flag
     honoring the same `Result` contract, for pure trait-level unit tests.
   - `GatewayBackend` (remote) — v1 fail-closed typed error (`MvmError::Backend`),
     exactly as `exec_machine`/`create_machine` are stubbed there today; wire a real
     REST call only when a fleet consumer needs remote pause/resume. Note it in the
     method doc.
   - `SubprocessBackend` (`mvm-sdk::facade`) — same v1 fail-closed stub.

5. **Stays in the CLI (`pause.rs`), the cross-cutting wrappers (the `down` pattern):**
   the `audit_emit!(WorkloadSleep/WorkloadWake, …)` calls and the success `println!`.
   `pause.rs` becomes: validate name → build `LocalBackend` (from `--hypervisor`) →
   `pause_machine`/`resume_machine` → render outcome + audit. No `mvm_runtime::`
   imports remain in `pause.rs`.

## Behavior preservation (trace-only — there are live-VM tests but no host-free golden)

- Same audit entries + payload fields (`WorkloadSleep` epoch/vmstate/mem;
  `WorkloadWake`).
- **Snapshot-replay refusal preserved** — `verify_and_resume` is called unchanged;
  a re-review must confirm the epoch/HMAC verification still gates every resume.
- `--warm` still fails closed with the typed `WarmStartError::Unsupported` hint on
  a disk-only backend; plain resume still sends PostRestore (skipped for mock);
  primed-barrier still fails closed on timeout.
- The `mock` (`CannedIO`) hermetic path still works — via `with_hypervisor("mock")`.
- `fc.paused` marker + registry `set_paused`/`touch_last_active` semantics identical,
  just relocated into `LocalBackend`.

## Risks / watch-items for the implementer + reviewer

- Do NOT let `SnapshotIO`, `Box<dyn SnapshotIO>`, FC sockets, or `mvm_runtime` types
  appear in any trait signature — that would break the REST-satisfiability invariant
  and the whole point of the boundary.
- The live-VM snapshot tests (`vm/pause.rs` `#[cfg(test)]` + any live lane) must stay
  green; the `mock`/`CannedIO` path is the hermetic coverage — keep it exercised.
- Trait growth touches all four impls; the two remote/subprocess stubs must be
  fail-closed typed errors, not `todo!()`/`unimplemented!()` (banned) or silent Ok.
- This is a bigger diff than slices 1–2; commit in two parts (trait+DTOs+impls, then
  the `pause.rs` swap) and run the full gate.

## Not in this slice

Snapshot **list/delete** subcommands (`list_instance_snapshots`/`delete_instance_snapshot`
reaches in `pause.rs`) — if they are separate verbs, migrate them in a follow-up
(a `list_snapshots`/`delete_snapshot` facade method or leave them as a snapshot-store
surface). Scope this slice to `pause` + `resume` only.
