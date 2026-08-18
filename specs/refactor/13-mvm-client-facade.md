# 13 — mvm-client facade migration (WS1h/1i)

**Status: DESIGN (scoping) — execution incremental, slice by slice.**

## Reality at the start

`mvm-client` already exists as a real facade: the `MvmClient` async trait (the
contract lives in `mvm-core::client` so `mvm-client` + `mvm-sdk` share it without
a cycle), an in-process `LocalBackend`, the `connect(Target)` selector, and a
`MockBackend`. Today the trait carries **9 machine-lifecycle methods**:
`list_machines`, `inspect_machine`, `create_machine`, `run_machine`,
`start_machine`, `stop_machine`, `remove_machine`, `machine_logs`,
`exec_machine`, `reconfigure_machine`.

But `mvm-cli` uses `mvm_client::` in **zero** files. Instead it reaches directly
into lower crates: `mvm_runtime::` across **59 files**, `mvm_hostd::` across 24,
`mvm_build::` across 36. The facade is built but unused — 1i never happened.

The `mvm_runtime::` reach, by submodule (call-site count):

| Surface | count | Verdict |
|---|---|---|
| `vm` (name_registry, runtime_meta, reconcile, template, overlay, instance_snapshot) | 91 | **behind facade** — machine lifecycle |
| `backend` (AnyBackend dispatch) | 24 | **behind facade** — dispatch is `LocalBackend`'s job |
| `microvm`, `vsock_transport`, `checkpoint`, `standby_pool` | 45 | **behind facade** — lifecycle internals |
| `ui` (Spinner, prompts) | 21 | **stays direct** — presentation, not a runtime op |
| `shell`, `shell_mock`, `base` (runtime_meta substrate, cow) | 19 | **stays direct** — the `ShellEnvironment` substrate re-exported as `mvmctl::runtime::*` |
| `image`, `catalog`, `artifacts`, `codesign`, `builder_runner`, `qemu`, `firecracker`, `storage`, `config` | ~40 | **out of 1i scope** — image/build/artifact concerns (mvm-build/OCI surface), not "drive a sandbox" |

## Inherited scope

The run-first CLI plan asked that its consolidated `RunArgs` be able to drive
`MvmClient::run_machine`. That is this refactor's work, not that plan's:
`run_machine` has three impls and zero non-test callers, so wiring one verb
through it in isolation would add a caller to an otherwise unused facade
without moving the 59-file reach that is the actual problem. Do it as part of
the machine-lifecycle slice, where the argument struct and the facade method
land together.

## The scope boundary (the load-bearing decision)

`MvmClient` covers **runtime machine-lifecycle operations only** — "drive a
sandbox": create/run/start/stop/pause/remove/checkpoint/inspect/logs/exec. It is
the surface a *user* (or a remote fleet, via `GatewayBackend`) touches.

Explicitly **not** behind the facade, and legitimately called directly by the CLI:

- **Presentation** — `mvm_runtime::ui` (spinners, prompts). The client returns
  data; the CLI renders it. A facade that owns terminal output is wrong.
- **Host substrate** — `shell`/`shell_mock`/`base` (the `ShellEnvironment` +
  `runtime_meta` re-exported as the `mvmctl::runtime::*` contract mvmd also
  consumes). This is infrastructure the `LocalBackend` is built *on*, not a
  client operation.
- **Build/image tooling** — `mvm-build` (nix, builder VM), `image`/`catalog`/
  `artifacts`/`codesign` (the OCI + local-image surface). These are
  contributor/authoring operations, not runtime drive-a-sandbox operations. If a
  facade is wanted for them later it is a *separate* `build`/`image` surface, not
  this one. Out of 1h/1i.
- **Daemon internals** — `mvm-hostd` (supervisor, broker, audit signer). A host
  daemon role, never a client op.

This keeps `MvmClient` lean and honest: it is the runtime-drive contract, and the
`remote` feature's `GatewayBackend` must be able to satisfy every method over
REST (so nothing host-local-only, like a raw `ShellEnvironment` handle, may leak
into a signature).

## Trait growth needed

The 9 current methods cover create/run/start/stop/remove/logs/exec/inspect/
reconfigure. The vm-lifecycle commands the CLI still drives directly need three
additions, each a clean request/response lifecycle op:

- `pause_machine(&id)` / `resume_machine(&id)` — `vm/pause.rs` reaches
  `vm::name_registry` + `vm::instance_snapshot` today.
- `checkpoint_machine(&id, CheckpointOpts)` / `restore_machine(spec, from)` —
  `vm/checkpoint.rs` + `checkpoint::CheckpointStore`.

Deliberately **left CLI-direct** (do not force into the trait):

- **console** (interactive PTY-over-vsock, dev-only, claim 15) — an interactive
  bidirectional stream, not a request/response op; it stays a CLI-direct
  `vsock_transport` path. Forcing it through an async trait method would distort
  the contract and cannot be satisfied by `GatewayBackend` anyway.
- **standby_pool** warm-VM plumbing — an optimization internal to `LocalBackend`,
  not a user-facing verb; it moves *inside* `LocalBackend`, not onto the trait.

## Migration sequence (each slice is an independent, reviewable task)

Ordered lowest-risk-first; every slice ends green (`nextest --workspace` + clippy
+ fmt) and deletes the direct `mvm_runtime::vm::*`/`backend::*` reaches it
replaces.

1. **Read-only queries** — `ps`/list and the `inspect`-shaped reads route through
   `LocalBackend::list_machines`/`inspect_machine`. Proves `LocalBackend` already
   surfaces what the name_registry/runtime_meta reads need (grow the returned DTO
   if not). No state mutation → safest first cut.
2. **Simple lifecycle** — `down`/`stop`, `remove` route through
   `stop_machine`/`remove_machine`.
3. **pause/resume** — add the two trait methods + `LocalBackend` impl; migrate
   `vm/pause.rs`.
4. **checkpoint/restore** — add the two trait methods + impl; migrate
   `vm/checkpoint.rs` (the heaviest slice).
5. **create/run/up** — `up`/`run` route through `create_machine`/`run_machine`
   (these already exist on the trait; the CLI just doesn't call them).
6. **Sweep + optional gate** — once the vm command group is migrated, consider a
   `check-cli-runtime-surface` lint that forbids `mvm_runtime::{vm,backend,
   microvm,vsock_transport,checkpoint}` in `mvm-cli` (allowlisting the substrate
   `ui`/`shell`/`base` + the out-of-scope image/build modules). Defer until the
   migration proves the boundary; a lint written first would be all-allowlist.

## Contract-faithfulness rule (resolved during slice 1)

Routing the CLI through the facade means the CLI renders **contract types**
(`MachineState`/`MachineStatus`), not internal runtime types (`VmInfo`/`VmStatus`).
Slice 1 surfaced that `mvmctl ps` currently leaks the internal `VmStatus` into its
`--json` and table output. The rule for the whole migration:

- **The client contract must be faithful, not lossy.** Where the contract
  under-models a real state the CLI needs, ENRICH the contract (it must stay
  REST-satisfiable — plain serde data, no internal-type leak), rather than either
  accepting information loss or leaking the internal type into the DTO. Concretely
  for status: `MachineStatus` gains a `Paused` unit variant (today it folds
  `Paused → Stopped`, which makes a paused VM vanish from the default `ps` table —
  a real functional regression that enrichment fixes). The failure *reason* rides
  as an optional `MachineState` field (e.g. `status_detail: Option<String>`), so
  `MachineStatus::Failed` stays a simple unit variant and `MachineFilter` equality
  stays clean.
- **The visible table/output a human reads is preserved.** Adding `Paused` keeps
  paused VMs in the non-`Stopped` retain; the failure detail keeps the reason on
  screen. No human-visible regression.
- **CLI machine-readable surfaces (`--json`) deliberately shift from the internal
  representation to the contract representation.** This is the *point* of the
  migration (the CLI/SDK speak the stable contract, not runtime internals) and is
  acceptable under the project's pre-1.0 / no-backcompat policy. Verify no in-repo
  consumer depends on the old bytes before landing each slice (for `ps --json`:
  confirmed none — the in-repo SDKs do not parse it). Note the shift in the slice's
  commit + report; if a slice's `--json` change WOULD break an in-repo consumer,
  that consumer moves to the contract type in the same slice.
- Adding a `MachineStatus` variant ripples to every exhaustive match (compiler-
  caught, ~bounded) and to the separate mvmd repo's copy of the contract — expected
  and handled under no-backcompat; the in-repo matches are fixed in the slice.

## Sequence correction (learned executing slices 1–2)

Slices 1 (`ps`) and 2 (`down`) are landed + reviewed. Reconnoitring the rest showed
the original "simple lifecycle" framing was too optimistic — the remaining
commands are NOT mechanical repeats, and each is its own design pass:

- **`pause`/`resume`** (`vm/pause.rs`, 462 lines) is a full instance-snapshot
  subsystem, not a state toggle: `pause_and_seal`/`verify_and_resume`, a
  `SnapshotIO` abstraction with per-hypervisor + mock `CannedIO` transports,
  snapshot-envelope **replay refusal** (a security property), warm-start via
  `VmBackend::warm_start`, and snapshot list/delete subcommands. Growing the trait
  with `pause_machine`/`resume_machine` means deciding what of that machinery is
  the contract vs stays host-local, and implementing/​stubbing it across all four
  `MvmClient` impls (`MockBackend`, `GatewayBackend`, `LocalBackend`,
  `SubprocessBackend`). Its own design + brief.
- **`checkpoint`** (18 reaches) — same shape, the checkpoint-store path.
- **`up`/`run`** (8 reaches) — the admission+boot path; `run_machine`/`create_machine`
  exist on the trait but the CLI's `up` does far more (image resolution, network,
  overlay, readiness) that must be reconciled with the facade boundary.
- **`logs`/`wait`** are streaming (`--follow`, vsock readiness waits) — like
  `console`, they do not fit the request/response trait and likely stay CLI-direct
  or need a streaming seam.
- **`set_ttl`/`readiness`** are name-registry mutations — candidates for
  `reconfigure_machine` or a small registry-facing method.

Do each as its own designed slice; do not batch or blind-dispatch. The trait
grows per slice and every impl must be updated (compiler-caught).

## Full remaining boundary (categorized worklist — done after slices 1–3)

Slices 1–3 (`ps`, `down`, `pause`/`resume`) route the first machine-lifecycle
verbs. A full sweep of mvm-cli's remaining `mvm_runtime::` reaches shows the rest
splits into five categories. Only the first is migration work; the other four are
legitimately-direct and become the eventual `check-cli-runtime-surface` lint's
allowlist.

**A. Facade-lifecycle (still to migrate — reach `vm::name_registry` / `AnyBackend`
dispatch for a drive-a-machine op):**
- `up`/`run` (`vm/up.rs`, ~4100 lines) — the boot path. `run_machine`/`create_machine`
  exist on the trait, but `up` layers image-resolve + network + overlay + readiness
  on top; its own decomposition (likely: keep the CLI prep, route the final
  admit+boot through `run_machine`). The single biggest command — its own design.
- `set_ttl` (`vm/set_ttl.rs`, 75 lines) — a name-registry `expires_at` mutation
  (the reaper's TTL). Small; a dedicated `set_ttl(id, Option<expires_at>)` facade
  method. Clean next slice.
- `sandbox` (`vm/sandbox.rs`) — registers/drives a sandbox; registry-backed.
- the **`machine` command group** (`commands/machine/{runtime,spec_ops,mod}.rs`) —
  a parallel VM abstraction that also loads the name registry directly; its own
  slice(s).
- `console`'s registry bookkeeping (the *interactive stream* stays direct — see C —
  but its `VmNameRegistry` reads/writes are lifecycle state).
- the `readiness.rs` helper (`record_readiness`) — the shared milestone writer used
  by up/down; folds behind the facade with the verbs that call it.

**B. Store surfaces (stay DIRECT — not "drive a running sandbox"):** `checkpoint`
(`vm/checkpoint.rs`, 2034 lines — create/ls/rm/fork/restore/diff over
`~/.mvm/checkpoints` + CoW rootfs) and `snapshot` (`vm/snapshot.rs`, already split
out in slice 3). These manage host-local artifact stores, exactly parallel to the
snapshot ls/rm the migration already left direct. A remote fleet does not
checkpoint through the machine-drive client. **Decision: checkpoint is not a facade
slice** — its `mvm_runtime::checkpoint` reach is legitimate; keep it in its own
well-bounded module.

**C. Streaming / interactive (stay DIRECT — do not fit request/response):**
`console` (PTY-over-vsock), `wait` (vsock readiness poll), `exec`/`proc` (exec-over-
vsock), `forward` (port forward), `fs`/`invoke` — all bidirectional or streaming
vsock transports, like `logs --follow`. A streaming seam could be added later; not
this migration.

**D. Image / build (stay DIRECT — out of the machine-drive scope, a separate
surface):** `mvm_runtime::{image,catalog,artifacts}` + `mvm-build` reaches in
`image`, `artifact`, `build/*`, `diff`. Contributor/authoring, not runtime drive.

**E. Substrate (stay DIRECT — the facade is built ON these):** `mvm_runtime::{ui,
base::{shell,shell_mock,runtime_meta,cow}}` in `ui.rs`, `doctor.rs`, `exec.rs`, etc.
Presentation + the `ShellEnvironment` re-export contract.

The migration is therefore larger than 3–4 slices: category A alone is `up`
(major) + `set_ttl` + `sandbox` + the `machine` group + console/readiness registry
bits. Each is its own designed slice. The `check-cli-runtime-surface` lint lands
LAST — once category A is drained — forbidding `mvm_runtime::vm::name_registry` and
`AnyBackend` dispatch in mvm-cli while allowlisting B–E.

## Non-goals / invariants

- The `mvmctl::runtime::*` re-export contract mvmd depends on is unchanged — this
  moves *mvm-cli's* call sites, not the runtime crate's surface.
- `GatewayBackend` (remote) parity: any method added to the trait must be
  REST-satisfiable; no host-local handle types in signatures.
- No behavior change per slice — same verbs, same output; the diff is which layer
  the command calls. Golden CLI tests in `tests/cli.rs` must stay green unchanged.

## First slice — concrete

`crates/mvm-cli/src/commands/vm/ps.rs` (+ any shared list helper) stops importing
`mvm_runtime::vm::name_registry` and instead constructs a `LocalBackend`
(via `mvm_client::connect(Target::Local)` or `LocalBackend::new(...)`) and calls
`list_machines(MachineFilter)`. If `MachineState` lacks a field `ps` prints
(pid, uptime, backend kind), add it to the DTO in `mvm-core::client::dto` and
populate it in `LocalBackend::list_machines`. This is the pattern every later
slice repeats.
