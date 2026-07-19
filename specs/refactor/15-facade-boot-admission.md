# 15 — facade slice: the machine-boot / admission path (`up`/`run`, the machine group)

**Status: DESIGN. Implementation GATED on a working test environment** (see the
"Why this one must be test-verified" section) — this touches the claim-8 signed
ExecutionPlan admission gate, and a green `nextest` on the admission suite is a
hard precondition to landing it. It must not be landed on clippy-only verification
the way the small, test-free slices (`set_ttl`) were.

Builds on [13-mvm-client-facade.md](13-mvm-client-facade.md) (scope boundary +
category A worklist) and [14-facade-pause-resume.md](14-facade-pause-resume.md)
(the facade-owns-the-op / CLI-keeps-the-wrappers pattern).

## What this covers

The largest remaining category-A surface: the CLI-side admission + boot
orchestration. Despite its name, `crates/mvm-cli/src/commands/vm/up.rs` (4107 lines)
is **not** a thin `up` command — its own header calls it the "admission and boot
helpers consumed by `machine/mod.rs`": `untrusted_transient_admit`,
`admit_plan_for_boot`/`AdmitPlanForBootParams`, `start_persistent_oci_machine`,
`resolve_workload_kernel`, `resolve_kernel_pin_path`, `load_workload_ir`,
`emit_launched_if`/`emit_failed_if`. It is the CLI's claim-8 path: synthesize +
sign + admit a typed `ExecutionPlan`, then boot. The `machine` command group
(`commands/machine/{runtime,spec_ops,mod}.rs`) consumes it and also reads the name
registry directly.

Its few `mvm_runtime::` reaches (`AnyBackend`, `image`, `microvm::probe_verity_sidecar`,
`vm::name_registry` register, `workload_backend::require_workload_backend`) are the
boot path's runtime touches; the bulk of the 4107 lines is admission logic over
`mvm-core`/`mvm-hostd`.

## The primitive already exists

`LocalBackend::run_machine(MachineSpec)` (`crates/mvm-client/src/local.rs`) already
performs an admission-preserving boot: it resolves the rootfs + verity sidecars +
(HVF) workload kernel, builds a `LocalRunRequest`, and calls
`mvm_hostd::run::admit_and_boot_local(...)` under a fresh `InMemoryNonceLedger` +
`SystemClock` + the host signer at `~/.mvm/keys/`. That is the SAME signed-plan
admission gate (claim 8) `mvm_hostd::run` provides — and the crate's own module doc
states the invariant plainly: *"A workload never boots on a path that skipped
admission."* So the facade boot primitive is real; this slice reconciles the CLI's
richer path with it.

## The reconciliation (the design problem)

`run_machine` today is the LEANER local run (rootfs image → admit → boot). `up.rs`
is RICHER: transient vs. persistent lifecycle, OCI persistent machines, kernel-pin
resolution, Workload-IR load, the launched/failed audit emits, name-registry
registration with metadata. The slice must route the machine-boot commands through
the facade WITHOUT either (a) weakening admission or (b) duplicating a second
admission path.

Two candidate shapes (decide at implementation, with the admission tests as the
arbiter):

1. **Thin `run_machine`, rich CLI prep (preferred).** Keep the CLI-side prep that is
   genuinely presentation/authoring (kernel-pin flags, IR load from a flake, the
   transient-vs-persistent decision, the audit emits, name-registry registration) in
   the CLI, and have it converge on a `MachineSpec` + `run_machine`/`create_machine`
   for the actual admit+boot. The registry `register_with_metadata` reach moves into
   the facade (like `stop_machine`'s deregister did). This keeps ONE admission gate
   (`admit_and_boot_local`) and matches the `down`/`pause` pattern (facade owns the
   op, CLI keeps the wrappers).
2. **Grow the spec.** If `run_machine`'s `MachineSpec`/`LocalRunRequest` cannot carry
   what the CLI boot needs (kernel pin, IR-derived entrypoint, persistent-OCI intent),
   extend `MachineSpec` (plain serde, REST-satisfiable — it is a `mvm-core` DTO, so
   this pays the full-rebuild tax) rather than adding a parallel boot method.

Do NOT add a second `admit_*` seam to the trait; the admission gate stays
`admit_and_boot_local` inside `run_machine`/`create_machine`.

## Design resolution (from the boot-surface scoping)

A full read of the boot surface settled the option-1-vs-2 question and the risk
profile:

- **One shared claim-8 gate.** `admit_plan_for_boot` (the CLI helper, shared by
  ~6 boot sites: transient run, persistent, MCP code-runner, session-resume,
  entrypoint-invoke, checkpoint-fork) and `run_machine`→`admit_and_boot_local`
  both bottom out in `mvm_hostd::plan_admission::admit_for_run`
  (synthesize→sign→verify→validity-window→nonce). The CLI has **no** independent
  signing/verification. Routing boot through the facade therefore **cannot
  duplicate or weaken the gate** — the two wrappers differ only in what they feed
  it and what they emit around it.
- **The wrappers differ in richness.** The CLI wrapper lowers network policy,
  verifies the bundle pin, admits shares, builds the `AuditEmitter`
  (`plan.admitted`/`launched`/`failed`/`grant_required`/…), registers the name,
  and records readiness. `admit_and_boot_local` hardcodes deny-all egress +
  `Standard` seccomp + no secrets/bundle/shares, emits nothing, and registers
  nothing.
- **Neither literal option works.** Option 1 (converge on `MachineSpec`) is
  impossible: `MachineSpec` is a `deny_unknown_fields` wire DTO ("intent only,
  never host paths"), so the CLI's resolved rootfs/kernel/verity/overlay-initrd
  paths cannot travel through it. Option 2 (grow `MachineSpec`) only conveys
  intent fields (net/kernel-pin/agent-verbs/profile/…), still not the artifacts.

**Resolution: the facade grows to own the rich boot.** The register + audit-emit +
policy + readiness orchestration moves from `up.rs` into `LocalBackend`, which
takes a richer *host-local* request (a `LocalRunRequest`-plus carrying resolved
paths + policy + secrets + shares + audit intent). The CLI keeps the prep
(image/kernel resolve, overlay, IR load) and hands the resolved request to the
facade. `MachineSpec` stays lean (the remote/create-intent surface).
`admit_for_run` is never touched.

**Staged, because the lint's two targets (`name_registry`, `AnyBackend`) are
independently removable:**

- **Stage 1 — `name_registry` behind the facade.** Add a facade registration
  method; route `up.rs`'s `register_with_metadata`, `sandbox`, the `machine`
  group's registry reads, and `console`'s registry bookkeeping through it +
  existing `list`/`inspect`. Removes the `vm::name_registry` reaches. Lower risk
  (registry read/write, not the boot dispatch).
- **Stage 2 — boot dispatch behind the facade.** Move the admit+`backend.start`
  orchestration into `LocalBackend` via the richer local request; the CLI hands
  off its prepped inputs. Removes the `AnyBackend` dispatch. The architectural
  core — full `nextest --workspace` gate.

Then the `check-cli-runtime-surface` lint lands.

## Invariants the implementer + reviewer MUST preserve

- **Claim 8 unweakened.** Every boot still goes through the signed-plan admission
  gate; there is no new code path that reaches a backend `start` without
  `admit_and_boot_local` (or the fleet's equivalent). The nonce/replay ledger and
  the validity window still apply. A boot that skips admission is a Critical.
- The `plan.admitted`/`plan.launched`/`plan.failed` chain-signed audit entries still
  emit with the same shape.
- Transient vs. persistent semantics, OCI persistent-machine behavior, kernel-pin
  resolution, and the name-registry registration are behavior-preserved.
- `MachineSpec` growth stays REST-satisfiable (no `mvm_runtime`/host-handle types).

## Why this one must be test-verified (not clippy-only)

The claim-8 admission gate is enforced by tests, not the type system: `up.rs`'s
`admit_plan_tests` (`emit_launched_and_failed_no_op_when_admission_skipped`, the
synthesize/sign/verify/replay-reject ladder) and the `mvm-hostd`/`mvm-core` plan
admission suites are what prove the gate still rejects unsigned/expired/replayed
plans. clippy proves it compiles; only the suite proves it still refuses. Therefore
this slice does not land until `cargo nextest run --workspace` (or at minimum the
`-p mvm-cli -p mvm-hostd -p mvm-core` admission tests) runs green — which currently
requires host memory headroom the box lacks (see
[[reference_slow_builds_are_host_memory_exhaustion]] / doc-13 notes).

## Sequencing within category A

`up`/machine-boot is the capstone. Smaller category-A slices (`sandbox`'s registry
reach; the `machine` group's non-boot registry reads) precede it and are also
test-gated but lower-risk. The `check-cli-runtime-surface` lint lands LAST, once
category A is drained, banning `mvm_runtime::vm::name_registry` + `AnyBackend`
dispatch in mvm-cli with B–E allowlisted.

**`readiness.rs` — LANDED, as a sync free function (deviation from the implied
trait method).** Recording a readiness milestone is best-effort *local
observability*, not a machine-lifecycle op: a remote fleet's daemon records its
own milestones, so an async, remote-capable `MvmClient` trait method is an
impedance mismatch (it would force a tokio runtime around a purely-local registry
write, and the gateway/subprocess impls could only no-op). Resolved instead by
`mvm_client::record_readiness(vm_name, readiness)` — a sync free function on the
client boundary crate, which *is* allowed to reach the host name registry.
mvm-cli's `record_vm_readiness` shim now calls it, so mvm-cli no longer names
`mvm_runtime` for readiness; the callers (`up`/`down`) are unchanged.
