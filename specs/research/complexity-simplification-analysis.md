# Complexity & Simplification Analysis (fresh hotspot hunt)

Grounded pass over `main` (worktree read from `/Users/auser/work/tinylabs/mvmco/mvm`).
Complements the in-flight `specs/refactor/` plan of record — it does **not** restate it.
Every hotspot is tagged **NEW** (not yet a workstream deliverable) or **TRACKED**
(already owned by a `specs/refactor/` WS; listed only to point at the concrete files).

## What the existing plan already owns (do not re-plan these)

Read `specs/refactor/{01-goals,02-architecture,06-execution-plan,07-progress-and-decisions,09-closeout}.md` first. The relevant already-tracked items:

- **File size >1500 production lines — DONE.** `xtask check-file-size` (`MAX_PROD_LINES = 1500`) is green and CI-wired. The 39 → 0 target is met; the 7149-line `libkrun_builder.rs` and 4287-line `mvm-host-vm-init.rs` pass because their *production* bodies are small and the rest is trailing `#[cfg(test)]`. WS8.
- **String backend dispatch — DONE.** `VmBackend::kind() -> BackendKind`; `check-no-string-backend-dispatch` guards it. WS6.
- **CLI top-level dispatch** is already a thin `TopLevelCommand` trait + 33-arm match (`crates/mvm-cli/src/commands/dispatch.rs`), one arm per verb delegating to a module `run`. The full per-command `Command`-trait redesign + verb consolidation is WS7 (not started).
- **Networking sprawl is TRACKED (WS1d + WS-NET).** `mvm-net` is a near-empty seam (`enforcement.rs` 108, `provider.rs` 103, `registry.rs` 132, `lib.rs` 27) while the implementation still lives in `mvm-hostd`: `supervisor/substitution_proxy.rs` (2972), `supervisor/aggregate.rs` (2695), `smoltcp_egress.rs` (2250), `network_tunnel.rs` (1648). The two-egress-model collision is also WS-NET. Not re-listed below.
- **Feature `#[cfg]` sprawl — partly TRACKED (WS5 surface done; WS10 dep cut).** 460 `#[cfg(feature …)]` sites remain (goal doc measured 396); worst files `mvm-build/src/rootfs.rs` (32), `qemu_builder.rs` (27), `pipeline/dev_build.rs` (24). Surface collapsed to `host`/`user`; the in-file `builder-vm` gating remains.
- **Single host+guest binary / no fork-exec — TRACKED (WS2).** Hotspot H2 below is the one independently-landable slice of it.

Everything under the numbered hotspots and Quick Wins below is **NEW** or a
concrete, not-yet-scoped filling of an existing WS.

---

## Prioritized hotspots (highest impact first)

### H1 — Builder-backend duplication + triple parallel abstraction  **NEW** (home: WS1f "slim the builder pipeline")

The largest single duplication surface in the tree, and it has **already drifted**
(the canonical failure mode this repo warns about). Three concrete symptoms:

1. **`validate_shell_job` copy-pasted and drifted.** `crates/mvm-build/src/qemu_builder.rs:792` (free fn) and `crates/mvm-build/src/libkrun_builder.rs:1325` (method) validate the identical `BuilderShellJob` contract with near-identical bodies — except libkrun added `ensure_utf8_path(&job.work_dir…)` / `ensure_utf8_path(&disk.path…)` guards and qemu did not. The qemu path silently accepts non-UTF-8 paths the libkrun path rejects. `mvm-runtime/src/builder_runner/hvf_builder.rs:83` calls a *third* `validate_shell_job`.

2. **`run_shell_script` re-implemented three ways** for one shell-job contract (`/work` in, `/out` out, `/job/cmd.sh` run by `mvm-host-vm-init`): `libkrun_builder.rs:997` (240 lines), `qemu_builder.rs:605` `run_shell_script_qemu` (185), `hvf_builder.rs:83`. Each independently: validates the job, acquires the nix-store image lock, stages the job dir, launches its VMM, reads the job result, maps exit codes. Only the VMM-launch middle differs.

3. **Small helpers duplicated + drifted.** `fn unique_job_id()` exists in both `hvf_builder.rs:157` (`format!("{pid}-{nanos}")`, nanoseconds) and `libkrun_builder.rs:2775` (`format!("{now:013}-{pid}")`, milliseconds) — **different field order and time unit** for the "same" id. `fn tail(s,n)` is byte-duplicated at `qemu_builder.rs:551` and `mvm-runtime/src/qemu.rs:930`. `pack_ext4`/`extract_out_artifacts`/`dir_stats`/`io_err` in `qemu_builder.rs` have libkrun analogues.

On top of the duplication there are **three parallel builder abstractions**: the `BuilderVm` trait (`mvm-build/src/builder_vm.rs:341`, impls: Libkrun/Qemu/Persistent/Stub/Hvf, the last one in a *different crate*), `MicrovmArtifactBuilder` (`mvm-runtime/src/artifacts/traits.rs:71`), and the `BuilderRunner`/`VmmDriver` seam (`HvfDriver`). Three trait vocabularies for "run a build in a VM."

Proposal:
- Lift the shell-job orchestration (validate → lock → stage → run → read-result → map-exit) into a single `builder_vm` module function parameterised by a `fn(&BuilderShellJob) -> VmLaunch` seam, or make it a **default method** on `BuilderVm` with backends supplying only `launch_vmm`. Delete the three `run_shell_script` bodies.
- Make `validate_shell_job`, `unique_job_id`, `tail`, `io_err`, `pack_ext4`, `extract_out_artifacts` **single shared fns** in `mvm-build` (drop the copies; the `hvf_builder` copies in `mvm-runtime` import them — the types already cross the crate boundary, e.g. `hvf_builder` already uses `mvm_build::libkrun_builder::BuilderShellJob`).
- Collapse `BuilderVm` + `MicrovmArtifactBuilder` into one trait (they both mean "produce `BuilderArtifacts` from a `BuilderJob`").

Impact: removes the highest-drift-risk duplication in the codebase and gives WS1f (currently a one-line "slim the builder pipeline" with no content) a concrete deliverable.

### H2 — Aux-binary path resolution hand-rolled at every spawn site despite a central resolver  **NEW** (independently landable slice of WS2)

`crates/mvm-runtime/src/aux_bin.rs` already centralises helper-binary resolution:
`resolve(&AuxBin{ bin, env_var })` does override-env → `MVM_AUX_BIN_DIR` → exe-dir →
`target/{release,debug}`, with a proper missing-binary error. But it is `pub(crate)`
in `mvm-runtime`, so **every other spawn site re-implements the override leg inline**:

- `crates/mvm-runtime/src/hvf_backend.rs:299` — `env::var_os("MVM_HVF_SUPERVISOR_PATH")…`
- `crates/mvm-runtime/src/microvm/egress_bridge.rs:82` (`MVM_PASST_PATH`) and `:138` (`MVM_BRIDGE_PATH`)
- `crates/mvm-build/src/libkrun_builder.rs:418` (`MVM_SUBSTITUTION_ENDPOINT_PATH`) and `:3237` (`MVM_LIBKRUN_SUPERVISOR_PATH`)
- `crates/mvm-runtime/src/substitution_spawn.rs:425`, `crates/mvm-runtime/src/broker_services_spawn.rs` (`MVM_AUDIT_SIGNER_PATH`/`MVM_BROKER_PATH`)

29 `env::var*("MVM_*_(PATH|BIN)")` sites total. The set of aux binaries is a fixed,
knowable list (`mvm-hvf-supervisor`, `mvm-libkrun-supervisor`, `mvm-substitution-endpoint`,
`mvm-broker`, `mvm-audit-signer`, `mvm-host-signer`, passt, bridge, gateway).

Proposal: promote `AuxBin` + `resolve` to a shared location (`mvm-core` or its own leaf),
make the aux-bin set a single `enum AuxBinary { … }` with `bin()`/`env_var()`, and route
every spawn site through `aux_bin::resolve(AuxBinary::X)`. Each `MVM_*_PATH` string then
appears exactly once. Lands ahead of, and shrinks, WS2.

### H3 — `cache prune` is a 492-line mega-sweep of copy-pasted step handlers  **NEW** (complements WS7)

`crates/mvm-cli/src/commands/ops/cache.rs:182 fn run` is the largest non-test function
in the tree (492 lines). The `CacheAction::Prune` arm is a flat sequence of ~8 independent
sweep steps — orphaned VM helpers, template slots, Stage-0 staging dirs, flow-byte-log,
standby pool, checkpoints, expired packs, pack versions — each an inline
`match sweep(…) { Ok(n) => removed += n, Err(e) => ui::warn(…) }` block (lines 178, 214,
250, 280, 305, 331, 341, 370, …). The Ok/Err/warn boilerplate is copy-pasted per step and
each step reaches into a different subsystem, so none is independently testable.

Proposal: a `trait PruneStep { fn name(&self) -> &str; fn run(&self, dry_run: bool) -> Result<Reclaimed>; }`,
one impl per subsystem, iterated by a single loop that owns the `warn`-on-error + totals
accounting. Collapses the 492-line fn to a table + a ~15-line driver and makes each sweeper
unit-testable. WS7 folds `cache prune`/`pack prune`/`storage gc` into `env cleanup`/`env reset`;
this is the refactor that makes that fold trivial.

### H4 — Repeated `io::Error` → domain-error wrapping: 132 verbatim closures  **NEW**

`BuilderVmError::ExtractionFailed(format!("<op> {}: {e}", path.display()))` (and its
`NixBuildFailed` sibling) appears **132 times** across `mvm-build`, 80 of them in
`libkrun_builder.rs` alone (`builder_vm_runtime.rs` 27, `qemu_builder.rs` 11). One backend
already factored it — `qemu_builder.rs:556 fn io_err(ctx, path, e) -> BuilderVmError` — but
the helper is local and unused by the other 120 sites.

Proposal: promote `io_err` to the crate root (or an `IoCtx` extension trait
`io::Result<T>::ctx(op, path)`), convert the 132 sites. Pure mechanical line-count reduction
(~2–4 lines → 1 per site) that also erases the incidental drift between which sites map to
`ExtractionFailed` vs an ad-hoc `format!`.

### H5 — Two parallel backend enums with duplicated string round-trips  **NEW (minor)**

WS6 removed `backend.name() == "…"` dispatch, but two independent enums each keep their own
name↔string codec: runtime `BackendKind` and `BuilderBackendChoice`
(`mvm-build/src/builder_backend_select.rs:93` name arm, `:144` parse arm — `"libkrun"`/`"qemu"`/`"hvf"`).
`"libkrun"|"hvf"|"firecracker"|"qemu"` literals recur across 20 files. This is not the
banned dispatch pattern (each enum has one parse fn), but it is a parallel-enum smell: the
builder backend set is a subset of the workload backend set expressed as a separate type.
Fold into the `H1` builder consolidation — one `BackendKind` with a `builder_capable()`
predicate rather than a second enum.

---

## High-value quick wins (each an independent small PR)

1. **Dedupe `tail(s,n)`.** `crates/mvm-build/src/qemu_builder.rs:551` is byte-identical to `crates/mvm-runtime/src/qemu.rs:930` (the latter adds an `n==0` guard). Move one copy to a shared util (or `mvm-core`), delete the other.

2. **Unify `unique_job_id()` and kill the format drift.** `hvf_builder.rs:157` emits `"{pid}-{nanos}"` (ns); `libkrun_builder.rs:2775` emits `"{now:013}-{pid}"` (ms) — different unit *and* field order for the same-named id. Pick one, export it, delete the other. This is a latent bug, not just tidiness (any code that parses a job id by position breaks across backends).

3. **Reconcile `validate_shell_job`.** Make `qemu_builder.rs:792` and `hvf_builder.rs`'s copy call the same fn as `libkrun_builder.rs:1325`, closing the missing-`ensure_utf8_path` gap on the qemu path (a real validation divergence today).

4. **Route the three easiest aux-bin lookups through `aux_bin::resolve`.** Bump `aux_bin::{AuxBin,resolve}` visibility and convert `hvf_backend.rs:299`, `egress_bridge.rs:82`, `egress_bridge.rs:138`. Removes three hand-rolled `env::var_os` override blocks; a down-payment on H2.

5. **Introduce `io_err`/`.ctx()` and convert `libkrun_builder.rs`'s 80 wrappers.** Single file, mechanical, ~150-line reduction; promotes the existing `qemu_builder.rs:556` helper.

6. **Fix stale plan-of-record facts.** `specs/refactor/07-progress-and-decisions.md:31` lists `mvm-verify` in "Current crate set (14)", but it was absorbed into `mvm_protocol::verify` and is **not** a workspace member (`Cargo.toml`). The same doc's `egress_server.rs` "parked/dead" bullet (`:39`) is also stale — the module no longer exists in the tree. Two one-line corrections keep the SoT honest.

7. **Make `OutputFormat::from_str_arg` fail loudly.** `crates/mvm-cli/src/output.rs:19` maps any unrecognised `--output` value to `Self::Table` via `_ => Self::Table`, so `--output jsonn` silently prints a table instead of erroring. Convert to `FromStr` with an explicit error (and let clap validate). Small correctness win, removes a silent stringly fallthrough.

8. **Resolve the `DmsetupBackend` stub cluster.** `crates/mvm-runtime/src/storage/backend.rs:116–179` has 8 methods returning `"…phase-2 work…"`. The read path (`storage info`/`gc`) is live (per WS8 notes) but the create/mutate path is an unimplemented stub. Either wire it or delete `DmsetupBackend` and keep only the live read surface — before WS8's "0 dead modules" gate reaches it.

---

## Method / evidence notes

- Function sizes measured by brace-matched span over `crates/ xtask/ src/` (excluding the vendored `.mvm-test/cargo` registry). Only one non-test fn exceeds 400 lines (`cache.rs:182`, 492); the rest of the top of the distribution is data tables (`threat_classifier.rs:426 literal_patterns`, 396) or already-decomposed backend `start`/`run_build` bodies (~200–330). WS8's decomposition largely holds.
- Duplication was confirmed by reading both bodies, not by name-match alone (H1.1, QW1, QW2 all verified drifted or byte-identical in-place).
- Crate count grounded against `Cargo.toml` workspace members: 14 non-fuzz library/bin crates + root + `xtask` (mvm-verify absent).
