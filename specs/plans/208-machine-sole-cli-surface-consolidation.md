# Plan 208 — `machine` as the sole workload CLI surface (consolidation)

**Status:** Proposed — not started
**Owner:** mvm
**Date:** 2026-06-21
**Decision:** [ADR-092](../adrs/092-machine-as-sole-workload-cli-surface.md)
**Depends on:** [ADR-091](../adrs/091-unified-machine-run-lifecycle.md) /
[Plan 207](207-machine-run-unified-lifecycle.md) (unified `machine run` modes)
merged to `main` first.
**Amends:** [Plan 200](200-machine-ux-dx-layer.md) — supersedes its "UX layer
over primitives, do not touch `up`/`down`" framing.

> **For agentic workers:** implement task-by-task. Each task is independently
> testable, ends green (`cargo nextest run --workspace` + `cargo clippy
> --workspace -- -D warnings` + `cargo fmt --all -- --check`), and is its own
> commit. Steps use `- [ ]` checkboxes.

## Goal

Collapse the workload-VM CLI to a single noun, `machine`. Remove the verb-first
commands (`up`, `down`, `run`, `invoke`, `logs`, `console`, `ls`) and the
separate `vm` noun; fold every lifecycle and operate-on-running verb under
`machine`, kept scannable with clap `help_heading` groups. Image source becomes
a flag (`--image` OCI / `--flake` Nix). No aliases — hard removal, per the
pre-1.0 no-backcompat rule.

This is a **surface rename over unchanged enforcement.** Every retired verb
already delegates to a handler `machine` will keep calling
(`vm::exec::run_secure`, `vm::up::*`, `vm::down::run`, `vm::console::run`,
`vm::logs::run`, `vm::ps::run`, `vm::group::*`). No admission, signing, audit,
or backend code changes. Claims 8–15 are untouched and must stay untouched.

## Global constraints

- `cargo fmt --all -- --check`, `cargo nextest run --workspace`, `cargo test
  --workspace --doc`, `cargo clippy --workspace -- -D warnings` all green per
  task. (`just ci`.)
- No `#[allow(clippy::too_many_arguments)]`; group args into structs.
- No spec/PR/ADR citations in code comments (lint-gated).
- No new dependencies.
- Hard removal: a retired command name must **not** parse afterward (no hidden
  clap alias). The negative test for each is "old name → clap error".
- Handlers are **moved, not rewritten.** A task that retires `Foo` re-points
  `machine`'s dispatch at the same handler function `Commands::Foo` called.
- `dev` (builder VM) is out of scope and stays a top-level command.

## The contract to test (end state)

| Removed | New invocation | Backing handler (unchanged) |
| --- | --- | --- |
| `up --flake .` | `machine run --flake .` | `vm::up::run` via `machine run` dispatch |
| `down [name]` | `machine stop [name]` | `vm::down::run` |
| `run -- cmd` | `machine run -- cmd` | `vm::exec::run_secure` |
| `invoke … ` | `machine run --entrypoint …` | `vm::invoke::run` |
| `ls [--all]` | `machine ls [--all]` | `vm::ps::run` |
| `logs <name>` | `machine logs <name>` | `vm::logs::run` |
| `console <name>` | `machine console <name>` / `machine shell` | `vm::console::run` |
| `build image …` | `machine build …` | `build::image` handler |
| `vm <verb>` | `machine <verb>` (Advanced group) | `vm::group::*` |

`machine --help` groups subcommands under `help_heading`s: **Lifecycle**
(`run`/`build`/`create`/`start`/`stop`/`rm`), **Inspect**
(`ls`/`logs`/`inspect`/`shell`/`exec`/`console`), **Advanced** (`pause`/`resume`/
`snapshot`/`save`/`restore`/`checkpoint`/`cp`/`wait`/`set-ttl`/`forward`/`diff`/
`fs`/`proc`/`session`/`volume`/`sandbox`).

Top-level `--help` groups the infra commands (`pool`/`cache`/`storage`/
`manifest`/`catalog`/`image`/`bundle`/`trust`/`deps`/`artifact`/`secret`/
`network`/`ops`/`env`/`reconcile`) under an **Infrastructure** heading, leaving
`machine`/`dev`/`build`/`init`/`doctor` ungrouped at the top.

## Key files

- `crates/mvm-cli/src/commands/mod.rs` — top-level `Commands` enum (mod.rs:71)
  and its dispatch `match`; this is where variants get deleted and `help_heading`
  is applied.
- `crates/mvm-cli/src/commands/machine/mod.rs` — `MachineAction` enum
  (mod.rs:57) and its dispatch (mod.rs:1416); where folded verbs land.
- `crates/mvm-cli/src/commands/vm/{up,down,exec,invoke,logs,ps,console,group}.rs`
  — handler bodies (moved, not rewritten).
- `crates/mvm-cli/tests/cli.rs` — clap parse/help integration tests; primary
  test surface for every task.
- SDK machine wrappers (Python/TS/Rust) and `public/src/content/docs/` — updated
  per wave that retires a verb they reference.

## Test approach

Each task is gated by `tests/cli.rs` assertions using clap's
`Command::try_get_matches_from` (no VM boot needed to prove the surface):

- **positive:** new path parses and routes to the intended handler args
  (assert on the parsed `MachineAction` / arg fields).
- **negative (hard removal):** the retired top-level name returns
  `clap::error::ErrorKind::InvalidSubcommand`.
- **help grouping:** `--help` output contains the `help_heading` label and the
  subcommand under it.

Behavior parity (does the VM actually boot/stop) is already covered by the
existing handler tests, which keep running unchanged because the handler is the
same function. Live dev-host boot smoke is the final task.

---

## Task 1: Top-level `--help` grouping (no removals yet)

Pure presentation; lands first so reviewers see the target shape before any
verb moves. Apply `#[command(help_heading = "Infrastructure")]` to the infra
variants of `Commands` (mod.rs:71): `Pool`, `Cache`, `Storage`, `Manifest`,
`Catalog`, `Image`, `Bundle`, `Trust`, `Deps`, `Artifact`, `Secret`, `Network`,
`Ops`, `Env`, `Reconcile`. Leave `Machine`/`Dev`/`Build`/`Init`/`Doctor`
ungrouped.

- [ ] Write failing test in `tests/cli.rs`: `top_level_help_groups_infra` —
  render `Cli::command().render_help()`, assert it contains `"Infrastructure"`
  and that `"pool"` appears after that heading.
- [ ] Run it; confirm FAIL (heading absent).
- [ ] Add `help_heading` attributes to the infra variants.
- [ ] Run it; confirm PASS. Run `cargo run -- --help` and eyeball the grouping.
- [ ] `just ci`; commit `docs(cli): group infrastructure commands in --help`.

**Done when:** `--help` leads with the daily drivers; infra is under one
heading; no command renamed or removed.

## Task 2: `machine` subcommand `help_heading` groups

Add `help_heading` to the existing `MachineAction` variants (mod.rs:57):
Lifecycle = `Run`/`Create`/`Start`/`Stop`/`Rm`; Inspect = `Ls`/`Inspect`/
`Shell`/`Exec`. (`Build`/`logs`/`console`/advanced verbs arrive in later tasks
and are grouped as they land.)

- [ ] Write failing test `machine_help_groups_lifecycle_and_inspect` in
  `tests/cli.rs`: render `machine --help`, assert `"Lifecycle"` and `"Inspect"`
  headings present with `run`/`ls` under them.
- [ ] Run; FAIL. Add the attributes. Run; PASS.
- [ ] `just ci`; commit `docs(cli): group machine subcommands in --help`.

**Done when:** `machine --help` is grouped; no behavior change.

## Task 3: Fold `build image` → `machine build`

`machine build` is the explicit image build (OCI or Nix-flake) that produces a
manifest/image `machine run --image` consumes. Add a `Build(MachineBuildArgs)`
variant to `MachineAction` (Lifecycle heading); its handler **calls the existing
`build::group` image handler** with the translated args. Remove the `image`
subcommand from the `build` group (`build compile/validate/kernel` stay).

- [ ] Write failing test `machine_build_parses_image_and_flake`: assert
  `machine build --image alpine` and `machine build --flake .` both parse and
  that supplying both is a clap conflict error.
- [ ] Write failing test `build_image_subcommand_removed`: assert
  `build image …` → `InvalidSubcommand`.
- [ ] Run both; FAIL. Add `MachineBuildArgs` (mirror the old `build image` args;
  reuse the same arg struct if one exists), wire dispatch (mod.rs:1416) to the
  existing build handler, delete the `Image` arm from `build::group`.
- [ ] Run; PASS. Add a doctest/handler test asserting the build handler is
  invoked with equivalent args (assert on the constructed build request struct).
- [ ] `just ci`; commit `feat(cli): move build image to machine build`.

**Done when:** `machine build` builds; `build image` no longer parses; the build
pipeline code is unchanged (only its entry point moved).

## Task 4: Fold `up`/`run`/`invoke` → `machine run` (orthogonal model)

This is the crux task and the largest. It was written before Plan 207 reshaped
`machine run`; this is the refined design.

### Why the old "delegate" sketch is wrong

The original sketch ("`--flake` routes to `vm::up::run`, `--entrypoint` routes
to `vm::invoke::run`") is the **(b) delegate** approach, and it is rejected:
`vm::up::run` carries its own persistent + attach lifecycle, so
`machine run --flake .` would behave persistently while `machine run --image X`
is transient — `-d`/`-t` would be silently ignored on the flake path. That is
the exact "two behaviors under one name" the consolidation exists to remove.

### The model: three orthogonal axes

`machine run` already separates lifecycle (Plan 207's `run_dispatch`:
Transient / Persistent via `--name`/`-d` / Interactive via `-t`). Task 4 adds
two more axes so all three compose freely:

- **Source** (exactly one; none ⇒ bundled default image):
  - `--image <ref>` → OCI pull + materialize (existing `run_secure`
    `ImageSource::Prebuilt`).
  - `--manifest <path>` → pre-built manifest/template (existing `run_secure`
    `ImageSource::Template`).
  - `--flake <path>` → **NEW**: Nix build in the builder VM, then feed the
    built manifest into the same run path. Reuse the existing build step
    (`build::run` / the `vm::up` build helper) — do NOT duplicate nix-build
    logic, and do NOT route to `vm::up::run` wholesale (that would drag up's
    lifecycle in). Build → resolved manifest → `run_dispatch`.
- **Action** (default = argv command):
  - trailing `-- <argv>` → run the command (today's `run_secure`).
  - `--entrypoint` → call the image's baked entrypoint instead of argv (today's
    `vm::invoke::run`), carrying invoke's `--input`/`--stdin`/`--fresh`/`--reset`.
    Conflicts with trailing argv (clap).
- **Lifecycle** (unchanged, Plan 207): Transient | `--name`/`-d` | `-t`/`-i`.
  Works for every source × action combination.

### Old → new mapping (behaviour parity)

- `up --flake . [--name N]` → `machine run --flake . -d` (or `--name N`) — build
  + persistent. (up's bare attach/`--wait` ⇒ default persistent-attached
  behaviour; preserve via the existing persistent path.)
- `run -- cmd` → `machine run -- cmd` (already works).
- `invoke <manifest> --input k=v` → `machine run --manifest <manifest>
  --entrypoint --input k=v`.

### Implementation

- Add `--flake`, `--manifest`, `--entrypoint` (+ `--input`/`--stdin`/`--fresh`/
  `--reset`) to `MachineRunArgs`. clap: a `required = false` source group making
  `--image`/`--manifest`/`--flake` mutually exclusive; `--entrypoint`
  `conflicts_with = "argv"`.
- Resolve **source → bootable manifest/image BEFORE `run_dispatch`**: `--flake`
  ⇒ build (reuse build helper) ⇒ manifest; thread `--manifest`/built-manifest
  into `RunArgs` (which already accepts `--manifest`); `--image` unchanged.
- Resolve **action**: default argv via `run_secure`; `--entrypoint` reuses
  invoke's entrypoint-send within the selected lifecycle (extract invoke's
  entrypoint-send so persistent/interactive can reuse it — don't fork it).
- Delete `Commands::Up`, `Commands::Run`, `Commands::Invoke` + dispatch arms.

### Staging (each sub-step green)

Land in two commits inside Task 4 if the whole is large:
1. **Source axis** — add `--flake`/`--manifest` to `machine run` composing with
   lifecycle; retire `up` + `run`. (`--entrypoint` not yet.)
2. **Action axis** — add `--entrypoint` (+ invoke flags); retire `invoke`.

### Tests (TDD)

- [ ] `machine_run_source_flags_parse`: `--image`/`--manifest`/`--flake` each
  parse; any two together → clap `ArgumentConflict`.
- [ ] `machine_run_flake_builds_then_runs`: `machine run --flake . -d` resolves
  the source to the build step and then the Persistent lifecycle (assert the
  resolved source enum + `MachineRunMode::Persistent`, no separate up path).
- [ ] `machine_run_entrypoint_conflicts_with_argv`: `--entrypoint -- cmd` →
  conflict; `--entrypoint` alone selects the entrypoint action.
- [ ] `up_removed`/`run_removed`/`invoke_removed`: each → `InvalidSubcommand`.
- [ ] Behaviour parity: a `--flake` build-and-run yields the same artifact as
  old `up`; an `--entrypoint` call matches old `invoke` (reuse their existing
  handler tests against the new entry points).
- [ ] Audit: run the workspace audit suite (`nextest --workspace -E
  'test(/audit/)'`) — removing `up`/`run`/`invoke` will need
  `audit_total_coverage` + `audit_emissions_live` updated (stale top-level
  entries; their postures move under `machine`'s `--entrypoint`/source paths as
  appropriate). Keep `machine`'s `cmd.machine.*` verb behaviour.
- [ ] `just ci`; commit(s) per the staging above.

**Done when:** `up`/`run`/`invoke` no longer parse; `machine run` covers OCI /
manifest / Nix-flake sources × argv / entrypoint actions × transient /
persistent / interactive lifecycle, with no hidden mode divergence; the build
and entrypoint-send logic is reused, not duplicated.

## Task 5: Fold `down` → `machine stop`

`machine stop` exists (delegates to `vm::down::run`). This task makes it the
**only** stop path: extend `machine stop` to accept `down`'s full surface
(by-name, `--all`, `mvm.toml`-derived set) and remove `Commands::Down`.

- [ ] Write failing test `machine_stop_supports_all_and_named`: assert
  `machine stop --all` and `machine stop web` parse to the same options `down`
  accepted.
- [ ] Write failing test `down_removed`: `down` → `InvalidSubcommand`.
- [ ] Run; FAIL. Widen `MachineStopArgs` to `down`'s args, ensure dispatch passes
  them straight to `vm::down::run`, delete `Commands::Down` + arm.
- [ ] Run; PASS. `just ci`; commit `feat(cli): fold down into machine stop`.

**Done when:** `machine stop` covers every `down` invocation; `down` gone.

## Task 6: Fold `ls`/`logs`/`console` → Inspect group

`machine ls` exists; `logs`/`console` do not yet. Add `Logs(...)` and
`Console(...)` to `MachineAction` (Inspect heading), each delegating to
`vm::logs::run` / `vm::console::run`. Confirm `machine ls --all` matches `ls
--all`. Remove `Commands::Ls`, `Commands::Logs`, `Commands::Console`.

- [ ] Write failing tests: `machine_logs_parses`, `machine_console_parses`,
  `machine_ls_supports_all`, and `ls_removed`/`logs_removed`/`console_removed`
  (each old name → `InvalidSubcommand`).
- [ ] Run; FAIL. Add the two `MachineAction` variants delegating to the existing
  handlers; verify `machine ls` already forwards `--all`; delete the three
  `Commands` variants + arms.
- [ ] Run; PASS. Note: `machine console` keeps the claim-15 `enforce_accessible_gate`
  because it calls the same `vm::console::run` — add a test asserting it is still
  refused on a sealed image (reuse the existing `console_refused_on_sealed_image`
  fixture path).
- [ ] `just ci`; commit `feat(cli): fold ls/logs/console into machine`.

**Done when:** the three inspect verbs live under `machine`; claim-15 gate
preserved (test proves it); old names gone.

## Task 7: Fold the `vm` noun → `machine` Advanced group

Move every `vm` subcommand under `machine` and delete `Commands::Vm`. The
`vm::group` subcommands (`pause`/`resume`/`snapshot`/`save`/`restore`/
`checkpoint`/`cp`/`wait`/`set-ttl`/`forward`/`diff` + the `fs`/`proc`/`session`/
`volume`/`sandbox` nested groups) become `MachineAction` variants under the
**Advanced** `help_heading`, each delegating to the same `vm::group::*` handler.

- [ ] Write failing test `machine_advanced_verbs_parse`: parameterized over
  `pause`/`snapshot`/`cp`/`fs`/`proc`/`session`/`volume`/`sandbox`, assert each
  parses under `machine` and routes to the matching `vm::group` handler.
- [ ] Write failing test `vm_noun_removed`: `vm pause` → `InvalidSubcommand`.
- [ ] Write failing test `machine_help_groups_advanced`: `machine --help`
  contains `"Advanced"` with `snapshot` under it.
- [ ] Run; FAIL. Re-home the `vm::group` action enum under `MachineAction`
  (prefer flattening the existing group enum as a sub-enum to avoid rewriting 16
  handlers), apply the Advanced heading, delete `Commands::Vm` + arm.
- [ ] Run; PASS. Confirm all existing `vm::group` handler tests pass unchanged.
- [ ] `just ci`; commit `feat(cli): fold the vm noun into machine`.

**Done when:** `machine --help` shows Lifecycle/Inspect/Advanced; `vm` is gone;
no `vm::group` handler logic changed.

## Task 8: Sweep references — SDK wrappers, docs, examples, specs

Mechanical follow-through so nothing advertises a removed verb.

- [ ] `rg -n '\b(mvmctl|mvm) (up|down|run|invoke|logs|console|ls|vm) ' --type-not
  rust` across `public/`, `examples/`, `specs/`, SDK wrapper sources; replace
  each with its `machine` form (use the contract table).
- [ ] Update Python/TS/Rust SDK machine wrappers that shell out to old verbs.
- [ ] Update `public/src/content/docs/reference/cli-commands.md` and the
  quickstart/guides.
- [ ] Tick the matching boxes in `specs/REFACTOR-STATUS.md` and update Plan 200's
  status to note ADR-092 supersedes its `up`/`down` framing; bump "Last updated".
- [ ] `just ci`; run the docs link/spec gates
  (`cargo build --all-targets`, `xtask check-no-spec-refs-in-comments`,
  `xtask check-spec-numbers`). Commit `docs(cli): retire verb-first commands across docs/SDK`.

**Done when:** no doc, example, or SDK wrapper invokes a removed verb; status
rollups current.

## Task 9: Live dev-host verification

Surface tests prove parsing; this proves the moved handlers still boot a VM.

- [ ] On the dev host (macOS 26 / Vz or Linux/KVM box per
  `[[project_dev_host_runs_builder_via_vz]]`), run, capturing console logs:
  - `mvmctl machine run --image alpine -- echo hi` (transient OCI)
  - `mvmctl machine run --flake . --name w -d` then `machine stop w` (Nix persistent)
  - `mvmctl machine ls` / `machine logs w` while up
  - `mvmctl machine snapshot w` (one Advanced verb, smoke)
- [ ] Confirm each succeeds and that no removed verb exists (`mvmctl up` →
  error). Record timings/log paths in the plan.
- [ ] Commit `test(cli): record machine-consolidation dev-host verification`.

**Done when:** the daily-driver paths boot and tear down on a real backend
through the new surface.

## Out of scope

- `dev` (builder VM) — stays a distinct top-level command (ADR-088).
- Any admission / signing / audit / backend change — this is surface-only.
- The unified `machine run` *modes* themselves — owned by Plan 207; this plan
  assumes them present.
- Renaming infra commands — they keep their names, only gain a help heading.

## Deferred follow-ups

- [ ] Decide whether `manifest`/`catalog`/`image` (image-adjacent infra) should
  later nest under `machine` too; left as infra for now to bound this plan.
