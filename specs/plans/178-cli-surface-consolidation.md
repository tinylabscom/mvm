# Plan 178 — CLI surface consolidation (Implementation Plan)

> **Numbering:** 178 is the next free plan number after 177. Confirm at merge.

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans`.
> Steps use checkbox (`- [ ]`) syntax.
>
> **Decision source:** [ADR-077](../adrs/077-cli-surface-consolidation.md).

**Goal:** Collapse the ~56 flat top-level `mvmctl` commands into ~8
ergonomic top-level verbs plus ~8 noun-grouped namespaces, hide internal
subprocess commands, and rationalize the overlapping run-family — so the
CLI reads like one cohesive product instead of an accreted toolbox.

**Architecture:** The command surface is the `Commands` enum in
`crates/mvm-cli/src/commands/mod.rs` (top-level variants) dispatched in
`run()`. Grouping = introduce parent clap subcommand enums (e.g. `Vm`,
`Image`, `Trust`, `Storage`, `Net`, `Ops`) whose variants are the moved
leaf commands; the leaf `Args` structs and their `run()` fns stay put and
get re-parented. No-backcompat means hard renames with no alias layer.

**Tech Stack:** Rust, clap derive, `crates/mvm-cli/src/commands/`.

---

## Guardrails (every task)
- Never break a security-claim command path (`audit`, `bundle`, `trust`,
  `attest`, `secret`, `up`/`run` admission). Move them; don't alter behavior.
- The `tests/cli.rs` help/parse integration tests + `commands/tests.rs`
  (hidden-command assertions) are the safety net — extend them per task.
- One group per task so each diff is reviewable and bisectable.
- CI fmt nightly; `cargo clippy -p mvm-cli --all-targets -- -D warnings`.
- No `Co-Authored-By: Claude` trailer.

## Target surface

Top-level (kept flat for ergonomics):
`run` `exec` `ls` `console` `down` `dev` `doctor` `init`

Grouped:
- `vm` — `pause` `resume` `snapshot` `save` `restore` `wait` `ttl`
  (`set-ttl`) `diff` `logs` `fs` `proc` `cp` `invoke`
- `build` — `build` `compile` `validate` `kernel`
- `image` — `image` `catalog` `manifest` `artifact`
- `trust` — `sign` `bundle` `attest` `receipt` `audit` (existing `trust`)
- `storage` — `storage` `volume` `cache`
- `net` — `network` `forward`
- `secret` — unchanged
- `ops` — `metrics` `bench` `config` `mcp`

Hidden (subprocess/internal): `persistent-builder` `boot-report`
`reconcile` `shell-init` (`__qemu-vsock-bridge` already hidden — leave).

---

## Task 1: Audit current surface + lock the mapping
**Files:** read `crates/mvm-cli/src/commands/mod.rs`, `tests.rs`; create no code.
- [ ] List every `Commands` variant with its current name, `Args` type, and `run()` entry. `rg -n 'hide = true' crates/mvm-cli/src/commands/mod.rs` to see what's already hidden (expect `__qemu-vsock-bridge`).
- [ ] Produce the old→new mapping table (verb → group path) as a comment block at the top of a new `crates/mvm-cli/src/commands/GROUPING.md`-style note, or in this plan. Flag any verb whose semantics are unclear for Task 7 (run-family).
- [ ] Commit the mapping note: `git commit -m "docs(cli): lock command grouping map"`

## Task 2: Hide the leaking internal commands
**Files:** `crates/mvm-cli/src/commands/mod.rs`, `commands/tests.rs`.
- [ ] **Failing test.** Extend `commands/tests.rs` (the hidden-command test, `tests.rs:38`) to assert `persistent-builder`, `boot-report`, `reconcile`, `shell-init` are absent from top-level `--help`. Run → FAIL.
- [ ] **Hide.** Add `#[command(hidden)]` (matching the `__qemu-vsock-bridge` form) to the `PersistentBuilder`, `BootReport`, `Reconcile`, `ShellInit` variants. Verify each still dispatches in `run()`.
- [ ] **Green.** `cargo nextest run -p mvm-cli`; `cargo test -p mvm-cli --test cli` (help-text integration). clippy clean.
- [ ] **Commit.** `git commit -m "refactor(cli): hide internal subprocess commands from help"`

## Task 3: Introduce the `vm` group
**Files:** new `crates/mvm-cli/src/commands/vm/group.rs` (parent enum); `mod.rs`.
- [ ] **Failing test.** In `tests/cli.rs` assert `mvmctl vm pause --help` parses and `mvmctl pause` no longer exists. FAIL.
- [ ] **Implement.** Add a `Vm(vm::group::Args)` top-level variant whose inner enum has `Pause Resume Snapshot Save Restore Wait Ttl Diff Logs Fs Proc Cp Invoke`. Move those variants off `Commands`; re-export their existing `Args`/`run()` unchanged (the leaf modules don't move — only the parenting). Dispatch `Vm` in `run()` by matching the inner enum. (`save`/`restore` may be new leaves if Plan 177 surfaced them — if absent, omit and add in the DX-parity plan.)
- [ ] **Green.** `cargo nextest run -p mvm-cli`; `cargo test -p mvm-cli --test cli`. clippy clean.
- [ ] **Commit.** `git commit -m "refactor(cli): group running-VM verbs under \`vm\`"`

## Task 4: Introduce `image`, `build`, `storage` groups
**Files:** parent enums under each command dir; `mod.rs`.
- [ ] **Failing test.** Assert `mvmctl image catalog --help`, `mvmctl build compile --help`, `mvmctl storage volume --help` parse; old flat names gone. FAIL.
- [ ] **Implement.** `Image` group ← `image catalog manifest artifact`; `Build` group ← `build compile validate kernel`; `Storage` group ← `storage volume cache`. Re-parent only. (Note `build` and `image` already exist as single commands — promote each to a group with the former command as a default/leaf, or rename the former leaf to `image image`→`image pull` style only if clearly better; otherwise keep the existing leaf name under the group.)
- [ ] **Green + commit.** nextest + cli test + clippy; `git commit -m "refactor(cli): group image/build/storage verbs"`

## Task 5: Introduce `trust`, `net`, `ops` groups
**Files:** parent enums; `mod.rs`. (`trust` already exists — extend it.)
- [ ] **Failing test.** Assert `mvmctl trust sign`, `mvmctl trust audit`, `mvmctl net forward`, `mvmctl ops metrics` parse; old flat names gone. FAIL.
- [ ] **Implement.** `Trust` group gains `sign bundle attest receipt audit`; new `Net` group ← `network forward`; new `Ops` group ← `metrics bench config mcp`. Re-parent only; security-claim leaves (`audit`, `bundle`, `attest`) keep identical behavior.
- [ ] **Green + commit.** nextest + cli test + clippy; `git commit -m "refactor(cli): group trust/net/ops verbs"`

## Task 6: Dev-environment grouping
**Files:** `crates/mvm-cli/src/commands/env/`; `mod.rs`.
- [ ] **Failing test.** Assert `dev`, `doctor`, `init`, `run`, `exec`, `ls`, `console`, `down` remain top-level; `bootstrap cleanup uninstall update` move under `dev` (or stay top-level if `dev` is already a busy group — decide from Task 1 audit). FAIL on the chosen change.
- [ ] **Implement** the chosen dev grouping; keep `dev up/down/shell/status` intact.
- [ ] **Green + commit.** nextest + cli test + clippy; `git commit -m "refactor(cli): consolidate dev-environment verbs"`

## Task 7: Run-family rationalization (READ FIRST — do not guess)
**Files:** `crates/mvm-cli/src/commands/vm/{up,exec,invoke,sandbox}.rs`.
- [ ] **Read every implementation before changing anything.** `up.rs` (signed `ExecutionPlan` workload boot — claim-8 path), `exec.rs` (transient-VM runner + `Exec`/`Run`/`Receipt` args — `reference_exec_rs_transient_runner`), `invoke.rs` (`send_run_entrypoint` function-service `--input` — `feedback_input_flag_and_mode_aliases`), `sandbox.rs`. Write a one-paragraph semantics summary for each into this task before editing.
- [ ] **Decide the collapse** from the summaries (candidate: `run` = boot+run a workload [absorbs `up`/`sandbox` where they overlap], `exec` = run-in-existing-guest, `invoke` = call a function entrypoint). Record the decision; do NOT merge anything whose audit/admission behavior differs without preserving it.
- [ ] **Failing tests** encoding the chosen surface (each kept verb parses with its flags; removed verbs gone; `--dev`/`--prod` aliases + `--input name=value` preserved). FAIL.
- [ ] **Implement** the collapse, preserving claim-8 admission, the transient-VM path, and `--input`/mode-alias behavior exactly.
- [ ] **Green.** Full `cargo nextest run -p mvm-cli`; `cargo test -p mvm-cli --test cli`; re-run any admission/audit tests touching `up`/`run`. clippy clean.
- [ ] **Commit.** `git commit -m "refactor(cli): rationalize run-family verbs"`

## Task 8: Verification + docs
- [ ] `mvmctl --help` shows ~8 top-level verbs + ~8 groups; no internal commands visible.
- [ ] `just ci` green (fmt, nextest, `cargo test -p mvm-cli --test cli`, clippy, claim/spec gates).
- [ ] Update `public/src/content/docs/reference/cli-commands.md` to the new surface.
- [ ] Update `CLAUDE.md` "Build and Run" examples to grouped forms.
- [ ] Tick the Plan 178 boxes in `specs/REFACTOR-STATUS.md`; bump "Last updated".

---

## Self-review / success criteria
- [ ] ~56 flat verbs → ~8 top-level + ~8 groups; internals hidden.
- [ ] Every security-claim command path moved, never behavior-changed.
- [ ] Run-family collapse landed only after reading each implementation;
      `--input`, `--dev`/`--prod`, claim-8 admission, transient-runner
      behavior all preserved.
- [ ] CLI help/parse integration tests cover every new path; `just ci` green.
- [ ] Independent of the VZ work; safe to run parallel to Plan 177 Phase 1.
