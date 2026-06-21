# Plan 207 — Unified `machine run` lifecycle (transient / persistent / interactive)

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task, and superpowers:test-driven-development for every task — each flag combination in the behavior matrix gets a failing test first. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fold three flag-selected modes into `machine run` — transient (today),
**persistent** (`--name`/`-d`), and **interactive** (`-t`/`--tty`, dev-only) —
so `machine run --image alpine -- /bin/sh` drops into a shell in dev, and a
persistent machine no longer needs the `create` → `start` → `shell` ceremony.
Compose the existing machine verbs; do not add new lifecycle code.

**Design:** ADR-091 (`specs/adrs/091-unified-machine-run-lifecycle.md`) and the
design note `specs/notes/2026-06-21-machine-run-unified-lifecycle-design.md`.
Read both first — they are the contract. The locked rules:

- Persistence = `--name <N>` OR `-d`/`--detach` (auto-names, printed). No `--persist`.
- Interactivity = `-t`/`--tty` (`-i` alias so `-it` parses). **Dev-only**, refused
  in `--prod`/sealed via `enforce_accessible_gate` (claim 15). `--tty` never
  affects persistence; `-it` alone = transient interactive (gone on shell exit).
- Default (no flags) = transient `run_secure`, byte-for-byte unchanged.
- Collision (named spec exists, different config) = **error** unless `--force`
  (stop + overwrite + restart).

**Key anchors (verify before editing):**
`crates/mvm-cli/src/commands/machine/mod.rs` (`MachineRunArgs`, `run()` dispatch,
`MachineSpec` create/load/save, `start_machine`, `shell_machine`/`exec_machine`),
`crates/mvm-cli/src/commands/vm/exec.rs` (`run_secure`, the output-only `Exec`
stream — leave unchanged), `console::run` (PTY attach to reuse), and
`enforce_accessible_gate` (claim 15 gate).

## Behavior matrix (the contract to test)

| Command | Persistent | Name | Interactive | Returns | Machine after |
|---|---|---|---|---|---|
| `run --image X -- cmd` | no | — | no | after cmd (streamed) | gone |
| `run -it --image X -- /bin/sh` (dev, TTY) | no | — | yes | on shell exit | gone |
| `run -it --prod --image X -- /bin/sh` | — | — | — | refused before boot | unchanged |
| `run --name web --image X -- cmd` | yes | web | no | after cmd (streamed) | up |
| `run -it --name web --image X -- /bin/sh` | yes | web | yes | on shell exit | up |
| `run -d --image X` | yes | auto, printed | no | after boot | up |
| `run -d --name web --image X` | yes | web | no | after boot | up |
| `run --name web` (exists, diff config) | — | — | — | error | unchanged |
| `run --force --name web ...` (diff config) | yes | web | per flags | per flags | recreated |

---

## Task 1: Flags + dispatch scaffolding (transient stays unchanged) — DONE

- [x] Add to `MachineRunArgs`: `--name <N>`, `-d`/`--detach`, `-t`/`--tty` (with
      `-i` as an accepted alias so `-it` bundles parse). Keep all existing
      transient flags intact.
- [x] **Free `-d` for `--detach`.** `machine run`'s host-dir share flag was
      `-d`/`--add-dir`, which collided with the locked `-d`=detach decision.
      Renamed it to **`--volume`** (long-only — `-v` is the global verbosity
      counter), matching the Docker `-v`/`--volume` mental model. Scoped to the
      `machine run` surface: the rename rippled to the three `machine` SDK
      builders (`mvm-sdk` `MachineRunBuilder::volume/volumes`, Python
      `_machine.py volumes=`, TS `_machine.ts volumes`) and the shared
      `sdks/machine-fixtures/run-admission.argv`. The lower-level
      `mvmctl run`/`exec --add-dir` is a different command and is left unchanged.
- [x] `argv` is no longer clap-`required` (persistent/interactive boot without a
      command); a plain transient run with no argv is refused at dispatch with a
      clear message.
- [x] Compute `persistent = name.is_some() || detach` and
      `interactive = tty || -i` once via `MachineRunArgs::{persistent,interactive}`;
      `tty` is **not** consulted for persistence. `resolve_mode()` maps the two
      axes to `MachineRunMode::{Transient,Persistent,InteractiveTransient,InteractivePersistent}`.
- [x] Branch `run()` → `run_dispatch`: `Transient` → `run_secure(into_run_args())`
      unchanged; `Persistent`/`Interactive*` → stubs (`bail!`) filled by Tasks 2/3.
- [x] Tests: `resolve_mode_covers_the_behavior_matrix` (every matrix row incl.
      `-it` bundling + `-i` alias), `transient_run_without_argv_is_rejected_at_dispatch`,
      and the flag-parse coverage. All mvm-cli + mvm-sdk suites green.

## Task 2: Persistent path (`--name` / `-d`, no `-t`)

- [ ] `run_persistent`: resolve name — given `--name`, use it; given bare `-d`,
      auto-generate via the existing transient `vm_name` generator / `mvm-core`
      ID helper (no second scheme). Surface the resolved name on stdout + `--json`.
- [ ] Create-or-reuse the `MachineSpec` (same struct `create` writes): absent →
      write; present + config matches → reuse; present + config differs → **error**
      with a clear message, unless `--force` → stop + overwrite + restart.
- [ ] Start if not already running — reuse `start_machine` and the liveness check
      `start`/`stop` already use against `machine_state_dir` (never double-boot).
- [ ] Post-start behavior: argv + no `-d` → `exec` it, stream, leave machine up;
      argv + `-d` → `exec` detached, return; no argv + `-d` → boot, print name,
      return; no argv + no `-d` → boot and print a hint pointing at
      `machine shell <name>`.
- [ ] Tests: same-config reuse vs different-config error vs `--force` reconcile;
      auto-name surfaced + reconnect by it through `machine shell`/`exec`/`stop`;
      no-double-boot when already running.

## Task 3: Interactive path (`-t`/`--tty`, dev-only)

- [ ] Route to `console::run` (the PTY path `machine shell` uses) against the
      just-booted VM. For the **transient** case (no name/detach) boot a throwaway
      VM, attach, and **tear it down on shell exit**; for the persistent case
      boot/reuse the named machine and **leave it up** on exit.
- [ ] Dev-only gate: refuse `--tty` under `--prod`, a sealed (dm-verity) image, or
      a non-`dev-shell` agent — **before boot** — via `enforce_accessible_gate`
      (claim 15). Clear error.
- [ ] Refuse `--tty` when host stdin is not a TTY, with a clear message (no hang).
- [ ] Tests: `--tty` refused for `--prod`/sealed via the gate; non-TTY stdin
      refused; transient-interactive selects teardown-on-exit, persistent-interactive
      leaves the machine up. (Live PTY round-trip is Task 5.)

## Task 4: Docs + claim integrity

- [ ] Update `public/src/content/docs/reference/cli-commands.md` for the new
      `machine run` flags and the three modes; add a troubleshooting note that a
      bare `run -- /bin/sh` is non-interactive by design and `-it` (dev) gives a
      shell.
- [ ] Confirm `xtask check-claim-catalog` stays green — this plan introduces no
      new claim; `-it` is an application of claim 15. No catalog edits expected.

## Task 5: Verification (dev-host bootable)

- [ ] On this macOS dev host (vz/libkrun): `machine run -it --image <dev-image>
      -- /bin/sh` drops into a live shell and tears the VM down on exit; capture
      the session.
- [ ] `machine run -d --name web --image <dev-image>` returns immediately, prints
      `web`, `machine ls` shows it, `machine shell web` reconnects, `machine stop
      web` tears down.
- [ ] `machine run -it --prod --image <sealed>` is refused before boot with the
      claim-15 error.
- [ ] `just ci` green (fmt --all, nextest, doctests, clippy -D warnings).

## Out of scope

- Idle auto-stop / TTL reaping of persistent machines (warm-pool/reaper work is
  the right home if wanted later).
- Any change to the `Exec` vsock transport, `run_secure`, or existing machine verbs.
