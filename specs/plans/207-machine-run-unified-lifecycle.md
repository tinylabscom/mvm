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

## Task 2: Persistent path (`--name` / `-d`, no `-t`) — DONE

- [x] `run_persistent`: resolve name via `resolve_machine_run_name` — `--name`
      used verbatim; bare `-d` auto-names via `auto_machine_name()` =
      `mvm_core::naming::generate_instance_id()` (one scheme, valid VM name). The
      name is surfaced on stdout (`start_machine` line + a bare-name last line for
      `-d`) and in `--json`.
- [x] Create-or-reuse via `resolve_persistent_spec` + `reconcile_machine_spec`:
      absent → `Create` (write); same launch config → `Reuse`; different config →
      **error** (`machine 'N' exists with a different config; pass --force …`)
      unless `--force` → `Recreate` (stop running + overwrite). `--image`-less
      invocations are a pure reconnect to the on-disk spec.
- [x] `machine_config_matches` compares only boot-affecting fields, ignoring
      runtime metadata (resolved digest / timestamps) so a restart never trips a
      false collision.
- [x] Start only if not already running — `machine_is_running` (backend
      `status` = `kill(pid,0)`-cheap) guards a double-boot; otherwise reuse
      `start_machine`.
- [x] Post-start (`run_persistent_post_start`): argv → `wait_for_guest_agent` +
      `console::run` exec (streamed, machine left up); no argv + `-d` → print the
      name; no argv + no `-d` → print a `machine shell <name>` hint.
- [x] Tests: reconcile create/reuse/error/force; config-match ignores metadata;
      run-spec field mapping; auto-name validity; `--image`-less reconnect +
      missing-machine error. (Live reconnect through `shell`/`exec`/`stop` is
      Task 5.)

### deferred follow-ups

- [ ] `--volume` host-directory shares on a managed boot (persistent **or**
      interactive). The `MachineSpec` boot path carries no bind-share field, so
      `reject_volume_for_managed_boot` refuses `--volume` with `-d`/`--name`/`-t`;
      it rides the plain transient `run_secure` path only. Persisting/re-materializing
      a bind-share for these lifecycles needs its own design (host-path drift); no
      behavior-matrix row depends on it. Interactive (`-t`) bind-shares are the
      most likely first extension (Docker `run -it -v $PWD:/app` parity).

## Task 3: Interactive path (`-t`/`--tty`, dev-only) — DONE

- [x] `run_interactive` boots (or reconnects to) the machine via the **shared**
      `persist_and_boot_machine` (same managed path as the persistent lifecycle —
      `run_persistent` was refactored onto it), then attaches a PTY via
      `console::run` (`command: None` ⇒ shell). Transient (no name/`-d`) →
      **tear down on exit** (`stop_running_machine` + drop the throwaway spec);
      persistent → **left up**. The decision is `should_teardown_after_interactive`
      = `!persistent`.
- [x] Dev-only gate: `enforce_accessible_gate` (claim 15, now
      `pub(in crate::commands)`) is called **before boot** for an existing
      machine; a fresh boot is re-checked by `console::run` post-boot. The
      recreate `--force` is deliberately **not** threaded into the gate, so it
      cannot bypass claim 15. (`machine run` has no `--prod` flag — it is
      dev-tier; the sealed-image/non-`dev-shell`-agent triggers are the relevant
      ones.)
- [x] `require_tty(stdin_is_tty)` refuses a non-TTY stdin up front with a clear
      message — no hang. Call site reads `std::io::stdin().is_terminal()`.
- [x] Tests: `interactive_requires_a_host_tty`,
      `interactive_tears_down_only_the_transient_machine`,
      `interactive_refuses_a_sealed_machine_via_the_claim15_gate`. (Live PTY
      round-trip is Task 5.)

## Task 4: Docs + claim integrity — DONE

- [x] `public/src/content/docs/reference/cli-commands.md`: documented the three
      `machine run` lifecycles (transient / persistent / interactive), the
      `--name`/`-d`/`-t`/`-i` flags, the independence of persistence vs
      interactivity, the `--volume` rename + bind-share-only-on-transient note,
      and added behavior-matrix example rows.
- [x] `public/src/content/docs/guides/troubleshooting.md`: added a "Machine Run
      Issues" note explaining that a bare `run -- /bin/sh` is non-interactive by
      design and `-it` (dev-only) gives a shell. Remaining `--add-dir` doc
      references belong to the lower-level `mvmctl up`/`run` and are unchanged.
- [x] `xtask check-claim-catalog` clean (16 claims, 39 witnesses) — no new claim;
      `-it` is an application of claim 15, no catalog edits. `xtask
      check-spec-numbers` clean (207/091 unique).

## Task 5: Verification (dev-host bootable) — DONE

- [x] **`-d` persistent boot round-trip (live, macOS Vz).** `machine run -d
      --image alpine` booted in ~5s on a warm cache, printed its auto-name
      (`i-642dc34e`), and returned; `machine ls` listed it; `machine exec --name
      <N> -- echo hello-from-guest` reconnected and printed `hello-from-guest`
      from inside the guest (proving the machine genuinely booted and the
      `console::run` reconnect transport works); `machine stop <N>` tore it down
      cleanly. The same `exec` transport backs the interactive shell, so the
      interactive path's plumbing is exercised here.
- [x] **`-t`/`--tty` gates fire (live).** `machine run -it --image alpine --
      /bin/sh` under non-TTY stdin refuses fast with
      *"interactive `-t`/`--tty` needs a terminal on stdin…"* — no hang. The
      literal interactive keystroke loop needs a real terminal, so it is not
      runnable headless; the sealed-image refusal (claim 15) needs a sealed image
      and is covered by the `enforce_accessible_gate` unit tests
      (`console_refused_on_sealed_image`). `machine run` has no `--prod` flag —
      the dev-only gate keys off the sealed/`dev-shell` posture, not a flag.
- [x] **Persistent dispatch + admission (live, `--dry-run`).** `machine run
      --name <N> --image alpine --dry-run` resolves the spec, OCI digest, and the
      deny-all / flow-drop admission posture without booting.
- [x] `just ci` green — fmt --all clean, clippy -D warnings clean, doctests pass,
      full nextest suite passes. (One unrelated `mvm-hostd` broker-UDS test flaked
      under parallel load and passes in isolation; not touched by this change.)

## Post-merge regression: interactive PTY data port never reachable on Vz/libkrun

Task 5 verified the `-d` boot over the **agent-port `Exec` transport** and the
`-t` TTY refusal gate, but assumed (line above) the exec transport "backs the
interactive shell, so the interactive path's plumbing is exercised here." That
was wrong: the interactive PTY uses a **second** transport leg. `ConsoleOpen`
returns a dynamic data port (`CONSOLE_PORT_BASE + session_id`, e.g. 20001) and
the host then connects to it — a different socket than the agent port. The
per-port-UDS backends (Vz, libkrun) bind only a *static* vsock port list at
boot (`vsock.ports = [GUEST_AGENT_PORT]`), so that data-port socket never
existed and every `machine run -t` / `machine shell` / `up --console` attach
failed with `Failed to connect to console data port … No such file or
directory`. Firecracker was unaffected (it multiplexes all ports over one UDS).

Fixed: `VmStartConfig.dev_console` pre-opens the bounded console data range
(`mvm_guest::vsock::dev_console_data_ports()`, 128 ports — the same range the
builder VM already opens) on the per-port-UDS backends. `cmd_run` sets it from
`--console`; `start_persistent_oci_machine` sets it `true` so managed machines
stay shell-able for their whole life. Claim 15 is unchanged — the dev-shell
agent + `enforce_accessible_gate` still bar a sealed prod guest, leaving the
listeners inert there. Live-proven on macOS Vz: a managed alpine boot binds
`vsock-20001.sock`…`vsock-20128.sock` and the guest agent answers.

## Out of scope

- Idle auto-stop / TTL reaping of persistent machines (warm-pool/reaper work is
  the right home if wanted later).
- Any change to the `Exec` vsock transport, `run_secure`, or existing machine verbs.
