# `machine run` — unified transient / persistent / interactive lifecycle

**Status:** design, approved 2026-06-21. Implementation plan to follow in `specs/plans/`.

## Problem

`machine run --image alpine -- /bin/sh` silently exits instead of giving a shell.
It is not a crash: `machine run` is the one-shot *transient* runner
(`machine/mod.rs` → `vm::exec::run_secure` → the guest agent `Exec` over vsock).
That transport is output-only — it streams `ExecEvent::Stdout`/`Stderr` back to the
host and never forwards host stdin or allocates a PTY. So `/bin/sh` gets EOF on
stdin, exits `0`, the VM tears down, and `mvmctl` returns `0` with no output.

Two capabilities are missing, both present in comparable microVM tooling:

1. A **persistent** machine without the `create` → `start` → `shell` three-step
   ceremony — one command that boots a machine, leaves it running, and is
   reconnectable by name.
2. An **interactive** shell from a single `run` invocation (the original
   complaint), which the `Exec` stream fundamentally cannot provide.

## Goal

One front door — `machine run` — that covers three modes selected entirely by
flags, while leaving every existing verb (`create`/`start`/`shell`/`exec`/
`stop`/`ls`/`inspect`) and the transient `run_secure` path unchanged.

## Design

### Three orthogonal axes

| Axis | Flag | Meaning |
|---|---|---|
| Persistence | `--name <N>` / `-d`, `--detach` | machine survives after the command; named, or auto-named |
| Interactivity | `-t`, `--tty` (`-i` accepted as alias so `-it` parses) | attach a PTY shell — **dev-only** |
| Default | (no flag) | transient, non-interactive — today's `run_secure`, untouched |

`--name` and `-d`/`--detach` both imply persistence; they differ only in naming
and whether the command blocks. There is deliberately **no** standalone
`--persist` flag — it would be redundant with `--name` and silent on the
blocking question. `-d`/`--detach` is the canonical persistence-without-a-name
flag (matches the universal `-d` idiom and carries the "hand me back my prompt"
lifecycle meaning).

### Dispatch inside `machine run`

Persistence and interactivity are **independent axes**. Persistence is computed
once from the flags; `--tty` never affects it — it only decides *how the command
attaches*. Whether a machine is torn down is decided by persistence alone:

```
let persistent  = args.name.is_some() || args.detach;   // --tty is NOT consulted here
let interactive = args.tty;                              // dev-only

if interactive {
    // attach a PTY shell (boot transient, or boot/reuse the named/detached one)
    boot-or-reuse VM; console::run(...);
    on exit: tear down  iff !persistent          // -it alone => transient => gone
} else if persistent {
    create-or-reuse spec + start + maybe exec;   // leave up
} else {
    run_secure(...)                              // unchanged transient one-shot
}
```

So `-it` with neither `--name` nor `-d` is a **transient** interactive machine —
it exists only for the life of the shell.

The interactive and persistent paths **compose existing building blocks** — they
introduce no new lifecycle code:

- **Auto-name:** reuse the transient `vm_name` generator / `mvm-core` ID helper;
  no second naming scheme. Surface the chosen name on stdout and in `--json`.
- **Spec creation:** the persistent path writes the same `MachineSpec` that
  `machine create` writes today.
- **Boot:** the persistent path boots through `start_machine` exactly as
  `machine start` does — same signed-`ExecutionPlan` admission, same
  default-deny egress. No new trust surface.
- **Reconnect/teardown:** `machine shell <name>`, `machine exec <name>`,
  `machine stop <name>`, `machine ls`, `machine inspect <name>` already key off
  the on-disk `MachineSpec` by name, so an auto-generated name plugs straight in.
- **Interactive attach:** reuse `console::run` (the PTY-over-vsock path
  `machine shell` already uses), pointed at the just-booted VM.

### `-t`/`--tty` is dev-only — the security contract

Interactive access requires **dev mode** + a **dev-shell guest agent** + a host
TTY. It reuses `enforce_accessible_gate` (claim 15: no interactive access to a
sealed production microVM).

- `machine run -it --image <dev-image> -- /bin/sh` on a TTY → drops into a shell.
- `--prod`, or a sealed (dm-verity) image, or an agent built without the
  `dev-shell` console symbol → **refused up front, before boot**, with a clear
  error. Claim 15 stays intact and CI-gated.

This is not a removable limitation; it is the posture. It aligns cleanly:
interactive shells are a dev affordance, which is exactly when the flag is used.

### Create-or-reuse collision

When `machine run --name web` targets a name whose on-disk `MachineSpec` already
exists but with a **different** config (image / cpus / memory / profile / …):

- Default → **error**: `machine 'web' exists with a different config; pass
  --force to recreate, or use a different name`.
- `--force` → stop, overwrite the spec, restart with the new config.

Silently ignoring the new flags, or silently destroying machine state, are both
footguns and are rejected.

### Behavior matrix (the contract to test)

| Command | Persistent | Name | Interactive | Returns | Machine after |
|---|---|---|---|---|---|
| `run --image X -- cmd` | no | — | no | after cmd (streamed) | gone |
| `run -it --image X -- /bin/sh` (dev, TTY) | no | — | yes | on shell exit | gone |
| `run -it --prod --image X -- /bin/sh` | — | — | — | **refused before boot** | unchanged |
| `run --name web --image X -- cmd` | yes | web | no | after cmd (streamed) | up |
| `run -it --name web --image X -- /bin/sh` | yes | web | yes | on shell exit | up |
| `run -d --image X` | yes | auto, printed | no | after boot | up |
| `run -d --name web --image X` | yes | web | no | after boot | up |
| `run --name web` (exists, diff config) | — | — | — | **error** | unchanged |
| `run --force --name web ...` (diff config) | yes | web | per flags | per flags | recreated |

### Explicitly unchanged

- `create` / `start` / `shell` / `exec` / `stop` / `ls` / `inspect`.
- The transient `run_secure` path — byte-for-byte; existing tests stay green.
- The signed-`ExecutionPlan` + default-deny-egress posture on every boot.

## Out of scope

- Idle auto-stop / TTL reaping of persistent machines (separate concern; the
  warm-pool/reaper work already in flight is the right home if wanted later).
- Any change to the `Exec` vsock transport itself — interactivity goes through
  the existing PTY console, not by teaching `Exec` to carry stdin.

## Testing focus

- CLI parse tests for every flag combination in the matrix (incl. `-it`
  short-flag bundling and the `-i` alias).
- Dispatch unit tests: `--tty` → interactive, name/`-d` → persistent, neither →
  `run_secure` (assert the transient path is selected unchanged).
- Collision: same-config reuse vs different-config error vs `--force` reconcile.
- Security: `--tty` refused for `--prod` / sealed image via
  `enforce_accessible_gate`; refused when stdin is not a TTY with a clear message
  (no hang).
- Auto-name surfaced on stdout + `--json`; reconnect by the generated name works
  through `machine shell`/`exec`/`stop`.
