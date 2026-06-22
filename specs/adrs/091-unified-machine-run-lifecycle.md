# ADR-091 — Unified `machine run` lifecycle (transient / persistent / interactive)

**Status:** Proposed
**Date:** 2026-06-21
**Relates to:** [ADR-002](002-microvm-security-posture.md) (security posture, claim 15),
[Plan 165](../plans/165-entrypoint-presence-and-sealed-interactivity.md) (sealed interactivity / claim 15),
[Plan 207](../plans/207-machine-run-unified-lifecycle.md) (implementation),
design note `specs/notes/2026-06-21-machine-run-unified-lifecycle-design.md`.

## Context

`machine run --image alpine -- /bin/sh` silently exits instead of giving a shell.
That is not a crash: `machine run` is the one-shot **transient** runner
(`commands/machine/mod.rs` → `vm::exec::run_secure` → the guest agent `Exec` RPC
over vsock). The `Exec` transport is output-only — it streams
`ExecEvent::Stdout`/`Stderr` to the host and never forwards host stdin or
allocates a PTY. So `/bin/sh` reads EOF, exits `0`, the VM tears down, and
`mvmctl` returns `0` with no output.

Two capabilities common to comparable microVM tooling are missing:

1. A **persistent** machine without the `create` → `start` → `shell` three-step
   ceremony — one command that boots, leaves the machine running, and is
   reconnectable by name.
2. An **interactive** shell from a single `run` invocation — which the `Exec`
   stream fundamentally cannot provide.

The naïve fix — teach `Exec` to carry stdin/PTY, or auto-attach a shell whenever
`/bin/sh` is passed — collides with the security posture: interactive access to a
**sealed production** microVM is forbidden and CI-gated (claim 15, ADR-002 / Plan
165). Any solution must keep that invariant intact.

## Decision

Make `machine run` a single front door over **three orthogonal, flag-selected
axes**, composing the existing machine verbs rather than adding new lifecycle
code.

### 1. Persistence and interactivity are independent axes

- **Persistence** is decided *solely* by `--name <N>` or `-d`/`--detach`.
  `--name` persists under a chosen name; `-d` persists under an auto-generated
  name (printed to stdout and `--json`). There is **no standalone `--persist`**
  flag — it would be redundant with `--name` and silent on the blocking question.
- **Interactivity** is `-t`/`--tty` (with `-i` accepted as an alias so the
  familiar `-it` bundle parses). It controls *how the command attaches*; it is
  **never consulted to decide persistence**.
- With neither persistence nor interactivity flag, `run` is the transient,
  non-interactive one-shot it is today — `run_secure`, byte-for-byte unchanged.

Concretely: `run -it -- /bin/sh` (no name, no detach) is a **transient**
interactive machine — it lives only for the life of the shell and is torn down on
exit. Adding `--name`/`-d` is the *only* thing that keeps a machine alive.

### 2. `-t`/`--tty` is dev-only and reuses the existing PTY path

Interactive access goes through `console::run` (the PTY-over-vsock path
`machine shell` already uses), pointed at the just-booted VM — **not** by
extending `Exec`. It requires dev mode + a `dev-shell` guest agent + a host TTY,
and is gated by the existing `enforce_accessible_gate` (claim 15). `--prod`, a
sealed (dm-verity) image, or an agent built without the console symbol →
**refused up front, before boot**, with a clear error. Non-TTY stdin with `-t` →
clear error rather than a hang.

### 3. Persistence composes existing verbs; collisions fail closed

The persistent path writes the same `MachineSpec` that `machine create` writes,
boots through `start_machine` (same signed-`ExecutionPlan` admission + default-deny
egress as `machine start`), and is reconnectable through the existing
`machine shell`/`exec`/`stop`/`ls`/`inspect` (which already key off the on-disk
spec by name). Auto-names reuse the transient `vm_name` generator — no second
naming scheme.

When `--name <N>` targets an existing spec with a **different** config, `run`
**auto-recreates** the machine (stop the old instance, overwrite the spec,
reboot), announced loudly on stderr naming the changed fields. *(Superseded: this
originally errored-unless-`--force`. The convergent model won — a machine is
defined by its config, so a config change converges to a fresh machine like
`compose up`; durable data belongs in `--volume` host shares that live on the
host and survive the recreate, so recreating loses nothing that matters. The
loud notice keeps an unintended clobber, e.g. a typo'd `--image`, observable;
silently ignoring the new flags is still rejected.)*

## Consequences

- The original command works in dev (`run -it --image <dev-image> -- /bin/sh`
  → a shell) and is explicitly refused in prod — claim 15 is preserved, not
  weakened, and its CI gate is untouched. This ADR introduces **no new claim**;
  it is an application of claim 15.
- No change to the `Exec` vsock transport, `run_secure`, or any existing machine
  verb. Existing tests stay green; the new surface is additive.
- One mild non-orthogonality remains by design: `-t`/`--tty` is dev-only while
  persistence is not, so `run -it --prod --name web` is refused for the `-it`
  even though the persistent part would be valid. This is acceptable — the user
  is asking for an interactive prod shell, which is the thing claim 15 forbids.
- Idle auto-stop / TTL reaping of persistent machines is **out of scope**; the
  in-flight warm-pool/reaper work is the right home if wanted later.

## Alternatives considered

- **Auto-detect interactivity from a TTY** (no `-it` flag). Rejected: the same
  command would behave differently interactively vs piped, and an explicit flag
  is the established idiom; the dev-only gate is also clearer when the intent is
  explicit.
- **A separate `machine up` verb** for the persistent path. Rejected: a single
  front door (`run`, mode chosen by flags) is the DX target; `up` would split the
  mental model and duplicate flag surfaces.
- **Teach `Exec` to carry stdin/PTY.** Rejected: it would create a second
  interactive transport to audit against claim 15, for no benefit over the
  existing PTY console.
