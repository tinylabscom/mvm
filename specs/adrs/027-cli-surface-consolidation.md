# ADR-027: `machine` is the sole CLI surface for workload microVMs

## Status

Accepted

## Context

A flat, ungrouped command list scales badly: every new capability adds
one more sibling to a wall of top-level verbs, several of which are
internal subprocess plumbing that has no business in `--help`, and
lifecycle actions on "a microVM" end up reachable through more than one
name for the same underlying operation. The product's pre-1.0
"no backwards compatibility — this is the first version" stance means
commands can be renamed and regrouped hard, with no alias layer to soften
the transition.

## Decision

### `machine` is the one workload-VM noun

Every workload lifecycle and operate-on-running-VM verb hangs off
`mvmctl machine`: `run`, `build`, `create`, `start`, `restart`, `stop`,
`reconfigure`, `rm`, `ls`/`ps`, `inspect`, `shell`, `exec`, `set-timeout`,
`logs`, `console`, `check-artifact` — plus every advanced single-VM
operation (pause, resume, snapshot, cp, fs, proc, session, volume,
sandbox, and the rest) flattened directly into the same subcommand list.
There is no separate `vm` noun; its verbs are `machine`'s verbs. There is
no `up`, `down`, `run` (as a top-level verb), `console`, or `invoke`
command — those names do not exist at the top level.

Two other top-level surfaces exist deliberately alongside `machine`,
because they are different objects: `dev` (host build substrate, not a
workload) and the SDK-only `run` transport, kept but hidden from
`--help`, retained solely because the Python/TS SDKs shell to it as their
launch mechanism — not a user-facing command.

### One listing, over every store

`machine ls` (alias `ps`) is the only listing verb. There is no top-level
`ls`.

A microVM is described by three stores and none is complete on its own:
the persisted spec registry (machines created by name), the VM name
registry, and the live per-backend state-dir scan. The historical split —
a top-level `ls` reading the live scan and a `machine ls` reading the spec
registry — meant neither command answered "what do I have?". A running
transient VM appeared only in the former, a stopped persistent machine
only in the latter, and the two listings shared no rows.

`machine ls` joins them by name and labels each row's `KIND`:

- **persistent** — backed by a spec, listed whether or not it is booted,
  because the spec is the only record that it exists.
- **transient** — live only (a `machine run`, a direct boot). It exists
  only while it runs, so a stopped one is leftover state and is hidden
  unless `--all` is passed.

`--json` keeps the shape SDK facades already parse: the persisted spec
flattened at the top level, with `status` (snake_case) and `build_mode`
beside it. `Sandbox.connect(id)` reads `build_mode` from this listing to
inherit the dev-only exec guard, so a transient row resolves it too and
fails closed to `prod`.

### Image source is a flag, not a command

`machine run`, `machine create`, and `machine build` accept the source
over the path that already exists: `--image <ref>` for the OCI pull +
materialize path, `--flake <path>` (or a discovered manifest) for the Nix
build-in-the-builder-VM path. The two are mutually exclusive at the flag
level. There is no separate command tree per image source.

### `machine run` unifies transient, persistent, and interactive lifecycles

Persistence and interactivity are independent, flag-selected axes on one
command, not separate verbs:

- **Persistence** is decided solely by `--name <N>` (persist under a
  chosen name) or `-d`/`--detach` (persist under an auto-generated name).
  With neither, `run` is the transient, non-interactive one-shot it has
  always been — booted, run, torn down.
- **Interactivity** is `-t`/`--tty`. It controls how the command attaches
  and is never consulted to decide persistence — `run -it` with no name
  and no detach is a transient interactive machine, live only for the
  shell's lifetime.
- `-t`/`--tty` is dev-only: it requires dev mode, a dev-shell guest agent,
  and a host TTY, and is refused up front — before boot — against
  `--prod` or a sealed image. This is the same sealed-interactivity
  invariant that gates `mvmctl console` everywhere else; unifying the
  lifecycle verbs does not relax it.
- `--entrypoint` calls the image's baked `/etc/mvm/entrypoint` (the
  function-call path) instead of running an argv command, and can target
  an already-running named machine instead of booting a fresh one.

### Hidden internals, visible daily drivers

`machine`, `build`, `kernel`, `init`, `doctor`, plus a handful of
reporting verbs (`explain`, `prepare`, `pack`, `bootstrap`) are the
visible top-level surface. Every other historical top-level command —
`env`, `manifest`, `image`, `storage`, `ops`, `network`, `catalog`,
`cache`, `pool`, `reconcile`, `secret`, `bundle`, `trust`, `deps`,
`artifact`, and internal subprocess transports (`shell-init`,
`persistent-builder`, the QEMU vsock bridge) — is
marked hidden. They still work; they simply do not compete for attention
in `--help`.

### Hard removal, no aliases

Renamed and removed verbs do not survive as hidden aliases. This follows
directly from the pre-1.0 no-backward-compatibility stance: a shim layer
would preserve exactly the muscle-memory confusion this consolidation
exists to remove, in exchange for debt owed to no user yet.

### One client contract behind both the CLI and the SDK

The trait that drives machine lifecycle — list/run/stop/logs and the rest
— lives once, as `MvmClient` in `mvm-core::client` (behind a `client`
feature, so the contract itself carries no runtime dependency). Two
implementations satisfy it: `LocalBackend`, which drives this host's
microVMs in-process and is what `mvm-client`'s `connect(Target::Local)`
returns; and `GatewayBackend`, a REST client reachable only when the
`remote` feature is enabled. `mvm-client` is the single user-facing crate
that re-exports the trait, the DTOs, and both backends, so a consumer
writes one import regardless of transport.

The SDKs do not yet consume this trait directly: `mvm-sdk`'s
`MachineClient` still deliberately shells out to `mvmctl machine ...` as
a subprocess, because `mvm-sdk` sits below the runtime in the dependency
graph and linking `mvm-client`'s local backend directly would form a
cycle. The trait's relocation to the cycle-free `mvm-core::client` module
exists specifically to make that convergence possible without breaking
the dependency direction; the SDK's call sites migrating onto it is
follow-on work, not yet done.

## Consequences

- One object, one noun: a user learns `machine` and reaches every
  workload operation through it; there is no second name for the same
  running VM.
- The daily-driver `--help` surface is short; the long tail is hidden,
  not deleted — every hidden command still works when named explicitly.
- No admission or audit change: every `machine` verb already routes
  through the same signed-`ExecutionPlan` admission and audit chain as
  before this consolidation. This ADR is a surface rename over unchanged
  enforcement.
- High-churn rename: any script, doc, or example that names the old
  top-level verbs (`up`, `down`, `vm <verb>`, a bare `run`) breaks with no
  transition alias, by design.
- A single noun carrying dozens of verbs is inherently a large `--help`
  tree; the mitigation is `display_order`/grouping inside `machine`, not
  a second noun.

## Alternatives considered

- **Keep the flat, ungrouped surface.** Rejected: it is the confusion this
  ADR exists to remove.
- **Keep a separate `vm` noun for advanced operations.** Rejected:
  re-introduces two names for one running object along a frequency seam
  instead of solving the overwhelm within one noun.
- **Hidden aliases for a transition window.** Rejected under the pre-1.0
  no-backward-compatibility rule — nothing depends on the old verbs that
  is owed stability yet.
- **Teach the transient runner's transport to carry stdin/PTY instead of
  reusing the existing console path for `-t`/`--tty`.** Rejected: would
  create a second interactive transport to audit against the sealed-
  interactivity invariant, for no benefit over the console path already
  in place.
