# ADR-027: `machine` is the workload-microVM noun, and `run` is its one-shot

## Status

Accepted. Amended 2026-08-17: `run` is a first-class visible top-level
verb, and the hidden/visible split is restated as three buckets with a
gate. See "`run` is a first-class transient verb" and "Three visibility
buckets, and the cost of hiding".

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
no `up`, `down`, `console`, or `invoke` command — those names do not
exist at the top level.

`run` is the exception, and it is a deliberate one: see
"`run` is a first-class transient verb" below. `dev` (host build
substrate, not a workload) is the other top-level surface that exists
alongside `machine` because it is a different object.

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

### `run` is a first-class transient verb (amendment)

`mvmctl run <command>` is a visible top-level verb: the lowest-friction
path to "run this once in a fresh microVM." `mvmctl machine run` remains
visible as its noun-grouped sibling. They are not two implementations and
not an alias pair — the intent is one argument struct consumed by both,
so there is no second name for a second behaviour.

This does not reopen the wall of verbs. `run` earns its place by being
the single most common thing anyone asks the tool to do, and by having
been documented as the flagship in the CLI reference for long enough that
hiding it was the drift, not the discipline. Every other lifecycle verb
stays under `machine`.

### Three visibility buckets, and the cost of hiding

The original rule — daily drivers visible, everything else hidden — was
applied until `--help` no longer described the product. `secret`,
`trust`, `image`, `catalog`, `cache`, `network`, `bundle`, `deps`,
`artifact`, `pool`, `env` and `manifest` were all hidden while the
published CLI reference documented them; a user could not discover
`mvmctl secret set` (the entry point to the whole substitution subsystem)
or `mvmctl trust receipt verify` (the verification half of the receipt
feature) from the tool itself. A verb a user cannot discover is a verb
they do not have.

Verbs sort into three buckets:

- **Visible.** Anything a user is expected to invoke: `machine`, `run`,
  `build`, `kernel`, `deploy`, `generate`, `template`, `init`, `doctor`,
  `bootstrap`, the reporting verbs (`explain`, `prepare`, `watch`,
  `pack`), and the object groups `env`, `manifest`, `image`, `catalog`,
  `cache`, `network`, `pool`, `secret`, `trust`, `bundle`, `artifact`,
  `deps`, `ops`, `shell-init`. Grouped by `display_order` so `--help`
  reads in tiers rather than alphabetically.
- **Dev tooling.** Real commands that a user is not expected to reach
  for, and whose absence from `--help` costs them nothing:
  `seccomp-audit`, `storage`, `reconcile`, `dashboard`,
  `persistent-builder`.
- **Internal transports.** Subprocess plumbing, named with a `__` prefix
  so it cannot be typed by accident: `__sdk-no-vm`,
  `__builder-vm-bootstrap`, `__builder-egress-supervisor`,
  `__builder-shell-job`, `__qemu-vsock-bridge`.

`xtask check-cli-help-matches-docs` holds the visible bucket and
`public/src/content/docs/reference/cli-commands.md` to each other in both
directions: a documented verb must be visible, and a visible verb must be
documented. Hiding a verb to avoid writing its reference row therefore
also deletes it from `--help` — the escape has a price, which is what
stops this drift from returning silently.

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
