# ADR-027 — CLI surface consolidation (grouped command namespaces)

**Status:** accepted 2026-06-10. Implemented by
`specs/plans/178-cli-surface-consolidation.md`. Cross-refs: ADR-006
(mvm-provider CLI contract — the mvmd/provider boundary, unaffected), ADR-022
(target architecture). No security claim changes — command paths move, not
behavior.

## Context

`mvmctl`'s top-level `Commands` enum (`crates/mvm-cli/src/commands/mod.rs`)
carries **~56 flat verbs**. The flat namespace is the single largest source
of CLI cognitive load: there is no grouping, several internal subprocess
commands leak into the user-facing `--help`, and the "start and run
something" intent is spread across five overlapping verbs
(`up`/`run`/`exec`/`sandbox`/`invoke`). Well-regarded sibling tools in this
space present ~20 commands under a few noun groups and read as one cohesive
product; the gap between mvm and them is cohesion, not capability.

This is the CLI half of the feature-reduction effort (the backend half is
ADR-007). The product's "no backwards compatibility — this is the first
version" stance means commands can be renamed and regrouped hard, with no
alias layer.

## Decision

**Regroup + targeted merges.** Not a pure reorg (which keeps every verb), not
a ground-up redesign (which risks the claim command paths).

Keep the daily-driver verbs flat for ergonomics:
`run` `exec` `ls` `console` `down` `dev` `doctor` `init`.

Move the rest under noun groups (parent clap subcommand enums; the leaf
`Args`/`run()` are re-parented, not rewritten):

- `vm` — `pause` `resume` `snapshot` `save` `restore` `wait` `ttl` `diff`
  `logs` `fs` `proc` `cp` `invoke`
- `build` — `build` `compile` `validate` `kernel`
- `image` — `image` `catalog` `manifest` `artifact`
- `trust` — `sign` `bundle` `attest` `receipt` `audit` (+ existing `trust`)
- `storage` — `storage` `volume` `cache`
- `net` — `network` `forward`
- `secret` — unchanged
- `ops` — `metrics` `bench` `config` `mcp`

**Hide** the internal subprocess commands from `--help` (`#[command(hidden)]`):
`persistent-builder`, `boot-report`, `reconcile`, `shell-init`.
(`__qemu-vsock-bridge` is already hidden and stays — it is QEMU's vsock
transport for the surviving dev/test backend.)

**Rationalize the run-family** (`up`/`run`/`exec`/`sandbox`/`invoke`) into a
coherent few. These have genuinely different semantics — signed-`ExecutionPlan`
workload boot (claim-8 admission), transient-VM runner, and function-service
`--input` invoke — so the implementing plan MUST read each implementation
first and propose the exact collapse. The merge preserves claim-8 admission,
the transient-runner path, `--input name=value`, and the `--dev`/`--prod`
mode aliases exactly. No merge from memory.

## Consequences

- ~56 flat verbs → ~8 top-level + ~8 groups; internals off the user surface.
- Hard renames break muscle memory and any external scripts — acceptable
  under the no-backcompat stance, and the right time to pay it (first
  version). Docs (`public/.../cli-commands.md`, `CLAUDE.md` examples) update
  with the change.
- Independent of the backend work (ADR-007); safe to land in parallel with
  that plan's Phase 1.

## Alternatives considered

- **Pure regroup, no merges.** Keeps every capability but leaves the
  run-family confusion and does not reduce feature count — only half the goal.
- **Ground-up redesign around a minimal core.** Highest DX ceiling, but
  largest churn and highest risk to the 16 claims' command/audit paths.
  Rejected as disproportionate to the A/B pains.
- **Alias layer for old names.** Rejected — contradicts the no-backcompat
  stance and re-introduces surface to maintain.

## Out of scope

- The mvmd/provider CLI contract (ADR-006) — a different surface.
- Adding new commands (e.g. cleanly surfaced `save`/`restore`) — that rides
  with the DX-parity follow-on once ADR-007's HVF backend convergence lands.


## Consolidated from ADR-091 — Unified `machine run` lifecycle (transient / persistent / interactive)

**Status:** Proposed
**Date:** 2026-06-21
**Relates to:** [ADR-001](001-microvm-security-posture.md) (security posture, claim 15),
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
**sealed production** microVM is forbidden and CI-gated (claim 15, ADR-001 / Plan
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

### 4. Production lifecycle is entrypoint-driven; the guest never idles to "stay up"

A microVM always has an entrypoint (the user's workload), and it is preserved end
to end: the CLI/SDK/flake declare it, mkGuest bakes it to `/etc/mvm/entrypoint`,
and every backend — including the HVF/KVM VMM — boots `init=/init`, the
mkGuest PID-1 wrapper that runs the baked entrypoint. `init=/init` is never a
bypass; the entrypoint survives the boot path unchanged.

In **production** (a sealed image) the lifecycle is uniform and strict: PID 1 runs
the entrypoint and the VM **shuts down with the entrypoint's exit code** (captured
by `/init` and reported over the workload-exit vsock port). There is **no shell**
(claim 15) and **no guest-side "stay up regardless" idle**. We deliberately reject
the idle-keep-alive shape: a PID 1 that idles to hold a VM open after its workload
exited is a resource-consuming zombie that *hides* the failure behind a
still-"running" VM. A *persistent* production service stays up because its
entrypoint is long-running; when that entrypoint exits, the VM exits with the code
and **restart/persistence is the control plane's (mvmd) policy** — reconcile,
reschedule, or keep-for-postmortem — never a guest behavior. This keeps the guest a
pure workload runner and orchestration where it belongs.

Consequently `-d`/`--detach` (and the SDK's `MachineRun::detach()`, the host-side
counterpart added so SDK callers can request it too) are **host-side**: they
detach the caller and make the machine addressable by name; they introduce **no**
guest-side stay-up. The only stay-up conveniences — the *dev* image's idle PID 1
and on-demand `machine shell`/`exec` PTY — are dev-only by construction and remain
gated by claim 15 / `enforce_accessible_gate`. There is no production code path
that adds a shell or an idle keep-alive, and none should be added.

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


## Consolidated from ADR-092 — `machine` is the sole workload-VM CLI surface

**Status:** Proposed
**Date:** 2026-06-21
**Relates to:** [ADR-001](001-microvm-security-posture.md),
ADR-027 §"Consolidated from ADR-091",
[Plan 200](../plans/200-machine-ux-dx-layer.md),
[Plan 207](../plans/207-machine-run-unified-lifecycle.md)

## Context

`mvmctl --help` lists 28 top-level commands. Daily-driver workload lifecycle
sits in a flat list next to rarely-touched infrastructure, and — worse — the
same microVM lifecycle is reachable through **two parallel surfaces**:

- verb-first, project-shaped: `up`, `down`, `run`, `invoke`, `ls`, `logs`,
  `console`, and the `vm` sub-group (`pause`/`snapshot`/`cp`/`fs`/…);
- noun-first, Docker-shaped: `machine run`/`create`/`start`/`stop`/`exec`/
  `shell`/`ls`/`inspect`/`rm`, added by Plan 200.

These are **not** two runtimes. `machine` is a thin translation layer over the
same code: `machine run` → `vm::exec::run_secure`, `machine start` →
`vm::up::start_persistent_oci_machine`, `machine stop` → `vm::down::run`,
`machine shell`/`exec` → `vm::console::run`. The cost is entirely UX: a user
must learn which of two names operates on the one object, and the split runs
along the wrong axis. `up` versus `machine run` differs mainly in *image
source* (Nix flake/manifest vs OCI) and *audience muscle-memory* — neither of
which deserves a separate command tree. Lifecycle (transient / persistent /
interactive / operate-on-running) is the dimension users actually reason about,
and image source is properly a flag, not a noun.

Plan 200 deliberately framed `machine` as "a UX layer over mvm's existing
primitives, not a parallel runtime stack," and stopped short of touching
`up`/`down`. ADR-091 / Plan 207 then unified `machine run` itself into
transient / persistent / interactive modes. With that front door in place, the
verb-first surface no longer earns its keep — it only re-creates the split.

This ADR records the decision to finish the job: collapse to **one workload
noun**.

A second object is in scope only to keep it *out* of scope: `dev` (the builder
VM) is a genuinely different thing — host build substrate, not a workload — and
stays its own command. ADR-001 (consolidated from ADR-088) already draws that boundary.

## Decision

`machine` becomes the **sole** CLI surface for workload microVMs. Every
workload lifecycle and operate-on-running verb hangs off it; the verb-first
commands and the separate `vm` noun are **removed outright** (no aliases).

### 1. Image source is a flag, not a command

`machine run`, `machine create`, and `machine build` accept the source as a
flag over the path that already exists under the hood:

- `--image <ref>` → OCI path (pull + materialize ext4; no Nix).
- `--flake <path>` (or a discovered `mvm.toml`) → Nix build path inside the
  builder VM.

`machine build` is the explicit build step (today's `build image`), producing a
manifest/image that `machine run --image …` can consume. `machine run --flake .`
remains the one-step build-and-run. Source detection is exclusive: `--image`
selects OCI, `--flake`/manifest selects Nix; supplying both errors.

### 2. One noun, every verb — grouped, not split

`vm` is **not** a second noun. Its verbs fold into `machine`; its sub-groups
stay nested under it. `machine --help` is kept scannable with clap
`help_heading`s rather than by inventing another object:

- **Lifecycle:** `run` · `build` · `create` · `start` · `stop` · `rm`
- **Inspect:** `ls` · `logs` · `inspect` · `shell` · `exec`
- **Advanced:** `pause` · `resume` · `snapshot` · `save` · `restore` ·
  `checkpoint` · `cp` · `wait` · `set-ttl` · `forward` · `diff` ·
  `fs` · `proc` · `session` · `volume` · `sandbox`

This is the Docker model done literally: one noun, the overwhelm solved by
in-`--help` grouping, never by a parallel surface.

### 3. Verb→home mapping (removals)

| Removed top-level command | New home |
| --- | --- |
| `up` | `machine run --flake .` (`-d`/`--name` for persistent) |
| `down` | `machine stop` |
| `run` | `machine run` |
| `invoke` | `machine run --entrypoint` |
| `ls` | `machine ls` |
| `logs` | `machine logs <name>` |
| `console` | `machine shell` / `machine console` |
| `build image` | `machine build` |
| `vm <verb>` | `machine <verb>` (Advanced group) |

Unchanged: `build compile`/`validate`/`kernel` stay under `build` (build-time
SDK/kernel work, not VM lifecycle); `dev` stays separate (builder VM).

### 4. Infrastructure commands stay, but get a help heading

`dev`, `pool`, `cache`, `storage`, `doctor`, `init`, `secret`, `bundle`,
`trust`, `deps`, `artifact`, `network`, `manifest`, `catalog`, `image`, `ops`,
`env` remain. They move under an **Infrastructure / advanced** `help_heading`
so the top-level `--help` leads with the daily drivers (`machine`, `dev`,
`build`, `init`, `doctor`) instead of a flat 28-item wall.

### 5. Hard removal, no aliases

Consistent with the project's pre-1.0 "no backwards compatibility — first
version" rule, the removed verbs do **not** survive as hidden aliases. `--help`
advertises exactly one workload noun. Hidden aliases would preserve the
muscle-memory split this ADR is paying to delete, and a shim layer is debt with
no offsetting user we owe stability to yet.

## Consequences

**Positive**

- One object, one noun. A user learns `machine` and can reach every workload
  operation; there is no second name for the same thing.
- `--help` leads with ~5 daily drivers; the long tail is grouped, not gone.
- Image source becomes an honest flag; the Nix-vs-OCI distinction stops
  masquerading as a lifecycle distinction.
- No security/admission change: every path already routes through the signed
  `ExecutionPlan` admission and audit chain (claims 8–15 unaffected). This is a
  surface rename over unchanged enforcement.

**Negative / costs**

- High-churn rename. `up`/`run`/`down`/`vm` are referenced across specs, other
  in-flight branches, docs, examples, and the SDK machine wrappers; all must
  move in lockstep with the removal, since there are no aliases to soften it.
- `machine` grows large. Mitigated by `help_heading` grouping and the nested
  sub-groups (`fs`/`proc`/`session`/`volume`/`sandbox`), but a single noun
  carrying ~25 verbs is inherently heavier than the old split.
- Coordination with ADR-091 / Plan 207: this ADR sits *above* that work and
  assumes the unified `machine run` modes land first.

## Alternatives considered

- **Keep both surfaces (status quo / Plan 200 as written).** Rejected: it is
  exactly the two-name-for-one-object confusion that motivated this ADR.
- **Verb-first wins; delete `machine`.** Coherent, lower churn, but throws away
  the Docker-shaped onboarding `machine` was added to provide and keeps no
  single noun for the object. Rejected in favour of the friendlier, newer noun.
- **Keep `vm` as a second power-user noun.** Pragmatic (smaller `machine`
  `--help`), but re-introduces the split along a frequency seam instead of a
  muscle-memory seam — still two names for one running object. Rejected;
  grouping inside `machine` solves the overwhelm without a second noun.
- **Hidden aliases for a transition window.** Rejected under the pre-1.0
  no-backcompat rule; nothing yet depends on the old verbs that we owe
  stability.

## Sequencing

Land in waves rather than one mega-PR, each green and shippable:

1. **Prerequisite:** ADR-091 / Plan 207 unified `machine run` modes merge.
2. **Lifecycle fold-in:** retire `up`/`down`/`run`/`invoke`; `machine run`
   learns `--flake`/`--entrypoint`; `machine build` absorbs `build image`.
3. **Inspect fold-in:** retire `logs`/`console`; `machine logs`/`console`;
   confirm `machine ls` covers `ls --all`.
4. **Advanced fold-in:** retire the `vm` noun; its verbs/sub-groups move under
   `machine` with the Advanced `help_heading`.
5. **Help grouping:** apply `help_heading`s to top-level (Infrastructure group)
   and to `machine`'s subcommands (Lifecycle/Inspect/Advanced).

Each wave updates the affected specs, docs, examples, and SDK machine wrappers
in the same change. A follow-on implementation plan (next free plan number)
tracks the task-by-task, TDD breakdown; this ADR records only the decision.


## Consolidated from ADR-105 — SDK ↔ facade machine-driving convergence on the `MvmClient` trait

- Status: Proposed
- Date: 2026-07-01
- Owner: MVM Project
- Related: `specs/notes/mvm-client-facade-design.md` + Plan 216 (the `mvm-client` facade), ADR-001 (cloud control-plane trust boundary — the facade's remote path, consolidated from ADR-104), ADR-014 (signed audited execution plans — claim 8, the admission the local `run` path must not skip). Sequenced by: Plan 218.

## Update (2026-07-06): the trait lives in `mvm-core`, one user-facing crate

The original decision below put the trait + DTOs in a standalone `mvm-client`
crate and pushed `LocalBackend` into a second `mvm-client-local` crate to keep
the first `mvm-*`-free. Two crates, two imports (`mvm_client::{MvmClient, …}` +
`mvm_client_local::LocalBackend`) — confusing for consumers.

That two-crate split is replaced. The trait + DTOs + `MockBackend` + the remote
`GatewayBackend` now live in **`mvm-core::client`**, behind a `client` feature
(the gateway behind `client-remote`). `LocalBackend` and `connect` live in a
single user-facing **`mvm-client`** crate that re-exports the `mvm-core::client`
surface, so consumers write one import:

```rust
use mvm_client::{MvmClient, MachineSpec, LocalBackend};
```

**Why this is now the right home** — and why the "rejected: put it in
`mvm-core`" bullet below was mistaken: it claimed the `check-core-runtime-free`
gate "forbids pulling async runtimes there." The gate (`xtask
check-core-runtime-free`) only forbids **`tokio`**. `async-trait` is a
proc-macro (`proc-macro2`/`quote`/`syn`) that desugars async methods to boxed
futures — it pulls no async runtime — so gating it behind `client` keeps
`mvm-core`'s default closure `tokio`-free, and the guest-agent gate
(`check-guest-agent-runtime-free`, which *does* forbid `async-trait`) stays
green because the guest never enables the feature. The cycle the split existed
to avoid also dissolves: `mvm-core` is the foundation everyone already depends
on, so `mvm-sdk` reaches the trait via `mvm-core/client` with no new edge, and
`LocalBackend`'s `mvm-backend` dependency stays above the foundation in
`mvm-client`. `mvm-sdk`'s subprocess `SubprocessBackend` and the cycle guard
(`no_backend_dep.rs`) are unchanged in intent.

The prose below is the original (superseded) reasoning, kept for history.

## Context

There are **two** clients that drive local microVM lifecycle, with overlapping responsibility and different mechanisms:

- **`crates/mvm-sdk/src/machine.rs`** — a builder-based client (`MachineClient`, `Machine::{start, stop, exec, shell}`, `MachineRunBuilder{image, command, …}`) whose module doc says it *"deliberately shells to `mvmctl machine …`"* — it drives lifecycle by spawning the `mvmctl` subprocess.
- **`crates/mvm-client`** — the `MvmClient` facade: `list_machines` / `run_machine` / `stop_machine` / `machine_logs` over `LocalBackend` (in-process) or `GatewayBackend` (REST). Landed in Plan 216.

Both drive machines; the SDK reinvents it via subprocess. That is the repo's most common bug source (duplicated logic drifts) applied to a security-sensitive surface — the SDK's `run` and the facade's `run` both ultimately need the signed-plan admission (claim 8), and two separate drivers means two places to get admission right (or wrong).

### Why the SDK shells a subprocess — the constraint that shapes any fix

The dependency graph runs high→low:

```
mvm-client (local feature) → mvm-backend → mvm-build → mvm-sdk → mvm-core
```

`mvm-sdk` sits **below** the runtime. If the SDK linked `LocalBackend` (which pulls `mvm-backend`), the result is a cycle: `mvm-sdk → mvm-client(local) → mvm-backend → mvm-build → mvm-sdk`. The process boundary in `machine.rs` is a **deliberate** way to sidestep that cycle, not an oversight. Any convergence must respect it.

### The unlock

The trait + DTOs must live in a crate whose **manifest declares no `mvm-*` dependency at all**. A first attempt — `mvm-client` with `default-features = false` — **fails**: Cargo detects cycles on the *manifest* graph, **optional dependencies included**. Because `mvm-client`'s manifest declares `mvm-backend` (for the `local` feature), it forms a cycle regardless of features:

```
mvm-sdk → mvm-client → mvm-backend → mvm-build → mvm-network → mvm-sdk
```

(verified live: `cargo` refuses with `cyclic package dependency: mvm-backend depends on itself`). Turning the feature off does not help — the edge is in the manifest.

The real fix is structural: **extract `LocalBackend` (the only `mvm-backend`-linking piece) into a separate `mvm-client-local` crate.** Then `mvm-client` holds the trait + DTOs + `GatewayBackend` + `connect` and its manifest carries **zero `mvm-*` deps**, so `mvm-sdk` can depend on it freely. `mvm-client-local` sits *above* the runtime (it links `mvm-backend`) and is used by the CLI. `connect(Target::Local)` — which can no longer reach `LocalBackend` — directs callers to construct `mvm_client_local::LocalBackend` directly.

## Decision

Keep the two crates and their **distinct responsibilities** — `mvm-sdk` is *authoring* (the `Workload` IR: image, entrypoints, deps, resources, network, hooks), `mvm-client` is *operating* (drive machine lifecycle). Converge only the overlapping *"drive a machine"* mechanism onto the shared trait:

1. **One interface: `MvmClient`.** The trait + DTOs are the single machine-driving contract, in `mvm-client` — whose manifest carries no `mvm-*` dependency (`LocalBackend` moved to `mvm-client-local`). Every layer depends on that cycle-free crate for the contract.
2. **Three impls, one per layer's constraint:**
   - `LocalBackend` (in-process) — CLI. Needs the runtime; lives above it.
   - `GatewayBackend` (REST) — studio / remote. No runtime dep.
   - **A subprocess impl in `mvm-sdk`** — the SDK keeps shelling `mvmctl machine`, but *behind `MvmClient`*, so it satisfies the same contract while respecting the cycle.
3. **One spec vocabulary.** The SDK's `Workload`/`App` IR is the rich authoring definition; it **lowers** to the facade's operational `MachineSpec` (a projection: image/resources/env → the run spec). No second parallel spec type maintained by hand.
4. **One admission path.** When the admitted-boot library seam lands (issue #1388 / Plan 214), *both* `LocalBackend::run` and the SDK's subprocess `run` route through the **same** admitted-boot function. There is never a second, admission-skipping boot path — the property claim 8 protects.

## Consequences

- The SDK's bespoke `machine.rs` shrinks to an `MvmClient` impl + the authoring-side builders; its ad-hoc lifecycle surface stops being a parallel API.
- Callers (SDK live/invoke, CLI, studio) program against `MvmClient`, so swapping transport or moving a workload local↔remote is a backend choice, not a rewrite.
- `MachineSpec` gains a documented lowering from `Workload`; the two stop drifting.
- No dependency cycle is introduced: the shared surface is the runtime-free trait+DTOs; runtime-linking impls stay in the crates that already sit above the runtime.

## Alternatives considered

- **Make `mvm-sdk` depend on `LocalBackend`.** Rejected — introduces the `mvm-sdk → mvm-backend → mvm-build → mvm-sdk` cycle. The subprocess boundary exists precisely to avoid this.
- **Merge `mvm-sdk` and `mvm-client`.** Rejected — they are genuinely different responsibilities (authoring vs operating) at different points in the dep graph; merging would drag the runtime under the SDK.
- **Leave two drivers, document the overlap.** Rejected — the duplication is on the security-critical `run`/admission path; two drivers means two admission implementations to keep correct. Converging on one trait + one admitted-boot fn is the whole point.
- **Put the shared spec/trait in `mvm-core`.** Considered. The trait is async (`async-trait`); `mvm-core` is the runtime-free foundation and the `check-core-runtime-free` gate forbids pulling async runtimes there. Keeping the trait in `mvm-client` (default-features light) is the cycle-safe home; `mvm-core` may hold pure DTO structs if reuse warrants.

## Scope / sequencing (Plan 218)

- **P1** — `mvm-sdk` depends on `mvm-client` (`default-features = false`); add a subprocess `impl MvmClient` (list/stop/logs) that shells `mvmctl machine`. Additive; the existing builders stay.
- **P2** — Define the `Workload`/`App` → `MachineSpec` lowering; the SDK's run builder produces a `MachineSpec`.
- **P3** — Migrate SDK live/invoke call sites to the `MvmClient` trait; retire the duplicated bits of `machine.rs`.
- **P4** — When the admitted-boot seam lands, wire `LocalBackend::run` **and** the SDK subprocess `run` through the one admitted-boot library fn. Closes issue #1388 for the facade.

## Runbook: publishing the mvm SDKs (consolidated from specs/runbooks/publish-sdks.md)

# Runbook: publishing the mvm SDKs (PyPI + npm)

Publishes the Python SDK (`crates/mvm-sdk/python`, package **`mvm`**) and the
TypeScript SDK (`crates/mvm-sdk/typescript`, package **`mvm-sdk`**) to PyPI and
npm. Driven by `.github/workflows/publish-pypi.yml` and
`publish-npm.yml`, alongside the existing `publish-crates.yml`.

**Why these ship coupled to the toolchain:** the SDK emits the Workload
IR that the *same-version* `mvmctl` consumes (`launch.json`
`toolchain_version` == mvmctl `CARGO_PKG_VERSION`). Both workflows refuse
to publish unless the SDK version equals the release tag, so a published
SDK can never drift from the toolchain. Bump the SDK versions in the same
commit that bumps the toolchain.

## One-time setup (manual — outward-facing, do these first)

These claim public names and configure credentials; they can't be
automated from the repo.

### 1. Names + orgs

- **PyPI: `mvm`** under the **`runmvm`** PyPI org. The project already
  exists (latest `0.1.2`; history 0.1.0–0.1.2) — manage it from the
  `runmvm` org. The distribution name stays `mvm` and the import stays
  `import mvm` (PyPI orgs don't scope names).
- **npm: `@runmvm/mvm`** — a **scoped** package under the **`runmvm`**
  npm org. This is a rename from the old unscoped `mvm-sdk` (latest
  `0.1.2`), so `@runmvm/mvm` is a fresh package: the first publish
  creates it under the org. TS import becomes `from "@runmvm/mvm"`.
  Optionally retire the old name: `npm deprecate mvm-sdk "moved to
  @runmvm/mvm"`.

Local is `0.15.0`, not on either registry, so the first publish is a
clean bump (no duplicate-version rejection) that aligns the registries
with the toolchain. Re-check anytime:

```sh
curl -s https://pypi.org/pypi/mvm/json | python3 -c 'import sys,json;print(json.load(sys.stdin)["info"]["version"])'
curl -s https://registry.npmjs.org/@runmvm/mvm | python3 -c 'import sys,json;print(json.load(sys.stdin).get("dist-tags",{}).get("latest","(unpublished)"))'
```

### 2. PyPI — Trusted Publishing (no token)

The `mvm` project already exists, so add a **regular** trusted publisher
to it: PyPI → project `mvm` → **Manage** → **Publishing** → **Add a new
publisher** (GitHub):

- Owner: `tinylabscom`
- Repository: `mvm`
- Workflow name: `publish-pypi.yml`
- Environment: `pypi`

(No API token is stored — the workflow authenticates via OIDC.) Also
create a repo **Environment** named `pypi` (Settings → Environments) if
you want required reviewers gating publishes. If you'd rather not use
trusted publishing, drop a `PYPI_API_TOKEN` secret and swap the publish
step to `with: { password: ${{ secrets.PYPI_API_TOKEN }} }`.

### 3. npm — org + automation token

- Ensure the **`runmvm`** npm org exists and your account is a member
  with publish rights.
- Create a **granular automation token** scoped to publish under
  `@runmvm/*` (npm → Access Tokens → Granular → Packages and scopes →
  `@runmvm`).
- Add it as repo secret **`NPM_TOKEN`** (Settings → Secrets → Actions).
- The package is scoped, so the publish must be public — the workflow
  passes `--access public` and `package.json` sets
  `publishConfig.access = public`.

## Rehearse (safe, no upload)

Run each workflow via **Actions → Run workflow** with `dry_run: true`:

- PyPI: builds sdist+wheel, runs the version guard, **skips upload**.
- npm: `npm ci && npm run build && npm publish --dry-run` (no upload).

Fix anything that fails here before a real release.

## Publish (real)

Publishing is tied to a GitHub Release so crates + PyPI + npm go out
together at one version:

1. Bump versions in the **same commit**:
   - `crates/mvm-sdk/python/pyproject.toml` `version`
   - `crates/mvm-sdk/typescript/package.json` `version`
   - the workspace/toolchain version (`Cargo.toml`) — keep all three equal.
2. Tag + release:
   ```sh
   gh release create v0.15.0 --generate-notes
   ```
   The `release: published` event fans out to `publish-crates.yml`,
   `publish-pypi.yml`, and `publish-npm.yml`. Each asserts its package
   version equals `0.15.0` and refuses otherwise.
3. Verify:
   ```sh
   pip index versions mvm        # or: pip install mvm==0.15.0
   npm view @runmvm/mvm version
   ```

## Notes

- Both packages are pure (Python: zero runtime deps, hatchling; TS: tsc →
  `dist`), so there's nothing platform-specific to matrix.
- The SDKs are **host authoring tools** — they are never installed into a
  workload guest (the `@mvm.app` decorator is stripped from the bundled
  source at compile, see `crates/mvm-sdk/src/compile/strip_framework.rs`).
- For contributors working from a source checkout, prefer the editable
  install over the published package so the SDK always matches local
  HEAD (see the development guide).
