# ADR-092 — `machine` is the sole workload-VM CLI surface

**Status:** Proposed
**Date:** 2026-06-21
**Relates to:** [ADR-002](002-microvm-security-posture.md),
[ADR-091](091-unified-machine-run-lifecycle.md),
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
stays its own command. ADR-088 already draws that boundary.

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
