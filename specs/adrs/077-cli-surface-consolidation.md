# ADR-077 — CLI surface consolidation (grouped command namespaces)

**Status:** accepted 2026-06-10. Implemented by
`specs/plans/178-cli-surface-consolidation.md`. Cross-refs: ADR-012
(mvm-provider CLI contract — the mvmd/provider boundary, unaffected), ADR-066
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
ADR-076). The product's "no backwards compatibility — this is the first
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
- Independent of the backend work (ADR-076); safe to land in parallel with
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

- The mvmd/provider CLI contract (ADR-012) — a different surface.
- Adding new commands (e.g. cleanly surfaced `save`/`restore`) — that rides
  with the DX-parity follow-on once ADR-076's `vz` convergence lands.
