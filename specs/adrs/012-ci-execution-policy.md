# ADR-012: CI execution policy — push runs a lean lane; the full matrix and release gates are separately triggered

## Status

Accepted.

## Context

A push with no PR open still needs fast feedback, and every push
shouldn't pay for platform lanes (macOS, live KVM), OCI ratification, or
a dependency audit that only need to run before a release or on
deliberate request. Heavy, expensive lanes running on every push slow
down day-to-day iteration for no proportional benefit.

## Decision

### Triggers, by workflow

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | `push` (any branch, excluding merge-queue transient refs) + `merge_group` + `workflow_dispatch` | day-to-day signal on every push; a required merge-queue check |
| `architecture.yml` | `push: main` + `pull_request` + `merge_group` + `workflow_dispatch` | structural/architectural invariants; a required merge-queue check |
| `ci-full.yml` | `workflow_dispatch` only | the full platform + live-VM + OCI-ratification matrix; operator-triggered, never automatic |
| `security.yml` | `push: tags: v*` + nightly cron + `workflow_dispatch` | dependency audit / advisory scan; release-time backstop plus nightly catch for new advisories |
| `windows.yml` | `push: tags: v*` + `workflow_dispatch` | non-blocking informational Windows build check; never a required check |
| `release.yml` | `push: tags: v*` | builds and publishes release artifacts |

### `ci.yml` is capped at four jobs

`lint` (fmt, clippy, and the full battery of `xtask` architectural
checks — see ADR-010), `test` (the workspace nextest run),
`mcp-server-smoke`, and `nix-flake-check`. Nothing
platform-specific (macOS, live KVM, Windows) or slow (OCI ratification,
dependency audit, the full builder-VM image build) runs on every push —
those live in `ci-full.yml`, run only by explicit `workflow_dispatch`.

### The merge queue's required checks

`ci.yml` and `architecture.yml` are the only two workflows that run on
`merge_group`, making them the required checks a PR must pass before it
merges. `ci-full.yml`, `security.yml`, and `windows.yml` are not part of
the merge-queue gate.

### Pre-commit hook (`.githooks/pre-commit`)

Activated via `git config core.hooksPath .githooks`, it runs on every
local commit: `cargo fmt --all` (auto-fixes and re-stages), then
`cargo clippy --workspace --all-targets -- -D warnings` — the same
`-D warnings` gate CI enforces, skippable per-commit via
`MVM_SKIP_CLIPPY=1` for fast iteration (CI still gates the merge) — and
`nix fmt` on any staged `.nix` file when the `nix` CLI is present,
skipped silently otherwise. `cargo test --workspace`, `cargo deny check`,
and `just ci` are documented pre-push checks, not pre-commit ones — too
slow to run on every commit.

### `just ci`

`just ci` (`lint`, `test`, `test-doc`, `bdd`) reproduces what `ci.yml`'s
push lane checks, so a contributor can sanity-check locally before
pushing.

## Consequences

An ordinary push gets fast, complete feedback from the checks that
matter for almost every change — four Linux-only jobs plus the
architecture-invariant lane. An operator opts into the expensive
platform, live-VM, and OCI-ratification matrix deliberately through
`ci-full.yml`, rather than paying for it on every push.

A change that only breaks on macOS or under live KVM is not caught until
someone runs `ci-full.yml`, or until a release-time gate runs — there is
a real gap between "push is green" and "every platform has been
exercised."

Release-time-only gates (`security.yml`, `windows.yml`, `release.yml`)
stay timed to minimize per-push cost while still forming a hard backstop
before anything ships.
