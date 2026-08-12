# ADR-012: CI execution policy — pull requests run a lean lane; the full matrix and release gates are separately triggered

## Status

Accepted.

## Context

Hosted CI should produce merge signal, not run speculatively on every
development-branch push. Contributors can run `just ci` locally or
dispatch a workflow manually before opening a pull request. Once a pull
request exists, each update still needs fast feedback, but it should not
pay for platform lanes (macOS, live KVM), OCI ratification, or a
dependency audit that only need to run before a release or on deliberate
request. Heavy, expensive lanes running during every iteration slow down
day-to-day development for no proportional benefit.

## Decision

### Triggers, by workflow

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | `pull_request` + `merge_group` + `workflow_dispatch` | parallel compiler/policy/feature and workspace/Linux lanes with stable `lint` and `test` aggregate checks; Nix is added in the merge queue / manual dispatch |
| `architecture.yml` | `pull_request` + `merge_group` + `workflow_dispatch` | structural/architectural invariants; skips the actual work on docs-only PRs, always runs in merge queue |
| `ci-full.yml` | `workflow_dispatch` only | the full platform + live-VM + OCI-ratification matrix; operator-triggered, never automatic |
| `security.yml` | `push: tags: v*` + nightly cron + `workflow_dispatch` | dependency audit / advisory scan; release-time backstop plus nightly catch for new advisories |
| `windows.yml` | `push: tags: v*` + `workflow_dispatch` | non-blocking informational Windows build check; never a required check |
| `release.yml` | `push: tags: v*` | builds and publishes release artifacts |

### `ci.yml` shares expensive work and keeps required results conclusive

`lint` (fmt, clippy, and the full battery of `xtask` architectural
checks — see ADR-010) and `test` (the workspace nextest run, doctests,
hermetic BDD, no-std target checks, man-page feature tests, and real-kernel
ext4 checks) remain the required pull-request signals. Their independent
compiler/policy/feature and workspace/Linux lanes run concurrently; the
aggregate jobs retain the exact check names branch protection expects.
`nix-flake-check` runs only in the merge queue and on manual dispatch, so
ordinary PR updates pay for the lighter compile/test signal and the heavier
eval work runs once before merge. The SDK publication dry-run is part of the
manual full matrix rather than the development lane.
Nothing platform-specific
(macOS, live KVM, Windows) or slow (OCI ratification, dependency audit,
the full builder-VM image build) runs on every pull request — those live
in `ci-full.yml`, run only by explicit `workflow_dispatch`.

The compiler, policy, feature, workspace, and Linux-only groups each have a
dedicated runner so independent work can progress concurrently. The stable
`lint` and `test` jobs only inspect their lane results and fail closed when any
lane fails. The PR
workflow does not upload `target/`: GitHub scopes caches from pull-request and
merge-queue refs so sibling runs cannot restore them, making the former 4+ GB
archives pure upload/storage cost except on a rerun of the same generated ref.
The feature lanes retain the existing targeted package coverage, and the
Linux-only filesystem/no-std/BDD commands live in one script rather than being
duplicated between workflows.

A fail-closed scope job compares the exact pull-request or merge-group base and
head SHAs before allocating Rust runners. Diffs that cannot change compiled or
generated behavior skip compiler lint, feature coverage, workspace tests,
release-profile witnesses, Linux/conformance coverage, and eBPF coverage.
Policy still runs for every diff because prose and claims are part of its input
surface. Manual dispatch and an unresolvable diff run the complete matrix. The
required aggregates accept a lane only when it passed or the successful scope
decision deliberately skipped it; scope and policy themselves must pass. Nix
retains its own independent, fail-closed classifier.

Every Rust lane must appear in an aggregate's `needs` *and* in that aggregate's
result comparison. A lane that runs but is named by neither is a lane whose
failure cannot block a merge — it spends runner time and gates nothing. The
eBPF telemetry lane was in exactly that state until it was added to the `Test`
aggregate; because it finishes well inside the workspace and Linux lanes it
gates for free, adding no wall-clock time to a code-bearing merge group.

### The merge queue's required checks

`ci.yml` and `architecture.yml` are the only two workflows that run on
`merge_group`, making them the required checks a PR must pass before it
merges. `ci-full.yml`, `security.yml`, and `windows.yml` are not part of
the merge-queue gate.

Both required workflows listen explicitly for `checks_requested`. Their
concurrency keys include the workflow, event type, and event ref, so unrelated
pull requests and merge-group commits do not serialize. A new commit cancels a
superseded `pull_request` run for the same PR; `merge_group` runs are never
cancelled by workflow concurrency, because cancelling validation of the exact
queue commit can eject the entry or leave its required checks unresolved.
Manual dispatches use the run ID and therefore remain independent.

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

`just ci` (`lint`, `test`, `test-doc`, `bdd`) reproduces the core Rust
checks from `ci.yml`, so a contributor can sanity-check locally before
pushing. The workflow additionally exercises Linux-only real-kernel
filesystem behavior, no-std cross-target boundaries, and Nix
evaluation on the hosted Linux runner.

## Consequences

A pull-request update gets fast, complete feedback from the checks that
matter for almost every change — parallel Linux-only lanes behind the stable
`lint` and `test` aggregates plus the architecture-invariant lane, with the
heavier `nix-flake-check` work deferred to the merge queue. The merge queue
runs the full set of four required check names against the final merge group;
the aggregate names remain `Lint (fmt + clippy + policy)`, `Test`, `Nix flake
check (Linux eval)`, and `Invariant`.
Development branches without a pull request consume no hosted runners
unless an operator dispatches CI manually. Landing that already-checked
commit on `main` does not run them a third time. An operator opts into the expensive platform, live-VM,
SDK-publication dry-run, and OCI-ratification matrix deliberately through
`ci-full.yml`, rather than paying for it on every update.

A change that only breaks on macOS or under live KVM is not caught until
someone runs `ci-full.yml`, or until a release-time gate runs — there is
a real gap between "the PR is green" and "every platform has been
exercised."

Release-time-only gates (`security.yml`, `windows.yml`, `release.yml`)
stay timed to minimize development cost while still forming a hard backstop
before anything ships.
