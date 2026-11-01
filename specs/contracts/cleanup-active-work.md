# Cleanup active work and release baseline (umbrella #4839)

Backing: preview
Validation: none — this records state observed on 2026-11-01; the issues own status.

Measured at `2d226a3b9185eee7d6ed0688af3e0aae4ee49233` (origin/main). Companion to
`cleanup-inventory.md` (supported shape, flags and knobs) and
`cleanup-preservation-ledger.md` (evidence runs).

## 1. Release baseline

The runbook (`gist d62dde28…/cleanup.md`, Stage 1) requires confirming "the required MVM
release exists" with its exact tag and commit, and stopping if it has not been cut.

| Fact | Value | Command |
|---|---|---|
| Latest published GitHub release | `v0.22.0`, commit `b6b77f83730bed54d52f5f8b9cdcd8d5136ca1de` | `gh release list --exclude-pre-releases` ; `git rev-list -n1 v0.22.0` |
| Newest tag | `v0.26.0`, commit `88f7919f15ff9f11e05041cf4099b595fc7becb9` (a main commit) | `git rev-list -n1 v0.26.0` |
| `release.yml` on `v0.26.0` | run 41279625530 `failure`; run 41338795119 had no conclusion when observed | `gh run list --workflow release.yml` |
| Pinned image set | `image-set/v0.2.4` | `crates/mvm-core/images.lock` |

`v0.26.0` is tagged but not published, so no release newer than `v0.22.0` satisfies the
runbook's gate. Which release the runbook meant by "next release" is a maintainer
decision; until it is made, the gate in #4839 stays open. No release is chosen here.

## 2. Open and in-flight cleanup work

Owner is `unassigned` unless stated: `gh pr list`/`gh issue list` report no assignees on any item below.

| Item | State | Note |
|---|---|---|
| PR #4944 `docs/cleanup-inventory-flags-knobs` | open | flags/knobs/backends/compat layers inventory |
| Issues #4926, #4840, #4875, #3730, #3731, #4882 | open | linked from the umbrella; see `cleanup-inventory.md` §2 for the workstream each feeds |

Merged #4839 slices (squash-merged; local branches still ahead of main by the pre-squash commit):
#4918 (`c4839-staged-docs`), #4919 (`docs/4839-secret-kms-contract`), #4920 (`c4839-docs-deps`),
#4927 (`c4839-dedupe-sha`), #4938 (`fix/4839-embedder-toolchain-refusal`), #4939 (`docs/4839-dep-evidence`),
#4947 (`docs/4839-prepared-launch-evidence`), #4950-#4956 (`*-comments-{cli,agentd,sdk,vmm,hostd,runtime}`
and `chore/comment-cleanup-lower-crates-4839`).

Local worktrees (not owners of record; each belongs to whichever session created it, so do not edit them):
`git worktree list | rg '4839|c4839|deps-sweep|test-quality'` — `/tmp/wt-4839*`, `/tmp/wt-c4839-*`,
`/tmp/wt-deps-sweep` and `/tmp/wt-test-quality` (both at main with no commits, no PR).

## 3. Atomic child workstreams

Supersedes the coarse W1-W7 table in `cleanup-inventory.md` §2 where finer. Each row is one
reviewable PR. "Depends" names the prior row.

| ID | Scope | Depends | Acceptance | Validation |
|---|---|---|---|---|
| A1 | Choose the baseline release or amend the gate (maintainer) | none | tag + commit recorded in #4839 | `git rev-list -n1 <tag>` |
| A2 | Re-run the graph inventory with a fresh full-mode index | none | `check_index_coverage` shows `src/bin` trees indexed | `check_index_coverage` on the five paths in `cleanup-inventory.md` §1.1 |
| A3 | Retire the singular-entrypoint path (#4926) | A1 | callers, tests, docs migrated together | `cargo nextest run --workspace`; `rg` for the old form |
| A4 | Consolidate small workspace crates (#4542) | A1 | one fewer package per merged crate; tests preserved | `cargo metadata --no-deps`; `cargo run -p xtask -- check-all` |
| A5 | Hermetic pair-image tests (#4840) | none | immutable baseline; identical-feature timing; native macOS run completed | `cargo nextest run --workspace` on macOS, timed |
| A6 | Embedded toolchain upgrade (#4875) | none | pinned toolchain bumped, release build embeds | `just payload::toolchain`; `cargo build --release` |
| A7 | Thin CLI over `mvm-client` (#3730, #4412-#4416) | A1 | no production CLI path bypasses the client | `cargo run -p xtask -- check-thin-cli` |
| A8 | Comment/slop sweeps per crate | none | no narration or history comments; invariants kept | `cargo clippy --workspace -- -D warnings`; `cargo fmt --all -- --check` |
| A9 | Release compile-time causes | A1 | repeated compilation measured and fixed | `cargo build --release --timings` |

Rows with a live issue keep that issue as the status owner; rows without one (A1, A2, A8, A9)
have none yet.

## 4. Maintainer prompts

The record of subsequent maintainer prompts is the comment thread of #4839, not a file:
`gh issue view 4839 --comments`. This document does not duplicate it.
