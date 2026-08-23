# Workflow hygiene: pinned actions, and one driver for the policy gates

Backing: shipped-source
Validation: check-claim-catalog

## Actions floated on a branch

Every one of this repository's 18 `DeterminateSystems/nix-installer-action`
uses was `@main` — including `release.yml` and `release-boot-image.yml`,
the lanes that build and sign what we publish. At the time of the change
`main` was **43 commits ahead of the newest release**, so 43 commits nobody
here had looked at were executing on the signing path, and would be
re-resolved on every run.

All 18 now pin `ef8a148080ab6020fd15196c2084a2eea5ff2d25` (v22), sha with
the version in a trailing comment.

`dtolnay/rust-toolchain@master` stays, as the one named exception:
that action publishes no version tags — the channel *is* the branch name —
and `@master` is its documented entry point when the toolchain is supplied
as an input instead, which is how the lanes pinning a nightly *date* have
to call it. Floating the action to pin the compiler is the trade its design
forces.

`check-workflow-paths` now rejects any third-party `@main` / `@master`, and
rejects one action pinned to two versions. Writing that check surfaced a
bug in its own first draft: the parser only matched `uses:` at the start of
a step, not the more common `- uses:` form, so it read 134 refs where there
were 206 and would have called a floating ref clean. The unit test caught
it before the gate shipped.

The action pin alone is not enough for `setup-uv`: without its `version`
input, the action fetches a remote "latest" manifest before any test runs.
A hosted-runner fetch failure exposed that second floating boundary. Every
CI and BDD setup now pins uv 0.12.5, and `check-workflow-paths` rejects a
future `setup-uv` step that omits the tool version.

Version split, found by the new check: `publish-npm.yml` and
`publish-pypi.yml` paired `upload-artifact@v4` with `download-artifact@v4`
while eleven other lanes were on v7 — one major bump away from a handoff
that fails only on the release path. Unified to v7/v8.

## Sixty gate steps became one

`ci.yml`'s lint-policy job ran 60 consecutive
`cargo run -p xtask -- check-<name>` steps. Two costs. They ran serially
and stopped at the first failure, so a branch breaking four gates was
found, fixed and re-pushed four times, each round trip paying a full lane.
And the list existed only in the YAML — which is why more than one
session's notes carry the instruction "derive the gate list by grepping the
workflows".

`xtask check-all` owns the list now, and `main.rs` dispatches individual
gates from the same table, so a gate cannot be a subcommand and sit outside
the lane. It runs all 63 in one process and reports every failure. The
first run against this branch reported three at once — which is the
behaviour change, demonstrated.

**Three gates were reachable as subcommands and run by nothing:**
`check-backend-resource-controls`, `check-single-fixture-corpus`,
`check-single-grants-projection`. No workflow invoked them. All three pass
on a clean tree, so they were not excluded for failing — they were never
wired in. They are in the table now, and
`every_dispatched_gate_is_in_the_lane_or_excluded_with_a_reason` makes the
omission impossible to repeat: a gate must be in the table or on an
exclusion list that states why. `check-kernel-config-budget` is on that
list because it takes a path to a resolved kernel `.config`; the other six
exclusions name a lane they run in instead.

### The ledger had to learn about the driver

Collapsing named steps broke `ci:` witness resolution: ADR-001 cites
`ci:check-abi-layout`, which resolved against the parenthesised token in
that step's name. `claims_ledger::ci_anchors` now anchors every gate in the
table when it sees the driver invoked, so the witness resolves for the same
reason it always did — the gate runs in CI. Removing a gate from the table
immediately unbacks its claims, verified by doing it.

The consolidated workflow step also retains the established
`(check-abi-layout)` display-name anchor. The conformance harness resolves
claim witnesses directly from workflow-visible anchors, independently of the
xtask ledger, so this keeps its claim check honest without duplicating the
driver's gate table in a second crate.

That also collapsed a duplicate: `check_conformance` had its own `ci:`
resolver, a `text.contains(name)` scan that matched a name in a comment as
readily as a live job — the weak form `ci_anchors` was written to replace.
It routes through the shared one now.

## Deliberately not changed

The raw `actions/cache@v5` blocks in `security.yml` and `ci-full.yml` are
**not** drift against `./.github/actions/rust-cache`, and were listed as
such in this work's first survey. The composite is restore-only with a
single writer on `main`, by a reasoned policy about GitHub's per-ref cache
scoping and its 10 GB LRU cap. The nightly lanes want the opposite: their
own per-package target caches, written where they run. Two strategies for
two kinds of lane, not one strategy applied inconsistently.
