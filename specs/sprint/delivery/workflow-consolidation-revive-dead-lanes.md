# Workflow consolidation: revive the lanes that never ran, delete the rest

Backing: shipped-source
Validation: check-claim-catalog

A survey of the 25 workflows for consolidation found that the largest
single file, `ci-full.yml` (1,236 lines, 18 jobs), had **never been run** —
`total_count: 0` against the Actions API. Eleven of its eighteen jobs also
carried `if: github.event_name == 'workflow_dispatch'`, a redundant guard
on a workflow whose only trigger was `workflow_dispatch`.

That mattered because ADR-001's ledger cites `ci:app-deps-audit` as claim
11's witness, and that job lived there. It is the only `ci:` witness in the
table that was not already in `security.yml`. Claim 11 held a green ledger
row for as long as the row has existed, against a lane that had never once
executed.

## Revived

| lane | was | now |
| --- | --- | --- |
| `app-deps-audit` | `ci-full.yml`, dispatch-only, 0 runs | `security.yml`, nightly |
| six `oci-*` lanes | `ci-full.yml`, dispatch-only, 0 runs | `security.yml` `oci-hardening` matrix, nightly |
| `pack-signing-smoke.yml` | dispatch-only, 0 runs | nightly cron at `43 4 * * *` |

`app-deps-audit` keeps its exact job name: ADR-001 and `model/claims.toml`
both cite it, and `check-claim-catalog` / `check-conformance` match on it.

The six OCI lanes were six near-identical jobs — checkout, toolchain, apt,
cache, one or two `cargo test` invocations — differing only in the test
selector, so they are one matrix. Their `dorny/paths-filter` steps are
dropped rather than ported: each gated its real work on
`steps.filter.outputs.oci == 'true' || github.ref == 'refs/heads/main'`,
and on this workflow's triggers the second arm is always true, so the
filter decided nothing. ADR-001 cites none of the six, so no ledger row
moves; CLAUDE.md's prose named them and now says so explicitly.

`pack-signing-smoke.yml` gets its own trigger rather than being called from
`security.yml`, because it reconstructs its own cosign OIDC identity from
`.../pack-signing-smoke.yml@${REF}` and the SAN semantics under
`workflow_call` are not obviously the same. `security-lane-watch.yml` now
watches it too, so a red signing round-trip is reported like any other
lane; its issue title is keyed on the workflow name so two lanes cannot
overwrite each other's report.

## Deleted

- `ci-full.yml` — everything left in it after the move duplicated `ci.yml`
  (`lint`, `test`, `nix-flake-check`, 17 xtask gates).
- `windows.yml` — the only workflow in the tree with no consumer at all:
  no test, no script, no gate, no dispatch from another workflow, and
  0 runs ever.

Two consumers had to be updated first, and neither would have failed
loudly: `tests/github_actions_fuzz_gate.rs` `include_str!`s `ci-full.yml`,
so deleting it is a **compile** error, and `scripts/check-fast-cargo.sh`
required two exact strings from it.

## Not deleted, despite never running

The survey's first pass called six workflows dead on run count alone. Five
were load-bearing, and deleting them on that evidence would have removed
release machinery and a security lane:

- `publish-crates.yml` and `kernel-build.yml` are dispatched by
  `release.yml` (lines 657 and 678). Zero runs because `release.yml` has
  itself run once.
- `pack-signing-smoke.yml` is a security lane — revived, above.
- `merge-queue-requeue.yml` is disabled at the GitHub level, not in YAML,
  and has a test.
- `architecture.yml` is read by `xtask/src/check_workflow_paths.rs`.

Run count is evidence a lane is not running. It is not evidence nothing
depends on it.

## Duplicate required-check name

`ci.yml:kernel` and `kernel-build.yml:kernel` both declared
`name: Build kernels (${{ matrix.arch }})`, which is a required status
check, and both build from the same `scripts/build-kernel-artifacts.sh`.
It resolves unambiguously today only because their triggers are disjoint —
`pull_request`/`merge_group` against tags/dispatch — which is a property
nothing in the name states. The tag-time publisher is now
`Publish kernels (<arch>)`, and
`only_one_workflow_claims_the_required_kernel_check_name` pins it beside
the existing test that pins the triggers apart, so neither half of the
arrangement can quietly lapse.

## Still open

`security.yml` runs only on tags and the nightly cron, never on a pull
request, so none of its 21 jobs gate a merge. The watcher and its tracking
issue are the entire enforcement surface for every claim witness in it.
That is a deliberate design, but it is also why both defects fixed
alongside this went unnoticed for a fortnight, and it is worth revisiting
separately.
