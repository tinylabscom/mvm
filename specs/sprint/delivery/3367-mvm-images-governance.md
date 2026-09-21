# `mvm-images` governance closeout

Backing: shipped-source
Validation: check-sprint-append

W2 of `specs/plans/2026-09-16-image-repository-extraction.md` establishes the
image repository before it can publish. This record audits the repository at
`tinylabscom/mvm-images` commit
`4c0d55e562dc88032c6d1cd5a3c588dafbdcffc6` and its live GitHub settings on
2026-09-21.

## Repository controls

- The repository is public and its default branch is `main`.
- Active branch ruleset `23670916` covers the default branch. It refuses
  deletion and non-fast-forward updates, requires a pull request, permits only
  squash merging, and requires the `action-pins` status check. It has no bypass
  actor.
- `.github/CODEOWNERS` assigns every path to `@auser`.
- Workflows default to read-only permissions and cannot approve pull requests.
  Every checked-in workflow also declares `contents: read`, and every checkout
  disables persisted credentials.
- `.github/dependabot.yml` checks GitHub Actions weekly. `SECURITY.md` defines
  the reporting and incident path, and `README.md` documents ownership,
  supported `x86_64` and `aarch64` guest architectures, every artifact role,
  change-driven release cadence, indefinite retention, immutable releases,
  rollback by lock update, and the no-secrets/no-customer-data rule.
- Active tag ruleset `23670918` covers `image-set/*` and `boot-image/*`. It
  refuses update, deletion, and non-fast-forward changes and has no bypass
  actor.
- The `image-release` environment accepts only `image-set/*` tags and requires
  review by `auser`. No branch is eligible for that environment.

These controls were read from the repository, ruleset, Actions-permission, and
environment APIs. The repository uses rulesets rather than the legacy branch
protection endpoint.

## No-publish witness

The `Build` workflow is the W2 dry run. It can run on pull requests, `main`, or
manual dispatch, but has only `contents: read`. It builds and uploads workflow
artifacts with `if-no-files-found: error`; it has no release, signing,
deployment, `id-token: write`, or `contents: write` step. An empty, partial, or
synthetic artifact set therefore has no publication path. Adding the actual
atomic completeness check and release identity is deliberately W6 work; it
must preserve this fail-closed boundary before gaining write or OIDC
permissions.

Main run
[`35462836122`](https://github.com/tinylabscom/mvm-images/actions/runs/35462836122)
built the two-architecture image set successfully from the audited commit
without publishing or signing it. Lint run
[`35462836130`](https://github.com/tinylabscom/mvm-images/actions/runs/35462836130)
passed the immutable-action-pin gate on the same commit.

An untrusted branch cannot mint the future allow-listed identity: no current
workflow can request an OIDC token, branch deployments cannot enter the release
environment, and a matching protected tag still requires environment review.

## Validation

Run against the audited `mvm-images` checkout:

```text
./scripts/check-action-pins.sh --self-test
check-action-pins --self-test: every unpinned shape was refused, every pinned one admitted

./scripts/check-action-pins.sh
check-action-pins: clean (3 workflow file(s))

python3 -m unittest discover -s scripts/tests -v
Ran 28 tests in 3.888s
OK
```

The live-settings audit plus the repository tests satisfy #3367. W6 remains
responsible for adding publication only after the complete-set validator,
signing identity, and consumer trust migration are ready together.
