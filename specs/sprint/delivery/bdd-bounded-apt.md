# BDD setup uses the bounded apt path

**Status:** COMPLETE

## Failure reproduced

Three independent BDD jobs exhausted their 30-minute job budget in `apt-get
update` without reaching the suite. The shared `.github/actions/apt-deps`
action already replaces the hosted runner's unreliable Azure mirrorlist and
bounds each update/install attempt, but `.github/workflows/bdd.yml` bypassed it
with raw `apt-get` commands.

## Delivered

- The canonical reusable BDD workflow now installs `libcap-ng-dev` and `lld`
  through `.github/actions/apt-deps`.
- A workflow-structure regression test refuses any return to raw `sudo
  apt-get` in that workflow and requires the shared action.

This changes setup behavior only. The BDD command, cache policy, SDK suites,
and 30-minute job ceiling are unchanged.

## Validation

- The exact new test was run before the workflow edit and failed on the
  missing shared action.
- `cargo test --test github_actions_bdd_gate
  canonical_bdd_workflow_uses_bounded_apt_action -- --exact`: 1 passed.
- `cargo test --test github_actions_bdd_gate`: 6 passed.
