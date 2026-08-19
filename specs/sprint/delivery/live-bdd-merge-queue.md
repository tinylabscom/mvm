# Live BDD is visible and merge-gated

Issue #2657 had three independent failure modes: capability-gated scenarios
were silently absent from reports, no required CI lane opted into live BDD, and
the README's persistent-machine walkthrough was tested only as parsing and
fixture behavior.

PR #2727 closes all three. Skipped scenarios are summarized with their reason,
and a KVM-backed job runs only for merge-queue candidates or explicit manual
dispatch. Its single `@ci_live` scenario drives the public README lifecycle
against a real Firecracker guest: create, start, exec, logs, inspect, stop, and
remove.

The narrow selector is implemented inside the typed scenario gate rather than
as a cucumber command-line tag filter. Cucumber's CLI filter replaces the
programmatic filter; using it here would have bypassed both `MVM_BDD_LIVE` and
the KVM capability check. Unit probes prove that the CI subset still refuses
when live execution is not opted in or Firecracker is unavailable.

## Validation

- `actionlint .github/workflows/bdd.yml`
- focused conformance and workflow-structure tests
- safe scenario-selection probes with live execution disabled and without KVM
- `cargo fmt --all -- --check`
- `cargo check --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --lib --bins --tests`
- `just check-gated`
