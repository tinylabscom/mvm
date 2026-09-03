# mvm-conformance

`mvm-conformance` is the development-only behavior-driven conformance harness
for mvm. It connects Gherkin scenarios under `features/suites/` to the real
`mvmctl` binary and, where appropriate, the `mvm-client` facade.

## Who uses it

No shipped crate depends on `mvm-conformance`. Contributors and CI use it to
prove user-visible workflows, documentation examples, runtime capability
claims, and security behavior across the workspace.

## How it works

The `bdd` feature enables the cucumber test target. Cucumber-specific `World`
state and step macros live in `tests/`, while reusable logic in `src/` remains
ordinary Rust that can be tested without starting the runner.

Before a scenario runs, the harness derives `RuntimeCaps` from the host and
environment. `scenario_gate_for_ci` interprets tags and either runs the
scenario or reports a deliberate capability skip. Important tags include:

| Tag | Meaning |
|---|---|
| `@wip` | Step implementation is intentionally pending |
| `@live` | Boots or reaches a real external/runtime resource; opt in explicitly |
| `@ci_live` | Narrow live lifecycle selected by the merge queue |
| Firecracker capability tags | Require usable KVM and Firecracker |

Each scenario receives isolated `MVM_HOME`, Cargo state, and process cleanup so
parallel runs cannot reuse a developer's machines or credentials. Source
command helpers parse documented commands, and claims helpers connect scenarios
to the repository's evidence catalog.

## Main modules

| Module | Responsibility |
|---|---|
| `claims` | Claim/evidence lookup used by conformance scenarios |
| `doc_examples` | Extract and validate executable documentation examples |
| `source_commands` | Parse commands from source-controlled prose |
| crate root | Capability detection, tag gating, and isolated-home helpers |

## Developing

Run unit tests with `cargo test -p mvm-conformance`. Compile and run the BDD
target with the repository's `just bdd` workflow or
`cargo test -p mvm-conformance --features bdd`. Live microVM scenarios must run
only in their approved environment and must never be silently substituted for
hermetic coverage.
