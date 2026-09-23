# Issue #3315 — composable console session options

Status: validated; delivery pending

## Outcome

`mvm-cli` no longer exposes parallel `console_interactive`,
`console_interactive_with_env`, and `console_interactive_with_env_and_argv`
entry points. One `console_interactive` function accepts
`ConsoleSessionOptions`, constructed through a builder with named environment
and argv fields.

The function returns the guest exit code. Command and machine boundaries keep
propagating a nonzero code through `mvm_observability::exit`, while the session
attach boundary keeps its prior behavior of treating a completed interactive
session as a successful attach. The refactor therefore removes overloads
without changing exit-status policy.

## Regression coverage

- an options-composition test proves environment and argv values survive the
  builder unchanged;
- existing console relay, accessibility, transport-selection, command, machine,
  and session tests continue to exercise the single entry point;
- the public-function-name gate is ratcheted from the fresh pre-change count of
  61 to 59 remaining sibling pairs and treats
  `mvm-cli/src/commands/vm/console.rs` as cleared.

## Validation

- test-first compile — failed as expected because `ConsoleSessionOptions` was
  not yet defined;
- `cargo test -p mvm-cli session_options_compose_environment_and_argv` — passed;
- `cargo test -p xtask check_public_function_names` — passed (4 focused gate
  tests);
- direct live scan with the gate's regex and same-file pairing rule — 59 pairs,
  with none in the cleared console module;
- `cargo fmt --all --check` — passed;
- `cargo check --workspace` — passed;
- `cargo clippy --workspace --all-targets -- -D warnings` — passed;
- `cargo test -p mvm-cli` — 2,101 unit tests passed, 2 ignored, with all
  integration tests and doctests passing;
- `cargo test --workspace -- --test-threads=1` — every workspace unit and
  integration test passed. Its final `mvm-build` doctest link step initially
  encountered a transient missing `mvm_sdk` artifact after concurrent suite
  activity; an isolated `cargo test -p mvm-build --doc` rebuilt that dependency
  graph and passed;
- `just check-gated` — passed for the Linux workspace/all-targets cross-check
  and the `mvm-conformance` BDD-feature target;
- `cargo run -q -p xtask -- check-all` — all 74 repository gates passed;
- `just bdd` — 67 features, 265 scenarios (264 passed, 1 expected skip), and
  1,015 steps (1,014 passed, 1 expected skip). The suite reported its existing
  82 declared exclusions: 7 `@wip`, 2 release-bundle fixtures, and 73 live
  microVM scenarios.

The optional all-feature lint expansion reaches two pre-existing
`clippy::needless_update` findings in untouched `mvm-client/src/local.rs`
(lines 2477 and 2497). The repository's standard all-target lint command is
green, and this slice does not modify that module.
