# Issue #3315 — composable VMM run hooks

Status: validated; queued delivery pending

## Outcome

`mvm-vmm` no longer exposes parallel `run`, `run_with_pause_hook`, and
`run_with_hooks` functions. One `run` entry point accepts `RunHooks`, while
`RunHooks::new`, `on_pause`, and `throttle_when` make optional behavior explicit
without adding positional arguments.

The device-bus entry point remains distinct because it selects a different
device-ownership model rather than adding an optional behavior to `run`.

## Regression coverage

- a standard hook set runs a vCPU without requiring pause or throttle hooks;
- pause and throttle hooks compose on the same parameter object;
- existing pause, throttle, stop, device-poll, exception, MMIO, and PIO behavior
  tests continue to exercise the single entry point;
- the public-function-name gate is ratcheted from 64 to 62 remaining sibling
  pairs and treats `mvm-vmm/src/vmm/run.rs` as cleared.

## Validation

- `cargo test -p mvm-vmm run_accepts_one_composable_hook_set` — passed;
- `cargo test -p mvm-vmm` — passed (760 tests);
- `cargo test -p xtask check_public_function_names` — passed (4 focused gate
  tests);
- `cargo run -p xtask -- check-public-function-names` — passed (62 remaining
  sibling pairs; 3 cleared modules);
- `cargo check --workspace` — passed;
- `cargo clippy --workspace --all-targets -- -D warnings` — passed;
- `just check-gated` — passed;
- `cargo run -p xtask -- check-all` — passed (74 gates);
- `just bdd` — passed (255 scenarios and 981 steps, with one intentional skip
  and the optional/live exclusions reported separately);
- `cargo test --workspace -- --test-threads=1` — passed, including doctests.
