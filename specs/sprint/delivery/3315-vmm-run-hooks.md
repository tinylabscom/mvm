# Issue #3315 — composable VMM run hooks

Status: implementation complete; validation in progress

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
- full crate, workspace, gated-target, repository-gate, and BDD validation is
  recorded before merge.
