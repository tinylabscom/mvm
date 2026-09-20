# Network policy builder cleanup

Issue [#3315](https://github.com/tinylabscom/mvm/issues/3315), tracked by
`specs/plans/2026-09-15-the-big-cleanup.md` D3.

## Result

A fresh lexical scan finds 70 public `f` / `f_with_*` sibling pairs across the
current crate tree. The first reviewable module slice removes all five pairs from
`mvm-contract/src/policy/network_policy.rs`:

- `NetworkPolicy::with_egress_mode` composes with either base policy constructor
  and replaces the preset/allow-list mode-specific constructors.
- The existing `NetworkPolicy::with_ai` composes with either base constructor and
  replaces the two unused AI-specific constructors.
- `AiPolicy::with_total_budget` composes from `AiPolicy::metered` and replaces the
  long budget-specific constructor while preserving the serialized policy shape.

`xtask check-public-function-names` scans Rust visibility declarations without
trying to infer production/test scope from braces. It ratchets the remaining
lexical count at 65 and separately requires every cleared module to stay at zero;
future per-module slices can lower the ceiling and extend the cleared-module list.

## Verification

- focused contract suite: 63 tests passed
- focused client coverage: both total-budget resolution and grant propagation
  tests passed
- gate unit suite: 4 tests passed
- `cargo run -p xtask -- check-public-function-names`: 65 pairs remain; one
  module cleared
- `cargo check --workspace`: passed
- `cargo clippy --workspace --all-targets -- -D warnings`: passed
- `just check-gated`: passed for Linux targets and the BDD feature closure
- `cargo run -p xtask -- check-all`: 74 gates passed
- `just bdd`: 255 scenarios passed and one declared scenario skipped
- `cargo test --workspace -- --test-threads=1` with the ambient `RUST_LOG`
  override removed: all unit and integration tests passed; the trailing rustdoc
  process exited transiently, then `cargo test --workspace --doc --
  --test-threads=1` passed every documentation test
