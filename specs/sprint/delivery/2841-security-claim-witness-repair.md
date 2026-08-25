# Scheduled security claim witnesses execute their current surfaces

The scheduled Security workflow again runs the exact witnesses that back the
sealed-production request policy. The locked agent tests follow their
post-refactor modules, and the shared security-policy tests run from their
source-of-truth `mvm-contract` crate instead of the compatibility facade.

Mutation evidence is current as well. A contributor-channel test proves that
the in-tree runtime-overlay flake is detected, catching the checkout-predicate
mutation that previously survived. Baseline entries for mutations now caught
by the expanded suite are removed. The macOS/Windows confinement compatibility
stub has a distinct name and a narrowly documented baseline entry, so its
platform no-op cannot hide a mutation of the Linux fail-closed confinement
function.

Validation:

- `scripts/check-sealed-prod-allowlist.sh` (8 exact witnesses)
- `cargo test -p mvm-build --features pure-mkfs contributor_build_detects_the_compiled_in_runtime_overlay_flake`
- `cargo test -p mvm-hostd --bin mvm-network-endpoint` (24 tests)
- `cargo run -p xtask -- check-mutation-witnesses`
- `cargo clippy --workspace --all-targets -- -D warnings`

This repairs the failed scheduled Security evidence and the downstream claim
freshness report tracked by issues #2841 and #2842.
