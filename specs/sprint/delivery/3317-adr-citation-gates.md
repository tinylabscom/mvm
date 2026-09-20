# Accepted ADR citations resolve to live evidence

Issue #3317, item A2.3 of `2026-09-15-the-big-cleanup`.

`check-witness-citations` now reads accepted ADRs as governed evidence rather
than treating them as unchecked prose. It resolves snake-case witness names,
concrete workspace paths and qualified Rust module paths, including crate-aware
paths beneath the `mvm` facade. Proposed ADRs stay outside the live-evidence
contract so future designs can name deliberately absent types without passing
as implementation witnesses.

`check-adr-coverage` separately verifies that every ADR number cited from an
ADR exists and that quoted or symbolic section references name a real heading.
Those cross-references do not count as implementation coverage. ADR-001's
legacy W-section labels remain explicit known debt owned by issue #3318 instead
of becoming an unexplained gate exception.

The first strict pass corrected stale citations across the accepted set. It
also corrected ADR-015's protocol version and removed a false claim that a
cross-repository mvmd fixture currently enforces hostd compatibility. ADR-038
and ADR-041 are now Proposed because their named implementations are absent;
ADR-110 records the production transcript anchor that already ships.

## Validation

- `cargo fmt --all --check`
- `just dev-cargo test -p xtask`: 809 tests passed, zero failed
- `just dev-clippy`: workspace clippy passed with warnings denied
- `just dev-check`: workspace check passed
- `env -u RUST_LOG just dev-cargo test --workspace -- --test-threads=1`:
  full serialized workspace and doctest suite passed
- `just dev-cargo run -p xtask -- check-witness-citations`: 237 citations
  resolved
- `just dev-cargo run -p xtask -- check-adr-coverage`: zero broken references;
  only the issue #3318 known-debt warnings remain
- `just dev-cargo run -p xtask -- check-all`: all 72 repository gates passed
  after rebasing onto the latest `main`
