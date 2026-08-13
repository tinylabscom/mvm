# 328 — RFC 6962 consistency proofs for `mvm-contract::merkle`

The audit log already publishes signed Merkle roots and verifies inclusion
proofs. This change adds RFC 6962 consistency proofs: an `O(log n)` way to show
that a tree of `m` leaves is a prefix of a tree of `n` leaves, without replaying
either chain.

This is deliberately **piece A of three**. It adds the pure math; it does not
add an off-host witness (piece B) or a monitor that compares successive roots
(piece C). On its own it changes no security property, and no claim witness was
added.

## Delivered

- `crates/mvm-contract/src/merkle.rs`:
  - `ConsistencyProof` wire type with `#[serde(deny_unknown_fields)]`.
  - `build_consistency_proof(leaf_lines, m, n)` — level-by-level construction
    reusing the module's existing `reduce_level` / `sibling_path` logic.
  - `verify_consistency(proof)` — reconstructs both roots from the path and
    checks them against the proof's embedded roots.
  - `verify_consistency_against_roots(proof, old, new)` — binds the proof to two
    independently signed `SignedAuditRoot`s before folding.
  - New `MerkleError` variants: `ConsistencyOldSizeZero`, `ConsistencyShrunk`,
    `NewSizeExceedsLeaves`, `ConsistencyPathTooShort`, `ConsistencyPathTooLong`,
    `OldRootMismatch`, `NewRootMismatch`, `RootBindingMismatch`.
  - Module-level documentation spelling out the three limits: an unbound proof
    detects nothing; a host-signed root on the host proves nothing against a
    malicious host; and even with a witness the property is detection, not
    prevention, only back to the last witnessed root.
- Tests:
  - Independent RFC 6962 `SUBPROOF` oracle for every `(m, n)` with
    `1 <= m <= n <= 33`.
  - Known-answer vectors from the Certificate Transparency reference tree
    (`transparency-dev/merkle` testdata) for `(1,1)`, `(1,8)`, `(6,8)`,
    `(2,5)`, `(6,7)`.
  - Round-trip build-verify for every pair up to 33.
  - Executable truncation failure mode: a shortened log returns
    `ConsistencyShrunk`, and a truncate-then-append rewrite fails
    `OldRootMismatch`.
  - Fail-closed ladder for path length, hex decode, flipped/tampered nodes,
    `m == 0`, `m > n`, `n >` leaf count, serde unknown fields, and binding
    mismatches.

## Explicitly not delivered

- No host-side CLI verb or emitter change. The existing `trust audit
  publish-root` / `prove` / `verify-inclusion` wiring remains the entry point;
  exposing consistency proofs through it is a follow-up.
- No off-host root store (piece B) and no monitor (piece C). Those are trust-
  topology and operational decisions, not code.
- No `model/claims.toml` or ADR-001 change. Adding a claim witness would assert
  a security property this code does not deliver.

## Witnesses

- `cargo test -p mvm-contract --lib merkle` — 50 tests pass.
- `cargo clippy -p mvm-contract --all-targets -- -D warnings` — clean.
