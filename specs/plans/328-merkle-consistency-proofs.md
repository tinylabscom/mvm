# Plan 328 — RFC 6962 consistency proofs for `mvm-contract::merkle`

**Status: COMPLETE**

Issue: #328.

## Summary

Add RFC 6962 **consistency proofs** to `mvm-contract::merkle`:
`build_consistency_proof(leaf_lines, m, n)` and `verify_consistency(...)`.
Pure, `no_std`, no new dependency.

This is **piece A of three**, and on its own it changes no security property.
See "What this does not do" before reading further.

## Verified against `origin/main` (c1e06dea8) before designing

- `crates/mvm-contract/src/merkle.rs` (896 lines) has `build_inclusion_proof` /
  `verify_inclusion`, `merkle_root`, `SignedAuditRoot` + `verify_signed_root`.
  **No consistency proofs** — `rg -i consistency` over the crate finds only
  unrelated prose in `ir/error_codes.rs`, `l3/frame.rs`, `stream/chain.rs`,
  `policy/projection.rs`.
- The tree is a level-by-level fold with lone-node promotion
  (`reduce_level`, merkle.rs:241). Its equivalence to RFC 6962's
  split-at-largest-power-of-two **is** tested against an independent recursive
  oracle: `merkle_root_matches_rfc6962_oracle_for_many_sizes` (merkle.rs:509),
  `n = 0..=32`, oracle at merkle.rs:448. Still holds on main. The whole
  consistency algorithm rests on this.
- `SignedAuditRoot {tenant, tree_size, root_hash, timestamp, signature,
  signer_pubkey}` is signed by the **host** signer
  (`~/.mvm/keys/host-signer.ed25519`) and written to
  `~/.mvm/audit/<tenant>.root.json` —
  `crates/mvm-hostd/src/audit/emitter.rs:322`, published by
  `mvmctl trust audit publish-root`. Same host, same directory as the log it
  attests. Confirmed.

Two things the brief did not mention, found while verifying:

- Host-side wiring already exists: `crates/mvm-hostd/src/audit/merkle.rs`
  (`build_root_in`, `build_inclusion_in`, `read_leaves` spanning the whole
  segment set), the `trust audit publish-root` / `prove` / `verify-inclusion`
  verbs, and a wasm verifier at `web/audit-verify`. None of it is in scope
  here, but it means A slots in without new plumbing.
- **ADR-001 contains no merkle or transparency prose at all.** Its claim-8 row
  already states the limit correctly and verbatim: *"Tail truncation stays
  undetectable, as it was before rotation"*. Nothing in it overclaims, so
  nothing in it needs repair — and nothing in it will be changed by this work.

## What this does not do

Stated here because it is the most likely thing to be misread later:

1. **A consistency proof on its own detects nothing about truncation.** It is a
   prerequisite that makes an off-host witness meaningful. Without B and C
   below it adds capability, not a guarantee.
2. **A host-signed root stored on the host provides zero tamper-evidence
   against that host.** A host that can rewrite `<tenant>.jsonl` can re-sign
   `<tenant>.root.json` with the same key in the same directory. That is true
   today and stays true after this change.
3. **Even with A+B+C the property is DETECTION, never prevention**, and only
   back to the last witnessed root. Anything appended and then truncated
   *between* two witness points stays invisible. **The detection window equals
   the witnessing interval.**

No claim witness is added to `model/claims.toml` and no ADR-001 row changes —
deliberately, for the reason above. Adding a witness would assert a security
property that this code does not deliver. Claim 8's tail-truncation limit
stands verbatim.

## Explicitly out of scope (decisions, not code)

- **B.** Where a root goes such that the host cannot rewrite it — mvmd co-sign,
  Sigstore Rekor, an object-lock store, an operator-held offline copy. This is
  a trust-topology choice for the project.
- **C.** A monitor that fetches successive roots and checks consistency between
  them.

## Design

### API

```rust
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub old_root: String,   // 64 lowercase hex
    pub new_root: String,   // 64 lowercase hex
    pub path: Vec<String>,  // sibling hashes, bottom -> top
}

pub fn build_consistency_proof(
    leaf_lines: &[impl AsRef<[u8]>], m: usize, n: usize,
) -> Result<ConsistencyProof, MerkleError>;

pub fn verify_consistency(proof: &ConsistencyProof) -> Result<(), MerkleError>;

// The safe composition: binds the proof to two independently signed roots.
// Caller must have `verify_signed_root`-checked both first.
pub fn verify_consistency_against_roots(
    proof: &ConsistencyProof, old: &SignedAuditRoot, new: &SignedAuditRoot,
) -> Result<(), MerkleError>;
```

`verify_consistency` alone folds to the proof's *own embedded* roots, so a
fabricated proof self-verifies — the identical footgun `InclusionProof`'s doc
already warns about. `verify_consistency_against_roots` is the composition that
actually means something, mirroring `verify_membership` in `web/audit-verify`.
It is included because for a consistency proof the binding *is* the entire
point; shipping only the unbound verifier would be shipping a footgun.

The proof carries no leaf bytes, so unlike `build_inclusion_proof` it has no
UTF-8 requirement.

### Construction (level-by-level, matching the module's existing discipline)

The existing tree gives node `i` at level `j` the range
`[i·2^j, min((i+1)·2^j, n))`, and its hash is `MTH` over that range — that is
exactly what lone-node promotion buys, and what the existing oracle test pins.

For `0 < m < n`:
- `j = trailing_zeros(m)`, `i = (m-1) >> j`. Node `(j, i)` is the root of the
  largest perfect subtree ending exactly at leaf `m-1`; it covers
  `[m - 2^j, m)`.
- If `i != 0` (equivalently: `m` is not a power of two), push node `(j, i)` as
  the first path element. When `m` *is* a power of two, node `(j,i)` **is** the
  old root, so it is not sent.
- Then walk up from `(j, i)` to the root of the size-`n` tree pushing siblings,
  skipping levels where the node is the lone trailing node — the same walk
  `build_inclusion_proof` already does, reusing `sibling_path`.

Degenerate cases: `m == n` -> empty path, `old_root == new_root`. `m == 0` ->
refused (RFC 6962 defines the proof only for `0 < m`). `m > n` -> refused;
this is the shrink signal.

### Verification

Seed both accumulators at node `(j,i)` — the first path element, or `old_root`
itself when `m` is a power of two. Walk up with the same `idx`/`count`
arithmetic `verify_inclusion` uses (`count` at level `j` = `n` div-ceil'd `j`
times):

- sibling on the **left** (`idx` odd): folds into **both** — it is part of the
  old tree.
- sibling on the **right** (`idx` even): folds into the **new** accumulator
  only — those are leaves the old tree did not have.

Then check both accumulators against the claimed roots, and that the path is
fully consumed.

### New `MerkleError` variants

`ConsistencyOldSizeZero`, `ConsistencyShrunk { old_size, new_size }`,
`ConsistencyPathTooShort`, `ConsistencyPathTooLong`, `OldRootMismatch`,
`NewRootMismatch`, `NewSizeExceedsLeaves { new_size, leaves }`,
`RootBindingMismatch(&'static str)`.

`ConsistencyShrunk` and `OldRootMismatch` are the two ways a truncated log
fails — named distinctly so a future monitor can tell "the log is shorter than
the root I hold" from "the log is long enough but no longer contains what I
witnessed".

## Tests

Following the module's discipline: verify against an **independent** oracle,
not against the implementation.

1. **Independent RFC 6962 `SUBPROOF` oracle** — a recursive
   `SUBPROOF(m, D, b)` transcribed straight from RFC 6962 §2.1.2, structurally
   unrelated to the level-by-level builder. Assert the builder's path equals
   the oracle's for **every** `(m, n)` with `1 <= m <= n <= 33` (~561 pairs,
   crossing the 32 power-of-two boundary).
2. **Published known-answer vectors** — the CT reference tree
   (`transparency-dev/merkle` `testdata/consistency/*`), which is a genuinely
   foreign implementation, not our own output pasted back. Five cases pinned as
   literal hex: `(1,1)` empty, `(1,8)`, `(6,8)`, `(2,5)`, `(6,7)`, each with
   its published `root1`, `root2` and full proof. Reference leaves are the
   standard CT set (`""`, `00`, `10`, `2021`, `3031`, `40414243`,
   `5051525354555657`, `606162636465666768696a6b6c6d6e6f`), so the pins also
   re-confirm our roots equal the published CT roots for sizes 1–8.
3. **Round-trip** build -> verify for every `(m, n)` up to 33.
4. **The failure-mode test the issue exists for** — not a comment describing
   truncation, an executable demonstration:
   - build a log, publish/derive root R at size n;
   - truncate the newest k entries (tail truncation, the undetectable-today
     case);
   - assert `build_consistency_proof` from the truncated log **cannot**
     produce a proof consistent with R — `ConsistencyShrunk`;
   - and, for a truncate-then-append forgery where the sizes line up again,
     assert `verify_consistency` fails `OldRootMismatch`.
5. Fail-closed ladder: path too short / too long, flipped sibling, tampered
   `old_root`, tampered `new_root`, `m == 0`, `m > n`, `n >` leaf count,
   unknown serde field, serde round-trip, binding helper rejecting a tenant /
   size / root-hash mismatch.

Test 4 is a **library-level** demonstration. It proves the math refuses a
truncated log against its own earlier root. It does **not** demonstrate
host-level detection, because there is nothing off-host holding the earlier
root — that is exactly piece B.

## Deliverables

- [x] `crates/mvm-contract/src/merkle.rs` — implementation, module-doc section
      carrying the three statements above.
- [x] `specs/plans/328-merkle-consistency-proofs.md`
- [x] `specs/sprint/delivery/328-merkle-consistency-proofs.md`
- [x] No `model/claims.toml` change, no ADR-001 change — deliberately, for the
      reason above.
