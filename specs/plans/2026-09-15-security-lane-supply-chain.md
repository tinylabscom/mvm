# Security lane supply-chain repair

Backing: shipped-source
Validation: check-sprint-append

**Issue:** [#3249](https://github.com/tinylabscom/mvm/issues/3249)

## Outcome

Restore the scheduled Security workflow's supply-chain witnesses by moving the
workspace off vulnerable rustls 0.23.41 while retaining the existing dependency
policy and cryptographic backend.

The separate #3250 delivery adds the missing mutation coverage reported by the
same Security run. This pull request closes #3249 only after that prerequisite
has merged, so every failed job named by the issue is repaired.

## Checklist

- [x] Reproduce RUSTSEC-2026-0285 against rustls 0.23.41.
- [x] Resolve rustls 0.23.45 and its compatible cryptographic dependency set.
- [x] Pass `cargo audit`, `cargo deny check`, workspace tests/check, gated
      compilation, zero-warning Clippy, formatting, and repository policy gates.
- [x] Merge the #3250 mutation-coverage prerequisite.
- [x] Pass the complete Security workflow on the pull-request head.
- [x] Merge this issue-linked pull request and close #3249.
