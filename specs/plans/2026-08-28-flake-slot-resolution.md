# Flake slot resolution

Backing: shipped-source
Validation: check-sprint-append

**Status:** IN PROGRESS
**Issue:** #2967

## Outcome

`machine run --flake <ref>` must resolve the slot it just built through the
slot registry instead of treating the slot address as a manifest filesystem
path. Unknown or internally inconsistent slot records continue to fail closed.

## Tasks

- [x] Reproduce the live failure with a resolver regression that starts from a
      materialized flake slot address.
- [x] Resolve strict 64-character slot addresses through the existing slot
      registry while leaving every other bare argument as a manifest path.
- [x] Cover successful lookup, unknown-slot refusal, and mismatched-identity
      refusal.
- [x] Pass workspace tests, gated-target compilation, and zero-warning Clippy.
- [ ] Open the pull request, enter the merge queue, and verify the merge.
