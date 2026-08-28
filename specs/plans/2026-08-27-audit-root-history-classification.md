# Audit root-history classification repair

Backing: shipped-source
Validation: check-sprint-append

Issue: #2940

## Goal

Keep signed Merkle-root history files out of lifecycle-chain verification so a
healthy audit directory cannot produce a false tampering diagnosis.

## Checklist

- [x] Add a regression test proving `<tenant>.roots.jsonl` is not a lifecycle chain.
- [x] Define the root-history suffix beside the other audit filename contracts.
- [x] Make the root-history writer and lifecycle classifier share that suffix.
- [x] Preserve retired lifecycle segments in verification scope.
- [x] Run focused tests, workspace tests and doctests, check, and Clippy.
- [ ] Merge the repair through the queue.
