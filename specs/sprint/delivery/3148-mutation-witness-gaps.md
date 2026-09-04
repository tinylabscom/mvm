# Claim witnesses that bite

- [x] Kept `#![cfg(test)]` module files off the mutation surface. Resolution
      assumes a witness's file is the enforcement code it guards, which fails
      for a separate tests module — and the cost was a dead shard, not a weak
      measurement: cargo-mutants writes no `outcomes.json` for a file with no
      mutants, and the gate died reading it, reporting nothing about the four
      files in the same shard that did have mutants.
- [x] Re-pinned the surface for that change alone; claim 19 keeps its coverage
      through four other files and no claim became uncovered.
- [x] Closed the eight claim-20 survivors in `artifact_verify.rs` — outcome
      counter routing, the security-versus-operational audit guard, and the
      manifest digest predicate.
- [x] Closed twelve of the twenty survivors in `plan/types.rs`; seven more are
      closed by the evidence-that-earns-trust work, and the twentieth is proven
      equivalent and recorded as an accepted miss with its proof.
- [x] Verified every new witness by applying the reported mutation and
      confirming the test fails.
- [x] Resolved nothing with `--write-baseline --run`.
- [ ] Confirm the three shards green on the first uninterrupted nightly.
- [ ] Merge the linked pull request through the queue.

Owning plan: `specs/plans/2026-09-04-claim-witnesses-that-bite.md`.
