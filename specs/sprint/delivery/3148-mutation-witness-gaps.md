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

## Follow-up: the survivors the dead shard was hiding

The first fix stopped the mvm-cli shard dying, which let it reach files it had
never run. Two more shards' worth of survivors came out from behind it.

- [x] Closed the four claim-10 survivors in `NetworkPolicy::admits_outbound`.
      #3170 added the function — the "egress rules *or* a peer route" question
      every site deciding whether to build the outbound path must ask — and it
      shipped without a witness. Replacing it with `true` or `false`, narrowing
      the `||`, and dropping the `!` all survived.
- [x] Closed the two claim-19 survivors in `admit_plan_for_boot_with_ingress`,
      where admission pins a directory share's content digest. `==` to `!=`
      hashes disks and skips directory shares; `&&` to `||` overwrites a
      caller-supplied pin with a snapshot of the tree. The existing witness
      tests the enforcement side in mvm-hostd and is handed a plan that already
      carries a digest, so it cannot see either.
- [x] Verified all six by applying the reported mutation and confirming failure.
- [ ] Confirm the shards green on the next nightly.
