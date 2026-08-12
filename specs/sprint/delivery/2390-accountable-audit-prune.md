- [x] Accountable audit-segment pruning — **plan 326** (issue #2390). Plan 319
      said deleting a retired segment was "an explicit operator action" but
      shipped no verb for it, so pruning meant `rm`, which left the chain
      reporting `TruncatedFront` forever. That made pruning strictly worse than
      not pruning, so keep-everything was the only reachable state rather than a
      chosen one. `mvmctl trust audit prune --through <seq>` now verifies the
      set, appends a signed `chain.pruned` record, and only then deletes —
      dry-run unless `--ack`. The record may only claim what the surviving
      handoff independently attests, so it cannot relabel an edit as a removal;
      an over-claiming, wrong-tip, or forged record is refused, and an
      unrecorded deletion is still tampering. Pruning is prefix-only, leaving
      exactly one boundary for the chain to corroborate, and refuses outright on
      a chain that does not verify. Verification now returns a set verdict, so a
      pruned chain reports **verified-with-a-gap** rather than simply verified,
      and doctor names the entry count that will never verify again. Only the
      upper boundary of a pruned range is cross-checked; tail truncation is
      unchanged and still undetectable. 11 new tests; 35 pass across the prune,
      rotation and frozen-bytes suites.
