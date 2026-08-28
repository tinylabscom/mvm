# Security lane red repair

Backing: shipped-source
Validation: check-sprint-append

**Issue:** [#2982](https://github.com/tinylabscom/mvm/issues/2982)

## Outcome

The scheduled Security workflow no longer resolves the yanked `chacha20
0.10.1` release, and the mutation witness suite observes libkrun's advertised
vCPU ceiling. Mutation exemptions that the current suite already catches are
removed so the baseline remains a ratchet rather than an archive.

## Delivery checklist

- [x] Reproduce the yanked dependency and mutation-witness failures from the
      scheduled Security run.
- [x] Update the lockfile to `chacha20 0.10.2` and add a lockfile regression.
- [x] Assert libkrun's advertised vCPU ceiling and remove the eight stale
      mutation exemptions reported by CI.
- [x] Pass the focused dependency and libkrun regressions, `cargo deny`, and
      the static mutation-surface gate.
- [ ] Pass workspace tests, zero-warning Clippy, policy gates, and the Linux
      mutation-witness lane.
- [ ] Merge the tested pull request and close #2982 through its linkage.
