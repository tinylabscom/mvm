# Restore successful scheduled security evidence

Backing: historical
Validation: check-claim-witness-freshness

**Status: BLOCKED on #3679**

Issue: #3750. Worktree: `mvm-3750-witness-freshness`.

Security ran on schedule at 2026-09-28T04:34:13Z (run 36378277756), and its
conclusion was failure. The freshness check reports that failed conclusion;
there is no evidence that its schedule stopped. The reported mutation gaps
are tracked independently by #3679 and its dedicated worktree.

- [ ] Merge the validated Security repair for #3679.
- [ ] Obtain a successful scheduled Security run on the repaired main revision.
- [ ] Run the existing check-claim-witness-freshness --check-reporting gate and
      verify the watcher observes the successful evidence.
- [ ] Confirm #3750 closes only after its scheduled evidence is healthy.

Do not silence the gate, change its schedule, or close the alert on the basis
of a successful dispatch alone: it specifically inspects scheduled runs.
No independent scheduler fix is justified by the available logs.
