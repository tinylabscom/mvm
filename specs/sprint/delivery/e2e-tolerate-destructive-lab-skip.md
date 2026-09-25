# The documented-surface lane tolerates the destructive-lab skip

Backing: shipped-source
Validation: shellcheck scripts/e2e-documented-surface.sh

The `v0.18.0-rc.2` release (run 36119669178) passed all 333 scenarios on the
Linux Firecracker documented-surface lane and still failed: the CVE containment
witness added in #3674 is skipped with `needs-destructive-lab-opt-in` unless the
host sets `MVM_BDD_DESTRUCTIVE_LAB=1`, and the lane runs under
`MVM_BDD_STRICT_SKIPS` with an allow-list that did not name it. The macOS lane
did not trip because the scenario is Firecracker-only there.

The allow-list admits only properties of the host, never capabilities the lane
is meant to provide. A risk ceiling that requires a throwaway lab host is the
first kind: a release runner must never detonate a real exploit, so the reason
joins `ALLOWED_SKIPS` with that justification beside it, and the skip stays
counted in the tally.
