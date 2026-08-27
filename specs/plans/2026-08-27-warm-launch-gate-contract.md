# Warm-launch gate contract repair

Backing: shipped-source
Validation: check-sprint-append

Issue: #2942

## Goal

Make the live warm-residency witness enforce the authoritative warm-claim
contract instead of borrowing the prepared-cold 200 ms target.

## Checklist

- [x] Reproduce the mismatch between the literal Gherkin threshold and the CLI's
      strict warm-claim ceiling.
- [x] Expose the CLI's warm-launch ceiling and predicate through one narrow
      validation surface.
- [x] Make phase timing and the live conformance step share the predicate.
- [x] Add a strict-boundary unit test and compile the BDD target.
- [x] Run workspace tests, check, Clippy, formatting, and repository gates.
- [ ] Merge the repair through the queue and close issue #2942.
