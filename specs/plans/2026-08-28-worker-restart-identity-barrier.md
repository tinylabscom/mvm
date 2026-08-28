# Worker restart identity barrier

Backing: shipped-source
Validation: check-sprint-append

**Issue:** [#2976](https://github.com/tinylabscom/mvm/issues/2976)

## Outcome

The restart integration test observes the supervisor-published replacement
worker identity before sending the post-crash broker call. This prevents a
successful process-group signal from being mistaken for proof that the dying
worker and signer helper have completed their transition.

## Delivery checklist

- [x] Identify the missing state transition in the workspace-only failure.
- [x] Wait for a live replacement PID before asserting restored registration.
- [x] Pass the focused regression and complete host-agent restart suite.
- [ ] Pass workspace tests, Clippy, formatting, and repository policy gates.
- [ ] Record the completed implementation in the sprint and refactor rollup.
- [ ] Merge the tested pull request and close #2976 through its linkage.
