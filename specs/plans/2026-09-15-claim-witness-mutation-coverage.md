# Claim-witness mutation coverage repair

Backing: shipped-source
Validation: check-sprint-append

**Issue:** [#3250](https://github.com/tinylabscom/mvm/issues/3250)

## Outcome

Restore current evidence for the mutation-tested `mvm-backends` security claim
by killing the two surviving `read_handoff_response` mutants reported by the
scheduled Security workflow.

## Checklist

- [x] Identify the exact two surviving handoff-response mutants.
- [x] Add an empty-EOF regression that refuses to treat no response as a valid
      refusal reason.
- [x] Add a short unterminated-response regression that retains the bytes read
      before EOF.
- [x] Pass focused tests, workspace tests/check, gated compilation,
      zero-warning Clippy, formatting, and repository policy gates.
- [x] Pass the authoritative Linux mutation ratchet in pull-request CI.
- [x] Merge the issue-linked pull request.
- [x] Reconcile a successful complete Security run and close #3250 with the
      fresh claim evidence.
