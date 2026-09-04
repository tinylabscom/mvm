# Nightly lanes stop cancelling themselves

Backing: shipped-source
Validation: check-workflow-paths

**Issue:** [#3007](https://github.com/tinylabscom/mvm/issues/3007)

## Outcome

`Extended CI`, `Security` and `Miri` no longer cancel a run that is already
under way. Each is scheduled-and-dispatched only, so cancellation could never
reach the thing it was written for and could only reach the thing it must not.

## What was actually wrong

All three carried:

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

with a comment explaining that this keeps a pull request's check panel free of
runs from superseded SHAs, and that `main` runs are safe because the group is
keyed on the ref.

Both halves are wrong for these files.

None of the three has a `pull_request` trigger, so there is no check panel to
keep tidy — the only run cancellation can reach is one already in flight.

And the ref does not separate the triggers that *do* exist. A scheduled run and
an operator dispatch both carry `refs/heads/main`, so far from putting them in
different groups, keying on the ref put them in the *same* one. Every dispatch
killed the nightly, and every dispatch killed the dispatch before it.

That is what #3007 is. Four consecutive `Extended CI` runs were cancelled by
their successors while the documented-surface e2e lane — which needs over an
hour — was still running. Each reported `cancelled`, which in a run list is
indistinguishable from a failure, so the lane read as red. It was not red. It
had never been allowed to finish, and so had never produced the
Linux/Firecracker verdict the release wanted from it.

On `Security` the same defect has a sharper cost: the mutation shards run for
over two hours, and a cancelled run leaves nine numbered claims with a green
ledger entry and nothing behind it, which is the condition
`check-claim-witness-freshness` exists to report.

## The fix

`ci.yml` already solved this, so the shape is reused rather than invented:

```yaml
group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'workflow_dispatch' && github.run_id || github.ref }}
cancel-in-progress: false
```

A dispatch is keyed on its own run id, so an operator request never lands on
top of the nightly and never waits behind one. The nightly keeps the ref, so
only one runs at a time. Tag pushes on `Security` already sat in their own
group. Nothing in flight is cancelled.

## Keeping it

`a_workflow_without_pull_requests_never_cancels_a_run_in_flight` walks
`.github/workflows/` and fails any file that has no `pull_request:` trigger yet
sets `cancel-in-progress: true`. Derived from the trigger list rather than a
filename allow-list, so a new nightly workflow inherits the rule instead of
having to be remembered. Verified by reverting `miri.yml` and confirming the
test names that file and that reason.

Workflows that *do* have a `pull_request` trigger are untouched: cancellation
is correct for them, and `network-perf.yml` and `kernel-cve-watch.yml` keep it.

## Delivery checklist

- [x] Scope the concurrency group on `ci-full.yml` so a scheduled or dispatched
      run is not cancelled by the next one.
- [x] Apply the same repair to `security.yml` and `miri.yml`, which carry the
      identical defect.
- [x] Add a derived structural test so a new nightly workflow cannot
      reintroduce it.
- [ ] Confirm with one uninterrupted `Extended CI` run that the documented
      surface lane completes and reports a scenario summary.
- [ ] Merge the tested pull request and close #3007 through its linkage.

## What this does not fix

The two documented-surface e2e failures named in #3007 are separately in
flight. This change is the precondition for reading their verdict at all: while
runs cancelled each other, a red lane and an unfinished lane were the same
symbol.
