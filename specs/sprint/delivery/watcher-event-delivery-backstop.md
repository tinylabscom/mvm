# A backstop for the verdict that never arrives

Backing: shipped-source
Validation: check-claim-catalog

`security-lane-watch.yml` fires on `workflow_run: [Security] completed`.
On 2026-08-21 the Security nightly completed at 11:36:49Z and **no watcher
run was created for it** — no repo workflow run exists in that window at
all. Every other sampled completion, cancelled ones included, did trigger
one, so cancellation does not explain it. Tracked as #2792; the mechanism
is still unknown.

An event that is never delivered produces no run, no verdict and no trace,
which reads exactly like a green night. That is the same silence the
five-week Security blackout produced, reached from a different direction,
and it is why the enforcement surface cannot be a single event-driven
watcher.

`check-claim-witness-freshness` is the right owner: it already runs on its
own schedule rather than on `workflow_run`, precisely so it can notice
absence. It asked "did the lane run?"; it now also asks "did the thing that
reports on the lane run?".

This is not the duplication its module header warns against. That header
declines to re-check *conclusions*, because the watcher owns that verdict
and two gates on one property can disagree. Whether a verdict was produced
at all is a different property with no other owner.

Run against the live repository, it reproduces the incident:

```
security.yml completed at 2026-08-21T11:36:49Z and security-lane-watch.yml
never ran for it — claim(s) [1, 3, 4, 5, 6, 7, 10, 11, 15] had no verdict
reported either way
```

## Why it is off for pull requests

The check is behind `--check-reporting`, which the workflow passes on every
trigger except `pull_request`. The two questions this gate now asks have
different audiences:

- **A lane stopped firing** can be *caused* by the diff under review — a
  cron edit that drops a lane out of scope is exactly what the PR trigger
  exists to catch. That still fails a pull request.
- **A completed run nobody reported on** is history. No PR author can fix
  it, and reddening their branch for it is how a gate teaches people to
  ignore it — the failure mode this whole area keeps producing.

So the reporting-chain finding goes to the scheduled run and its tracking
issue, which is where the other absence findings already go.

## Limits

It detects that no watcher run followed a completion. It does not explain
why the event was not delivered, and it cannot force delivery. If #2792
turns out to be a recurring GitHub behaviour rather than a one-off, the
watcher stops being a sound design and the verdict wants pulling into the
lane itself — but that is a bigger change than a backstop, and it should
wait for evidence of a second occurrence.
