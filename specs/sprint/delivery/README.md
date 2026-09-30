# Delivery entries — frozen historical archive

This directory preserves delivery notes written before GitHub issues and pull
requests became the sole work-tracking and delivery record. Do not add or
update entries here as part of ordinary work.

```
specs/sprint/delivery/<issue-or-plan>-<slug>.md
```

e.g. `2365-audit-log-rotation.md`, `2321-workload-runner-root.md`.

The file name is the historical identity and `git log` is the ordering.

## Why this exists rather than a list in one file

`specs/SPRINT.md` had a single append-only section that every session wrote to
at the same insertion point. Git cannot merge that, so it conflicted on
essentially every rebase while the team was productive — the conflict rate was a
function of throughput, not of anything anyone did wrong.

The cost was never the resolution, which takes a minute. It was that every
rebase forces a full re-gate (fmt, clippy, ~11k tests), so a documentation
conflict spends twenty minutes re-proving code that did not change. PRs were
observed going `CLEAN` → queued → `DIRTY` with their own code untouched, purely
because another session appended a paragraph. One of them (#2379) was evicted
from the merge queue by exactly that.

The real risk was worse than the delay. Hand-merging the same prose repeatedly
is how somebody's entry silently disappears — resolving those conflicts
correctly means keeping *both* sides every single time, and nothing enforced
that. Twice during one session `main` had *rewritten* an entry a branch had also
edited, which a careless `--theirs` would have reverted.

Separate files cannot conflict with each other. That removes the collision
instead of making it cheaper to resolve, and it makes losing an entry take a
deliberate `git rm` rather than a moment's inattention.

The former sprint and refactor dashboards are preserved under
`specs/archive/status/`. Current status belongs in GitHub issues, and delivery
and validation belong in pull requests.
