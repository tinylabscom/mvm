# Delivery entries — one file per landed change

Write a **new file here** when you land something. Do not append to
`specs/SPRINT.md`.

```
specs/sprint/delivery/<issue-or-plan>-<slug>.md
```

e.g. `2365-audit-log-rotation.md`, `2321-workload-runner-root.md`.

No frontmatter, no index to update, no ordering to agree on. The file name is
the identity and `git log` is the ordering.

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

`xtask check-sprint-append` keeps the old section from growing back.

## Reading them together

```sh
cargo run -p xtask -- sprint
```

Renders every entry newest-first by commit date. Deliberately not committed —
a generated file in the tree is one more thing to conflict over, which is the
problem this directory exists to solve.
