# Pack signing smoke acceptance evidence

Backing: preview
Validation: none — this records evidence for the parent issue; it is not a claim of complete enforcement.

This reconciles [#4537](https://github.com/tinylabscom/mvm/issues/4537) (the
`Pack signing smoke` lane red) against a run after the fix. The issue owns
status.

## Acceptance evidence and its limits

| Criterion | Evidence | Limit |
|---|---|---|
| The cause is identified and fixed | [Run 39338499440](https://github.com/tinylabscom/mvm/actions/runs/39338499440) on `61c07997a30b5e8a6d35e5952f02dc4b43c2a7ab` passed genuine builder and runtime signature verification, then failed image-set protocol compatibility: the synthetic fixture declared contract 1 and the host requires contract 5. The fixture now derives its contract from the image lock, without changing production verification or admission | The fix is to the test fixture. Nothing about production admission was exercised differently. |
| The lane is green after the fix | [Run 39435165141](https://github.com/tinylabscom/mvm/actions/runs/39435165141), `workflow_dispatch` on `260797edf7fa81ef03fb6e8c043348ec1e1a956e`, which contains the fix: job `smoke` succeeded | A dispatch, not the tag-push event the issue was opened for. Both run the same `smoke` job; the tag-push run will repeat on the next `v*` tag. A scheduled run on main also passed on 2026-10-20 at 04:49Z, but it predates the fix merging and is not counted. |
