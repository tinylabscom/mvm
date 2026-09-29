# Open-issue burn-down: current ownership and priority

Backing: preview
Validation: none

**Status: DRAFT.** Snapshot: 2026-09-28 PT. This supersedes the 2026-09-24
snapshot in `2026-09-24-open-issue-burndown.md`; issue, PR, worktree, and
session ownership must be checked again immediately before starting each item.

## Target and scope

The target is zero open issues authored by `auser` across `mvm`,
`mvm-assurance`, and `mvm-images`, with the relevant implementation PRs merged.
The live snapshot has 43 such open issues in `mvm`, none in `mvm-assurance`,
and one in `mvm-images` (#8). An issue is available to this workstream only if
another session is not working on it and no open or merged implementation PR
already covers it. A plan mention or partial documentation PR is not proof
that an implementation issue is done.

Use one dedicated worktree and branch per issue. Do not edit another session's
worktree. `mvm` owns its product plan, code, tests, issues, and PRs; the
canonical image build, composition, signing, and publication path belongs in
`mvm-images`. `mvm` may consume and verify those images but must not create a
replacement image-build path. Closing an epic waits for its children and
acceptance evidence, not just a merged tracking-plan PR.

## Ordered queue for this workstream

These are the currently unclaimed or dependency-gated items, in the order to
reconsider them. A gate is not permission to take work from its owner. Keep a
checkbox unchecked until the issue is closed by verified merged work.

1. [ ] **#3725 — Nix developer experience.** Draft PR #3818 is this
   workstream's dedicated branch. Finish builder-VM evaluation/build of
   `#prebuilt`, measure default devShell cold start before/after, clear CI,
   update the owning plan, sprint, and rollup together, then merge and confirm
   issue closure. Keep the source-built `nix/` package separate; no external
   cache provider or image-building logic is added here.
2. [ ] **#3724 — distribution packaging.** The dedicated worktree is clean.
   Decide signing/notarization policy, whether registry publication is manual
   or automatic, and supported host targets before slicing the issue. Do not
   overlap the active pack-signing, SDK, and publication workstreams. Then
   deliver package formats, ordered crate publication, native libraries in
   Python/npm artifacts, and per-artifact smoke as separately reviewable PRs.
3. [ ] **#3723 — per-tool privileges.** Wait for PS-05 policy profiles (open
   PR #3798) to merge. Then take a new ownership snapshot, implement tool
   mediation and credential brokering on the resolved-policy contract, and
   prove fail-closed behavior and audit records.
4. [ ] **#3716 — signed packs and registry.** Depends on PS-05 and PS-13.
   Its manifest/signing acceptance also names `mvm-templates`; coordinate that
   repository's scope before editing it. Verify publisher trust, digest pins,
   pack profile restrictions, and admission re-verification before merge.
5. [ ] **#3267 — attended display input.** Wait for the owned host OAuth
   broker (#3266). Keep view and input grants distinct; sealed-tier denial,
   clipboard default-off, and no keycode audit leakage are acceptance gates.
6. [ ] **#3727 — capability and client documentation.** No implementing PR
   was found in this snapshot. Wait for policy/schema and pack surfaces to
   stabilize, then document each shipped capability and generate the schema
   reference. Do not document unmerged behavior as shipped.
7. [ ] **#3553 — Windows host support.** No implementation PR or matching
   worktree was found. First obtain the platform/backend decision and a real
   Windows build-and-boot CI lane; then implement in its own worktree. This is
   later than security and shipped-path work because its validation platform
   is not yet established.
8. [ ] **#3373 — post-cutover history compaction measurement.** Wait for the
   image cutover and owned W7/W8 work to settle. This issue authorizes a
   measurement and go/no-go record, not an automatic history rewrite.
9. [ ] **#3599 — Kubernetes PID-namespace smoke.** Parked by the owner as low
   priority. The original no-`--fork` reproducer did not prove a kernel bug;
   the remaining evidence is a real pod on the relevant workload kernel.
   Do not change kernel configuration based on the old reproducer. Existing
   merged PRs addressed documentation and the image-source bridge, not this
   final pod witness.

## Owned lanes: observe, do not implement here

These open issues still count toward zero, but another session has an open PR,
a live/claimed worktree, or a partial merged implementation campaign. The
named PR/worktree is ownership evidence, not a claim that acceptance is done.
If an owner drops a lane, recheck issue comments, PR contents and status,
worktree state, and session ownership before moving it into the queue above.

| Lane | Open issues | Current evidence and release order |
|---|---|---|
| Shipped-path correctness | #3752, #3303, #3384 | #3752 has PRs #3814/#3804; #3303 has admitted-launch worktrees; #3384 has checkpoint work/review. Finish these before broadening launch/storage behavior. |
| Policy and egress | #3712, #3714, #3715, #3717 | #3715 has PR #3798; #3714 has PR #3816; #3712 has an egress/injection worktree; #3717 has merged PR #3756 but remains open. Reconcile acceptance after the owned changes land. |
| Agent product surface | #3731, #3729, #3726, #3721, #3720, #3719, #3718 | #3731 is the epic. Open PRs #3767, #3768, #3753, #3751 cover four children; audit-session and undo-diff worktrees cover two more. Close the epic only after all children and witnesses land. |
| OAuth, SDK, display | #3743, #3266, #3261, #3275, #3276 | #3743 has PR #3808; #3266 has an OAuth worktree; #3261 has merged partial PRs and active SDK worktrees. The two epics wait for their child acceptance, including #3267 above. |
| Security conformance | #3655 | A dedicated containment-lab worktree exists. Keep destructive live exploit validation in its owner-controlled lab lane. |
| GPU | #3580, #3562, #3561, #3560 | Active GPU campaign and merged partial PRs; hardware witnesses and the epic closure stay with that owner. |
| Portable artifacts | #3551, #3457 | Dedicated embedded-image-set and SDK-sidecar worktrees exist. Coordinate their producer contract with `mvm-images`; no duplicate producer in `mvm`. |
| Telemetry | #3426, #3425, #3424, #3423, #3422, #3421, #3419 | #3421 has PR #3659; the W3→W7 sequence is owned. Preserve that dependency order and close the core epic last. |
| Naming | #3315 | Multiple merged module PRs and an ongoing sweep; reconcile remaining public API pairs with its owner. |
| Image base | `mvm-images#8` | The image repository has active worktrees and partial merged work. The base image remains backend-neutral, NIC-less, and built/published only there. |

`mvm-assurance` has no open `auser` issue in this snapshot. Do not invent work
there to make the count appear smaller.

## Reconciliation loop

For each issue in priority order: check the live author/open list across all
three repositories; inspect all open and merged PRs by **content**; inspect
worktrees and session ownership; only then create or resume that issue's own
worktree. Write tests first, run the repository gates in the correct host or
builder-VM boundary, update the issue's plan checkboxes plus `SPRINT.md` and
`REFACTOR-STATUS.md` together after green evidence, and merge through its PR
queue. After each merge, sync the main checkout and verify whether GitHub
closed the issue. If not, inspect unmet acceptance before closing it.

Repeat the inventory after every merge and ownership handoff. The final audit
is not a stale plan checkbox: it is zero live open `auser` issues in the three
repositories, with the relevant implementation PRs merged and every accepted
behavior verified. If an issue remains owned elsewhere, report that count
explicitly rather than taking over its worktree or claiming zero.
