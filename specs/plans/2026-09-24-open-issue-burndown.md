# Open-issue burn-down: every unowned `auser` issue to merged and closed

Backing: preview
Validation: none

**Status:** DRAFT. Snapshot taken 2026-09-24 against `origin/main` at
`988f1f6c2b`. Verify this before starting any item: ownership moves quickly.

## Scope

On 2026-09-24 there were 35 open issues. This plan covers the 17 that meet
all four conditions:

1. opened by `auser`;
2. no live session is working on them in `mvm`, `mvm-assurance` or
   `mvm-images`;
3. no open PR implements them;
4. no merged PR implements them.

"Implements" is judged by content, not by a number match. A PR that only
mentions an issue does not count: the plan PR that created it, a dead-code
sweep, or an unrelated PR whose number collides. The two cases where that
call matters are flagged inline (#3304, #3639).

"Done" means every issue below is closed, each by a merged PR that names it,
and every epic here is closed because its children are.

### How ownership was established

- `ListAgents`, plus the tmux panes of the seven peer sessions. Four of them
  (`image-repo`, `noKV`, `smolvm`, and the image-extraction session) have hit
  their weekly limit and stay idle until 2026-09-25 09:00 PT. They still own
  their campaigns.
- Session transcripts under `~/.claude/projects/` and the Codex thread table,
  to see which issues each session had claimed.
- `git worktree list` for all three repos, with each worktree's last commit,
  uncommitted-file mtimes and upstream. A worktree whose newest edit is older
  than 24 hours, with no session referencing it since, counts as **stalled**
  rather than owned.
- `gh pr list --state all --search "<n> in:title,body"` for each issue.

## Excluded, and why (18)

These stay with their owners. They are listed so the zero-open target is
honest about what it does not cover.

| Issue | Reason |
|---|---|
| #3637, #3651 | Not opened by `auser` (`aneyzberg`, `github-actions`). |
| #3366, #3368 | Open PR #3649 (W7/W8 plan). The image-extraction campaign owns them. |
| #3419, #3421 | Open PR #3643 (telemetry W2 witnesses). |
| #3560, #3561, #3580 | Open PR #3656 (MLX design). The GPU campaign merged #3652–#3654 today. |
| #3562 | Part of the live GPU epic #3560. |
| #3646 | Live: `mvm-base-image-cve-gate` committed 11 minutes before the snapshot and has staged code. |
| #3261 | Nine implementation PRs merged (#3469 … #3571). The agent-sandbox workstream is still in flight. |
| #3275 | Epic. Child #3261 is still in flight, and #3338 merged. |
| #3303 | #3337 and #3357 merged. The unification worktrees are stale (2026-09-18) but claimed. |
| #3315 | Per-module sweep under way: #3545, #3546, #3547, #3613, #3620. |
| #3384 | #3473, #3575, #3626 merged. The sandbox-review session holds C1–C3. |
| #3422, #3423 | Telemetry W3/W4. #3441, #3464 and #3472 merged. |

## Priority order

Ordering rule: first, a defect that writes a **wrong** audit entry or breaks a
shipped path; then evidence integrity; then the product claim (agent
sandbox); then cost and portability; last, anything blocked on an owned
campaign.

### Wave 1: P0 correctness and security bugs (parallel, disjoint files)

- [ ] **#3304 — a grant that failed to apply is audited as enforced.** The
  CLI arm (`grants_report.rs` `read_back_tier`) falls back to
  `EnforcedGrants::all_declared()` and emits a chain-signed entry that
  claims enforcement. That is a wrong entry against Preview claim 18.
  - Fix it narrowly, without unifying the two launch stacks (that is #3303's
    work, and #3303 is claimed). On an apply failure, fail closed the way
    `start_admitted` does: stop the VM and emit no `plan.grants_enforced`.
    Pass the backend object that started the VM instead of rebuilding one
    from a string with `AnyBackend::from_hypervisor`.
  - Witness: a mock backend whose `apply_grants` errors means the boot is
    refused and the audit chain has no enforced entry for it.
  - Coordination: the `mvm-admitted-launch-unification` and
    `mvm-3303-admitted-launch` worktrees touch the same tail. Read their diffs
    first. Do not edit inside them.
- [ ] **#3502 — a Firecracker transient run rewrites the cached dev rootfs.**
  The journal commit lands after admission hashed the image, so
  `plan.admitted` records a digest the file no longer has, and the shared
  cache is mutated on every run.
  - Salvage the stalled `mvm-3502-fc-rootfs-immutability` diff (4 files, last
    edit 2026-09-22) into a fresh worktree. Then attach the cached image
    read-only at the drive, or give each run its own copy-on-write clone.
    Whichever it is, the cached file must not be writable by the VMM.
  - Witness (Linux/KVM only): the digest is unchanged across N runs, and the
    `plan.admitted` digest matches the file after the run. Needs the KVM box.
    Run `just check-gated`, because this is `cfg(target_os = "linux")` code.
- [ ] **#3484 — builder dependency installs dial upstream directly.** On the
  libkrun builder, installs fail outright: no NIC, no TSI, no route. On QEMU
  they leave through slirp, bypassing the host `EgressGate`.
  - Salvage the stalled `mvm-3484-install-vsock` diff (31 files, last edit
    2026-09-19; the 2026-09-19 "Taking this" comment has gone quiet). Rewire
    the install job onto `VsockProxyLifecycle` for NIC-less builders. The QEMU
    builder should either use the same relay or refuse installs, but it must
    not keep a second egress path. `check-single-network-path` must stay
    green.
  - Witness: a NIC-less builder install reaches an allow-listed index through
    the gate, a denied destination is refused, and QEMU does not dial direct.
- [ ] **#3503 — `machine stop` of a restored HVF machine leaves its state
  directory**, so the next restore fails with `EEXIST`. Deterministic.
  - Fix only the stop and cleanup lifecycle. Do not touch restore or verify:
    that is #3384 C1–C3's territory, and its owner is idle until 2026-09-25.
    Also look at the related one-off race, where the state directory was
    removed while a restore was running.
  - Witness: create → checkpoint → stop → restore → stop → restore succeeds
    three times in a row on HVF (this host). Add a unit test on the
    state-directory removal.

### Wave 2: P1 evidence integrity and external evidence

- [ ] **#3639 — mutation lane: unpinned cargo-mutants, and silent shard-tail
  gaps.** Borderline on scope: #3640 only realigned one baseline entry and
  addressed neither ask.
  - Pin `cargo-mutants --version X.Y.Z` in `security.yml`.
  - Make `check-mutation-witnesses --run` compare each shard's expected file
    list against the files it actually reported. A file that was never reached
    is **unmeasured**, which is a failure, not a pass.
  - Witness: an xtask unit test in which a truncated shard fails.
- [ ] **#3655 — witnessed CVE-2026-80521 containment.** Time-sensitive: the
  public disclosure is dated 2026-09-22, and the response post waits on this
  witness.
  - Build a `mvm-conformance` scenario at risk ceiling `DestructiveLabOnly`.
    It boots a sealed guest on a kernel known to be vulnerable, runs the
    public exploit through admission, and asserts from the host: guest
    compromised; host and sibling guest untouched; egress denied; audit chain
    intact.
  - Lab-only (KVM box). It must never gate a PR. Pin the vulnerable kernel
    and the exploit source by digest.

### Wave 3: P2 agent-sandbox surface (sequential where noted)

- [ ] **#3262 — MCP drive verbs; fail closed on unclassified tools.**
  - The stalled `mvm-3262-mcp-drive` branch has four unpushed commits. Three
    are already on `main` (drive plane #3505, guest operations #3482). Rebase
    onto `origin/main` in a fresh worktree and keep only `630ca0b8d5`
    ("expose grant-gated drive tools").
  - Witnesses named in the issue: `mcp_tool_absent_when_grant_absent`,
    `mcp_unclassified_tool_is_denied`.
- [ ] **#3266 — host-side OAuth broker.** Consent happens in a host browser.
  The token stays in the supervisor and is injected through the existing
  substitution endpoint. The guest receives a destination-bound placeholder,
  and the binding model is extended to cover refresh.
  - Salvage the stalled `mvm-3266-oauth-broker` diff (15 files, last edit
    2026-09-19).
  - Security review before merge: this is adjacent to claim 13.
  - Witness: `oauth_token_substituted_at_endpoint_never_reaches_guest`.
- [ ] **#3267 — `display.input`, attended tier only.** Blocked on #3266.
  - Separate `display.view` and `display.input` grants. Refuse on the sealed
    tier without an attended grant. Reuse `InputGate`'s lease, but not its
    secret scan. Audit event kinds and counts, never keycodes. Clipboard is
    its own grant, default off. The human-credential marker refuses
    fork/checkpoint for the rest of the run.
  - Witnesses: the three named in the issue.
- [ ] **#3276 — display-plane epic.** Close it once #3266 and #3267 merge
  (#3265 is already closed).

### Wave 4: P3 cost and portability features

- [ ] **#3457 — fetch the published SDK sidecar when its source fingerprint
  matches.** Saves 23–27 minutes per Linux release E2E.
  - Two repositories. First, `mvm-images` publishes the fingerprint in the
    signed manifest or image-set member metadata. Then `mvm` compares
    fingerprints, and on a match fetches and verifies the published sidecar
    instead of building it.
  - The stalled `mvm-3457-sdk-sidecar` branch is stacked on #3369's
    pre-merge commit, and #3369 closed today. Rebase before salvaging.
  - Coordinate the producer half with the image-extraction session once it
    resumes (2026-09-25).
- [ ] **#3551 — embed the image set in `.mvmpkg`.** Consumer side only; the
  producer is `mvm-images#8`. Every validation calls `mvm_core::image_set`,
  with no forked checks. "Backend cannot satisfy this artifact" becomes a
  named refusal.
  - The stalled `mvm-3551-embedded-image-set` branch (18 dirty files) is also
    stacked on #3369's pre-merge commit. Rebase first.
  - Likely two or three PRs: manifest member class, then fetch/install
    admission, then the backend-capability refusal.
- [ ] **#3553 — Windows host via libkrun.** The largest item and the last
  feature.
  - Needs a Windows CI lane that builds and smoke-boots under the Windows
    Hypervisor Platform, a supported-tier label that admission can reason
    about, and platform docs.
  - It also reverses CLAUDE.md's "libkrun is explicit-only" on one platform.
    Get an ADR or maintainer decision before any code.

### Wave 5: P4 blocked on owned campaigns (do not start early)

- [ ] **#3424, #3425, #3426 — telemetry W5–W7.** Hard sequencing in the
  issues: W3 + W4 → W5 → W6 → W7. W2 (#3643) is open, and W3/W4
  (#3422/#3423) are still open. Pick these up only once W3 and W4 close, and
  then only after confirming with the telemetry owner (the #3643 author).
- [ ] **#3373 — measure post-cutover history compaction.** Starts after
  #3366 and #3368 close. Measurement and a go/no-go record only. A history
  rewrite needs separate owner approval and a merge freeze.

## Per-issue procedure (Definition of Done)

For every item:

1. Re-check ownership: `ListAgents`, `gh pr list --search <n>`, and the
   worktree mtime. If anything changed, skip the item and note why here.
2. `git fetch && git worktree add ../.worktrees/mvm-<n>-<slug> -b <type>/<n>-<slug> origin/main`.
   Never work inside another session's worktree. Salvage from a stalled one
   with `git diff` / `git cherry-pick` into the fresh worktree.
3. Write the failing witness first, then the fix.
4. Run the full gate list from the CI workflows: `cargo fmt --all -- --check`,
   `cargo nextest run --workspace`, `cargo test --workspace --doc`,
   `cargo clippy --workspace -- -D warnings`, `cargo run -p xtask -- check-all`,
   `just check-gated`, plus the test-support lane and any Linux-gated
   cross-check.
5. Record the delivery in `specs/sprint/delivery/<n>-<slug>.md`. Tick the
   matching boxes in `specs/SPRINT.md`, `specs/REFACTOR-STATUS.md` and the
   owning plan in the same change.
6. Open a PR whose body says `Closes #<n>`, then run
   `gh pr merge <pr> --auto --squash`. Follow it through the merge queue to
   merge, and verify the merge by content on `main`.
7. Confirm the issue closed, tick it here, and remove the worktree.

## Parallelism and collision map

- Wave 1's four items touch disjoint areas and can run at the same time:
  - `mvm-cli`/`mvm-client` grants tail
  - `mvm-backends` FC drive config
  - `mvm-build` egress proxy and host-vm-init
  - HVF stop lifecycle
- Wave 2 can overlap Wave 1.
- The #3304 grants tail collides with the #3303 unification worktrees.
- The #3503 stop lifecycle sits next to #3384's restore rewrite.
- The #3457/#3551 image-set code sits next to the image-extraction campaign.
- Host constraints:
  - #3502 and #3655 need the Linux KVM box.
  - #3503 needs this macOS 26 HVF host.
  - #3553 needs a Windows runner.
