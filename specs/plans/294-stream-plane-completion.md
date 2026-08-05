# Plan 294 — stream plane completion and handoff

**Status:** WS-A complete. WS-B outstanding.

PR #2139 **merged** 2026-08-05 as `b567b01d6`, all lanes green. Issue #2152 closed.
What remains is WS-B plus the renumbering and the fleet slice.

Tracking issue: tinylabscom/mvm#2152 (closed). PR: tinylabscom/mvm#2139 (merged).

This is the state-of-the-world doc for the workload stream plane. The design
lives in `specs/plans/283-workload-stream-plane.md`, the follow-ups in
`specs/plans/293-stream-plane-followups.md`, and the fleet slice in
`specs/plans/292-fleet-stream-fan-out.md`. This doc says what is done, what is
left, and the two traps that will otherwise cost a session.

## Read this first: two plan numbers are ambiguous

`main` and the stream-plane branches independently claimed the same numbers:

| Number | On `main` | On the stream-plane branches |
| --- | --- | --- |
| 283 | `283-production-object-store-volumes.md` | `283-workload-stream-plane.md` |
| 292 | `292-tiered-artifact-storage-and-warm-start.md` | `292-fleet-stream-fan-out.md` |

`main` already carries two 284s and two 285s, so the convention had slipped
before this. **Refer to these documents by filename, never by number.**

Renumbering to 295/296 is deferred until after #2139's merge lands — renaming a
file inside an unresolved 42-file merge produces rename/modify conflicts, which
resolve worse than content conflicts. Do it as a follow-up commit, not as part
of the merge.

- [ ] After #2139 merges: renumber `283-workload-stream-plane.md` and
      `292-fleet-stream-fan-out.md` to free numbers, updating cross-references
      in ADR-035, ADR-001, `specs/REFACTOR-STATUS.md`, and this doc.

## Branch inventory

| Branch | Worktree | State |
| --- | --- | --- |
| `docs/workload-stream-plane` | *(worktree removable)* | **MERGED** as `b567b01d6`. |
| `feat/stream-plane-followups` | `.worktrees/mvm-followups` | WS1 complete and pushed. **No PR yet.** |

About 20 other worktrees are live and most have active work. Touch only these
two.

Mechanics that bite: the shell cwd resets to the main checkout between
commands, so use `cd <abs> &&` or `git -C`; and Bash writes into `.worktrees/*`
are outside the primary working directory, so they are silently discarded
without `dangerouslyDisableSandbox`.

---

## WS-A — Unblock PR #2139

### The finding: CI has never been dispatched, and this is not a test failure

`gh pr checks 2139` reports *no checks*. The API confirms zero workflow runs
ever, for both the branch and the head SHA. The panel is empty, not red.

For `pull_request` events GitHub tests `refs/pull/N/merge` — a merge commit it
computes between head and base. With 42 conflicting files that ref cannot be
computed, so **no workflow is ever dispatched**. `ci.yml` has no branch or path
filter, and Actions is healthy on other PRs; nothing is misconfigured.

Resolving the conflicts starts CI on its own. Do not go hunting in `ci.yml`.

### The merge

- [x] `git merge origin/main` — **done**, in two passes (`c5851cfb6`, then
      `ad10db4c9` when main landed the crate rename mid-merge). CI dispatched
      on the second push; the PR went `CONFLICTING` → `MERGEABLE` and
      auto-merge is armed.

`merge-tree`'s "changed in both" over-reported: of 42 such files only **8**
actually conflicted, 10 hunks total. The second pass was larger — main
renamed `mvm-protocol` to `mvm-contract` (#2154), which moved 72 references
across 32 files and required moving this branch's `stream/` module into the
renamed crate by hand, since git renames the crate's own files but cannot
carry across a module the branch had added.

**Disable `rerere` first** — `git config rerere.enabled false`, already set in
that worktree. It has previously replayed a stale resolution and silently
dropped content in this repo. Verify `git diff --cached` before committing.

#### Most conflicts resolve by taking both sides

Main's 21 commits are largely **additive to the plan schema**: kernel pinning
(`56f2cc705`), attested deployment references (`40b87a77c`, `2adc85e8f`),
precomputed rootfs digest verification (`a620e3212`), agent verb tiers
(`b2c6c5fec`, `970004aab`).

This branch is **also additive** to the same structures: a `host.stream.v1`
services grant, private `AdmittedPlan` fields, stream and transcript plumbing.

So the dominant conflict is *both sides added a field or match arm at the same
spot*. **Take both.** If you find yourself deleting a field, arm, test, or doc
paragraph that only one side had, re-read — that is the failure mode this repo
has actually hit.

Where one side does win:

- **`Cargo.lock`** — do not hand-merge. Take either side, let cargo regenerate,
  commit the result.
- **`specs/SPRINT.md`, `specs/REFACTOR-STATUS.md`** — take both sides' entries.
  These are rollups; dropping a line silently un-does someone else's status
  update.
- **`public/astro.config.mjs`** — take both sides' nav entries.

The 42 conflicting files span `crates/mvm-{cli,core,hostd,protocol,runtime,
agentd,client,sdk}`, `Cargo.lock`, `README.md`, `public/astro.config.mjs`,
`specs/SPRINT.md`, and `specs/REFACTOR-STATUS.md`. The full list is in #2152;
`git merge origin/main` will reproduce it exactly.

### Invariants that must survive the merge — verify each explicitly

Several are claim-backed. A silent loss in a 42-file merge is a security
regression, not a bug.

- [ ] `AdmittedPlan` fields stay **private** — an input grant must not be
      forgeable by an in-process struct literal
- [ ] `host.stream.v1` grant, its default-deny, and the `--prod`
      shell-entrypoint refusal
- [ ] Workload guests keep **no NIC**; egress stays vsock-only (both `xtask`
      vsock gates)
- [ ] Single redaction seam — redaction runs once, *before* hash-chaining
- [ ] Reserved `mvm.` fd-3 kind namespace — a workload must not forge
      agent-authored control records
- [ ] Transcript manifest format version, and the sealed-root **preimage** test
      (it pins the JSON preimage, not a digest, so it survives a root change)

### Gates

```
cargo fmt --all -- --check
cargo +nightly fmt --all -- --check      # CI Lint uses NIGHTLY rustfmt
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
cargo test --workspace --doc             # nextest skips doctests
cargo run -p xtask check-claim-catalog
cargo run -p xtask check-uniform-vsock-egress
cargo run -p xtask check-vsock-only-egress
cargo run -p xtask check-no-spec-refs
cargo run -p xtask check-core-runtime-free
cargo run -p xtask check-guest-agent-runtime-free
```

Known-environmental, not caused by this branch: `check_cmd_rustup_on_host`
(rustup absent on the dev machine), and seven `mvm-runtime` spawn tests that
need an idle machine — they pass in under 1.3s each at idle, so run
`-p mvm-runtime` alone rather than concluding they are broken.

### Open question — who owns the `replay_vectors` failures?

- [ ] Three `mvm-core plan::content_id::tests::replay_vectors::*` tests were
      failing **before** any merge. Main added fields to `ExecutionPlan`, which
      changes content IDs, so these are plausibly pinned vectors invalidated by
      main's own schema change. Determine whether they fail on `origin/main`
      alone — `/private/tmp/mvm-basecheck` is a spare detached worktree. If main
      owns them, do not paper over it in this branch; report it separately.
      This was never settled and should not be assumed either way.

---

## WS-B — `feat/stream-plane-followups`

### WS1 — complete

Landed in `a3643e1e4`, reviewed, spec compliance and task quality both
approved. Fingerprints are computed inside `mvm-substitution-endpoint` where the
credentials already live; only a 16-byte
`SecretFingerprint { len, hash, category }` crosses to the CLI; `KnownSecret`
was deleted rather than deprecated. Claim 17's limit 1 is genuinely closed and
the row correctly stays `Preview`.

The review's Important finding (the blanket carry stalling stdin) and all three
Minors were fixed in that same commit. Details in
`specs/plans/293-stream-plane-followups.md` §"WS1 follow-on".

**Do not re-open the carry design.** The module doc in
`crates/mvm-hostd/src/stream/secret_scan.rs` states the problem and its
resolution in adjacent sections; reading only the first half suggests an
unfixed defect. `DEFAULT_IDLE_FLUSH_AFTER` = 50ms and `InputSession::refresh`
release the withheld tail on **elapsed time alone**.

The reason that design is what it is, recorded so it is not re-litigated: the
obvious alternative is binding *prefix* fingerprints so the scanner withholds
only a live prefix. That looks free and is not. It makes the withhold/deliver
decision **depend on content**, which is a **prefix oracle** — anyone holding
the input grant feeds a byte, observes whether it was withheld, and walks a
40-byte secret out in ~40×256 probes instead of 256⁴⁰. That is a
secret-extraction path against what claim 13 protects, and strictly worse than
a stall. The blanket carry is load-bearing precisely because it leaks nothing
about content, and the idle release is safe precisely because elapsed time is
not content.

### Remaining

- [ ] **WS2 — redact the console fallback.** It is currently unredacted while
      the transcript is redacted, which is a real disclosure gap and the
      highest-value item left on this branch.
- [ ] **WS3 — gate prose against the ledger.** Prose drifted from the ledger
      nine times during the stream-plane work, including witnesses that exist
      nowhere: `audit_chain_carries_no_payload_bytes` is cited in `CLAUDE.md`
      and was cited three times in the design plan, and does not exist.
- [ ] **WS4 — gate dormant controls.** Six tasks shipped correct, tested,
      unreachable machinery with no production caller, each caught only by
      review. This is the single most repeated defect in the effort.

WS3 and WS4 guard against recurrence rather than fixing a present defect, so
they are the most deferrable items here. WS2 is not — it is an open gap.

- [ ] Open a PR for this branch. It has none, and its work is invisible to CI
      until it does.

---

## Also queued

- [ ] **`specs/plans/292-fleet-stream-fan-out.md`** — VM-to-VM fan-out,
      unstarted. All seven design decisions (E1–E7) are settled in that
      document: redaction is a property of the edge, defaulting to redacted; an
      opt-out edge gives the consumer raw bytes while the transcript stays
      masked and the divergence is audited; the single-writer lease stays and
      fan-in is a merge node; `lossy` (default) rings and marks a gap while
      `reliable` fails the edge loudly, never silently dropping; DAG only,
      rejected at admission; a broken edge fails the workflow, because a fresh
      `SecretScanner` per session means reconnect would split a secret across
      two scanners; and redaction opt-out needs operator acknowledgement shaped
      like `MVM_ACK_UNRESTRICTED_NETWORK=1`.

## Sequencing

WS-A first — it unblocks CI on 60 commits of finished work, and nothing else on
this effort can merge behind it. WS2 next, since it is an open disclosure gap.
WS3 and WS4 after. The fleet slice last; it depends on the stream plane being
on `main`.
