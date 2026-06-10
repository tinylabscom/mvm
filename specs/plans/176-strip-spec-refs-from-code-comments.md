# Plan 176 — Strip plan/PR/ADR/sprint references from code comments (Implementation Plan)

> **Numbering:** 176 is the next free plan number (`origin/main` holds plans
> through 175 — 175 = firecracker-warmstart). `check-spec-numbers` rejects
> duplicates — confirm still-free at merge time.

> **For agentic workers:** mechanical, high-volume sweep. Use
> `superpowers:subagent-driven-development` and fan the file list out to
> parallel workers — each owns a disjoint set of files, applies the
> transform rules below, and reports back. Steps use checkbox (`- [ ]`)
> syntax.

**Goal:** No source comment refers to a plan, PR, sprint, ADR, or
workstream by number. Those are *implementation-process* artifacts — they
belong in `specs/`, in commit messages, and in PR descriptions, never in
the shipped code. The *reasoning* a reference used to gesture at (an
invariant, a gotcha, a fail-closed rationale) must survive — stated
directly — wherever it was load-bearing. Where the reference was the
whole comment, the comment goes.

**Why now:** ~2,531 such comments have accumulated across the tree (≈1,865
`Plan N`, ≈750 `ADR-NN`, ≈315 `Wn.X` workstream, ≈28 `Sprint N`, ≈13
`PR #`). They read as scaffolding from the refactor chain that was never
cleaned up. A reader of the code shouldn't need the spec archive to parse
a comment, and a reference like `// Plan 46:` ages into noise the moment
the plan merges.

**Scope:** Comment text only — `//`, `///`, `//!`, and `/* … */` — in
`.rs`, `.nix`, `.sh`, `.toml`, and `build.rs`. Out of scope and explicitly
NOT touched: string literals, identifiers, audit-detail wire formats, the
`specs/` tree, `public/` docs, and the lint code that legitimately parses
these tokens (see Guardrails).

---

## Guardrails (every task)

- **Preserve behavior. Comments only.** Never edit a string literal, a
  `const`, an identifier, a test name, or an emitted audit-detail format
  — even when it contains `ADR-006` or `plan`. If a `match` arm or wire
  string carries a plan/ADR token as *data*, leave it. A change that
  alters compiled output is out of scope by definition.
- **Keep the reasoning, drop the citation.** When a reference is bolted
  onto a real explanation (`/// … ADR-007 / plan 41 W4 — refusing to
  resume a tampered snapshot is a security action`), strip only the
  citation, keep the rest (`/// … refusing to resume a tampered snapshot
  is a security action`). When the citation *is* the comment
  (`// --- Plan 46: metering API ---` → `// --- metering API ---`, or
  delete if the label adds nothing), remove it.
- **Do NOT delete a comment that loses its only content** without
  checking it wasn't carrying a real warning. If `// Plan 88 W6` sat
  above a non-obvious block, the fix may be to *write* the missing why,
  not to leave a bare line. Bias toward stating the invariant.
- **xtask lints are safe but verify.** `xtask check-adr-coverage`
  (`xtask/src/check_adr_coverage.rs`) fails only on a code reference to a
  *non-existent* ADR; zero references is a soft warn — so removing
  in-code ADR refs cannot break it (it can only shrink the
  `KNOWN_MISSING_ADRS` allowlist, a welcome side effect — prune entries
  that reach zero references in the same change). `check-doc-claims`
  scans only `*.md`/`*.mdx`, unaffected. **Both lints' own source files
  must keep their ADR/claim tokens** — they document the patterns they
  scan for; carve `xtask/src/check_adr_coverage.rs` and
  `xtask/src/check_doc_claims.rs` out of the sweep.
- **No new dead comments, no slop.** Rewrites read like a peer wrote them
  (`feedback_write_like_expert_human_not_ai`): say the non-obvious, never
  restate the code.
- Per touched crate: `cargo clippy -p <crate> --all-targets -- -D
  warnings` clean; CI fmt is nightly (`rustup run nightly cargo fmt
  --all`).
- No `Co-Authored-By: Claude` trailer (`feedback_no_claude_coauthor_trailer`).

## Transform rules (the decision the worker applies per hit)

For each matched comment, classify and act:

1. **Bare section label** — `// --- Plan 47: dm-thin storage pool ops ---`
   → drop the citation, keep a useful label (`// --- dm-thin storage pool
   ops ---`) or delete the divider if the label was only the plan name.
2. **Citation + real explanation** — strip the leading/trailing
   `Plan N` / `ADR-NN` / `Wn.X` / `PR #N` / `Sprint N` token (and its
   adjoining `—`, `(…)`, or `/` glue), keep the explanation, fix
   capitalization/punctuation so it still reads as a sentence.
3. **Pure citation, no content** — `// Plan 170 WS-A` alone above code →
   delete, UNLESS the code below is non-obvious, in which case replace
   with a one-line *why* comment that says what the reference implied.
4. **Citation inside a doc-comment** (`///`/`//!`) — same as (2); these
   are user/maintainer-facing, so the surviving prose matters most.

When unsure whether a remainder is load-bearing, keep and rewrite rather
than delete.

## File Structure

No files created. Edits land across the workspace; the heaviest files
(use as the pilot batch in T2):

- `crates/mvm-build/src/bin/mvm-host-vm-init.rs` (≈97)
- `crates/mvm-guest/src/vsock.rs` (≈77)
- `crates/mvm-cli/src/commands/env/apple_container.rs` (≈75)
- `crates/mvm-guest/src/bin/mvm-guest-agent.rs` (≈67)
- `crates/mvm-build/src/libkrun_builder.rs` (≈65)
- `crates/mvm-cli/src/commands/vm/up.rs` (≈60)
- `crates/mvm-core/src/policy/audit.rs` (≈45)

---

## Tasks

### T1 — Build the worklist and the detection regex
- [ ] Settle the canonical match set: `\b[Pp]lan \d+`, `\bADR[- ]\d+`,
      `\bW\d+\.[A-Z0-9]`, `\b[Ss]print \d+`, `\bPR #?\d+`, and bare
      `#\d{2,}` inside a comment. Record it in this plan so the future
      lint (T5) and the sweep use one source of truth.
- [ ] Generate the file list (`rg -l … crates/ src/ xtask/ nix/`),
      excluding `specs/`, `public/`, and the two carved-out lint files.
- [ ] Spot-confirm the count baseline (~2,531) so completion is
      measurable.

### T2 — Pilot batch (the 7 heaviest files)
- [ ] Apply the transform rules by hand to the heaviest files above;
      this calibrates the rules before fan-out. Reviewer eyeballs the
      diff for over-deletion (lost reasoning) and slop.
- [ ] `cargo clippy` + nightly fmt clean on the touched crates.

### T3 — Fan-out sweep (remaining files)
- [ ] Partition the rest into disjoint batches (≈one crate per worker)
      and apply the rules. Each worker returns a short note on any
      comment it rewrote rather than deleted, for review.
- [ ] Reconcile `KNOWN_MISSING_ADRS` in `check_adr_coverage.rs`: drop
      any entry whose in-code references all went to zero.

### T4 — Verify nothing regressed
- [ ] `rg` the canonical set over `crates/ src/ xtask/ nix/` (minus the
      two lint files) returns zero comment hits.
- [ ] `just ci` green (fmt, `cargo nextest run --workspace`, doctests,
      clippy `-D warnings`, `xtask check-adr-coverage`,
      `check-claim-catalog`, `check-spec-numbers`).
- [ ] Diff review confirms no string literal / identifier / wire format
      changed (`git diff` shows only comment lines).

### T5 — Lint to prevent regression (keeps the 2,531 from creeping back)
- [ ] Add `xtask check-no-spec-refs-in-comments`: parse comments out of
      `.rs`/`.nix`/`.sh` (not string literals), fail on the canonical
      token set, exempt the two self-referential lint files via an
      explicit allowlist. Wire into the Lint CI job next to
      `check-spec-numbers`.
- [ ] Test the lint: a fixture comment with `// Plan 99` fails; the same
      tokens inside a string literal pass.

### deferred follow-ups
- [ ] Test/function names that encode plan numbers (`fn plan_170_…`) are
      identifiers, not comments — a separate, riskier rename pass; track
      here, don't bundle into this sweep.

## Success criteria
- [ ] Zero plan/PR/ADR/sprint/workstream citations remain in source
      comments (T4 grep is empty).
- [ ] Every rewrite preserves the original comment's reasoning; no
      behavior change (comment-only diff).
- [ ] `just ci` green; `check-no-spec-refs-in-comments` lands and gates
      future PRs.
- [ ] `specs/REFACTOR-STATUS.md` updated in the same change.
