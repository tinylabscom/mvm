# Committed agent notes, and a gate for prose that asserts absence

Backing: shipped-source
Validation: check-asserted-absence

## Why

Two holes, both visible in this repository's own history.

**Findings do not survive the session that produced them.** An agent working
here accumulates expensive negative results — the fix that was tried and
reverted, the cause that was measured and refuted — and stores them in a
per-user, per-machine memory that is invisible in a PR, absent from a fresh
clone, and unavailable to a human reader. The next session re-derives them.
`stop_pid_disappearance` scaling with guest RAM was measured, the obvious fix
attempted, A/B'd, and reverted on 2026-08-30; nothing in the tree records that,
so nothing stops it being attempted again.

**Prose that asserts something does *not* exist is ungated.** `CLAUDE.md`
already distinguishes the two directions by hand:

> named — in quotes rather than backticks, because backticks assert a real
> identifier and these are names nobody ever wrote

`check-witness-citations` enforces the backtick direction: a cited identifier
must resolve. Nothing enforces the quoted direction. The paragraphs saying
"none of them exist, and none ever did" are load-bearing — they are the record
of a months-long fabrication — and they decay silently the moment anyone adds a
function with one of those names. A claim of absence is a claim.

## What ships

### 1. `.agent-memory/` — committed, diffable findings

One finding per file under `.agent-memory/notes/<slug>.md`, YAML frontmatter
(`title`, `date`, `tags`, optional `superseded_by`). Recall is `rg` — at a few
hundred terse, keyword-dense engineering notes, a substring match beats a vector
model on speed, footprint and dependencies, and the corpus is nowhere near the
size where paraphrase recall starts to matter.

Two rules carry the value:

- **Record why a thing failed, not that it did.** The falsifications narrow the
  search space; the successes are already in the diff.
- **Commit the note with the change it explains.** A note plus its code change
  in one commit is a decision log nobody has to maintain separately.

Machine-specific context — host names, fleet layout, ssh targets, local paths —
stays in the agent's own global memory. It confuses contributors and it is not a
finding.

### 2. `xtask check-agent-notes`

Frontmatter parses; the `title` is present and non-empty; `date` is ISO-8601 and
not in the future; `tags` is non-empty; `superseded_by` names a note that exists.
A superseded note may not itself be cited as current by another note's body.

Cheap, and it stops the directory rotting into a folder of undated fragments.

### 3. `xtask check-asserted-absence`

Opt-in regions in governed prose:

```markdown
<!-- absent:begin -->
…paragraph naming identifiers that must not exist…
<!-- absent:end -->
```

Inside a region, every identifier-shaped token — `snake_case` with at least one
underscore, or `kebab-case` with at least one dash — written in quotes or
backticks must resolve to **nothing** in the workspace sources or workflows.
Outside a region the gate is silent, so ordinary prose cannot trip it.

The resolver is the one `check-witness-citations` already uses, lifted into a
shared module and called from both. Two resolvers drift, and the drift is
invisible until one of them is wrong — the same reasoning
`check-declared-backing` gives for reusing the citation resolver rather than
growing its own.

Three ways to fail:

| Failure | Why it is a failure |
|---|---|
| A named identifier resolves | The absence claim is now false |
| A region asserts nothing | A region with no identifiers is a marker someone forgot to fill, not a passing check |
| Unbalanced or nested markers | The region's extent is ambiguous, so what it asserts is unknown |

## Governed prose

`check-asserted-absence` scans the same set `check-witness-citations` does.
Regions are added to the paragraphs that already assert absence in prose:

- `CLAUDE.md` claim 12 — the five test names and the `fuzz_service_call.rs`
  target that were never written.
- `CLAUDE.md` claim 13 — the six test names in the same shape.
- `CLAUDE.md` claim 10 — `MVM_ACK_UNRESTRICTED_NETWORK`, read nowhere.

## Deliberately not in scope

**Witness reachability.** `CLAUDE.md` states the remaining hole exactly: the
claim gate "proves a named witness *exists*, never that anything calls the code
it tests". That is a real gap and it is not this change — it needs call-graph
analysis over 86 `fn:` witnesses with a false-positive budget near zero, and a
gate that cries wolf gets deleted. Tracked below, not built here.

## Follow-on

- [ ] Extend `check-dormant-controls` to the `fn:` witnesses in the claims
      ledger. It already implements the rule — a caller is a mention in
      production Rust outside the defining file and outside any `#[cfg(test)]`
      module or `tests/` tree, declared per symbol in
      `xtask/dormant-controls.toml`, on a list that may only shrink. Pointing
      it at the 86 ledger witnesses is a smaller change than a new gate, and it
      keeps one definition of "reachable" rather than two. Measure against the
      current ledger before turning it on.
- [ ] Blank comments and literals in `check-dormant-controls`' haystack. Its
      own docs record the limit — "a symbol named in a comment counts as a
      caller" — and that is the same defect this change fixed in the citation
      resolver, with the same one-line answer
      (`rust_source::blank_comments_and_strings`). A control whose only
      "caller" is a doc comment is precisely the dormant control it hunts.
- [ ] Fix the five doc comments in `mvm-core`, `mvm-cli`, `mvm-build` and
      `xtask` that reference `download_dev_image`, a function that does not
      exist. Surfaced by this change; left out of it to keep the diff to one
      concern.
