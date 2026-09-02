# `.agent-memory` — committed findings

Cross-session memory for the agents and humans working on mvm, kept as plain
markdown with YAML frontmatter, in the repository, under version control — so a
finding is **shared with contributors, visible in a PR diff, and present in a
fresh clone**.

The alternative is what we had: findings in a per-user, per-machine agent
memory. Invisible in review, absent from a clone, unavailable to a human, and
gone the moment someone else picks up the work. The expensive ones get
re-derived. `stop_pid_disappearance` scaling with guest RAM was measured, the
obvious fix attempted, A/B'd across two guest sizes, and reverted on
2026-08-30; nothing in the tree recorded that, so nothing stopped it being
attempted again.

**No database, no embeddings, no service.** Recall is lexical — `rg` over a few
hundred terse, keyword-dense engineering notes full of function names, env
flags and commit SHAs. A substring match is faster, has no dependencies, and is
the right tool at this size. Embeddings earn their cost on large,
paraphrase-heavy corpora; if this one ever becomes that, the upgrade path is a
semantic re-rank over the same markdown, which is a later decision and not a
day-one dependency.

## Layout

- `notes/<slug>.md` — one finding per file. Frontmatter: `title`, `date`,
  `tags`, optionally `superseded_by: <slug>`.
- Link related notes with `[[slug]]`. The link must name a note that exists —
  `xtask check-agent-notes` enforces it.

## Use

```sh
just recall teardown ram          # ripgrep-ranked recall
just notes                        # list every note, newest first
just remember <slug>              # scaffold a new note
```

## Conventions

- **Project findings go here.** Machine-specific context — host names, fleet
  layout, ssh targets, local paths — stays in your own global agent memory. It
  confuses contributors and it is not a finding.
- **One finding per note, and keep it terse.** Detail goes in the body, not in
  a long title.
- **Record _why_ it failed, not that it did.** "The guest memory is released
  before the supervisor clears its marker, so both strategies wait for the same
  thing" beats "the marker fix didn't help". The falsifications are the
  valuable notes: they narrow the search space, and unlike the successes they
  are nowhere in the diff.
- **Say what not to retry.** A note that names the refuted causes explicitly is
  what stops the next session spending a day on them.
- **Commit the note with the change it explains.** A note plus its code change
  in one commit is a decision log nobody has to maintain separately.
- **Supersede rather than delete.** A finding that stops being true gets
  `superseded_by`; the record of having believed it is itself useful.
- **Recall before answering.** A note you did not read is a note that did not
  exist.

## Not a specification

These are observations bound to a date and a measurement. They are not
authority: `specs/adrs/` owns decisions, `specs/plans/` owns intent, and the
claims ledger in `specs/adrs/001-microvm-security-posture.md` owns what is
enforced. A note that contradicts one of those is either stale or a bug report,
and either way the owner wins.
