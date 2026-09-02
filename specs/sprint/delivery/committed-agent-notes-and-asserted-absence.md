# Committed agent notes, and a gate for prose that asserts absence

Plan: `specs/plans/2026-09-01-committed-agent-notes-and-asserted-absence.md`

## Delivered

- `.agent-memory/notes/` — committed findings, one per file, seeded with five
  real ones ported out of per-user agent memory. Four are falsifications: the
  teardown fix that was A/B'd and reverted, the admit outliers that were not
  the audit chain, the `prepared_cold` budget that covers far less than it
  reads as covering, and the `legacy` sweep where four of six families were
  live code with a wrong comment.
- `xtask check-agent-notes` — frontmatter parses, dates are real calendar
  dates, tags are non-empty, `superseded_by` and every `[[link]]` resolve.
- `xtask check-asserted-absence` — opt-in `<!-- absent:begin -->` regions whose
  named identifiers must resolve to nothing. Fails on a resolving name, on a
  region that names nothing checkable, and on unbalanced or nested markers.
  Markers inside a fenced block are an example, not a region.
- `xtask/src/prose_citations.rs` — one resolver, shared by the citation gate
  and the absence gate, so the two cannot demand opposite things of one name.
- `just recall` / `just notes` / `just remember` / `just agent-notes`.
- Four absence regions in `CLAUDE.md`: claims 6, 10, 12, 13.

## Defect found and fixed

`check-witness-citations` matched over the **raw** text of every `.rs` file,
which includes string literals. `CLAUDE.md` backticks
`audit_chain_carries_no_payload_bytes` in a paragraph stating the name was
never written; the citation resolved anyway, because its only two occurrences
in the tree were literals inside that same gate's tests, asserting the name has
the shape the gate inspects. The gate was reading its own fixture back as
evidence and reporting `clean`.

The Rust haystack now goes through `rust_source::blank_comments_and_strings`
first, so a cited symbol must appear as code. That tightening turned up two
more real misses and one shape defect:

- `download_dev_image` — named by five stale doc comments across `mvm-core`,
  `mvm-cli`, `mvm-build` and `xtask`, defining nothing. `CLAUDE.md` already
  said so; it is now in an absence region. **The five comments are still
  wrong** and are left for a separate change.
- `python_image` — a real Python SDK entry point that the resolver could not
  see, because it only walked `.rs`. The resolver now reads the Python SDK too,
  raw, since there is no Python lexer here.
- `check-no-spec-refs-in-comments` — a live gate whose kebab spelling exists
  only as a string literal and a YAML key. Blanking would have reported it as
  fabricated, so gate and job names resolve against the raw haystack while
  symbols resolve against the blanked one. Both gates ask one shape-dispatched
  predicate.

## Gates

`cargo run -p xtask -- check-all` → 65 clean (was 63). `cargo nextest run
-p xtask` → 689 pass.

## Not delivered

Witness reachability — the hole `CLAUDE.md` names directly, where the claim
gate proves a witness *exists* but never that anything calls the code it tests.
`check-dormant-controls` already holds exactly that rule for security-relevant
symbols — a caller is a mention in production Rust outside the defining file
and outside any test module, and its list may only shrink — so the follow-on is
to extend it to `fn:` witnesses rather than build a third mechanism. Recorded
in the plan.

That gate's own stated limit is also now fixable: its docs say "a symbol named
in a comment counts as a caller", which is the same defect this change fixed in
the citation resolver, and `blank_comments_and_strings` is the same answer.
Also recorded in the plan.
