# `.agent-memory/` is local-only, and the docs and gate now say so

Untracking `.agent-memory/` (#3166) made the notes local to a checkout. Three
things still described them as committed, and one gate went quietly dead.

**The dead gate.** `check-agent-notes` was gate 109 of the PR-gating
`check-all`. With the directory gitignored, CI has no `.agent-memory/notes` at
all, so the gate printed "nothing to check" and exited 0 on every pull request —
green because there was nothing to look at, which is the vacuity failure the
verification matrix exists to catch. Moved into `NOT_IN_LINT_LANE` with the
reason stated. It still dispatches standalone for the one place it is
meaningful: a contributor who has just written a note. `check-all` is 67 gates.

**The prose.** `CLAUDE.md` still called the section "Committed findings", said
the notes are "reviewed in a PR like any other file", and told you to "commit
the note with the change it explains". All three were false the moment #3166
landed. The section now says the notes are local, when they stopped being
committed, and that anything another contributor needs has to go somewhere
tracked instead. The "machine-specific context does not go here" rule inverted
with it — a local note is exactly where host names and local paths belong now.

**The recipes.** A fresh clone is now the default state, and both readers broke
in it: `just notes` emitted two `sed: No such file or directory` lines and a
stray `* — `, and `just recall` failed outright with exit 2. Both now detect the
missing directory and print one line pointing at `just remember`. Their comments
no longer claim the findings are committed.

Left alone deliberately: `release_evidence.rs` still lists `.agent-memory/`
among the paths that are not material to release evidence. It is now moot rather
than wrong, and it stays correct if the directory is ever tracked again.

Verified: `cargo run -p xtask -- check-all` 67 gates clean, `cargo nextest run
-p xtask` 705 passed including the three `check_all` exclusion invariants, and
both recipes exercised against a checkout with no `.agent-memory/`.
