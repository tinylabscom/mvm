---
title: A witness citation resolved because the gate's own test mentioned the name
date: 2026-09-01
tags: [gates, docs-drift, xtask, falsification]
---

`check-witness-citations` decided whether a cited identifier exists by
substring-matching the raw text of every `.rs` file under `crates/`, `xtask/`
and `src/`. Raw text includes string literals, and a gate's test fixtures are
string literals.

`CLAUDE.md` names `audit_chain_carries_no_payload_bytes` in a paragraph whose
whole point is that the name was never written. It was backticked, so the
citation gate required it to resolve — and it did, because its only two
occurrences anywhere in the tree were inside `check-witness-citations`' own
tests, as literals asserting that the name has the shape the gate inspects. The
gate was reading its own fixture back as evidence.

Nothing was wrong with the ledger, and nothing went red. The gate reported
`clean` for a citation that pointed at nothing.

## What changed

The Rust haystack now goes through `blank_comments_and_strings` before
matching, so a citation resolves to **code** and not to a comment or a literal.
Each file's path is appended to the haystack as well, so a token naming a file
resolves against the tree rather than against whatever the file contains.

## What to take from it

A gate whose corpus includes its own fixtures can be fed its own answer. When a
text gate matches over source, decide explicitly whether comments and literals
are part of the evidence — for an existence claim they are not.

Same shape as [[legacy-keyword-mostly-mislabels-live-code]]: the artifact
looked like it denoted something real, and checking what actually backed it was
the whole finding.
