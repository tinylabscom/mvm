# `mvmctl --help` and the CLI reference now describe one product

**Plan:** `specs/plans/329-run-first-cli-and-upstream-adoption.md`, Phase A
(added in this change). **ADR:** ADR-027, amended.

## What was wrong

The published CLI reference documented `mvmctl run` as the one-shot flagship —
"like `docker run --rm` but with a Firecracker microVM as the sandbox" — and
put it in the three-command happy path for the primary audience. In the code it
carried `hide = true`, demoted in its own doc comment to an SDK transport.

It was not only `run`. Eleven documented verbs were invisible in `--help`,
including `secret` (the entry point to the whole host-side substitution
subsystem) and `trust` (which owns `trust receipt verify`, the verification
half of the signed-receipt feature). Seven visible verbs had no reference row.
A user could not discover from the tool that either subsystem had a CLI.

## What changed

- ADR-027 amended: `run` is a first-class visible top-level verb alongside
  `machine run`, and the hidden/visible split is restated as three buckets —
  visible, dev tooling, and `__`-prefixed internal transports.
- Fifteen user-facing verb groups promoted out of `hide = true` and grouped by
  `display_order`. Five stay hidden as dev tooling; the subprocess transports
  stay hidden as internal.
- Twelve reference rows written for visible verbs that had none.
- The `mvmctl doctor` claim-10 failure string told the user to set a flag that
  does not exist (`--network-preset`) and cited ADR-002 for a claim that lives
  in ADR-001. Both fixed, along with two comments on live paths naming the same
  dead flag.

## The gate

`xtask check-cli-help-matches-docs`, in the Lint job. Two rules, both
directions: a documented verb must be visible, and a visible verb must be
documented. Only command evidence counts as documentation — a table row or a
fenced invocation — because the reference legitimately discusses retired verbs
in prose and in one place explicitly negates one ("not by a public
`mvmctl policy` command").

Hiding a verb to avoid writing its row also deletes it from `--help`. That is
the price that keeps the escape honest, and it is why the gate needs no
allowlist.

Mutation-checked before being believed: re-hiding `secret` and deleting the
`pool` rows each produced exactly one finding, and restoring them returned the
gate to clean.
