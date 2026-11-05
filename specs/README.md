# Specifications

GitHub issues are the source of truth for work status, remaining scope,
dependencies, ownership, and acceptance criteria. Pull requests record what
landed and how it was verified. Do not duplicate those changing facts in a
shared sprint, refactor, delivery, or progress dashboard under `specs/`.

## Agent read order

Do not recursively read this directory to understand a task. Start from the
issue and read only what it links.

1. Start from the open GitHub issue. It owns the outcome, scope, dependencies,
   priority, and acceptance evidence.
2. Read only the ADRs and contracts linked by that issue. They own durable
   decisions and interfaces.
3. Use Trail to locate the implementation and determine its blast radius.
4. Use the pull request to record the implementation and verification. Use
   `Closes #N` only when the PR completes the issue's last unchecked checkbox;
   otherwise link it with `Part of #N`. An issue may only close once every
   checkbox in its body and comments is checked.

`just maint::task-context <issue>` generates a read-only briefing from those
sources. The briefing is disposable output, never another work ledger.

## What belongs here

`check-spec-hygiene` fails on any tracked path under `specs/` that is not
listed here. The directory is deliberately small.

- `prd.md` is the product requirements document: what mvm is, what is always
  important, and the requirements it is measured against. It states
  requirements, not status; the ADR-001 ledger and GitHub issues own status.
- `adrs/` contains durable architectural decisions. Supersede an ADR rather
  than rewriting the history of a decision.
- `contracts/` contains stable behavioral or protocol contracts that are not
  expressed more clearly by types, schemas, or executable tests.

Plans, research, notes, sprint ledgers and progress dashboards do not belong
here: design discussion lives in the issue, and delivery lives in the pull
request. Machine-consumed registries and committed evidence live with the code
that reads them, under `xtask/data/`.

## Lifecycle

When work closes, keep its issue and pull requests as the delivery record.
Extract enduring decisions into ADRs and user-facing guidance into the public
documentation. The plans, notes and ledgers that used to live here were removed
in the 2026-11 cleanup; the last commit that carried them is tagged
`specs-archive-2026-11-02`.
